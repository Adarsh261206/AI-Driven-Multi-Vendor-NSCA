"""
Configuration Normalization Engine

Maps vendor-specific parsed configurations to the Universal Security Model.

Spec §10.5 contract: consumes a SemanticInterpretation payload (structured
parse evidence when the pipeline provides it, raw_lines compatibility
otherwise) and produces a NormalizedConfiguration-shaped result using
DETERMINISTIC mapping rules.

There is no knowledge base in this repository, so mapping rules live here
as documented deterministic extractors. Every mapper key is validated
against UniversalSecurityModel at engine initialization (§43); any drift
fails fast instead of reaching compliance scoring.

Core fidelity rules (F1):
- Only real configuration statements produce observed values. Comments
  (vendor-aware), blanks and banner payloads never do.
- Absence produces no mapping (None), never a fabricated value. Model
  defaults live in the model, not in normalized output.
- Real negation (`no ...`, `unset ...`, `deactivate ...`) is honored;
  commented-out negation is a comment.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

from app.engines.universal_model import UniversalSecurityModel
from app.ai import kb_domain as _kb_domain


class NormalizationResultType(str, Enum):
    """Result of normalization"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


# Deterministic confidence policy (§21). Numeric, categorical, documented:
# DIRECT_EXACT         verbatim statement value (hostname, on/off flags)
# DIRECT_NEGATED       real negated statement (no/unset/deactivate)
# STRUCTURED_EXTRACTION parsed/converted/section-scoped value
# DERIVED              computed across statements (secure_only, default_action)
# Absence never emits (no UNKNOWN class needed); model defaults are never
# emitted by the normalizer.
CONFIDENCE_DIRECT_EXACT = 0.95
CONFIDENCE_DIRECT_NEGATED = 0.95
CONFIDENCE_STRUCTURED = 0.85
CONFIDENCE_DERIVED = 0.75
CONFIDENCE_POLICY = {
    "DIRECT_EXACT": CONFIDENCE_DIRECT_EXACT,
    "DIRECT_NEGATED": CONFIDENCE_DIRECT_NEGATED,
    "STRUCTURED_EXTRACTION": CONFIDENCE_STRUCTURED,
    "DERIVED": CONFIDENCE_DERIVED,
}

# Canonical platform identity (§25). One representation for lookup, result,
# persistence and benchmark evaluation.
CANONICAL_PLATFORM = {
    ("cisco", "ios"): "ios_xe",
    ("cisco", "ios_xe"): "ios_xe",
    ("juniper", "junos"): "junos",
    ("fortinet", "fortios"): "fortios",
}

# Control characters rejected/sanitized in normalized values (F16).
# NUL, C0 controls and surrogates never reach normalized output or storage.
_UNSAFE_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")


def _sanitize(value: str) -> str:
    """Strip unsafe control characters (deterministic, documented).

    Removes NUL, C0 controls and lone surrogates; legitimate whitespace
    (tab, LF, CR, space) is preserved. Never maps malicious content to a
    different semantic value — deletion only.
    """
    return _UNSAFE_CHARS_RE.sub("", value)


@dataclass
class NormalizationMapping:
    """A single normalization mapping (spec §12.1 NormalizedValue)."""
    model_path: str
    value: Any
    confidence: float
    source_path: list[str] = field(default_factory=list)
    vendor_specific_syntax: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_path": self.model_path,
            "value": self.value,
            "confidence": self.confidence,
            "source_path": list(self.source_path),
            "vendor_specific_syntax": self.vendor_specific_syntax,
        }


@dataclass
class NormalizationResult:
    """Result of configuration normalization (spec §12.1 NormalizedConfiguration)."""
    vendor: str
    platform: str
    universal_config: dict[str, Any]
    mappings: list[NormalizationMapping]
    unmapped_paths: list[str]
    result_type: NormalizationResultType
    # Spec §12.1 envelope (F4).
    id: str = ""
    semantic_interpretation_id: Optional[str] = None
    universal_model_version: str = ""
    unmapped_concepts: list[str] = field(default_factory=list)
    # Spec §12.1 normalized_values: the mappings in contract shape. Stored
    # (not a property) so the field set is explicit and serializable.
    normalized_values: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "platform": self.platform,
            "universal_model_version": self.universal_model_version,
            "semantic_interpretation_id": self.semantic_interpretation_id,
            "universal_config": self.universal_config,
            "mappings": [m.to_dict() for m in self.mappings],
            "normalized_values": self.normalized_values,
            "unmapped_paths": self.unmapped_paths,
            "unmapped_concepts": self.unmapped_concepts,
            "result_type": self.result_type.value,
        }


@dataclass
class _Evidence:
    """One classified configuration statement (internal)."""
    text: str              # cleaned statement text (comment stripped)
    raw: str               # original source line (preserved for vendor syntax)
    line: int              # 1-based source line number
    negated: bool          # real negation (no/unset/deactivate or E04 flag)
    section: tuple = ()    # enclosing section labels (best effort)


# Type of a mapper function: evidence -> (value, syntax, source, conf-class)
_MapperOut = Optional[tuple[Any, str, list[str], str]]


@dataclass
class _Ctx:
    """Per-normalize mapper context (internal)."""
    ev: list[_Evidence]
    vendor: str
    platform: str


class NormalizationEngine:
    """
    Configuration Normalization Engine

    Maps vendor-specific parsed configurations to the Universal Security Model.
    """

    def __init__(self):
        self._model = UniversalSecurityModel()
        self.vendor_mappers: dict[str, dict[str, Any]] = {}
        self._initialize_mappers()
        self._validate_mapper_registry()

    # ------------------------------------------------------------------
    # Registry (§43): every mapper key must exist in the model.
    # ------------------------------------------------------------------

    def _validate_mapper_registry(self) -> None:
        """Fail fast on mapper/model drift (init time, not scoring time)."""
        strays: list[str] = []
        for vendor, platforms in self.vendor_mappers.items():
            for platform, mapper in platforms.items():
                for key in mapper:
                    if not self._model.is_valid_path(key):
                        strays.append(f"{vendor}/{platform}:{key}")
        if strays:
            raise ValueError(
                "mapper paths outside UniversalSecurityModel: "
                + ", ".join(sorted(strays))
            )

    @property
    def unsupported_leaves(self) -> list[str]:
        """Model leaves no vendor mapper can produce (explicitly unmapped)."""
        union: set[str] = set()
        for platforms in self.vendor_mappers.values():
            for mapper in platforms.values():
                union.update(mapper)
        return sorted(set(self._model.leaf_paths()) - union)

    # ------------------------------------------------------------------
    # Mappers: path -> evidence function. A function returns None when its
    # concept is not observed (absence is never a value).
    # ------------------------------------------------------------------

    def _initialize_mappers(self) -> None:
        """Initialize vendor-specific mappers"""

        # ============ CISCO IOS MAPPER ============
        cisco_ios_mapper = {
            "device.hostname": lambda ctx: self._cisco_hostname(ctx),
            "device.vendor": lambda ctx: self._caller_identity(ctx, "vendor"),
            "device.platform": lambda ctx: self._caller_identity(ctx, "platform"),
            "device.firmware_version": lambda ctx: self._cisco_firmware(ctx),
            "device.time_zone": lambda ctx: self._cisco_time_zone(ctx),
            "management.http.enabled": lambda ctx: self._cisco_http_enabled(ctx),
            "management.http.port": lambda ctx: self._cisco_http_port(ctx),
            "management.http.secure_only": lambda ctx: self._cisco_secure_only(ctx),
            "management.https.enabled": lambda ctx: self._cisco_https_enabled(ctx),
            "management.https.port": lambda ev: None,
            "management.https.certificate_valid": lambda ev: None,
            "management.ssh.enabled": lambda ctx: self._cisco_ssh_enabled(ctx),
            "management.ssh.version": lambda ctx: self._cisco_ssh_version(ctx),
            "management.ssh.port": lambda ev: None,
            "management.ssh.timeout": lambda ctx: self._cisco_exec_timeout(ctx),
            "management.ssh.auth_retries": lambda ctx: self._cisco_ssh_auth_retries(ctx),
            "management.ssh.max_retries": lambda ctx: self._cisco_ssh_auth_retries(ctx),
            "management.ssh.source_interface": lambda ctx: self._cisco_ssh_source_interface(ctx),
            "management.ssh.strict_host_key_check": lambda ctx: self._cisco_strict_host_key(ctx),
            "management.ssh.root_login": lambda ev: None,
            "management.ssh.session_timeout": lambda ctx: self._cisco_ssh_session_timeout(ctx),
            "management.ssh.key_size": lambda ctx: self._cisco_ssh_key_size(ctx),
            "management.telnet.enabled": lambda ctx: self._cisco_telnet_enabled(ctx),
            "management.vty.transport": lambda ctx: self._cisco_vty_transport(ctx),
            "management.vty.exec_timeouts": lambda ctx: self._cisco_exec_timeouts(ctx),
            "management.vty.conflicts": lambda ctx: self._cisco_conflicts(ctx),
            "config.conflicts": lambda ctx: self._cisco_conflicts(ctx),
            "management.vty.console_timeout": lambda ctx: self._cisco_block_timeout(ctx, "con"),
            "management.vty.aux_timeout": lambda ctx: self._cisco_block_timeout(ctx, "aux"),
            "management.vty.vty_timeout": lambda ctx: self._cisco_block_timeout(ctx, "vty"),
            "authentication.password_policy.min_length": lambda ctx: self._cisco_min_length(ctx),
            "authentication.password_policy.complexity": lambda ctx: self._cisco_pw_complexity(ctx),
            "authentication.password_policy.expiration": lambda ctx: self._cisco_pw_expiration(ctx),
            "authentication.password_policy.history": lambda ctx: self._cisco_pw_history(ctx),
            "authentication.password_policy.hash_algorithm": lambda ev: None,
            "authentication.mfa_enabled": lambda ev: None,
            "aaa.authentication_enabled": lambda ctx: self._cisco_aaa(ctx, "authentication"),
            "aaa.authorization_enabled": lambda ctx: self._cisco_aaa(ctx, "authorization"),
            "aaa.accounting_enabled": lambda ctx: self._cisco_aaa(ctx, "accounting"),
            "aaa.radius_configured": lambda ctx: self._cisco_aaa_server(ctx, "radius-server"),
            "aaa.tacacs_configured": lambda ctx: self._cisco_aaa_server(ctx, "tacacs-server"),
            "logging.enabled": lambda ctx: self._cisco_logging_enabled(ctx),
            "logging.level": lambda ctx: self._cisco_logging_level(ctx),
            "logging.remote_enabled": lambda ctx: self._cisco_logging_remote(ctx),
            "logging.remote_server": lambda ctx: self._cisco_logging_server(ctx),
            "logging.source_interface": lambda ctx: self._cisco_logging_source(ctx),
            "ntp.configured": lambda ctx: self._cisco_ntp_configured(ctx),
            "ntp.authenticated": lambda ctx: self._cisco_ntp_authenticated(ctx),
            "ntp.servers": lambda ctx: self._cisco_ntp_servers(ctx),
            "access_control.acl_applied": lambda ctx: self._cisco_acl_applied(ctx),
            "access_control.rules_count": lambda ctx: self._cisco_acl_count(ctx),
            "access_control.default_action": lambda ctx: self._cisco_acl_default(ctx),
            "crypto.ssh_key_size": lambda ctx: self._cisco_ssh_key_size(ctx),
            "crypto.https_cert_valid": lambda ev: None,
            "crypto.snmp_v3_auth": lambda ctx: self._cisco_snmp_v3(ctx),
            "monitoring.syslog.enabled": lambda ctx: self._cisco_logging_remote(ctx),
            "monitoring.syslog.severity_level": lambda ctx: self._cisco_syslog_severity(ctx),
            "monitoring.syslog.source_interface": lambda ctx: self._cisco_logging_source(ctx),
            "monitoring.audit_trail.enabled": lambda ctx: self._cisco_audit_trail(ctx),
            "networking.access_control.enabled": lambda ctx: self._cisco_net_access_control(ctx),
            "services.snmp.enabled": lambda ctx: self._cisco_snmp_enabled(ctx),
            "services.snmp.version": lambda ctx: self._cisco_snmp_version(ctx),
            "services.snmp.community_string_type": lambda ctx: self._cisco_community_type(ctx),
            "services.dns.configured": lambda ctx: self._cisco_dns(ctx),
            "services.dhcp.enabled": lambda ctx: self._cisco_dhcp(ctx),
            "interfaces.unused_interfaces_shutdown": lambda ctx: self._cisco_unused_shutdown(ctx),
            "interfaces.management_interface_identified": lambda ev: None,
            "interfaces.loopback_configured": lambda ctx: self._cisco_loopback(ctx),
        }

        self.vendor_mappers["cisco"] = {
            "ios": cisco_ios_mapper,
            "ios_xe": cisco_ios_mapper,
        }

        # ============ FORTINET MAPPER ============
        self.vendor_mappers["fortinet"] = {
            "fortios": {
                "device.hostname": lambda ctx: self._forti_hostname(ctx),
                "device.vendor": lambda ctx: self._caller_identity(ctx, "vendor"),
                "device.platform": lambda ctx: self._caller_identity(ctx, "platform"),
                "device.firmware_version": lambda ev: None,
                "management.http.enabled": lambda ctx: self._forti_allowaccess(ctx, "http"),
                "management.https.enabled": lambda ctx: self._forti_allowaccess(ctx, "https"),
                "management.ssh.enabled": lambda ctx: self._forti_allowaccess(ctx, "ssh"),
                "management.ssh.port": lambda ctx: self._forti_admin_port(ctx, "admin-ssh-port"),
                "management.telnet.enabled": lambda ctx: self._forti_allowaccess(ctx, "telnet"),
                "authentication.password_policy.min_length": lambda ctx: self._forti_pw_int(ctx, "min-length"),
                "authentication.password_policy.complexity": lambda ctx: self._forti_pw_complexity(ctx),
                "authentication.password_policy.expiration": lambda ctx: self._forti_pw_int(ctx, "expire-days"),
                "authentication.password_policy.history": lambda ctx: self._forti_pw_int(ctx, "history"),
                "aaa.authentication_enabled": lambda ctx: self._forti_section_present(ctx, "config user local"),
                "aaa.authorization_enabled": lambda ctx: self._forti_section_present(ctx, "config user group"),
                "logging.enabled": lambda ctx: self._forti_section_present(ctx, "config log setting"),
                "logging.remote_enabled": lambda ctx: self._forti_syslog_status(ctx),
                "logging.remote_server": lambda ctx: self._forti_syslog_server(ctx),
                "ntp.configured": lambda ctx: self._forti_section_present(ctx, "config system ntp"),
                "ntp.servers": lambda ctx: self._forti_ntp_servers(ctx),
                "access_control.acl_applied": lambda ctx: self._forti_section_present(ctx, "config firewall policy"),
                "access_control.rules_count": lambda ctx: self._forti_policy_count(ctx),
                "access_control.default_action": lambda ctx: self._forti_acl_default(ctx),
                "services.snmp.enabled": lambda ctx: self._forti_section_present(ctx, "config system snmp-community"),
                "services.dns.configured": lambda ctx: self._forti_section_present(ctx, "config system dns"),
                "services.dhcp.enabled": lambda ctx: self._forti_section_present(ctx, "config system dhcp server"),
                "interfaces.management_interface_identified": lambda ctx: self._forti_mgmt_interface(ctx),
            },
        }

        # ============ JUNIPER MAPPER ============
        self.vendor_mappers["juniper"] = {
            "junos": {
                "device.hostname": lambda ctx: self._junos_hostname(ctx),
                "device.vendor": lambda ctx: self._caller_identity(ctx, "vendor"),
                "device.platform": lambda ctx: self._caller_identity(ctx, "platform"),
                "device.firmware_version": lambda ctx: self._junos_firmware(ctx),
                "device.time_zone": lambda ctx: self._junos_time_zone(ctx),
                "management.ssh.enabled": lambda ctx: self._junos_flag(ctx, ("system", "services"), "ssh"),
                "management.ssh.port": lambda ctx: self._junos_ssh_port(ctx),
                "management.ssh.version": lambda ctx: self._junos_ssh_version(ctx),
                "management.ssh.root_login": lambda ctx: self._junos_root_login(ctx),
                "management.telnet.enabled": lambda ctx: self._junos_flag(ctx, ("system", "services"), "telnet"),
                "management.http.enabled": lambda ctx: self._junos_flag(ctx, ("web-management",), "http"),
                "management.https.enabled": lambda ctx: self._junos_flag(ctx, ("web-management",), "https"),
                "authentication.password_policy.min_length": lambda ctx: self._junos_min_length(ctx),
                "authentication.password_policy.hash_algorithm": lambda ctx: self._junos_pw_format(ctx),
                "authentication.lockout_policy.max_attempts": lambda ctx: self._junos_tries(ctx),
                "authentication.lockout_policy.lockout_duration": lambda ctx: self._junos_lockout(ctx),
                "aaa.authentication_enabled": lambda ctx: self._junos_any(ctx, ("authentication-order",)),
                "aaa.authorization_enabled": lambda ctx: self._junos_any(ctx, ("authorization-order",)),
                "aaa.accounting_enabled": lambda ctx: self._junos_accounting(ctx),
                "logging.enabled": lambda ctx: self._junos_flag(ctx, ("system",), "syslog"),
                "logging.remote_enabled": lambda ctx: self._junos_syslog_host(ctx),
                "logging.remote_server": lambda ctx: self._junos_syslog_server(ctx),
                "ntp.configured": lambda ctx: self._junos_ntp_configured(ctx),
                "ntp.servers": lambda ctx: self._junos_ntp_servers(ctx),
                "ntp.authenticated": lambda ctx: self._junos_flag(ctx, ("ntp",), "authentication-key"),
                "ntp.version": lambda ctx: self._junos_ntp_version(ctx),
                "access_control.acl_applied": lambda ctx: self._junos_flag(ctx, ("firewall",), "filter"),
                "services.snmp.enabled": lambda ctx: self._junos_any(ctx, ("snmp",)),
                "services.snmp.version": lambda ctx: self._junos_snmp_version(ctx),
                "services.dns.configured": lambda ctx: self._junos_any(ctx, ("name-server",)),
                "interfaces.loopback_configured": lambda ctx: self._junos_loopback(ctx),
                "config.conflicts": lambda ctx: self._junos_conflicts(ctx),
            },
        }

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def normalize(
        self,
        config: dict[str, Any],
        vendor: str,
        platform: str,
        semantic_interpretation: Optional[dict[str, Any]] = None,
        knowledge_base: Any = None,
    ) -> NormalizationResult:
        """
        Normalize vendor-specific config to universal model

        Args:
            config: Vendor-specific parsed configuration (compat layer:
                {"raw_lines": [...]}). Structured §10.5 evidence may also
                arrive via semantic_interpretation (a SemanticInterpretation
                payload: {"sections": [...E04 node dicts...], "unknown": [...]});
                deterministic mapping rules apply to either source.
            vendor: Vendor name (case-insensitive; canonicalized)
            platform: Platform name (case-insensitive; canonicalized per §25)
            semantic_interpretation: Optional §10.5 interpretation payload. The payload carries parse-tree sections (see §22).
            knowledge_base: Optional knowledge base (E06 F1, spec §10.6
                "provide lookup for normalization"). Any object exposing
                lookup(vendor, platform, raw_syntax, require_confirmed).
                Only confirmed mappings at/above the trust threshold are
                reused, and only for model paths the deterministic mappers
                left unmapped; unconfirmed/low-confidence rows never become
                authoritative output.

        Returns:
            NormalizationResult with universal config and mappings
        """
        canon_vendor = (vendor or "").strip().lower()
        raw_platform = (platform or "").strip().lower()
        canon_platform = CANONICAL_PLATFORM.get(
            (canon_vendor, raw_platform), raw_platform)

        result_id = self._result_id(canon_vendor, canon_platform, config)
        version = UniversalSecurityModel.VERSION
        sem_id = None
        if isinstance(semantic_interpretation, dict):
            sem_id = semantic_interpretation.get("id")

        def failed() -> NormalizationResult:
            return NormalizationResult(
                vendor=canon_vendor,
                platform=canon_platform,
                universal_config={},
                mappings=[],
                unmapped_paths=[],
                result_type=NormalizationResultType.FAILED,
                id=result_id,
                semantic_interpretation_id=sem_id,
                universal_model_version=version,
                unmapped_concepts=self._model.leaf_paths(),
                normalized_values=[],
            )

        # Supported mapper check (F6: validate, never trust blindly).
        vendor_platforms = self.vendor_mappers.get(canon_vendor, {})
        mapper = vendor_platforms.get(canon_platform, {})
        if not mapper:
            return failed()

        # Payload validation (F17): typed, deterministic, never a crash.
        if not isinstance(config, dict):
            return failed()
        raw_lines = config.get("raw_lines")
        if not isinstance(raw_lines, list):
            return failed()
        if any(not isinstance(ln, str) for ln in raw_lines):
            return failed()

        # Evidence (§47: structured tree preferred, raw_lines compat).
        sections = None
        if isinstance(semantic_interpretation, dict):
            raw_sections = semantic_interpretation.get("sections")
            if isinstance(raw_sections, list) and raw_sections:
                sections = raw_sections
        try:
            evidence = self._build_evidence(
                raw_lines, canon_vendor, sections=sections)
        except Exception:
            return failed()

        # Foreign-content coherence (F3 dimension B for normalization):
        # structurally foreign content is incompatible input, not success.
        if self._is_foreign(evidence, canon_vendor):
            return failed()

        universal_config: dict[str, Any] = {}
        mappings: list[NormalizationMapping] = []
        unmapped_paths: list[str] = []
        ctx = _Ctx(ev=evidence, vendor=canon_vendor, platform=canon_platform)

        # Apply mappings
        for universal_path, mapper_func in mapper.items():
            try:
                produced = mapper_func(ctx)
            except Exception:
                unmapped_paths.append(universal_path)
                continue
            if produced is None:
                continue
            value, syntax, source, conf_class = produced
            checked = self._check_value(universal_path, value)
            if checked is None:
                # Wrong-typed output is dropped, never coerced silently
                # beyond documented integer parsing (done in extractors).
                unmapped_paths.append(universal_path)
                continue
            confidence = CONFIDENCE_POLICY.get(conf_class,
                                               CONFIDENCE_STRUCTURED)
            # Store in universal config
            self._set_nested_value(universal_config, universal_path, checked)
            # Track mapping (§12.1 NormalizedValue shape)
            mappings.append(NormalizationMapping(
                model_path=universal_path,
                value=checked,
                confidence=confidence,
                source_path=source,
                vendor_specific_syntax=syntax,
            ))

        produced_paths = {m.model_path for m in mappings}
        if knowledge_base is not None:
            self._apply_kb_mappings(
                evidence, canon_vendor, canon_platform, raw_platform,
                knowledge_base, produced_paths, universal_config, mappings)

        produced_paths = {m.model_path for m in mappings}
        unmapped_concepts = sorted(set(self._model.leaf_paths()) - produced_paths)

        # Result semantics (F15/F6): SUCCESS = valid payload, no errors
        # (mappings may be 0 — absence is not failure); PARTIAL = completed
        # with recoverable mapper issues; FAILED = unsupported/invalid.
        result_type = NormalizationResultType.SUCCESS
        if unmapped_paths:
            result_type = NormalizationResultType.PARTIAL

        return NormalizationResult(
            vendor=canon_vendor,
            platform=canon_platform,
            universal_config=universal_config,
            mappings=mappings,
            unmapped_paths=sorted(set(unmapped_paths)),
            result_type=result_type,
            id=result_id,
            semantic_interpretation_id=sem_id,
            universal_model_version=version,
            unmapped_concepts=unmapped_concepts,
            normalized_values=[m.to_dict() for m in mappings],
        )

    def _apply_kb_mappings(
        self,
        evidence: list,
        vendor: str,
        platform: str,
        raw_platform: str,
        knowledge_base: Any,
        produced_paths: set,
        universal_config: dict[str, Any],
        mappings: list,
    ) -> None:
        """Apply confirmed, trusted KB mappings to otherwise-unmapped paths.

        E06 F1 (spec section 10.6 "provide lookup for normalization"): for
        each evidence statement (first-seen order, deterministic), an exact
        canonical lookup runs. A hit is consumed only when it is confirmed,
        at/above the trust threshold, names a valid model path the
        deterministic mappers left unmapped, and its meaning coerces to the
        path's data type. Unconfirmed/low-confidence rows never become
        authoritative output; a KB failure never fails normalization (the
        deterministic result stands on its own).

        Platform lookup tries the canonical platform first, then the
        caller-supplied form (training rows predate/canonicalize
        independently of E05 platform aliasing); the first hit wins.
        """
        seen: set[str] = set()
        platforms = [platform]
        if raw_platform and raw_platform != platform:
            platforms.append(raw_platform)
        for ev in evidence:
            text = ev.text if isinstance(ev.text, str) else ""
            if not text or text in seen:
                continue
            seen.add(text)
            hit = None
            for plat in platforms:
                try:
                    hit = knowledge_base.lookup(
                        vendor=vendor,
                        platform=plat,
                        raw_syntax=text,
                        require_confirmed=True,
                    )
                except Exception:
                    hit = None
                if hit is not None:
                    break
            if hit is None:
                continue
            if not _kb_domain.is_trusted(
                    admin_confirmed=hit.admin_confirmed,
                    confidence=hit.confidence):
                continue
            path = hit.universal_model_path
            if not path or path in produced_paths:
                continue
            if self._model.get_concept(path) is None:
                continue
            checked = self._check_value(path, hit.semantic_meaning)
            if checked is None:
                continue
            line = ev.line if isinstance(ev.line, int) else 0
            self._set_nested_value(universal_config, path, checked)
            mappings.append(NormalizationMapping(
                model_path=path,
                value=checked,
                confidence=hit.confidence,
                source_path=[f"line:{line}", f"kb:{hit.id}"],
                vendor_specific_syntax=ev.raw.strip() if isinstance(
                    ev.raw, str) else text,
            ))
            produced_paths.add(path)

    @staticmethod
    def _result_id(vendor: str, platform: str, config: Any) -> str:
        """Deterministic result id: content hash (stable across runs)."""
        try:
            lines = config.get("raw_lines") if isinstance(config, dict) else None
            if not isinstance(lines, list):
                lines = []
            blob = vendor + "\x00" + platform + "\x00" + "\n".join(
                ln if isinstance(ln, str) else repr(ln) for ln in lines)
        except Exception:
            blob = vendor + "\x00" + platform
        return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:32]

    def _set_nested_value(self, d: dict, path: str, value: Any) -> None:
        """Set a nested dictionary value using dot-separated path"""
        parts = path.split(".")
        current = d
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value

    def _check_value(self, path: str, value: Any) -> Any:
        """Validate (and minimally coerce) a value against the model (F13)."""
        concept = self._model.get_concept(path)
        if concept is None:
            return None
        dtype = concept.data_type
        if dtype == "boolean":
            return value if isinstance(value, bool) else None
        if dtype == "integer":
            if isinstance(value, bool):
                return None
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value.strip())
                except (ValueError, AttributeError):
                    return None
            return None
        if dtype == "string":
            if not isinstance(value, str):
                return None
            return _sanitize(value)
        if dtype == "list":
            if not isinstance(value, list):
                return None
            return [_sanitize(v) if isinstance(v, str) else v for v in value]
        if dtype == "enum":
            allowed = concept.allowed_values or []
            return value if value in allowed else None
        if dtype == "object":
            return value if isinstance(value, dict) else None
        return None

    # ------------------------------------------------------------------
    # Evidence layer: vendor-aware line classification (F1, §47).
    # Only real statements become evidence. Comments (per-vendor syntax),
    # blanks and banner payloads never do. Structured E04 parse sections
    # are preferred when the pipeline provides them.
    # ------------------------------------------------------------------

    _CISCO_SECTION_RES = [
        ("interface", r"^interface\s+(.+)$"),
        ("line", r"^line\s+(.+)$"),
        ("router", r"^router\s+(.+)$"),
        ("vlan", r"^vlan\s+(\d+)\s*$"),
        ("acl", r"^ip\s+access-list\s+(.+)$"),
        ("crypto", r"^crypto\s+(.+)$"),
        ("key_chain", r"^key\s+chain\s+(\S+)\s*$"),
        ("control-plane", r"^control-plane\s*$"),
        ("nested", r"^(?:ip\s+)?(?:prefix-list|route-map|community-list)\s+(\S+).*$"),
        ("switch", r"^switch\s+(.+)$"),
    ]
    _CISCO_CLASSIC_ACL_RE = re.compile(r"^access-list\s+\S")
    _BANNER_RE = re.compile(r"^banner\s+(\S+)(?:\s+(\S)(.*))?$", re.IGNORECASE)
    _FORTI_CONFIG_RE = re.compile(r"^config\s+(\S.*)$")
    _FORTI_EDIT_RE = re.compile(r"^edit\s+(\S.*)$")

    @classmethod
    def _banner_body_lines(cls, lines: list[str]) -> set[int]:
        """0-based banner payload lines (same delimiter rule as E04)."""
        body: set[int] = set()
        i, n = 0, len(lines)
        while i < n:
            m = cls._BANNER_RE.match(lines[i].strip())
            if not m:
                i += 1
                continue
            delim, rest = m.group(2), m.group(3) or ""
            if not delim:
                i += 1
                continue
            if delim in rest:
                i += 1
                continue
            j = i + 1
            while j < n:
                body.add(j)
                if delim in lines[j]:
                    break
                j += 1
            i = j + 1
        return body

    def _build_evidence(
        self,
        lines: list[str],
        vendor: str,
        sections: Optional[list] = None,
    ) -> list[_Evidence]:
        """Classify raw lines (or E04 sections) into statement evidence."""
        if sections:
            return self._evidence_from_sections(sections, vendor)
        if vendor == "cisco":
            return self._cisco_evidence(lines)
        if vendor == "juniper":
            return self._junos_evidence(lines)
        return self._forti_evidence(lines)

    def _evidence_from_sections(
        self, sections: list, vendor: str
    ) -> list[_Evidence]:
        """Flatten E04 parse-tree node dicts into evidence (preferred source)."""
        out: list[_Evidence] = []

        def visit(nodes: list, section: tuple) -> None:
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                key = node.get("key") or ""
                if key == "banner":
                    continue
                raw = node.get("raw_text") or ""
                text = raw.strip()
                if not text:
                    continue
                negated = bool(node.get("negated"))
                if vendor == "cisco" and not negated \
                        and text.lower().startswith("no "):
                    negated = True
                    text = text[3:].strip()
                if vendor == "fortinet" and key.startswith("unset_"):
                    negated = True
                    text = key[len("unset_"):] + (
                        f" {node.get('value')}" if node.get("value") else "")
                    text = text.strip()
                if not text:
                    continue
                ln = node.get("line_number") or 0
                path = tuple(node.get("path") or ())
                kids = node.get("children") or []
                out.append(_Evidence(text=text, raw=raw, line=int(ln),
                                     negated=negated, section=path or section))
                if isinstance(kids, list) and kids:
                    visit(kids, path or section)

        visit(sections, ())
        return out

    def _cisco_evidence(self, lines: list[str]) -> list[_Evidence]:
        banner_body = self._banner_body_lines(lines)
        out: list[_Evidence] = []
        stack: list[str] = []
        for idx, line in enumerate(lines):
            if idx in banner_body:
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                continue
            # Section starts (flat IOS grammar: new section closes the old).
            matched = False
            for family, pattern in self._CISCO_SECTION_RES:
                m = re.match(pattern, stripped)
                if m:
                    try:
                        ident = (m.group(1) or "").strip()
                    except IndexError:
                        ident = ""
                    # Classic single-line ACLs are standalone statements.
                    if family == "acl" and self._CISCO_CLASSIC_ACL_RE.match(stripped):
                        out.append(_Evidence(text=stripped, raw=line,
                                             line=idx + 1, negated=False,
                                             section=()))
                        matched = True
                        break
                    label = family + (f" {ident}" if ident else "")
                    stack = [label]
                    out.append(_Evidence(text=stripped, raw=line, line=idx + 1,
                                         negated=False, section=(label,)))
                    matched = True
                    break
            if matched:
                continue
            if stripped == "end":
                stack = []
                out.append(_Evidence(text=stripped, raw=line, line=idx + 1,
                                     negated=False, section=()))
                continue
            negated = False
            text = stripped
            if text.lower().startswith("no ") and len(text) > 3:
                negated = True
                text = text[3:].strip()
                if not text:
                    continue
            out.append(_Evidence(text=text, raw=line, line=idx + 1,
                                 negated=negated, section=tuple(stack)))
        return out

    def _junos_evidence(self, lines: list[str]) -> list[_Evidence]:
        out: list[_Evidence] = []
        stack: list[str] = []
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            # E04-established: '##' prefixes show-configuration output
            # (content); a single '#' starts a comment.
            if stripped.startswith("##"):
                stripped = stripped[2:].strip()
                if not stripped:
                    continue
            elif stripped.startswith("#"):
                continue
            text = stripped.rstrip(";").strip()
            # Brace tracking on the raw line (structure, not content).
            opens = line.count("{")
            closes = line.count("}")
            if opens:
                label = line.replace("{", "").strip().rstrip(";").strip()
                if label:
                    stack.append(label)
                # A pure opener carries no statement.
                if not text.replace("{", "").strip():
                    continue
            if closes and not opens and text.replace("}", "").strip() == "":
                if stack:
                    stack.pop()
                continue
            if closes:
                for _ in range(closes):
                    if stack:
                        stack.pop()
            if not text:
                continue
            negated = False
            if text.startswith("deactivate "):
                negated = True
                text = text[len("deactivate "):].strip()
            elif text.startswith("inactive:"):
                negated = True
                text = text[len("inactive:"):].strip()
            if not text:
                continue
            out.append(_Evidence(text=text, raw=line, line=idx + 1,
                                 negated=negated, section=tuple(stack)))
        return out

    def _forti_evidence(self, lines: list[str]) -> list[_Evidence]:
        out: list[_Evidence] = []
        stack: list[str] = []
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = self._FORTI_CONFIG_RE.match(stripped)
            if m:
                stack = [f"config {m.group(1).strip()}"]
                out.append(_Evidence(text=stripped, raw=line, line=idx + 1,
                                     negated=False, section=tuple(stack)))
                continue
            if stripped == "end":
                stack = []
                continue
            m = self._FORTI_EDIT_RE.match(stripped)
            if m:
                stack = stack[:1] + [f"edit {m.group(1).strip()}"]
                out.append(_Evidence(text=stripped, raw=line, line=idx + 1,
                                     negated=False, section=tuple(stack)))
                continue
            if stripped == "next":
                stack = stack[:1]
                continue
            negated = False
            text = stripped
            if text.startswith("unset "):
                negated = True
                text = text[len("unset "):].strip()
                if not text:
                    continue
            out.append(_Evidence(text=text, raw=line, line=idx + 1,
                                 negated=negated, section=tuple(stack)))
        return out

    # ------------------------------------------------------------------
    # Foreign-content coherence (normalization-level F3 dimension B).
    # Structurally foreign content is incompatible input (FAILED), never
    # silent success. Mirrors the E04 parser pre-scans, banner-aware.
    # ------------------------------------------------------------------

    def _is_foreign(self, evidence: list[_Evidence], vendor: str) -> bool:
        if not evidence:
            return False
        if vendor == "cisco":
            for ev in evidence:
                t = ev.text
                if re.search(r"\{\s*$", t) or re.match(r"^\}\s*(;.*)?$", t):
                    return True
                if re.match(r"^config\s+\S", t) or re.match(r"^edit\s+\S", t):
                    return True
            return False
        if vendor == "juniper":
            has_marker = False
            for ev in evidence:
                t = ev.text
                if re.match(r"^config\s+\S", t) or re.match(r"^edit\s+\S", t) \
                        or re.match(r"^(end|next)\s*$", t):
                    return True
                if ("{" in ev.raw) or t.startswith("set ") or (";" in ev.raw):
                    has_marker = True
            return not has_marker
        if vendor == "fortinet":
            for ev in evidence:
                t = ev.text
                if re.match(r"^config\s+\S", t) or re.match(r"^edit\s+\S", t) \
                        or re.match(r"^(end|next)\s*$", t):
                    return False
            return True
        return False

    # ------------------------------------------------------------------
    # Small matching helpers over evidence (token-aware, never substring).
    # ------------------------------------------------------------------

    @staticmethod
    def _hit(evidence: _Evidence, value: Any, conf: str) -> tuple:
        section = [f"section:{s}" for s in evidence.section]
        return (value, evidence.raw.strip(),
                [f"line:{evidence.line}"] + section, conf)

    @staticmethod
    def _tokens(text: str) -> list[str]:
        return text.split()

    @classmethod
    def _seq_at(cls, tokens: list[str], seq: list[str]) -> Optional[int]:
        """Index of a token subsequence, else None (multi-word keys, F7)."""
        if not seq or len(seq) > len(tokens):
            return None
        for i in range(len(tokens) - len(seq) + 1):
            if tokens[i:i + len(seq)] == seq:
                return i
        return None

    @staticmethod
    def _to_int(token: str) -> Optional[int]:
        try:
            return int(token.strip())
        except (ValueError, AttributeError):
            return None

    # ------------------------------------------------------------------
    # Cisco extractors. Every function takes the mapper context and returns
    # (value, vendor_syntax, source_path, confidence_class) or None when
    # the concept is not observed. Comments never reach this layer.
    # ------------------------------------------------------------------

    def _cisco_hostname(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^hostname\s+(\S+)\s*$", e.text)
            if m:
                return (m.group(1), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _caller_identity(self, ctx, which: str) -> _MapperOut:
        value = ctx.vendor if which == "vendor" else ctx.platform
        return (value, "", [f"caller:{which}"], "DERIVED")

    def _cisco_firmware(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^version\s+(\S+)\s*$", e.text)
            if m:
                return (m.group(1), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_time_zone(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^clock timezone\s+(\S+)", e.text)
            if m:
                return (m.group(1), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_http_enabled(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text.split() == ["ip", "http", "server"]:
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_http_port(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^ip http port\s+(\d+)\s*$", e.text)
            if m:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "STRUCTURED_EXTRACTION")
        return None

    def _cisco_secure_only(self, ctx) -> _MapperOut:
        https = http_affirm = None
        for e in ctx.ev:
            if e.text == "ip http secure-server" and not e.negated:
                https = https or e
            if e.text.split() == ["ip", "http", "server"] and not e.negated:
                http_affirm = http_affirm or e
        if https is not None and http_affirm is None:
            return (True, https.raw.strip(), [f"line:{https.line}"], "DERIVED")
        if http_affirm is not None:
            return (False, http_affirm.raw.strip(),
                    [f"line:{http_affirm.line}"], "DERIVED")
        return None

    def _cisco_https_enabled(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text == "ip http secure-server":
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_ssh_enabled(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.text.startswith("line vty"):
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_ssh_version(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^ip ssh version\s+([12])\s*$", e.text)
            if m and not e.negated:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_line_blocks(self, ctx) -> list[dict]:
        """Evidence-based line blocks: [{type, range, settings{...}}]."""
        blocks: list[dict] = []
        cur: Optional[dict] = None
        for e in ctx.ev:
            m = re.match(r"^line\s+(vty|con|aux)\s+(.+)$", e.text)
            if m:
                cur = {"type": m.group(1), "range": m.group(2).strip(),
                       "settings": {}, "line": e.line, "raw": e.raw.strip()}
                blocks.append(cur)
                continue
            if cur is None:
                continue
            if e.section and e.section[0].startswith("line "):
                if e.text.startswith("exec-timeout"):
                    cur["settings"]["exec-timeout"] = e
                elif e.text.startswith("transport input"):
                    cur["settings"]["transport input"] = e
                elif e.text.startswith("transport output"):
                    cur["settings"]["transport output"] = e
            else:
                # Left line context (another section or a root statement).
                cur = None
        return blocks

    @staticmethod
    def _exec_seconds(text: str) -> Optional[int]:
        parts = text.split()
        try:
            idx = next(i for i, p in enumerate(parts) if "exec-timeout" in p)
        except StopIteration:
            return None
        rest = parts[idx + 1:]
        if not rest:
            return None
        try:
            minutes = int(rest[0])
            seconds = int(rest[1]) if len(rest) > 1 else 0
        except ValueError:
            return None
        return minutes * 60 + seconds

    def _cisco_exec_timeout(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if "exec-timeout" in e.text and not e.negated:
                seconds = self._exec_seconds(e.text)
                if seconds is not None:
                    return (seconds, e.raw.strip(), [f"line:{e.line}"],
                            "STRUCTURED_EXTRACTION")
        return None

    def _cisco_ssh_auth_retries(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^ip ssh authentication-retries\s+(\d+)\s*$", e.text)
            if m and not e.negated:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_ssh_source_interface(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^ip ssh source-interface\s+(\S+)\s*$", e.text)
            if m and not e.negated:
                return (m.group(1), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_strict_host_key(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text == "ip ssh stricthostkeycheck":
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_ssh_session_timeout(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^ip ssh time-?out\s+(\d+)\s*$", e.text)
            if m and not e.negated:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_ssh_key_size(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^crypto key generate rsa modulus\s+(\d+)\s*.*$", e.text)
            if m and not e.negated:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "STRUCTURED_EXTRACTION")
        return None

    def _cisco_vty_transports(self, ctx) -> list[tuple]:
        """(block_label, [transports]) for vty blocks with transport input."""
        out = []
        for b in self._cisco_line_blocks(ctx):
            if b["type"] != "vty":
                continue
            ev = b["settings"].get("transport input")
            if ev is None:
                continue
            parts = ev.text.split()
            transports = [p.lower() for p in parts[2:]] if len(parts) >= 3 else []
            out.append((f"line vty {b['range']}", transports, ev))
        return out

    def _cisco_telnet_enabled(self, ctx) -> _MapperOut:
        entries = self._cisco_vty_transports(ctx)
        if not entries:
            return None
        for _label, transports, ev in entries:
            if "telnet" in transports:
                return (True, ev.raw.strip(), [f"line:{ev.line}"],
                        "DIRECT_EXACT")
        # Transport is fully specified per block and telnet is absent
        # everywhere: observed disabled (closed-world statement).
        _label, _t, ev = entries[0]
        return (False, ev.raw.strip(), [f"line:{ev.line}"], "DERIVED")

    def _cisco_vty_transport(self, ctx) -> _MapperOut:
        last = None
        for _label, transports, ev in self._cisco_vty_transports(ctx):
            last = (transports, ev)
        if last is None:
            # "unknown" is an honest model value (allowed_values): analyzed
            # content states no vty transport. With no statements at all
            # there is nothing to assess -> absent.
            vty = [b for b in self._cisco_line_blocks(ctx)
                   if b["type"] == "vty"]
            if vty:
                first = vty[0]
                return ("unknown", first["raw"], [f"line:{first['line']}"],
                        "STRUCTURED_EXTRACTION")
            if ctx.ev:
                first_ev = ctx.ev[0]
                return ("unknown", first_ev.raw.strip(),
                        [f"line:{first_ev.line}"], "STRUCTURED_EXTRACTION")
            return None
        transports, ev = last
        tset = set(transports)
        if "ssh" in tset and "telnet" in tset:
            value = "ssh telnet"
        elif "ssh" in tset:
            value = "ssh"
        elif "telnet" in tset:
            value = "telnet"
        elif "none" in tset:
            value = "none"
        else:
            value = " ".join(sorted(tset)) if tset else "unknown"
        return (value, ev.raw.strip(), [f"line:{ev.line}"],
                "STRUCTURED_EXTRACTION")

    def _cisco_exec_timeouts(self, ctx) -> _MapperOut:
        blocks = [b for b in self._cisco_line_blocks(ctx)]
        if not blocks:
            return None
        results = []
        for b in blocks:
            ev = b["settings"].get("exec-timeout")
            seconds = self._exec_seconds(ev.text) if ev is not None else None
            results.append({
                "block": f"line {b['type']} {b['range']}",
                "type": b["type"],
                "range": b["range"],
                "timeout_seconds": seconds,
                "raw": ev.raw.strip() if ev is not None else None,
            })
        first = blocks[0]
        return (results, first["raw"], [f"line:{first['line']}"],
                "STRUCTURED_EXTRACTION")

    def _cisco_conflicts(self, ctx) -> _MapperOut:
        blocks = self._cisco_line_blocks(ctx)
        if not blocks and not ctx.ev:
            return None
        groups: dict[str, list[dict]] = {}
        for b in blocks:
            label = f"line {b['type']} {b['range']}"
            for key, ev in b["settings"].items():
                groups.setdefault(key, []).append({"block": label,
                                                   "raw": ev.raw.strip()})
        conflicts = []
        for key, entries in groups.items():
            if len(entries) < 2:
                continue
            unique = {e["raw"] for e in entries}
            conflicts.append({
                "setting": key,
                "blocks": [e["block"] for e in entries],
                "values": [e["raw"] for e in entries],
                "conflict": len(unique) > 1,
                "path_prefix": "management.vty",
            })
        if ctx.ev:
            first = ctx.ev[0]
            return (conflicts, first.raw.strip(), [f"line:{first.line}"],
                    "STRUCTURED_EXTRACTION")
        return None

    def _cisco_block_timeout(self, ctx, kind: str) -> _MapperOut:
        for b in self._cisco_line_blocks(ctx):
            if b["type"] != kind:
                continue
            ev = b["settings"].get("exec-timeout")
            if ev is None:
                continue
            seconds = self._exec_seconds(ev.text)
            if seconds is not None:
                return (seconds, ev.raw.strip(), [f"line:{ev.line}"],
                        "STRUCTURED_EXTRACTION")
        return None

    def _cisco_min_length(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^security passwords min-length\s+(\d+)\s*$", e.text)
            if m and not e.negated:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_pw_complexity(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text == "password complexity":
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_pw_expiration(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^password aging\s+(\d+)\s*$", e.text)
            if m and not e.negated:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_pw_history(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^password history\s+(\d+)\s*$", e.text)
            if m and not e.negated:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_aaa(self, ctx, kind: str) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text == f"aaa {kind}" or e.text.startswith(f"aaa {kind} "):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
            elif e.text in ("aaa new-model",) and e.negated:
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_aaa_server(self, ctx, key: str) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text == key or e.text.startswith(key + " ") or e.text.startswith(key + "-"):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_logging_enabled(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text == "logging" or e.text.startswith("logging "):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    _LOGGING_LEVELS = ("emergencies", "alerts", "critical", "errors",
                       "warnings", "notifications", "informational", "debugging")

    def _cisco_logging_level(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            tokens = e.text.split()
            if tokens[:2] == ["logging", "trap"] or tokens[:2] == ["logging", "level"]:
                for level in self._LOGGING_LEVELS:
                    if level in tokens[2:]:
                        return (level, e.raw.strip(), [f"line:{e.line}"],
                                "DIRECT_EXACT")
        return None

    def _cisco_logging_remote(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text == "logging host" or e.text.startswith("logging host "):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_logging_server(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^logging host\s+(\S+)", e.text)
            if m and not e.negated:
                return (m.group(1), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_logging_source(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^logging source-interface\s+(\S+)", e.text)
            if m and not e.negated:
                return (m.group(1), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_ntp_configured(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            tokens = e.text.split()
            if tokens[:2] == ["ntp", "server"] or (
                    tokens and tokens[0] == "ntp" and e.section):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
            elif e.text == "ntp" and e.negated:
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_ntp_authenticated(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text.startswith("ntp authentication"):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_ntp_servers(self, ctx) -> _MapperOut:
        servers: list[str] = []
        first = None
        for e in ctx.ev:
            tokens = e.text.split()
            if tokens[:2] == ["ntp", "server"] and not e.negated and len(tokens) > 2:
                if first is None:
                    first = e
                servers.append(tokens[2])
        if not servers or first is None:
            return None
        seen: list[str] = []
        for s in servers:
            if s not in seen:
                seen.append(s)
        src = [f"line:{e.line}" for e in ctx.ev
               if e.text.split()[:2] == ["ntp", "server"] and not e.negated]
        return (seen, "\n".join(e.raw.strip() for e in ctx.ev
                                if e.text.split()[:2] == ["ntp", "server"]
                                and not e.negated),
                src, "STRUCTURED_EXTRACTION")

    _CISCO_ACL_ENTRY_RE = re.compile(r"^(\d+\s+)?(permit|deny|evaluate)\b")

    def _cisco_acl_applied(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text.startswith("access-list ") or (
                    e.text.startswith("ip access-list")):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
            elif e.section and e.section[0].startswith("acl") \
                    and self._CISCO_ACL_ENTRY_RE.match(e.text):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "STRUCTURED_EXTRACTION")
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_acl_count(self, ctx) -> _MapperOut:
        count = 0
        first = None
        for e in ctx.ev:
            if e.negated:
                continue
            if self._CISCO_CLASSIC_ACL_RE.match(e.text):
                # Classic single-line entry (F12: the statement itself).
                count += 1
                first = first or e
            elif e.text.startswith("ip access-list"):
                continue  # named header, entries counted below
            elif e.section and e.section[0].startswith("acl") \
                    and self._CISCO_ACL_ENTRY_RE.match(e.text):
                count += 1
                first = first or e
        # A rule count is a truthful measurement (model default 0), so it is
        # always emitted for a valid payload — even when it is zero.
        if first is None:
            return (0, "", [], "STRUCTURED_EXTRACTION")
        src = [f"line:{e.line}" for e in ctx.ev if not e.negated and (
            self._CISCO_CLASSIC_ACL_RE.match(e.text)
            or (e.section and e.section[0].startswith("acl")
                and self._CISCO_ACL_ENTRY_RE.match(e.text)))]
        return (count, first.raw.strip(), src, "STRUCTURED_EXTRACTION")

    def _cisco_acl_default(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            if self._CISCO_CLASSIC_ACL_RE.match(e.text) or (
                    e.section and e.section[0].startswith("acl")
                    and self._CISCO_ACL_ENTRY_RE.match(e.text)):
                # Documented IOS implicit-deny at the end of every ACL.
                return ("deny", e.raw.strip(), [f"line:{e.line}"], "DERIVED")
        return None

    def _cisco_snmp_v3(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            tokens = e.text.split()
            if "snmp" in tokens and "v3" in tokens and not e.negated:
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_syslog_severity(self, ctx) -> _MapperOut:
        level_map = {"emergencies": 0, "alerts": 1, "critical": 2,
                     "errors": 3, "warnings": 4, "notifications": 5,
                     "informational": 6, "debugging": 7}
        for e in ctx.ev:
            tokens = e.text.split()
            if tokens[:2] == ["logging", "trap"] and not e.negated:
                for level, num in level_map.items():
                    if level in tokens[2:]:
                        return (num, e.raw.strip(), [f"line:{e.line}"],
                                "STRUCTURED_EXTRACTION")
        return None

    def _cisco_audit_trail(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text.startswith("logging buffered") \
                    or e.text.startswith("logging host"):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    _NO_IP_FEATURES = ("redirects", "unreachables", "proxy-arp", "source-route")

    def _cisco_net_access_control(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            tokens = e.text.split()
            if tokens[:2] == ["ip", "redirects"] or tokens[:2] == ["ip", "unreachables"] \
                    or tokens[:2] == ["ip", "proxy-arp"] or tokens[:2] == ["ip", "source-route"]:
                # Affirmative form handled below via negated flag inversion:
                # evidence stores "no ip X" as negated "ip X".
                if not e.negated:
                    neg = neg or e
                else:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_NEGATED")
        if neg is not None:
            # Hardening explicitly disabled -> control-plane exposure.
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_EXACT")
        return None

    def _cisco_snmp_enabled(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            tokens = e.text.split()
            if tokens[:1] == ["snmp-server"] and len(tokens) > 1 and tokens[1] in (
                    "community", "group", "host", "user"):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_snmp_version(self, ctx) -> _MapperOut:
        community = None
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = e.text.split()
            if tokens[:2] == ["snmp-server", "group"] and "v3" in tokens:
                return (3, e.raw.strip(), [f"line:{e.line}"], "DIRECT_EXACT")
            if tokens[:2] == ["snmp-server", "community"]:
                community = community or e
        if community is not None:
            # Community strings are v1/v2c constructs (documented derivation).
            return (2, community.raw.strip(), [f"line:{community.line}"],
                    "DERIVED")
        return None

    def _cisco_community_type(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            tokens = e.text.split()
            if tokens[:2] == ["snmp-server", "community"] and not e.negated:
                rest = tokens[2:]
                if "public" in rest:
                    value = "public"
                elif "private" in rest:
                    value = "private"
                else:
                    value = "custom"
                return (value, e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _cisco_dns(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text == "ip name-server" or e.text.startswith("ip name-server "):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_dhcp(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if e.text == "ip dhcp" or e.text.startswith("ip dhcp "):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_unused_shutdown(self, ctx) -> _MapperOut:
        found_plain = None
        found_neg = None
        for e in ctx.ev:
            if e.text == "shutdown":
                if not e.negated:
                    found_plain = found_plain or e
                else:
                    found_neg = found_neg or e
        if found_plain is not None:
            return (True, found_plain.raw.strip(),
                    [f"line:{found_plain.line}"], "DIRECT_EXACT")
        if found_neg is not None:
            return (False, found_neg.raw.strip(), [f"line:{found_neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _cisco_loopback(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.text.startswith("interface Loopback"):
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    # ------------------------------------------------------------------
    # FortiOS extractors (section-scoped, token-aware).
    # ------------------------------------------------------------------

    def _forti_hostname(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            m = re.match(r"^set hostname\s+\"([^\"]+)\"", e.text)
            if m:
                return (m.group(1), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
            m = re.match(r"^set hostname\s+(\S+)", e.text)
            if m:
                return (m.group(1).strip('"'), e.raw.strip(),
                        [f"line:{e.line}"], "DIRECT_EXACT")
        return None

    def _forti_block_status(self, ctx, section: tuple) -> Optional[_Evidence]:
        """The `set status ...` line of an edit block, if any."""
        for e in ctx.ev:
            if e.section == section and e.text.startswith("set status"):
                return e
        return None

    def _forti_allowaccess(self, ctx, proto: str) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = e.text.split()
            if len(tokens) >= 3 and tokens[0] == "set" and tokens[1] == "allowaccess":
                protos = [p.lower().strip('"') for p in tokens[2:]]
                if proto in protos:
                    status = self._forti_block_status(ctx, e.section)
                    if status is not None and "disable" in status.text.split():
                        continue
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
        return None

    def _forti_section_present(self, ctx, header: str) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            if e.text == header or e.section == (header,):
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "STRUCTURED_EXTRACTION")
        return None

    def _forti_pw_complexity(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if not e.section or e.section[0] != "config system password-policy":
                continue
            if e.text == "set complexity enable":
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
            elif e.text == "set complexity disable" and not e.negated:
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _forti_pw_int(self, ctx, key: str) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            if not e.section or e.section[0] != "config system password-policy":
                continue
            m = re.match(r"^set\s+" + re.escape(key) + r"\s+(\d+)\s*$", e.text)
            if m:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _forti_syslog_status(self, ctx) -> _MapperOut:
        neg = None
        for e in ctx.ev:
            if not e.section or e.section[0] != "config log syslogd setting":
                continue
            if e.text == "set status enable":
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
                neg = neg or e
            elif e.text == "set status disable" and not e.negated:
                neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _forti_syslog_server(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            if not e.section or e.section[0] != "config log syslogd setting":
                continue
            m = re.match(r"^set server\s+\"?([^\"]+)\"?\s*$", e.text)
            if m:
                return (m.group(1).strip().strip('"'), e.raw.strip(),
                        [f"line:{e.line}"], "DIRECT_EXACT")
        return None

    def _forti_ntp_servers(self, ctx) -> _MapperOut:
        servers: list[str] = []
        src: list[str] = []
        syntax: list[str] = []
        for e in ctx.ev:
            if e.negated:
                continue
            if not e.section or e.section[0] != "config system ntp":
                continue
            m = re.match(r"^set ntpserver\s+\"?([^\"]+)\"?\s*$", e.text)
            if m:
                servers.append(m.group(1).strip().strip('"'))
                src.append(f"line:{e.line}")
                syntax.append(e.raw.strip())
        if not servers:
            return None
        seen: list[str] = []
        for s in servers:
            if s not in seen:
                seen.append(s)
        return (seen, "\n".join(syntax), src, "STRUCTURED_EXTRACTION")

    def _forti_policy_count(self, ctx) -> _MapperOut:
        count = 0
        first = None
        in_policies = False
        for e in ctx.ev:
            if e.negated:
                continue
            if e.section and e.section[0] == "config firewall policy":
                in_policies = True
                if re.match(r"^edit\s+\d+\s*$", e.text):
                    count += 1
                    first = first or e
        if not in_policies:
            return (0, "", [], "STRUCTURED_EXTRACTION")
        if first is None:
            return (0, "", [], "STRUCTURED_EXTRACTION")
        src = [f"line:{e.line}" for e in ctx.ev if not e.negated and e.section
               and e.section[0] == "config firewall policy"
               and re.match(r"^edit\s+\d+\s*$", e.text)]
        return (count, first.raw.strip(), src, "STRUCTURED_EXTRACTION")

    def _forti_acl_default(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            if e.section and e.section[0] == "config firewall policy" \
                    and re.match(r"^edit\s+\d+\s*$", e.text):
                # Documented FortiOS implicit-deny at the end of policies.
                return ("deny", e.raw.strip(), [f"line:{e.line}"], "DERIVED")
        return None

    def _forti_admin_port(self, ctx, key: str) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            if not e.section or e.section[0] != "config system global":
                continue
            m = re.match(r"^set\s+" + re.escape(key) + r"\s+(\d+)\s*$", e.text)
            if m:
                return (int(m.group(1)), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _forti_mgmt_interface(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            if e.text == "set dedicated-to management":
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    # ------------------------------------------------------------------
    # Juniper extractors (token + hierarchy-context aware; F11 token
    # boundaries everywhere: `host` never matches `host-name`).
    # ------------------------------------------------------------------

    @staticmethod
    def _jtokens(ev: _Evidence) -> list[str]:
        return ev.text.split()

    def _junos_ctx_tokens(self, ev: _Evidence) -> set[str]:
        """All context tokens: section labels plus the statement tokens."""
        toks: set[str] = set()
        for part in ev.section:
            toks.update(str(part).replace(";", "").split())
        toks.update(self._jtokens(ev))
        return toks

    def _junos_flag(self, ctx, context: tuple, target: str) -> _MapperOut:
        """Target token present with all context words (either syntax)."""
        neg = None
        for e in ctx.ev:
            tokens = self._jtokens(e)
            if target not in tokens:
                continue
            scope = self._junos_ctx_tokens(e)
            if not all(c in scope for c in context):
                continue
            if not e.negated:
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
            neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _junos_any(self, ctx, needles: tuple) -> _MapperOut:
        """Any of the tokens present (comment-free evidence)."""
        neg = None
        for e in ctx.ev:
            tokens = self._jtokens(e)
            if not any(n in tokens for n in needles):
                continue
            if not e.negated:
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
            neg = neg or e
        if neg is not None:
            return (False, neg.raw.strip(), [f"line:{neg.line}"],
                    "DIRECT_NEGATED")
        return None

    def _junos_kv(self, ctx, key: str) -> Optional[tuple]:
        """First `key value` token pair (either syntax), or None."""
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = self._jtokens(e)
            if key in tokens:
                idx = tokens.index(key)
                if idx + 1 < len(tokens):
                    return (tokens[idx + 1], e)
        return None

    def _junos_hostname(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            tokens = self._jtokens(e)
            if tokens[:3] == ["set", "system", "host-name"] and len(tokens) > 3:
                return (tokens[3], e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
            if tokens[:1] == ["host-name"] and len(tokens) > 1 \
                    and not e.negated:
                return (tokens[1], e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _junos_firmware(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            m = re.match(r"^version\s+(\S+)", e.text)
            if m and not e.negated:
                return (m.group(1), e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _junos_time_zone(self, ctx) -> _MapperOut:
        hit = self._junos_kv(ctx, "time-zone")
        if hit is None:
            return None
        value, e = hit
        return (value, e.raw.strip(), [f"line:{e.line}"], "DIRECT_EXACT")

    def _junos_ssh_version(self, ctx) -> _MapperOut:
        hit = self._junos_kv(ctx, "protocol-version")
        if hit is None:
            return None
        value, e = hit
        if value.lower() == "v2":
            return (2, e.raw.strip(), [f"line:{e.line}"], "DIRECT_EXACT")
        if value.lower() == "v1":
            return (1, e.raw.strip(), [f"line:{e.line}"], "DIRECT_EXACT")
        return None

    def _junos_root_login(self, ctx) -> _MapperOut:
        hit = self._junos_kv(ctx, "root-login")
        if hit is None:
            return None
        value, e = hit
        if value in ("deny", "allow", "allow-and-password"):
            return (("deny" if value == "deny" else "allow"),
                    e.raw.strip(), [f"line:{e.line}"], "DIRECT_EXACT")
        return None

    def _junos_ssh_port(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = self._jtokens(e)
            if "port" not in tokens or "ssh" not in self._junos_ctx_tokens(e):
                continue
            idx = tokens.index("port")
            if idx + 1 < len(tokens):
                val = self._to_int(tokens[idx + 1])
                if val is not None:
                    return (val, e.raw.strip(), [f"line:{e.line}"],
                            "STRUCTURED_EXTRACTION")
        return None

    def _junos_min_length(self, ctx) -> _MapperOut:
        hit = self._junos_kv(ctx, "minimum-length")
        if hit is None:
            return None
        value, e = hit
        val = self._to_int(value)
        if val is None:
            return None
        return (val, e.raw.strip(), [f"line:{e.line}"], "DIRECT_EXACT")

    def _junos_pw_format(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = self._jtokens(e)
            if "format" not in tokens or "password" not in self._junos_ctx_tokens(e):
                continue
            idx = tokens.index("format")
            if idx + 1 < len(tokens):
                val = tokens[idx + 1].lower()
                if val in ("md5", "sha1", "sha256", "sha512"):
                    return (val, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
        return None

    def _junos_tries(self, ctx) -> _MapperOut:
        hit = self._junos_kv(ctx, "tries-before-disconnect")
        if hit is None:
            return None
        value, e = hit
        val = self._to_int(value)
        if val is None:
            return None
        return (val, e.raw.strip(), [f"line:{e.line}"], "DIRECT_EXACT")

    def _junos_lockout(self, ctx) -> _MapperOut:
        hit = self._junos_kv(ctx, "lockout-period")
        if hit is None:
            return None
        value, e = hit
        val = self._to_int(value)
        if val is None:
            return None
        return (val * 60, e.raw.strip(), [f"line:{e.line}"],
                "STRUCTURED_EXTRACTION")

    def _junos_accounting(self, ctx) -> _MapperOut:
        seen = None
        for e in ctx.ev:
            scope = self._junos_ctx_tokens(e)
            if "accounting" not in scope:
                continue
            if seen is None:
                seen = e
            if "events" in self._jtokens(e):
                if not e.negated:
                    return (True, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
        if seen is not None:
            return (False, seen.raw.strip(), [f"line:{seen.line}"],
                    "STRUCTURED_EXTRACTION")
        return None

    def _junos_syslog_host(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = self._jtokens(e)
            if "host" not in tokens:
                continue
            scope = self._junos_ctx_tokens(e)
            if "system" in scope and "syslog" in scope:
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _junos_syslog_server(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = self._jtokens(e)
            if "host" not in tokens:
                continue
            scope = self._junos_ctx_tokens(e)
            if "system" not in scope or "syslog" not in scope:
                continue
            idx = tokens.index("host")
            if idx + 1 < len(tokens):
                return (tokens[idx + 1], e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    def _junos_ntp_servers(self, ctx) -> _MapperOut:
        servers: list[str] = []
        src: list[str] = []
        syntax: list[str] = []
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = self._jtokens(e)
            scope = self._junos_ctx_tokens(e)
            if "ntp" not in scope:
                continue
            if "server" in tokens:
                idx = tokens.index("server")
                for token in tokens[idx + 1:]:
                    if token in ("key", "version", "prefer"):
                        break
                    if "boot-server" in token:
                        continue
                    servers.append(token)
                    src.append(f"line:{e.line}")
                    syntax.append(e.raw.strip())
            elif tokens[:1] == ["server"] and "ntp" in scope:
                if len(tokens) > 1 and "boot-server" not in tokens[1]:
                    servers.append(tokens[1])
                    src.append(f"line:{e.line}")
                    syntax.append(e.raw.strip())
        if not servers:
            return None
        seen: list[str] = []
        for s in servers:
            if s not in seen:
                seen.append(s)
        return (seen, "\n".join(syntax), src, "STRUCTURED_EXTRACTION")

    def _junos_ntp_configured(self, ctx) -> _MapperOut:
        servers = self._junos_ntp_servers(ctx)
        if servers is not None:
            _val, _syn, _src, _conf = servers
            first_line = _src[0] if _src else "line:0"
            first_syn = _syn.split("\n")[0] if _syn else ""
            return (True, first_syn, [first_line], "STRUCTURED_EXTRACTION")
        for e in ctx.ev:
            if e.negated:
                continue
            if "ntp" in self._junos_ctx_tokens(e):
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "STRUCTURED_EXTRACTION")
        return None

    def _junos_ntp_version(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = self._jtokens(e)
            scope = self._junos_ctx_tokens(e)
            if "version" not in tokens or "ntp" not in scope:
                continue
            idx = tokens.index("version")
            if idx + 1 < len(tokens):
                val = self._to_int(tokens[idx + 1])
                if val in (3, 4):
                    return (val, e.raw.strip(), [f"line:{e.line}"],
                            "DIRECT_EXACT")
        return None

    def _junos_snmp_version(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            tokens = self._jtokens(e)
            if "snmp" not in self._junos_ctx_tokens(e):
                continue
            if "v3" in tokens:
                return (3, e.raw.strip(), [f"line:{e.line}"], "DIRECT_EXACT")
            if "v2c" in tokens:
                first = e
                break
        else:
            return None
        return (2, first.raw.strip(), [f"line:{first.line}"], "DERIVED")

    def _junos_loopback(self, ctx) -> _MapperOut:
        for e in ctx.ev:
            if e.negated:
                continue
            scope = self._junos_ctx_tokens(e)
            tokens = self._jtokens(e)
            if "lo0" in scope and "address" in tokens:
                return (True, e.raw.strip(), [f"line:{e.line}"],
                        "DIRECT_EXACT")
        return None

    _JUNOS_CONFLICT_LEAVES = {
        "protocol-version", "root-login", "host-name", "minimum-length",
        "format", "tries-before-disconnect", "backoff-threshold",
        "backoff-factor", "lockout-period", "version", "address",
        "server", "authorization", "client-list-name", "time-zone",
        "idle-timeout", "connection-limit", "rate-limit", "source-address",
    }

    _JUNOS_CONFLICT_PATH_MAP = {
        "protocol-version": "management.ssh.version",
        "root-login": "management.ssh.root_login",
        "tries-before-disconnect": "authentication.lockout_policy.max_attempts",
        "lockout-period": "authentication.lockout_policy.lockout_duration",
        "minimum-length": "authentication.password_policy.min_length",
        "format": "authentication.password_policy.hash_algorithm",
        "version": "ntp.version",
        "time-zone": "device.time_zone",
        "telnet": "management.telnet.enabled",
        "events": "aaa.accounting_enabled",
        "password": "authentication.password_policy.min_length",
    }

    def _junos_conflicts(self, ctx) -> _MapperOut:
        statements: list[tuple] = []
        for e in ctx.ev:
            tokens = self._jtokens(e)
            if not tokens:
                continue
            if tokens[0] == "set":
                parts = tokens[1:]
                if len(parts) < 2:
                    continue
                if parts[-2] in self._JUNOS_CONFLICT_LEAVES:
                    statements.append((">".join(parts[:-2]), parts[-2],
                                       parts[-1], e))
                else:
                    statements.append((">".join(parts[:-1]), parts[-1],
                                       "", e))
                continue
            # Hierarchical brace style (set lines excluded: handled above).
            context = ">".join(e.section)
            if len(tokens) >= 1:
                key = tokens[0]
                val = " ".join(tokens[1:])
                statements.append((context, key, val, e))
        groups: dict[tuple, list] = {}
        for c, k, v, e in statements:
            groups.setdefault((c, k), []).append((v, e))
        conflicts = []
        for (c, k), vals in groups.items():
            if len(vals) < 2:
                continue
            unique = {v for v, _e in vals}
            conflicts.append({
                "setting": k,
                "context": c,
                "values": [v for v, _e in vals],
                "conflict": len(unique) > 1,
                "path_prefix": self._JUNOS_CONFLICT_PATH_MAP.get(k),
            })
        if not ctx.ev:
            return None
        first = ctx.ev[0]
        return (conflicts, first.raw.strip(), [f"line:{first.line}"],
                "STRUCTURED_EXTRACTION")
