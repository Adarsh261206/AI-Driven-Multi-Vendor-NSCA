"""
Configuration Validation Engine

Validates configuration content for structural integrity and security
concerns. This module is the single source of truth for the validation
contract consumed by AuditExecutor (`validate(config_content)` -> gate).

Input contract (F14)
--------------------
`content` must be a `str`. Any other type raises `TypeError` with an
explicit message before any string method is touched. A normal `str` is
always accepted and never raises: every input problem is reported as a
`ValidationResult`.

Severity / gate semantics (F2, F15)
-----------------------------------
* ERROR   -> `is_valid = False`. The audit pipeline stops.
* WARNING -> `is_valid` unchanged. Concerning but not fatal; the audit
             continues (AuditExecutor inspects only `is_valid`).
* INFO    -> `is_valid` unchanged. Informational observations.

Errors defined by this engine (each one reachable, each one makes
`is_valid=False`):

* EMPTY_CONTENT            - zero-length or whitespace-only input.
* NULL_BYTE                - U+0000 anywhere; reported per line with an
                             accurate 1-based line number, then analysis
                             stops (CWE-158).
* BINARY_CONTENT           - binary file signature, disallowed C0
                             control character, or >10% non-printable
                             density.
* NO_SUBSTANTIVE_CONTENT   - input contains only comments/whitespace.
* MISSING_VALUE            - a command that structurally requires an
                             argument has none (see boundary below).
* INVALID_ARGUMENT         - a numeric-first command received a
                             non-numeric first argument.

Warnings: LONG_LINE, SENSITIVE_DATA, INSECURE_CONFIG, UNKNOWN_CONTENT,
MIXED_VENDOR, VENDOR_HINT_CONFLICT, UNKNOWN_VENDOR_HINT.
Info: MIXED_LINE_ENDINGS, VENDOR_HINT_MATCH.

Empty / whitespace policy (F4)
------------------------------
Zero-length and whitespace-only content (spaces, tabs, CR/LF, form feed,
vertical tab, file separators) -> EMPTY_CONTENT error, gate closed.
Comment-only content is NOT empty; see below.

Comment-only policy (F5)
------------------------
Content whose substantive lines (comment-stripped) number zero ->
NO_SUBSTANTIVE_CONTENT error, gate closed. Content that mixes comments
with real commands stays valid. Recognised comment syntaxes (F11):
`!` (IOS), `#` (Junos/shell), `//` (line), `/* ... */` (block, may span
lines), plus trailing `!`, `#` and `//` when preceded by whitespace.
`//` preceded by `:` (as in `http://`) is never a comment.

Structural syntax validation boundary (F1)
------------------------------------------
Deterministic structural checks only - no vendor grammar:

* value-required commands must carry an argument
  (`hostname`, `username`, `interface`, `router`, `vlan`, `line`,
  `enable secret`, `enable password`, `password`, `set`,
  `security passwords min-length`, `ip ssh version`, `logging host`,
  `transport input`);
* numeric-first commands must receive digits
  (`security passwords min-length`, `ip ssh version`, `exec-timeout`);
* an assignment to a known configuration key with an empty right-hand
  side (`password=`) is incomplete.

Negated lines (`no ...`, `delete ...`, `unset ...`, `negate ...`) are
exempt from these checks: the negation itself is complete. Unknown or
unsupported individual commands are NOT flagged - this engine has no
per-command vocabulary and does not claim one. Unknown *content* (no
recognised vendor structure at all) is reported as UNKNOWN_CONTENT.

vendor_hint / vendor recognition (F6)
-------------------------------------
Independently deterministic; this engine does not import Engine 03.
Recognised structural families: cisco (IOS-like), juniper (JUNOS),
fortinet (FortiOS), paloalto (PAN-OS CLI). `vendor_hint` is normalised
through an alias table (ios->cisco, junos->juniper, fortios->fortinet,
panos->paloalto, ...):
* unknown hint            -> UNKNOWN_VENDOR_HINT warning;
* hint matches structure  -> VENDOR_HINT_MATCH info;
* hint contradicts structure -> VENDOR_HINT_CONFLICT warning;
* >=2 families in one file -> MIXED_VENDOR warning;
* zero families           -> UNKNOWN_CONTENT warning (explicit, never
                             silently "valid with no opinion").
Unknown content stays `is_valid=True`: the validator cannot prove it
invalid, and the contract requires recognition rather than rejection.

Credential detection (F7, F9, F10)
----------------------------------
SENSITIVE_DATA (warning, one per line, evidence redacted - values never
echoed): `password <value>`, `password=:`/`passwd`/`pwd`, `enable secret
<value>`, `enable encrypted-password <value>`, bare `secret <value>`,
`set password <value>` (FortiOS), `encrypted-password <value>` (JUNOS
root-auth), `username <u> password <value>`, SNMP-community in SNMP
context only (`snmp-server community`, `set snmp community`,
`set community` inside a FortiOS `config snmp community` block),
PEM `-----BEGIN ... PRIVATE KEY-----` blocks and `key <material>` where
material is a long base64/hex blob. The bare words `key`/`community`/
`password` in descriptions, comments or route-policy values are NOT
credential evidence: `crypto key generate ...` and JUNOS
`community 11537:950;` never raise SENSITIVE_DATA.

Insecure detection (F8)
-----------------------
INSECURE_CONFIG (warning, one per line), negation-aware: a leading
`no`/`delete`/`unset`/`negate` token suppresses the match - disabling a
service is not enabling it:
* `ip http server` (not `ip http secure-server`);
* `transport input telnet|all`;
* `snmp-server community public|private` and
  `set snmp community public|private` (default community names);
* JUNOS `set system services telnet|ftp`;
* FortiOS `set telnet enable`.

Binary detection policy (F12, F3)
---------------------------------
1. NUL -> NULL_BYTE (line-accurate), analysis stops.
2. Known binary signatures at offset 0 -> BINARY_CONTENT.
3. Any C0 control (U+0000-U+001F) other than TAB/CR/LF -> binary,
   except U+0003 (ETX) on `banner ...` lines, where it is the standard
   IOS banner delimiter; concentration is still bounded by the density
   rule below.
4. >10% non-printable characters (excluding TAB/CR/LF) -> BINARY_CONTENT
   (defence in depth against diluted payloads, including non-C0 format
   characters such as ZWSP).

Result contract (F13)
---------------------
`ValidationResult.issues` is the unified, deterministically ordered
list of every finding. `warnings` and `info` are dedicated buckets,
always synchronised as subsequences of `issues`. `error_count` /
`warning_count` / `info_count` count by severity. Line numbers are
1-based. Repeated identical input produces identical `is_valid`,
codes, messages, severities, line numbers and ordering.

Cross-engine note: Engine 01 performs ingestion-time validation
(extension, size, decode); this engine never re-checks bytes/encoding
and Engine 01 never calls this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class ValidationSeverity(str, Enum):
    """Severity of validation issues"""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """Single validation issue"""
    severity: ValidationSeverity
    code: str
    message: str
    line_number: Optional[int] = None
    column: Optional[int] = None


@dataclass
class ValidationResult:
    """Result of configuration validation.

    `issues` is the unified list (errors, warnings and info) in
    emission order; `warnings` and `info` are synchronised views of
    the same objects (F13).
    """
    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)
    info: list[ValidationIssue] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return len([i for i in self.issues if i.severity == ValidationSeverity.ERROR])

    @property
    def warning_count(self) -> int:
        return len([i for i in self.issues if i.severity == ValidationSeverity.WARNING])

    @property
    def info_count(self) -> int:
        return len([i for i in self.issues if i.severity == ValidationSeverity.INFO])

    def add_error(self, code: str, message: str, line_number: Optional[int] = None) -> None:
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.ERROR,
            code=code,
            message=message,
            line_number=line_number,
        ))
        self.is_valid = False

    def add_warning(self, code: str, message: str, line_number: Optional[int] = None) -> None:
        issue = ValidationIssue(
            severity=ValidationSeverity.WARNING,
            code=code,
            message=message,
            line_number=line_number,
        )
        self.issues.append(issue)
        self.warnings.append(issue)

    def add_info(self, code: str, message: str, line_number: Optional[int] = None) -> None:
        issue = ValidationIssue(
            severity=ValidationSeverity.INFO,
            code=code,
            message=message,
            line_number=line_number,
        )
        self.issues.append(issue)
        self.info.append(issue)


# vendor_hint normalisation: aliases -> canonical structural family (F6)
_VENDOR_ALIASES = {
    "cisco": "cisco", "ios": "cisco", "ios-xe": "cisco", "iosxe": "cisco",
    "ios xe": "cisco", "xe": "cisco", "nx-os": "cisco", "nxos": "cisco",
    "cisco ios": "cisco", "iosxr": "cisco", "ios-xr": "cisco",
    "juniper": "juniper", "junos": "juniper",
    "fortinet": "fortinet", "fortios": "fortinet", "fortigate": "fortinet",
    "paloalto": "paloalto", "palo alto": "paloalto", "panos": "paloalto",
    "pan-os": "paloalto", "panorama": "paloalto",
}

# Lines starting with one of these tokens are complete negations (F8/F1)
_NEGATION_TOKENS = frozenset({"no", "delete", "unset", "negate"})

# Commands that structurally require at least one argument (F1)
_VALUE_REQUIRED = (
    ("security", "passwords", "min-length"),
    ("ip", "ssh", "version"),
    ("logging", "host"),
    ("transport", "input"),
    ("enable", "secret"),
    ("enable", "password"),
    ("hostname",),
    ("username",),
    ("interface",),
    ("router",),
    ("vlan",),
    ("line",),
    ("password",),
    ("set",),
)

# Commands whose first argument must be numeric (F1)
_NUMERIC_FIRST = (
    ("security", "passwords", "min-length"),
    ("ip", "ssh", "version"),
    ("exec-timeout",),
)

# Known configuration keys for the empty-assignment rule (F1). Restricted
# so data fragments such as a wrapped base64 line `UX8=` are not treated
# as malformed assignments.
_ASSIGNMENT_KEYS = frozenset({
    "password", "passwd", "pwd", "secret", "hostname", "host", "ip",
    "address", "gateway", "dns", "domain", "server", "community",
    "username", "user", "vlan", "port", "key", "timeout",
})


def _compile(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p) for p in patterns)


class ConfigurationValidator:
    """
    Configuration Content Validator

    Validates:
    - Content structure (bounded structural syntax - see module docstring)
    - Encoding issues (binary detection, mixed line endings)
    - Potential security concerns (credentials, insecure settings)
    - Vendor structure recognition (vendor_hint, mixed/unknown content)
    """

    # --- credential detection (F7/F9/F10); first match per line wins ---
    SENSITIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        # SNMP community - SNMP context only, never bare `community` (F10)
        (re.compile(r"^\s*snmp-server\s+community\s+\S+", re.I),
         "Potential SNMP community string"),
        (re.compile(r"^\s*set\s+snmp\s+community\s+\S+", re.I),
         "Potential SNMP community string"),
        (re.compile(r"^\s*set\s+community\s+\S+", re.I),
         "Potential SNMP community string"),
        # password family - keyword at line start only, never mid-sentence
        (re.compile(r"^\s*(?:enable\s+)?(?:encrypted-)?password\s+\S+", re.I),
         "Potential plaintext password"),
        (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S+", re.I),
         "Potential plaintext password"),
        (re.compile(r"^\s*set\s+(?:password|passwd)\s+\S+", re.I),
         "Potential plaintext password"),
        (re.compile(r"^\s*(?:enable\s+)?secret\s+\S+", re.I),
         "Potential enable secret"),
        (re.compile(r"encrypted-password\s+\S+", re.I),
         "Potential encrypted password hash"),
        (re.compile(r"^\s*username\s+\S+\s+(?:password|secret)\s+\S+", re.I),
         "Potential user credentials"),
        # key material (F9): PEM blocks or a long encoded blob - the bare
        # word `key` (e.g. `crypto key generate ...`) never matches
        (re.compile(r"-----BEGIN\s[A-Z ]*PRIVATE KEY-----"),
         "Potential private key material"),
        (re.compile(r"(?<![\w-])key\s+[A-Za-z0-9+/=]{32,}", re.I),
         "Potential cryptographic key material"),
    )

    # --- insecure settings (F8); negation-aware, one match per line ---
    INSECURE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"^\s*ip\s+http\s+server\b(?!\s*\S*secure)", re.I),
         "HTTP server enabled (insecure)"),
        (re.compile(r"^\s*transport\s+input\b[^#\n]*\b(?:telnet|all)\b", re.I),
         "Telnet transport enabled (insecure)"),
        (re.compile(r"^\s*snmp-server\s+community\s+(?:public|private)\b", re.I),
         "Default SNMP community string"),
        (re.compile(r"^\s*set\s+snmp\s+community\s+(?:public|private)\b", re.I),
         "Default SNMP community string"),
        (re.compile(r"^\s*set\s+system\s+services\s+(?:telnet|ftp)\b", re.I),
         "Telnet/FTP service enabled (insecure)"),
        (re.compile(r"^\s*set\s+telnet\s+enable\b", re.I),
         "Telnet service enabled (insecure)"),
    )

    # --- structural vendor-family markers (F6) ---
    _VENDOR_MARKERS: dict[str, tuple[re.Pattern[str], ...]] = {
        "cisco": _compile((
            r"^\s*interface\s+(?:GigabitEthernet|FastEthernet|TenGigabitEthernet|"
            r"Loopback|Vlan|Serial|Ethernet|Port-channel|Tunnel|Null|Dialer|Bdi|"
            r"mgmt|Management|AppGigabitEthernet)\S*",
            r"^\s*router\s+(?:ospf|rip|bgp|eigrp|isis|is-is)\b",
            r"^\s*enable\s+(?:secret|password)\b",
            r"^\s*ip\s+route\s+\d",
            r"^\s*ip\s+ssh\s+version\b",
            r"^\s*ip\s+http\s+(?:secure-)?server\b",
            r"^\s*snmp-server\s+",
            r"^\s*access-list\s+\d",
            r"^\s*line\s+(?:vty|con|aux)\b",
            r"^\s*aaa\s+(?:new-model|authentication|authorization|accounting)\b",
            r"^\s*crypto\s+key\s+generate\b",
            r"^\s*spanning-tree\s",
            r"^\s*banner\s+(?:motd|login|exec|slip-pty|autocommand)\b",
            r"^\s*hostname\s+\S",
            r"^\s*logging\s+(?:host|buffered|trap|source-interface)\b",
            r"^\s*transport\s+input\b",
            r"^\s*username\s+\S+\s+(?:password|secret|privilege)\b",
            r"^\s*vlan\s+\d+\s*$",
            r"^\s*switchport\s+",
            r"^\s*security\s+passwords\s+min-length\b",
            r"^\s*no\s+(?:ip|aaa|service|cdp|logging|snmp-server|username)\s+\S",
        )),
        "juniper": _compile((
            r"^\s*set\s+(?:system|protocols|routing-options|interfaces|snmp|"
            r"security|forwarding-options|vlans|policy-options|chassis|"
            r"applications|groups|routing-instances|class-of-service)\s+\S",
            r"^\s*(?:system|protocols|routing-options|interfaces|snmp|security|"
            r"vlans|policy-options|forwarding-options|chassis|applications|"
            r"routing-instances|class-of-service|configuration)\s*\{",
            r"^\s*host-name\s+\S+\s*;",
            r"^\s*route-policy\s+\S+\s+(?:permit|deny)\b",
            r"^\s*(?:ge|xe|fe|et|reth)-\d+/\d+/\d+\s*\{",
            r"^\s*set\s+nth\b",
        )),
        "fortinet": _compile((
            r"^\s*config\s+[a-z][\w-]*(?:\s+[\w-]+)*\s*$",
            r"^\s*edit\s+\"?\S+?\"?\s*$",
        )),
        "paloalto": _compile((
            r"^\s*set\s+deviceconfig\s+\S",
            r"^\s*set\s+rulebase\s+\S",
            r"^\s*set\s+network\s+(?:virtual-router|interface|profiles)\b",
            r"^\s*set\s+config\s+sntp\s+",
        )),
    }

    # binary file signatures at offset 0 (F12); multi-byte, unambiguous
    _BINARY_SIGNATURES: tuple[str, ...] = (
        "\x7fELF", "%PDF-", "GIF87a", "GIF89a", "\x89PNG",
        "PK\x03\x04", "\x1f\x8b\x08", "\xfd7zXZ", "\xca\xfe\xba\xbe",
        "OLE\x02\x01", "\xd0\xcf\x11\xe0", "BZh9", "\x00asm",
    )

    _COMMENT_TOKENS = re.compile(r"(^|\s)(!|#|//|/\*)")

    def validate(
        self,
        content: str,
        vendor_hint: Optional[str] = None,
        check_sensitive: bool = True,
        check_insecure: bool = True,
    ) -> ValidationResult:
        """
        Validate configuration content

        Args:
            content: Configuration content string (str only - F14)
            vendor_hint: Optional vendor hint (normalised, validated and
                applied - F6; see module docstring)
            check_sensitive: Check for sensitive data patterns
            check_insecure: Check for insecure configuration patterns

        Returns:
            ValidationResult with all issues found. Never raises for
            str input; non-str input raises TypeError (F14).
        """
        if not isinstance(content, str):
            raise TypeError(
                f"content must be str, got {type(content).__name__}"
            )

        result = ValidationResult(is_valid=True)

        # 1. empty / whitespace-only content fails closed (F4)
        if not content.strip():
            result.add_error("EMPTY_CONTENT", "Configuration file is empty")
            return result

        lines_raw = content.splitlines()

        # 2. NUL bytes: explicit, line-accurate, sole representation (F3)
        nul_lines = [i for i, line in enumerate(lines_raw, 1) if "\x00" in line]
        if nul_lines:
            for i in nul_lines:
                result.add_error(
                    "NULL_BYTE", f"Null byte detected on line {i}", line_number=i,
                )
            return result

        # 3. binary content (F12): signatures, C0 controls, density
        if self._has_binary_content(content, lines_raw):
            result.add_error("BINARY_CONTENT", "File appears to contain binary data")
            return result

        # 4. mixed line endings - informational only
        if self._has_mixed_line_endings(content):
            result.add_info("MIXED_LINE_ENDINGS", "Mixed line endings detected")

        # 5. comment-aware preprocessing (F11)
        lines = self._strip_comments(lines_raw)  # (lineno, raw, active_text)

        # 6. comment-only content fails closed (F5)
        if not any(text.strip() for _, _, text in lines):
            result.add_error(
                "NO_SUBSTANTIVE_CONTENT",
                "Configuration contains no substantive lines (comments only)",
            )
            return result

        # 7. structure: long lines + bounded syntax rules (F1)
        self._validate_structure(lines, result)
        self._validate_syntax(lines, result)

        # 8. vendor structure / vendor_hint (F6)
        families = self._detect_families([text for _, _, text in lines])
        self._apply_vendor(vendor_hint, families, result)

        # 9/10. security detection (F7-F10), comment-stripped input
        active = [(n, text) for n, _, text in lines if text.strip()]
        if check_sensitive:
            self._check_sensitive_patterns(active, result)
        if check_insecure:
            self._check_insecure_patterns(active, result)

        return result

    # ------------------------------------------------------------------
    # structure / syntax (F1)
    # ------------------------------------------------------------------

    def _validate_structure(self, lines: list[tuple[int, str, str]],
                            result: ValidationResult) -> None:
        """Basic structure checks: NUL (already handled upstream) and
        extremely long lines."""
        for lineno, raw, _ in lines:
            if len(raw) > 10000:
                result.add_warning(
                    "LONG_LINE",
                    f"Line {lineno} is extremely long ({len(raw)} characters)",
                    line_number=lineno,
                )

    @staticmethod
    def _is_negated(text: str) -> bool:
        """True for `no`/`delete`/`unset`/`negate` prefixed commands (F8)."""
        first = text.lstrip().split(None, 1)
        return bool(first) and first[0].lower() in _NEGATION_TOKENS

    def _validate_syntax(self, lines: list[tuple[int, str, str]],
                         result: ValidationResult) -> None:
        """Bounded structural syntax validation (F1). See module docstring
        for the exact supported boundary - no vendor grammar is claimed."""
        for lineno, _, text in lines:
            stripped = text.strip()
            if not stripped or self._is_negated(stripped):
                continue
            tokens = stripped.split()
            lowered = tuple(t.lower() for t in tokens)
            for prefix in _VALUE_REQUIRED:
                if lowered[:len(prefix)] == prefix and len(lowered) <= len(prefix):
                    result.add_error(
                        "MISSING_VALUE",
                        f"Command '{' '.join(prefix)}' requires a value",
                        line_number=lineno,
                    )
                    break
            else:
                for prefix in _NUMERIC_FIRST:
                    if lowered[:len(prefix)] == prefix and len(lowered) > len(prefix):
                        value = tokens[len(prefix)]
                        if not value.lstrip("-").isdigit():
                            result.add_error(
                                "INVALID_ARGUMENT",
                                f"Command '{' '.join(prefix)}' expects a numeric "
                                f"argument, got {value!r}",
                                line_number=lineno,
                            )
                        break
                else:
                    if (
                        len(lowered) == 2
                        and lowered[0] in _ASSIGNMENT_KEYS
                        and tokens[1] == "="
                    ) or (
                        len(lowered) == 1 and lowered[0].endswith("=")
                        and lowered[0][:-1] in _ASSIGNMENT_KEYS
                    ):
                        result.add_error(
                            "MISSING_VALUE",
                            f"Assignment '{stripped.rstrip('=')}=' has no value",
                            line_number=lineno,
                        )

    # ------------------------------------------------------------------
    # comments (F11)
    # ------------------------------------------------------------------

    def _strip_comments(self, lines: list[str]) -> list[tuple[int, str, str]]:
        """Deterministic comment-aware preprocessing.

        Returns (line_number, raw_line, active_text). Supports `!`, `#`,
        `//`, `/* ... */` (stateful across lines) and trailing `!`/`#`/`//`
        preceded by whitespace. `//` after `:` (URLs) is never a comment.
        """
        out: list[tuple[int, str, str]] = []
        in_block = False
        for lineno, raw in enumerate(lines, 1):
            text = raw
            # Juniper JUNOS `##`-prefixed lines are substantive show-config
            # content, not comments — keep them active (parser strips `##`).
            if text.lstrip().startswith("##"):
                out.append((lineno, raw, text))
                continue
            if in_block:
                end = text.find("*/")
                if end < 0:
                    out.append((lineno, raw, ""))
                    continue
                text = text[end + 2:]
                in_block = False
            match = self._COMMENT_TOKENS.search(text)
            while match is not None:
                token = match.group(2)
                if token == "/*":
                    end = text.find("*/", match.end())
                    if end < 0:
                        text = text[:match.start()]
                        in_block = True
                        break
                    text = text[:match.start()] + text[end + 2:]
                    match = self._COMMENT_TOKENS.search(text)
                    continue
                # trailing `!`, `#`, `//` (whitespace-preceded only)
                text = text[:match.start() + (1 if match.group(1) else 0)]
                break
            out.append((lineno, raw, text))
        return out

    # ------------------------------------------------------------------
    # vendor structure / vendor_hint (F6)
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_families(texts: list[str]) -> list[str]:
        """Structural vendor families present in the content (deterministic,
        sorted). Independent of Engine 03."""
        present = []
        for family, markers in ConfigurationValidator._VENDOR_MARKERS.items():
            for text in texts:
                if any(m.search(text) for m in markers):
                    present.append(family)
                    break
        return present

    def _apply_vendor(self, vendor_hint: Optional[str], families: list[str],
                      result: ValidationResult) -> None:
        hint: Optional[str] = None
        if vendor_hint is not None:
            if not isinstance(vendor_hint, str):
                result.add_warning(
                    "UNKNOWN_VENDOR_HINT",
                    f"vendor_hint must be a string, got {type(vendor_hint).__name__}",
                )
            else:
                hint = _VENDOR_ALIASES.get(vendor_hint.strip().lower())
                if hint is None:
                    result.add_warning(
                        "UNKNOWN_VENDOR_HINT",
                        f"vendor_hint {vendor_hint.strip()!r} is not one of the "
                        "supported vendors (cisco/juniper/fortinet/paloalto)",
                    )

        if len(families) >= 2:
            result.add_warning(
                "MIXED_VENDOR",
                "Content mixes multiple vendor structures: "
                + ", ".join(sorted(families)),
            )
        elif not families:
            result.add_warning(
                "UNKNOWN_CONTENT",
                "Content does not match any supported vendor structure "
                "(cisco/juniper/fortinet/paloalto)",
            )

        if hint is not None and families:
            if hint in families:
                result.add_info(
                    "VENDOR_HINT_MATCH",
                    f"vendor_hint {hint!r} matches detected structure",
                )
            else:
                result.add_warning(
                    "VENDOR_HINT_CONFLICT",
                    f"vendor_hint {hint!r} conflicts with detected structure "
                    f"({', '.join(sorted(families))})",
                )

    # ------------------------------------------------------------------
    # security detection (F7-F10)
    # ------------------------------------------------------------------

    # FortiOS `config snmp community` block boundaries (F7), precompiled
    _CFG_SNMP_COMMUNITY_RE = re.compile(r"^\s*config\s+snmp\s+community\s*$", re.I)
    _END_LINE_RE = re.compile(r"^\s*end\s*$", re.I)

    @staticmethod
    def _fortinet_snmp_mask(texts: list[str]) -> list[bool]:
        """Per-index FortiOS `config snmp community` block membership.

        `mask[i]` is True when a `config snmp community` opener appears in
        lines 0..i-1 with no `end` closing it before index i - exactly the
        predicate the previous per-line prefix rescan produced, computed
        in a single O(n) pass (F7; the old form was O(n^2) and made large
        files unvalidatable).
        """
        mask = [False] * len(texts)
        inside = False
        for i, text in enumerate(texts):
            mask[i] = inside
            if ConfigurationValidator._CFG_SNMP_COMMUNITY_RE.match(text):
                inside = True
            elif ConfigurationValidator._END_LINE_RE.match(text):
                inside = False
        return mask

    def _check_sensitive_patterns(self, lines: list[tuple[int, str]],
                                  result: ValidationResult) -> None:
        """Check for patterns that may contain sensitive data (F7/F9/F10).

        One SENSITIVE_DATA warning per line; evidence is the pattern label
        only - secret values are never echoed into messages.
        """
        texts = [text for _, text in lines]
        snmp_block = self._fortinet_snmp_mask(texts)
        for index, (lineno, text) in enumerate(lines):
            for pattern, message in self.SENSITIVE_PATTERNS:
                if pattern.pattern.startswith(r"^\s*set\s+community"):
                    if not snmp_block[index]:
                        continue
                if pattern.search(text):
                    result.add_warning(
                        "SENSITIVE_DATA",
                        f"{message} on line {lineno}",
                        line_number=lineno,
                    )
                    break

    def _check_insecure_patterns(self, lines: list[tuple[int, str]],
                                 result: ValidationResult) -> None:
        """Check for insecure configurations (F8). A negated command line
        (`no ...`) is never reported as an enabled insecure setting."""
        for lineno, text in lines:
            if self._is_negated(text):
                continue
            for pattern, message in self.INSECURE_PATTERNS:
                if pattern.search(text):
                    result.add_warning(
                        "INSECURE_CONFIG",
                        f"{message} on line {lineno}",
                        line_number=lineno,
                    )
                    break

    # ------------------------------------------------------------------
    # binary detection (F12)
    # ------------------------------------------------------------------

    def _has_binary_content(self, content: str,
                            lines: Optional[list[str]] = None) -> bool:
        """Check if content appears to be binary (F12).

        Signatures, disallowed C0 controls (banner ETX delimiter exempt)
        and the >10% density heuristic, in that order. NUL is handled
        upstream as NULL_BYTE (F3).
        """
        if content.startswith(self._BINARY_SIGNATURES):
            return True

        if lines is None:
            lines = content.splitlines()
        for line in lines:
            banner_line = line.lstrip().startswith("banner ")
            for ch in line:
                if ord(ch) < 32 and ch not in "\t\r\n":
                    if ch == "\x03" and banner_line:
                        continue
                    return True

        non_printable = sum(
            1 for c in content if not c.isprintable() and c not in "\n\r\t"
        )
        if len(content) > 0 and (non_printable / len(content)) > 0.1:
            return True

        return False

    def _has_mixed_line_endings(self, content: str) -> bool:
        """Check if content has mixed line endings (\\r\\n and \\n)"""
        has_crlf = '\r\n' in content
        has_lf = False
        for i, c in enumerate(content):
            if c == '\n' and (i == 0 or content[i-1] != '\r'):
                has_lf = True
                break
        return has_crlf and has_lf
