"""Remediation plan generator (finding -> structured RemediationPlan).

Consumes the live finding shape (title/severity/confidence/evidence/
remediation/control_id/vendor/platform) plus an optional resolved
control. Executable lines come ONLY from the control's authoritative
remediation_command; the registry contributes metadata (contexts,
preconditions, risk, rollback policy, param types). Unknown control,
missing command or unsupported family refuses with a structured
explanation — never invented commands.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from app.engines.remediation import diff as _diff
from app.engines.remediation import preconditions as _pre
from app.engines.remediation import safety as _safety
from app.engines.remediation.models import (
    PlanChange,
    PlanDevice,
    PlanDiff,
    PlanFinding,
    PlanParam,
    PlanStatus,
    RemediationPlan,
    RemediationPlanError,
    SafetyClass,
    coerce_safety,
    new_plan_id,
)
from app.engines.remediation.registry import (
    SUPPORTED_FAMILIES,
    TemplateEntry,
    get_template,
    param_type,
)

_PLACEHOLDER_RE = re.compile(r"<([^<>\s][^<>]*)>")

_CONTEXT_PREFIXES = ("line ", "interface ", "router ", "vlan ",
                     "ip access-list ", "crypto ", "control-plane")


def _plain(value: Any, default: Any = "") -> Any:
    if value is None:
        return default
    if hasattr(value, "value") and not isinstance(value, str):
        try:
            return value.value
        except Exception:
            return default
    return value


def _str(value: Any, default: str = "") -> str:
    value = _plain(value, default)
    return value if isinstance(value, str) else default


def extract_placeholders(commands: list[str]) -> list[str]:
    """Ordered unique <placeholder> names across command lines."""
    found: list[str] = []
    for cmd in commands:
        for match in _PLACEHOLDER_RE.finditer(cmd or ""):
            name = match.group(1).strip()
            if name and name not in found:
                found.append(name)
    return found


def observed_contexts(evidence: Any) -> list[str]:
    """Context-like lines visible in finding evidence (anchoring)."""
    texts: list[str] = []

    def _collect(value: Any) -> None:
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                _collect(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                _collect(v)

    _collect(evidence if isinstance(evidence, dict) else {})
    found: list[str] = []
    for text in texts:
        for line in text.splitlines():
            stripped = line.strip()
            lowered = stripped.lower()
            if any(lowered.startswith(p) for p in _CONTEXT_PREFIXES):
                # Keep the context header only (first line of a block).
                header = stripped.splitlines()[0] if stripped else ""
                if header and header not in found:
                    found.append(header)
    return found


def evidence_text(evidence: Any) -> str:
    parts: list[str] = []

    def _collect(value: Any) -> None:
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                _collect(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                _collect(v)

    _collect(evidence if isinstance(evidence, dict) else {})
    return "\n".join(parts)


_CISCO_REGISTRY: Any = None


def _cisco_controls() -> dict[str, Any]:
    """control_id -> BenchmarkControl for Cisco IOS-XE (cached)."""
    global _CISCO_REGISTRY
    if _CISCO_REGISTRY is None:
        from app.benchmarks import cisco_ios_xe_controls as cisco_mod

        _CISCO_REGISTRY = {
            c.control_id: c for c in cisco_mod.get_registry().controls
        }
    return _CISCO_REGISTRY


def resolve_control(control_id: str, vendor: str = "",
                    platform: str = "") -> Optional[Any]:
    """Look up a control definition; None when unknown or mismatched."""
    if not control_id:
        return None
    if ((vendor or "").strip().lower(),
            (platform or "").strip().lower()) not in SUPPORTED_FAMILIES:
        # Only Cisco controls are indexed in this release; other
        # families resolve through their own adapter later.
        if (vendor or "").strip().lower() != "cisco":
            return None
    control = _cisco_controls().get(control_id)
    if control is None:
        return None
    return control


def _refusal(finding_id: str, control_id: str, vendor: str, platform: str,
             title: str, severity: str, confidence: float,
             reason: str) -> RemediationPlan:
    plan = RemediationPlan(
        plan_id=new_plan_id(), finding_id=finding_id,
        control_id=control_id,
        device=PlanDevice(vendor=vendor, platform=platform),
        finding=PlanFinding(title=title, severity=severity,
                            confidence=confidence),
        risk_flags=[f"blocked:{reason}"],
        safety_class=SafetyClass.BLOCKED,
        safe_to_apply=False,
        requires_approval=True,
        status=PlanStatus.VALIDATION_FAILED,
    )
    plan.preconditions.append(_pre.Precondition(
        name="refusal", passed=False, severity="critical",
        message=reason))
    return plan


def generate_plan(finding: dict[str, Any],
                  control: Optional[Any] = None,
                  config_fresh: Optional[bool] = None) -> RemediationPlan:
    """Build a structured RemediationPlan from a finding dict.

    config_fresh: True/False from the caller when the configuration
    hash was re-checked, None in pure dry-run (recorded as a warning,
    verified at approve/apply time).
    """
    if not isinstance(finding, dict):
        raise RemediationPlanError(
            f"finding must be a mapping, got {type(finding).__name__}")
    finding_id = _str(finding.get("finding_id") or finding.get("id"))
    control_id = _str(finding.get("control_id"))
    vendor = _str(finding.get("vendor") or finding.get("affected_vendor"))
    platform = _str(finding.get("platform")
                    or finding.get("affected_platform"))
    title = _str(finding.get("finding_title") or finding.get("title"),
                 "Untitled finding")
    severity = _str(finding.get("severity"), "UNKNOWN")
    try:
        confidence = float(finding.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    evidence = finding.get("evidence") or {}
    device_name = _str(finding.get("affected_device")
                       or finding.get("device_name"))

    def _refuse(reason: str) -> RemediationPlan:
        return _refusal(finding_id, control_id, vendor, platform, title,
                        severity, confidence, reason)

    # 1-2. family + control + command resolution (refuse, never invent).
    family = (vendor.strip().lower(), platform.strip().lower())
    if family not in SUPPORTED_FAMILIES:
        return _refuse(f"unsupported vendor/platform {vendor!r}/"
                       f"{platform!r}")
    if control is None:
        control = resolve_control(control_id, vendor, platform)
    if control is None:
        return _refuse(f"unknown control {control_id!r}")
    command = (_str(getattr(control, "remediation_command", ""))).strip()
    if not command:
        return _refuse(f"control {control_id!r} carries no authoritative "
                       f"remediation command")
    entry = get_template(control_id, vendor, platform)
    if entry is None:
        return _refuse(f"no remediation template for control "
                       f"{control_id!r}")

    # 3. structured context blocks (hierarchical Cisco config preserved).
    changes = _diff.parse_command_block(command)
    flat_commands = [c for ch in changes for c in ch.commands]

    # 4. parameters (<...> placeholders block until resolved).
    params = [PlanParam(name=name, type=param_type(entry, name))
              for name in extract_placeholders(flat_commands)]
    unresolved = [p.name for p in params if p.required and not p.supplied]

    # 5-6. context anchoring: template contexts must not contradict
    # observed evidence (interface evidence must never yield a global
    # plan and vice versa).
    observed = observed_contexts(evidence)
    scoped = [o for o in observed
              if any(o.lower().startswith(p) for p in _CONTEXT_PREFIXES)]
    context_checks: list = []
    if entry.contexts:
        hit = [c for c in entry.contexts if c in observed]
        foreign = [o for o in scoped if o not in entry.contexts]
        if hit:
            context_checks.append(_pre.check_context_present(
                entry.contexts, observed))
        elif foreign:
            context_checks.append(_pre.Precondition(
                name="context_present", passed=False, severity="critical",
                message=f"evidence shows {foreign} but the remediation "
                        f"targets {entry.contexts}; refusing cross-context "
                        f"plan"))
        else:
            context_checks.append(_pre.Precondition(
                name="context_present", passed=True, severity="warning",
                message=f"context {entry.contexts} assumed from template; "
                        f"not confirmed in evidence"))
    elif scoped:
        # Global command but interface/line-scoped evidence: the observed
        # vulnerable state lives in a specific context (e.g. interface
        # Gi0/0 "no cdp enable"), which a global command ("no cdp run")
        # must never silently absorb. Refuse with the reason stated.
        context_checks.append(_pre.Precondition(
            name="context_present", passed=False, severity="critical",
            message=f"evidence is scoped to {scoped} but the remediation "
                    f"is global; refusing cross-context plan"))

    # 7. rollback (override > prohibition > conservative derivation).
    rollback: list[PlanChange] = []
    rollback_flags: list[str] = []
    if entry.rollback_override is not None:
        rollback = [PlanChange(context=c.context,
                               commands=list(c.commands))
                    for c in entry.rollback_override]
    elif entry.rollback_prohibited:
        rollback_flags.append("rollback_unavailable:prohibited-for-domain")
    else:
        derived, confident = _safety.derive_rollback(
            changes, vendor, platform)
        if confident:
            rollback = derived
        else:
            rollback_flags.append("rollback_unavailable:unsafe-inverse")

    # 8. verification from the control's audit procedure.
    verification: list[str] = []
    audit_command = _str(getattr(control, "audit_command", "")).strip()
    if audit_command:
        verification.append(audit_command)
    for step in (getattr(control, "verification_steps", None) or []):
        if (isinstance(step, str) and step.strip()
                and step.strip() not in verification):
            verification.append(step.strip())

    # 9-10. preconditions + safety classification.
    checks = [
        _pre.check_vendor_known(vendor),
        _pre.check_platform_known(vendor, platform),
        _pre.check_control_known(control),
        _pre.check_command_known(command),
        *context_checks,
        _pre.check_vulnerable_state_observed(
            bool(evidence),
            "evidence carries observed vulnerable state"
            if evidence else "finding carries no evidence"),
        _pre.check_syntax_valid(changes),
        _pre.check_no_lockout_risk(changes, evidence_text(evidence)),
        _pre.check_params_resolved(unresolved),
        _pre.check_rollback_known(rollback),
    ]
    for name in entry.preconditions:
        if name == "https_available":
            https = any("secure-server" in (c or "")
                        for c in evidence_text(evidence).splitlines())
            checks.append(_pre.check_https_available(https))
    if config_fresh is None:
        checks.append(_pre.Precondition(
            name="config_fresh", passed=True, severity="warning",
            message="freshness not verified in dry-run; re-checked at "
                    "approve/apply time"))
    else:
        checks.append(_pre.check_config_fresh(bool(config_fresh)))

    safety, safety_flags = _safety.classify(
        entry.risk_level, changes, vendor, platform)

    pre_ok, pre_flags = _pre.evaluate(checks)
    risk_flags = list(pre_flags) + list(safety_flags) + list(
        rollback_flags)
    for name in entry.preconditions:
        if name not in ("vendor_known", "platform_known", "control_known",
                        "command_known", "https_available"):
            risk_flags.append(f"template-precondition:{name}")

    safe = (pre_ok and safety != SafetyClass.BLOCKED and not unresolved
            and config_fresh is not False)
    if safety == SafetyClass.BLOCKED:
        safe = False

    plan = RemediationPlan(
        plan_id=new_plan_id(), finding_id=finding_id,
        control_id=control_id,
        device=PlanDevice(name=device_name, vendor=vendor,
                          platform=platform),
        finding=PlanFinding(title=title, severity=severity,
                            confidence=confidence),
        preconditions=checks,
        changes=changes,
        rollback=rollback,
        verification=verification,
        risk_flags=sorted(set(risk_flags)),
        params=params,
        safety_class=coerce_safety(safety),
        safe_to_apply=safe,
        requires_approval=True,
        status=PlanStatus.VALIDATED,
    )
    # 11. diff from structured changes (+ observed removals for
    # replacements inside a known context).
    removed = _removed_lines(evidence, changes)
    plan.diff = _diff.build_diff(changes, removed)
    return plan


def _removed_lines(evidence: Any,
                   changes: list[PlanChange]) -> list[PlanChange]:
    """Observed vulnerable lines a change replaces (same context only).

    A removal candidate shares an added command's leading directive
    (first two tokens, e.g. "transport input") but differs in full
    text (e.g. observed "transport input telnet ssh" vs added
    "transport input ssh"). Global one-liner hardening
    ("no ip http server") has no removal side. Context-free evidence
    never yields removals: without a known context anchor the diff
    must not guess.
    """
    texts = [ln.strip()
             for ln in evidence_text(evidence).splitlines()]
    texts = [t for t in texts if t]
    out: list[PlanChange] = []
    for change in changes:
        if not change.context:
            continue
        for cmd in change.commands:
            key = " ".join(cmd.split()[:2])
            if not key:
                continue
            for line in texts:
                if line != cmd and line.startswith(key):
                    out.append(PlanChange(context=change.context,
                                          commands=[line]))
                    break
    return out
