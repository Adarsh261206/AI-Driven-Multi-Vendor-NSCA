"""Deterministic precondition checks for remediation plans.

Each check returns a Precondition (never raises for domain input).
A single critical failure makes the plan unsafe; warnings are
advisory. Checks are pure functions of the supplied context so the
same finding always yields the same verdicts.
"""

from __future__ import annotations

import re
from typing import Any

from app.engines.remediation.models import Precondition
from app.engines.remediation.registry import SUPPORTED_FAMILIES


def _ok(name: str, message: str = "") -> Precondition:
    return Precondition(name=name, passed=True, severity="info",
                        message=message)


def _fail(name: str, message: str,
          severity: str = "critical") -> Precondition:
    return Precondition(name=name, passed=False, severity=severity,
                        message=message)


def check_vendor_known(vendor: str) -> Precondition:
    families = {v for v, _ in SUPPORTED_FAMILIES}
    if (vendor or "").strip().lower() in families:
        return _ok("vendor_known", f"vendor={vendor}")
    return _fail("vendor_known", f"unsupported vendor {vendor!r}")


def check_platform_known(vendor: str, platform: str) -> Precondition:
    if ((vendor or "").strip().lower(),
            (platform or "").strip().lower()) in SUPPORTED_FAMILIES:
        return _ok("platform_known", f"platform={platform}")
    return _fail("platform_known",
                 f"unsupported platform {platform!r} for {vendor!r}")


def check_control_known(control: Any) -> Precondition:
    if control is not None:
        return _ok("control_known", "control definition resolved")
    return _fail("control_known", "unknown control: no benchmark definition")


def check_command_known(command: str) -> Precondition:
    if (command or "").strip():
        return _ok("command_known", "authoritative remediation command found")
    return _fail("command_known",
                 "control carries no authoritative remediation command")


def check_context_present(expected: list[str],
                          observed: list[str]) -> Precondition:
    """Every expected config context must appear in observed evidence."""
    missing = [c for c in expected if c not in observed]
    if not missing:
        return _ok("context_present",
                   f"contexts={expected or ['global']}")
    return _fail("context_present",
                 f"expected context missing from evidence: {missing}")


def check_vulnerable_state_observed(observed: bool,
                                    detail: str = "") -> Precondition:
    if observed:
        return _ok("vulnerable_state_observed", detail or "vulnerable "
                   "state present in evidence")
    return _fail("vulnerable_state_observed",
                 "vulnerable state not observed; nothing to remediate")


def check_syntax_valid(changes: list) -> Precondition:
    """Every command is a safe single line (no pipes/redirects/NUL).

    Lines carrying <placeholders> are skipped here: placeholders are
    validated separately (params_resolved at plan time,
    check_placeholders_resolved after substitution), so this check
    never fails on text that only a human can complete.
    """
    bad: list[str] = []
    for change in changes:
        for cmd in change.commands:
            if not isinstance(cmd, str) or not cmd.strip():
                bad.append(repr(cmd))
                continue
            if "<" in cmd and ">" in cmd:
                continue
            if "\n" in cmd or "\r" in cmd or "\x00" in cmd:
                bad.append(repr(cmd))
                continue
            if any(p in cmd for p in ("|", ">", "#")):
                bad.append(repr(cmd))
    if not bad:
        return _ok("syntax_valid", "all commands are safe single lines")
    return _fail("syntax_valid", f"unsafe command text: {bad[:3]}")


def check_placeholders_resolved(commands: list[str],
                                allowed_secrets: list[str]) -> Precondition:
    """Every surviving <placeholder> must be a supplied secret name.

    Called after plain substitution: remaining placeholders are filled
    at script runtime via getpass, so only supplied-secret names may
    remain. Anything else is a critical failure.
    """
    import re as _re

    allowed = set(allowed_secrets)
    bad: list[str] = []
    for cmd in commands or []:
        for match in _re.finditer(r"<([^<>]+)>", cmd or ""):
            if match.group(1).strip() not in allowed:
                bad.append(match.group(1).strip())
    if not bad:
        return _ok("placeholders_resolved",
                   "only supplied-secret placeholders remain")
    return _fail("placeholders_resolved",
                 f"unresolved placeholders in commands: {sorted(set(bad))}")


def check_no_lockout_risk(changes: list, evidence_text: str) -> Precondition:
    """Fail closed on management-access lockout patterns.

    Removing the only vty transport, or disabling AAA while it is the
    sole auth path with no console evidence, blocks the plan.
    """
    joined = " ".join(c for ch in changes for c in ch.commands).lower()
    if re.search(r"\bno\s+transport\s+input\b", joined):
        return _fail("no_lockout_risk",
                      "bare 'no transport input' would kill vty access")
    if "no aaa new-model" in joined and "console" not in (
            evidence_text or "").lower():
        return _fail("no_lockout_risk",
                      "disabling AAA with no console fallback observed")
    return _ok("no_lockout_risk", "no lockout pattern detected")


def check_params_resolved(unresolved: list[str]) -> Precondition:
    if not unresolved:
        return _ok("params_resolved", "no placeholders outstanding")
    return _fail("params_resolved",
                 f"unresolved placeholders: {sorted(set(unresolved))}")


def check_rollback_known(rollback: list) -> Precondition:
    if rollback:
        return _ok("rollback_known", "safe rollback available")
    return Precondition(name="rollback_known", passed=True,
                        severity="warning",
                        message="no safe rollback; change is one-way "
                                "unless manually reverted")


def check_config_fresh(fresh: bool) -> Precondition:
    if fresh:
        return _ok("config_fresh", "configuration hash matches plan time")
    return _fail("config_fresh",
                 "configuration changed since plan generation; regenerate")


def check_https_available(available: bool) -> Precondition:
    if available:
        return _ok("https_available", "HTTPS serves; HTTP can go")
    return Precondition(name="https_available", passed=True,
                        severity="warning",
                        message="HTTPS not observed; disabling HTTP removes "
                                "web management entirely")


def evaluate(checks: list[Precondition]) -> tuple[bool, list[str]]:
    """Overall verdict: unsafe if any critical check failed.

    Returns (safe_to_apply, risk_flags). Warnings never block; they are
    recorded as flags for the approval screen.
    """
    flags = [f"warning:{c.name}:{c.message}" for c in checks
             if c.passed and c.severity == "warning"]
    critical = [c.name for c in checks
                if not c.passed and c.severity == "critical"]
    if critical:
        flags = [f"blocked:{name}" for name in critical] + flags
        return False, flags
    return True, flags
