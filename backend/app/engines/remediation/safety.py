"""Safety classification for remediation plans.

Reuses negate_statement()/invert_command() from the advisory contract —
no second implementation. SafetyClass derives from the template risk
level, dangerous patterns, lockout analysis and rollback availability;
BLOCKED is terminal and fail-closed.
"""

from __future__ import annotations

import re

from app.engines.compliance.remediation import (
    invert_command,
    negate_statement,
)
from app.engines.remediation.models import (
    PlanChange,
    SafetyClass,
    coerce_safety,
)

#: Command patterns that always block, regardless of template.
BLOCKED_PATTERNS = (
    "reload",
    "write erase",
    "erase ",
    "format ",
    "delete flash:",
    "request system",
)

#: Substrings marking high-risk domains (routing/crypto/auth fabric).
HIGH_RISK_HINTS = (
    "aaa ",
    "tacacs",
    "radius",
    "bgp",
    "ospf",
    "nat",
    "vpn",
    "crypto ",
    "vrf",
    "shutdown",
    "access-class",
    "access-list",
)


def classify(risk_level: str, changes: list[PlanChange],
             vendor: str, platform: str) -> tuple[SafetyClass, list[str]]:
    """Classify changes; returns (class, risk_flags).

    BLOCKED triggers: unknown family, blocked patterns, unparseable
    commands. Otherwise the template risk_level seeds the class and
    dangerous content escalates it. Never downgrades below the seed.
    """
    flags: list[str] = []
    family = (vendor or "").strip().lower()
    if family not in ("cisco",):
        return SafetyClass.BLOCKED, ["blocked:unsupported-vendor-family"]
    try:
        seed = {"safe": SafetyClass.SAFE, "low": SafetyClass.SAFE,
                "controlled": SafetyClass.CONTROLLED,
                "medium": SafetyClass.CONTROLLED,
                "high": SafetyClass.HIGH_RISK,
                "high_risk": SafetyClass.HIGH_RISK,
                "critical": SafetyClass.BLOCKED,
                "blocked": SafetyClass.BLOCKED}[risk_level]
    except KeyError:
        return SafetyClass.BLOCKED, ["blocked:unknown-risk-level"]
    level = seed
    texts = [c for ch in changes for c in ch.commands]
    for cmd in texts:
        lowered = cmd.lower()
        if any(p in lowered for p in BLOCKED_PATTERNS):
            return SafetyClass.BLOCKED, [
                f"blocked:dangerous-pattern:{cmd[:60]}"]
        if not cmd.strip() or "\n" in cmd or "\x00" in cmd:
            return SafetyClass.BLOCKED, ["blocked:malformed-command"]
    if any(any(h in c.lower() for h in HIGH_RISK_HINTS) for c in texts):
        if level == SafetyClass.CONTROLLED:
            level = SafetyClass.HIGH_RISK
            flags.append("escalated:high-risk-domain")
        elif level == SafetyClass.SAFE:
            level = SafetyClass.CONTROLLED
            flags.append("escalated:high-risk-domain")
    if not texts:
        return SafetyClass.BLOCKED, ["blocked:empty-changes"]
    return level, flags


def derive_rollback(changes: list[PlanChange], vendor: str,
                    platform: str) -> tuple[list[PlanChange], bool]:
    """Best-effort safe rollback via the advisory inverse rules.

    Returns (rollback_changes, confident). Complex/fabric commands
    (AAA/BGP/OSPF/ACL/NAT/VPN and anything multi-statement ambiguous)
    are never blindly inverted: not confident.
    """
    out: list[PlanChange] = []
    fabric = re.compile(
        r"\b(aaa|bgp|ospf|access-list|access-class|nat|vpn|crypto|"
        r"tacacs|radius|vrf|shutdown)\b", re.IGNORECASE)
    for change in changes:
        inverted: list[str] = []
        for cmd in change.commands:
            # Fabric scope covers the context too: anything under router
            # bgp/ospf (or touching crypto/aaa/nat/vpn/vrf) is never
            # blindly inverted, even when the command line alone looks
            # innocent.
            if fabric.search(f"{change.context or ''} {cmd}"):
                return [], False
            inv = invert_command(cmd, vendor, platform)
            if not inv:
                # Try the negation direction (removal commands restore
                # by re-adding through negate of the negated form).
                neg = negate_statement(cmd, vendor, platform)
                if not neg or neg == cmd:
                    return [], False
                inv = neg
            inverted.append(inv)
        out.append(PlanChange(context=change.context, commands=inverted))
    if not out:
        return [], False
    return out, True


def coerce_safety_class(value: object) -> SafetyClass:
    return coerce_safety(value)
