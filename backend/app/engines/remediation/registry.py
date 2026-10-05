"""Remediation template registry (metadata only — never commands).

Executable commands are ALWAYS mined at plan time from
BenchmarkControl.remediation_command (the authoritative source). A
registry entry carries only what controls do not provide: expected
configuration contexts, precondition names, risk level, rollback
policy and parameter type hints.

Unknown control / missing command / unsupported vendor-platform →
no entry match → the generator refuses with a structured explanation
(safe_to_apply=false). Nothing is ever invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from app.engines.remediation.models import PlanChange

#: Vendor families with a remediation adapter in this release.
SUPPORTED_FAMILIES = frozenset({("cisco", "ios_xe")})

#: Placeholder names treated as secrets unless a template says otherwise.
SECRET_NAME_HINTS = frozenset(
    {"password", "secret", "key", "community", "private"})


@dataclass
class TemplateEntry:
    """Metadata overlay for one control's authoritative command."""
    control_id: str
    vendor: str = "cisco"
    platform: str = "ios_xe"
    # Expected configuration contexts, e.g. ["line vty 0 15"]. Empty
    # means global configuration mode.
    contexts: list[str] = field(default_factory=list)
    # Precondition names evaluated by preconditions.py.
    preconditions: list[str] = field(default_factory=list)
    # low | medium | high | critical — seed for the safety classifier.
    risk_level: str = "medium"
    # Explicit safe rollback (PlanChange list). None = try conservative
    # auto-derivation; rollback_prohibited = never derive.
    rollback_override: Optional[list[PlanChange]] = None
    rollback_prohibited: bool = False
    # Placeholder name -> "secret" | "plain". Unknown names fall back to
    # SECRET_NAME_HINTS, then "plain".
    param_types: dict[str, str] = field(default_factory=dict)
    notes: str = ""


def _t(control_id: str, risk_level: str = "medium",
       contexts: Optional[list[str]] = None,
       preconditions: Optional[list[str]] = None,
       rollback_override: Optional[list[PlanChange]] = None,
       rollback_prohibited: bool = False,
       param_types: Optional[dict[str, str]] = None,
       notes: str = "") -> TemplateEntry:
    return TemplateEntry(
        control_id=control_id,
        contexts=list(contexts or []),
        preconditions=list(preconditions or ["vendor_known",
                                             "platform_known",
                                             "control_known",
                                             "command_known"]),
        risk_level=risk_level,
        rollback_override=rollback_override,
        rollback_prohibited=rollback_prohibited,
        param_types=dict(param_types or {}),
        notes=notes,
    )


def _rb(context: str, *commands: str) -> PlanChange:
    return PlanChange(context=context, commands=list(commands))


#: Control-id -> metadata. Covers every Cisco control that carries a
#: real remediation_command (P0 AAA/SSH/Telnet/VTY/HTTP/source-route,
#: P1 CDP/NTP/logging/SNMP, P2 loopback/interface/ACL). Controls with
#: empty commands (1.2.1, 1.5.2-1.5.5, 2.1.6) and unknown controls
#: (OSPF/BGP/Layer-2 have no benchmark controls at all) match nothing
#: and refuse safely.
TEMPLATE_REGISTRY: dict[str, TemplateEntry] = {}


def _register(entry: TemplateEntry) -> None:
    TEMPLATE_REGISTRY[entry.control_id] = entry


# ---------------------------------------------------------------------------
# P0 - AAA (HIGH_RISK; rollback never auto-derived for auth changes)
# ---------------------------------------------------------------------------
for _cid in ("1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6",
             "1.1.7", "1.1.8", "1.1.9", "1.1.10"):
    _register(_t(_cid, "high", rollback_prohibited=True,
                 notes="AAA change: inverse touches authentication"))

# ---------------------------------------------------------------------------
# P0 - SSH / Telnet / VTY
# ---------------------------------------------------------------------------
_register(_t("1.2.2", "high", contexts=["line vty 0 15"],
             rollback_override=[_rb("line vty 0 15",
                                    "transport input telnet ssh")],
             notes="restores prior dual transport; never bare 'no transport'"))
_register(_t("1.2.3", "controlled", contexts=["line aux 0"]))
_register(_t("1.2.5", "high", contexts=["line vty 0 15"],
             param_types={"acl": "plain"},
             notes="management access change; ACL name required"))
_register(_t("1.2.6", "controlled", contexts=["line aux 0"]))
_register(_t("1.2.7", "controlled", contexts=["line con 0"]))
_register(_t("1.2.8", "controlled", contexts=["line vty 0 15"]))
_register(_t("2.1.1", "controlled"))
_register(_t("2.1.2", "controlled"))
_register(_t("2.1.3", "controlled"))
_register(_t("2.1.4", "controlled"))
_register(_t("2.1.5", "high", param_types={"interface": "plain"},
             notes="management-plane source interface"))

# ---------------------------------------------------------------------------
# P0 - HTTP / HTTPS + source routing
# ---------------------------------------------------------------------------
_register(_t("2.1.10", "controlled",
             preconditions=["vendor_known", "platform_known",
                            "control_known", "command_known",
                            "https_available"],
             notes="SAFE-class candidate only when HTTPS already serves"))
for _cid in ("2.1.13", "2.1.14", "2.1.15", "2.1.16"):
    _register(_t(_cid, "controlled"))

# ---------------------------------------------------------------------------
# P1 - CDP / LLDP, NTP, logging, SNMP
# ---------------------------------------------------------------------------
_register(_t("2.1.11", "controlled"))
_register(_t("2.1.12", "controlled"))
_register(_t("2.3.1", "controlled", param_types={"ip-address": "plain"}))
_register(_t("2.3.2", "high", rollback_prohibited=True,
             param_types={"key": "secret"},
             notes="shared secret involved; rollback needs the old key"))
_register(_t("2.3.3", "controlled"))
_register(_t("2.3.4", "controlled"))
for _cid in ("2.2.1", "2.2.2", "2.2.3", "2.2.5", "2.2.6", "2.2.7"):
    _register(_t(_cid, "controlled"))
_register(_t("2.2.4", "controlled", param_types={"ip-address": "plain"}))
_register(_t("1.5.6", "high",
             notes="community ACL change; inverse removes the list"))

# ---------------------------------------------------------------------------
# P1 services (finger/pad/small-servers) + password policy
# ---------------------------------------------------------------------------
for _cid in ("2.1.7", "2.1.8", "2.1.9"):
    _register(_t(_cid, "controlled"))
_register(_t("1.3.1", "controlled"))
_register(_t("1.3.2", "high", rollback_prohibited=True,
             param_types={"password": "secret"},
             notes="secret; rollback would need the old password"))
_register(_t("1.3.4", "controlled"))

# ---------------------------------------------------------------------------
# P2 - loopback / interface + remaining AAA-adjacent
# ---------------------------------------------------------------------------
_register(_t("2.4.1", "high", contexts=["interface Loopback0"],
             rollback_prohibited=True,
             param_types={"ip": "plain", "mask": "plain"},
             notes="interface creation; inverse deletes the interface"))


def get_template(control_id: str, vendor: str = "",
                 platform: str = "") -> Optional[TemplateEntry]:
    """Return the metadata entry for a control, or None (refuse)."""
    entry = TEMPLATE_REGISTRY.get(control_id or "")
    if entry is None:
        return None
    if (entry.vendor, entry.platform) != (
            (vendor or "").strip().lower(),
            (platform or "").strip().lower()):
        return None
    return entry


def param_type(entry: TemplateEntry, name: str) -> str:
    """secret | plain for a placeholder name."""
    if name in entry.param_types:
        return entry.param_types[name]
    lowered = name.lower()
    if any(hint in lowered for hint in SECRET_NAME_HINTS):
        return "secret"
    return "plain"


def supported_control_ids() -> list[str]:
    return sorted(TEMPLATE_REGISTRY)
