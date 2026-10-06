"""Structured remediation-plan contracts (dataclasses + to_dict).

Conventions mirror app.engines.compliance.remediation and
app.engines.normalization: typed dataclasses, explicit to_dict(), and
a single ValueError-family error type. Nothing here touches a device.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


class RemediationPlanError(ValueError):
    """A remediation-plan input or transition violates the contract."""


class SafetyClass(str, enum.Enum):
    SAFE = "safe"
    CONTROLLED = "controlled"
    HIGH_RISK = "high_risk"
    BLOCKED = "blocked"


class PlanStatus(str, enum.Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    VALIDATION_FAILED = "validation_failed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    APPROVAL_REJECTED = "approval_rejected"
    APPLYING = "applying"
    APPLIED = "applied"
    APPLY_FAILED = "apply_failed"
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"
    ROLLBACK_REQUIRED = "rollback_required"
    ROLLED_BACK = "rolled_back"
    STALE_PLAN = "stale_plan"


#: Strict lifecycle transitions. No API accepts a status value; only
#: server-side action endpoints move plans along these edges.
PLAN_TRANSITIONS: dict[PlanStatus, frozenset[PlanStatus]] = {
    PlanStatus.DRAFT: frozenset({PlanStatus.VALIDATED,
                                 PlanStatus.VALIDATION_FAILED}),
    PlanStatus.VALIDATED: frozenset({PlanStatus.AWAITING_APPROVAL}),
    PlanStatus.VALIDATION_FAILED: frozenset(),
    PlanStatus.AWAITING_APPROVAL: frozenset({PlanStatus.APPROVED,
                                             PlanStatus.APPROVAL_REJECTED,
                                             PlanStatus.STALE_PLAN}),
    PlanStatus.APPROVED: frozenset({PlanStatus.APPLYING,
                                    PlanStatus.STALE_PLAN}),
    PlanStatus.APPROVAL_REJECTED: frozenset(),
    PlanStatus.APPLYING: frozenset({PlanStatus.APPLIED,
                                    PlanStatus.APPLY_FAILED}),
    PlanStatus.APPLIED: frozenset({PlanStatus.VERIFIED,
                                   PlanStatus.VERIFICATION_FAILED,
                                   PlanStatus.ROLLBACK_REQUIRED}),
    PlanStatus.APPLY_FAILED: frozenset({PlanStatus.ROLLBACK_REQUIRED}),
    PlanStatus.VERIFIED: frozenset(),
    PlanStatus.VERIFICATION_FAILED: frozenset(
        {PlanStatus.ROLLBACK_REQUIRED}),
    PlanStatus.ROLLBACK_REQUIRED: frozenset({PlanStatus.ROLLED_BACK}),
    PlanStatus.ROLLED_BACK: frozenset(),
    PlanStatus.STALE_PLAN: frozenset(),
}


def check_transition(frm: PlanStatus, to: PlanStatus) -> None:
    """Raise RemediationPlanError unless frm -> to is a legal edge."""
    allowed = PLAN_TRANSITIONS.get(frm, frozenset())
    if to not in allowed:
        raise RemediationPlanError(
            f"illegal plan transition {frm.value} -> {to.value}")


def coerce_status(value: Any) -> PlanStatus:
    if isinstance(value, PlanStatus):
        return value
    if isinstance(value, str):
        try:
            return PlanStatus(value)
        except ValueError:
            pass
    raise RemediationPlanError(f"unknown plan status {value!r}")


def coerce_safety(value: Any) -> SafetyClass:
    if isinstance(value, SafetyClass):
        return value
    if isinstance(value, str):
        try:
            return SafetyClass(value)
        except ValueError:
            pass
    raise RemediationPlanError(f"unknown safety class {value!r}")


@dataclass
class PlanChange:
    """Structured commands under one configuration context.

    context "" means global configuration mode. commands are single
    device lines (multi-line remediation is a list, never one blob).
    """
    context: str = ""
    commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"context": self.context, "commands": list(self.commands)}


@dataclass
class Precondition:
    """One deterministic precondition check result."""
    name: str
    passed: bool
    severity: str = "info"  # info | warning | critical
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed,
                "severity": self.severity, "message": self.message}


@dataclass
class PlanParam:
    """A <placeholder> the template needs resolved.

    The descriptor NEVER carries a secret value: for secrets only
    supplied/redacted flags persist. Resolved plain values live in the
    plan's commands, never here.
    """
    name: str
    type: str = "plain"  # plain | secret
    required: bool = True
    supplied: bool = False
    redacted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.type,
                "required": self.required, "supplied": self.supplied,
                "redacted": self.redacted}


@dataclass
class PlanDevice:
    name: str = ""
    vendor: str = ""
    platform: str = ""
    model: Optional[str] = None
    version: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "vendor": self.vendor,
                "platform": self.platform, "model": self.model,
                "version": self.version}


@dataclass
class PlanFinding:
    title: str = ""
    severity: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "severity": self.severity,
                "confidence": self.confidence}


@dataclass
class PlanDiff:
    before: list[str] = field(default_factory=list)
    after: list[str] = field(default_factory=list)
    add: list[str] = field(default_factory=list)
    remove: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"before": list(self.before), "after": list(self.after),
                "add": list(self.add), "remove": list(self.remove)}


@dataclass
class RemediationPlan:
    """The structured plan: finding -> validated changes -> approval."""
    plan_id: str = ""
    finding_id: str = ""
    control_id: str = ""
    device: PlanDevice = field(default_factory=PlanDevice)
    finding: PlanFinding = field(default_factory=PlanFinding)
    preconditions: list[Precondition] = field(default_factory=list)
    changes: list[PlanChange] = field(default_factory=list)
    diff: PlanDiff = field(default_factory=PlanDiff)
    rollback: list[PlanChange] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)
    params: list[PlanParam] = field(default_factory=list)
    safety_class: SafetyClass = SafetyClass.BLOCKED
    safe_to_apply: bool = False
    requires_approval: bool = True
    status: PlanStatus = PlanStatus.DRAFT
    configuration_id: Optional[str] = None
    configuration_hash_before: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "control_id": self.control_id,
            "device": self.device.to_dict(),
            "finding": self.finding.to_dict(),
            "preconditions": [p.to_dict() for p in self.preconditions],
            "changes": {
                "add": list(self.diff.add),
                "remove": list(self.diff.remove),
                "contexts": [c.to_dict() for c in self.changes],
            },
            "diff": self.diff.to_dict(),
            "rollback": [c.to_dict() for c in self.rollback],
            "verification": list(self.verification),
            "risk_flags": list(self.risk_flags),
            "params": [p.to_dict() for p in self.params],
            "safety_class": self.safety_class.value,
            "safe_to_apply": self.safe_to_apply,
            "requires_approval": self.requires_approval,
            "status": self.status.value,
            "configuration_id": self.configuration_id,
            "configuration_hash_before": self.configuration_hash_before,
        }


def new_plan_id() -> str:
    return f"plan-{uuid.uuid4().hex[:12]}"


def remediation_plan_from_dict(data: dict[str, Any]) -> RemediationPlan:
    """Rebuild a RemediationPlan from its to_dict() form (never secrets:
    descriptors carry flags only, so reconstruction is leak-free)."""
    if not isinstance(data, dict):
        raise RemediationPlanError(
            f"plan payload must be a mapping, got {type(data).__name__}")
    device = data.get("device") or {}
    finding = data.get("finding") or {}
    diff = data.get("diff") or {}
    changes = data.get("changes") or {}
    plan = RemediationPlan(
        plan_id=str(data.get("plan_id") or ""),
        finding_id=str(data.get("finding_id") or ""),
        control_id=str(data.get("control_id") or ""),
        device=PlanDevice(
            name=str(device.get("name") or ""),
            vendor=str(device.get("vendor") or ""),
            platform=str(device.get("platform") or ""),
            model=device.get("model"),
            version=device.get("version")),
        finding=PlanFinding(
            title=str(finding.get("title") or ""),
            severity=str(finding.get("severity") or ""),
            confidence=float(finding.get("confidence") or 0.0)),
        diff=PlanDiff(
            before=list(diff.get("before") or []),
            after=list(diff.get("after") or []),
            add=list(diff.get("add") or []),
            remove=list(diff.get("remove") or [])),
        verification=[str(v) for v in (data.get("verification") or [])],
        risk_flags=[str(f) for f in (data.get("risk_flags") or [])],
        safe_to_apply=bool(data.get("safe_to_apply", False)),
        requires_approval=bool(data.get("requires_approval", True)),
        status=coerce_status(data.get("status") or "draft"),
        configuration_id=data.get("configuration_id"),
        configuration_hash_before=data.get("configuration_hash_before"),
    )
    for raw in (data.get("preconditions") or []):
        if isinstance(raw, dict):
            plan.preconditions.append(Precondition(
                name=str(raw.get("name") or ""),
                passed=bool(raw.get("passed", False)),
                severity=str(raw.get("severity") or "info"),
                message=str(raw.get("message") or "")))
    for raw in (changes.get("contexts") or []):
        if isinstance(raw, dict):
            plan.changes.append(PlanChange(
                context=str(raw.get("context") or ""),
                commands=[str(c) for c in (raw.get("commands") or [])]))
    for raw in (data.get("rollback") or []):
        if isinstance(raw, dict):
            plan.rollback.append(PlanChange(
                context=str(raw.get("context") or ""),
                commands=[str(c) for c in (raw.get("commands") or [])]))
    for raw in (data.get("params") or []):
        if isinstance(raw, dict):
            plan.params.append(PlanParam(
                name=str(raw.get("name") or ""),
                type=str(raw.get("type") or "plain"),
                required=bool(raw.get("required", True)),
                supplied=bool(raw.get("supplied", False)),
                redacted=bool(raw.get("redacted", False))))
    plan.safety_class = coerce_safety(data.get("safety_class") or "blocked")
    return plan
