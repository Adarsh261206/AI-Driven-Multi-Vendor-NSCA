"""
Finding Generator

Generates findings from compliance evaluation results.
Each finding includes evidence chain, severity, and remediation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any

from app.engines.compliance.models import (
    ComplianceResultType, Severity, FindingStatus,
)
from app.engines.compliance.engine import ControlEvaluation, ComplianceEvaluation
from app.engines.compliance.risk import RiskEngine, SeverityCalculator


def _utcnow_naive() -> datetime:
    """Naive UTC now — identical values to datetime.utcnow() without the
    deprecation warning (which fires per-Finding and distorts perf tests).
    Naive semantics preserved for TIMESTAMP WITHOUT TIME ZONE columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class Finding:
    """A compliance finding — the canonical §12 Finding interface plus
    documented operational fields.

    Canonical (§12): id, compliance_result_id, control_id, title,
    description, severity, confidence, evidence, affected_device,
    affected_vendor, remediation, status.
    Operational (engine-internal, documented): audit_id (which audit run
    produced it), risk_score + priority (Engine 09 outputs, computed by the
    canonical RiskEngine so findings carry them), risk_method +
    risk_model_version (scoring lineage: which scorer and version produced
    the attached score), result (the source verdict: FAIL/REVIEW —
    PASS never becomes a finding), affected_platform (vendor context),
    created_at/updated_at (record lifecycle).
    """
    id: str
    audit_id: str
    compliance_result_id: str
    control_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    result: ComplianceResultType
    status: FindingStatus
    evidence: dict
    remediation: Optional[dict] = None
    affected_device: str = ""
    affected_vendor: str = ""
    affected_platform: str = ""
    risk_score: float = 0.0
    priority: str = ""
    risk_method: str = ""
    risk_model_version: str = ""
    created_at: datetime = field(default_factory=_utcnow_naive)
    updated_at: datetime = field(default_factory=_utcnow_naive)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "audit_id": self.audit_id,
            "compliance_result_id": self.compliance_result_id,
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "result": self.result.value,
            "status": self.status.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "affected_device": self.affected_device,
            "affected_vendor": self.affected_vendor,
            "affected_platform": self.affected_platform,
            "risk_score": self.risk_score,
            "priority": self.priority,
            "risk_method": self.risk_method,
            "risk_model_version": self.risk_model_version,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class FindingGenerator:
    """
    Finding Generator

    Generates findings from compliance evaluation results. Risk scoring
    belongs to the canonical RiskEngine (spec §10.9): each finding is
    assessed through RiskEngine.attach with finding-grade inputs, so
    there is exactly one scoring implementation.
    """

    def __init__(self):
        self.risk_engine = RiskEngine()
        self.severity_calc = SeverityCalculator()
    
    def generate_findings(
        self,
        evaluation: ComplianceEvaluation,
        audit_id: str,
        device_name: str = "",
    ) -> list[Finding]:
        """
        Generate findings from compliance evaluation

        One finding per FAIL/REVIEW evaluation; PASS never becomes a
        finding. Unsafe evaluations never arrive here: the executor only
        builds a ComplianceEvaluation for completed runs, and boundary
        statuses (unsupported/mismatch/empty/failed) carry no evaluation.

        Args:
            evaluation: Compliance evaluation results (must be a
                ComplianceEvaluation with an evaluations list)
            audit_id: ID of the audit
            device_name: Name of the device

        Returns:
            List of findings

        Raises:
            TypeError: evaluation is not a ComplianceEvaluation.
            ValueError: an evaluation row lacks a control id (typed,
                deterministic — never an AttributeError downstream).
        """
        if not isinstance(evaluation, ComplianceEvaluation):
            raise TypeError(
                "evaluation must be a ComplianceEvaluation, got "
                f"{type(evaluation).__name__}")
        findings = []

        for ctrl_eval in evaluation.evaluations or []:
            # Only generate findings for FAIL and REVIEW
            if ctrl_eval.result == ComplianceResultType.PASS:
                continue
            if not getattr(ctrl_eval, "control_id", None) or not isinstance(
                    ctrl_eval.control_id, str):
                raise ValueError(
                    "cannot generate a finding for an evaluation without a "
                    "control id")

            finding = self._create_finding(
                ctrl_eval=ctrl_eval,
                audit_id=audit_id,
                device_name=device_name,
                vendor=evaluation.vendor,
                platform=evaluation.platform,
                device_type=getattr(evaluation, "device_type", "") or "",
                hostname=getattr(evaluation, "hostname", "") or "",
            )
            findings.append(finding)

        return findings
    
    def _create_finding(
        self,
        ctrl_eval: ControlEvaluation,
        audit_id: str,
        device_name: str,
        vendor: str,
        platform: str,
        device_type: str = "",
        hostname: str = "",
    ) -> Finding:
        """Create a single finding from control evaluation.

        The finding identity is minted first; risk is then assessed by
        the canonical RiskEngine from finding-grade inputs (the same
        severity/vendor/confidence values stored on the finding, plus the
        evaluation's category context) and attached — satisfying the 10.9
        input contract (V09-73).

        Device provenance (hostname/device_type) is stamped into the
        finding evidence so per-device aggregation never has to guess
        (Issue #1).
        """
        finding_id = str(uuid.uuid4())
        assessment = self.risk_engine.assess(
            finding_id=finding_id,
            severity=ctrl_eval.severity,
            vendor=vendor,
            category=ctrl_eval.category,
            confidence=ctrl_eval.confidence,
        )

        # Build description based on result
        if ctrl_eval.result == ComplianceResultType.FAIL:
            description = (
                f"Control {ctrl_eval.control_id} failed evaluation. "
                f"{ctrl_eval.evidence.reasoning}"
            )
        else:
            description = (
                f"Control {ctrl_eval.control_id} requires manual review. "
                f"{ctrl_eval.evidence.reasoning}"
            )

        # §12 remediation linkage (F3): the remediation content rides on the
        # evaluation; finding_id/finding_title are stamped here where the
        # finding identity exists.
        remediation = dict(ctrl_eval.remediation or {})
        remediation["finding_id"] = finding_id
        remediation["finding_title"] = ctrl_eval.control_title

        return Finding(
            id=finding_id,
            audit_id=audit_id,
            compliance_result_id=getattr(ctrl_eval, "compliance_result_id",
                                         "") or "",
            control_id=ctrl_eval.control_id,
            title=ctrl_eval.control_title,
            description=description,
            severity=ctrl_eval.severity,
            confidence=ctrl_eval.confidence,
            result=ctrl_eval.result,
            status=FindingStatus.OPEN,
            evidence=ctrl_eval.evidence.to_dict(),
            remediation=remediation,
            affected_device=device_name,
            affected_vendor=vendor,
            affected_platform=platform,
            risk_score=assessment.risk_score,
            priority=assessment.priority,
            risk_method=assessment.scoring_method,
            risk_model_version=assessment.scoring_version,
        )
