"""
Finding Generator

Generates findings from compliance evaluation results.
Each finding includes evidence chain, severity, and remediation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any

from app.engines.compliance.models import (
    ComplianceResultType, Severity, FindingStatus,
)
from app.engines.compliance.engine import ControlEvaluation, ComplianceEvaluation
from app.engines.compliance.evidence import EvidenceChain


@dataclass
class Finding:
    """A compliance finding"""
    id: str
    audit_id: str
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
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "audit_id": self.audit_id,
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
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class SeverityCalculator:
    """Calculate risk scores and priority levels"""
    
    # Severity base scores
    SEVERITY_SCORES = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
    }
    
    # Impact multipliers
    VENDOR_IMPACT = {
        "cisco": 1.2,
        "paloalto": 1.2,
        "fortinet": 1.1,
        "juniper": 1.1,
    }
    
    CATEGORY_IMPACT = {
        "authentication": 1.3,
        "ssh": 1.2,
        "management": 1.1,
        "logging": 1.0,
        "snmp": 1.0,
        "access_control": 1.1,
    }
    
    # Priority thresholds
    PRIORITY_THRESHOLDS = [
        (80, "P1"),
        (60, "P2"),
        (40, "P3"),
        (0, "P4"),
    ]
    
    def calculate_risk_score(
        self,
        severity: Severity,
        vendor: str = "",
        category: str = "",
        confidence: float = 1.0,
    ) -> float:
        """
        Calculate risk score for a finding
        
        ML-enhanced: Uses RandomForest model if available, fallback to deterministic formula.
        Formula: severity_score * vendor_impact * category_impact * confidence_factor
        Normalized to 0-100
        """
        # Try ML model first (real, not hardcoded)
        try:
            from app.ml.model import get_risk_predictor
            model, available = get_risk_predictor()
            if available:
                sev_map = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
                sev_str = severity.value if hasattr(severity, 'value') else str(severity)
                sev_num = sev_map.get(sev_str.upper(), 1)
                v_mult = self.VENDOR_IMPACT.get(vendor.lower(), 1.0)
                c_mult = self.CATEGORY_IMPACT.get(category, 1.0)
                # ML predict — 4 features as trained
                pred = model.predict([[sev_num, v_mult, c_mult, confidence]])[0]
                return round(float(max(0, min(100, pred))), 1)
        except Exception:
            pass

        base_score = self.SEVERITY_SCORES.get(severity, 5.0)
        vendor_mult = self.VENDOR_IMPACT.get(vendor.lower(), 1.0)
        category_mult = self.CATEGORY_IMPACT.get(category, 1.0)
        confidence_factor = max(confidence, 0.5)
        
        raw_score = base_score * vendor_mult * category_mult * confidence_factor
        
        # Normalize to 0-100 (max possible ~10 * 1.2 * 1.3 * 1.0 = 15.6)
        normalized = min(100.0, (raw_score / 15.6) * 100)
        
        return round(normalized, 1)
    
    def calculate_priority(self, risk_score: float) -> str:
        """Calculate priority level from risk score"""
        for threshold, priority in self.PRIORITY_THRESHOLDS:
            if risk_score >= threshold:
                return priority
        return "P4"


class FindingGenerator:
    """
    Finding Generator
    
    Generates findings from compliance evaluation results.
    """
    
    def __init__(self):
        self.severity_calc = SeverityCalculator()
    
    def generate_findings(
        self,
        evaluation: ComplianceEvaluation,
        audit_id: str,
        device_name: str = "",
    ) -> list[Finding]:
        """
        Generate findings from compliance evaluation
        
        Args:
            evaluation: Compliance evaluation results
            audit_id: ID of the audit
            device_name: Name of the device
            
        Returns:
            List of findings
        """
        findings = []
        
        for ctrl_eval in evaluation.evaluations:
            # Only generate findings for FAIL and REVIEW
            if ctrl_eval.result == ComplianceResultType.PASS:
                continue
            
            finding = self._create_finding(
                ctrl_eval=ctrl_eval,
                audit_id=audit_id,
                device_name=device_name,
                vendor=evaluation.vendor,
                platform=evaluation.platform,
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
    ) -> Finding:
        """Create a single finding from control evaluation"""
        
        # Calculate risk score
        risk_score = self.severity_calc.calculate_risk_score(
            severity=ctrl_eval.severity,
            vendor=vendor,
            category=ctrl_eval.category,
            confidence=ctrl_eval.confidence,
        )
        
        priority = self.severity_calc.calculate_priority(risk_score)
        
        # Build description based on result
        if ctrl_eval.result == ComplianceResultType.FAIL:
            description = (
                f"Control {ctrl_eval.control_id} failed evaluation. "
                f"{ctrl_eval.evidence.result_reasoning}"
            )
        else:
            description = (
                f"Control {ctrl_eval.control_id} requires manual review. "
                f"{ctrl_eval.evidence.result_reasoning}"
            )
        
        return Finding(
            id=str(uuid.uuid4()),
            audit_id=audit_id,
            control_id=ctrl_eval.control_id,
            title=ctrl_eval.control_title,
            description=description,
            severity=ctrl_eval.severity,
            confidence=ctrl_eval.confidence,
            result=ctrl_eval.result,
            status=FindingStatus.OPEN,
            evidence=ctrl_eval.evidence.to_dict(),
            remediation=ctrl_eval.remediation,
            affected_device=device_name,
            affected_vendor=vendor,
            affected_platform=platform,
            risk_score=risk_score,
            priority=priority,
        )
