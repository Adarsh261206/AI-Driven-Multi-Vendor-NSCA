"""
Rule Engine Core

Deterministic compliance evaluation engine.
Evaluates normalized configurations against security framework controls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any

from app.engines.compliance.models import (
    Control, ComplianceResultType, Severity, RuleType,
)
from app.engines.compliance.evidence import EvidenceChain, EvidenceChainBuilder


@dataclass
class ControlEvaluation:
    """Result of evaluating a single control"""
    control_id: str
    control_title: str
    control_description: str
    severity: Severity
    category: str
    result: ComplianceResultType
    confidence: float
    evidence: EvidenceChain
    remediation: Optional[dict] = None
    # Authoritative framework attribution from the control's own metadata
    # (F3) — attached by the canonical path so persistence cannot infer it.
    framework: str = ""
    framework_version: str = ""
    # Persistence linkage (E08 F1): the compliance_results row id, attached
    # by the persistence layer after insert (empty before persistence).
    compliance_result_id: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_title": self.control_title,
            "control_description": self.control_description,
            "severity": self.severity.value,
            "category": self.category,
            "result": self.result.value,
            "confidence": self.confidence,
            "evidence": self.evidence.to_dict(),
            "remediation": self.remediation,
        }


@dataclass
class ComplianceEvaluation:
    """Complete compliance evaluation result"""
    evaluations: list[ControlEvaluation] = field(default_factory=list)
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    review: int = 0
    overall_score: float = 0.0
    vendor: str = ""
    platform: str = ""
    # E05 F5: provenance of the single authoritative normalization result.
    normalization_id: Optional[str] = None
    universal_model_version: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluations": [e.to_dict() for e in self.evaluations],
            "summary": {
                "total_controls": self.total_controls,
                "passed": self.passed,
                "failed": self.failed,
                "review": self.review,
                "overall_score": self.overall_score,
                "vendor": self.vendor,
                "platform": self.platform,
                "normalization_id": self.normalization_id,
                "universal_model_version": self.universal_model_version,
            },
        }


class RuleEngine:
    """DEPRECATED — retired legacy evaluator (F10).

    Deterministic compliance evaluation engine. No LLM used for PASS/FAIL
    decisions.

    This class is NOT part of the canonical audit path (the executor uses
    BenchmarkExecutionEngine exclusively). It is retained only so existing
    unit tests keep importing; no production code may instantiate it for
    real evaluations.
    """
    
    def __init__(self):
        self.evidence_builder = EvidenceChainBuilder()
    
    def evaluate(
        self,
        controls: list[Control],
        normalized_config: dict[str, Any],
        confidence: float = 0.9,
        vendor: str = "",
        platform: str = "",
        raw_config: str = "",
    ) -> ComplianceEvaluation:
        """
        Evaluate all applicable controls against normalized configuration
        
        Args:
            controls: List of controls to evaluate
            normalized_config: Normalized configuration from Phase 2
            confidence: Normalization confidence
            vendor: Device vendor
            platform: Device platform
            original_config: Original raw configuration
            
        Returns:
            ComplianceEvaluation with all results
        """
        evaluation = ComplianceEvaluation(
            vendor=vendor,
            platform=platform,
        )
        
        for control in controls:
            if not control.enabled:
                continue
            
            # Check if control is applicable to this vendor/platform
            if not self._is_control_applicable(control, vendor, platform):
                continue
            
            # Evaluate the control
            result = self._evaluate_control(
                control=control,
                normalized_config=normalized_config,
                confidence=confidence,
                vendor=vendor,
                platform=platform,
                raw_config=raw_config,
            )
            
            evaluation.evaluations.append(result)
            
            # Update counters
            if result.result == ComplianceResultType.PASS:
                evaluation.passed += 1
            elif result.result == ComplianceResultType.FAIL:
                evaluation.failed += 1
            elif result.result == ComplianceResultType.REVIEW:
                evaluation.review += 1
        
        # Set total controls to number of evaluations (applicable controls only)
        evaluation.total_controls = len(evaluation.evaluations)
        
        # Calculate overall score (excluding REVIEW results)
        total_decisive = evaluation.passed + evaluation.failed
        if total_decisive > 0:
            evaluation.overall_score = (evaluation.passed / total_decisive) * 100
        else:
            evaluation.overall_score = 0.0
        
        return evaluation
    
    def _is_control_applicable(
        self,
        control: Control,
        vendor: str,
        platform: str,
    ) -> bool:
        """Check if a control is applicable to the given vendor/platform"""
        # If control has no vendor requirement, it's applicable
        if control.vendor is None:
            return True
        
        # Check vendor match
        if control.vendor.lower() != vendor.lower():
            return False
        
        # Check platform match if specified
        if control.platform and control.platform.lower() != platform.lower():
            return False
        
        return True
    
    def _evaluate_control(
        self,
        control: Control,
        normalized_config: dict[str, Any],
        confidence: float,
        vendor: str,
        platform: str,
        raw_config: str,
    ) -> ControlEvaluation:
        """Evaluate a single control"""
        
        # Extract actual value from normalized config
        actual_value = self._extract_value(
            normalized_config,
            control.rule.target.model_path if control.rule else "",
        )
        
        # Build evidence chain
        evidence = self.evidence_builder.build(
            control=control,
            normalized_config=normalized_config,
            actual_value=actual_value,
            confidence=confidence,
            vendor=vendor,
            platform=platform,
            raw_config=raw_config,
        )
        
        # Build remediation if FAIL
        remediation = None
        if evidence.result == "FAIL" and control.remediation:
            remediation = {
                "title": control.remediation.title,
                "description": control.remediation.description,
                "why_it_matters": control.remediation.why_it_matters,
                "recommended_config": control.remediation.recommended_config,
                "verification_steps": control.remediation.verification_steps,
                "rollback_steps": control.remediation.rollback_steps,
                "references": control.remediation.references,
            }
        
        # Parse result
        result = ComplianceResultType(evidence.result)
        
        return ControlEvaluation(
            control_id=control.id,
            control_title=control.title,
            control_description=control.description,
            severity=control.severity,
            category=control.category,
            result=result,
            confidence=evidence.overall_confidence,
            evidence=evidence,
            remediation=remediation,
        )
    
    def _extract_value(self, config: dict, path: str) -> Optional[Any]:
        """Extract a nested value from config using dot-separated path"""
        if not path:
            return None
        
        parts = path.split(".")
        current = config
        
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current
