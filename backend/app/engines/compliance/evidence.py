"""
Evidence Chain Builder

Builds complete evidence chains for compliance findings.
Every finding traces: RAW → PARSED → NORMALIZED → CONTROL → EXPECTED → ACTUAL → RESULT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any

from app.engines.compliance.models import (
    Control, ComplianceResultType, Operator,
)


@dataclass
class EvidenceChain:
    """Complete evidence chain for a compliance finding.

    Leads with the eight §12 canonical keys (raw_config, parsed_value,
    normalized_value, security_control, expected_value, actual_value,
    result, reasoning); the rest is traceability metadata.
    """
    # Raw configuration
    raw_config: str = ""
    raw_config_line_numbers: list[int] = field(default_factory=list)

    # Parsed value
    parsed_value: Any = None
    parsed_path: str = ""

    # Normalized value
    normalized_value: Any = None
    universal_model_path: str = ""
    normalization_confidence: float = 0.0

    # Control reference (§12 security_control names the evaluated control)
    control_id: str = ""
    security_control: str = ""
    control_description: str = ""
    
    # Evaluation
    expected_value: Any = None
    actual_value: Any = None
    operator: str = ""
    result: str = ""
    reasoning: str = ""
    
    # Confidence
    overall_confidence: float = 0.0
    
    # Vendor context
    vendor: str = ""
    platform: str = ""
    vendor_specific_syntax: str = ""

    # REVIEW reason code + evaluation method (carried from benchmark
    # evidence so persisted/reported evidence stays explainable).
    review_code: str = ""
    evaluation_method: str = ""

    # Benchmark identity (carried from benchmark evidence for §6
    # applicability reporting; "" when unknown — never invented).
    benchmark_id: str = ""
    benchmark_name: str = ""
    framework_version: str = ""
    framework: str = ""

    # Scope + states (§8): every result retains its evaluation scope, the
    # observed configuration state and the required state.
    scope: str = ""
    observed_state: str = ""
    expected_state: str = ""
    # Scope cardinality (Issue #1): evidence blocks vs affected interfaces.
    evidence_block_count: int = 0
    affected_scope_count: int = 0

    # Device provenance (Issue #1): hostname + device type stamped from the
    # single authoritative detection, so findings inherit lineage and
    # finding evidence stays identical to evaluation evidence.
    hostname: str = ""
    device_type: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_config": self.raw_config,
            "raw_config_line_numbers": self.raw_config_line_numbers,
            "parsed_value": self.parsed_value,
            "parsed_path": self.parsed_path,
            "normalized_value": self.normalized_value,
            "universal_model_path": self.universal_model_path,
            "normalization_confidence": self.normalization_confidence,
            "control_id": self.control_id,
            "security_control": self.security_control,
            "control_description": self.control_description,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "operator": self.operator,
            "result": self.result,
            "reasoning": self.reasoning,
            "overall_confidence": self.overall_confidence,
            "vendor": self.vendor,
            "platform": self.platform,
            "vendor_specific_syntax": self.vendor_specific_syntax,
            "review_code": self.review_code,
            "evaluation_method": self.evaluation_method,
            "benchmark_id": self.benchmark_id,
            "benchmark_name": self.benchmark_name,
            "framework_version": self.framework_version,
            "framework": self.framework,
            "scope": self.scope,
            "observed_state": self.observed_state,
            "expected_state": self.expected_state,
            "evidence_block_count": self.evidence_block_count,
            "affected_scope_count": self.affected_scope_count,
            "hostname": self.hostname,
            "device_type": self.device_type,
        }


class EvidenceChainBuilder:
    """
    Evidence Chain Builder
    
    Constructs complete evidence chains for compliance findings.
    """
    
    def build(
        self,
        control: Control,
        normalized_config: dict[str, Any],
        actual_value: Any,
        confidence: float,
        vendor: str = "",
        platform: str = "",
        raw_config: str = "",
        raw_line_numbers: Optional[list[int]] = None,
    ) -> EvidenceChain:
        """
        Build an evidence chain for a compliance evaluation
        
        Args:
            control: The compliance control being evaluated
            normalized_config: The normalized configuration dict
            actual_value: The actual value extracted from config
            confidence: Normalization confidence
            vendor: Device vendor
            platform: Device platform
            raw_config: Original raw configuration
            raw_line_numbers: Line numbers in raw config
            
        Returns:
            Complete EvidenceChain
        """
        # Get expected value from control rule
        expected_value = None
        operator_str = ""
        if control.rule and control.rule.expected:
            expected_value = control.rule.expected.value
            operator_str = control.rule.expected.operator.value
        
        # Determine result
        result, reasoning = self._evaluate(
            control=control,
            actual_value=actual_value,
            expected_value=expected_value,
            confidence=confidence,
        )
        
        # Build evidence chain
        chain = EvidenceChain(
            raw_config=raw_config,
            raw_config_line_numbers=raw_line_numbers or [],
            parsed_value=actual_value,
            parsed_path=control.rule.target.model_path if control.rule else "",
            normalized_value=actual_value,
            universal_model_path=control.rule.target.model_path if control.rule else "",
            normalization_confidence=confidence,
            control_id=control.id,
            security_control=control.id,
            control_description=control.description,
            expected_value=expected_value,
            actual_value=actual_value,
            operator=operator_str,
            result=result.value,
            reasoning=reasoning,
            overall_confidence=confidence,
            vendor=vendor,
            platform=platform,
        )
        
        return chain
    
    def _evaluate(
        self,
        control: Control,
        actual_value: Any,
        expected_value: Any,
        confidence: float,
    ) -> tuple[ComplianceResultType, str]:
        """
        Evaluate a control against actual value
        
        Returns:
            Tuple of (result, reasoning)
        """
        # If no rule, result is REVIEW
        if not control.rule:
            return ComplianceResultType.REVIEW, "No evaluation rule defined"
        
        # If confidence too low, force REVIEW
        if confidence < 0.7:
            return (
                ComplianceResultType.REVIEW,
                f"Normalization confidence {confidence:.2f} is below threshold 0.7. "
                "Manual review required to verify configuration.",
            )
        
        # If actual value is None/missing, result is REVIEW (not FAIL)
        if actual_value is None:
            return (
                ComplianceResultType.REVIEW,
                f"Value for '{control.rule.target.model_path}' was not observed "
                "in the configuration. Cannot determine compliance without evidence.",
            )
        
        # Apply operator
        operator = control.rule.expected.operator
        expected = control.rule.expected.value
        
        passed = self._apply_operator(actual_value, expected, operator)
        
        if passed:
            return (
                ComplianceResultType.PASS,
                f"Actual value '{actual_value}' meets expected condition "
                f"'{operator.value} {expected}'.",
            )
        else:
            return (
                ComplianceResultType.FAIL,
                f"Actual value '{actual_value}' does not meet expected condition "
                f"'{operator.value} {expected}'.",
            )
    
    def _apply_operator(self, actual: Any, expected: Any, operator: Operator) -> bool:
        """Apply comparison operator"""
        try:
            if operator == Operator.EQUALS:
                return actual == expected
            elif operator == Operator.NOT_EQUALS:
                return actual != expected
            elif operator == Operator.GREATER_THAN:
                return float(actual) > float(expected)
            elif operator == Operator.LESS_THAN:
                return float(actual) < float(expected)
            elif operator == Operator.GREATER_EQUAL:
                return float(actual) >= float(expected)
            elif operator == Operator.LESS_EQUAL:
                return float(actual) <= float(expected)
            elif operator == Operator.CONTAINS:
                return str(expected) in str(actual)
            elif operator == Operator.NOT_CONTAINS:
                return str(expected) not in str(actual)
            elif operator == Operator.IN:
                if isinstance(expected, list):
                    return actual in expected
                return actual == expected
            elif operator == Operator.NOT_IN:
                if isinstance(expected, list):
                    return actual not in expected
                return actual != expected
            elif operator == Operator.IS_TRUE:
                # Equivalent to `actual == True or actual == "true"`
                # (True/1/1.0 all compare equal to True) without E712.
                return actual in (True, 1, 1.0) or actual == "true"
            elif operator == Operator.IS_FALSE:
                # Equivalent to `actual == False or actual == "false"`.
                return actual in (False, 0) or actual == "false"
            elif operator == Operator.IS_SET:
                return actual is not None and actual != ""
            elif operator == Operator.IS_NOT_SET:
                return actual is None or actual == ""
            elif operator == Operator.REGEX_MATCH:
                import re
                # Unanchored search — the single canonical regex semantics
                # (F8/F10 drift fix; matches selection.apply_operator).
                return bool(re.search(str(expected), str(actual)))
            else:
                return False
        except (ValueError, TypeError):
            return False
