"""
Evidence Chain Builder

Builds complete evidence chains for compliance findings.
Every finding traces: RAW → PARSED → NORMALIZED → CONTROL → EXPECTED → ACTUAL → RESULT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any

from app.engines.compliance.models import (
    Control, ComplianceResultType, Severity, Operator,
)


@dataclass
class EvidenceChain:
    """Complete evidence chain for a compliance finding"""
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
    
    # Control reference
    control_id: str = ""
    control_description: str = ""
    
    # Evaluation
    expected_value: Any = None
    actual_value: Any = None
    operator: str = ""
    result: str = ""
    result_reasoning: str = ""
    
    # Confidence
    overall_confidence: float = 0.0
    
    # Vendor context
    vendor: str = ""
    platform: str = ""
    vendor_specific_syntax: str = ""
    
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
            "control_description": self.control_description,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "operator": self.operator,
            "result": self.result,
            "result_reasoning": self.result_reasoning,
            "overall_confidence": self.overall_confidence,
            "vendor": self.vendor,
            "platform": self.platform,
            "vendor_specific_syntax": self.vendor_specific_syntax,
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
            control_description=control.description,
            expected_value=expected_value,
            actual_value=actual_value,
            operator=operator_str,
            result=result.value,
            result_reasoning=reasoning,
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
                return actual is True or actual == "true" or actual == True
            elif operator == Operator.IS_FALSE:
                return actual is False or actual == "false" or actual == False
            elif operator == Operator.IS_SET:
                return actual is not None and actual != ""
            elif operator == Operator.IS_NOT_SET:
                return actual is None or actual == ""
            elif operator == Operator.REGEX_MATCH:
                import re
                return bool(re.match(str(expected), str(actual)))
            else:
                return False
        except (ValueError, TypeError):
            return False
