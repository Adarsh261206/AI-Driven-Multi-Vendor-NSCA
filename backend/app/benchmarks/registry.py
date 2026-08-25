"""Control Registry - manages benchmark controls and their mappings."""

from __future__ import annotations

from typing import Any, Optional

from app.benchmarks.models import (
    AssessmentStatus,
    BenchmarkControl,
    BenchmarkRegistry,
    ControlSeverity,
)


class ControlRegistry:
    """
    Central registry for all benchmark controls.

    Provides lookup by control_id, vendor/platform filtering,
    and mapping to Universal Security Model paths.
    """

    def __init__(self) -> None:
        self._controls: dict[str, BenchmarkControl] = {}
        self._by_vendor_platform: dict[str, list[BenchmarkControl]] = {}
        self._by_category: dict[str, list[BenchmarkControl]] = {}
        self._by_model_path: dict[str, list[BenchmarkControl]] = {}
        self._registries: dict[str, BenchmarkRegistry] = {}

    def register_benchmark(self, registry: BenchmarkRegistry) -> None:
        """Register a full benchmark registry."""
        key = f"{registry.vendor}:{registry.platform}:{registry.benchmark_id}"
        self._registries[key] = registry
        for control in registry.controls:
            self.register_control(control)

    def register_control(self, control: BenchmarkControl) -> None:
        """Register a single control."""
        self._controls[control.control_id] = control

        vp_key = f"{control.vendor}:{control.platform}"
        if vp_key not in self._by_vendor_platform:
            self._by_vendor_platform[vp_key] = []
        self._by_vendor_platform[vp_key].append(control)

        if control.category not in self._by_category:
            self._by_category[control.category] = []
        self._by_category[control.category].append(control)

        if control.target_model_path:
            if control.target_model_path not in self._by_model_path:
                self._by_model_path[control.target_model_path] = []
            self._by_model_path[control.target_model_path].append(control)

    def get_control(self, control_id: str) -> Optional[BenchmarkControl]:
        """Get a control by its ID."""
        return self._controls.get(control_id)

    def get_controls_by_vendor_platform(
        self, vendor: str, platform: str
    ) -> list[BenchmarkControl]:
        """Get all controls for a specific vendor and platform."""
        return self._by_vendor_platform.get(f"{vendor}:{platform}", [])

    def get_controls_by_category(self, category: str) -> list[BenchmarkControl]:
        """Get all controls in a category."""
        return self._by_category.get(category, [])

    def get_controls_by_model_path(self, model_path: str) -> list[BenchmarkControl]:
        """Get all controls mapped to a specific model path."""
        return self._by_model_path.get(model_path, [])

    def get_automated_controls(
        self, vendor: Optional[str] = None, platform: Optional[str] = None
    ) -> list[BenchmarkControl]:
        """Get all automated controls, optionally filtered by vendor/platform."""
        controls = self._filter_by_vendor_platform(vendor, platform)
        return [c for c in controls if c.assessment_status == AssessmentStatus.AUTOMATED.value]

    def get_manual_controls(
        self, vendor: Optional[str] = None, platform: Optional[str] = None
    ) -> list[BenchmarkControl]:
        """Get all manual controls, optionally filtered by vendor/platform."""
        controls = self._filter_by_vendor_platform(vendor, platform)
        return [c for c in controls if c.assessment_status == AssessmentStatus.MANUAL.value]

    def get_mapped_controls(
        self, vendor: Optional[str] = None, platform: Optional[str] = None
    ) -> list[BenchmarkControl]:
        """Get all controls that have a model path mapping."""
        controls = self._filter_by_vendor_platform(vendor, platform)
        return [c for c in controls if c.target_model_path is not None]

    def get_unmapped_controls(
        self, vendor: Optional[str] = None, platform: Optional[str] = None
    ) -> list[BenchmarkControl]:
        """Get all controls without a model path mapping."""
        controls = self._filter_by_vendor_platform(vendor, platform)
        return [c for c in controls if c.target_model_path is None]

    def evaluate_control(
        self,
        control: BenchmarkControl,
        normalized_config: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Evaluate a single control against normalized configuration.

        Returns a dict with:
          - control_id: str
          - result: "PASS" | "FAIL" | "REVIEW"
          - confidence: float
          - actual_value: Any
          - expected_value: Any
          - reasoning: str
        """
        if control.assessment_status == AssessmentStatus.MANUAL.value:
            return {
                "control_id": control.control_id,
                "result": "REVIEW",
                "confidence": 1.0,
                "actual_value": None,
                "expected_value": control.expected_value,
                "reasoning": f"Manual control: {control.title}. Requires human review.",
            }

        if not control.target_model_path:
            if control.negated:
                return {
                    "control_id": control.control_id,
                    "result": "PASS",
                    "confidence": 0.9,
                    "actual_value": None,
                    "expected_value": control.expected_value,
                    "reasoning": f"Negated control {control.control_id}: absence of configuration means compliance.",
                }
            return {
                "control_id": control.control_id,
                "result": "REVIEW",
                "confidence": 0.5,
                "actual_value": None,
                "expected_value": control.expected_value,
                "reasoning": f"No model path mapping for control {control.control_id}.",
            }

        actual_value = self._extract_value(normalized_config, control.target_model_path)

        if actual_value is None and not control.negated:
            return {
                "control_id": control.control_id,
                "result": "REVIEW",
                "confidence": 0.5,
                "actual_value": None,
                "expected_value": control.expected_value,
                "reasoning": f"Value not found at path '{control.target_model_path}'.",
            }

        result = self._apply_operator(actual_value, control.expected_value, control.operator, control.negated)

        confidence = 0.95
        reasoning = self._generate_reasoning(control, actual_value, result)

        return {
            "control_id": control.control_id,
            "result": "PASS" if result else "FAIL",
            "confidence": confidence,
            "actual_value": actual_value,
            "expected_value": control.expected_value,
            "reasoning": reasoning,
        }

    def _extract_value(self, config: dict[str, Any], path: str) -> Any:
        """Extract a value from a nested dict using dot-notation path."""
        parts = path.split(".")
        current = config
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _apply_operator(
        self,
        actual: Any,
        expected: Any,
        operator: str,
        negated: bool = False,
    ) -> bool:
        """Apply the comparison operator."""
        if operator == "equals":
            result = actual == expected
        elif operator == "not_equals":
            result = actual != expected
        elif operator == "contains":
            if isinstance(actual, str):
                result = str(expected) in actual
            elif isinstance(actual, list):
                result = expected in actual
            else:
                result = False
        elif operator == "is_set":
            result = actual is not None
        elif operator == "not_set":
            result = actual is None
        elif operator == "greater_than":
            try:
                result = float(actual) > float(expected)
            except (TypeError, ValueError):
                result = False
        elif operator == "less_than":
            try:
                result = float(actual) < float(expected)
            except (TypeError, ValueError):
                result = False
        elif operator == "regex_match":
            import re
            if isinstance(actual, str):
                result = bool(re.search(str(expected), actual))
            else:
                result = False
        else:
            result = actual == expected

        return not result if negated else result

    def _generate_reasoning(
        self, control: BenchmarkControl, actual_value: Any, result: bool
    ) -> str:
        """Generate human-readable reasoning for a control evaluation."""
        if result:
            return f"Configuration complies with {control.control_id}: {control.title}"
        else:
            return (
                f"Configuration violates {control.control_id}: {control.title}. "
                f"Expected: {control.expected_value} ({control.operator}), "
                f"Actual: {actual_value}"
            )

    def _filter_by_vendor_platform(
        self, vendor: Optional[str], platform: Optional[str]
    ) -> list[BenchmarkControl]:
        """Filter controls by optional vendor and platform."""
        if vendor and platform:
            return self.get_controls_by_vendor_platform(vendor, platform)
        elif vendor:
            return [c for c in self._controls.values() if c.vendor == vendor]
        else:
            return list(self._controls.values())

    def get_stats(self) -> dict[str, Any]:
        """Get registry statistics."""
        all_controls = list(self._controls.values())
        return {
            "total": len(all_controls),
            "automated": sum(1 for c in all_controls if c.assessment_status == AssessmentStatus.AUTOMATED.value),
            "manual": sum(1 for c in all_controls if c.assessment_status == AssessmentStatus.MANUAL.value),
            "mapped": sum(1 for c in all_controls if c.target_model_path is not None),
            "unmapped": sum(1 for c in all_controls if c.target_model_path is None),
            "by_category": {
                cat: len(controls)
                for cat, controls in self._by_category.items()
            },
            "by_vendor_platform": {
                vp: len(controls)
                for vp, controls in self._by_vendor_platform.items()
            },
        }
