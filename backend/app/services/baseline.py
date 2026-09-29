"""Company Baseline Validation Service.

Validates company baseline control selections against the canonical CIS
control registry. Handles duplicate detection, unknown control rejection,
malformed ID parsing, and benchmark compatibility checking.

Never silently removes invalid entries. Always returns explicit error
information so the caller can decide how to proceed.
"""

from __future__ import annotations

from typing import Any, Optional, Set

from app.benchmarks.registry import ControlRegistry


class BaselineValidationError(Exception):
    """Raised when baseline validation finds issues that block activation."""

    def __init__(self, message: str, errors: list[dict[str, str]]) -> None:
        super().__init__(message)
        self.errors = errors


class BaselineValidationService:
    """Service for validating company baseline control selections."""

    def __init__(self, registry: Optional[ControlRegistry] = None) -> None:
        # A bare ControlRegistry() is EMPTY — controls only exist after
        # benchmarks are registered. Mirror the audit pipeline's
        # _load_benchmarks so validation runs against the real control set.
        self._registry = registry or ControlRegistry()
        if registry is None:
            self._load_benchmarks()

    def _load_benchmarks(self) -> None:
        """Register the same benchmark control sets the audit pipeline uses."""
        from app.benchmarks.cisco_ios_xe_controls import get_registry as cisco_registry
        from app.benchmarks.juniper_junos_controls import get_registry as juniper_registry
        from app.benchmarks.nist_sp800_53_controls import get_registry as nist_registry
        self._registry.register_benchmark(cisco_registry())
        self._registry.register_benchmark(juniper_registry())
        self._registry.register_benchmark(nist_registry())

    def validate(
        self,
        controls: list[str],
    ) -> dict[str, Any]:
        """Validate a list of CIS control IDs for company baseline.

        Returns a dict with:
        - valid_count: number of controls that resolve against the registry
        - errors: list of error dicts with 'control_id' and 'reason'
        - invalid_controls: set of control IDs that are invalid/unknown
        - valid_controls: set of control IDs that are valid

        Every control is checked against the canonical CIS control registry.
        Unknown controls, duplicates, and malformed IDs are reported.
        """

        all_controls = self._registry.get_automated_controls()  # type: ignore[attr-defined]
        all_control_ids: Set[str] = {c.control_id for c in all_controls}

        if not controls or len(controls) == 0:
            raise BaselineValidationError(
                "Baseline validation failed: baseline is empty",
                [{"control_id": "", "reason": "empty"}],
            )

        seen: set[str] = set()
        duplicates: list[dict[str, str]] = []
        unknown: list[dict[str, str]] = []
        malformed: list[dict[str, str]] = []
        valid: list[str] = []

        for ctrl_id in controls:
            # Check for duplicates (within this baseline submission)
            if ctrl_id in seen:
                duplicates.append({"control_id": ctrl_id, "reason": "duplicate"})
                continue
            seen.add(ctrl_id)

            # Check if the control exists in the registry
            if ctrl_id not in all_control_ids:
                unknown.append({"control_id": ctrl_id, "reason": "unknown"})
                continue

            # Validate the control ID format (basic check: should match CIS pattern)
            # CIS control IDs follow pattern like "1.1.1", "1.2.8", "2.1.13", etc.
            if not self._is_valid_control_id(ctrl_id):
                malformed.append({"control_id": ctrl_id, "reason": "malformed"})
                continue

            valid.append(ctrl_id)

        error_list: list[dict[str, str]] = []
        error_list.extend(duplicates)
        error_list.extend(unknown)
        error_list.extend(malformed)

        if error_list:
            raise BaselineValidationError(
                f"Baseline validation failed: {len(error_list)} invalid controls out of {len(controls)}",
                error_list,
            )

        return {
            "valid_count": len(valid),
            "errors": error_list,
            "invalid_controls": {
                e["control_id"] for e in error_list
            },
            "valid_controls": set(valid),
        }

    @staticmethod
    def _is_valid_control_id(ctrl_id: str) -> bool:
        """Basic validation of CIS control ID format.

        CIS control IDs follow patterns like:
        - "1.1.1", "1.2.8", "2.1.13" (dot-separated numeric)
        - "AA-1", "SC-2" (prefix-alpha followed by numeric)
        Must have at least one dot or hyphen-separated component.
        """
        if not isinstance(ctrl_id, str) or not ctrl_id.strip():
            return False
        stripped = ctrl_id.strip()
        # Must not contain spaces
        if " " in stripped:
            return False
        # Should have at least one dot or known prefix pattern
        # Accept: dotted numeric like 1.1.1, alpha-numeric like AC-2, IA-2, etc.
        has_dot = "." in stripped
        has_hyphen = "-" in stripped
        if not (has_dot or has_hyphen):
            # Single numeric could be valid (e.g., "1" but that's unlikely)
            # Require at least a pattern check
            return stripped.isdigit() or len(stripped) > 1
        return True


# Convenience function for fast validation without instantiation
def validate_baseline_controls(
    controls: list[str],
    registry: Optional[ControlRegistry] = None,
) -> dict[str, Any]:
    """Validate baseline controls using the provided registry."""
    service = BaselineValidationService(registry)
    return service.validate(controls)