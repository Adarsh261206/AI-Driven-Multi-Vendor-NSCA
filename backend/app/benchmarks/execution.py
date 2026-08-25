"""
Benchmark Execution Engine

Executes CIS benchmark controls against normalized device configurations.
Produces deterministic PASS / FAIL / REVIEW results with full evidence chains.

Pipeline:
  Raw Config → Detect Vendor → Normalize → Evaluate Controls → Evidence → Findings
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from app.benchmarks.models import (
    AssessmentStatus,
    BenchmarkControl,
    BenchmarkRegistry,
    ControlSeverity,
)
from app.benchmarks.registry import ControlRegistry
from app.engines.detection import VendorDetector
from app.engines.normalization import NormalizationEngine, NormalizationResult


# ---------------------------------------------------------------------------
# Evidence Chain
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkEvidence:
    """Full evidence chain for a single control evaluation."""
    control_id: str
    title: str
    category: str
    benchmark_id: str
    vendor: str
    platform: str

    # Raw evidence
    raw_config_lines: list[str] = field(default_factory=list)
    raw_evidence_line_numbers: list[int] = field(default_factory=list)
    raw_evidence_snippet: str = ""

    # Regex-based evidence (for unmapped controls)
    audit_command: str = ""
    audit_regex_matched: bool = False
    audit_regex_match_text: str = ""

    # Normalized model evidence
    target_model_path: str = ""
    normalized_value: Any = None
    normalization_confidence: float = 0.0

    # Evaluation
    expected_value: Any = None
    actual_value: Any = None
    operator: str = ""
    result: str = "REVIEW"  # PASS | FAIL | REVIEW
    result_reasoning: str = ""
    confidence: float = 0.0

    # Metadata
    assessment_status: str = ""
    severity: str = ""
    remediation_command: str = ""
    source_document: str = ""
    source_location: str = ""
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ControlEvaluationResult:
    """Result of evaluating a single control."""
    control_id: str
    result: str  # PASS | FAIL | REVIEW
    confidence: float
    evidence: BenchmarkEvidence
    is_automated: bool


@dataclass
class BenchmarkExecutionResult:
    """Complete result of executing a benchmark against a configuration."""
    benchmark_id: str
    benchmark_name: str
    vendor: str
    platform: str
    total_controls: int
    evaluated: int
    passed: int
    failed: int
    review: int
    score: float
    evaluations: list[ControlEvaluationResult]
    vendor_identification: Any = None
    normalization_result: Optional[NormalizationResult] = None
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Benchmark Execution Engine
# ---------------------------------------------------------------------------

class BenchmarkExecutionEngine:
    """
    Executes CIS benchmark controls against device configurations.

    Uses the existing NormalizationEngine to map raw config → universal model,
    then evaluates each control against the normalized config.
    """

    # Controls whose settings can conflict with duplicates.
    # Maps control_id → setting key in conflicts list
    CONFLICT_AFFECTED_CONTROLS: dict[str, str] = {
        "1.2.6": "exec-timeout",
        "1.2.7": "exec-timeout",
        "1.2.8": "exec-timeout",
        "1.2.2": "transport input",
    }

    # Controls that must be evaluated across ALL applicable blocks (e.g., all VTY blocks).
    # Key: control_id → (multi_block_path, block_type, evaluation_mode)
    #   evaluation_mode: "all_must_pass" = every block must satisfy the threshold
    MULTI_BLOCK_CONTROLS: dict[str, tuple[str, str, str]] = {
        "1.2.8": ("management.vty.exec_timeouts", "vty", "all_must_pass"),
    }

    def __init__(self) -> None:
        self.vendor_detector = VendorDetector()
        self.normalizer = NormalizationEngine()
        self.control_registry = ControlRegistry()
        self._load_benchmarks()

    def _load_benchmarks(self) -> None:
        """Load all registered benchmark control sets."""
        from app.benchmarks.cisco_ios_xe_controls import get_registry as cisco_registry
        from app.benchmarks.juniper_junos_controls import get_registry as juniper_registry
        self.control_registry.register_benchmark(cisco_registry())
        self.control_registry.register_benchmark(juniper_registry())

    def execute(
        self,
        raw_config: str,
        vendor: str = "cisco",
        platform: str = "ios_xe",
    ) -> BenchmarkExecutionResult:
        """
        Execute all applicable controls against a raw configuration.

        Args:
            raw_config: Raw device configuration text
            vendor: Expected vendor (default: cisco)
            platform: Expected platform (default: ios_xe)

        Returns:
            BenchmarkExecutionResult with per-control evaluations
        """
        # Step 1: Detect vendor (informational, we trust the caller)
        vendor_id = self.vendor_detector.detect(raw_config)

        # Normalize platform aliases per vendor:
        #   VendorDetector returns "ios" for Cisco IOS/IOS-XE, but benchmark
        #   controls are registered under "ios_xe".
        #   Juniper returns "junos" which matches the registered benchmark platform.
        vendor_lower = (vendor or "").lower()
        platform_lower = (platform or "").lower()
        effective_platform = platform
        if vendor_lower == "cisco" and platform_lower in ("ios", "ios_xe"):
            effective_platform = "ios_xe"

        # Step 2: Normalize config to universal model
        config_dict = {"raw_lines": raw_config.splitlines()}
        norm_result = self.normalizer.normalize(config_dict, vendor, effective_platform)

        # Step 3: Get applicable controls
        controls = self.control_registry.get_controls_by_vendor_platform(vendor, effective_platform)

        # Step 4: Evaluate each control
        evaluations: list[ControlEvaluationResult] = []
        for control in controls:
            ev = self._evaluate_control(control, norm_result, raw_config)
            evaluations.append(ev)

        # Step 5: Compute summary
        passed = sum(1 for e in evaluations if e.result == "PASS")
        failed = sum(1 for e in evaluations if e.result == "FAIL")
        review = sum(1 for e in evaluations if e.result == "REVIEW")
        evaluated = len(evaluations)
        score = (passed / evaluated * 100) if evaluated > 0 else 0.0

        # Derive benchmark metadata from the evaluated controls (vendor-neutral)
        benchmark_id = ""
        benchmark_name = ""
        if controls:
            benchmark_id = controls[0].benchmark_id
            benchmark_name = controls[0].benchmark_name

        return BenchmarkExecutionResult(
            benchmark_id=benchmark_id,
            benchmark_name=benchmark_name,
            vendor=vendor,
            platform=platform,
            total_controls=len(controls),
            evaluated=evaluated,
            passed=passed,
            failed=failed,
            review=review,
            score=round(score, 1),
            evaluations=evaluations,
            vendor_identification=vendor_id,
            normalization_result=norm_result,
        )

    def _evaluate_control(
        self,
        control: BenchmarkControl,
        norm_result: NormalizationResult,
        raw_config: str,
    ) -> ControlEvaluationResult:
        """Evaluate a single benchmark control."""
        evidence = BenchmarkEvidence(
            control_id=control.control_id,
            title=control.title,
            category=control.category,
            benchmark_id=control.benchmark_id,
            vendor=control.vendor,
            platform=control.platform,
            assessment_status=control.assessment_status,
            severity=control.severity.value if hasattr(control.severity, 'value') else control.severity,
            remediation_command=control.remediation_command,
            source_document=control.source_document,
            source_location=control.source_location,
            audit_command=control.audit_command,
        )

        # MANUAL controls always → REVIEW
        if control.assessment_status == AssessmentStatus.MANUAL.value:
            evidence.result = "REVIEW"
            evidence.result_reasoning = f"Manual control: {control.title}. Requires human review."
            evidence.confidence = 1.0
            return ControlEvaluationResult(
                control_id=control.control_id,
                result="REVIEW",
                confidence=1.0,
                evidence=evidence,
                is_automated=False,
            )

        # NEGATED controls without model path: absence = PASS
        if not control.target_model_path and control.negated:
            matched = self._run_audit_regex(control.audit_regex, raw_config)
            evidence.audit_regex_matched = matched
            if matched:
                evidence.result = "FAIL"
                evidence.result_reasoning = (
                    f"Negated control {control.control_id}: pattern found in config "
                    f"but should be absent."
                )
                evidence.confidence = 0.85
            else:
                evidence.result = "PASS"
                evidence.result_reasoning = (
                    f"Negated control {control.control_id}: pattern absent from config, "
                    f"which means compliance."
                )
                evidence.confidence = 0.9
            return ControlEvaluationResult(
                control_id=control.control_id,
                result=evidence.result,
                confidence=evidence.confidence,
                evidence=evidence,
                is_automated=True,
            )

        # Controls WITHOUT model path → try audit_regex, else REVIEW
        if not control.target_model_path:
            matched = self._run_audit_regex(control.audit_regex, raw_config)
            evidence.audit_regex_matched = matched
            if control.audit_regex and matched:
                evidence.result = "PASS"
                evidence.result_reasoning = (
                    f"Regex pattern matched for {control.control_id}: {control.title}"
                )
                evidence.confidence = 0.8
            elif control.audit_regex and not matched:
                evidence.result = "FAIL"
                evidence.result_reasoning = (
                    f"Regex pattern not matched for {control.control_id}: {control.title}"
                )
                evidence.confidence = 0.8
            else:
                evidence.result = "REVIEW"
                evidence.result_reasoning = (
                    f"No model path or audit regex for control {control.control_id}."
                )
                evidence.confidence = 0.5
            return ControlEvaluationResult(
                control_id=control.control_id,
                result=evidence.result,
                confidence=evidence.confidence,
                evidence=evidence,
                is_automated=True,
            )

        # CONTROLS WITH MODEL PATH → evaluate against normalized config
        evidence.target_model_path = control.target_model_path

        # CONFLICT DETECTION: duplicate conflicting settings → REVIEW
        # Skip for multi-block controls — they handle per-block evaluation
        if control.control_id not in self.MULTI_BLOCK_CONTROLS:
            # Legacy Cisco-specific map (precise control_id → setting)
            legacy_conflict = self._legacy_conflict_check(control, norm_result)
            if legacy_conflict is not None:
                return self._review_with_conflict(control, evidence, legacy_conflict)
            # Generic vendor-neutral check based on universal model path prefixes
            generic_conflict = self._generic_conflict_check(control, norm_result)
            if generic_conflict is not None:
                return self._review_with_conflict(control, evidence, generic_conflict)

        # MULTI-BLOCK EVALUATION: check ALL blocks for controls like 1.2.8
        if control.control_id in self.MULTI_BLOCK_CONTROLS:
            return self._evaluate_multi_block(
                control, norm_result, raw_config, evidence
            )

        actual_value = self._extract_value(
            norm_result.universal_config, control.target_model_path
        )
        evidence.normalized_value = actual_value
        evidence.actual_value = actual_value
        evidence.expected_value = control.expected_value
        evidence.operator = control.operator

        # Also collect raw evidence
        raw_lines = raw_config.splitlines()
        evidence.raw_config_lines = raw_lines
        matching_lines = self._find_matching_lines(control, raw_lines)
        evidence.raw_evidence_line_numbers = [ln for ln, _ in matching_lines]
        evidence.raw_evidence_snippet = "\n".join(text for _, text in matching_lines[:5])

        # Missing value → REVIEW (never FALSE)
        if actual_value is None:
            evidence.result = "REVIEW"
            evidence.result_reasoning = (
                f"Value not found at path '{control.target_model_path}' "
                f"for control {control.control_id}."
            )
            evidence.confidence = 0.5
            return ControlEvaluationResult(
                control_id=control.control_id,
                result="REVIEW",
                confidence=0.5,
                evidence=evidence,
                is_automated=True,
            )

        # Apply operator
        result_bool = self._apply_operator(
            actual_value, control.expected_value, control.operator, control.negated
        )

        if result_bool:
            evidence.result = "PASS"
            evidence.result_reasoning = (
                f"Configuration complies with {control.control_id}: {control.title}. "
                f"Actual={actual_value} ({control.operator} expected={control.expected_value})"
            )
            evidence.confidence = 0.95
        else:
            evidence.result = "FAIL"
            evidence.result_reasoning = (
                f"Configuration violates {control.control_id}: {control.title}. "
                f"Actual={actual_value} ({control.operator} expected={control.expected_value})"
            )
            evidence.confidence = 0.95

        return ControlEvaluationResult(
            control_id=control.control_id,
            result=evidence.result,
            confidence=evidence.confidence,
            evidence=evidence,
            is_automated=True,
        )

    def _legacy_conflict_check(
        self, control: BenchmarkControl, norm_result: NormalizationResult
    ) -> Optional[dict]:
        """Legacy Cisco-specific conflict check (control_id → setting)."""
        if control.control_id not in self.CONFLICT_AFFECTED_CONTROLS:
            return None
        conflicts = self._extract_value(
            norm_result.universal_config, "management.vty.conflicts"
        )
        setting_key = self.CONFLICT_AFFECTED_CONTROLS[control.control_id]
        if not conflicts or not isinstance(conflicts, list):
            return None
        for conflict in conflicts:
            if conflict.get("setting") == setting_key and conflict.get("conflict"):
                return conflict
        return None

    def _generic_conflict_check(
        self, control: BenchmarkControl, norm_result: NormalizationResult
    ) -> Optional[dict]:
        """Vendor-neutral conflict check based on universal model path prefixes."""
        target_path = control.target_model_path or ""
        if not target_path:
            return None
        for conflict_path in ("config.conflicts", "management.vty.conflicts"):
            conflicts = self._extract_value(norm_result.universal_config, conflict_path)
            if not conflicts or not isinstance(conflicts, list):
                continue
            for conflict in conflicts:
                if not conflict.get("conflict"):
                    continue
                prefix = conflict.get("path_prefix")
                if not prefix:
                    continue
                if (target_path == prefix
                        or target_path.startswith(prefix + ".")
                        or prefix in target_path):
                    return conflict
        return None

    def _review_with_conflict(
        self,
        control: BenchmarkControl,
        evidence: BenchmarkEvidence,
        conflict: dict,
    ) -> ControlEvaluationResult:
        """Build a REVIEW result with conflict evidence."""
        setting = conflict.get("setting", "setting")
        values = conflict.get("values", [])
        context = conflict.get("context") or conflict.get("blocks") or "configuration"
        evidence.result = "REVIEW"
        evidence.result_reasoning = (
            f"Conflicting duplicate '{setting}' settings detected: "
            f"{values} in {context}. "
            f"Cannot determine correct value for control {control.control_id}."
        )
        evidence.confidence = 0.6
        evidence.raw_evidence_snippet = str(conflict)
        return ControlEvaluationResult(
            control_id=control.control_id,
            result="REVIEW",
            confidence=0.6,
            evidence=evidence,
            is_automated=True,
        )

    def _evaluate_multi_block(
        self,
        control: BenchmarkControl,
        norm_result: NormalizationResult,
        raw_config: str,
        evidence: BenchmarkEvidence,
    ) -> ControlEvaluationResult:
        """Evaluate a control across ALL applicable blocks.
        
        For controls like 1.2.8 (VTY exec-timeout), ALL VTY blocks must satisfy
        the threshold. If ANY block fails, the control FAILS.
        If ANY block has missing data, the control gets REVIEW for that block.
        """
        multi_path, block_type, eval_mode = self.MULTI_BLOCK_CONTROLS[control.control_id]
        
        # Extract per-block data
        block_data = self._extract_value(norm_result.universal_config, multi_path)
        
        if block_data is None or not isinstance(block_data, list):
            evidence.result = "REVIEW"
            evidence.result_reasoning = (
                f"Multi-block data not found at '{multi_path}' for control {control.control_id}."
            )
            evidence.confidence = 0.5
            return ControlEvaluationResult(
                control_id=control.control_id,
                result="REVIEW",
                confidence=0.5,
                evidence=evidence,
                is_automated=True,
            )
        
        # Filter to relevant block type
        relevant_blocks = [b for b in block_data if b.get("type") == block_type]
        
        if not relevant_blocks:
            evidence.result = "REVIEW"
            evidence.result_reasoning = (
                f"No {block_type} blocks found for control {control.control_id}."
            )
            evidence.confidence = 0.5
            return ControlEvaluationResult(
                control_id=control.control_id,
                result="REVIEW",
                confidence=0.5,
                evidence=evidence,
                is_automated=True,
            )
        
        # Evaluate each block
        block_results: list[dict] = []
        all_pass = True
        any_review = False
        any_fail = False
        
        for block in relevant_blocks:
            block_label = block.get("block", f"line {block_type}")
            timeout_val = block.get("timeout_seconds")
            raw_line = block.get("raw", "")
            
            if timeout_val is None:
                block_results.append({
                    "block": block_label,
                    "timeout": None,
                    "result": "REVIEW",
                    "raw": raw_line,
                })
                any_review = True
                all_pass = False
            else:
                result_bool = self._apply_operator(
                    timeout_val, control.expected_value, control.operator, control.negated
                )
                block_result = "PASS" if result_bool else "FAIL"
                block_results.append({
                    "block": block_label,
                    "timeout": timeout_val,
                    "result": block_result,
                    "raw": raw_line,
                })
                if not result_bool:
                    any_fail = True
                    all_pass = False
        
        # Aggregate evidence: show ALL blocks
        evidence_lines = []
        for br in block_results:
            evidence_lines.append(f"{br['block']}:")
            if br['raw']:
                evidence_lines.append(f"  {br['raw']}")
            evidence_lines.append(f"  → timeout={br['timeout']}s, result={br['result']}")
        
        evidence.actual_value = block_results
        evidence.expected_value = control.expected_value
        evidence.operator = control.operator
        evidence.raw_evidence_snippet = "\n".join(evidence_lines)
        
        # Also collect raw config lines
        raw_lines = raw_config.splitlines()
        evidence.raw_config_lines = raw_lines
        matching_lines = self._find_matching_lines(control, raw_lines)
        evidence.raw_evidence_line_numbers = [ln for ln, _ in matching_lines]
        
        # Determine aggregate result
        if any_fail:
            failed_blocks = [br for br in block_results if br["result"] == "FAIL"]
            evidence.result = "FAIL"
            evidence.result_reasoning = (
                f"Control {control.control_id} failed on {len(failed_blocks)}/{len(relevant_blocks)} "
                f"{block_type} blocks. Failed: {[br['block'] for br in failed_blocks]}."
            )
            evidence.confidence = 0.95
        elif any_review:
            evidence.result = "REVIEW"
            review_blocks = [br for br in block_results if br["result"] == "REVIEW"]
            evidence.result_reasoning = (
                f"Control {control.control_id}: incomplete data on "
                f"{len(review_blocks)}/{len(relevant_blocks)} {block_type} blocks."
            )
            evidence.confidence = 0.7
        else:
            evidence.result = "PASS"
            evidence.result_reasoning = (
                f"Control {control.control_id}: all {len(relevant_blocks)} {block_type} "
                f"blocks comply ({control.operator} {control.expected_value}s)."
            )
            evidence.confidence = 0.95
        
        return ControlEvaluationResult(
            control_id=control.control_id,
            result=evidence.result,
            confidence=evidence.confidence,
            evidence=evidence,
            is_automated=True,
        )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _extract_value(config: dict[str, Any], path: str) -> Any:
        """Extract a value from a nested dict using dot-notation path."""
        parts = path.split(".")
        current = config
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    @staticmethod
    def _apply_operator(
        actual: Any, expected: Any, operator: str, negated: bool = False
    ) -> bool:
        """Apply comparison operator. Returns True if compliant."""
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
        elif operator == "greater_than_or_equal":
            try:
                result = float(actual) >= float(expected)
            except (TypeError, ValueError):
                result = False
        elif operator == "less_than":
            try:
                result = float(actual) < float(expected)
            except (TypeError, ValueError):
                result = False
        elif operator == "less_than_or_equal":
            try:
                result = float(actual) <= float(expected)
            except (TypeError, ValueError):
                result = False
        elif operator == "regex_match":
            if isinstance(actual, str):
                result = bool(re.search(str(expected), actual))
            else:
                result = False
        else:
            result = actual == expected

        return not result if negated else result

    @staticmethod
    def _run_audit_regex(pattern: str, raw_config: str) -> bool:
        """Run an audit regex against raw config, return True if matched."""
        if not pattern:
            return False
        try:
            return bool(re.search(pattern, raw_config, re.MULTILINE))
        except re.error:
            return False

    @staticmethod
    def _find_matching_lines(
        control: BenchmarkControl, raw_lines: list[str]
    ) -> list[tuple[int, str]]:
        """Find raw config lines relevant to this control."""
        matches: list[tuple[int, str]] = []
        # Try audit_regex first
        if control.audit_regex:
            try:
                pat = re.compile(control.audit_regex)
                for i, line in enumerate(raw_lines, start=1):
                    if pat.search(line):
                        matches.append((i, line))
            except re.error:
                pass
        # Fallback: search for audit_command keywords
        if not matches and control.audit_command:
            keywords = [
                w for w in control.audit_command.split()
                if len(w) > 2 and w not in ("show", "running-config", "|", "include", "section")
            ]
            for i, line in enumerate(raw_lines, start=1):
                if any(kw in line for kw in keywords):
                    matches.append((i, line))
        return matches
