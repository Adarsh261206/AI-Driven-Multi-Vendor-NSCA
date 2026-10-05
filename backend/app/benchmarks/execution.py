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
from app.benchmarks.selection import (
    ComplianceInputError,
    ControlSelectionService,
    InvalidControlError,
    UnknownFrameworkVersionError,
    UnsupportedFrameworkError,
    UnsupportedVendorError,
    SUPPORTED_EVALUATION_VENDORS,
    DUAL_BASELINE,
    RAW_MATCH_CONFIDENCE,
    apply_operator,
    compose_confidence,
    needs_review,
    normalize_framework,
    normalize_framework_version,
    normalize_platform,
    normalize_vendor,
    overall_score,
)
from app.engines.detection import VendorDetector
from app.engines.normalization import (
    NormalizationEngine,
    NormalizationResult,
    NormalizationResultType,
)


#: NUL and C0 controls (except tab/LF/CR) have no legitimate place in a
#: configuration under evaluation; they are rejected, never silently kept.
_UNSAFE_INPUT_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _index_norm_mappings(norm_result: NormalizationResult) -> dict[str, dict]:
    """Index normalization mappings by model path.

    Each entry carries the normalized value, the mapping's own confidence
    (the normalization-confidence input, F7), the vendor statement that
    produced it (the parsed_value, F4) and the source line numbers.
    """
    facts: dict[str, dict] = {}
    for mapping in getattr(norm_result, "mappings", None) or []:
        path = getattr(mapping, "model_path", None)
        if not path or path in facts:
            continue
        line_numbers: list[int] = []
        for source in getattr(mapping, "source_path", None) or []:
            text = str(source)
            if text.startswith("line:"):
                try:
                    line_numbers.append(int(text.split(":", 1)[1]))
                except ValueError:
                    continue
        facts[path] = {
            "value": getattr(mapping, "value", None),
            "confidence": getattr(mapping, "confidence", None),
            "vendor_syntax": getattr(mapping, "vendor_specific_syntax", "") or "",
            "line_numbers": sorted(set(line_numbers)),
        }
    return facts


# ---------------------------------------------------------------------------
# Evidence Chain
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkEvidence:
    """Evidence chain for a single control evaluation.

    The eight §12 canonical keys come first (raw_config, parsed_value,
    normalized_value, security_control, expected_value, actual_value,
    result, reasoning); the remaining fields are Engine 07 traceability
    metadata (operator, confidences, line numbers, snippets, remediation
    pointers) — not a competing schema.
    """
    # §12 canonical keys
    raw_config: str = ""
    parsed_value: Any = None
    normalized_value: Any = None
    security_control: str = ""
    expected_value: Any = None
    actual_value: Any = None
    result: str = "REVIEW"  # PASS | FAIL | REVIEW
    reasoning: str = ""

    # Traceability metadata
    control_id: str = ""
    title: str = ""
    category: str = ""
    benchmark_id: str = ""
    framework: str = ""
    framework_version: str = ""
    vendor: str = ""
    platform: str = ""
    operator: str = ""
    confidence: float = 0.0
    normalization_confidence: Optional[float] = None
    rule_confidence: float = 1.0
    # Model path this decision was evaluated against ("" for raw-evidence
    # and manual decisions — never fabricated).
    universal_model_path: str = ""
    raw_config_line_numbers: list[int] = field(default_factory=list)
    raw_evidence_snippet: str = ""
    audit_regex_matched: bool = False
    # The explicit audit pattern this raw-evidence decision was evaluated
    # against ("" when the control defines none — never invented).
    audit_regex: str = ""
    assessment_status: str = ""
    severity: str = ""
    remediation_command: str = ""
    # Control-authored remediation content for the E10 RemediationEngine
    # ("" / [] when the control defines none — never invented here).
    audit_command: str = ""
    verification_steps: list[str] = field(default_factory=list)
    rollback_steps: list[str] = field(default_factory=list)
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
    framework: str = ""
    framework_version: str = ""
    total_controls: int = 0
    evaluated: int = 0
    passed: int = 0
    failed: int = 0
    review: int = 0
    score: float = 0.0
    evaluations: list[ControlEvaluationResult] = field(default_factory=list)
    vendor_identification: Any = None
    normalization_result: Optional[NormalizationResult] = None
    # Safety boundary outcome (F6/F12/F13): "completed" means a normal
    # evaluation ran; anything else means zero decisive verdicts were
    # produced and status_reason explains why.
    status: str = "completed"
    status_reason: str = ""
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
        self.selection = ControlSelectionService(
            list(self.control_registry._controls.values()))

    def _load_benchmarks(self) -> None:
        """Load all registered benchmark control sets — dual-baseline: CIS + NIST in one go."""
        from app.benchmarks.cisco_ios_xe_controls import get_registry as cisco_registry
        from app.benchmarks.juniper_junos_controls import get_registry as juniper_registry
        from app.benchmarks.nist_sp800_53_controls import get_registry as nist_registry
        self.control_registry.register_benchmark(cisco_registry())
        self.control_registry.register_benchmark(juniper_registry())
        self.control_registry.register_benchmark(nist_registry())

    def _boundary_result(self, vendor: str, platform: str,
                         framework: Optional[str], version: Optional[str],
                         vendor_identification, normalization_result,
                         status: str, reason: str) -> BenchmarkExecutionResult:
        """Explicit safety-boundary outcome: zero evaluations, zero decisive
        verdicts, and a machine-readable status (F6/F12/F13)."""
        return BenchmarkExecutionResult(
            benchmark_id="",
            benchmark_name="",
            vendor=vendor,
            platform=platform,
            framework=framework or "",
            framework_version=version or "",
            total_controls=0,
            evaluated=0,
            passed=0,
            failed=0,
            review=0,
            score=0.0,
            evaluations=[],
            vendor_identification=vendor_identification,
            normalization_result=normalization_result,
            status=status,
            status_reason=reason,
        )

    @staticmethod
    def _benchmark_metadata(controls: list[BenchmarkControl],
                            frameworks: list[str]) -> tuple[str, str]:
        """Name what actually ran. A mixed-framework run is the explicit
        dual baseline — never understated as the first control's benchmark."""
        if not controls:
            return "", ""
        if len(frameworks) > 1:
            return (DUAL_BASELINE,
                    " + ".join(sorted({c.benchmark_name for c in controls})))
        first = controls[0]
        return first.benchmark_id, first.benchmark_name

    def execute(
        self,
        raw_config: str,
        vendor: str = "cisco",
        platform: str = "ios_xe",
        vendor_identification=None,
        normalization_result: Optional[NormalizationResult] = None,
        framework: Optional[str] = None,
        framework_version: Optional[str] = None,
    ) -> BenchmarkExecutionResult:
        """
        Execute all applicable controls against a raw configuration.

        Args:
            raw_config: Raw device configuration text
            vendor: Declared vendor (canonicalized; cross-checked against
                detection — a declared/actual mismatch is a safety boundary,
                never a silent substitution)
            platform: Declared platform (canonicalized, aliases resolved)
            vendor_identification: Optional VendorIdentification from the caller
                (E03 F17) — when supplied it is reused instead of re-running
                detection on the same content.
            normalization_result: Optional authoritative NormalizationResult
                from the caller (E05 F5) — when supplied it is consumed
                directly instead of running normalization a second time.
            framework: CIS, NIST, explicit dual (CIS+NIST), or None for the
                canonical dual baseline. Unknown frameworks raise
                UnsupportedFrameworkError (F1) — never silent fallback.
            framework_version: version that must exist in the loaded
                inventory (F1); None selects all versions.

        Returns:
            BenchmarkExecutionResult with per-control evaluations. When a
            safety boundary stops evaluation (unsupported vendor, vendor
            mismatch, empty input, failed normalization), status names the
            boundary, evaluations is empty, and no decisive verdict exists.
        """
        # Typed input boundary (F13): never an AttributeError as a result.
        if raw_config is None:
            raise ComplianceInputError("raw_config must be str, got None")
        if not isinstance(raw_config, str):
            raise ComplianceInputError(
                f"raw_config must be str, got {type(raw_config).__name__}")
        if _UNSAFE_INPUT_RE.search(raw_config):
            raise ComplianceInputError(
                "raw_config contains NUL/control characters")

        vendor_c = normalize_vendor(vendor)
        platform_c = normalize_platform(vendor_c, platform)
        framework_c = normalize_framework(framework)
        version_c = normalize_framework_version(framework_version)

        if not raw_config.strip():
            return self._boundary_result(
                vendor_c, platform_c, framework_c, version_c,
                vendor_identification, None,
                status="empty_input",
                reason="empty configuration carries no evidence; "
                       "nothing is evaluated, nothing passes",
            )

        # Detection cross-check (F6): the engine respects the upstream
        # vendor state instead of trusting the caller blindly.
        if vendor_identification is not None:
            vendor_id = vendor_identification
        else:
            vendor_id = self.vendor_detector.detect(raw_config)
        detected_vendor = normalize_vendor(
            getattr(vendor_id, "vendor", "unknown") or "unknown")
        detected_platform = normalize_platform(
            detected_vendor,
            getattr(vendor_id, "platform", "unknown") or "unknown")
        if (detected_vendor in SUPPORTED_EVALUATION_VENDORS
                and (detected_vendor != vendor_c
                     or detected_platform != platform_c)):
            return self._boundary_result(
                vendor_c, platform_c, framework_c, version_c, vendor_id, None,
                status="vendor_mismatch",
                reason=f"declared {vendor_c!r}/{platform_c!r} disagrees with "
                       f"detected {detected_vendor!r}/{detected_platform!r}; "
                       "evaluating as declared would serve another vendor's "
                       "verdicts",
            )

        # Step 2: Normalize config to universal model (E05 F5: exactly one
        # normalization per audit — reuse the caller's result when provided).
        if normalization_result is None:
            config_dict = {"raw_lines": raw_config.splitlines()}
            norm_result = self.normalizer.normalize(
                config_dict, vendor_c, platform_c)
        else:
            norm_result = normalization_result

        # Step 2b: failed normalization is a safety boundary (E05 F6) — stop
        # evaluation instead of scoring unevaluated state.
        if norm_result.result_type == NormalizationResultType.FAILED:
            return self._boundary_result(
                vendor_c, platform_c, framework_c, version_c, vendor_id,
                norm_result,
                status="normalization_failed",
                reason="normalization failed: compliance evaluation stopped "
                       "(no trustworthy normalized state)",
            )

        # Step 3: canonical control selection (F1/F2). Unsupported vendors
        # and unknown frameworks/versions raise here — translated into an
        # explicit boundary result, never a silent substitution.
        try:
            selection = self.selection.select_for_evaluation(
                vendor_c, platform_c, framework_c, version_c)
        except (UnsupportedVendorError, UnsupportedFrameworkError,
                UnknownFrameworkVersionError) as exc:
            return self._boundary_result(
                vendor_c, platform_c, framework_c, version_c, vendor_id,
                norm_result,
                status="unsupported_selection",
                reason=str(exc),
            )
        controls = selection.controls
        requested_mode = selection.framework

        # Per-path normalization facts for evidence + confidence (F4/F7).
        path_facts = _index_norm_mappings(norm_result)

        # Step 4: Evaluate each control
        evaluations: list[ControlEvaluationResult] = []
        for control in controls:
            ev = self._evaluate_control(control, norm_result, raw_config,
                                        path_facts)
            evaluations.append(ev)

        # Step 5: ONE summary (F5) via the canonical score function.
        passed = sum(1 for e in evaluations if e.result == "PASS")
        failed = sum(1 for e in evaluations if e.result == "FAIL")
        review = sum(1 for e in evaluations if e.result == "REVIEW")
        evaluated = len(evaluations)
        score = overall_score(passed, evaluated)

        # Benchmark metadata reflects what actually ran (F3/H07-16): a mixed
        # run names the dual baseline explicitly instead of understating it
        # with the first control's benchmark.
        frameworks_run = sorted({c.framework for c in controls if c.framework})
        benchmark_id, benchmark_name = self._benchmark_metadata(
            controls, frameworks_run)

        return BenchmarkExecutionResult(
            benchmark_id=benchmark_id,
            benchmark_name=benchmark_name,
            vendor=vendor_c,
            platform=platform_c,
            framework=requested_mode,
            framework_version=version_c or "",
            total_controls=len(controls),
            evaluated=evaluated,
            passed=passed,
            failed=failed,
            review=review,
            score=score,
            evaluations=evaluations,
            vendor_identification=vendor_id,
            normalization_result=norm_result,
            status="completed",
            status_reason="",
        )

    @staticmethod
    def _review_confidence(norm_conf: Optional[float],
                           rule_conf: Optional[float]) -> float:
        """Confidence recorded on a forced REVIEW: the composed value when
        both inputs exist, else the available input, else 0.5 (documented
        'no evidence basis' — never a decisive verdict)."""
        composed = compose_confidence(norm_conf, rule_conf)
        if composed is not None:
            return composed
        if norm_conf is not None:
            return max(0.0, min(1.0, float(norm_conf)))
        if rule_conf is not None:
            return max(0.0, min(1.0, float(rule_conf)))
        return 0.5

    def _base_evidence(self, control: BenchmarkControl) -> BenchmarkEvidence:
        """Evidence skeleton with §12 keys and control-owned metadata."""
        return BenchmarkEvidence(
            security_control=control.control_id,
            control_id=control.control_id,
            title=control.title,
            category=control.category,
            benchmark_id=control.benchmark_id,
            framework=control.framework,
            framework_version=control.framework_version,
            vendor=control.vendor,
            platform=control.platform,
            operator=control.operator,
            rule_confidence=control.rule_confidence,
            expected_value=control.expected_value,
            assessment_status=(control.assessment_status.value
                               if hasattr(control.assessment_status, "value")
                               else str(control.assessment_status)),
            severity=(control.severity.value
                      if hasattr(control.severity, "value")
                      else str(control.severity)),
            remediation_command=control.remediation_command,
            audit_command=control.audit_command,
            verification_steps=list(control.verification_steps or []),
            rollback_steps=list(control.rollback_steps or []),
            source_document=control.source_document,
            source_location=control.source_location,
        )

    def _finish_review(self, control: BenchmarkEvidence,
                       reason: str, norm_conf: Optional[float],
                       rule_conf: float) -> ControlEvaluationResult:
        """Forced REVIEW with complete evidence and an honest confidence."""
        control.result = "REVIEW"
        control.reasoning = reason
        control.confidence = self._review_confidence(norm_conf, rule_conf)
        control.normalization_confidence = norm_conf
        return ControlEvaluationResult(
            control_id=control.control_id,
            result="REVIEW",
            confidence=control.confidence,
            evidence=control,
            is_automated=False,
        )

    def _evaluate_control(
        self,
        control: BenchmarkControl,
        norm_result: NormalizationResult,
        raw_config: str,
        path_facts: Optional[dict[str, dict]] = None,
    ) -> ControlEvaluationResult:
        """Evaluate a single benchmark control (canonical path, F4/F7).

        Decisive PASS/FAIL requires: an automated control, a composed final
        confidence at/above 0.70, and sufficient evidence (observed value or
        matched raw evidence, line numbers, snippet, reasoning). Anything
        short of that is REVIEW — missing evidence is never a FAIL and an
        invalid configuration never becomes a PASS.
        """
        if path_facts is None:
            path_facts = _index_norm_mappings(norm_result)
        evidence = self._base_evidence(control)
        rule_conf = control.rule_confidence

        # MANUAL controls always → REVIEW (review certainty, not a verdict).
        if control.assessment_status == AssessmentStatus.MANUAL.value:
            evidence.normalization_confidence = None
            return self._finish_review(
                evidence,
                f"Manual control: {control.title}. Requires human review.",
                None, 1.0)

        raw_lines = raw_config.splitlines()

        # Controls WITHOUT a model path evaluate against raw evidence only
        # when explicitly defined as regex-based (F4/F10 raw-regex rule).
        if not control.target_model_path:
            return self._evaluate_unmapped(control, evidence, raw_config,
                                           raw_lines, rule_conf)

        # Mapped controls: the normalization fact is the evidence basis.
        fact = path_facts.get(control.target_model_path, {})
        norm_conf = fact.get("confidence")
        evidence.normalization_confidence = norm_conf
        evidence.normalized_value = fact.get("value")
        evidence.universal_model_path = control.target_model_path or ""
        evidence.parsed_value = fact.get("vendor_syntax") or None
        line_numbers = list(fact.get("line_numbers") or [])
        if not line_numbers:
            line_numbers = [ln for ln, _ in
                            self._find_matching_lines(control, raw_lines)]
        evidence.raw_config_line_numbers = line_numbers
        evidence.raw_config = "\n".join(
            raw_lines[i - 1] for i in line_numbers[:5]
            if 1 <= i <= len(raw_lines))
        evidence.raw_evidence_snippet = evidence.raw_config

        # CONFLICT DETECTION: duplicate conflicting settings → REVIEW.
        # Skip for multi-block controls — they handle per-block evaluation.
        if control.control_id not in self.MULTI_BLOCK_CONTROLS:
            legacy_conflict = self._legacy_conflict_check(control, norm_result)
            if legacy_conflict is not None:
                return self._review_with_conflict(
                    control, evidence, legacy_conflict, norm_conf, rule_conf)
            generic_conflict = self._generic_conflict_check(control, norm_result)
            if generic_conflict is not None:
                return self._review_with_conflict(
                    control, evidence, generic_conflict, norm_conf, rule_conf)

        # MULTI-BLOCK EVALUATION across ALL applicable blocks.
        if control.control_id in self.MULTI_BLOCK_CONTROLS:
            return self._evaluate_multi_block(
                control, norm_result, raw_config, evidence, norm_conf,
                rule_conf)

        actual_value = fact.get("value")
        evidence.actual_value = actual_value

        # Missing value → REVIEW (never FALSE, never FAIL).
        if actual_value is None:
            return self._finish_review(
                evidence,
                f"Value not found at path '{control.target_model_path}' "
                f"for control {control.control_id}.",
                norm_conf, rule_conf)

        # Apply the canonical operator (unknown → typed config error → the
        # control cannot produce a decisive verdict, but the audit survives).
        try:
            result_bool = apply_operator(
                actual_value, control.expected_value, control.operator,
                control.negated)
        except InvalidControlError as exc:
            return self._finish_review(
                evidence,
                f"Control configuration error for {control.control_id}: "
                f"{exc.reason}.",
                norm_conf, rule_conf)

        # §13.3 step 4: compose confidence from both actual inputs.
        final_conf = compose_confidence(norm_conf, rule_conf)
        if needs_review(final_conf):
            return self._finish_review(
                evidence,
                f"Composed confidence {final_conf} from normalization "
                f"({norm_conf}) x rule ({rule_conf}) is below the 0.70 "
                f"threshold for control {control.control_id}.",
                norm_conf, rule_conf)
        evidence.confidence = final_conf

        evidence.result = "PASS" if result_bool else "FAIL"
        evidence.reasoning = (
            f"Configuration {'complies with' if result_bool else 'violates'} "
            f"{control.control_id}: {control.title}. Actual={actual_value} "
            f"({control.operator} expected={control.expected_value})"
        )

        # Decisive results must be reconstructable (F4 sufficiency gate).
        if not self._sufficient_evidence(evidence, absence_ok=False):
            return self._finish_review(
                evidence,
                f"Insufficient evidence to justify a decisive verdict for "
                f"control {control.control_id}.",
                norm_conf, rule_conf)

        return ControlEvaluationResult(
            control_id=control.control_id,
            result=evidence.result,
            confidence=evidence.confidence,
            evidence=evidence,
            is_automated=True,
        )

    @staticmethod
    def _sufficient_evidence(evidence: BenchmarkEvidence,
                             absence_ok: bool) -> bool:
        """A decisive verdict must be reconstructable from its chain: an
        observed value or matched raw evidence, line numbers (except
        absence-based PASS, which has no lines by definition), a snippet
        and non-empty reasoning."""
        if not evidence.reasoning:
            return False
        if evidence.raw_evidence_snippet == "" and not absence_ok:
            return False
        if not evidence.raw_config_line_numbers and not absence_ok:
            return False
        return True

    def _evaluate_unmapped(
        self,
        control: BenchmarkControl,
        evidence: BenchmarkEvidence,
        raw_config: str,
        raw_lines: list[str],
        rule_conf: float,
    ) -> ControlEvaluationResult:
        """Raw-evidence evaluation for controls without a model path.

        Only explicitly regex-based controls may decide from raw text, and
        only with matched raw evidence recorded. A regex miss is REVIEW
        unless the control explicitly defines absence as a verified FAIL;
        negated (absence-means-compliant) controls PASS on absence because
        that absence IS their defined compliant state.
        """
        try:
            matched, matched_lines = self._match_audit_regex(
                control, raw_config)
        except re.error as exc:
            return self._finish_review(
                evidence,
                f"Control configuration error for {control.control_id}: "
                f"invalid audit_regex ({exc}).",
                None, rule_conf)
        evidence.audit_regex_matched = matched
        evidence.audit_regex = control.audit_regex or ""
        evidence.raw_config_line_numbers = [ln for ln, _ in matched_lines]
        evidence.raw_evidence_snippet = "\n".join(
            text for _, text in matched_lines[:5])
        evidence.raw_config = evidence.raw_evidence_snippet
        evidence.normalization_confidence = None
        evidence.parsed_value = (matched_lines[0][1]
                                 if matched_lines else None)

        if control.negated:
            # Absence of the forbidden pattern is the defined compliant
            # state; the scanned configuration is the evidence.
            if matched:
                evidence.result = "FAIL"
                evidence.reasoning = (
                    f"Negated control {control.control_id}: forbidden "
                    f"pattern found in config but should be absent."
                )
            else:
                evidence.result = "PASS"
                evidence.reasoning = (
                    f"Negated control {control.control_id}: forbidden "
                    f"pattern absent from {len(raw_lines)} scanned lines, "
                    f"which means compliance."
                )
            final_conf = compose_confidence(RAW_MATCH_CONFIDENCE, rule_conf)
            evidence.confidence = (final_conf
                                   if final_conf is not None else rule_conf)
            if needs_review(evidence.confidence):
                return self._finish_review(
                    evidence,
                    f"Raw-evidence confidence {evidence.confidence} below "
                    f"0.70 for control {control.control_id}.",
                    None, rule_conf)
            if not self._sufficient_evidence(evidence, absence_ok=True):
                return self._finish_review(
                    evidence,
                    f"Insufficient evidence for control {control.control_id}.",
                    None, rule_conf)
            return ControlEvaluationResult(
                control_id=control.control_id,
                result=evidence.result,
                confidence=evidence.confidence,
                evidence=evidence,
                is_automated=True,
            )

        if control.audit_regex and matched:
            evidence.result = "PASS"
            evidence.reasoning = (
                f"Explicit regex matched for {control.control_id}: "
                f"{control.title}"
            )
            final_conf = compose_confidence(RAW_MATCH_CONFIDENCE, rule_conf)
            evidence.confidence = (final_conf
                                   if final_conf is not None else rule_conf)
            if needs_review(evidence.confidence):
                return self._finish_review(
                    evidence,
                    f"Raw-evidence confidence {evidence.confidence} below "
                    f"0.70 for control {control.control_id}.",
                    None, rule_conf)
            if not self._sufficient_evidence(evidence, absence_ok=False):
                return self._finish_review(
                    evidence,
                    f"Insufficient evidence for control {control.control_id}.",
                    None, rule_conf)
            return ControlEvaluationResult(
                control_id=control.control_id,
                result="PASS",
                confidence=evidence.confidence,
                evidence=evidence,
                is_automated=True,
            )
        if control.audit_regex and not matched:
            if control.absence_is_fail:
                evidence.result = "FAIL"
                evidence.reasoning = (
                    f"Control {control.control_id} explicitly defines "
                    f"regex absence as a verified FAIL condition."
                )
                final_conf = compose_confidence(RAW_MATCH_CONFIDENCE,
                                                rule_conf)
                evidence.confidence = (final_conf
                                       if final_conf is not None else rule_conf)
                return ControlEvaluationResult(
                    control_id=control.control_id,
                    result="FAIL",
                    confidence=evidence.confidence,
                    evidence=evidence,
                    is_automated=True,
                )
            return self._finish_review(
                evidence,
                f"Regex pattern not matched for {control.control_id}: "
                f"insufficient evidence to establish the required security "
                f"state (a miss is not a verified violation).",
                None, rule_conf)
        return self._finish_review(
            evidence,
            f"No model path or audit regex for control {control.control_id}.",
            None, rule_conf)

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
        norm_conf: Optional[float],
        rule_conf: float,
    ) -> ControlEvaluationResult:
        """Build a REVIEW result with conflict evidence."""
        setting = conflict.get("setting", "setting")
        values = conflict.get("values", [])
        context = conflict.get("context") or conflict.get("blocks") or "configuration"
        evidence.result = "REVIEW"
        evidence.reasoning = (
            f"Conflicting duplicate '{setting}' settings detected: "
            f"{values} in {context}. "
            f"Cannot determine correct value for control {control.control_id}."
        )
        evidence.confidence = self._review_confidence(norm_conf, rule_conf)
        evidence.normalization_confidence = norm_conf
        evidence.raw_evidence_snippet = str(conflict)
        evidence.raw_config = evidence.raw_evidence_snippet
        return ControlEvaluationResult(
            control_id=control.control_id,
            result="REVIEW",
            confidence=evidence.confidence,
            evidence=evidence,
            is_automated=True,
        )

    def _evaluate_multi_block(
        self,
        control: BenchmarkControl,
        norm_result: NormalizationResult,
        raw_config: str,
        evidence: BenchmarkEvidence,
        norm_conf: Optional[float],
        rule_conf: float,
    ) -> ControlEvaluationResult:
        """Evaluate a control across ALL applicable blocks.

        For controls like 1.2.8 (VTY exec-timeout), ALL VTY blocks must satisfy
        the threshold. If ANY block fails, the control FAILS.
        If ANY block has missing data, the control gets REVIEW for that block.
        Confidence is composed from the multi-path mapping confidence and the
        rule confidence; below 0.70 the aggregate is REVIEW.
        """
        multi_path, block_type, eval_mode = self.MULTI_BLOCK_CONTROLS[control.control_id]

        # Extract per-block data
        block_data = self._extract_value(norm_result.universal_config, multi_path)

        if block_data is None or not isinstance(block_data, list):
            return self._finish_review(
                evidence,
                f"Multi-block data not found at '{multi_path}' for control "
                f"{control.control_id}.",
                norm_conf, rule_conf)

        # Filter to relevant block type
        relevant_blocks = [b for b in block_data if b.get("type") == block_type]

        if not relevant_blocks:
            return self._finish_review(
                evidence,
                f"No {block_type} blocks found for control {control.control_id}.",
                norm_conf, rule_conf)

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
                try:
                    result_bool = apply_operator(
                        timeout_val, control.expected_value, control.operator,
                        control.negated)
                except InvalidControlError as exc:
                    return self._finish_review(
                        evidence,
                        f"Control configuration error for {control.control_id}: "
                        f"{exc.reason}.",
                        norm_conf, rule_conf)
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
        evidence.normalized_value = block_data
        # parsed_value: the observed vendor statements behind the blocks.
        evidence.parsed_value = "\n".join(
            str(br.get("raw", "")) for br in block_results
            if br.get("raw")) or None
        evidence.universal_model_path = multi_path
        evidence.normalization_confidence = norm_conf
        evidence.raw_evidence_snippet = "\n".join(evidence_lines)
        evidence.raw_config = evidence.raw_evidence_snippet

        # Also collect raw config lines
        raw_lines = raw_config.splitlines()
        matching_lines = self._find_matching_lines(control, raw_lines)
        evidence.raw_config_line_numbers = [ln for ln, _ in matching_lines]

        final_conf = compose_confidence(norm_conf, rule_conf)
        if needs_review(final_conf):
            return self._finish_review(
                evidence,
                f"Composed confidence {final_conf} below 0.70 for multi-block "
                f"control {control.control_id}.",
                norm_conf, rule_conf)
        evidence.confidence = final_conf

        # Determine aggregate result
        if any_fail:
            failed_blocks = [br for br in block_results if br["result"] == "FAIL"]
            evidence.result = "FAIL"
            evidence.reasoning = (
                f"Control {control.control_id} failed on {len(failed_blocks)}/{len(relevant_blocks)} "
                f"{block_type} blocks. Failed: {[br['block'] for br in failed_blocks]}."
            )
        elif any_review:
            evidence.result = "REVIEW"
            review_blocks = [br for br in block_results if br["result"] == "REVIEW"]
            evidence.reasoning = (
                f"Control {control.control_id}: incomplete data on "
                f"{len(review_blocks)}/{len(relevant_blocks)} {block_type} blocks."
            )
            return self._finish_review(
                evidence, evidence.reasoning, norm_conf, rule_conf)
        else:
            evidence.result = "PASS"
            evidence.reasoning = (
                f"Control {control.control_id}: all {len(relevant_blocks)} {block_type} "
                f"blocks comply ({control.operator} {control.expected_value}s)."
            )

        if not self._sufficient_evidence(evidence, absence_ok=False):
            return self._finish_review(
                evidence,
                f"Insufficient evidence for control {control.control_id}.",
                norm_conf, rule_conf)

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
        """Apply comparison operator (canonical implementation, F8)."""
        return apply_operator(actual, expected, operator, negated)

    @staticmethod
    def _match_audit_regex(control: BenchmarkControl,
                           raw_config: str) -> tuple[bool, list[tuple[int, str]]]:
        """Evaluate the control's explicit audit_regex against raw text.

        The verdict match comes ONLY from the regex itself (re.search over
        the full text, MULTILINE). Keyword fallbacks are display-only and
        must never decide a verdict. Invalid patterns raise re.error (the
        caller converts this into a configuration-error REVIEW).
        """
        matched_lines = BenchmarkExecutionEngine._find_matching_lines(
            control, raw_config.splitlines(), regex_only=True)
        matched = False
        if control.audit_regex:
            matched = bool(re.search(control.audit_regex, raw_config,
                                     re.MULTILINE))
        if not matched_lines:
            matched_lines = BenchmarkExecutionEngine._find_matching_lines(
                control, raw_config.splitlines(), regex_only=False)
        return matched, matched_lines

    @staticmethod
    def _find_matching_lines(
        control: BenchmarkControl, raw_lines: list[str],
        regex_only: bool = False,
    ) -> list[tuple[int, str]]:
        """Find raw config lines relevant to this control.

        With regex_only=True, only audit_regex matches are returned (used
        for verdict-relevant line evidence). Otherwise an audit_command
        keyword fallback adds display lines when the regex finds nothing —
        display-only, never verdict-relevant.
        """
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
        if regex_only or matches:
            return matches
        # Fallback: search for audit_command keywords
        if control.audit_command:
            keywords = [
                w for w in control.audit_command.split()
                if len(w) > 2 and w not in ("show", "running-config", "|", "include", "section")
            ]
            for i, line in enumerate(raw_lines, start=1):
                if any(kw in line for kw in keywords):
                    matches.append((i, line))
        return matches
