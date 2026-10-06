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
    count_affected_interfaces,
)


#: NUL and C0 controls (except tab/LF/CR) have no legitimate place in a
#: configuration under evaluation; they are rejected, never silently kept.
_UNSAFE_INPUT_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: Root statements that OPEN a configuration block. Everything indented
#: under such a header is block content and out of scope for GLOBAL
#: controls (V4-2): only root-level statements decide.
_GLOBAL_BLOCK_START_RE = re.compile(
    r"(?i)^(?:"
    r"interface(?:\s+range)?\b"
    r"|line\s+(?:con(?:sole)?|aux|vty|tty)\b"
    r"|router\s+\S"
    r"|vrf\s+definition\b"
    r"|ip\s+access-list\b"
    r"|control-plane\s*$"
    r"|ip\s+dhcp\s+pool\b"
    r"|object\s+\S"
    r"|key\s+chain\b"
    r"|route-map\b|policy-map\b|class-map\b"
    r"|vlan\s+\d+\s*$"
    r"|crypto\s+\S"
    r")"
)


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
    benchmark_name: str = ""
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
    # REVIEW reason code (§21): INSUFFICIENT_EVIDENCE | UNSUPPORTED_PLATFORM |
    # UNSUPPORTED_SYNTAX | PARSER_ERROR | VERSION_UNKNOWN |
    # BENCHMARK_VERSION_UNKNOWN | AMBIGUOUS_CONFIGURATION |
    # MANUAL_VERIFICATION_REQUIRED. Empty unless result is REVIEW.
    review_code: str = ""
    # How the verdict was reached: exact_structured_match |
    # raw_regex_match | multi_block | unmapped_regex | manual |
    # conflict_review | absence_verified | boundary. Never empty on PASS/FAIL.
    evaluation_method: str = ""
    # Scope + states (§8): every result retains its evaluation scope, the
    # observed configuration state and the required state.
    scope: str = ""
    observed_state: str = ""
    expected_state: str = ""
    # Scope cardinality (Issue #1): evidence blocks evaluated vs affected
    # interfaces. A range block counts 1 block but N interfaces.
    evidence_block_count: int = 0
    affected_scope_count: int = 0


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
    # Verified compliance rate (§15): PASS / (PASS + FAIL). REVIEW is never
    # treated as failure — it is reported separately with its reasons.
    verified_rate: float = 0.0
    # Evidence coverage (§15): controls with sufficient (decisive) evidence
    # over applicable controls. Decisive PASS/FAIL passed the sufficiency
    # gate by construction.
    evidence_coverage: float = 0.0
    # Benchmark applicability (§6): VERIFIED (single benchmark identity) |
    # PARTIAL (dual baseline, each control explicitly identified) | UNKNOWN.
    benchmark_applicability: str = "UNKNOWN"
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
    #   evaluation_mode: "all_must_pass" = every block must satisfy the
    #     threshold via the canonical operator on the block's value_key;
    #     "all_ssh_only" = every block's transports must be ssh-only.
    MULTI_BLOCK_CONTROLS: dict[str, tuple[str, str, str]] = {
        "1.2.8": ("management.vty.exec_timeouts", "vty", "all_must_pass"),
        "1.2.2": ("management.vty.transport_blocks", "vty", "all_ssh_only"),
    }

    # Actual values that mean "no evidence" (§1): UNKNOWN / NOT_FOUND /
    # parser uncertainty must NEVER become FAIL. Only explicit contradictory
    # evidence may produce FAIL.
    NO_EVIDENCE_VALUES = frozenset({"unknown", "", "n/a", "na", "null", "none_found"})

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

        # §15 scoring: verified rate excludes REVIEW; coverage counts
        # decisive (evidence-backed) controls over evaluated ones.
        decisive = passed + failed
        verified_rate = round(passed / decisive * 100, 1) if decisive else 0.0
        evidence_coverage = (round(decisive / evaluated * 100, 1)
                             if evaluated else 0.0)
        benchmark_ids = {c.benchmark_id for c in controls if c.benchmark_id}
        if not benchmark_ids:
            benchmark_applicability = "UNKNOWN"
        elif len(benchmark_ids) == 1:
            benchmark_applicability = "VERIFIED"
        else:
            benchmark_applicability = "PARTIAL"

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
            verified_rate=verified_rate,
            evidence_coverage=evidence_coverage,
            benchmark_applicability=benchmark_applicability,
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
            benchmark_name=getattr(control, "benchmark_name", "") or "",
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
                       rule_conf: float,
                       review_code: str = "INSUFFICIENT_EVIDENCE") -> ControlEvaluationResult:
        """Forced REVIEW with complete evidence and an honest confidence."""
        control.result = "REVIEW"
        control.reasoning = reason
        control.review_code = review_code
        if not control.evaluation_method:
            control.evaluation_method = "review_forced"
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
        # Every result retains its evaluation scope (§8).
        _scope_obj = getattr(control, "scope", None)
        evidence.scope = (_scope_obj.value if hasattr(_scope_obj, "value")
                          else str(_scope_obj or "UNKNOWN"))
        # Human-readable required state from the control definition.
        evidence.expected_state = self._expected_state_text(control)

        # MANUAL controls always → REVIEW (review certainty, not a verdict).
        if control.assessment_status == AssessmentStatus.MANUAL.value:
            evidence.normalization_confidence = None
            evidence.evaluation_method = "manual"
            return self._finish_review(
                evidence,
                f"Manual control: {control.title}. Requires human review.",
                None, 1.0,
                review_code="MANUAL_VERIFICATION_REQUIRED")

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
        # Skip for LINE_AUX / LINE_CONSOLE scoped controls — the legacy
        # conflict index aggregates exec-timeouts across ALL line families,
        # which would falsely report aux/console blocks as conflicting
        # duplicates (§7 isolation).
        _ctrl_scope = getattr(control, "scope", None)
        _scope_val = (_ctrl_scope.value if hasattr(_ctrl_scope, "value")
                      else str(_ctrl_scope or ""))
        if (control.control_id not in self.MULTI_BLOCK_CONTROLS
                and _scope_val not in ("LINE_AUX", "LINE_CONSOLE")):
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

        # SCOPE-AWARE EVALUATION (§2/§3): INTERFACE controls evaluate every
        # interface block independently; GLOBAL controls only root-level
        # statements (never arbitrary interface blocks); ROUTER_PROCESS
        # controls evaluate every routing-process block independently.
        if _scope_val in ("INTERFACE", "INTERFACE_RANGE"):
            return self._evaluate_interface_scope(
                control, norm_result, raw_config, evidence, norm_conf,
                rule_conf, path_facts)
        if _scope_val == "GLOBAL":
            return self._evaluate_global_scope(
                control, raw_config, evidence, rule_conf)
        if _scope_val == "ROUTER_PROCESS":
            return self._evaluate_router_process_scope(
                control, norm_result, raw_config, evidence, norm_conf,
                rule_conf, path_facts)

        actual_value = fact.get("value")
        evidence.actual_value = actual_value

        # Missing value → raw-regex rescue, else REVIEW (never FALSE/FAIL).
        # When the normalizer cannot populate the mapped path but the
        # control's own audit_regex (which by contract matches the
        # COMPLIANT configuration) matches an evidence line, the raw
        # statement rescues the decision as PASS. A miss still falls
        # through to REVIEW — absence is never a violation here.
        if actual_value is None:
            rescued = self._rescue_via_audit_regex(
                control, raw_config, evidence, norm_conf, rule_conf)
            if rescued is not None:
                return rescued
            _miss_detail = ""
            if control.audit_regex:
                _miss_detail = (
                    " No statement matching the compliant pattern was "
                    "observed; absence is not a verified violation.")
            return self._finish_review(
                evidence,
                f"Value not found at path '{control.target_model_path}' "
                f"for control {control.control_id}.{_miss_detail}",
                norm_conf, rule_conf,
                review_code="INSUFFICIENT_EVIDENCE")

        # §1: parser uncertainty is REVIEW, never FAIL. A normalized value
        # of "unknown" (or equivalent) means the parser could not establish
        # state — only explicit contradictory evidence may produce FAIL.
        if isinstance(actual_value, str) and actual_value.strip().lower() in self.NO_EVIDENCE_VALUES:
            return self._finish_review(
                evidence,
                f"Parser could not establish state for control "
                f"{control.control_id} (normalized value "
                f"'{actual_value}'); treating as REVIEW, not FAIL.",
                norm_conf, rule_conf,
                review_code="INSUFFICIENT_EVIDENCE")

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
                norm_conf, rule_conf,
                review_code="PARSER_ERROR")

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
        evidence.evaluation_method = "exact_structured_match"
        evidence.observed_state = str(actual_value)
        # LINE-scoped verdicts carry their enclosing block header so
        # console evidence can never masquerade as AUX (and vice versa).
        _scope_here = (_scope_val or "").upper()
        if _scope_here in ("LINE_AUX", "LINE_CONSOLE", "LINE_VTY"):
            _hdrs = []
            for _ln in (evidence.raw_config_line_numbers or []):
                _h = self._block_at_line(raw_lines, _ln)
                if _h and _h not in evidence.raw_evidence_snippet:
                    _hdrs.append(_h)
            if _hdrs:
                evidence.raw_evidence_snippet = (
                    "\n".join(_hdrs) + "\n" + evidence.raw_evidence_snippet)
                evidence.raw_config = evidence.raw_evidence_snippet
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
                None, rule_conf,
                review_code="PARSER_ERROR")
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
                evidence.evaluation_method = "affirmative_violation"
                evidence.observed_state = (matched_lines[0][1].strip()
                                           if matched_lines else "")
                evidence.reasoning = (
                    f"Negated control {control.control_id}: forbidden "
                    f"pattern found in config but should be absent."
                )
            else:
                evidence.result = "PASS"
                evidence.evaluation_method = "absence_verified"
                evidence.observed_state = (
                    f"forbidden pattern absent from {len(raw_lines)} "
                    f"scanned lines")
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
            # Registry-driven explicit violation (e.g. an RW community
            # string) beats the compliant match: a config with both forms
            # still violates. Non-negated evidence lines only.
            violation_hits: list[tuple[int, str]] = []
            if getattr(control, "violation_regex", ""):
                try:
                    vflags = self._regex_flags(
                        getattr(control, "vendor", ""))
                    vpat = re.compile(control.violation_regex, vflags)
                    vendor_v = getattr(control, "vendor", "") or ""
                    for ln, tx in matched_lines:
                        if re.match(r"(?i)^\s*no\s+", tx):
                            continue
                        if not self._is_evidence_line(tx, vendor_v):
                            continue
                        if vpat.search(tx):
                            violation_hits.append((ln, tx))
                except re.error:
                    violation_hits = []
            if violation_hits:
                evidence.audit_regex_matched = True
                evidence.raw_config_line_numbers = [
                    ln for ln, _ in violation_hits]
                evidence.raw_evidence_snippet = "\n".join(
                    text for _, text in violation_hits[:5])
                evidence.raw_config = evidence.raw_evidence_snippet
                evidence.parsed_value = violation_hits[0][1].strip()
                evidence.actual_value = violation_hits[0][1].strip()
                evidence.observed_state = violation_hits[0][1].strip()
                evidence.result = "FAIL"
                evidence.evaluation_method = "explicit_violation"
                evidence.reasoning = (
                    f"Control {control.control_id}: explicit violation "
                    f"('{violation_hits[0][1].strip()}') matches the "
                    f"control-defined violation pattern."
                )
                final_conf_e = compose_confidence(
                    RAW_MATCH_CONFIDENCE, rule_conf)
                evidence.confidence = (final_conf_e
                                       if final_conf_e is not None else rule_conf)
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
                    result="FAIL",
                    confidence=evidence.confidence,
                    evidence=evidence,
                    is_automated=True,
                )
            evidence.result = "PASS"
            evidence.evaluation_method = "raw_regex_match"
            evidence.observed_state = (matched_lines[0][1].strip()
                                       if matched_lines else "")
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
            # Affirmative-violation check (§1/§8): when the control defines
            # compliance as a negative (`no X`), an observed affirmative
            # (`X`, non-negated, on an evidence line) is explicit
            # contradictory evidence → FAIL. Derived generically from the
            # control's own pattern — never hardcoded per control.
            affirmative = self._derive_affirmative_violation(
                control.audit_regex)
            violation_hits: list[tuple[int, str]] = []
            if affirmative:
                violation_hits = self._match_affirmative_violation(
                    affirmative, raw_lines,
                    self._regex_flags(getattr(control, "vendor", "")),
                    getattr(control, "vendor", "") or "")
            if violation_hits:
                regex_only_lines = self._find_matching_lines(
                    control, raw_lines, regex_only=True)
                last_ok = max((ln for ln, _ in regex_only_lines), default=0)
                last_bad = max(ln for ln, _ in violation_hits)
                if last_ok > last_bad:
                    # Both forms present; the compliant `no` statement is
                    # later — effective state is ambiguous, needs a human.
                    evidence.raw_config_line_numbers = sorted(
                        {ln for ln, _ in regex_only_lines + violation_hits})
                    evidence.raw_evidence_snippet = "\n".join(
                        text for _, text in sorted(
                            regex_only_lines + violation_hits))
                    evidence.evaluation_method = "conflict_review"
                    return self._finish_review(
                        evidence,
                        f"Control {control.control_id}: both compliant and "
                        f"violating statements present; ordering ambiguous, "
                        f"needs human review.",
                        None, rule_conf,
                        review_code="AMBIGUOUS_CONFIGURATION")
                evidence.audit_regex_matched = False
                evidence.raw_config_line_numbers = [
                    ln for ln, _ in violation_hits]
                evidence.raw_evidence_snippet = "\n".join(
                    text for _, text in violation_hits[:5])
                evidence.raw_config = evidence.raw_evidence_snippet
                evidence.parsed_value = violation_hits[0][1]
                evidence.result = "FAIL"
                evidence.evaluation_method = "affirmative_violation"
                evidence.observed_state = violation_hits[0][1].strip()
                evidence.reasoning = (
                    f"Control {control.control_id}: explicit violation "
                    f"evidence observed ({violation_hits[0][1].strip()}) "
                    f"where '{control.audit_regex}'-style absence is required."
                )
                final_conf_v = compose_confidence(
                    RAW_MATCH_CONFIDENCE, rule_conf)
                evidence.confidence = (final_conf_v
                                       if final_conf_v is not None else rule_conf)
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
                    result="FAIL",
                    confidence=evidence.confidence,
                    evidence=evidence,
                    is_automated=True,
                )
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
            None, rule_conf,
            review_code="UNSUPPORTED_SYNTAX")

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
        evidence.review_code = "AMBIGUOUS_CONFIGURATION"
        evidence.evaluation_method = "conflict_review"
        return ControlEvaluationResult(
            control_id=control.control_id,
            result="REVIEW",
            confidence=evidence.confidence,
            evidence=evidence,
            is_automated=True,
        )

    #: Interface feature -> control's audit_regex keyword. Derived from the
    #: control's own pattern (e.g. `no\s+ip\s+redirects` -> redirects), so no
    #: control-id hardcoding: the feature is whatever `ip <feature>` the
    #: control's audit_regex targets.
    _IP_FEATURE_RE = re.compile(r"\\s?ip\\s+(\\S+)" if False else r"ip\\s+(\\S+)")

    @staticmethod
    def _feature_from_audit_regex(audit_regex: str) -> Optional[str]:
        """Derive the interface/global feature from a control's audit_regex.

        The control's audit_regex is a *pattern string* containing a literal
        `\\s+` token, e.g. `no\\s+ip\\s+redirects` -> `redirects`;
        `no\\s+ip\\s+proxy-arp` -> `proxy-arp`. Returns None when the
        pattern does not target an `ip <feature>` statement.
        """
        if not audit_regex:
            return None
        m = re.search(r"ip\\s\+([a-z0-9-]+)", audit_regex, re.IGNORECASE)
        if not m:
            return None
        return m.group(1).replace("-", "_")

    @staticmethod
    def _command_from_audit_regex(audit_regex: str) -> Optional[list[str]]:
        """Derive the full compliant command tokens from audit_regex.

        `no\\s+ip\\s+http\\s+server` -> ['no', 'ip', 'http', 'server'];
        `no\\s+cdp\\s+run` -> ['no', 'cdp', 'run']. Used by global-scope
        matching so `ip http secure-server` never satisfies (or violates)
        a control about `ip http server`. Only meaningful for simple
        literal patterns; returns None otherwise.
        """
        if not audit_regex:
            return None
        # Reject patterns with groups/alternations/quantified tokens —
        # those are not plain commands.
        if re.search(r"[\(\)\[\]\{\}\|]", audit_regex):
            return None
        text = re.sub(r"\\s[\*\+]", " ", audit_regex)
        text = re.sub(r"[\^\$]", " ", text)
        tokens = [t for t in text.split() if t]
        if not tokens or any(re.search(r"[^a-zA-Z0-9_\-]", t) for t in tokens):
            return None
        return tokens

    def _evaluate_interface_scope(
        self,
        control: BenchmarkControl,
        norm_result: NormalizationResult,
        raw_config: str,
        evidence: BenchmarkEvidence,
        norm_conf: Optional[float],
        rule_conf: float,
        path_facts: Optional[dict[str, dict]] = None,
    ) -> ControlEvaluationResult:
        """Interface-scope evaluation (§3/§4/§17).

        Parse every interface block, evaluate each independently, preserve
        context, and aggregate:
          ANY explicit violation -> FAIL (with the violating interface)
          ALL applicable interfaces explicitly compliant -> PASS
          Insufficient evidence -> REVIEW

        A single PASS interface never hides a violating interface.

        Confidence follows the canonical formula (§13.3 step 4) using the
        interface-blocks mapping confidence as the normalization input.
        """
        feature = self._feature_from_audit_regex(control.audit_regex or "")
        evidence.evaluation_method = "interface_scope"
        blocks = self._extract_value(
            norm_result.universal_config, "networking.interface_blocks")
        # Normalization input for the canonical confidence formula: the
        # interface-blocks mapping's own confidence (STRUCTURED_EXTRACTION).
        facts = path_facts or {}
        iface_fact = facts.get("networking.interface_blocks", {})
        iface_conf = iface_fact.get("confidence")
        if iface_conf is None:
            iface_conf = RAW_MATCH_CONFIDENCE
        evidence.normalization_confidence = iface_conf
        evidence.universal_model_path = "networking.interface_blocks"
        if not isinstance(blocks, list) or not blocks:
            return self._finish_review(
                evidence,
                f"No interface blocks found for interface-scoped control "
                f"{control.control_id}.", norm_conf, rule_conf,
                review_code="INSUFFICIENT_EVIDENCE")

        if feature is None:
            # Control's pattern does not name an ip feature — cannot do
            # per-interface decomposition generically.
            return self._finish_review(
                evidence,
                f"Control {control.control_id} has no derivable interface "
                f"feature; interface-scope evaluation is not applicable.",
                norm_conf, rule_conf, review_code="UNSUPPORTED_SYNTAX")

        violations: list[dict] = []
        compliant: list[dict] = []
        neutral: list[dict] = []
        not_applicable: list[dict] = []
        for block in blocks:
            name = str(block.get("name") or "?")
            # Interface lifecycle (Issue #3): SHUTDOWN interfaces and
            # loopbacks cannot forward traffic, so interface hardening is
            # moot — excluded from the applicable set, documented, never
            # counted as compliant and never as violations. ACTIVE and
            # UNKNOWN-lifecycle interfaces remain applicable (shutdown
            # must be explicit; defaults are never guessed).
            lifecycle = str(block.get("lifecycle") or "UNKNOWN").upper()
            if lifecycle == "SHUTDOWN" or block.get("shutdown") or block.get("is_loopback"):
                not_applicable.append({"interface": name})
                continue
            state = block.get(feature)
            if state == "enabled":
                violations.append({
                    "interface": name,
                    "line": block.get("line"),
                    "raw": str(block.get("raw") or ""),
                    "state": "enabled",
                })
            elif state == "disabled":
                compliant.append({
                    "interface": name,
                    "line": block.get("line"),
                    "raw": str(block.get("raw") or ""),
                    "state": "disabled",
                })
            else:
                neutral.append({"interface": name})

        evidence.actual_value = {
            "feature": feature,
            "blocks": [
                {"interface": b.get("name"), feature: b.get(feature)}
                for b in blocks
            ],
        }
        evidence.normalized_value = blocks

        # Aggregation (§3): ANY violation -> FAIL.
        if violations:
            v = violations[0]
            affected = sum(count_affected_interfaces(str(x.get("interface", "")))
                           for x in violations)
            evidence.result = "FAIL"
            evidence.review_code = ""
            evidence.evidence_block_count = len(violations)
            evidence.affected_scope_count = affected
            evidence.reasoning = (
                f"Control {control.control_id} requires ip {feature.replace('_', '-')} "
                f"disabled on every interface; explicit violation on "
                f"{len(violations)} evidence block(s), "
                f"{affected} affected interface(s). Violating interface: "
                f"{v['interface']} with 'ip {feature.replace('_', '-')}'."
            )
            evidence.raw_evidence_snippet = (
                f"{v['interface']}:\n  ip {feature.replace('_', '-')}")
            evidence.raw_config_line_numbers = (
                [int(v["line"])] if isinstance(v["line"], int) else [])
            evidence.raw_config = f"interface {v['interface']}\n ip {feature.replace('_', '-')}"
            evidence.parsed_value = f"ip {feature.replace('_', '-')}"
            evidence.observed_state = (
                f"ip {feature.replace('_', '-')} enabled on {v['interface']}")
            final_conf = compose_confidence(iface_conf, rule_conf)
            if needs_review(final_conf):
                return self._finish_review(
                    evidence,
                    f"Composed confidence {final_conf} below 0.70 for "
                    f"control {control.control_id}.",
                    iface_conf, rule_conf)
            evidence.confidence = final_conf
            return ControlEvaluationResult(
                control_id=control.control_id, result="FAIL",
                confidence=evidence.confidence, evidence=evidence,
                is_automated=True)

        # ALL applicable interfaces explicitly compliant -> PASS.
        # Shutdown/loopback interfaces are not applicable (excluded above).
        if compliant and not neutral:
            evidence.result = "PASS"
            names = ", ".join(c["interface"] for c in compliant[:4])
            affected_ok = sum(count_affected_interfaces(str(c["interface"]))
                              for c in compliant)
            evidence.evidence_block_count = len(compliant)
            evidence.affected_scope_count = affected_ok
            evidence.reasoning = (
                f"Control {control.control_id}: all {len(compliant)} "
                f"applicable interface(s) explicitly disable ip "
                f"{feature.replace('_', '-')}: {names}"
                + (f" ({len(not_applicable)} shutdown/loopback "
                   f"interface(s) not applicable)"
                   if not_applicable else "")
                + "."
            )
            evidence.raw_evidence_snippet = "\n".join(
                f"{c['interface']}: no ip {feature.replace('_', '-')}"
                for c in compliant[:5])
            evidence.raw_config_line_numbers = [
                int(c["line"]) for c in compliant if isinstance(c.get("line"), int)
            ][:5]
            evidence.parsed_value = "disabled"
            evidence.observed_state = (
                f"ip {feature.replace('_', '-')} disabled on all "
                f"{len(compliant)} applicable interface(s)")
            final_conf_p = compose_confidence(iface_conf, rule_conf)
            if needs_review(final_conf_p):
                return self._finish_review(
                    evidence,
                    f"Composed confidence {final_conf_p} below 0.70 for "
                    f"control {control.control_id}.",
                    iface_conf, rule_conf)
            evidence.confidence = final_conf_p
            return ControlEvaluationResult(
                control_id=control.control_id, result="PASS",
                confidence=evidence.confidence, evidence=evidence,
                is_automated=True)

        # Some interfaces have no statement -> insufficient evidence.
        # No applicable interfaces at all -> REVIEW (nothing to verify).
        missing = [n["interface"] for n in neutral]
        if not compliant and not violations and not neutral and not_applicable:
            evidence.result = "REVIEW"
            evidence.reasoning = (
                f"Control {control.control_id}: no applicable interfaces "
                f"({len(not_applicable)} shutdown/loopback excluded); "
                f"nothing to verify."
            )
            evidence.review_code = "INSUFFICIENT_EVIDENCE"
            evidence.raw_evidence_snippet = ""
            evidence.parsed_value = None
            return self._finish_review(
                evidence, evidence.reasoning, norm_conf, rule_conf,
                review_code="INSUFFICIENT_EVIDENCE")
        evidence.result = "REVIEW"
        evidence.reasoning = (
            f"Control {control.control_id}: {len(neutral)} interface(s) "
            f"carry no ip {feature.replace('_', '-')} statement: "
            f"{', '.join(missing[:4])}. A miss is not a verified violation."
        )
        evidence.review_code = "INSUFFICIENT_EVIDENCE"
        evidence.raw_evidence_snippet = "\n".join(
            f"{n['interface']}: (no statement)" for n in neutral[:5])
        evidence.parsed_value = None
        return self._finish_review(
            evidence, evidence.reasoning, norm_conf, rule_conf,
            review_code="INSUFFICIENT_EVIDENCE")

    def _evaluate_router_process_scope(
        self,
        control: BenchmarkControl,
        norm_result: NormalizationResult,
        raw_config: str,
        evidence: BenchmarkEvidence,
        norm_conf: Optional[float],
        rule_conf: float,
        path_facts: Optional[dict[str, dict]] = None,
    ) -> ControlEvaluationResult:
        """Routing-process-scope evaluation (generic, no control-id hacks).

        Every `router ospf|bgp|eigrp|rip|isis` block is evaluated
        independently against the control's own audit_regex (compliant-state
        pattern) plus its derived affirmative violation:
          block with affirmative non-negated statement -> violation
          block with compliant match, no violation -> compliant
          block with neither -> neutral
        Aggregate: ANY violation -> FAIL (block identified); ALL compliant
        -> PASS; else REVIEW. Confidence follows the canonical formula
        using the routing-processes mapping confidence.
        """
        evidence.evaluation_method = "router_process_scope"
        blocks = self._extract_value(
            norm_result.universal_config, "networking.routing_processes")
        facts = path_facts or {}
        rp_fact = facts.get("networking.routing_processes", {})
        rp_conf = rp_fact.get("confidence")
        if rp_conf is None:
            rp_conf = RAW_MATCH_CONFIDENCE
        evidence.normalization_confidence = rp_conf
        evidence.universal_model_path = "networking.routing_processes"
        if not isinstance(blocks, list) or not blocks:
            return self._finish_review(
                evidence,
                f"No routing-process blocks found for control "
                f"{control.control_id}.", norm_conf, rule_conf,
                review_code="INSUFFICIENT_EVIDENCE")

        flags = self._regex_flags(getattr(control, "vendor", ""))
        compliant_pat = control.audit_regex or ""
        affirmative = (self._derive_affirmative_violation(compliant_pat)
                       if compliant_pat else None)
        try:
            comp_re = re.compile(compliant_pat, flags) if compliant_pat else None
        except re.error:
            return self._finish_review(
                evidence,
                f"Control configuration error for {control.control_id}: "
                f"invalid audit_regex.", norm_conf, rule_conf,
                review_code="PARSER_ERROR")
        try:
            aff_re = re.compile(affirmative, flags) if affirmative else None
        except re.error:
            aff_re = None

        violations: list[dict] = []
        compliant: list[dict] = []
        neutral: list[dict] = []
        for block in blocks:
            name = str(block.get("name") or "?")
            statements = block.get("statements") or []
            texts = [
                str(s.get("text") or "")
                for s in statements
                if self._is_evidence_line(str(s.get("raw") or s.get("text") or ""))
            ]
            neg_texts = [
                str(s.get("text") or "")
                for s in statements
                if s.get("negated")
                and self._is_evidence_line(str(s.get("raw") or s.get("text") or ""))
            ]
            hit_violation = any(
                aff_re.search(t) and not re.match(r"(?i)^\s*no\s+", t)
                for t in texts) if aff_re is not None else False
            hit_compliant = any(
                comp_re.search(t) for t in texts) if comp_re is not None else False
            # A negated compliant statement (`no X`) inside the block also
            # counts as explicit compliance.
            hit_negated = any(
                comp_re.search(t) for t in neg_texts) if comp_re is not None else False
            if hit_violation:
                violations.append({"process": name,
                                   "line": block.get("line"),
                                   "raw": str(block.get("raw") or "")})
            elif hit_compliant or hit_negated:
                compliant.append({"process": name,
                                  "line": block.get("line"),
                                  "raw": str(block.get("raw") or "")})
            else:
                neutral.append({"process": name})

        evidence.actual_value = {
            "processes": [
                {"process": b.get("name"),
                 "statements": len(b.get("statements") or [])}
                for b in blocks
            ],
        }
        evidence.normalized_value = blocks

        if violations:
            v = violations[0]
            evidence.result = "FAIL"
            evidence.review_code = ""
            evidence.reasoning = (
                f"Control {control.control_id}: explicit violation in "
                f"routing process '{v['process']}' "
                f"({len(violations)}/{len(blocks)} processes)."
            )
            evidence.raw_evidence_snippet = (
                f"{v['process']}:\n  violation observed")
            evidence.raw_config_line_numbers = (
                [int(v["line"])] if isinstance(v["line"], int) else [])
            evidence.raw_config = str(v.get("raw") or "")
            evidence.parsed_value = str(v.get("raw") or "")
            final_conf = compose_confidence(rp_conf, rule_conf)
            if needs_review(final_conf):
                return self._finish_review(
                    evidence,
                    f"Composed confidence {final_conf} below 0.70 for "
                    f"control {control.control_id}.",
                    rp_conf, rule_conf)
            evidence.confidence = final_conf
            return ControlEvaluationResult(
                control_id=control.control_id, result="FAIL",
                confidence=evidence.confidence, evidence=evidence,
                is_automated=True)

        if compliant and not neutral:
            evidence.result = "PASS"
            evidence.reasoning = (
                f"Control {control.control_id}: all {len(compliant)} "
                f"routing process(es) explicitly compliant."
            )
            evidence.raw_evidence_snippet = "\n".join(
                c["process"] for c in compliant[:5])
            evidence.raw_config_line_numbers = [
                int(c["line"]) for c in compliant if isinstance(c.get("line"), int)
            ][:5]
            evidence.parsed_value = "compliant"
            final_conf_p = compose_confidence(rp_conf, rule_conf)
            if needs_review(final_conf_p):
                return self._finish_review(
                    evidence,
                    f"Composed confidence {final_conf_p} below 0.70 for "
                    f"control {control.control_id}.",
                    rp_conf, rule_conf)
            evidence.confidence = final_conf_p
            return ControlEvaluationResult(
                control_id=control.control_id, result="PASS",
                confidence=evidence.confidence, evidence=evidence,
                is_automated=True)

        missing = [n["process"] for n in neutral]
        evidence.result = "REVIEW"
        evidence.reasoning = (
            f"Control {control.control_id}: {len(neutral)} routing "
            f"process(es) carry no relevant statement: "
            f"{', '.join(missing[:4])}. A miss is not a verified violation."
        )
        evidence.review_code = "INSUFFICIENT_EVIDENCE"
        evidence.parsed_value = None
        return self._finish_review(
            evidence, evidence.reasoning, rp_conf, rule_conf,
            review_code="INSUFFICIENT_EVIDENCE")

    def _evaluate_global_scope(
        self,
        control: BenchmarkControl,
        raw_config: str,
        evidence: BenchmarkEvidence,
        rule_conf: float,
    ) -> ControlEvaluationResult:
        """Global-scope evaluation (§5): only root-level statements decide.

        A global control (e.g. 2.1.16 ip source-route) must never be
        satisfied or violated by statements inside interface blocks, and a
        `description` containing the phrase is never evidence.
        """
        feature = self._feature_from_audit_regex(control.audit_regex or "")
        evidence.evaluation_method = "global_scope"
        evidence.actual_value = None
        # Full compliant command (e.g. ['no','ip','http','server']) so
        # `ip http secure-server` can never match a control about
        # `ip http server`. Falls back to the single feature word.
        cmd_tokens = self._command_from_audit_regex(control.audit_regex or "")
        if cmd_tokens and cmd_tokens[0].lower() == "no":
            cmd_affirm = cmd_tokens[1:]
        elif cmd_tokens:
            cmd_affirm = cmd_tokens
        else:
            cmd_affirm = []
        if feature is None and not cmd_affirm:
            return self._finish_review(
                evidence,
                f"Control {control.control_id} has no derivable global "
                f"feature; global-scope evaluation is not applicable.",
                None, rule_conf, review_code="UNSUPPORTED_SYNTAX")

        # Feature name with hyphen (proxy-arp) and underscore forms both
        # match the CLI token.
        feat_hyphen = (feature or "").replace("_", "-")
        # Ordered (line, text, negated) matches: IOS overwrite semantics
        # mean the LAST matching root statement decides the verdict (V4-2).
        matches: list[tuple[int, str, bool]] = []
        raw_lines = raw_config.splitlines()
        banner_body = NormalizationEngine._banner_body_lines(raw_lines)
        in_block = False
        for ln, raw in enumerate(raw_lines, start=1):
            if (ln - 1) in banner_body:
                continue
            stripped = raw.strip()
            if not stripped or stripped.startswith("!"):
                continue
            # Any non-root block (interface, line, router, ACL, VRF ...)
            # hides its children from global evaluation: only root-level
            # statements are in scope for a GLOBAL control (V4-2/V4-7).
            if _GLOBAL_BLOCK_START_RE.match(stripped):
                in_block = True
                continue
            if in_block:
                # End of block: a non-indented root-level statement
                # (checked on the RAW line) or end/!.
                if re.match(r"(?i)^(?:end|!)\s*$", stripped) or (
                        raw and raw[0] not in (" ", "\t")):
                    in_block = False
                else:
                    continue
            if re.match(r"(?i)^description\b", stripped):
                continue
            # Match the full affirmative command (word-boundary); a lone
            # `ip http` never matches `ip http server` and vice versa.
            if cmd_affirm:
                body = r"\s+".join(re.escape(t) for t in cmd_affirm)
                m = re.match(rf"(?i)^(no\s+)?{body}\b", stripped)
            else:
                # `ip <feature>` may carry a trailing subcommand (`ip http
                # server`), so match a word boundary, not end-of-line.
                m = re.match(
                    rf"(?i)^(no\s+)?ip\s+{re.escape(feat_hyphen)}\b", stripped)
            if not m:
                continue
            matches.append((ln, stripped, bool(m.group(1))))

        # The deciding statement is the LAST match in file order.
        dec_ln, dec_text, dec_negated = matches[-1] if matches else (0, "", False)
        evidence.raw_config_line_numbers = [dec_ln] if matches else []
        evidence.raw_evidence_snippet = dec_text
        evidence.raw_config = evidence.raw_evidence_snippet
        # Raw-evidence decisions compose from RAW_MATCH_CONFIDENCE (0.85),
        # exactly like the canonical unmapped path — never an invented 0.8.
        evidence.normalization_confidence = RAW_MATCH_CONFIDENCE

        if matches and not dec_negated:
            evidence.result = "FAIL"
            evidence.reasoning = (
                f"Control {control.control_id}: global statement "
                f"'{dec_text}' explicitly enables ip {feat_hyphen} "
                f"(last matching statement decides)."
            )
            evidence.parsed_value = dec_text
            evidence.actual_value = dec_text
            evidence.normalized_value = {feature: "enabled"}
            evidence.observed_state = (
                f"ip {feat_hyphen} enabled (global statement "
                f"'{dec_text}')")
            final_conf_a = compose_confidence(RAW_MATCH_CONFIDENCE, rule_conf)
            if needs_review(final_conf_a):
                return self._finish_review(
                    evidence,
                    f"Composed confidence {final_conf_a} below 0.70 for "
                    f"control {control.control_id}.",
                    RAW_MATCH_CONFIDENCE, rule_conf)
            evidence.confidence = final_conf_a
            return ControlEvaluationResult(
                control_id=control.control_id, result="FAIL",
                confidence=evidence.confidence, evidence=evidence,
                is_automated=True)
        if matches and dec_negated:
            evidence.result = "PASS"
            evidence.reasoning = (
                f"Control {control.control_id}: global statement "
                f"'{dec_text}' explicitly disables ip {feat_hyphen} "
                f"(last matching statement decides)."
            )
            evidence.parsed_value = dec_text
            evidence.actual_value = dec_text
            evidence.normalized_value = {feature: "disabled"}
            evidence.observed_state = (
                f"ip {feat_hyphen} disabled (global statement "
                f"'{dec_text}')")
            final_conf_n = compose_confidence(RAW_MATCH_CONFIDENCE, rule_conf)
            if needs_review(final_conf_n):
                return self._finish_review(
                    evidence,
                    f"Composed confidence {final_conf_n} below 0.70 for "
                    f"control {control.control_id}.",
                    RAW_MATCH_CONFIDENCE, rule_conf)
            evidence.confidence = final_conf_n
            return ControlEvaluationResult(
                control_id=control.control_id, result="PASS",
                confidence=evidence.confidence, evidence=evidence,
                is_automated=True)
        return self._finish_review(
            evidence,
            f"Control {control.control_id}: no global ip {feat_hyphen} "
            f"statement; absence is not a verified violation.",
            None, rule_conf, review_code="INSUFFICIENT_EVIDENCE")

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
        any_review = False
        any_fail = False

        if eval_mode == "all_ssh_only":
            # CIS 1.2.2 semantics per block: ssh-only transport required.
            # ["ssh"] → PASS; ["none"] → PASS (no remote access at all);
            # missing/empty → REVIEW; anything else (telnet, all, ...) → FAIL.
            for block in relevant_blocks:
                block_label = block.get("block", f"line {block_type}")
                transports = block.get("transports")
                raw_line = block.get("raw", "")
                if not transports:
                    block_results.append({
                        "block": block_label,
                        "transports": transports,
                        "result": "REVIEW",
                        "raw": raw_line,
                    })
                    any_review = True
                    continue
                tset = {str(t).lower() for t in transports}
                if tset == {"ssh"} or tset == {"none"}:
                    block_results.append({
                        "block": block_label,
                        "transports": transports,
                        "result": "PASS",
                        "raw": raw_line,
                    })
                else:
                    block_results.append({
                        "block": block_label,
                        "transports": transports,
                        "result": "FAIL",
                        "raw": raw_line,
                    })
                    any_fail = True
        else:
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

        # Aggregate evidence: show ALL blocks
        evidence_lines = []
        for br in block_results:
            evidence_lines.append(f"{br['block']}:")
            if br['raw']:
                evidence_lines.append(f"  {br['raw']}")
            if eval_mode == "all_ssh_only":
                evidence_lines.append(
                    f"  → transports={br.get('transports')}, "
                    f"result={br['result']}")
            else:
                evidence_lines.append(
                    f"  → timeout={br.get('timeout')}s, "
                    f"result={br['result']}")
        evidence.evaluation_method = "multi_block"

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
            evidence.observed_state = "; ".join(
                f"{br['block']}: "
                f"{br.get('transports', br.get('timeout'))}"[:80]
                for br in failed_blocks[:3])
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
            evidence.observed_state = (
                f"all {len(relevant_blocks)} {block_type} blocks compliant")
            if eval_mode == "all_ssh_only":
                evidence.reasoning = (
                    f"Control {control.control_id}: all "
                    f"{len(relevant_blocks)} {block_type} blocks enforce "
                    f"ssh-only transport."
                )
            else:
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
    def _is_evidence_line(line: str, vendor: str = "") -> bool:
        """Only actual configuration commands count as evidence (§12).

        Excludes blanks, `!` comment lines (Cisco), `#` comment lines
        (Juniper/Fortinet inactive and comment markers), and `description`
        free-text lines: a `description "transport input ssh"` must never
        satisfy a control. Banner bodies are excluded by the parser
        upstream; this is the raw-text safety net for regex matching.
        """
        stripped = line.strip()
        if not stripped:
            return False
        if stripped.startswith("!"):
            return False
        if (vendor or "").lower() in ("juniper", "fortinet"):
            # Single `#` is a comment, but `##`-prefixed lines are active
            # JunOS content (show-configuration style) — the parser strips
            # the prefix and treats them as real statements.
            if stripped.startswith("#") and not stripped.startswith("##"):
                return False
        if re.match(r"(?i)^description\b", stripped):
            return False
        # ACL `remark` lines are free-text annotations, never commands:
        # `remark no lldp run` and `access-list 99 remark ... no cdp run`
        # must not satisfy a control about the real command (V4-6).
        # Mirrors _CISCO_ACL_ENTRY_RE, which already requires
        # permit/deny/evaluate after the optional index.
        if re.match(
            r"(?i)^(?:access-list\s+\S+\s+)?(?:\d+\s+)?remark\b", stripped
        ):
            return False
        return True

    @staticmethod
    def _regex_flags(vendor: str) -> int:
        """Cisco IOS CLI is case-insensitive; its audit patterns match
        regardless of case. Other vendors keep exact matching."""
        flags = re.MULTILINE
        if (vendor or "").lower() == "cisco":
            flags |= re.IGNORECASE
        return flags

    @staticmethod
    def _derive_affirmative_violation(audit_regex: str) -> Optional[str]:
        """Derive the forbidden affirmative from a compliant-negative pattern.

        Controls like 2.1.7 (`no\\s+service\\s+finger`) define compliance as
        absence of `service finger`. The affirmative form — the same pattern
        with the leading `no` + whitespace-class removed — is explicit
        contradictory evidence and must produce FAIL when observed on a
        non-negated evidence line. Returns None when the pattern does not
        define a compliant negative (no derivation invented).

        Note: audit_regex is a *pattern string*, so stripping operates on
        pattern tokens (`^`, `\\s*`, `no`) — not on whitespace text.
        """
        if not audit_regex:
            return None
        s = audit_regex.strip()
        # Leading ^ anchor.
        s = re.sub(r"^\^", "", s)
        # Leading whitespace-class tokens (`\s*`, `\s+`) and literal spaces.
        s = re.sub(r"^(?:\\s[\*\+]|\s)+", "", s)
        # Leading `no` keyword followed by a whitespace class. The required
        # whitespace after `no` prevents false stripping of words like
        # `node` or `noteworthy`.
        m = re.match(r"(?i)^no(?:\\s[\*\+]|\s)+(.*)$", s, re.DOTALL)
        if not m:
            return None
        rest = m.group(1).strip()
        if not rest:
            return None
        return rest

    def _rescue_via_audit_regex(
        self,
        control: BenchmarkControl,
        raw_config: str,
        evidence: BenchmarkEvidence,
        norm_conf: Optional[float],
        rule_conf: float,
    ) -> Optional[ControlEvaluationResult]:
        """Raw-regex rescue for mapped controls with missing values.

        Returns a PASS result when the control's audit_regex (contractually
        the COMPLIANT-state pattern) matches an evidence line, else None
        (caller falls through to REVIEW). Rescue can only produce PASS,
        never FAIL, and records method raw_regex_rescue with the observed
        statement as actual_value.
        """
        if not control.audit_regex:
            return None
        try:
            matched, matched_lines = self._match_audit_regex(
                control, raw_config)
        except re.error:
            return None
        if not matched or not matched_lines:
            return None
        # Scope gate (§3/§5): the rescued line must live inside the
        # control's scope. A console `exec-timeout` must never rescue an
        # AUX-scoped control.
        scope_val = ""
        _scope_obj = getattr(control, "scope", None)
        if _scope_obj is not None:
            scope_val = (_scope_obj.value if hasattr(_scope_obj, "value")
                         else str(_scope_obj))
        raw_lines_all = raw_config.splitlines()
        banner_all = NormalizationEngine._banner_body_lines(raw_lines_all)
        usable = [(ln, tx) for ln, tx in matched_lines
                  if not re.match(r"(?i)^\s*no\s+", tx)
                  and self._line_in_scope(raw_lines_all, ln, scope_val)
                  and not self._superseded_by_later_statement(
                      raw_lines_all, ln, tx, banner_all)]
        if not usable:
            return None
        line_no, line_text = usable[0]
        evidence.audit_regex_matched = True
        evidence.audit_regex = control.audit_regex
        evidence.raw_config_line_numbers = [line_no]
        evidence.raw_evidence_snippet = line_text.strip()
        # Scope context in the snippet: the enclosing block header travels
        # with the statement (console evidence never masquerades as AUX).
        header = self._block_at_line(raw_lines_all, line_no)
        if header and header not in evidence.raw_evidence_snippet:
            evidence.raw_evidence_snippet = (
                f"{header}\n  {line_text.strip()}")
        evidence.raw_config = evidence.raw_evidence_snippet
        evidence.parsed_value = line_text.strip()
        evidence.actual_value = line_text.strip()
        evidence.observed_state = line_text.strip()
        # No normalizer mapping exists (hence the rescue); record the raw
        # observed statement as the judged value so the row is complete.
        evidence.normalized_value = line_text.strip()
        evidence.normalization_confidence = RAW_MATCH_CONFIDENCE
        evidence.result = "PASS"
        evidence.evaluation_method = "raw_regex_rescue"
        evidence.reasoning = (
            f"Control {control.control_id}: normalizer produced no value, "
            f"but the compliant-state pattern matched '{line_text.strip()}' "
            f"(line {line_no})."
        )
        final_conf = compose_confidence(RAW_MATCH_CONFIDENCE, rule_conf)
        if needs_review(final_conf):
            return None
        evidence.confidence = final_conf
        if not self._sufficient_evidence(evidence, absence_ok=False):
            return None
        return ControlEvaluationResult(
            control_id=control.control_id,
            result="PASS",
            confidence=evidence.confidence,
            evidence=evidence,
            is_automated=True,
        )

    @staticmethod
    def _expected_state_text(control: BenchmarkControl) -> str:
        """Human-readable required state for reports (§8/§13)."""
        if control.audit_regex:
            return f"configuration matching '{control.audit_regex}'"
        if control.target_model_path:
            return (f"{control.target_model_path} {control.operator} "
                    f"{control.expected_value}")
        if control.negated:
            return "forbidden pattern absent"
        return "required state per benchmark"

    @staticmethod
    def _block_at_line(raw_lines: list[str], line_no: int) -> str:
        """Enclosing block header for a 1-based line number.

        Tracks `line aux|console|vty ...` and `interface ...` headers in
        raw order; returns the header text (e.g. `line aux 0`) or "" for
        root-level lines. Generic, scope-agnostic.
        """
        current = ""
        for idx, raw in enumerate(raw_lines, start=1):
            if idx > line_no:
                break
            stripped = raw.strip()
            if not stripped or stripped.startswith("!"):
                continue
            if re.match(r"(?i)^(?:line\s+(?:aux|con(?:sole)?|vty)\b|interface\b)", stripped):
                current = stripped
                continue
            if stripped.lower() == "end" or (
                    raw and raw[0] not in (" ", "\t")):
                # Root-level statement ends any block context (except the
                # header line itself, handled above).
                if idx < line_no and not re.match(
                        r"(?i)^(?:line\s+(?:aux|con(?:sole)?|vty)\b|interface\b)",
                        stripped):
                    current = ""
        return current

    @staticmethod
    def _superseded_by_later_statement(
        raw_lines: list[str], line_no: int, line_text: str,
        banner_body: Optional[set[int]] = None,
    ) -> bool:
        """True when a LATER statement in the same block negates this line.

        IOS applies configuration in order: `access-class MGMT in` at line
        100 followed by `no access-class MGMT in` at line 150 leaves the
        ACL UNapplied — a positive rescue line whose effect was undone
        later must not rescue the control (V4-11, order-aware rescue).
        Same-block only: another VTY range's removal never undoes this
        line's effect.
        """
        base = re.sub(r"(?i)^\s*no\s+", "", line_text.strip())
        norm = " ".join(base.split()).lower()
        if not norm:
            return False
        banner = banner_body if banner_body is not None else set()

        def eff_header(n: int) -> str:
            raw = raw_lines[n - 1]
            if raw and raw[0] not in (" ", "\t") and not re.match(
                    r"(?i)^(?:line\s+(?:aux|con(?:sole)?|vty)\b|interface\b)",
                    raw.strip()):
                # A root statement is root regardless of what preceded it.
                return ""
            return BenchmarkExecutionEngine._block_at_line(raw_lines, n)

        header = eff_header(line_no)
        for idx in range(line_no + 1, len(raw_lines) + 1):
            if (idx - 1) in banner:
                continue
            later = raw_lines[idx - 1]
            if not BenchmarkExecutionEngine._is_evidence_line(later, ""):
                continue
            cand = re.sub(r"(?i)^\s*no\s+", "", later.strip())
            if " ".join(cand.split()).lower() != norm:
                continue
            if eff_header(idx) == header:
                return True
        return False

    @staticmethod
    def _line_in_scope(raw_lines: list[str], line_no: int, scope: str) -> bool:
        """Whether a line belongs to the control's scope (§3/§5 isolation).

        LINE_AUX → inside `line aux`; LINE_CONSOLE → `line con/console`;
        LINE_VTY → `line vty`; INTERFACE → inside `interface`;
        GLOBAL → root level (no enclosing block).
        """
        header = BenchmarkExecutionEngine._block_at_line(raw_lines, line_no)
        scope = (scope or "").upper()
        if scope == "LINE_AUX":
            return bool(re.match(r"(?i)^line\s+aux\b", header))
        if scope == "LINE_CONSOLE":
            return bool(re.match(r"(?i)^line\s+con(?:sole)?\b", header))
        if scope == "LINE_VTY":
            return bool(re.match(r"(?i)^line\s+vty\b", header))
        if scope in ("INTERFACE", "INTERFACE_RANGE"):
            return header.lower().startswith("interface")
        if scope == "GLOBAL":
            return header == ""
        return True

    @staticmethod
    def _match_affirmative_violation(
        affirmative: str, raw_lines: list[str], flags: int,
        vendor: str = "",
    ) -> list[tuple[int, str]]:
        """Find non-negated lines matching the affirmative violation pattern."""
        try:
            pat = re.compile(affirmative, flags)
        except re.error:
            return []
        hits: list[tuple[int, str]] = []
        banner_body = NormalizationEngine._banner_body_lines(raw_lines)
        for i, line in enumerate(raw_lines, start=1):
            if (i - 1) in banner_body:
                continue
            if not BenchmarkExecutionEngine._is_evidence_line(line, vendor):
                continue
            # A negated line (`no X`) is compliance evidence, not violation.
            if re.match(r"(?i)^\s*no\s+", line):
                continue
            if pat.search(line):
                hits.append((i, line))
        return hits

    @staticmethod
    def _match_audit_regex(control: BenchmarkControl,
                           raw_config: str) -> tuple[bool, list[tuple[int, str]]]:
        """Evaluate the control's explicit audit_regex against raw text.

        The verdict match comes ONLY from the regex itself over evidence
        lines (comments/descriptions excluded), MULTILINE (+ IGNORECASE for
        Cisco). Keyword fallbacks are display-only and must never decide a
        verdict. Invalid patterns raise re.error (the caller converts this
        into a configuration-error REVIEW).
        """
        flags = BenchmarkExecutionEngine._regex_flags(
            getattr(control, "vendor", ""))
        vendor = getattr(control, "vendor", "") or ""
        matched_lines = BenchmarkExecutionEngine._find_matching_lines(
            control, raw_config.splitlines(), regex_only=True)
        matched = False
        if control.audit_regex:
            try:
                vpat = re.compile(control.audit_regex, flags)
            except re.error:
                raise
            audit_lines = raw_config.splitlines()
            banner_body = NormalizationEngine._banner_body_lines(audit_lines)
            for i, line in enumerate(audit_lines, start=1):
                if (i - 1) in banner_body:
                    # Banner payloads are parser decorations (V4-7),
                    # matching the normalization evidence layer.
                    continue
                if not BenchmarkExecutionEngine._is_evidence_line(line, vendor):
                    continue
                m = vpat.search(line)
                if not m:
                    continue
                # Token-boundary guard: a pattern without a `^` anchor must
                # not match inside a longer hyphenated/word token
                # (`server` inside `boot-server` is not an NTP server).
                # Anchored patterns already constrain position themselves.
                if not control.audit_regex.lstrip().startswith("^"):
                    if m.start() > 0 and (
                            line[m.start() - 1].isalnum()
                            or line[m.start() - 1] in ("-", "_", ".")):
                        continue
                matched = True
                break
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
        # Try audit_regex first (evidence lines only; Cisco case-insensitive)
        flags = BenchmarkExecutionEngine._regex_flags(
            getattr(control, "vendor", ""))
        vendor = getattr(control, "vendor", "") or ""
        banner_body = NormalizationEngine._banner_body_lines(raw_lines)
        if control.audit_regex:
            try:
                pat = re.compile(control.audit_regex, flags)
                for i, line in enumerate(raw_lines, start=1):
                    if (i - 1) in banner_body:
                        continue
                    if not BenchmarkExecutionEngine._is_evidence_line(line, vendor):
                        continue
                    if pat.search(line):
                        matches.append((i, line))
            except re.error:
                pass
        if regex_only or matches:
            return matches
        # Fallback: search for audit_command keywords (display-only)
        if control.audit_command:
            keywords = [
                w for w in control.audit_command.split()
                if len(w) > 2 and w not in ("show", "running-config", "|", "include", "section")
            ]
            lowered = (getattr(control, "vendor", "") or "").lower() == "cisco"
            for i, line in enumerate(raw_lines, start=1):
                if (i - 1) in banner_body:
                    continue
                if not BenchmarkExecutionEngine._is_evidence_line(line, vendor):
                    continue
                hay = line.lower() if lowered else line
                if any((kw.lower() if lowered else kw) in hay for kw in keywords):
                    matches.append((i, line))
        return matches
