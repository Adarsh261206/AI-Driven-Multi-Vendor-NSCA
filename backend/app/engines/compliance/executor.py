"""
Audit Executor

Orchestrates the full compliance audit pipeline:
INGEST → VALIDATE → DETECT → PARSE → NORMALIZE → EVALUATE → FINDINGS

Uses the unified BenchmarkExecutionEngine as the canonical evaluation path.

The retired ControlLoader/RuleEngine pipeline (app.engines.compliance.loader,
app.engines.compliance.engine RuleEngine, app.engines.compliance.cisco_controls)
is NOT imported and NOT used in the main audit path; those modules carry
explicit DEPRECATED markers and survive only for backward compatibility with
existing unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime, timezone

from app.benchmarks.selection import (
    DUAL_BASELINE,
    normalize_framework,
    normalize_framework_version,
    overall_score,
)
from app.engines.compliance.models import ComplianceResultType
from app.engines.compliance.engine import ComplianceEvaluation
from app.engines.compliance.findings import Finding, FindingGenerator
from app.engines.validation import ConfigurationValidator
from app.engines.detection import VendorDetector, SUPPORTED_COMPLIANCE_VENDORS
from app.engines.normalization import NormalizationEngine, NormalizationResultType
from app.benchmarks.execution import BenchmarkExecutionEngine, BenchmarkExecutionResult


@dataclass
class AuditStep:
    """A step in the audit pipeline"""
    name: str
    status: str = "pending"  # pending, running, completed, failed
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Any] = None
    error: Optional[str] = None


@dataclass
class AuditResult:
    """Complete audit result"""
    audit_id: str
    status: str = "pending"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Device info
    vendor: str = ""
    platform: str = ""
    firmware_version: str = ""
    detection_confidence: float = 0.0
    # Canonical device identity (§4/§5): device_type from configuration
    # characteristics (never filename), hostname from config, os_family as
    # the single canonical evaluation platform (e.g. ios_xe, never ios).
    device_type: str = "unknown"
    hostname: str = ""
    os_family: str = ""
    
    # Pipeline results
    validation_result: Optional[Any] = None
    detection_result: Optional[Any] = None
    parse_result: Optional[Any] = None
    semantic_interpretation: Optional[Any] = None
    normalization_result: Optional[Any] = None
    compliance_evaluation: Optional[ComplianceEvaluation] = None
    benchmark_result: Optional[BenchmarkExecutionResult] = None
    findings: list[Finding] = field(default_factory=list)
    
    # Summary
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    review: int = 0
    overall_score: float = 0.0
    # Requested framework selection (F1): the canonical mode actually used.
    framework: str = ""
    framework_version: str = ""
    
    # Steps tracking
    steps: list[AuditStep] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "device": {
                "vendor": self.vendor,
                "platform": self.platform,
                "os_family": self.os_family,
                "device_type": self.device_type,
                "hostname": self.hostname,
                "firmware_version": self.firmware_version,
                "detection_confidence": self.detection_confidence,
            },
            "summary": {
                "total_controls": self.total_controls,
                "passed": self.passed,
                "failed": self.failed,
                "review": self.review,
                "overall_score": self.overall_score,
                "findings_count": len(self.findings),
            },
            "steps": [
                {"name": s.name, "status": s.status}
                for s in self.steps
            ],
        }


class AuditExecutor:
    """
    Audit Executor
    
    Orchestrates the full compliance audit pipeline.
    Uses BenchmarkExecutionEngine as the canonical evaluation path.
    """
    
    def __init__(self):
        self.finding_generator = FindingGenerator()
        self.validator = ConfigurationValidator()
        self.detector = VendorDetector()
        self.normalizer = NormalizationEngine()
        self.benchmark_engine = BenchmarkExecutionEngine()
    
    def _get_parser(self, vendor: str, platform: str):
        """Get the appropriate parser for the detected vendor/platform."""
        # E04 F3/F9/F10: single central selection contract. Unsupported or
        # unknown vendors get None (explicit no-parser outcome); platform is
        # accepted but one parser covers each vendor family.
        from app.engines.parsing import get_parser
        return get_parser(vendor, platform)

    @staticmethod
    def _build_semantic_interpretation(parse_result: Any) -> dict[str, Any]:
        """Build the §10.5 semantic interpretation payload from a parse tree.

        Deterministic and knowledge-base free: sections and unknowns come
        straight from the E04 ParseResult (full node dicts incl. negation
        and line numbers). The normalizer consumes this; the API persists it.
        """
        sections: list[dict[str, Any]] = []
        unknown: list[dict[str, Any]] = []
        if parse_result is not None:
            for node in (getattr(parse_result, "parse_tree", None) or []):
                try:
                    sections.append(node.to_dict())
                except Exception:
                    continue
            for item in (getattr(parse_result, "unknown_sections", None) or []):
                try:
                    unknown.append(item.to_dict())
                except Exception:
                    continue
        return {"id": None, "sections": sections, "unknown": unknown}

    def execute(
        self,
        audit_id: str,
        config_content: str,
        framework: str = "CIS",
        framework_version: Optional[str] = None,
        device_name: str = "",
    ) -> AuditResult:
        """
        Execute a full compliance audit

        Args:
            audit_id: Unique audit identifier
            config_content: Raw configuration content
            framework: Compliance framework (CIS, NIST, explicit CIS+NIST
                dual, or None for the canonical dual baseline). Unknown
                frameworks raise UnsupportedFrameworkError (F1).
            framework_version: Framework version (must exist in inventory)
            device_name: Name of the device

        Returns:
            AuditResult with all findings
        """
        # F1: framework selection is real — normalize and validate BEFORE
        # any work so CIS/NIST/BOGUS can never produce identical runs.
        # Unknown frameworks/versions raise typed errors here (the DB
        # pipeline catches them and marks the audit failed; direct callers
        # get the typed error, never a silent fallback).
        framework_c = normalize_framework(framework)
        version_c = normalize_framework_version(framework_version)
        if framework_c is None:
            framework_c = DUAL_BASELINE
        if version_c is not None:
            for wanted in (("CIS", "NIST") if framework_c == DUAL_BASELINE
                           else (framework_c,)):
                self.benchmark_engine.selection.validate_framework_version(
                    wanted, version_c)

        result = AuditResult(audit_id=audit_id)
        result.started_at = datetime.now(timezone.utc)
        result.status = "processing"
        result.framework = framework_c
        result.framework_version = version_c or ""
        
        # Initialize steps
        steps = [
            AuditStep(name="validation"),
            AuditStep(name="detection"),
            AuditStep(name="parsing"),
            AuditStep(name="normalization"),
            AuditStep(name="compliance_evaluation"),
            AuditStep(name="finding_generation"),
        ]
        result.steps = steps
        
        try:
            # Step 1: Validate
            result.steps[0].status = "running"
            result.steps[0].started_at = datetime.now(timezone.utc)
            
            validation = self.validator.validate(config_content)
            result.validation_result = validation
            
            if not validation.is_valid:
                result.steps[0].status = "failed"
                result.steps[0].error = (
                    "; ".join(i.code for i in
                              getattr(validation, "issues", None) or [])
                    or "configuration validation failed")
                result.steps[0].completed_at = datetime.now(timezone.utc)
                result.status = "failed"
                result.completed_at = datetime.now(timezone.utc)
                return result
            
            result.steps[0].status = "completed"
            result.steps[0].completed_at = datetime.now(timezone.utc)
            
            # Step 2: Detect vendor
            result.steps[1].status = "running"
            result.steps[1].started_at = datetime.now(timezone.utc)
            
            detection = self.detector.detect(config_content)
            result.detection_result = detection
            result.vendor = detection.vendor
            result.platform = detection.platform
            result.firmware_version = detection.firmware_version or ""
            result.detection_confidence = detection.confidence
            result.device_type = getattr(detection, "device_type", "unknown") or "unknown"
            result.hostname = getattr(detection, "hostname", "") or ""
            # Single canonical OS family for every downstream consumer
            # (report, controls, persistence): ios → ios_xe, etc.
            try:
                from app.benchmarks.selection import normalize_platform
                result.os_family = normalize_platform(
                    detection.vendor, detection.platform)
            except Exception:
                result.os_family = detection.platform
            
            result.steps[1].status = "completed"
            result.steps[1].completed_at = datetime.now(timezone.utc)
            
            # Step 3: Parse — only supported compliance vendors get a parser
            result.steps[2].status = "running"
            result.steps[2].started_at = datetime.now(timezone.utc)

            parser = None
            if detection.vendor in SUPPORTED_COMPLIANCE_VENDORS:
                parser = self._get_parser(detection.vendor, detection.platform)
            if parser is None:
                # E03 F2/F10: detection-only or unsupported vendor — stop the
                # audit after detection instead of running another vendor's
                # parser/controls over this content.
                result.steps[2].status = "failed"
                result.steps[2].error = (
                    f"vendor '{detection.vendor}' is detection-only: no compliance "
                    f"parser (supported: {', '.join(sorted(SUPPORTED_COMPLIANCE_VENDORS))})"
                )
                result.status = "failed"
                result.completed_at = datetime.now(timezone.utc)
                return result
            # E04 F12: vendor/platform/identity ride on the ParseResult so
            # downstream consumers never re-derive them.
            parse_result = parser.parse(
                config_content,
                vendor=detection.vendor,
                platform=detection.platform,
            )
            parse_result.id = audit_id
            result.parse_result = parse_result
            
            result.steps[2].status = "completed"
            result.steps[2].completed_at = datetime.now(timezone.utc)
            
            # Step 4: Normalize + Evaluate (unified path)
            result.steps[3].status = "running"
            result.steps[3].started_at = datetime.now(timezone.utc)

            # Canonical evaluation platform (single source: result.os_family).
            # VendorDetector returns "ios" for Cisco; the benchmark
            # inventory is keyed "ios_xe" — resolved once, consumed alike
            # by normalization, evaluation, persistence and reporting.
            bench_platform = result.os_family or detection.platform
            # E05 F4 (§10.5): semantic interpretation payload built from the
            # parse tree. E05 F5: ONE authoritative normalization per audit,
            # on the canonical platform, consumed downstream (not redone).
            semantic_interpretation = self._build_semantic_interpretation(
                result.parse_result)
            result.semantic_interpretation = semantic_interpretation
            config_dict = {"raw_lines": config_content.splitlines()}
            normalization = self.normalizer.normalize(
                config_dict,
                detection.vendor,
                bench_platform,
                semantic_interpretation,
            )
            result.normalization_result = normalization

            # E05 F6: failed normalization is a safety boundary — stop the
            # audit instead of scoring unevaluated state.
            if normalization.result_type == NormalizationResultType.FAILED:
                result.steps[3].status = "failed"
                result.steps[3].error = (
                    "normalization failed: compliance evaluation stopped "
                    "(no trustworthy normalized state)"
                )
                result.status = "failed"
                result.completed_at = datetime.now(timezone.utc)
                return result

            benchmark_result = self.benchmark_engine.execute(
                raw_config=config_content,
                vendor=detection.vendor,
                platform=bench_platform,
                vendor_identification=detection,
                normalization_result=normalization,
                framework=framework_c,
                framework_version=version_c,
            )
            result.benchmark_result = benchmark_result

            # A safety boundary inside the engine (unsupported vendor,
            # mismatch, empty input) stops the audit here: no compliance
            # evaluation is fabricated from zero evidence.
            if benchmark_result.status != "completed":
                result.steps[3].status = "failed"
                result.steps[3].error = benchmark_result.status_reason
                result.steps[3].completed_at = datetime.now(timezone.utc)
                result.status = "failed"
                result.completed_at = datetime.now(timezone.utc)
                return result

            result.steps[3].status = "completed"
            result.steps[3].completed_at = datetime.now(timezone.utc)
            
            # Step 5: Map benchmark results to compliance evaluation format
            result.steps[4].status = "running"
            result.steps[4].started_at = datetime.now(timezone.utc)
            
            evaluation = self._benchmark_to_compliance_evaluation(
                benchmark_result, normalization
            )
            # Device identity provenance (Issue #1): the single
            # authoritative detection result stamps the evaluation, so
            # findings inherit hostname/device lineage generically.
            evaluation.device_type = result.device_type or ""
            evaluation.hostname = result.hostname or ""
            evaluation.os_family = result.os_family or ""
            result.compliance_evaluation = evaluation
            result.total_controls = benchmark_result.evaluated
            result.passed = benchmark_result.passed
            result.failed = benchmark_result.failed
            result.review = benchmark_result.review
            result.overall_score = benchmark_result.score
            
            result.steps[4].status = "completed"
            result.steps[4].completed_at = datetime.now(timezone.utc)
            
            # Step 6: Generate findings
            result.steps[5].status = "running"
            result.steps[5].started_at = datetime.now(timezone.utc)
            
            findings = self.finding_generator.generate_findings(
                evaluation=evaluation,
                audit_id=audit_id,
                device_name=device_name,
            )
            result.findings = findings
            
            result.steps[5].status = "completed"
            result.steps[5].completed_at = datetime.now(timezone.utc)
            
            # Complete audit
            result.status = "completed"
            result.completed_at = datetime.now(timezone.utc)
            
        except Exception as e:
            result.status = "failed"
            result.completed_at = datetime.now(timezone.utc)
            # Mark current step as failed
            for step in result.steps:
                if step.status == "running":
                    step.status = "failed"
                    step.error = str(e)
                    break
        
        return result
    
    def _benchmark_to_compliance_evaluation(
        self,
        benchmark_result: BenchmarkExecutionResult,
        normalization: Any,
    ) -> ComplianceEvaluation:
        """Convert BenchmarkExecutionResult to ComplianceEvaluation.

        The evidence chain is mapped 1:1 onto the canonical §12 contract
        (F4): raw_config, parsed_value, normalized_value, security_control,
        expected_value, actual_value, result, reasoning — plus the recorded
        metadata. Framework attribution comes from the control's own
        metadata (F3), never from id shape or the audit request. The score
        is the single canonical overall_score (F5).
        """
        from app.engines.compliance.models import Severity
        from app.engines.compliance.evidence import EvidenceChain

        # Device provenance (Issue #1): the single authoritative detection
        # result stamps every evidence chain, so findings inherit
        # hostname/device lineage and finding evidence stays identical to
        # evaluation evidence (V07-115).
        _vid = getattr(benchmark_result, "vendor_identification", None)
        _ev_hostname = (getattr(_vid, "hostname", None) or "") if _vid else ""
        _ev_device_type = (getattr(_vid, "device_type", None) or "") if _vid else ""

        evaluation = ComplianceEvaluation(
            vendor=benchmark_result.vendor,
            platform=benchmark_result.platform,
        )
        # E05 F5: the executor's authoritative normalization result is
        # consumed here (provenance linkage, not a second normalization).
        if normalization is not None:
            evaluation.normalization_id = getattr(normalization, "id", None)
            evaluation.universal_model_version = getattr(
                normalization, "universal_model_version", None)

        for ev in benchmark_result.evaluations:
            # Map severity string to Severity enum
            sev_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            severity = sev_map.get(
                str(ev.evidence.severity).upper(), Severity.MEDIUM)

            # Canonical §12 evidence object — the same object that is
            # persisted and reported (F4). All eight required keys are set;
            # parsed_value is the vendor statement that produced the
            # normalized value (None only when no statement was observed).
            evidence = EvidenceChain(
                raw_config=ev.evidence.raw_config,
                raw_config_line_numbers=list(
                    ev.evidence.raw_config_line_numbers),
                parsed_value=ev.evidence.parsed_value,
                parsed_path="",
                normalized_value=ev.evidence.normalized_value,
                universal_model_path=ev.evidence.universal_model_path,
                normalization_confidence=(ev.evidence.normalization_confidence
                                          if ev.evidence.normalization_confidence
                                          is not None else 0.0),
                control_id=ev.evidence.control_id,
                security_control=ev.evidence.control_id,
                control_description=ev.evidence.title,
                expected_value=ev.evidence.expected_value,
                actual_value=ev.evidence.actual_value,
                operator=ev.evidence.operator,
                result=str(ev.evidence.result).upper(),
                reasoning=ev.evidence.reasoning,
                overall_confidence=ev.evidence.confidence,
                vendor=ev.evidence.vendor,
                platform=ev.evidence.platform,
                vendor_specific_syntax="",
                review_code=getattr(ev.evidence, "review_code", "") or "",
                evaluation_method=getattr(ev.evidence, "evaluation_method", "") or "",
                benchmark_id=getattr(ev.evidence, "benchmark_id", "") or "",
                benchmark_name=getattr(ev.evidence, "benchmark_name", "") or "",
                framework_version=getattr(ev.evidence, "framework_version", "") or "",
                framework=getattr(ev.evidence, "framework", "") or "",
                scope=getattr(ev.evidence, "scope", "") or "",
                observed_state=getattr(ev.evidence, "observed_state", "") or "",
                expected_state=getattr(ev.evidence, "expected_state", "") or "",
                evidence_block_count=getattr(ev.evidence, "evidence_block_count", 0) or 0,
                affected_scope_count=getattr(ev.evidence, "affected_scope_count", 0) or 0,
                hostname=_ev_hostname,
                device_type=_ev_device_type,
            )

            result_type = ComplianceResultType(evidence.result)

            from app.engines.compliance.engine import ControlEvaluation
            from app.engines.compliance.remediation import RemediationEngine
            # E10: remediation content is built by the canonical
            # RemediationEngine (single implementation) from control-authored
            # content carried on the evidence, the observed statement, and
            # the evaluated reasoning. finding_id/finding_title are stamped
            # by FindingGenerator where the finding identity exists.
            remediation = None
            if result_type != ComplianceResultType.PASS:
                observed = ev.evidence.parsed_value
                if not isinstance(observed, str) or not observed:
                    first_line = (ev.evidence.raw_config or "").splitlines()
                    observed = first_line[0] if first_line else ""
                remediation = RemediationEngine().build(
                    finding_title=ev.evidence.title,
                    risk_description=ev.evidence.reasoning,
                    why_it_matters=ev.evidence.title,
                    vendor=ev.evidence.vendor,
                    platform=ev.evidence.platform,
                    recommended_config=ev.evidence.remediation_command or "",
                    observed_statement=observed,
                    audit_command=ev.evidence.audit_command or "",
                    verification_steps=(list(ev.evidence.verification_steps)
                                        or None),
                    rollback_steps=(list(ev.evidence.rollback_steps)
                                    or None),
                    references=([f"{ev.evidence.source_document} "
                                 f"[{ev.evidence.source_location}]"]
                                if ev.evidence.source_document else []),
                )
                remediation["confidence"] = ev.evidence.confidence
            ctrl_eval = ControlEvaluation(
                control_id=ev.evidence.control_id,
                control_title=ev.evidence.title,
                control_description=ev.evidence.title,
                severity=severity,
                category=ev.evidence.category,
                result=result_type,
                confidence=ev.evidence.confidence,
                evidence=evidence,
                remediation=remediation,
            )
            # Framework attribution rides on the evaluation for persistence
            # (F3): the control's own metadata, attached here so the writer
            # below cannot substitute the request or an id heuristic.
            ctrl_eval.framework = ev.evidence.framework
            ctrl_eval.framework_version = ev.evidence.framework_version
            evaluation.evaluations.append(ctrl_eval)

            if result_type == ComplianceResultType.PASS:
                evaluation.passed += 1
            elif result_type == ComplianceResultType.FAIL:
                evaluation.failed += 1
            elif result_type == ComplianceResultType.REVIEW:
                evaluation.review += 1

        evaluation.total_controls = len(evaluation.evaluations)
        evaluation.overall_score = overall_score(
            evaluation.passed, evaluation.total_controls)

        return evaluation
