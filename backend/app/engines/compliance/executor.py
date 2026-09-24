"""
Audit Executor

Orchestrates the full compliance audit pipeline:
INGEST → VALIDATE → DETECT → PARSE → NORMALIZE → EVALUATE → FINDINGS

Uses the unified BenchmarkExecutionEngine as the canonical evaluation path.
The legacy ControlLoader/RuleEngine pipeline is kept for backward compatibility
but is NOT used in the main audit path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime, timezone

from app.engines.compliance.models import Control, ComplianceResultType
from app.engines.compliance.loader import ControlLoader
from app.engines.compliance.engine import RuleEngine, ComplianceEvaluation
from app.engines.compliance.findings import Finding, FindingGenerator
from app.engines.validation import ConfigurationValidator
from app.engines.detection import VendorDetector
from app.engines.parsing.cisco import CiscoIOSParser
from app.engines.parsing.juniper import JunosParser
from app.engines.normalization import NormalizationEngine
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
    
    # Pipeline results
    validation_result: Optional[Any] = None
    detection_result: Optional[Any] = None
    parse_result: Optional[Any] = None
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
        vendor_lower = vendor.lower()
        if vendor_lower == "cisco":
            return CiscoIOSParser()
        elif vendor_lower == "juniper":
            return JunosParser()
        elif vendor_lower == "fortinet":
            from app.engines.parsing.fortinet import FortiOSParser
            return FortiOSParser()
        else:
            # Fallback to Cisco parser for unknown vendors
            return CiscoIOSParser()
    
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
            framework: Compliance framework (CIS, NIST)
            framework_version: Framework version
            device_name: Name of the device
            
        Returns:
            AuditResult with all findings
        """
        result = AuditResult(audit_id=audit_id)
        result.started_at = datetime.now(timezone.utc)
        result.status = "processing"
        
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
                result.steps[0].status = "completed"
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
            
            result.steps[1].status = "completed"
            result.steps[1].completed_at = datetime.now(timezone.utc)
            
            # Step 3: Parse
            result.steps[2].status = "running"
            result.steps[2].started_at = datetime.now(timezone.utc)
            
            parser = self._get_parser(detection.vendor, detection.platform)
            parse_result = parser.parse(config_content)
            result.parse_result = parse_result
            
            result.steps[2].status = "completed"
            result.steps[2].completed_at = datetime.now(timezone.utc)
            
            # Step 4: Normalize + Evaluate (unified path)
            result.steps[3].status = "running"
            result.steps[3].started_at = datetime.now(timezone.utc)
            
            # Use benchmark engine for CIS Cisco IOS XE
            # VendorDetector returns "ios" for Cisco, but benchmark needs "ios_xe"
            bench_platform = detection.platform
            if detection.vendor.lower() == "cisco" and bench_platform.lower() in ("ios", "ios_xe"):
                bench_platform = "ios_xe"
            benchmark_result = self.benchmark_engine.execute(
                raw_config=config_content,
                vendor=detection.vendor,
                platform=bench_platform,
            )
            result.benchmark_result = benchmark_result
            
            config_dict = {"raw_lines": config_content.splitlines()}
            normalization = self.normalizer.normalize(
                config_dict,
                detection.vendor,
                detection.platform,
            )
            result.normalization_result = normalization
            
            result.steps[3].status = "completed"
            result.steps[3].completed_at = datetime.now(timezone.utc)
            
            # Step 5: Map benchmark results to compliance evaluation format
            result.steps[4].status = "running"
            result.steps[4].started_at = datetime.now(timezone.utc)
            
            evaluation = self._benchmark_to_compliance_evaluation(
                benchmark_result, normalization
            )
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
        """Convert BenchmarkExecutionResult to ComplianceEvaluation for backward compat."""
        from app.engines.compliance.models import Severity
        from app.engines.compliance.evidence import EvidenceChain
        
        evaluation = ComplianceEvaluation(
            vendor=benchmark_result.vendor,
            platform=benchmark_result.platform,
        )
        
        for ev in benchmark_result.evaluations:
            # Map severity string to Severity enum
            sev_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            severity = sev_map.get(ev.evidence.severity, Severity.MEDIUM)
            
            # Build a minimal EvidenceChain
            evidence = EvidenceChain(
                raw_config=ev.evidence.raw_evidence_snippet,
                normalized_value=ev.evidence.normalized_value,
                universal_model_path=ev.evidence.target_model_path,
                control_id=ev.evidence.control_id,
                control_description=ev.evidence.title,
                expected_value=ev.evidence.expected_value,
                actual_value=ev.evidence.actual_value,
                operator=ev.evidence.operator,
                result=ev.evidence.result.lower(),
                result_reasoning=ev.evidence.result_reasoning,
                overall_confidence=ev.evidence.confidence,
                vendor=ev.evidence.vendor,
                platform=ev.evidence.platform,
            )
            
            result_type = ComplianceResultType(ev.evidence.result.lower())
            
            from app.engines.compliance.engine import ControlEvaluation
            # Build remediation from benchmark control metadata (FAIL/REVIEW only)
            remediation = None
            if result_type != ComplianceResultType.PASS:
                references = []
                if ev.evidence.source_document:
                    ref = ev.evidence.source_document
                    if ev.evidence.source_location:
                        ref = f"{ref} [{ev.evidence.source_location}]"
                    references.append(ref)
                remediation = {
                    "title": ev.evidence.title,
                    "description": ev.evidence.result_reasoning,
                    "why_it_matters": ev.evidence.title,
                    "recommended_config": ev.evidence.remediation_command or "",
                    "verification_steps": [],
                    "rollback_steps": [],
                    "references": references,
                    "confidence": ev.evidence.confidence,
                    "vendor": ev.evidence.vendor,
                    "platform": ev.evidence.platform,
                }
            ctrl_eval = ControlEvaluation(
                control_id=ev.evidence.control_id,
                control_title=ev.evidence.title,
                control_description="",
                severity=severity,
                category=ev.evidence.category,
                result=result_type,
                confidence=ev.evidence.confidence,
                evidence=evidence,
                remediation=remediation,
            )
            evaluation.evaluations.append(ctrl_eval)
            
            if result_type == ComplianceResultType.PASS:
                evaluation.passed += 1
            elif result_type == ComplianceResultType.FAIL:
                evaluation.failed += 1
            elif result_type == ComplianceResultType.REVIEW:
                evaluation.review += 1
        
        evaluation.total_controls = len(evaluation.evaluations)
        total_decisive = evaluation.passed + evaluation.failed
        evaluation.overall_score = (evaluation.passed / total_decisive * 100) if total_decisive > 0 else 0.0
        
        return evaluation
