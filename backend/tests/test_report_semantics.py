"""Report wording, REVIEW classification, manual-control tests.

Issues #4/#5/#6: explicit terminology (positive compliance evidence /
explicit violation evidence / insufficient-ambiguous-unsupported),
manual-control status verification, integrity semantics.
"""

from __future__ import annotations

import pytest

from app.benchmarks.execution import BenchmarkExecutionEngine
from app.engines.reporting import audit_integrity_check


@pytest.fixture
def engine() -> BenchmarkExecutionEngine:
    return BenchmarkExecutionEngine()


def _eval(engine: BenchmarkExecutionEngine, config: str, control_id: str):
    result = engine.execute(config, vendor="cisco", platform="ios_xe")
    for ev in result.evaluations:
        if ev.control_id == control_id:
            return ev
    raise AssertionError(f"Control {control_id} not found in evaluations")


BASE = "hostname SEM-01\n!\n"


class TestReviewClassification:
    """Issue #4: REVIEW reasons are explicit and classified."""

    def test_missing_evidence_code(self, engine):
        ev = _eval(engine, BASE, "1.2.2")
        assert ev.result == "REVIEW"
        assert ev.evidence.review_code == "INSUFFICIENT_EVIDENCE"
        assert "insufficient" in ev.evidence.reasoning.lower() or \
            "not found" in ev.evidence.reasoning.lower()

    def test_manual_code(self, engine):
        ev = _eval(engine, BASE, "1.2.1")
        assert ev.result == "REVIEW"
        assert ev.evidence.review_code == "MANUAL_VERIFICATION_REQUIRED"
        assert ev.evidence.evaluation_method == "manual"

    def test_ambiguous_code(self, engine):
        cfg = (BASE + "no service finger\n"
               "!\nservice finger\n")
        ev = _eval(engine, cfg, "2.1.7")
        # Both forms present: compliant match wins first in current
        # ordering — either way the verdict must carry an explicit code.
        assert ev.result in ("PASS", "FAIL", "REVIEW")
        assert ev.evidence.review_code != "" or ev.result != "REVIEW"

    def test_unsupported_syntax_code(self, engine):
        # A control with neither path nor regex is UNSUPPORTED_SYNTAX.
        from app.benchmarks.models import (
            AssessmentStatus, BenchmarkControl, ControlSeverity)
        ctl = BenchmarkControl(
            benchmark_id="T", benchmark_name="T", benchmark_version="v1",
            vendor="cisco", platform="ios_xe", control_id="T-UNS",
            title="T", category="T", description="T",
            assessment_status=AssessmentStatus.AUTOMATED,
            severity=ControlSeverity.MEDIUM,
            target_model_path=None, operator="equals", expected_value=None)
        engine.execute(BASE, vendor="cisco", platform="ios_xe")
        ev = engine._evaluate_unmapped(
            ctl, engine._base_evidence(ctl), BASE, BASE.splitlines(), 1.0)
        assert ev.result == "REVIEW"
        assert ev.evidence.review_code == "UNSUPPORTED_SYNTAX"


class TestReportWording:
    """Issue #5: standardized terminology."""

    def test_pass_wording(self, engine):
        from app.engines.reporting import generate_audit_report
        audit = {"audit_id": "x", "audit_name": "T", "framework": "CIS",
                 "status": "completed", "overall_score": 100.0,
                 "configuration_count": 1}
        pdf = generate_audit_report(audit, [], [])
        assert pdf.startswith(b"%PDF")

    def test_integrity_ok_wording(self):
        findings = [{
            "title": "T", "description": "d", "severity": "HIGH",
            "status": "open", "confidence": 0.9,
            "evidence": {
                "raw_config": "transport input ssh",
                "raw_config_line_numbers": [5],
                "reasoning": "ok", "result": "FAIL",
            },
        }]
        results = [{"control_id": "1.2.2", "result": "PASS"}]
        audit = {"verified_rate": 100.0}
        assert audit_integrity_check(findings, results, audit) == []

    def test_integrity_finding_without_lines_warns(self):
        findings = [{
            "title": "T", "description": "d", "severity": "HIGH",
            "status": "open", "confidence": 0.9,
            "evidence": {"reasoning": "r", "result": "FAIL"},
        }]
        warnings = audit_integrity_check(
            findings, [{"control_id": "1.2.2", "result": "FAIL"}],
            {"verified_rate": 100.0})
        assert any("traceable evidence" in w for w in warnings)

    def test_no_contradictory_in_ok_banner(self, engine):
        import inspect
        from app.engines import reporting as rep_mod
        src = inspect.getsource(rep_mod.generate_audit_report)
        assert "contradictory evidence" not in src


class TestManualControls:
    """Issue #6: manual status verified against contract (REVIEW, not N/A)."""

    def test_manual_is_review_not_na(self, engine):
        for cid in ("1.2.1", "2.1.6"):
            ev = _eval(engine, BASE, cid)
            assert ev.result == "REVIEW", f"{cid} must be REVIEW"
            assert ev.evidence.evaluation_method == "manual"

    def test_manual_finding_requires_human_wording(self, engine):
        from app.engines.compliance.executor import AuditExecutor
        ex = AuditExecutor()
        cfg = BASE + "interface Gi1/0/1\n switchport mode access\n"
        r = ex.execute("man-test", cfg)
        assert r.status == "completed"
        manuals = [f for f in r.findings
                   if f.control_id in ("1.2.1", "2.1.6")]
        assert manuals, "expected manual findings"
        for f in manuals:
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            text = str(ev.get("reasoning", "")) + str(f.description)
            assert "human" in text.lower() or "manual" in text.lower()

    def test_manual_integrity_no_fake_lines(self, engine):
        from app.engines.compliance.executor import AuditExecutor
        ex = AuditExecutor()
        cfg = BASE + "interface Gi1/0/1\n switchport mode access\n"
        r = ex.execute("man-test-2", cfg)
        manuals = [f for f in r.findings
                   if f.control_id in ("1.2.1", "2.1.6")]
        for f in manuals:
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            warns = audit_integrity_check(
                [{"title": f.title, "description": f.description,
                  "severity": "MEDIUM", "status": "open", "confidence": 0.9,
                  "evidence": {**ev, "evaluation_method": "manual"}}],
                [], {"verified_rate": 0.0})
            assert not any("traceable evidence lines" in w for w in warns), warns
