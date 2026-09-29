"""Metric semantics unit tests (Issue #7).

Verified Compliance Rate = PASS / (PASS + FAIL).
Evidence Coverage = decisive / evaluated.
REVIEW is never FAIL and never PASS. Overall score keeps REVIEW as
non-pass. Denominators documented and tested for all combinations,
including empty and all-REVIEW audits.
"""

from __future__ import annotations

import pytest

from pathlib import Path

from app.benchmarks.execution import BenchmarkExecutionEngine
from app.benchmarks.selection import overall_score

FIXTURES = Path(__file__).parent / "fixtures" / "cisco"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.fixture
def engine() -> BenchmarkExecutionEngine:
    return BenchmarkExecutionEngine()


def _run(engine, cfg: str):
    return engine.execute(cfg, vendor="cisco", platform="ios_xe")


class TestVerifiedRate:
    def test_verified_excludes_review(self, engine):
        # Golden secure: 0 FAIL, some REVIEW -> verified must be 100.0
        # even though overall score < 100.
        cfg = _fixture("secure_switch_iosxe.cfg")
        r = _run(engine, cfg)
        assert r.failed == 0
        assert r.review > 0
        assert r.verified_rate == 100.0
        assert r.score < 100.0

    def test_verified_counts_only_decisive(self, engine):
        cfg = _fixture("insecure_switch_iosxe.cfg")
        r = _run(engine, cfg)
        decisive = r.passed + r.failed
        assert r.verified_rate == round(r.passed / decisive * 100, 1)

    def test_all_review_verified_zero(self, engine):
        r = _run(engine, "hostname T\n!\n")
        assert r.passed == 0 and r.failed == 0
        assert r.verified_rate == 0.0

    def test_empty_input_scores_zero(self, engine):
        r = _run(engine, "")
        assert r.score == 0.0
        assert r.verified_rate == 0.0
        assert r.evidence_coverage == 0.0


class TestEvidenceCoverage:
    def test_coverage_is_decisive_over_evaluated(self, engine):
        cfg = _fixture("secure_switch_iosxe.cfg")
        r = _run(engine, cfg)
        assert r.evidence_coverage == round(
            (r.passed + r.failed) / r.evaluated * 100, 1)

    def test_review_does_not_inflate_coverage(self, engine):
        cfg = _fixture("secure_switch_iosxe.cfg")
        r = _run(engine, cfg)
        assert r.evidence_coverage < 100.0  # REVIEWs exist
        assert r.verified_rate == 100.0  # but verified is still 100


class TestOverallScore:
    def test_review_is_non_pass(self):
        assert overall_score(5, 10) == 50.0

    def test_zero_evaluated_is_zero(self):
        assert overall_score(0, 0) == 0.0

    def test_review_never_equals_fail(self, engine):
        # A REVIEW-heavy audit must not score like an all-FAIL audit.
        cfg = _fixture("secure_switch_iosxe.cfg")
        r = _run(engine, cfg)
        assert r.score > 0.0
        assert r.failed == 0


class TestReportMetricsReconcile:
    def test_report_verified_matches_rows(self, engine):
        from app.engines.reporting import audit_integrity_check
        cfg = _fixture("secure_switch_iosxe.cfg")
        r = _run(engine, cfg)
        rows = [{"control_id": e.control_id, "result": e.result}
                for e in r.evaluations]
        audit_data = {"verified_rate": r.verified_rate}
        warnings = audit_integrity_check([], rows, audit_data)
        assert warnings == [], warnings
