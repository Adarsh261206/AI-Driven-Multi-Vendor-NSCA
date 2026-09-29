"""Golden Cisco baselines (§25 secure, §26 insecure).

Expected results are stored in tests/fixtures/cisco/expected_*.json and
compared against full engine runs. Any verdict change fails loudly with
OLD/NEW/why semantics carried by the evidence itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.benchmarks.execution import BenchmarkExecutionEngine

FIXTURES = Path(__file__).parent / "fixtures" / "cisco"


@pytest.fixture
def engine() -> BenchmarkExecutionEngine:
    return BenchmarkExecutionEngine()


def _run(engine: BenchmarkExecutionEngine, name: str):
    cfg = (FIXTURES / f"{name}.cfg").read_text()
    return engine.execute(cfg, vendor="cisco", platform="ios_xe")


def _results_map(result) -> dict[str, str]:
    return {ev.control_id: ev.result for ev in result.evaluations}


class TestGoldenSecure:
    def test_expected_file_exists(self):
        assert (FIXTURES / "expected_secure.json").exists()

    def test_no_fail(self, engine):
        result = _run(engine, "secure_switch_iosxe")
        fails = [ev.control_id for ev in result.evaluations
                 if ev.result == "FAIL"]
        assert fails == [], f"secure baseline must have zero FAIL: {fails}"

    def test_verified_rate_is_100(self, engine):
        result = _run(engine, "secure_switch_iosxe")
        assert result.verified_rate == 100.0

    def test_matches_expected(self, engine):
        expected = json.loads(
            (FIXTURES / "expected_secure.json").read_text())
        actual = _results_map(_run(engine, "secure_switch_iosxe"))
        mismatched = {cid: (expected.get(cid), actual.get(cid))
                      for cid in set(expected) | set(actual)
                      if expected.get(cid) != actual.get(cid)}
        assert mismatched == {}, f"golden drift: {mismatched}"

    def test_key_controls_pass(self, engine):
        actual = _results_map(_run(engine, "secure_switch_iosxe"))
        for cid in ["1.2.2", "2.1.7", "2.1.8", "2.1.10", "2.1.13", "2.1.14",
                    "2.1.15", "2.1.16", "2.2.1", "2.2.5", "2.2.6", "2.2.7"]:
            assert actual[cid] == "PASS", f"{cid} must PASS on secure baseline"

    def test_every_fail_has_evidence(self, engine):
        result = _run(engine, "secure_switch_iosxe")
        for ev in result.evaluations:
            if ev.result == "FAIL":
                assert ev.evidence.raw_evidence_snippet.strip(), ev.control_id
                assert ev.evidence.reasoning.strip(), ev.control_id


class TestGoldenRouter:
    """Golden Cisco IOS-XE ROUTER baseline: hardened edge router."""

    def test_expected_file_exists(self):
        assert (FIXTURES / "expected_router.json").exists()

    def test_no_fail(self, engine):
        result = _run(engine, "router_iosxe")
        fails = [ev.control_id for ev in result.evaluations
                 if ev.result == "FAIL"]
        assert fails == [], f"router baseline must have zero FAIL: {fails}"

    def test_verified_rate_is_100(self, engine):
        result = _run(engine, "router_iosxe")
        assert result.verified_rate == 100.0

    def test_matches_expected(self, engine):
        expected = json.loads(
            (FIXTURES / "expected_router.json").read_text())
        actual = _results_map(_run(engine, "router_iosxe"))
        mismatched = {cid: (expected.get(cid), actual.get(cid))
                      for cid in set(expected) | set(actual)
                      if expected.get(cid) != actual.get(cid)}
        assert mismatched == {}, f"golden drift: {mismatched}"

    def test_key_controls_pass(self, engine):
        actual = _results_map(_run(engine, "router_iosxe"))
        for cid in ["1.2.2", "1.2.8", "2.1.7", "2.1.10", "2.1.13", "2.1.14",
                    "2.1.15", "2.1.16"]:
            assert actual[cid] == "PASS", f"{cid} must PASS on router baseline"

    def test_detected_as_router(self):
        from app.engines.detection import VendorDetector
        cfg = (FIXTURES / "router_iosxe.cfg").read_text()
        d = VendorDetector().detect(cfg)
        assert d.vendor == "cisco"
        assert d.device_type == "router", f"router fixture detected as {d.device_type}"
        assert d.hostname == "RTR-EDGE-01"


class TestGoldenInsecure:
    def test_expected_file_exists(self):
        assert (FIXTURES / "expected_insecure.json").exists()

    def test_required_fails_present(self, engine):
        actual = _results_map(_run(engine, "insecure_switch_iosxe"))
        for cid in ["1.2.2", "2.1.7", "2.1.8", "2.1.10"]:
            assert actual[cid] == "FAIL", f"{cid} must FAIL on insecure baseline"

    def test_matches_expected(self, engine):
        expected = json.loads(
            (FIXTURES / "expected_insecure.json").read_text())
        actual = _results_map(_run(engine, "insecure_switch_iosxe"))
        mismatched = {cid: (expected.get(cid), actual.get(cid))
                      for cid in set(expected) | set(actual)
                      if expected.get(cid) != actual.get(cid)}
        assert mismatched == {}, f"golden drift: {mismatched}"

    def test_every_fail_has_contradictory_evidence(self, engine):
        result = _run(engine, "insecure_switch_iosxe")
        for ev in result.evaluations:
            if ev.result == "FAIL":
                assert ev.evidence.raw_evidence_snippet.strip(), ev.control_id
                assert ev.evidence.reasoning.strip(), ev.control_id
                assert ev.evidence.evaluation_method, ev.control_id
