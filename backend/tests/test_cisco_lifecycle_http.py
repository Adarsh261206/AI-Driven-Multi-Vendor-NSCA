"""Lifecycle + HTTP applicability tests (Issues #2, #3).

Lifecycle: ACTIVE/SHUTDOWN/UNKNOWN with last-wins precedence.
HTTP matrix A-G: deterministic evidence-backed outcomes.
"""

from __future__ import annotations

import pytest

from app.benchmarks.execution import BenchmarkExecutionEngine
from app.engines.normalization import NormalizationEngine


@pytest.fixture
def engine() -> BenchmarkExecutionEngine:
    return BenchmarkExecutionEngine()


def _eval(engine: BenchmarkExecutionEngine, config: str, control_id: str):
    result = engine.execute(config, vendor="cisco", platform="ios_xe")
    for ev in result.evaluations:
        if ev.control_id == control_id:
            return ev
    raise AssertionError(f"Control {control_id} not found in evaluations")


def _lifecycle(cfg: str, name: str) -> str:
    n = NormalizationEngine()
    nr = n.normalize({"raw_lines": cfg.splitlines()}, "cisco", "ios_xe")
    blocks = nr.universal_config.get("networking", {}).get("interface_blocks")
    for b in blocks or []:
        if b["name"] == name:
            return b.get("lifecycle", "UNKNOWN")
    raise AssertionError(f"Interface {name} not found")


BASE = "hostname LC-01\n!\n"


class TestLifecycle:
    """Issue #2 matrix: lifecycle states + precedence."""

    def test_no_shutdown_is_active(self):
        cfg = BASE + "interface Gi1/0/1\n no shutdown\n"
        assert _lifecycle(cfg, "Gi1/0/1") == "ACTIVE"

    def test_shutdown_is_shutdown(self):
        cfg = BASE + "interface Gi1/0/1\n shutdown\n"
        assert _lifecycle(cfg, "Gi1/0/1") == "SHUTDOWN"

    def test_shutdown_then_no_shutdown_is_active(self):
        cfg = BASE + "interface Gi1/0/1\n shutdown\n no shutdown\n"
        assert _lifecycle(cfg, "Gi1/0/1") == "ACTIVE"

    def test_no_shutdown_then_shutdown_is_shutdown(self):
        cfg = BASE + "interface Gi1/0/1\n no shutdown\n shutdown\n"
        assert _lifecycle(cfg, "Gi1/0/1") == "SHUTDOWN"

    def test_missing_lifecycle_is_unknown(self):
        cfg = BASE + "interface Gi1/0/1\n switchport mode access\n"
        assert _lifecycle(cfg, "Gi1/0/1") == "UNKNOWN"

    def test_malformed_lifecycle_ignored(self):
        # `shutdown now` is not the shutdown command; lifecycle stays UNKNOWN.
        cfg = BASE + "interface Gi1/0/1\n shutdown now\n"
        assert _lifecycle(cfg, "Gi1/0/1") == "UNKNOWN"

    def test_shutdown_interface_excluded_with_reason(self, engine):
        cfg = (BASE + "interface Gi1/0/1\n shutdown\n"
               "!\ninterface Gi1/0/2\n no ip redirects\n")
        ev = _eval(engine, cfg, "2.1.13")
        assert ev.result == "PASS", ev.evidence.reasoning
        assert "not applicable" in ev.evidence.reasoning.lower()


class TestHTTPMatrix:
    """Issue #3 matrix A-G: 1.1.5 deterministic outcomes."""

    def test_a_http_aaa_is_pass(self, engine):
        cfg = (BASE + "ip http server\n ip http authentication aaa\n")
        ev = _eval(engine, cfg, "1.1.5")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_b_http_no_auth_is_review(self, engine):
        cfg = BASE + "ip http server\n"
        ev = _eval(engine, cfg, "1.1.5")
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_c_http_disabled_is_review(self, engine):
        cfg = BASE + "no ip http server\nno ip http secure-server\n"
        ev = _eval(engine, cfg, "1.1.5")
        # Benchmark conditionality for a disabled service cannot be
        # established from the registry: REVIEW, never FAIL, never PASS.
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_d_https_only_no_auth_is_review(self, engine):
        cfg = BASE + "ip http secure-server\n"
        ev = _eval(engine, cfg, "1.1.5")
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_e_both_no_auth_is_review(self, engine):
        cfg = BASE + "ip http server\nip http secure-server\n"
        ev = _eval(engine, cfg, "1.1.5")
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_f_unknown_http_state_is_review(self, engine):
        ev = _eval(engine, BASE + "hostname X\n", "1.1.5")
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_g_malformed_http_is_review(self, engine):
        cfg = BASE + "ip http authentication\n"
        ev = _eval(engine, cfg, "1.1.5")
        assert ev.result == "REVIEW", ev.evidence.reasoning
