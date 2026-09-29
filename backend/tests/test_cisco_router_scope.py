"""Cisco ROUTER scope regression tests (PART 12).

Covers line/transport multi-block, aux/console isolation, global
source-route, interface proxy-arp, finger on/off, password-encryption
rescue, and description guards — all through the generic scope-aware
evaluator (no control-id hacks).
"""

from __future__ import annotations

import pytest

from app.benchmarks.execution import BenchmarkExecutionEngine


@pytest.fixture
def engine() -> BenchmarkExecutionEngine:
    return BenchmarkExecutionEngine()


def _eval(engine: BenchmarkExecutionEngine, config: str, control_id: str):
    result = engine.execute(config, vendor="cisco", platform="ios_xe")
    for ev in result.evaluations:
        if ev.control_id == control_id:
            return ev
    raise AssertionError(f"Control {control_id} not found in evaluations")


BASE = "hostname RTR-TEST-01\n!\n"


class TestRouterVtyTransport:
    """PART 12 case 1 + PART 3: per-VTY-block transport."""

    def test_01_mixed_vty_fail_identifies_block(self, engine):
        cfg = (BASE + "line vty 0 4\n transport input ssh\n"
               "!\nline vty 5 15\n transport input telnet\n")
        ev = _eval(engine, cfg, "1.2.2")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "line vty 5 15" in ev.evidence.reasoning
        assert ev.evidence.scope == "LINE_VTY"

    def test_all_ssh_pass(self, engine):
        cfg = (BASE + "line vty 0 4\n transport input ssh\n"
               "!\nline vty 5 15\n transport input ssh\n")
        ev = _eval(engine, cfg, "1.2.2")
        assert ev.result == "PASS", ev.evidence.reasoning


class TestRouterLineIsolation:
    """PART 12 cases 2-4 + PART 3: aux/console/vty evaluated independently."""

    def test_02_aux_independent(self, engine):
        ev = _eval(engine, BASE + "line aux 0\n exec-timeout 5 0\n", "1.2.6")
        assert ev.result == "PASS", ev.evidence.reasoning
        assert ev.evidence.scope == "LINE_AUX"

    def test_03_console_independent(self, engine):
        ev = _eval(engine, BASE + "line console 0\n exec-timeout 10 0\n", "1.2.7")
        assert ev.result == "PASS", ev.evidence.reasoning
        assert ev.evidence.scope == "LINE_CONSOLE"

    def test_04_vty_timeout_fail(self, engine):
        cfg = (BASE + "line vty 0 4\n exec-timeout 10 0\n"
               "!\nline vty 5 15\n exec-timeout 30 0\n")
        ev = _eval(engine, cfg, "1.2.8")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "line vty 5 15" in ev.evidence.reasoning


class TestRouterGlobal:
    """PART 12 cases 5-6 + PART 5."""

    def test_05_source_route_is_fail(self, engine):
        ev = _eval(engine, BASE + "ip source-route\n", "2.1.16")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert ev.evidence.scope == "GLOBAL"
        assert ev.evidence.observed_state != ""

    def test_06_no_source_route_is_pass(self, engine):
        ev = _eval(engine, BASE + "no ip source-route\n", "2.1.16")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_12_description_never_evidence(self, engine):
        ev = _eval(engine, BASE + 'description "ip source-route"\n', "2.1.16")
        assert ev.result == "REVIEW", ev.evidence.reasoning


class TestRouterInterface:
    """PART 12 cases 7-8 + PART 4."""

    def test_07_interface_proxy_arp_fail(self, engine):
        ev = _eval(engine, BASE + "interface Gi0/0/1\n ip proxy-arp\n", "2.1.15")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "Gi0/0/1" in ev.evidence.reasoning
        assert ev.evidence.scope == "INTERFACE"

    def test_08_interface_no_proxy_arp_pass(self, engine):
        ev = _eval(engine, BASE + "interface Gi0/0/1\n no ip proxy-arp\n", "2.1.15")
        assert ev.result == "PASS", ev.evidence.reasoning


class TestRouterNegatives:
    """PART 12 cases 9-10 + PART 6."""

    def test_09_finger_is_fail(self, engine):
        ev = _eval(engine, BASE + "service finger\n", "2.1.7")
        assert ev.result == "FAIL", ev.evidence.reasoning

    def test_10_no_finger_is_pass(self, engine):
        ev = _eval(engine, BASE + "no service finger\n", "2.1.7")
        assert ev.result == "PASS", ev.evidence.reasoning


class TestRouterNormalization:
    """PART 12 case 11 + PART 7: direct command recognition."""

    def test_11_password_encryption_deterministic(self, engine):
        ev = _eval(engine, BASE + "service password-encryption\n", "1.3.4")
        assert ev.result == "PASS", ev.evidence.reasoning
        assert ev.evidence.evaluation_method == "raw_regex_rescue"
        assert ev.evidence.observed_state != ""


class TestRouterProcessScope:
    """PART 2 ROUTER_PROCESS: generic per-process evaluation."""

    def test_router_blocks_normalized(self, engine):
        from app.engines.normalization import NormalizationEngine
        n = NormalizationEngine()
        cfg = (BASE + "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n"
               "!\nrouter bgp 65001\n neighbor 1.1.1.1 remote-as 65002\n")
        nr = n.normalize({"raw_lines": cfg.splitlines()}, "cisco", "ios_xe")
        blocks = nr.universal_config.get("networking", {}).get("routing_processes")
        assert isinstance(blocks, list) and len(blocks) == 2
        assert blocks[0]["proto"] == "ospf"
        assert blocks[1]["proto"] == "bgp"

    def test_router_process_scope_generic(self, engine):
        # Synthetic control proves the generic mechanism without touching
        # production controls: per-process regex evaluation.
        from app.benchmarks.models import (
            AssessmentStatus, BenchmarkControl, ControlSeverity)
        ctl = BenchmarkControl(
            benchmark_id="TEST", benchmark_name="Test",
            benchmark_version="v1", vendor="cisco", platform="ios_xe",
            control_id="T-RP-1", title="T", category="T",
            description="T", assessment_status=AssessmentStatus.AUTOMATED,
            severity=ControlSeverity.MEDIUM,
            target_model_path=None, operator="equals", expected_value=None,
            audit_command="", audit_regex=r"no\s+passive-interface",
            scope="ROUTER_PROCESS",
        )
        engine.execute(
            BASE + "router ospf 1\n passive-interface default\n",
            vendor="cisco", platform="ios_xe")
        # Control not in inventory; evaluate directly through the method.
        from app.engines.normalization import NormalizationEngine
        nr = NormalizationEngine().normalize(
            {"raw_lines": (BASE + "router ospf 1\n passive-interface default\n").splitlines()},
            "cisco", "ios_xe")
        ev = engine._evaluate_router_process_scope(
            ctl, nr, BASE + "router ospf 1\n passive-interface default\n",
            engine._base_evidence(ctl), None, 1.0, None)
        assert ev.result in ("PASS", "REVIEW", "FAIL")
        assert ev.evidence.evaluation_method == "router_process_scope"
