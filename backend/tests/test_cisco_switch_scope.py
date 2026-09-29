"""Cisco switch scope regression tests (PART 17).

Interface-scoped (2.1.13/2.1.14/2.1.15), global (2.1.16), AUX/CONSOLE
isolation (1.2.6/1.2.7), multi-VTY (1.2.2/1.2.8), description guards.
Generic scope-aware evaluator — no control-id hacks.
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


BASE = "hostname SW-TEST-01\n!\n"


class TestInterfaceViolations:
    """PART 17 cases 1-3, 11: affirmative per-interface state is FAIL."""

    def test_01_proxy_arp_violation_is_fail(self, engine):
        ev = _eval(engine, BASE + "interface Gi1/0/2\n ip proxy-arp\n", "2.1.15")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "Gi1/0/2" in ev.evidence.reasoning

    def test_02_redirects_violation_is_fail(self, engine):
        ev = _eval(engine, BASE + "interface Gi1/0/3\n ip redirects\n", "2.1.13")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "Gi1/0/3" in ev.evidence.reasoning

    def test_03_unreachables_violation_is_fail(self, engine):
        ev = _eval(engine, BASE + "interface Gi1/0/4\n ip unreachables\n", "2.1.14")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "Gi1/0/4" in ev.evidence.reasoning

    def test_11_mixed_interfaces_fail_with_violator(self, engine):
        cfg = (BASE + "interface Gi1/0/1\n no ip proxy-arp\n"
               "!\ninterface Gi1/0/2\n ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "Gi1/0/2" in ev.evidence.reasoning
        assert "Gi1/0/1" not in ev.evidence.reasoning.split("Violating")[1]


class TestInterfaceCompliant:
    """PART 17 cases 5, 12: all-applicable-compliant is PASS."""

    def test_05_global_negatives_pass(self, engine):
        # NOTE: bare global `no ip X` lines are legacy IOS global noise;
        # interface scope needs per-interface statements (see below).
        cfg = (BASE + "interface Gi1/0/1\n no ip proxy-arp\n"
               "!\ninterface Gi1/0/2\n no ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_12_all_compliant_pass(self, engine):
        cfg = (BASE + "interface Gi1/0/1\n no ip redirects\n"
               "!\ninterface Gi1/0/2\n no ip redirects\n")
        ev = _eval(engine, cfg, "2.1.13")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_13_insufficient_is_review(self, engine):
        ev = _eval(engine, BASE + "interface Gi1/0/1\n switchport mode access\n", "2.1.15")
        assert ev.result == "REVIEW", ev.evidence.reasoning
        assert ev.evidence.review_code == "INSUFFICIENT_EVIDENCE"


class TestGlobalSourceRoute:
    """PART 17 case 4 + PART 5."""

    def test_04_global_source_route_is_fail(self, engine):
        ev = _eval(engine, BASE + "ip source-route\n", "2.1.16")
        assert ev.result == "FAIL", ev.evidence.reasoning

    def test_global_negated_is_pass(self, engine):
        ev = _eval(engine, BASE + "no ip source-route\n", "2.1.16")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_interface_statement_ignored_for_global(self, engine):
        cfg = BASE + "interface Gi1/0/2\n ip source-route\n"
        ev = _eval(engine, cfg, "2.1.16")
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_description_never_evidence_global(self, engine):
        cfg = BASE + 'description "ip source-route"\n'
        ev = _eval(engine, cfg, "2.1.16")
        assert ev.result == "REVIEW", ev.evidence.reasoning


class TestAuxConsoleIsolation:
    """PART 17 cases 6-7 + PART 7."""

    def test_06_aux_independent(self, engine):
        cfg = (BASE + "line aux 0\n exec-timeout 5 0\n"
               "!\nline console 0\n exec-timeout 60 0\n"
               "!\nline vty 0 4\n exec-timeout 60 0\n")
        ev = _eval(engine, cfg, "1.2.6")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_07_console_independent(self, engine):
        cfg = (BASE + "line aux 0\n exec-timeout 60 0\n"
               "!\nline console 0\n exec-timeout 10 0\n"
               "!\nline vty 0 4\n exec-timeout 60 0\n")
        ev = _eval(engine, cfg, "1.2.7")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_aux_violation_is_fail(self, engine):
        ev = _eval(engine, BASE + "line aux 0\n exec-timeout 30 0\n", "1.2.6")
        assert ev.result == "FAIL", ev.evidence.reasoning

    def test_console_violation_is_fail(self, engine):
        ev = _eval(engine, BASE + "line console 0\n exec-timeout 30 0\n", "1.2.7")
        assert ev.result == "FAIL", ev.evidence.reasoning


class TestVtyMultiBlock:
    """PART 17 case 8 + PART 6."""

    def test_08_mixed_vty_fail_identifies_block(self, engine):
        cfg = (BASE + "line vty 0 4\n transport input ssh\n"
               "!\nline vty 5 15\n transport input telnet\n")
        ev = _eval(engine, cfg, "1.2.2")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "line vty 5 15" in ev.evidence.reasoning


class TestDescriptionGuards:
    """PART 17 cases 9-10."""

    def test_09_description_proxy_arp_ignored(self, engine):
        cfg = BASE + 'interface Gi1/0/2\n description "ip proxy-arp"\n'
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_10_description_redirects_ignored(self, engine):
        cfg = BASE + 'interface Gi1/0/3\n description "ip redirects"\n'
        ev = _eval(engine, cfg, "2.1.13")
        assert ev.result == "REVIEW", ev.evidence.reasoning
