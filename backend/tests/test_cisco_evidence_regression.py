"""Cisco evidence-first regression tests (§11 A-L, §12 adversarial).

UNKNOWN / NOT_FOUND / PARSER_ERROR / LOW_CONFIDENCE must NEVER become FAIL.
Only explicit contradictory evidence may produce FAIL.
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


BASE = "hostname TEST-RTR-01\n!\n"


class TestFalsePositives:
    """§11 A-L: supplied-report false positives."""

    def test_a_vty_ssh_is_pass(self, engine):
        ev = _eval(engine, BASE + "line vty 0 15\n transport input ssh\n", "1.2.2")
        assert ev.result == "PASS", f"1.2.2 raw evidence present, got {ev.result}: {ev.evidence.result_reasoning}"

    def test_b_no_http_server_is_pass(self, engine):
        ev = _eval(engine, BASE + "no ip http server\n", "2.1.10")
        assert ev.result == "PASS", f"2.1.10 got {ev.result}: {ev.evidence.result_reasoning}"

    def test_c_no_redirects_is_pass(self, engine):
        ev = _eval(engine, BASE + "interface GigabitEthernet0/0\n no ip redirects\n", "2.1.13")
        assert ev.result == "PASS", f"2.1.13 got {ev.result}: {ev.evidence.result_reasoning}"

    def test_d_no_unreachables_is_pass(self, engine):
        ev = _eval(engine, BASE + "interface GigabitEthernet0/0\n no ip unreachables\n", "2.1.14")
        assert ev.result == "PASS", f"2.1.14 got {ev.result}: {ev.evidence.result_reasoning}"

    def test_e_no_proxy_arp_is_pass(self, engine):
        ev = _eval(engine, BASE + "interface GigabitEthernet0/0\n no ip proxy-arp\n", "2.1.15")
        assert ev.result == "PASS", f"2.1.15 got {ev.result}: {ev.evidence.result_reasoning}"

    def test_f_no_source_route_is_pass(self, engine):
        ev = _eval(engine, BASE + "no ip source-route\n", "2.1.16")
        assert ev.result == "PASS", f"2.1.16 got {ev.result}: {ev.evidence.result_reasoning}"

    def test_g_no_finger_is_pass(self, engine):
        ev = _eval(engine, BASE + "no service finger\n", "2.1.7")
        assert ev.result == "PASS", f"2.1.7 got {ev.result}: {ev.evidence.result_reasoning}"

    def test_h_no_pad_is_pass(self, engine):
        ev = _eval(engine, BASE + "no service pad\n", "2.1.8")
        assert ev.result == "PASS", f"2.1.8 got {ev.result}: {ev.evidence.result_reasoning}"

    def test_i_finger_enabled_is_fail(self, engine):
        ev = _eval(engine, BASE + "service finger\n", "2.1.7")
        assert ev.result == "FAIL", f"2.1.7 explicit violation, got {ev.result}"

    def test_j_http_enabled_is_fail(self, engine):
        ev = _eval(engine, BASE + "ip http server\n", "2.1.10")
        assert ev.result == "FAIL", f"2.1.10 explicit violation, got {ev.result}"

    def test_k_vty_telnet_is_fail(self, engine):
        ev = _eval(engine, BASE + "line vty 0 15\n transport input telnet\n", "1.2.2")
        assert ev.result == "FAIL", f"1.2.2 explicit contradiction, got {ev.result}"

    def test_l_vty_ssh_telnet_never_pass(self, engine):
        ev = _eval(engine, BASE + "line vty 0 15\n transport input ssh telnet\n", "1.2.2")
        assert ev.result in ("FAIL", "REVIEW"), f"1.2.2 mixed transport must never PASS, got {ev.result}"


class TestUnknownNeverFail:
    """§1: UNKNOWN / missing / ambiguous evidence must be REVIEW, never FAIL."""

    def test_no_vty_block_is_review_not_fail(self, engine):
        ev = _eval(engine, BASE + "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n", "1.2.2")
        assert ev.result == "REVIEW", f"no VTY evidence must be REVIEW, got {ev.result}"

    def test_no_http_mention_is_review_not_fail(self, engine):
        ev = _eval(engine, BASE + "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n", "2.1.10")
        assert ev.result == "REVIEW", f"no HTTP evidence must be REVIEW, got {ev.result}"

    def test_empty_config_no_fail(self, engine):
        result = engine.execute("", vendor="cisco", platform="ios_xe")
        fails = [e for e in result.evaluations if e.result == "FAIL"]
        assert fails == [], f"empty config must produce zero FAIL, got {[e.control_id for e in fails]}"

    def test_review_has_reason(self, engine):
        ev = _eval(engine, BASE, "1.2.2")
        assert ev.result == "REVIEW"
        assert ev.evidence.reasoning, "REVIEW must carry an explicit reason"


class TestAdversarial:
    """§12: commands in comments/descriptions must not count as evidence."""

    def test_description_does_not_satisfy(self, engine):
        cfg = BASE + "interface GigabitEthernet0/0\n description \"transport input ssh\"\n"
        ev = _eval(engine, cfg, "1.2.2")
        assert ev.result == "REVIEW", f"description text must not satisfy control, got {ev.result}"

    def test_comment_does_not_satisfy(self, engine):
        cfg = BASE + "! transport input ssh\n"
        ev = _eval(engine, cfg, "1.2.2")
        assert ev.result == "REVIEW", f"comment text must not satisfy control, got {ev.result}"

    def test_case_insensitive(self, engine):
        ev = _eval(engine, BASE + "line vty 0 15\n TRANSPORT INPUT SSH\n", "1.2.2")
        assert ev.result == "PASS", f"Cisco is case-insensitive, got {ev.result}"

    def test_extra_whitespace(self, engine):
        ev = _eval(engine, BASE + "line vty 0 15\n   transport    input    ssh\n", "1.2.2")
        assert ev.result == "PASS", f"extra whitespace must still match, got {ev.result}"

    def test_multiple_vty_blocks_all_compliant(self, engine):
        cfg = BASE + "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input ssh\n"
        _eval(engine, cfg, "1.2.8")
        # 1.2.8 is exec-timeout; transport checked via 1.2.2
        ev2 = _eval(engine, cfg, "1.2.2")
        assert ev2.result == "PASS", f"multi-block all-compliant must PASS, got {ev2.result}"

    def test_multiple_vty_blocks_one_bad(self, engine):
        cfg = BASE + "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input telnet\n"
        ev = _eval(engine, cfg, "1.2.2")
        assert ev.result == "FAIL", f"one bad VTY block must FAIL with block evidence, got {ev.result}"

    def test_exec_timeout_multi_block(self, engine):
        cfg = BASE + "line vty 0 4\n exec-timeout 10 0\nline vty 5 15\n exec-timeout 10 0\n"
        ev = _eval(engine, cfg, "1.2.8")
        assert ev.result == "PASS", f"all VTY timeouts compliant must PASS, got {ev.result}: {ev.evidence.result_reasoning}"

    def test_exec_timeout_one_block_missing(self, engine):
        cfg = BASE + "line vty 0 4\n exec-timeout 10 0\nline vty 5 15\n transport input ssh\n"
        ev = _eval(engine, cfg, "1.2.8")
        assert ev.result in ("FAIL", "REVIEW"), f"incomplete block data must not PASS, got {ev.result}"
