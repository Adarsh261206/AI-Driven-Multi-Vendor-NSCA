"""Pipeline lineage regression tests: parser -> normalizer -> evaluator.

Every test runs the FULL production path (AuditExecutor.execute), which
feeds E04 parse-tree sections into normalization — the path where scoped
negation (`no ip X` inside interface blocks) was previously lost, yielding
false REVIEW for explicit positive evidence.

Matrix TEST 1-14 + cross-feature generalization + adversarial A-L.
"""

from __future__ import annotations

import pytest

from app.engines.compliance.executor import AuditExecutor


@pytest.fixture
def executor() -> AuditExecutor:
    return AuditExecutor()


def _eval(executor: AuditExecutor, config: str, control_id: str):
    result = executor.execute("lineage-test", config)
    assert result.status == "completed", f"audit failed: {result.status}"
    for ev in result.benchmark_result.evaluations:
        if ev.control_id == control_id:
            return ev
    raise AssertionError(f"Control {control_id} not found in evaluations")


BASE = "hostname LIN-01\n!\n"


class TestExplicitDisabled:
    """TEST 1: explicit disabled state per interface."""

    def test_01_redirects_disabled(self, executor):
        ev = _eval(executor,
                   BASE + "interface GigabitEthernet1/0/1\n no ip redirects\n",
                   "2.1.13")
        assert ev.result == "PASS", ev.evidence.reasoning
        assert "GigabitEthernet1/0/1" in ev.evidence.reasoning

    def test_10_all_three_features(self, executor):
        cfg = (BASE + "interface GigabitEthernet1/0/1\n no ip redirects\n"
               " no ip unreachables\n no ip proxy-arp\n")
        for cid in ("2.1.13", "2.1.14", "2.1.15"):
            ev = _eval(executor, cfg, cid)
            assert ev.result == "PASS", f"{cid}: {ev.evidence.reasoning}"


class TestExplicitEnabled:
    """TEST 2: explicit enabled state per interface is FAIL."""

    def test_02_redirects_enabled(self, executor):
        ev = _eval(executor,
                   BASE + "interface GigabitEthernet1/0/1\n ip redirects\n",
                   "2.1.13")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "GigabitEthernet1/0/1" in ev.evidence.reasoning


class TestAbsent:
    """TEST 3: absent statement is REVIEW, never PASS/FAIL."""

    def test_03_absent_is_review(self, executor):
        ev = _eval(executor,
                   BASE + "interface GigabitEthernet1/0/1\n description USER\n",
                   "2.1.13")
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_14_unrelated_command_no_effect(self, executor):
        ev = _eval(executor,
                   BASE + "interface GigabitEthernet1/0/1\n no shutdown\n",
                   "2.1.13")
        assert ev.result == "REVIEW", ev.evidence.reasoning


class TestOppositeStates:
    """TEST 4/12: two interfaces, opposite states — never merged."""

    def test_04_opposite_states(self, executor):
        cfg = (BASE + "interface GigabitEthernet1/0/1\n no ip redirects\n"
               "!\ninterface GigabitEthernet1/0/2\n ip redirects\n")
        ev = _eval(executor, cfg, "2.1.13")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "GigabitEthernet1/0/2" in ev.evidence.reasoning

    def test_12_block_transition(self, executor):
        cfg = (BASE + "interface GigabitEthernet1/0/1\n no ip redirects\n"
               "!\ninterface GigabitEthernet1/0/2\n ip redirects\n")
        ev = _eval(executor, cfg, "2.1.13")
        assert ev.result == "FAIL", ev.evidence.reasoning


class TestGlobalVsInterface:
    """TEST 5: global statements never satisfy interface controls."""

    def test_05_global_does_not_satisfy_interface(self, executor):
        ev = _eval(executor,
                   BASE + "no ip redirects\n"
                   "!\ninterface GigabitEthernet1/0/1\n description USER\n",
                   "2.1.13")
        assert ev.result == "REVIEW", ev.evidence.reasoning


class TestCommentsExcluded:
    """TEST 6: comments are never evidence."""

    def test_06_comment_ignored(self, executor):
        cfg = (BASE + "!\n! Recommended:\n! no ip redirects\n"
               "!\ninterface Gi1/0/1\n switchport mode access\n")
        ev = _eval(executor, cfg, "2.1.13")
        assert ev.result == "REVIEW", ev.evidence.reasoning


class TestRemediationNeverEvidence:
    """TEST 7: remediation text is never source evidence."""

    def test_07_evidence_is_config(self, executor):
        cfg = BASE + "interface Gi1/0/2\n ip proxy-arp\n"
        result = executor.execute("lineage-rem", cfg)
        f = next(x for x in result.findings if x.control_id == "2.1.15")
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        blob = str(ev.get("raw_config", "")) + str(ev.get("reasoning", ""))
        assert "Gi1/0/2" in blob


class TestInterfaceRange:
    """TEST 8/9: range semantics without duplication."""

    def test_08_range_compliant(self, executor):
        cfg = (BASE + "interface range GigabitEthernet1/0/5-47\n"
               " no ip redirects\n")
        ev = _eval(executor, cfg, "2.1.13")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_09_range_plus_override(self, executor):
        cfg = (BASE + "interface range GigabitEthernet1/0/5-47\n"
               " no ip redirects\n"
               "!\ninterface GigabitEthernet1/0/10\n ip redirects\n")
        ev = _eval(executor, cfg, "2.1.13")
        # The individual violating interface must be identified; the range
        # must not merge into it or hide it.
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "GigabitEthernet1/0/10" in ev.evidence.reasoning


class TestCaseWhitespace:
    """TEST 11: case and whitespace tolerance."""

    def test_11_case_whitespace(self, executor):
        cfg = (BASE + "interface   GigabitEthernet1/0/1\n"
               "    NO    IP REDIRECTS\n")
        ev = _eval(executor, cfg, "2.1.13")
        assert ev.result == "PASS", ev.evidence.reasoning


class TestSVI:
    """TEST 13: SVI is interface-scoped, never global."""

    def test_13_svi_scoped(self, executor):
        ev = _eval(executor,
                   BASE + "interface Vlan10\n no ip redirects\n",
                   "2.1.13")
        assert ev.result == "PASS", ev.evidence.reasoning
        assert "Vlan10" in ev.evidence.reasoning


class TestCrossFeature:
    """Cross-feature generalization: same mechanism, all scoped features."""

    def test_unreachables_enabled_is_fail(self, executor):
        ev = _eval(executor,
                   BASE + "interface Gi1/0/4\n ip unreachables\n",
                   "2.1.14")
        assert ev.result == "FAIL", ev.evidence.reasoning

    def test_unreachables_disabled_is_pass(self, executor):
        ev = _eval(executor,
                   BASE + "interface Gi1/0/5\n no ip unreachables\n",
                   "2.1.14")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_source_route_global_fail(self, executor):
        cfg = (BASE + "interface Loopback0\n"
               " ip address 10.0.0.1 255.255.255.255\n"
               "!\nip source-route\n")
        ev = _eval(executor, cfg, "2.1.16")
        assert ev.result == "FAIL", ev.evidence.reasoning

    def test_source_route_global_pass(self, executor):
        cfg = (BASE + "interface Loopback0\n"
               " ip address 10.0.0.1 255.255.255.255\n"
               "!\nno ip source-route\n")
        ev = _eval(executor, cfg, "2.1.16")
        assert ev.result == "PASS", ev.evidence.reasoning


class TestAdversarialLineage:
    """Adversarial A-L through the full executor path."""

    def test_a_console_only_no_aux(self, executor):
        ev = _eval(executor, BASE + "line console 0\n exec-timeout 10 0\n", "1.2.6")
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_b_aux_only(self, executor):
        ev = _eval(executor, BASE + "line aux 0\n exec-timeout 30 0\n", "1.2.6")
        assert ev.result == "FAIL", ev.evidence.reasoning

    def test_j_mixed_vty_identifies_block(self, executor):
        cfg = (BASE + "line vty 0 4\n transport input ssh\n"
               "!\nline vty 5 15\n transport input telnet\n")
        ev = _eval(executor, cfg, "1.2.2")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "line vty 5 15" in ev.evidence.reasoning
