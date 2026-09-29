"""Adversarial scope/context tests (mission mandatory cases A-L).

Console/AUX/VTY isolation, interface separation, range semantics,
global/local separation, comment exclusion, remediation-as-evidence ban.
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


BASE = "hostname ADV-01\n!\n"


class TestLineIsolation:
    """A/B: console evidence must never attach to AUX and vice versa."""

    def test_a_console_only_no_aux_evidence(self, engine):
        ev = _eval(engine, BASE + "line console 0\n exec-timeout 10 0\n", "1.2.6")
        # 1.2.6 is AUX-scoped: no AUX block exists -> REVIEW, and the
        # evidence must not reference console content.
        assert ev.result == "REVIEW", ev.evidence.reasoning
        assert "console" not in ev.evidence.raw_evidence_snippet.lower()

    def test_b_aux_only_evidence(self, engine):
        ev = _eval(engine, BASE + "line aux 0\n exec-timeout 30 0\n", "1.2.6")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "aux" in ev.evidence.raw_evidence_snippet.lower()
        assert "console" not in ev.evidence.raw_evidence_snippet.lower()


class TestInterfaceSeparation:
    """C/J: per-interface independence."""

    def test_c_single_interface_only(self, engine):
        ev = _eval(engine, BASE + "interface GigabitEthernet1/0/1\n no ip redirects\n", "2.1.13")
        assert ev.result == "PASS", ev.evidence.reasoning
        assert "GigabitEthernet1/0/1" in ev.evidence.reasoning

    def test_j_mixed_interfaces_separate(self, engine):
        cfg = (BASE + "interface GigabitEthernet1/0/1\n no ip redirects\n"
               "!\ninterface GigabitEthernet1/0/2\n ip redirects\n")
        ev = _eval(engine, cfg, "2.1.13")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "GigabitEthernet1/0/2" in ev.evidence.reasoning


class TestInterfaceRange:
    """D/K: range semantics without duplication."""

    def test_d_range_compliant(self, engine):
        cfg = (BASE + "interface range GigabitEthernet1/0/1-47\n"
               " no ip redirects\n")
        ev = _eval(engine, cfg, "2.1.13")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_k_range_and_individual_separate(self, engine):
        cfg = (BASE + "interface range GigabitEthernet1/0/1-47\n"
               " no ip redirects\n"
               "!\ninterface GigabitEthernet1/0/48\n ip redirects\n")
        ev = _eval(engine, cfg, "2.1.13")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "GigabitEthernet1/0/48" in ev.evidence.reasoning

    def test_range_no_duplicate_blocks(self, engine):
        from app.engines.normalization import NormalizationEngine
        n = NormalizationEngine()
        cfg = BASE + "interface range GigabitEthernet1/0/1-47\n no ip redirects\n"
        nr = n.normalize({"raw_lines": cfg.splitlines()}, "cisco", "ios_xe")
        blocks = nr.universal_config.get("networking", {}).get("interface_blocks")
        assert isinstance(blocks, list) and len(blocks) == 1
        assert "1-47" in blocks[0]["name"] or "range" in blocks[0]["name"].lower()


class TestSourceInterfaceControls:
    """E/F: logging/ntp host must not satisfy source-interface controls."""

    def test_e_logging_host_not_source_interface(self, engine):
        ev = _eval(engine, BASE + "logging host 10.0.0.10\n", "2.2.3")
        assert ev.result != "PASS", (
            f"logging host must not satisfy source-interface: {ev.result}")

    def test_e_logging_source_interface_pass(self, engine):
        ev = _eval(engine, BASE + "logging source-interface Loopback0\n", "2.2.3")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_f_ntp_server_not_source_interface(self, engine):
        ev = _eval(engine, BASE + "ntp server 10.0.0.1\n", "2.3.4")
        assert ev.result != "PASS", (
            f"ntp server must not satisfy source-interface: {ev.result}")

    def test_f_ntp_source_interface_pass(self, engine):
        ev = _eval(engine, BASE + "ntp source Loopback0\n", "2.3.4")
        assert ev.result == "PASS", ev.evidence.reasoning


class TestCommentExclusion:
    """H: comments are never evidence."""

    def test_h_commented_no_redirects_ignored(self, engine):
        cfg = BASE + "!\n! Recommended:\n! no ip redirects\n!\ninterface Gi1/0/1\n switchport mode access\n"
        ev = _eval(engine, cfg, "2.1.13")
        # Gi1/0/1 has no statement; the commented line must not count.
        assert ev.result == "REVIEW", ev.evidence.reasoning


class TestRemediationNeverEvidence:
    """G/I: remediation text is never source evidence."""

    def test_g_remediation_text_not_evidence(self, engine):
        # A config containing ONLY the remediation string as free text
        # (e.g. pasted doc) outside any interface block must not satisfy
        # an interface-scoped control.
        cfg = BASE + "no ip redirects\n"
        ev = _eval(engine, cfg, "2.1.13")
        # Global noise alone: no interface block carries the statement.
        assert ev.result == "REVIEW", ev.evidence.reasoning

    def test_i_finding_evidence_is_config(self, engine):
        from app.engines.compliance.executor import AuditExecutor
        ex = AuditExecutor()
        cfg = (BASE + "interface Gi1/0/2\n ip proxy-arp\n")
        r = ex.execute("adv-test", cfg)
        f = next(x for x in r.findings if x.control_id == "2.1.15")
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        blob = (str(ev.get("raw_config", "")) + str(ev.get("reasoning", "")))
        assert "Gi1/0/2" in blob
        # Remediation text must not appear as the observed config.
        assert "Remediation" not in blob or "ip proxy-arp" in blob


class TestGlobalLocalSeparation:
    """L: global statements never satisfy interface controls."""

    def test_l_global_does_not_satisfy_interface(self, engine):
        ev = _eval(engine, BASE + "no ip redirects\n", "2.1.13")
        assert ev.result == "REVIEW", ev.evidence.reasoning
