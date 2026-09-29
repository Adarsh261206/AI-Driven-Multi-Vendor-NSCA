"""Interface range scope tests (Issue #1 + matrix RANGE 1-15).

Block count vs affected interface count, expansion lineage, overrides,
shutdown ranges, duplicates — all generic, no control-id hacks.
"""

from __future__ import annotations

import pytest

from app.benchmarks.execution import BenchmarkExecutionEngine
from app.engines.normalization import (
    count_affected_interfaces,
    expand_interface_range,
    parse_interface_range,
)


@pytest.fixture
def engine() -> BenchmarkExecutionEngine:
    return BenchmarkExecutionEngine()


def _eval(engine: BenchmarkExecutionEngine, config: str, control_id: str):
    result = engine.execute(config, vendor="cisco", platform="ios_xe")
    for ev in result.evaluations:
        if ev.control_id == control_id:
            return ev
    raise AssertionError(f"Control {control_id} not found in evaluations")


BASE = "hostname RNG-01\n!\n"


class TestRangeUtility:
    """Matrix 11-13: counting primitives."""

    def test_single_interface_count_1(self):
        assert count_affected_interfaces("GigabitEthernet1/0/2") == 1

    def test_range_count(self):
        assert count_affected_interfaces("Gi1/0/10-14") == 5
        assert count_affected_interfaces("GigabitEthernet1/0/20-22") == 3
        assert count_affected_interfaces("GigabitEthernet1/0/5-47") == 43

    def test_malformed_range_count_1(self):
        assert count_affected_interfaces("Gi1/0/22-20") == 1
        assert count_affected_interfaces("") == 1
        assert count_affected_interfaces("Vlan10") == 1

    def test_expand_preserves_source(self):
        expanded = expand_interface_range("GigabitEthernet1/0/20-22")
        assert expanded == ["GigabitEthernet1/0/20",
                            "GigabitEthernet1/0/21",
                            "GigabitEthernet1/0/22"]

    def test_expand_single_returns_none(self):
        assert expand_interface_range("GigabitEthernet1/0/2") is None

    def test_parse_range(self):
        assert parse_interface_range("Gi1/0/20-22") == ("Gi1/0/", 20, 22)
        assert parse_interface_range("Gi1/0/2") is None


class TestRangeEvaluation:
    """Matrix 1-2, 6-8: single/range/multiple ranges."""

    def test_01_single_interface(self, engine):
        ev = _eval(engine, BASE + "interface Gi1/0/2\n ip proxy-arp\n", "2.1.15")
        assert ev.result == "FAIL"
        assert ev.evidence.evidence_block_count == 1
        assert ev.evidence.affected_scope_count == 1

    def test_02_range_counts_interfaces(self, engine):
        ev = _eval(engine, BASE + "interface Gi1/0/10-14\n ip proxy-arp\n", "2.1.15")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert ev.evidence.evidence_block_count == 1
        assert ev.evidence.affected_scope_count == 5

    def test_03_multiple_ranges(self, engine):
        cfg = (BASE + "interface Gi1/0/10-14\n ip proxy-arp\n"
               "!\ninterface Gi1/0/20-22\n ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "FAIL"
        assert ev.evidence.evidence_block_count == 2
        assert ev.evidence.affected_scope_count == 8

    def test_06_shutdown_range_excluded(self, engine):
        cfg = (BASE + "interface range Gi1/0/5-20\n shutdown\n"
               "!\ninterface Gi1/0/21\n no ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "PASS", ev.evidence.reasoning

    def test_07_secure_range(self, engine):
        cfg = (BASE + "interface range Gi1/0/5-20\n no ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "PASS", ev.evidence.reasoning
        assert ev.evidence.affected_scope_count == 16

    def test_08_insecure_range(self, engine):
        cfg = (BASE + "interface range Gi1/0/5-20\n ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert ev.evidence.affected_scope_count == 16


class TestRangeOverride:
    """Matrix 4-5: range + individual interaction."""

    def test_04_range_plus_individual_override(self, engine):
        cfg = (BASE + "interface range Gi1/0/5-20\n no ip proxy-arp\n"
               "!\ninterface Gi1/0/10\n ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "FAIL", ev.evidence.reasoning
        assert "Gi1/0/10" in ev.evidence.reasoning

    def test_05_individual_plus_later_range(self, engine):
        cfg = (BASE + "interface Gi1/0/2\n no ip proxy-arp\n"
               "!\ninterface range Gi1/0/5-20\n ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "FAIL", ev.evidence.reasoning


class TestRangeEdgeCases:
    """Matrix 9-10, 14-15: duplicates, mixed state, lineage."""

    def test_09_duplicate_commands_single_block(self, engine):
        cfg = (BASE + "interface Gi1/0/2\n ip proxy-arp\n ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "FAIL"
        assert ev.evidence.evidence_block_count == 1
        assert ev.evidence.affected_scope_count == 1

    def test_10_mixed_state_in_range(self, engine):
        # A range block holds ONE state per feature (last wins, IOS
        # order); mixed tested via separate blocks instead.
        cfg = (BASE + "interface Gi1/0/2\n no ip proxy-arp\n"
               "!\ninterface Gi1/0/3\n ip proxy-arp\n")
        ev = _eval(engine, cfg, "2.1.15")
        assert ev.result == "FAIL"
        assert ev.evidence.evidence_block_count == 1
        assert ev.evidence.affected_scope_count == 1

    def test_14_source_lineage_preserved(self, engine):
        from app.engines.normalization import NormalizationEngine
        n = NormalizationEngine()
        cfg = BASE + "interface range Gi1/0/20-22\n ip proxy-arp\n"
        nr = n.normalize({"raw_lines": cfg.splitlines()}, "cisco", "ios_xe")
        blocks = nr.universal_config.get("networking", {}).get("interface_blocks")
        assert len(blocks) == 1
        assert blocks[0]["name"] == "Gi1/0/20-22"
        assert blocks[0]["line"] == 3
        assert "range" in blocks[0]["raw"].lower()

    def test_15_no_duplicate_findings_from_range(self, engine):
        from app.engines.compliance.executor import AuditExecutor
        ex = AuditExecutor()
        cfg = BASE + "interface range Gi1/0/20-22\n ip proxy-arp\n"
        r = ex.execute("range-dup", cfg)
        ids = [f.control_id for f in r.findings if f.control_id == "2.1.15"]
        assert len(ids) == 1, f"range must not duplicate findings: {ids}"
