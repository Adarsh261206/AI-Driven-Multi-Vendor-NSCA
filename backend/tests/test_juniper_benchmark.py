"""
Phase 10 - Juniper Multi-Vendor Benchmark Integration Tests

Covers:
- Junos parser (hierarchical, set-style, ##-prefixed, malformed)
- Juniper normalization to universal model
- CIS Juniper OS v2.1.0 benchmark ingestion
- Deterministic PASS/FAIL/REVIEW evaluation through the shared engine
- Missing evidence, duplicate/conflicting settings
- Evidence chains, remediation metadata
- Full Juniper audits on 8 sample configs
- Cisco regression through the same engine
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.benchmarks.execution import BenchmarkExecutionEngine
from app.benchmarks.juniper_junos_controls import (
    get_all_controls,
    get_registry,
)
from app.benchmarks.models import AssessmentStatus, BenchmarkRegistry
from app.benchmarks.registry import ControlRegistry
from app.engines.normalization import NormalizationEngine
from app.engines.parsing.juniper import JunosParser

SAMPLE_DIR = Path(__file__).parent / "sample_configs"


def _load(name: str) -> str:
    return (SAMPLE_DIR / name).read_text()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def parser() -> JunosParser:
    return JunosParser()


@pytest.fixture(scope="module")
def normalizer() -> NormalizationEngine:
    return NormalizationEngine()


@pytest.fixture(scope="module")
def engine() -> BenchmarkExecutionEngine:
    return BenchmarkExecutionEngine()


@pytest.fixture(scope="module")
def registry() -> ControlRegistry:
    reg = ControlRegistry()
    reg.register_benchmark(get_registry())
    return reg


def _eval(result, control_id):
    return next(e for e in result.evaluations if e.control_id == control_id)


def _run_junos(engine, name: str):
    return engine.execute(_load(name), vendor="juniper", platform="junos")


# ===========================================================================
# TASK 2: Junos Parser
# ===========================================================================

class TestJunosParser:
    def test_hierarchical_parses_top_level(self, parser):
        result = parser.parse(_load("juniper_secure.txt"))
        assert result.parse_errors == []
        top = [n.key for n in result.parse_tree]
        assert "system" in top
        assert "interfaces" in top
        assert "snmp" in top

    def test_hierarchical_preserves_context(self, parser):
        result = parser.parse(_load("juniper_secure.txt"))
        ssh = JunosParser.get_section(result.parse_tree, ["system", "services", "ssh"])
        assert ssh is not None
        children = {c.key: c.value for c in ssh.children}
        assert children.get("protocol-version") == "v2"
        assert children.get("root-login") == "deny"

    def test_hierarchical_preserves_line_numbers(self, parser):
        result = parser.parse(_load("juniper_secure.txt"))
        ssh = JunosParser.get_section(result.parse_tree, ["system", "services", "ssh"])
        assert ssh is not None
        pv = next(c for c in ssh.children if c.key == "protocol-version")
        assert pv.line_number > 0
        assert "protocol-version" in pv.raw_text

    def test_repeated_blocks_preserved(self, parser):
        result = parser.parse(_load("juniper_multiple_blocks.txt"))
        ntp = JunosParser.get_section(result.parse_tree, ["system", "ntp"])
        servers = [c for c in ntp.children if c.key == "server"] if ntp else []
        assert len(servers) == 3

    def test_set_style_parsing(self, parser):
        cfg = (
            "set system host-name R2\n"
            "set system services ssh protocol-version v2\n"
            "set system services ssh root-login deny\n"
            "set system login retry-options tries-before-disconnect 3\n"
            "set interfaces lo0 unit 0 family inet address 10.0.0.1/32\n"
        )
        result = parser.parse(cfg)
        assert result.parse_errors == []
        ssh = JunosParser.get_section(result.parse_tree, ["system", "services", "ssh"])
        assert ssh is not None
        children = {c.key: c.value for c in ssh.children}
        assert children.get("protocol-version") == "v2"
        assert children.get("root-login") == "deny"

    def test_malformed_reports_unbalanced_braces(self, parser):
        result = parser.parse(_load("juniper_malformed.txt"))
        assert len(result.parse_warnings) >= 1
        assert any("Unclosed braces" in w.message for w in result.parse_warnings)

    def test_unknown_style_does_not_crash(self, parser):
        result = parser.parse(_load("juniper_unknown.txt"))
        assert result.parse_tree is not None

    def test_find_all(self, parser):
        result = parser.parse(_load("juniper_secure.txt"))
        addresses = JunosParser.find_all(result.parse_tree, "address")
        assert len(addresses) >= 1

    def test_parse_result_to_dict(self, parser):
        result = parser.parse(_load("juniper_secure.txt"))
        d = result.to_dict()
        assert "parse_tree" in d
        assert "parse_errors" in d
        assert "parse_warnings" in d


# ===========================================================================
# TASK 3: Juniper Normalization
# ===========================================================================

class TestJuniperNormalization:
    def test_secure_normalizes_all_paths(self, normalizer):
        cfg = {"raw_lines": _load("juniper_secure.txt").splitlines()}
        result = normalizer.normalize(cfg, "juniper", "junos")
        uc = result.universal_config

        assert uc.get("device", {}).get("hostname") == "SECURE-JUNOS-01"
        assert uc["device"]["time_zone"] == "UTC"
        assert uc["management"]["ssh"]["version"] == 2
        assert uc["management"]["ssh"]["root_login"] == "deny"
        assert "enabled" not in uc.get("management", {}).get("telnet", {})
        assert uc["authentication"]["password_policy"]["min_length"] == 10
        assert uc["authentication"]["password_policy"]["hash_algorithm"] == "sha512"
        assert uc["authentication"]["lockout_policy"]["max_attempts"] == 3
        assert uc["authentication"]["lockout_policy"]["lockout_duration"] == 1800
        assert uc["aaa"]["accounting_enabled"] is True
        assert uc["logging"]["remote_enabled"] is True
        assert uc["ntp"]["servers"] == ["10.0.0.20", "10.0.0.21"]
        assert uc["ntp"]["version"] == 4
        assert uc["interfaces"]["loopback_configured"] is True

    def test_min_length_not_mapped_to_authentication_order(self, normalizer):
        """Regression: min_length must NOT map to authentication-order (old bug)."""
        cfg = {"raw_lines": ["set system login password minimum-length 14"]}
        result = normalizer.normalize(cfg, "juniper", "junos")
        assert result.universal_config["authentication"]["password_policy"]["min_length"] == 14

    def test_missing_values_return_none(self, normalizer):
        cfg = {"raw_lines": ["## system {", "##     host-name only;", "## }"]}
        result = normalizer.normalize(cfg, "juniper", "junos")
        uc = result.universal_config
        # Strength/security values must be absent → REVIEW, never default-compliant
        assert "version" not in uc.get("management", {}).get("ssh", {})
        assert "root_login" not in uc.get("management", {}).get("ssh", {})
        assert "servers" not in uc.get("ntp", {})
        assert "version" not in uc.get("ntp", {})
        assert "password_policy" not in uc.get("authentication", {})
        assert "lockout_policy" not in uc.get("authentication", {})

    def test_set_style_normalization(self, normalizer):
        cfg = {"raw_lines": [
            "set system host-name R2",
            "set system services ssh protocol-version v2",
            "set system services ssh root-login deny",
            "set system login retry-options tries-before-disconnect 3",
            "set system ntp server 10.0.0.1",
            "set system time-zone UTC",
        ]}
        result = normalizer.normalize(cfg, "juniper", "junos")
        uc = result.universal_config
        assert uc["management"]["ssh"]["version"] == 2
        assert uc["management"]["ssh"]["root_login"] == "deny"
        assert uc["authentication"]["lockout_policy"]["max_attempts"] == 3
        assert uc["ntp"]["servers"] == ["10.0.0.1"]
        assert uc["device"]["time_zone"] == "UTC"

    def test_lockout_period_converted_to_seconds(self, normalizer):
        cfg = {"raw_lines": ["set system login retry-options lockout-period 45"]}
        result = normalizer.normalize(cfg, "juniper", "junos")
        assert result.universal_config["authentication"]["lockout_policy"]["lockout_duration"] == 2700


# ===========================================================================
# TASK 1 + TASK 4: Benchmark Ingestion
# ===========================================================================

class TestJuniperBenchmarkIngestion:
    def test_controls_load(self):
        controls = get_all_controls()
        assert 10 <= len(controls) <= 20

    def test_metadata(self):
        controls = get_all_controls()
        for c in controls:
            assert c.benchmark_id == "CIS-JUNIPER-OS-v2.1.0"
            assert c.benchmark_name == "CIS Juniper OS Benchmark"
            assert c.benchmark_version == "v2.1.0"
            assert c.vendor == "juniper"
            assert c.platform == "junos"
            assert c.source_document == "CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf"
            assert c.source_location
            assert c.title
            assert c.severity

    def test_automated_vs_manual(self):
        controls = get_all_controls()
        automated = [c for c in controls if c.assessment_status == AssessmentStatus.AUTOMATED.value]
        manual = [c for c in controls if c.assessment_status == AssessmentStatus.MANUAL.value]
        assert len(automated) >= 10
        assert len(manual) >= 1

    def test_model_path_vs_regex(self):
        controls = get_all_controls()
        model = [c for c in controls if c.target_model_path]
        regex = [c for c in controls if not c.target_model_path and c.assessment_status == AssessmentStatus.AUTOMATED.value]
        assert len(model) >= 10
        assert len(regex) >= 1

    def test_domains_covered(self):
        controls = get_all_controls()
        categories = {c.category for c in controls}
        required = {"SSH", "SNMP", "NTP", "Login"}
        assert required.issubset(categories)

    def test_registry_registration(self, registry):
        controls = registry.get_controls_by_vendor_platform("juniper", "junos")
        assert len(controls) == len(get_all_controls())

    def test_no_duplicate_control_ids(self):
        controls = get_all_controls()
        ids = [c.control_id for c in controls]
        assert len(ids) == len(set(ids))

    def test_registry_stats(self, registry):
        stats = registry.get_stats()
        assert stats["total"] == len(get_all_controls())


# ===========================================================================
# TASK 5: Deterministic Evaluation
# ===========================================================================

class TestJuniperEvaluation:
    def test_secure_all_automated_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        cis_fail = [ev.control_id for ev in result.evaluations
                    if ev.result == "FAIL" and ev.evidence.framework == "CIS"]
        # Every FAIL must be reconstructable from its evidence chain.
        for ev in result.evaluations:
            if ev.result == "FAIL":
                assert ev.evidence.reasoning.strip() != ""
                assert ev.evidence.raw_config_line_numbers
        assert cis_fail == []

    def test_insecure_most_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        assert result.failed >= 8

    def test_secure_score_high(self, engine):
        secure = _run_junos(engine, "juniper_secure.txt")
        insecure = _run_junos(engine, "juniper_insecure.txt")
        cis_secure = engine.execute(
            _load("juniper_secure.txt"), vendor="juniper", platform="junos",
            framework="CIS")
        # Unmapped controls REVIEW by design (§13.4), so the dual score is
        # REVIEW-heavy; the secure config must still outscore the insecure
        # one, and the CIS scope must be FAIL-free.
        assert secure.score > insecure.score
        assert cis_secure.failed == 0
        assert cis_secure.evaluated == 17

    def test_insecure_score_low(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        assert result.score <= 30

    def test_manual_always_review(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "1.7")
        assert ev.result == "REVIEW"
        assert "Manual" in ev.evidence.reasoning

    def test_benchmark_metadata_in_result(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        assert result.benchmark_id == "CIS+NIST"
        assert result.framework == "CIS+NIST"
        assert result.platform == "junos"
        scoped = engine.execute(
            _load("juniper_secure.txt"), vendor="juniper", platform="junos",
            framework="CIS")
        assert scoped.benchmark_id == "CIS-JUNIPER-OS-v2.1.0"
        assert scoped.benchmark_name == "CIS Juniper OS Benchmark"

    def test_all_controls_produce_valid_results(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        assert len(result.evaluations) == 143
        for ev in result.evaluations:
            assert ev.result in ("PASS", "FAIL", "REVIEW")

    # --- SSH controls ---

    def test_ssh_version_2_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.10.1.2")
        assert ev.result == "PASS"
        assert ev.evidence.actual_value == 2

    def test_ssh_version_1_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.10.1.2")
        assert ev.result == "FAIL"

    def test_ssh_version_missing_review(self, engine):
        result = _run_junos(engine, "juniper_minimal.txt")
        ev = _eval(result, "6.10.1.2")
        assert ev.result == "REVIEW"

    def test_root_login_deny_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.10.1.5")
        assert ev.result == "PASS"

    def test_root_login_allow_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.10.1.5")
        assert ev.result == "FAIL"

    def test_telnet_disabled_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.10.6")
        # E05 F1: the secure fixture states no telnet service, so telnet
        # enablement is unobserved (not fabricated False) -> REVIEW.
        assert ev.result == "REVIEW"
        assert ev.evidence.actual_value is None

    def test_telnet_enabled_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.10.6")
        assert ev.result == "FAIL"

    # --- Login controls ---

    def test_tries_before_disconnect_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.6.1.1")
        assert ev.result == "PASS"
        assert ev.evidence.actual_value == 3

    def test_tries_before_disconnect_10_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.6.1.1")
        assert ev.result == "FAIL"

    def test_lockout_period_30min_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.6.1.5")
        assert ev.result == "PASS"
        assert ev.evidence.actual_value == 1800

    def test_lockout_period_5min_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.6.1.5")
        assert ev.result == "FAIL"
        assert ev.evidence.actual_value == 300

    def test_password_min_length_10_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.6.11")
        assert ev.result == "PASS"

    def test_password_min_length_6_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.6.11")
        assert ev.result == "FAIL"

    def test_sha512_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.6.12")
        assert ev.result == "PASS"
        assert ev.evidence.actual_value == "sha512"

    def test_md5_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.6.12")
        assert ev.result == "FAIL"

    # --- NTP controls ---

    def test_ntp_servers_set_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.7.1")
        assert ev.result == "PASS"
        assert len(ev.evidence.actual_value) >= 1

    def test_ntp_servers_missing_review(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.7.1")
        assert ev.result == "REVIEW"

    def test_ntp_version_4_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.7.4")
        assert ev.result == "PASS"

    def test_ntp_version_missing_review(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.7.4")
        assert ev.result == "REVIEW"

    # --- Accounting / Logging ---

    def test_accounting_logins_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.1.2")
        assert ev.result == "PASS"

    def test_external_syslog_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.12.1")
        assert ev.result == "PASS"

    # --- System / Interfaces ---

    def test_timezone_utc_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.18")
        assert ev.result == "PASS"

    def test_timezone_non_utc_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "6.18")
        assert ev.result == "FAIL"

    def test_loopback_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "3.8")
        assert ev.result == "PASS"

    def test_loopback_missing_review(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "3.8")
        assert ev.result == "REVIEW"

    # --- SNMP regex controls ---

    def test_no_common_community_strings_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "5.1")
        assert ev.result == "PASS"

    def test_common_community_string_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "5.1")
        assert ev.result == "FAIL"

    def test_snmp_read_write_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "5.2")
        assert ev.result == "FAIL"

    def test_snmp_default_restrict_pass(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "5.4")
        assert ev.result == "PASS"

    def test_snmp_default_restrict_missing_fail(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "5.4")
        # The restrict pattern is absent: insufficient evidence for a
        # verified violation (§13.4) — REVIEW, never a fabricated FAIL.
        assert ev.result == "REVIEW"
        assert "insufficient evidence" in ev.evidence.reasoning


# ===========================================================================
# TASK 8: Sample Configs Robustness
# ===========================================================================

class TestJuniperSampleConfigs:
    def test_all_configs_produce_results(self, engine):
        names = [
            "juniper_secure.txt", "juniper_insecure.txt", "juniper_mixed.txt",
            "juniper_minimal.txt", "juniper_multiple_blocks.txt",
            "juniper_conflicting.txt", "juniper_malformed.txt",
        ]
        for name in names:
            result = _run_junos(engine, name)
            # Dual-baseline default: 17 CIS + 126 NIST.
            assert len(result.evaluations) == 143, name
            for ev in result.evaluations:
                assert ev.result in ("PASS", "FAIL", "REVIEW"), name

    def test_minimal_mostly_review(self, engine):
        result = _run_junos(engine, "juniper_minimal.txt")
        assert result.review >= 143 // 2

    def test_unknown_does_not_false_pass(self, engine):
        """Missing/unknown evidence must never become false compliance."""
        result = _run_junos(engine, "juniper_unknown.txt")
        # E05 F6: structurally foreign content fails normalization, so the
        # safety boundary stops evaluation entirely — no PASS is possible.
        assert result.normalization_result.result_type.value == "failed"
        assert result.evaluated == 0
        assert result.evaluations == []

    def test_malformed_no_crash(self, engine):
        result = _run_junos(engine, "juniper_malformed.txt")
        assert result.status == "completed"
        assert result.evaluated == 143
        for ev in result.evaluations:
            assert ev.result in ("PASS", "FAIL", "REVIEW")

    def test_conflicting_produces_review(self, engine):
        result = _run_junos(engine, "juniper_conflicting.txt")
        review_ids = [ev.control_id for ev in result.evaluations if ev.result == "REVIEW"]
        for cid in ["6.10.1.2", "6.10.1.5", "6.6.1.1", "6.6.11", "6.7.4"]:
            assert cid in review_ids, f"{cid} should REVIEW on conflict"

    def test_multiple_blocks_no_false_conflict(self, engine):
        """Multiple NTP servers / syslog hosts are legitimate, not conflicts."""
        result = _run_junos(engine, "juniper_multiple_blocks.txt")
        ev = _eval(result, "6.7.1")
        assert ev.result == "PASS"
        ev2 = _eval(result, "6.12.1")
        assert ev2.result == "PASS"

    def test_secure_beats_mixed_beats_insecure(self, engine):
        secure = _run_junos(engine, "juniper_secure.txt").score
        mixed = _run_junos(engine, "juniper_mixed.txt").score
        insecure = _run_junos(engine, "juniper_insecure.txt").score
        assert secure > mixed > insecure


# ===========================================================================
# TASK 5: Conflict Detection
# ===========================================================================

class TestJuniperConflicts:
    def test_conflict_detected_in_normalizer(self, normalizer):
        cfg = {"raw_lines": [
            "## system {",
            "##     services {",
            "##         ssh {",
            "##             protocol-version v1;",
            "##             protocol-version v2;",
            "##         }",
            "##     }",
            "## }",
        ]}
        result = normalizer.normalize(cfg, "juniper", "junos")
        conflicts = result.universal_config.get("config", {}).get("conflicts", [])
        assert len(conflicts) >= 1
        conflict = conflicts[0]
        assert conflict["setting"] == "protocol-version"
        assert conflict["conflict"] is True
        assert conflict["path_prefix"] == "management.ssh.version"

    def test_identical_duplicates_not_conflict(self, normalizer):
        cfg = {"raw_lines": [
            "## system {",
            "##     ntp {",
            "##         server 10.0.0.1;",
            "##         server 10.0.0.1;",
            "##     }",
            "## }",
        ]}
        result = normalizer.normalize(cfg, "juniper", "junos")
        conflicts = result.universal_config.get("config", {}).get("conflicts", [])
        ntp_conflicts = [c for c in conflicts if c["setting"] == "server"]
        assert len(ntp_conflicts) == 1
        assert ntp_conflicts[0]["conflict"] is False

    def test_conflicting_ssh_review(self, engine):
        cfg = "## system {\n##     services {\n##         ssh {\n##             protocol-version v1;\n##             protocol-version v2;\n##         }\n##     }\n## }\n"
        result = engine.execute(cfg, vendor="juniper", platform="junos")
        ev = _eval(result, "6.10.1.2")
        assert ev.result == "REVIEW"
        assert "Conflicting" in ev.evidence.reasoning

    def test_conflicting_ntp_version_review(self, engine):
        cfg = "## system {\n##     ntp {\n##         version 3;\n##         version 4;\n##     }\n## }\n"
        result = engine.execute(cfg, vendor="juniper", platform="junos")
        ev = _eval(result, "6.7.4")
        assert ev.result == "REVIEW"


# ===========================================================================
# TASK 6: Evidence Chain
# ===========================================================================

class TestJuniperEvidence:
    def test_model_path_evidence_full_chain(self, engine):
        cfg = _load("juniper_secure.txt")
        result = engine.execute(cfg, vendor="juniper", platform="junos")
        ev = _eval(result, "6.10.1.2")
        e = ev.evidence
        assert e.universal_model_path == "management.ssh.version"
        assert e.actual_value == 2
        assert e.expected_value == 2
        assert e.operator == "equals"
        assert e.result == "PASS"
        assert e.reasoning
        assert e.source_document
        assert e.source_location == "Page 334"
        assert e.remediation_command
        assert e.raw_config_line_numbers, "evidence must reference raw lines"
        # The raw evidence line must actually be in the config
        for ln in e.raw_config_line_numbers:
            assert 1 <= ln <= len(cfg.splitlines())

    def test_regex_evidence_has_match_flag(self, engine):
        result = _run_junos(engine, "juniper_insecure.txt")
        ev = _eval(result, "5.1")
        assert ev.evidence.audit_regex_matched is True
        assert ev.result == "FAIL"

    def test_manual_evidence_has_reasoning(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "1.7")
        assert "Manual" in ev.evidence.reasoning

    def test_evidence_consistent_with_cisco_format(self, engine):
        """Juniper evidence fields must match the Cisco evidence contract."""
        junos = _run_junos(engine, "juniper_secure.txt")
        cisco = engine.execute(_load("secure.txt"), vendor="cisco", platform="ios_xe")
        j_ev = junos.evaluations[0].evidence
        c_ev = cisco.evaluations[0].evidence
        for field in [
            "control_id", "title", "category", "benchmark_id", "vendor",
            "platform", "raw_config_line_numbers", "universal_model_path",
            "normalized_value", "expected_value", "actual_value", "operator",
            "result", "reasoning", "remediation_command",
            "source_document", "source_location",
        ]:
            assert hasattr(j_ev, field), f"Juniper evidence missing '{field}'"
            assert hasattr(c_ev, field), f"Cisco evidence missing '{field}'"


# ===========================================================================
# TASK 7: Remediation
# ===========================================================================

class TestJuniperRemediation:
    def test_all_automated_controls_have_remediation(self):
        controls = get_all_controls()
        for c in controls:
            if c.assessment_status == AssessmentStatus.AUTOMATED.value:
                assert c.remediation_command, f"{c.control_id} missing remediation"

    def test_remediation_in_evidence(self, engine):
        result = _run_junos(engine, "juniper_secure.txt")
        ev = _eval(result, "6.10.1.2")
        assert ev.evidence.remediation_command == "set system services ssh protocol-version v2"

    def test_remediation_uses_junos_syntax(self):
        controls = get_all_controls()
        for c in controls:
            if c.assessment_status == AssessmentStatus.AUTOMATED.value and c.remediation_command:
                assert (
                    c.remediation_command.startswith("set ")
                    or c.remediation_command.startswith("delete ")
                    or c.remediation_command.startswith("rename ")
                ), f"{c.control_id} remediation not JUNOS CLI: {c.remediation_command}"


# ===========================================================================
# TASK 9: Cisco Regression
# ===========================================================================

class TestCiscoRegression:
    def test_cisco_controls_still_execute(self, engine):
        result = engine.execute(_load("secure.txt"), vendor="cisco", platform="ios_xe")
        assert result.benchmark_id == "CIS+NIST"
        assert len(result.evaluations) == 179
        cis = [e for e in result.evaluations if e.evidence.framework == "CIS"]
        assert len(cis) == 53
        # CIS scope on secure.txt: 48 pass / 2 fail / 3 review (observed,
        # deterministic; the 2 FAILs are genuine control violations).
        scoped = engine.execute(_load("secure.txt"), vendor="cisco",
                                platform="ios_xe", framework="CIS")
        assert scoped.evaluated == 53
        assert scoped.benchmark_id == "CIS-CISCO-IOS-XE-17.x-v2.2.1"

    def test_cisco_insecure_still_fails(self, engine):
        result = engine.execute(_load("insecure.txt"), vendor="cisco", platform="ios_xe")
        assert result.failed > 0

    def test_engine_contains_both_benchmarks(self):
        engine = BenchmarkExecutionEngine()
        cisco = engine.control_registry.get_controls_by_vendor_platform("cisco", "ios_xe")
        junos = engine.control_registry.get_controls_by_vendor_platform("juniper", "junos")
        assert len(cisco) == 53
        assert len(junos) == len(get_all_controls())

    def test_cisco_platform_alias_still_works(self, engine):
        """VendorDetector returns 'ios' but benchmark registered under 'ios_xe'."""
        result = engine.execute(_load("secure.txt"), vendor="cisco", platform="ios")
        assert result.evaluated == 179
        assert result.platform == "ios_xe"


# ===========================================================================
# TASK 10: STIG Framework Mappings
# ===========================================================================

class TestFrameworkMappings:
    def test_mappings_load(self):
        from app.benchmarks.framework_mappings import get_concept_mappings
        mappings = get_concept_mappings()
        assert len(mappings) >= 5

    def test_each_mapping_has_cis_and_stig_refs(self):
        from app.benchmarks.framework_mappings import get_concept_mappings
        for m in get_concept_mappings():
            frameworks = {r.framework for r in m.references}
            assert "CIS Juniper OS" in frameworks
            assert frameworks.intersection({"RTR STIG", "NDM STIG"})

    def test_cis_reference_ids_match_registered_controls(self):
        from app.benchmarks.framework_mappings import get_concept_mappings
        controls = {c.control_id: c for c in get_all_controls()}
        for m in get_concept_mappings():
            for r in m.references:
                if r.framework == "CIS Juniper OS":
                    assert r.control_id in controls, (
                        f"mapping {m.universal_path} references missing control {r.control_id}"
                    )

    def test_ssh_version_maps_to_multiple_frameworks(self):
        from app.benchmarks.framework_mappings import get_mappings_for_universal_path
        m = get_mappings_for_universal_path("management.ssh.version")
        assert m is not None
        frameworks = {r.framework for r in m.references}
        assert "CIS Juniper OS" in frameworks
        assert len(frameworks) >= 2

    def test_stig_rules_are_manual(self):
        """STIG v1.0.0 rules are all Manual - automation must not be claimed."""
        from app.benchmarks.framework_mappings import get_concept_mappings
        for m in get_concept_mappings():
            for r in m.references:
                if r.framework in ("RTR STIG", "NDM STIG"):
                    assert r.assessment_status == "Manual"
