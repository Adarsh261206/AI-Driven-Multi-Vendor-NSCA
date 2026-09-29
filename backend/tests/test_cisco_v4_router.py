"""V4 adversarial router validation — mission tests 1-37.

Fixture: demo-configs/cisco_iosxe_router_v4_adversarial.cfg
Hostname: ADV-RTR-V4-01, vendor=cisco platform=ios_xe.

Expected CIS verdicts are computed from the adversarial content (42 PASS /
6 FAIL / 5 REVIEW), never pinned to game a score. Tests 1-31 cover the
fixture contract, 32-36 cover pipeline properties (parity, determinism,
performance, security, metrics) and 37 is the mutation battery.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from app.benchmarks.execution import BenchmarkExecutionEngine
from app.benchmarks.selection import ComplianceInputError, overall_score
from app.engines.compliance.executor import AuditExecutor
from app.engines.normalization import NormalizationEngine

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "demo-configs"
    / "cisco_iosxe_router_v4_adversarial.cfg"
)

EXPECTED_FAILS = {"1.2.2", "1.2.8", "1.5.2", "2.1.13", "2.1.16", "2.2.6"}
EXPECTED_REVIEWS = {"1.2.1", "1.2.5", "2.1.6", "2.1.12", "2.3.2"}

BANNER_MARKERS = (
    "AUTHORIZED ACCESS ONLY",
    "hint: no lldp run",
    "************************************************************",
)
REMARK_MARKERS = ("Restrict management plane to SSH", "legacy note Loopback0")


def _cis(cfg: str) -> dict:
    """Direct engine run, CIS baseline (53 controls)."""
    result = BenchmarkExecutionEngine().execute(
        cfg, vendor="cisco", platform="ios_xe", framework="CIS"
    )
    assert result.status == "completed"
    return {e.control_id: e for e in result.evaluations}


def _all(cfg: str) -> dict:
    result = BenchmarkExecutionEngine().execute(
        cfg, vendor="cisco", platform="ios_xe", framework=None
    )
    assert result.status == "completed"
    return {e.control_id: e for e in result.evaluations}


def _run_tuple(evaluation) -> tuple:
    ev = evaluation.evidence
    return (
        evaluation.control_id,
        evaluation.result,
        evaluation.confidence,
        ev.evaluation_method,
        ev.actual_value,
        ev.review_code or "",
    )


@pytest.fixture(scope="module")
def cfg_text() -> str:
    return FIXTURE.read_text()


@pytest.fixture(scope="module")
def verdicts(cfg_text) -> dict:
    return _cis(cfg_text)


# ---------------------------------------------------------------------------
# Tests 1-31: fixture-level contract
# ---------------------------------------------------------------------------


class TestFixtureVerdicts:
    def test_01_fixture_loads_and_selects_53_cis_controls(
        self, cfg_text, verdicts
    ):
        assert "hostname ADV-RTR-V4-01" in cfg_text
        assert len(verdicts) == 53

    def test_02_verdict_counts_42_6_5(self, verdicts):
        results = [e.result for e in verdicts.values()]
        assert results.count("PASS") == 42
        assert results.count("FAIL") == 6
        assert results.count("REVIEW") == 5

    def test_03_score_verified_coverage(self, cfg_text):
        result = BenchmarkExecutionEngine().execute(
            cfg_text, vendor="cisco", platform="ios_xe", framework="CIS"
        )
        assert result.score == 79.2
        assert result.verified_rate == 87.5
        assert result.evidence_coverage == 90.6

    def test_04_fail_set_exact(self, verdicts):
        fails = {cid for cid, e in verdicts.items() if e.result == "FAIL"}
        assert fails == EXPECTED_FAILS

    def test_05_review_set_exact(self, verdicts):
        reviews = {cid for cid, e in verdicts.items() if e.result == "REVIEW"}
        assert reviews == EXPECTED_REVIEWS

    def test_06_http_server_last_wins_pass(self, verdicts):
        ev = verdicts["2.1.10"]
        assert ev.result == "PASS"
        assert ev.evidence.evaluation_method == "global_scope"
        assert ev.evidence.actual_value == "no ip http server"

    def test_07_source_route_last_wins_fail_guard(self, verdicts):
        ev = verdicts["2.1.16"]
        assert ev.result == "FAIL"
        assert ev.evidence.evaluation_method == "global_scope"
        assert ev.evidence.actual_value == "ip source-route"

    def test_08_cdp_single_negated_form_pass(self, verdicts):
        assert verdicts["2.1.11"].result == "PASS"

    def test_09_console_level_last_wins_numeric_fail(self, verdicts):
        ev = verdicts["2.2.6"]
        assert ev.result == "FAIL"
        assert ev.evidence.evaluation_method == "exact_structured_match"
        assert ev.evidence.actual_value == 7
        assert "debugging" in (ev.evidence.raw_evidence_snippet or "")

    def test_10_monitor_numeric_severity_pass(self, verdicts):
        ev = verdicts["2.2.7"]
        assert ev.result == "PASS"
        assert ev.evidence.actual_value == 4
        assert "logging monitor 4" in (ev.evidence.raw_evidence_snippet or "")

    def test_11_buffered_numeric_severity_not_rescue(self, verdicts):
        ev = verdicts["2.2.1"]
        assert ev.result == "PASS"
        assert ev.evidence.evaluation_method == "exact_structured_match"
        assert ev.evidence.evaluation_method != "raw_regex_rescue"
        assert ev.evidence.actual_value == 6

    def test_12_trap_level_word_severity_pass(self, verdicts):
        ev = verdicts["2.2.5"]
        assert ev.result == "PASS"
        assert ev.evidence.actual_value == 6

    def test_13_authentication_key_is_not_authenticate(self, verdicts):
        ev = verdicts["2.3.2"]
        assert ev.result == "REVIEW"
        assert ev.evidence.evaluation_method == "review_forced"

    def test_14_trusted_key_dedicated_path(self, verdicts):
        ev = verdicts["2.3.3"]
        assert ev.result == "PASS"
        assert ev.evidence.universal_model_path == "ntp.trusted_key"
        assert ev.evidence.actual_value is True

    def test_15_acl_definition_is_not_vty_application(self, verdicts):
        ev = verdicts["1.2.5"]
        assert ev.result == "REVIEW"
        assert (
            ev.evidence.universal_model_path
            == "access_control.vty_access_class_applied"
        )

    def test_16_remark_and_banner_are_not_evidence(self, verdicts):
        ev = verdicts["2.1.12"]
        assert ev.result == "REVIEW"
        snippet = ev.evidence.raw_evidence_snippet or ""
        assert "remark" not in snippet
        assert "hint:" not in snippet

    def test_17_single_valued_sources_last_wins(self, verdicts):
        for cid in ("2.1.5", "2.2.3", "2.3.4"):
            assert verdicts[cid].result == "PASS", cid
            assert verdicts[cid].evidence.actual_value == "GigabitEthernet0/0/0"

    def test_18_multi_vty_block_any_fail(self, verdicts):
        for cid in ("1.2.2", "1.2.8"):
            ev = verdicts[cid]
            assert ev.result == "FAIL"
            assert ev.evidence.evaluation_method == "multi_block"
            assert ev.evidence.actual_value

    def test_19_snmp_rw_community_fails_others_pass(self, verdicts):
        assert verdicts["1.5.2"].result == "FAIL"
        assert verdicts["1.5.2"].evidence.evaluation_method == (
            "explicit_violation"
        )
        for cid in ("1.5.3", "1.5.4", "1.5.5"):
            assert verdicts[cid].result == "PASS", cid

    def test_20_interface_scope_subinterface_violation_shutdown_excluded(
        self, verdicts
    ):
        ev = verdicts["2.1.13"]
        assert ev.result == "FAIL"
        assert ev.evidence.evaluation_method == "interface_scope"
        assert "GigabitEthernet0/0/0.10" in (
            ev.evidence.raw_evidence_snippet or ""
        )
        assert verdicts["2.1.14"].result == "PASS"
        assert verdicts["2.1.15"].result == "PASS"

    def test_21_ntp_configured_from_effective_server(self, verdicts):
        ev = verdicts["2.3.1"]
        assert ev.result == "PASS"
        assert ev.evidence.actual_value is True

    def test_22_banner_payload_never_appears_in_evidence(self, verdicts):
        for ev in verdicts.values():
            snippet = ev.evidence.raw_evidence_snippet or ""
            for marker in BANNER_MARKERS + REMARK_MARKERS:
                assert marker not in snippet, (ev.control_id, marker)

    def test_23_manual_controls_review(self, verdicts):
        for cid in ("1.2.1", "2.1.6"):
            ev = verdicts[cid]
            assert ev.result == "REVIEW"
            assert ev.evidence.evaluation_method == "manual"

    def test_24_nist_acl_application_controls_pass(self, cfg_text):
        m = _all(cfg_text)
        assert m["AC-4"].result == "PASS"
        assert m["SC-7"].result == "PASS"

    def test_25_root_statements_close_sections(self, cfg_text):
        eng = NormalizationEngine()
        lines = [
            "hostname SEC-01",
            "!",
            "interface GigabitEthernet0/0/1",
            " ip address 10.0.0.1 255.255.255.0",
            " no shutdown",
            "!",
            "ntp server 10.0.0.5",
            "!",
            "line vty 0 4",
            " transport input ssh",
            "!",
            "exec-timeout 99 99",
        ]
        evidence = eng._cisco_evidence(lines)
        ntp = next(e for e in evidence if e.text.startswith("ntp server"))
        assert ntp.section == ()
        root_timeout = next(e for e in evidence if "exec-timeout" in e.text)
        assert root_timeout.section == ()
        # Engine-level: ntp server after an interface block still counts.
        cfg = (
            "hostname SYN-01\n!\n"
            "interface GigabitEthernet0/0/1\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            " no shutdown\n!\n"
            "ntp server 10.0.0.5\n"
        )
        assert _cis(cfg)["2.3.1"].result == "PASS"

    def test_26_aaa_and_http_hardening_set_pass(self, verdicts):
        for cid in (
            "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5",
            "1.1.6", "1.1.7", "1.1.8", "1.1.9", "1.1.10",
            "1.3.1", "1.3.2",
        ):
            assert verdicts[cid].result == "PASS", cid

    def test_27_syslog_host_positive_exact(self, verdicts):
        ev = verdicts["2.2.4"]
        assert ev.result == "PASS"
        assert ev.evidence.evaluation_method == "exact_structured_match"
        assert ev.evidence.actual_value is True

    def test_28_line_timeout_trio_pass(self, verdicts):
        for cid in ("1.2.3", "1.2.6", "1.2.7"):
            assert verdicts[cid].result == "PASS", cid
        assert verdicts["1.2.7"].evidence.actual_value == 300

    def test_29_regex_spot_checks_pass(self, verdicts):
        for cid in ("1.5.6", "2.4.1", "1.3.4", "2.1.7", "2.1.8", "2.1.9"):
            assert verdicts[cid].result == "PASS", cid

    def test_30_evidence_quality_review_codes_and_snippets(self, verdicts):
        for ev in verdicts.values():
            if ev.result == "REVIEW":
                assert (ev.evidence.review_code or "").strip(), ev.control_id
            else:
                assert (ev.evidence.raw_evidence_snippet or "").strip(), (
                    ev.control_id
                )
                assert ev.evidence.evaluation_method, ev.control_id

    def test_31_result_type_universe(self, verdicts):
        allowed = {"PASS", "FAIL", "REVIEW"}
        for ev in verdicts.values():
            assert ev.result in allowed
            assert ev.result != "NOT_APPLICABLE"
            assert ev.evidence.evaluation_method


# ---------------------------------------------------------------------------
# Tests 32-36: pipeline properties
# ---------------------------------------------------------------------------


class TestPipelineProperties:
    def test_32_raw_e04_parity_fixture_and_synthetic(self, cfg_text):
        direct = _cis(cfg_text)
        audit = AuditExecutor().execute("v4-parity", cfg_text)
        assert audit.status == "completed"
        via_audit = {e.control_id: e for e in audit.benchmark_result.evaluations}
        assert set(via_audit) == set(direct)
        for cid in direct:
            assert _run_tuple(direct[cid]) == _run_tuple(via_audit[cid]), cid

        synthetic = (
            "hostname SYN-01\n!\n"
            "interface GigabitEthernet0/0/1\n"
            " ip address 10.0.0.1 255.255.255.0\n"
            " no shutdown\n!\n"
            "ntp server 10.0.0.5\n"
            "!\n"
            "line con 0\n"
            " exec-timeout 5 0\n"
        )
        d2 = _cis(synthetic)
        a2 = AuditExecutor().execute("v4-parity-2", synthetic)
        v2 = {e.control_id: e for e in a2.benchmark_result.evaluations}
        for cid in d2:
            assert _run_tuple(d2[cid]) == _run_tuple(v2[cid]), cid
        assert d2["2.3.1"].result == "PASS"
        assert d2["1.2.7"].result == "PASS"
        assert d2["1.2.7"].evidence.actual_value == 300

    def test_33_determinism_two_runs_identical(self, cfg_text):
        first = BenchmarkExecutionEngine().execute(
            cfg_text, vendor="cisco", platform="ios_xe", framework="CIS"
        )
        second = BenchmarkExecutionEngine().execute(
            cfg_text, vendor="cisco", platform="ios_xe", framework="CIS"
        )
        t1 = [_run_tuple(e) for e in first.evaluations]
        t2 = [_run_tuple(e) for e in second.evaluations]
        assert t1 == t2
        assert first.score == second.score

        audit1 = AuditExecutor().execute("v4-det-1", cfg_text)
        audit2 = AuditExecutor().execute("v4-det-2", cfg_text)
        a1 = [_run_tuple(e) for e in audit1.benchmark_result.evaluations]
        a2 = [_run_tuple(e) for e in audit2.benchmark_result.evaluations]
        assert a1 == a2

    def test_34_performance_full_audit_under_five_seconds(self, cfg_text):
        durations = []
        for i in range(3):
            start = time.monotonic()
            result = BenchmarkExecutionEngine().execute(
                cfg_text, vendor="cisco", platform="ios_xe", framework="CIS"
            )
            durations.append(time.monotonic() - start)
            assert result.status == "completed"
        assert max(durations) < 5.0, durations

    def test_35_security_unsafe_input_rejected(self):
        with pytest.raises(ComplianceInputError):
            BenchmarkExecutionEngine().execute(
                "hostname X\x00\n", vendor="cisco", platform="ios_xe"
            )
        with pytest.raises(ComplianceInputError):
            BenchmarkExecutionEngine().execute(
                "hostname X\x7f\n", vendor="cisco", platform="ios_xe"
            )
        with pytest.raises(ComplianceInputError):
            BenchmarkExecutionEngine().execute(
                None, vendor="cisco", platform="ios_xe"
            )

    def test_36_metrics_internally_consistent(self, cfg_text):
        result = BenchmarkExecutionEngine().execute(
            cfg_text, vendor="cisco", platform="ios_xe", framework="CIS"
        )
        total = result.total_controls
        passed, failed, review = result.passed, result.failed, result.review
        assert passed + failed + review == total
        assert result.score == overall_score(passed, total)
        assert result.verified_rate == round(
            100 * passed / (passed + failed), 1
        )
        assert result.evidence_coverage == round(
            100 * (passed + failed) / total, 1
        )


# ---------------------------------------------------------------------------
# Test 37: mutation battery
# ---------------------------------------------------------------------------


def _drop(text: str, content: str) -> str:
    return (
        "\n".join(
            line for line in text.split("\n") if line.strip() != content
        )
        + "\n"
    )


def _insert_before_end(text: str, line: str) -> str:
    return text.replace("\nend\n", f"\n{line}\nend\n")


class TestMutationBattery:
    def test_37_mutations_produce_expected_verdict_deltas(self, cfg_text):
        base = _cis(cfg_text)
        base_results = {cid: e.result for cid, e in base.items()}
        insert_vty = (
            "line vty 0 4\n exec-timeout 10 0",
            "line vty 0 4\n access-class MGMT-ACL in\n exec-timeout 10 0",
        )
        remove_vty = (
            "line vty 0 4\n exec-timeout 10 0",
            "line vty 0 4\n access-class MGMT-ACL in\n"
            " no access-class MGMT-ACL in\n exec-timeout 10 0",
        )
        late_host = (
            "ip route 10.40.0.0 255.255.0.0 10.30.0.2",
            "ip route 10.40.0.0 255.255.0.0 10.30.0.2\n"
            "no logging host 10.30.0.53",
        )
        cases = [
            (
                "remove_trusted_key_exposes_2_3_3",
                _drop(cfg_text, "ntp trusted-key 9"),
                {"2.3.3": "REVIEW"},
            ),
            (
                "remove_logging_host_is_missing_not_false",
                _drop(cfg_text, "logging host 10.30.0.53"),
                {"2.2.4": "REVIEW"},
            ),
            (
                "remove_interface_access_group_cis_set_unchanged",
                _drop(cfg_text, "ip access-group MGMT-ACL in"),
                {},
            ),
            (
                "add_real_no_lldp_run_passes_2_1_12",
                _insert_before_end(cfg_text, "no lldp run"),
                {"2.1.12": "PASS"},
            ),
            (
                "add_ntp_authenticate_passes_2_3_2",
                _insert_before_end(cfg_text, "ntp authenticate"),
                {"2.3.2": "PASS"},
            ),
            (
                "add_vty_access_class_passes_1_2_5",
                cfg_text.replace(*insert_vty),
                {"1.2.5": "PASS"},
            ),
            (
                "last_console_warnings_cures_2_2_6",
                _insert_before_end(cfg_text, "logging console warnings"),
                {"2.2.6": "PASS"},
            ),
            (
                "last_no_ip_source_route_cures_2_1_16",
                _insert_before_end(cfg_text, "no ip source-route"),
                {"2.1.16": "PASS"},
            ),
            (
                "drop_late_negation_reexposes_2_1_10",
                _drop(cfg_text, "no ip http server"),
                {"2.1.10": "FAIL"},
            ),
            (
                "acl_remark_injection_changes_nothing",
                _insert_before_end(
                    cfg_text, "access-list 99 remark no ip source-route"
                ),
                {},
            ),
            (
                "late_removal_of_syslog_host_reviews_2_2_4",
                cfg_text.replace(*late_host),
                {"2.2.4": "REVIEW"},
            ),
            (
                "access_class_added_then_removed_fails_1_2_5",
                cfg_text.replace(*remove_vty),
                {"1.2.5": "FAIL"},
            ),
            (
                "superseded_rescue_statement_reviews_1_3_4",
                _insert_before_end(cfg_text, "no service password-encryption"),
                {"1.3.4": "REVIEW"},
            ),
        ]
        for name, mutated, expected in cases:
            results = {
                cid: e.result for cid, e in _cis(mutated).items()
            }
            diffs = {
                cid: results[cid]
                for cid in results
                if results[cid] != base_results.get(cid)
            }
            assert diffs == expected, name

        # AC-4/SC-7 follow the interface application event only.
        base_all = _all(cfg_text)
        mutated_all = _all(
            _drop(cfg_text, "ip access-group MGMT-ACL in")
        )
        for cid in ("AC-4", "SC-7"):
            assert base_all[cid].result == "PASS"
            assert mutated_all[cid].result == "REVIEW"
        other = [
            cid
            for cid in mutated_all
            if cid not in ("AC-4", "SC-7")
            and mutated_all[cid].result != base_all[cid].result
        ]
        assert other == []

        # A banner is never evidence, whatever it contains.
        banner_only = (
            "hostname ADV-MIN\n!\n"
            "banner motd ^\n"
            "no ip http server\n"
            "no cdp run\n"
            "no lldp run\n"
            "^\n"
        )
        banner_results = {cid: e.result for cid, e in _cis(banner_only).items()}
        assert banner_results["2.1.10"] == "REVIEW"
        assert banner_results["2.1.11"] == "REVIEW"
        assert banner_results["2.1.12"] == "REVIEW"
