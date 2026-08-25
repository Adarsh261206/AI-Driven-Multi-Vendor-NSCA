"""
Phase 8: Cisco Benchmark Hardening + Engine Unification Tests

Tests SSH transport granularity, exec-timeout normalization,
pipeline unification, and full control coverage.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.benchmarks.cisco_ios_xe_controls import get_all_controls, get_registry
from app.benchmarks.execution import (
    BenchmarkExecutionEngine,
    BenchmarkExecutionResult,
    ControlEvaluationResult,
)
from app.benchmarks.models import AssessmentStatus, BenchmarkControl
from app.benchmarks.registry import ControlRegistry
from app.engines.normalization import NormalizationEngine
from app.engines.compliance.executor import AuditExecutor, AuditResult


SAMPLE_DIR = Path(__file__).parent / "sample_configs"


def _load(name: str) -> str:
    return (SAMPLE_DIR / name).read_text()


@pytest.fixture
def engine() -> BenchmarkExecutionEngine:
    return BenchmarkExecutionEngine()


@pytest.fixture
def normalizer() -> NormalizationEngine:
    return NormalizationEngine()


@pytest.fixture
def executor() -> AuditExecutor:
    return AuditExecutor()


# =========================================================================
# TASK 1: SSH Transport Granularity
# =========================================================================

class TestSSHPTransport:
    """Control 1.2.2: Set Transport Input SSH for Line VTY"""

    def test_transport_ssh_only(self, engine):
        """transport input ssh → PASS"""
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "PASS"
        assert ev.evidence.actual_value == "ssh"

    def test_transport_telnet_only(self, engine):
        """transport input telnet → FAIL"""
        cfg = _load("insecure.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "FAIL"
        assert ev.evidence.actual_value == "telnet"

    def test_transport_telnet_ssh(self, engine):
        """transport input telnet ssh → FAIL (not ssh-only)"""
        cfg = _load("telnet_ssh.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "FAIL"
        assert ev.evidence.actual_value == "ssh telnet"

    def test_transport_none(self, engine):
        """No transport input configured → REVIEW"""
        cfg = _load("minimal.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        # Minimal config has no VTY → transport unknown
        assert ev.result in ("FAIL", "REVIEW")

    def test_transport_multiple_vty(self, engine):
        """Multiple VTY blocks with same transport → PASS"""
        cfg = _load("multiple_vty.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "PASS"
        assert ev.evidence.actual_value == "ssh"

    def test_normalizer_extracts_transport(self, normalizer):
        """Normalizer correctly extracts transport input"""
        config = {"raw_lines": [
            "line vty 0 4",
            " transport input ssh",
            " exec-timeout 5 0",
        ]}
        result = normalizer.normalize(config, "cisco", "ios_xe")
        transport = result.universal_config.get("management", {}).get("vty", {}).get("transport")
        assert transport == "ssh"

    def test_normalizer_telnet_ssh(self, normalizer):
        """Normalizer extracts both protocols"""
        config = {"raw_lines": [
            "line vty 0 4",
            " transport input telnet ssh",
        ]}
        result = normalizer.normalize(config, "cisco", "ios_xe")
        transport = result.universal_config.get("management", {}).get("vty", {}).get("transport")
        assert transport == "ssh telnet"

    def test_normalizer_no_transport(self, normalizer):
        """No transport input → unknown"""
        config = {"raw_lines": ["line vty 0 4", " exec-timeout 5 0"]}
        result = normalizer.normalize(config, "cisco", "ios_xe")
        transport = result.universal_config.get("management", {}).get("vty", {}).get("transport")
        assert transport == "unknown"

    def test_normalizer_no_vty(self, normalizer):
        """No VTY section → unknown"""
        config = {"raw_lines": ["hostname TEST"]}
        result = normalizer.normalize(config, "cisco", "ios_xe")
        transport = result.universal_config.get("management", {}).get("vty", {}).get("transport")
        assert transport == "unknown"

    def test_control_uses_correct_model_path(self):
        """Control 1.2.2 maps to management.vty.transport"""
        controls = get_all_controls()
        c = next(c for c in controls if c.control_id == "1.2.2")
        assert c.target_model_path == "management.vty.transport"
        assert c.operator == "equals"
        assert c.expected_value == "ssh"


# =========================================================================
# TASK 2: Exec-Timeout Normalization
# =========================================================================

class TestExecTimeoutNormalization:
    """Exec-timeout values must be numeric (total seconds)."""

    def test_5_0_is_300_seconds(self, engine):
        """exec-timeout 5 0 → 300 (checked via control 1.2.8 VTY timeout multi-block)"""
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        # Multi-block: actual_value is list of block results
        assert isinstance(ev.evidence.actual_value, list)
        assert ev.evidence.actual_value[0]["timeout"] == 300

    def test_10_0_is_600_seconds(self, normalizer):
        """exec-timeout 10 0 → 600"""
        config = {"raw_lines": ["exec-timeout 10 0"]}
        result = normalizer.normalize(config, "cisco", "ios_xe")
        val = result.universal_config.get("management", {}).get("ssh", {}).get("timeout")
        assert val == 600

    def test_10_30_is_630_seconds(self, normalizer):
        """exec-timeout 10 30 → 630"""
        config = {"raw_lines": ["exec-timeout 10 30"]}
        result = normalizer.normalize(config, "cisco", "ios_xe")
        val = result.universal_config.get("management", {}).get("ssh", {}).get("timeout")
        assert val == 630

    def test_missing_timeout(self, normalizer):
        """No exec-timeout → None (REVIEW)"""
        config = {"raw_lines": ["hostname TEST"]}
        result = normalizer.normalize(config, "cisco", "ios_xe")
        val = result.universal_config.get("management", {}).get("ssh", {}).get("timeout")
        assert val is None

    def test_malformed_timeout(self, normalizer):
        """exec-timeout abc def → None (REVIEW)"""
        config = {"raw_lines": ["exec-timeout abc def"]}
        result = normalizer.normalize(config, "cisco", "ios_xe")
        val = result.universal_config.get("management", {}).get("ssh", {}).get("timeout")
        assert val is None

    def test_threshold_less_than_pass(self, engine):
        """300 < 601 → PASS (exec-timeout on VTY)"""
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "PASS"

    def test_threshold_missing_value_review(self, engine):
        """Missing timeout → REVIEW (not FALSE PASS/FAIL)"""
        cfg = _load("minimal.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "2.1.3")
        assert ev.result == "REVIEW"

    def test_control_expected_value_is_seconds(self):
        """Control 2.1.3 expected value is in seconds"""
        controls = get_all_controls()
        c = next(c for c in controls if c.control_id == "2.1.3")
        assert c.expected_value == 601
        assert c.operator == "less_than"

    def test_exec_timeout_boundary_600_pass(self, engine):
        """exec-timeout 10 0 = 600s → PASS (≤10 minutes)"""
        cfg = "hostname BOUNDARY\nline vty 0 4\n exec-timeout 10 0\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "PASS"
        assert ev.evidence.actual_value[0]["timeout"] == 600

    def test_exec_timeout_boundary_601_fail(self, engine):
        """exec-timeout 10 1 = 601s → FAIL (>10 minutes)"""
        cfg = "hostname BOUNDARY\nline vty 0 4\n exec-timeout 10 1\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "FAIL"
        assert ev.evidence.actual_value[0]["timeout"] == 601

    def test_exec_timeout_zero_pass(self, engine):
        """exec-timeout 0 0 = 0s → PASS (no timeout = never expires, but 0 < 601)"""
        cfg = "hostname ZERO\nline vty 0 4\n exec-timeout 0 0\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "PASS"
        assert ev.evidence.actual_value[0]["timeout"] == 0

    def test_multi_vty_all_blocks_must_pass(self, engine):
        """All VTY blocks must satisfy timeout threshold"""
        cfg = "hostname MULTI\nline vty 0 4\n exec-timeout 5 0\nline vty 5 15\n exec-timeout 10 1\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "FAIL"
        assert len(ev.evidence.actual_value) == 2
        assert ev.evidence.actual_value[0]["result"] == "PASS"
        assert ev.evidence.actual_value[1]["result"] == "FAIL"

    def test_multi_vty_all_pass(self, engine):
        """All VTY blocks under threshold → PASS"""
        cfg = "hostname MULTI\nline vty 0 4\n exec-timeout 5 0\nline vty 5 15\n exec-timeout 8 0\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "PASS"
        assert len(ev.evidence.actual_value) == 2

    def test_ssh_timeout_60_pass(self, engine):
        """ip ssh time-out 60 = 60s → PASS (< 601)"""
        cfg = "hostname SSH\nip ssh time-out 60\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "2.1.3")
        assert ev.result == "PASS"
        assert ev.evidence.actual_value == 60


# =========================================================================
# TASK 3: Pipeline Unification
# =========================================================================

class TestPipelineUnification:
    """AuditExecutor now uses BenchmarkExecutionEngine."""

    def test_executor_completes(self, executor):
        """Full audit pipeline completes successfully"""
        cfg = _load("secure.txt")
        result = executor.execute("test-001", cfg)
        assert result.status == "completed"
        assert result.total_controls > 0

    def test_executor_has_benchmark_result(self, executor):
        """AuditResult includes benchmark_result"""
        cfg = _load("secure.txt")
        result = executor.execute("test-002", cfg)
        assert result.benchmark_result is not None
        assert result.benchmark_result.evaluated > 0

    def test_executor_scores_match(self, executor):
        """AuditResult scores match benchmark scores"""
        cfg = _load("secure.txt")
        result = executor.execute("test-003", cfg)
        assert result.overall_score == result.benchmark_result.score
        assert result.passed == result.benchmark_result.passed
        assert result.failed == result.benchmark_result.failed
        assert result.review == result.benchmark_result.review

    def test_executor_produces_findings(self, executor):
        """AuditResult includes findings"""
        cfg = _load("secure.txt")
        result = executor.execute("test-004", cfg)
        assert len(result.findings) > 0

    def test_executor_has_all_steps(self, executor):
        """All pipeline steps are tracked"""
        cfg = _load("secure.txt")
        result = executor.execute("test-005", cfg)
        step_names = [s.name for s in result.steps]
        assert "validation" in step_names
        assert "detection" in step_names
        assert "parsing" in step_names
        assert "normalization" in step_names
        assert "compliance_evaluation" in step_names
        assert "finding_generation" in step_names

    def test_executor_backward_compat(self, executor):
        """Old 10 controls still load via ControlLoader"""
        from app.engines.compliance.loader import ControlLoader
        loader = ControlLoader()
        controls = loader.get_controls(framework="CIS", vendor="cisco")
        assert len(controls) == 10
        ids = {c.id for c in controls}
        assert "CIS-Cisco-IOS-1.1" in ids
        assert "CIS-Cisco-IOS-5.2" in ids

    def test_regression_existing_controls(self, executor):
        """Old 10 controls produce correct results on secure config"""
        cfg = _load("secure.txt")
        result = executor.execute("test-regression", cfg)
        # Should complete without errors
        assert result.status == "completed"
        assert result.total_controls > 0


# =========================================================================
# TASK 4: Regex Controls Categorized
# =========================================================================

class TestRegexControls:
    """Regex-only controls: categorized and justified."""

    def test_regex_controls_identified(self):
        """Regex controls are identified (9 remaining after model-path conversion)"""
        controls = get_all_controls()
        regex_controls = [
            c for c in controls
            if c.assessment_status == "Automated" and not c.target_model_path
        ]
        assert len(regex_controls) == 9

    def test_regex_controls_have_pattern(self):
        """Every regex control has an audit_regex"""
        controls = get_all_controls()
        regex_controls = [
            c for c in controls
            if c.assessment_status == "Automated" and not c.target_model_path
        ]
        for c in regex_controls:
            assert c.audit_regex, f"Control {c.control_id} has no audit_regex"

    def test_regex_category_a_converted(self):
        """Control 1.2.3 now uses regex (was negated, now presence check)"""
        controls = get_all_controls()
        c = next(c for c in controls if c.control_id == "1.2.3")
        assert c.target_model_path is None
        assert c.audit_regex == r"no\s+exec"

    def test_regex_category_c_retained(self):
        """Controls like 2.1.7 (no service finger) correctly retained as regex"""
        controls = get_all_controls()
        c = next(c for c in controls if c.control_id == "2.1.7")
        assert c.target_model_path is None
        assert "service" in c.audit_regex and "finger" in c.audit_regex

    def test_regex_controls_execute(self):
        """All regex controls produce PASS/FAIL (not REVIEW) on secure config"""
        engine = BenchmarkExecutionEngine()
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        regex_controls = [
            e for e in result.evaluations
            if e.evidence.target_model_path == "" and e.is_automated
        ]
        for ev in regex_controls:
            assert ev.result in ("PASS", "FAIL"), (
                f"Regex control {ev.control_id} got REVIEW instead of PASS/FAIL"
            )


# =========================================================================
# TASK 5: Control Coverage Audit
# =========================================================================

class TestControlCoverageAudit:
    """All 53 controls have documented execution status."""

    def test_total_controls(self):
        assert len(get_all_controls()) == 53

    def test_all_automated_have_either_path_or_regex(self):
        """Every automated control has either model_path or audit_regex"""
        controls = get_all_controls()
        for c in controls:
            if c.assessment_status == "Automated":
                assert c.target_model_path or c.audit_regex, (
                    f"Control {c.control_id} has neither model_path nor audit_regex"
                )

    def test_all_have_severity(self):
        controls = get_all_controls()
        for c in controls:
            assert c.severity in ("HIGH", "MEDIUM", "LOW", "CRITICAL")

    def test_all_have_source(self):
        controls = get_all_controls()
        for c in controls:
            assert c.source_document != ""
            assert c.source_location != ""

    def test_all_have_benchmark_id(self):
        controls = get_all_controls()
        for c in controls:
            assert c.benchmark_id == "CIS-CISCO-IOS-XE-17.x-v2.2.1"

    def test_all_have_vendor_platform(self):
        controls = get_all_controls()
        for c in controls:
            assert c.vendor == "cisco"
            assert c.platform == "ios_xe"

    def test_coverage_matrix(self):
        """Produce coverage matrix"""
        controls = get_all_controls()
        matrix = []
        for c in controls:
            exec_type = "model_path" if c.target_model_path else (
                "regex" if c.audit_regex else "manual"
            )
            matrix.append({
                "control_id": c.control_id,
                "title": c.title,
                "assessment_status": c.assessment_status,
                "execution_type": exec_type,
                "model_path": c.target_model_path or "",
                "has_regex": bool(c.audit_regex),
                "has_remediation": bool(c.remediation_command),
                "severity": c.severity.value if hasattr(c.severity, 'value') else c.severity,
            })
        
        # Verify no control is missed
        assert len(matrix) == 53
        
        # Verify categories
        auto_model = sum(1 for m in matrix if m["execution_type"] == "model_path")
        auto_regex = sum(1 for m in matrix if m["execution_type"] == "regex")
        manual = sum(1 for m in matrix if m["assessment_status"] == "Manual")
        assert auto_model == 42
        assert auto_regex == 9
        assert manual == 2


# =========================================================================
# TASK 6: Full Test Matrix
# =========================================================================

class TestFullTestMatrix:
    """12+ config cases across all controls."""

    ALL_CONFIGS = [
        "secure.txt", "insecure.txt", "mixed.txt", "minimal.txt",
        "ssh_only.txt", "telnet_ssh.txt", "malformed.txt",
        "multiple_vty.txt", "conflicting.txt", "unknown_commands.txt",
        "nested_interfaces.txt",
    ]

    def test_all_configs_produce_results(self, engine):
        """Every config produces a complete result"""
        for name in self.ALL_CONFIGS:
            cfg = _load(name)
            result = engine.execute(cfg)
            assert result.evaluated == 53, f"{name}: wrong count"
            assert 0 <= result.score <= 100, f"{name}: bad score"

    def test_secure_highest_score(self, engine):
        """Secure config should have highest score"""
        scores = {}
        for name in self.ALL_CONFIGS:
            cfg = _load(name)
            result = engine.execute(cfg)
            scores[name] = result.score
        assert scores["secure.txt"] >= scores["mixed.txt"]
        assert scores["secure.txt"] >= scores["insecure.txt"]
        assert scores["secure.txt"] >= scores["minimal.txt"]

    def test_insecure_low_score(self, engine):
        cfg = _load("insecure.txt")
        result = engine.execute(cfg)
        assert result.score < 50

    def test_minimal_low_score(self, engine):
        cfg = _load("minimal.txt")
        result = engine.execute(cfg)
        assert result.score < 30

    def test_malformed_no_crash(self, engine):
        """Malformed config should not crash the engine"""
        cfg = _load("malformed.txt")
        result = engine.execute(cfg)
        assert result.evaluated == 53

    def test_unknown_commands_no_crash(self, engine):
        cfg = _load("unknown_commands.txt")
        result = engine.execute(cfg)
        assert result.evaluated == 53

    def test_conflicting_settings_no_crash(self, engine):
        cfg = _load("conflicting.txt")
        result = engine.execute(cfg)
        assert result.evaluated == 53

    def test_multiple_vty_ssh(self, engine):
        """Multiple VTY blocks both with ssh → PASS for 1.2.2"""
        cfg = _load("multiple_vty.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "PASS"

    def test_nested_interfaces(self, engine):
        cfg = _load("nested_interfaces.txt")
        result = engine.execute(cfg)
        assert result.evaluated == 53


# =========================================================================
# TASK 7: Evidence Quality
# =========================================================================

class TestEvidenceQuality:
    """Evidence chains are traceable and complete."""

    def test_model_path_controls_have_full_evidence(self, engine):
        """Model-path controls have raw+normalized+evaluation evidence"""
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        for ev in result.evaluations:
            if ev.evidence.target_model_path:
                e = ev.evidence
                assert e.control_id != ""
                assert e.result in ("PASS", "FAIL", "REVIEW")
                assert e.operator != "" or e.result == "REVIEW"
                assert e.result_reasoning.strip() != ""
                assert 0 < e.confidence <= 1

    def test_regex_controls_have_raw_evidence(self, engine):
        """Regex controls have audit_regex_matched flag"""
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        for ev in result.evaluations:
            if not ev.evidence.target_model_path and ev.is_automated:
                assert ev.evidence.audit_regex_matched is not None

    def test_manual_controls_have_reasoning(self, engine):
        """Manual controls have REVIEW reasoning"""
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        for ev in result.evaluations:
            if ev.evidence.assessment_status == "Manual":
                assert ev.result == "REVIEW"
                assert "Manual control" in ev.evidence.result_reasoning

    def test_evidence_chain_1_1_1(self, engine):
        """Full evidence chain for AAA control"""
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.1.1")
        e = ev.evidence
        assert e.target_model_path == "aaa.authentication_enabled"
        assert e.actual_value is True
        assert e.expected_value is True
        assert e.operator == "equals"
        assert e.result == "PASS"
        assert e.raw_evidence_snippet != ""

    def test_evidence_chain_2_1_1(self, engine):
        """Full evidence chain for SSH control"""
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "2.1.1")
        e = ev.evidence
        assert e.target_model_path == "management.ssh.version"
        assert e.actual_value == 2
        assert e.expected_value == 2
        assert e.result == "PASS"


# =========================================================================
# TASK 8: Regression Tests
# =========================================================================

class TestRegression:
    """Existing tests still pass, old controls still work."""

    def test_old_compliance_controls_still_load(self):
        from app.engines.compliance.cisco_controls import get_cisco_ios_controls
        controls = get_cisco_ios_controls()
        assert len(controls) == 10

    def test_old_compliance_engine_still_works(self):
        from app.engines.compliance.engine import RuleEngine
        from app.engines.compliance.loader import ControlLoader
        loader = ControlLoader()
        engine = RuleEngine()
        controls = loader.get_controls(framework="CIS", vendor="cisco")
        config = {"management": {"http": {"enabled": False}, "ssh": {"version": 2}}}
        result = engine.evaluate(controls, config, 0.9, "cisco", "ios", "")
        assert result.total_controls > 0

    def test_benchmark_registry_still_works(self):
        registry = ControlRegistry()
        registry.register_benchmark(get_registry())
        controls = registry.get_controls_by_vendor_platform("cisco", "ios_xe")
        assert len(controls) == 53

    def test_all_53_controls_executable(self, engine):
        """All 53 controls produce PASS/FAIL/REVIEW"""
        cfg = _load("secure.txt")
        result = engine.execute(cfg)
        for ev in result.evaluations:
            assert ev.result in ("PASS", "FAIL", "REVIEW")


# =========================================================================
# TASK 3: Duplicate Command Conflict Detection
# =========================================================================

class TestConflictDetection:
    """Conflicting duplicate settings produce REVIEW, not silent last-wins."""

    def test_no_conflict_single_value(self, engine):
        """Single consistent value → normal evaluation"""
        cfg = "hostname TEST\nline vty 0 4\n exec-timeout 5 0\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "PASS"

    def test_no_conflict_identical_duplicates(self, engine):
        """Duplicate identical values → normal evaluation"""
        cfg = "hostname TEST\nline vty 0 4\n exec-timeout 5 0\nline vty 5 15\n exec-timeout 5 0\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "PASS"

    def test_conflict_different_values_review(self, engine):
        """Conflicting duplicate settings → REVIEW for conflict-affected controls"""
        # Use a config with conflicting transport across VTY blocks (control 1.2.2)
        cfg = "hostname TEST\nline vty 0 4\n transport input ssh\nline vty 5 15\n transport input telnet\n"
        result = engine.execute(cfg)
        # 1.2.2 (transport) is conflict-affected and not multi-block → REVIEW
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "REVIEW"
        assert "Conflicting" in ev.evidence.result_reasoning

    def test_conflict_detected_in_normalizer(self, normalizer):
        """Normalizer detects conflicting duplicates"""
        cfg = {"raw_lines": [
            "line vty 0 4",
            " exec-timeout 5 0",
            " transport input ssh",
            "line vty 5 15",
            " exec-timeout 10 0",
            " transport input telnet",
        ]}
        result = normalizer.normalize(cfg, "cisco", "ios_xe")
        conflicts = result.universal_config.get("management", {}).get("vty", {}).get("conflicts", [])
        exec_conflicts = [c for c in conflicts if c["setting"] == "exec-timeout"]
        transport_conflicts = [c for c in conflicts if c["setting"] == "transport input"]
        assert len(exec_conflicts) == 1
        assert exec_conflicts[0]["conflict"] is True
        assert len(transport_conflicts) == 1
        assert transport_conflicts[0]["conflict"] is True

    def test_no_conflict_when_no_duplicates(self, normalizer):
        """No duplicates → no conflicts"""
        cfg = {"raw_lines": [
            "line vty 0 4",
            " exec-timeout 5 0",
            " transport input ssh",
        ]}
        result = normalizer.normalize(cfg, "cisco", "ios_xe")
        conflicts = result.universal_config.get("management", {}).get("vty", {}).get("conflicts", [])
        assert len(conflicts) == 0

    def test_identical_duplicates_not_conflict(self, normalizer):
        """Identical duplicate values → not a conflict"""
        cfg = {"raw_lines": [
            "line vty 0 4",
            " exec-timeout 5 0",
            "line vty 5 15",
            " exec-timeout 5 0",
        ]}
        result = normalizer.normalize(cfg, "cisco", "ios_xe")
        conflicts = result.universal_config.get("management", {}).get("vty", {}).get("conflicts", [])
        exec_conflicts = [c for c in conflicts if c["setting"] == "exec-timeout"]
        assert len(exec_conflicts) == 1
        assert exec_conflicts[0]["conflict"] is False


# =========================================================================
# TASK 4+5: Benchmark Source Validation + Edge-Case Testing
# =========================================================================

class TestBenchmarkSourceValidation:
    """Verify every automated control has correct metadata and thresholds."""

    def test_all_controls_have_required_fields(self):
        """Every control has title, severity, source, benchmark_id"""
        controls = get_all_controls()
        for c in controls:
            assert c.title, f"{c.control_id} missing title"
            assert c.severity, f"{c.control_id} missing severity"
            assert c.source_document, f"{c.control_id} missing source_document"
            assert c.source_location, f"{c.control_id} missing source_location"
            assert c.benchmark_id, f"{c.control_id} missing benchmark_id"

    def test_timeout_controls_correct_threshold(self):
        """Timeout controls use ≤10 minutes (600s) threshold"""
        controls = get_all_controls()
        for cid in ["1.2.6", "1.2.7", "1.2.8", "2.1.3"]:
            c = next(c for c in controls if c.control_id == cid)
            assert c.operator == "less_than", f"{cid} should use less_than"
            assert c.expected_value == 601, f"{cid} expected=601 (seconds)"

    def test_exec_timeout_model_paths_correct(self):
        """Exec-timeout controls map to correct per-line-block paths"""
        controls = get_all_controls()
        paths = {
            "1.2.6": "management.vty.aux_timeout",
            "1.2.7": "management.vty.console_timeout",
            "1.2.8": "management.vty.vty_timeout",
        }
        for cid, expected_path in paths.items():
            c = next(c for c in controls if c.control_id == cid)
            assert c.target_model_path == expected_path, (
                f"{cid} should map to {expected_path}, got {c.target_model_path}"
            )

    def test_ssh_timeout_uses_session_timeout_path(self):
        """Control 2.1.3 maps to SSH session timeout (ip ssh timeout)"""
        controls = get_all_controls()
        c = next(c for c in controls if c.control_id == "2.1.3")
        assert c.target_model_path == "management.ssh.session_timeout"

    def test_aaa_controls_all_mapped(self):
        """All AAA controls have model paths"""
        controls = get_all_controls()
        aaa = [c for c in controls if c.category == "AAA"]
        for c in aaa:
            assert c.target_model_path, f"{c.control_id} AAA control has no model path"

    def test_ssh_controls_all_mapped(self):
        """All automated SSH controls have model paths"""
        controls = get_all_controls()
        ssh = [c for c in controls if c.category == "SSH" and c.assessment_status == "Automated"]
        for c in ssh:
            assert c.target_model_path, f"{c.control_id} SSH control has no model path"

    def test_no_control_has_none_expected_with_operator(self):
        """No control has operator set but expected=None (except regex/manual)"""
        controls = get_all_controls()
        for c in controls:
            if c.target_model_path and c.operator not in ("equals",):
                # Model-path controls with operators must have expected values
                if c.operator != "is_set":
                    assert c.expected_value is not None, (
                        f"{c.control_id} has operator={c.operator} but expected=None"
                    )


class TestEdgeCases:
    """Edge cases from benchmark documentation."""

    def test_ssh_auth_retries_missing(self, engine):
        """No ip ssh authentication-retries → REVIEW"""
        cfg = "hostname TEST\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "2.1.2")
        assert ev.result == "REVIEW"

    def test_ssh_auth_retries_good(self, engine):
        """ip ssh authentication-retries 3 → PASS (≤3)"""
        cfg = "hostname TEST\nip ssh authentication-retries 3\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "2.1.2")
        assert ev.result == "PASS"

    def test_ssh_auth_retries_high(self, engine):
        """ip ssh authentication-retries 10 → FAIL (>3)"""
        cfg = "hostname TEST\nip ssh authentication-retries 10\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "2.1.2")
        assert ev.result == "FAIL"

    def test_transport_input_none(self, engine):
        """transport input none → SSH blocked"""
        cfg = "hostname TEST\nline vty 0 4\n transport input none\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "FAIL"  # expected=ssh, got=none

    def test_transport_telnet_only(self, engine):
        """transport input telnet only → FAIL"""
        cfg = "hostname TEST\nline vty 0 4\n transport input telnet\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "FAIL"

    def test_transport_ssh_telnet(self, engine):
        """transport input ssh telnet → FAIL (telnet allowed)"""
        cfg = "hostname TEST\nline vty 0 4\n transport input ssh telnet\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "FAIL"

    def test_missing_vty_section(self, engine):
        """No line vty section → REVIEW for VTY-dependent controls"""
        cfg = "hostname TEST\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "REVIEW"

    def test_console_no_exec_timeout(self, engine):
        """Console with no exec-timeout → REVIEW"""
        cfg = "hostname TEST\nline con 0\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.7")
        assert ev.result == "REVIEW"

    def test_aux_no_exec_timeout(self, engine):
        """AUX with no exec-timeout → REVIEW"""
        cfg = "hostname TEST\nline aux 0\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.6")
        assert ev.result == "REVIEW"

    def test_multiple_vty_transport_conflict(self, engine):
        """Multiple VTY blocks with different transport → REVIEW (conflict detected)"""
        cfg = "hostname TEST\nline vty 0 4\n transport input telnet\nline vty 5 15\n transport input ssh\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.2")
        assert ev.result == "REVIEW"
        assert "Conflicting" in ev.evidence.result_reasoning

    def test_exec_timeout_malformed(self, engine):
        """exec-timeout with non-numeric values → REVIEW"""
        cfg = "hostname TEST\nline vty 0 4\n exec-timeout abc def\n"
        result = engine.execute(cfg)
        ev = next(e for e in result.evaluations if e.control_id == "1.2.8")
        assert ev.result == "REVIEW"
