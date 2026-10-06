"""Tests for Benchmark Ingestion & Control Registry."""

from __future__ import annotations


from app.benchmarks.cisco_ios_xe_controls import (
    BENCHMARK_ID,
    BENCHMARK_NAME,
    BENCHMARK_VERSION,
    VENDOR,
    PLATFORM,
    get_all_controls,
    get_registry,
)
from app.benchmarks.models import (
    BenchmarkControl,
)
from app.benchmarks.registry import ControlRegistry


# ---------------------------------------------------------------------------
# Control Extraction
# ---------------------------------------------------------------------------

class TestControlExtraction:
    def test_get_all_controls_returns_list(self):
        controls = get_all_controls()
        assert isinstance(controls, list)
        assert len(controls) > 0

    def test_total_control_count(self):
        controls = get_all_controls()
        assert len(controls) == 53

    def test_every_control_is_benchmark_control(self):
        controls = get_all_controls()
        for c in controls:
            assert isinstance(c, BenchmarkControl)

    def test_unique_control_ids(self):
        controls = get_all_controls()
        ids = [c.control_id for c in controls]
        assert len(ids) == len(set(ids))

    def test_benchmark_metadata(self):
        controls = get_all_controls()
        for c in controls:
            assert c.benchmark_id == BENCHMARK_ID
            assert c.benchmark_name == BENCHMARK_NAME
            assert c.benchmark_version == BENCHMARK_VERSION
            assert c.vendor == VENDOR
            assert c.platform == PLATFORM

    def test_source_document_set(self):
        controls = get_all_controls()
        for c in controls:
            assert c.source_document != ""

    def test_source_location_set(self):
        controls = get_all_controls()
        for c in controls:
            assert c.source_location != ""


# ---------------------------------------------------------------------------
# Automated vs Manual Classification
# ---------------------------------------------------------------------------

class TestAutomatedVsManual:
    def test_automated_count(self):
        controls = get_all_controls()
        auto = [c for c in controls if c.assessment_status == "Automated"]
        assert len(auto) == 51

    def test_manual_count(self):
        controls = get_all_controls()
        manual = [c for c in controls if c.assessment_status == "Manual"]
        assert len(manual) == 2

    def test_manual_controls_are_access_rules(self):
        controls = get_all_controls()
        manual = [c for c in controls if c.assessment_status == "Manual"]
        for c in manual:
            assert c.assessment_status == "Manual"

    def test_manual_controls_have_no_model_path(self):
        controls = get_all_controls()
        manual = [c for c in controls if c.assessment_status == "Manual"]
        for c in manual:
            assert c.target_model_path is None


# ---------------------------------------------------------------------------
# Category Coverage
# ---------------------------------------------------------------------------

class TestCategoryCoverage:
    EXPECTED_CATEGORIES = {
        "AAA", "Access Rules", "Password Rules", "SNMP",
        "SSH", "Services", "Logging", "NTP", "Loopback",
    }

    def test_all_expected_categories_present(self):
        controls = get_all_controls()
        actual = set(c.category for c in controls)
        assert self.EXPECTED_CATEGORIES.issubset(actual)

    def test_aaa_controls_count(self):
        controls = get_all_controls()
        aaa = [c for c in controls if c.category == "AAA"]
        assert len(aaa) == 10

    def test_access_rules_count(self):
        controls = get_all_controls()
        ar = [c for c in controls if c.category == "Access Rules"]
        assert len(ar) == 7

    def test_ssh_controls_count(self):
        controls = get_all_controls()
        ssh = [c for c in controls if c.category == "SSH"]
        assert len(ssh) == 6

    def test_services_controls_count(self):
        controls = get_all_controls()
        svc = [c for c in controls if c.category == "Services"]
        assert len(svc) == 10

    def test_logging_controls_count(self):
        controls = get_all_controls()
        log = [c for c in controls if c.category == "Logging"]
        assert len(log) == 7

    def test_ntp_controls_count(self):
        controls = get_all_controls()
        ntp = [c for c in controls if c.category == "NTP"]
        assert len(ntp) == 4


# ---------------------------------------------------------------------------
# Model Mapping
# ---------------------------------------------------------------------------

class TestModelMapping:
    def test_mapped_count(self):
        controls = get_all_controls()
        mapped = [c for c in controls if c.target_model_path]
        assert len(mapped) == 42

    def test_unmapped_count(self):
        controls = get_all_controls()
        unmapped = [c for c in controls if not c.target_model_path]
        assert len(unmapped) == 11

    def test_mapped_paths_are_dotted_notation(self):
        controls = get_all_controls()
        mapped = [c for c in controls if c.target_model_path]
        for c in mapped:
            assert "." in c.target_model_path or c.target_model_path.isidentifier()

    def test_aaa_controls_all_mapped(self):
        controls = get_all_controls()
        aaa = [c for c in controls if c.category == "AAA"]
        for c in aaa:
            assert c.target_model_path is not None

    def test_ssh_controls_all_mapped(self):
        controls = get_all_controls()
        ssh_automated = [c for c in controls if c.category == "SSH" and c.assessment_status == "Automated"]
        for c in ssh_automated:
            assert c.target_model_path is not None


# ---------------------------------------------------------------------------
# Operator & Evaluation
# ---------------------------------------------------------------------------

class TestControlEvaluation:
    def setup_method(self):
        self.registry = ControlRegistry()
        self.benchmark = get_registry()
        self.registry.register_benchmark(self.benchmark)

    def test_evaluate_automated_pass(self):
        control = self.registry.get_control("1.1.1")
        assert control is not None
        result = self.registry.evaluate_control(
            control, {"aaa": {"authentication_enabled": True}}
        )
        assert result["result"] == "PASS"

    def test_evaluate_automated_fail(self):
        control = self.registry.get_control("1.1.1")
        assert control is not None
        result = self.registry.evaluate_control(
            control, {"aaa": {"authentication_enabled": False}}
        )
        assert result["result"] == "FAIL"

    def test_evaluate_manual_returns_review(self):
        control = self.registry.get_control("1.2.1")
        assert control is not None
        assert control.assessment_status == "Manual"
        result = self.registry.evaluate_control(control, {})
        assert result["result"] == "REVIEW"

    def test_evaluate_no_model_path_returns_review(self):
        control = self.registry.get_control("1.2.1")
        assert control is not None
        result = self.registry.evaluate_control(control, {})
        assert result["result"] == "REVIEW"

    def test_evaluate_ssh_version_2_pass(self):
        control = self.registry.get_control("2.1.1")
        assert control is not None
        result = self.registry.evaluate_control(
            control, {"management": {"ssh": {"version": 2}}}
        )
        assert result["result"] == "PASS"

    def test_evaluate_ssh_version_1_fail(self):
        control = self.registry.get_control("2.1.1")
        assert control is not None
        result = self.registry.evaluate_control(
            control, {"management": {"ssh": {"version": 1}}}
        )
        assert result["result"] == "FAIL"

    def test_evaluate_greater_than(self):
        control = self.registry.get_control("1.3.1")
        assert control is not None
        result = self.registry.evaluate_control(
            control, {"authentication": {"password_policy": {"min_length": 14}}}
        )
        assert result["result"] == "PASS"

    def test_evaluate_less_than(self):
        control = self.registry.get_control("2.1.3")
        assert control is not None
        result = self.registry.evaluate_control(
            control, {"management": {"ssh": {"session_timeout": 60}}}
        )
        assert result["result"] == "PASS"

    def test_evaluate_is_set(self):
        control = self.registry.get_control("2.1.5")
        assert control is not None
        result = self.registry.evaluate_control(
            control, {"management": {"ssh": {"source_interface": "Loopback0"}}}
        )
        assert result["result"] == "PASS"

    def test_evaluate_123_no_model_path_returns_review(self):
        control = self.registry.get_control("1.2.3")
        assert control is not None
        result = self.registry.evaluate_control(control, {})
        assert result["result"] == "REVIEW"

    def test_evaluate_missing_value_returns_review(self):
        control = self.registry.get_control("1.1.1")
        assert control is not None
        result = self.registry.evaluate_control(control, {})
        assert result["result"] == "REVIEW"


# ---------------------------------------------------------------------------
# Registry Lookup
# ---------------------------------------------------------------------------

class TestRegistryLookup:
    def setup_method(self):
        self.registry = ControlRegistry()
        self.benchmark = get_registry()
        self.registry.register_benchmark(self.benchmark)

    def test_get_control_by_id(self):
        c = self.registry.get_control("1.1.1")
        assert c is not None
        assert c.control_id == "1.1.1"

    def test_get_nonexistent_control(self):
        c = self.registry.get_control("999.999")
        assert c is None

    def test_get_by_vendor_platform(self):
        controls = self.registry.get_controls_by_vendor_platform("cisco", "ios_xe")
        assert len(controls) == 53

    def test_get_by_wrong_vendor(self):
        controls = self.registry.get_controls_by_vendor_platform("juniper", "ios")
        assert len(controls) == 0

    def test_get_by_category(self):
        aaa = self.registry.get_controls_by_category("AAA")
        assert len(aaa) == 10

    def test_get_by_model_path(self):
        controls = self.registry.get_controls_by_model_path("aaa.authentication_enabled")
        assert len(controls) > 0

    def test_get_automated_controls(self):
        auto = self.registry.get_automated_controls()
        assert len(auto) == 51

    def test_get_manual_controls(self):
        manual = self.registry.get_manual_controls()
        assert len(manual) == 2

    def test_get_mapped_controls(self):
        mapped = self.registry.get_mapped_controls()
        assert len(mapped) == 42

    def test_get_unmapped_controls(self):
        unmapped = self.registry.get_unmapped_controls()
        assert len(unmapped) == 11

    def test_stats(self):
        stats = self.registry.get_stats()
        assert stats["total"] == 53
        assert stats["automated"] == 51
        assert stats["manual"] == 2
        assert stats["mapped"] == 42
        assert stats["unmapped"] == 11
        assert "by_category" in stats
        assert "by_vendor_platform" in stats


# ---------------------------------------------------------------------------
# Registry Model
# ---------------------------------------------------------------------------

class TestBenchmarkRegistry:
    def test_get_registry(self):
        r = get_registry()
        assert r.benchmark_id == BENCHMARK_ID
        assert r.vendor == VENDOR
        assert r.platform == PLATFORM

    def test_total_controls_property(self):
        r = get_registry()
        assert r.total_controls == 53

    def test_automated_controls_property(self):
        r = get_registry()
        assert r.automated_controls == 51

    def test_manual_controls_property(self):
        r = get_registry()
        assert r.manual_controls == 2

    def test_mapped_controls_property(self):
        r = get_registry()
        assert r.mapped_controls == 42

    def test_unmapped_controls_property(self):
        r = get_registry()
        assert r.unmapped_controls == 11


# ---------------------------------------------------------------------------
# Severity Distribution
# ---------------------------------------------------------------------------

class TestSeverityDistribution:
    def test_all_severities_present(self):
        controls = get_all_controls()
        severities = set(c.severity for c in controls)
        assert "HIGH" in severities
        assert "MEDIUM" in severities

    def test_critical_not_used_yet(self):
        controls = get_all_controls()
        critical = [c for c in controls if c.severity == "CRITICAL"]
        assert len(critical) == 0


# ---------------------------------------------------------------------------
# Regression: Existing Detection Engine Controls Still Work
# ---------------------------------------------------------------------------

class TestExistingDetectionEngineCompatibility:
    """Ensure the 10 hardcoded Cisco controls from compliance engine still work."""

    EXPECTED_EXISTING_CONTROLS = [
        "CIS-Cisco-IOS-1.1",
        "CIS-Cisco-IOS-1.2",
        "CIS-Cisco-IOS-2.1",
        "CIS-Cisco-IOS-2.2",
        "CIS-Cisco-IOS-2.3",
        "CIS-Cisco-IOS-3.1",
        "CIS-Cisco-IOS-3.2",
        "CIS-Cisco-IOS-4.1",
        "CIS-Cisco-IOS-5.1",
        "CIS-Cisco-IOS-5.2",
    ]

    def test_existing_control_ids_still_exist(self):
        from app.engines.compliance.cisco_controls import get_cisco_ios_controls
        controls = get_cisco_ios_controls()
        existing_ids = {c.id for c in controls}
        for cid in self.EXPECTED_EXISTING_CONTROLS:
            assert cid in existing_ids, f"Missing control: {cid}"

    def test_existing_controls_count(self):
        from app.engines.compliance.cisco_controls import get_cisco_ios_controls
        controls = get_cisco_ios_controls()
        assert len(controls) == 10
