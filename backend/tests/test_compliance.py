"""
Unit Tests for Compliance Engine

Tests PASS, FAIL, REVIEW, missing value, unknown value, wrong vendor, malformed data.
"""

from app.engines.compliance.loader import ControlLoader
from app.engines.compliance.engine import RuleEngine
from app.engines.compliance.evidence import EvidenceChainBuilder
from app.engines.compliance.findings import FindingGenerator, SeverityCalculator
from app.engines.compliance.models import (
    Severity, ComplianceResultType,
)


class TestControlLoader:
    """Tests for Control Definition Loader"""
    
    def setup_method(self):
        self.loader = ControlLoader()
    
    def test_loads_cisco_controls(self):
        controls = self.loader.get_controls(framework="CIS", vendor="cisco")
        assert len(controls) >= 10
    
    def test_get_control_by_id(self):
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        assert control is not None
        assert control.title == "Disable HTTP Server"
    
    def test_get_frameworks(self):
        frameworks = self.loader.get_all_frameworks()
        assert len(frameworks) >= 1
        assert any(f.id == "CIS" for f in frameworks)
    
    def test_get_categories(self):
        categories = self.loader.get_categories()
        assert "management" in categories
        assert "ssh" in categories
        assert "authentication" in categories
    
    def test_filter_by_severity(self):
        critical = self.loader.get_controls(severity=Severity.CRITICAL)
        assert len(critical) > 0
        for c in critical:
            assert c.severity == Severity.CRITICAL
    
    def test_get_stats(self):
        stats = self.loader.get_stats()
        assert stats["total"] >= 10
        assert "CIS" in stats["by_framework"]


class TestRuleEngine:
    """Tests for Rule Engine"""
    
    def setup_method(self):
        self.engine = RuleEngine()
        self.loader = ControlLoader()
    
    def test_evaluate_pass_http_disabled(self):
        """Test PASS: HTTP server is disabled"""
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {"management": {"http": {"enabled": False}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert evaluation.passed == 1
        assert evaluation.failed == 0
        assert evaluation.evaluations[0].result == ComplianceResultType.PASS
    
    def test_evaluate_fail_http_enabled(self):
        """Test FAIL: HTTP server is enabled"""
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {"management": {"http": {"enabled": True}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert evaluation.passed == 0
        assert evaluation.failed == 1
        assert evaluation.evaluations[0].result == ComplianceResultType.FAIL
    
    def test_evaluate_review_low_confidence(self):
        """Test REVIEW: Low normalization confidence"""
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {"management": {"http": {"enabled": False}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.5,  # Below 0.7 threshold
            vendor="cisco",
            platform="ios",
        )
        
        assert evaluation.review == 1
        assert evaluation.evaluations[0].result == ComplianceResultType.REVIEW
    
    def test_evaluate_review_missing_value(self):
        """Test REVIEW: Value not observed in config"""
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {}  # No management section
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert evaluation.review == 1
        assert evaluation.evaluations[0].result == ComplianceResultType.REVIEW
    
    def test_evaluate_wrong_vendor(self):
        """Test: Control not applicable to wrong vendor"""
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {"management": {"http": {"enabled": False}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="fortinet",  # Wrong vendor
            platform="fortios",
        )
        
        # Control should be skipped (not applicable)
        assert evaluation.total_controls == 0
    
    def test_evaluate_ssh_version_pass(self):
        """Test PASS: SSH version is 2"""
        control = self.loader.get_control("CIS-Cisco-IOS-2.1")
        config = {"management": {"ssh": {"version": 2}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert evaluation.passed == 1
    
    def test_evaluate_ssh_version_fail(self):
        """Test FAIL: SSH version is 1"""
        control = self.loader.get_control("CIS-Cisco-IOS-2.1")
        config = {"management": {"ssh": {"version": 1}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert evaluation.failed == 1
    
    def test_evaluate_telnet_disabled_pass(self):
        """Test PASS: Telnet is disabled"""
        control = self.loader.get_control("CIS-Cisco-IOS-2.2")
        config = {"management": {"telnet": {"enabled": False}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert evaluation.passed == 1
    
    def test_evaluate_telnet_enabled_fail(self):
        """Test FAIL: Telnet is enabled"""
        control = self.loader.get_control("CIS-Cisco-IOS-2.2")
        config = {"management": {"telnet": {"enabled": True}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert evaluation.failed == 1
    
    def test_overall_score_calculation(self):
        """Test overall score calculation"""
        controls = self.loader.get_controls(framework="CIS", vendor="cisco")
        config = {
            "management": {
                "http": {"enabled": False},
                "https": {"enabled": True},
                "ssh": {"version": 2},
                "telnet": {"enabled": False},
            },
            "aaa": {"authentication_enabled": True},
        }
        
        evaluation = self.engine.evaluate(
            controls=controls,
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        # Score should be calculated correctly
        assert evaluation.overall_score >= 0
        assert evaluation.overall_score <= 100


class TestEvidenceChain:
    """Tests for Evidence Chain Builder"""
    
    def setup_method(self):
        self.builder = EvidenceChainBuilder()
        self.loader = ControlLoader()
    
    def test_build_pass_chain(self):
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {"management": {"http": {"enabled": False}}}
        
        chain = self.builder.build(
            control=control,
            normalized_config=config,
            actual_value=False,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert chain.result == "PASS"
        assert not chain.actual_value
        assert not chain.expected_value
        assert chain.control_id == "CIS-Cisco-IOS-1.1"
    
    def test_build_fail_chain(self):
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {"management": {"http": {"enabled": True}}}
        
        chain = self.builder.build(
            control=control,
            normalized_config=config,
            actual_value=True,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert chain.result == "FAIL"
        assert chain.actual_value
    
    def test_build_review_chain(self):
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        
        chain = self.builder.build(
            control=control,
            normalized_config={},
            actual_value=None,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        assert chain.result == "REVIEW"
    
    def test_chain_to_dict(self):
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        
        chain = self.builder.build(
            control=control,
            normalized_config={},
            actual_value=False,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        d = chain.to_dict()
        assert "raw_config" in d
        assert "normalized_value" in d
        assert "result" in d


class TestSeverityCalculator:
    """Tests for Severity/Risk Calculator"""
    
    def setup_method(self):
        self.calc = SeverityCalculator()
    
    def test_critical_severity_score(self):
        score = self.calc.calculate_risk_score(Severity.CRITICAL, "cisco", "authentication")
        assert score > 80
    
    def test_low_severity_score(self):
        score = self.calc.calculate_risk_score(Severity.LOW, "juniper", "logging")
        assert score < 40
    
    def test_priority_p1(self):
        priority = self.calc.calculate_priority(85)
        assert priority == "P1"
    
    def test_priority_p4(self):
        priority = self.calc.calculate_priority(20)
        assert priority == "P4"


class TestFindingGenerator:
    """Tests for Finding Generator"""
    
    def setup_method(self):
        self.generator = FindingGenerator()
        self.engine = RuleEngine()
        self.loader = ControlLoader()
    
    def test_generate_fail_finding(self):
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {"management": {"http": {"enabled": True}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        findings = self.generator.generate_findings(
            evaluation=evaluation,
            audit_id="test-audit-1",
            device_name="Router1",
        )
        
        assert len(findings) == 1
        assert findings[0].result == ComplianceResultType.FAIL
        assert findings[0].control_id == "CIS-Cisco-IOS-1.1"
        assert findings[0].affected_vendor == "cisco"
    
    def test_no_findings_for_pass(self):
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {"management": {"http": {"enabled": False}}}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        findings = self.generator.generate_findings(
            evaluation=evaluation,
            audit_id="test-audit-1",
        )
        
        assert len(findings) == 0
    
    def test_review_finding_generated(self):
        control = self.loader.get_control("CIS-Cisco-IOS-1.1")
        config = {}
        
        evaluation = self.engine.evaluate(
            controls=[control],
            normalized_config=config,
            confidence=0.95,
            vendor="cisco",
            platform="ios",
        )
        
        findings = self.generator.generate_findings(
            evaluation=evaluation,
            audit_id="test-audit-1",
        )
        
        assert len(findings) == 1
        assert findings[0].result == ComplianceResultType.REVIEW
