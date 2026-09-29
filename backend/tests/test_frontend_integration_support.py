"""
Phase 11 - Frontend Integration Support Tests

Covers the minimal backend changes made to support the production
frontend console:

- Findings carry real remediation metadata derived from benchmark
  controls (recommended_config, references, confidence).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.engines.compliance.executor import AuditExecutor

SAMPLE_DIR = Path(__file__).parent / "sample_configs"


@pytest.fixture(scope="module")
def executor() -> AuditExecutor:
    return AuditExecutor()


class TestRemediationPopulation:
    def test_failed_findings_have_remediation(self, executor):
        cfg = (SAMPLE_DIR / "insecure.txt").read_text()
        result = executor.execute("test-remediation", cfg)
        assert result.status == "completed"
        assert result.findings

        with_remediation = [f for f in result.findings if f.remediation]
        assert with_remediation, "FAIL/REVIEW findings must carry remediation metadata"

    def test_remediation_has_benchmark_recommended_config(self, executor):
        cfg = (SAMPLE_DIR / "insecure.txt").read_text()
        result = executor.execute("test-remediation", cfg)
        failing = [f for f in result.findings if f.remediation]
        # recommended_config must be a string; most controls carry a command
        assert all(isinstance(f.remediation.get("recommended_config"), str) for f in failing)
        assert any(f.remediation.get("recommended_config") for f in failing)

    def test_remediation_has_source_reference(self, executor):
        cfg = (SAMPLE_DIR / "insecure.txt").read_text()
        result = executor.execute("test-remediation", cfg)
        failing = [f for f in result.findings if f.remediation]
        assert all(f.remediation.get("references") for f in failing)

    def test_remediation_has_vendor_and_platform(self, executor):
        cfg = (SAMPLE_DIR / "insecure.txt").read_text()
        result = executor.execute("test-remediation", cfg)
        failing = [f for f in result.findings if f.remediation]
        assert all(
            f.remediation.get("vendor") == "cisco"
            and f.remediation.get("platform") == "ios_xe"
            for f in failing
        )

    def test_juniper_findings_have_remediation(self, executor):
        cfg = (SAMPLE_DIR / "juniper_insecure.txt").read_text()
        result = executor.execute("test-remediation-junos", cfg)
        assert result.status == "completed"
        with_remediation = [f for f in result.findings if f.remediation]
        assert with_remediation
        # Automated JUNOS controls use set/delete/rename CLI syntax
        # (manual controls like 1.7 use natural-language remediation)
        junos_cli = [
            f for f in with_remediation
            if f.remediation.get("recommended_config", "").strip()
            and f.control_id != "1.7"
        ]
        assert junos_cli
        assert all(
            f.remediation["recommended_config"].startswith(("set ", "delete ", "rename "))
            for f in junos_cli
        )

    def test_secure_config_has_no_findings_with_remediation_gaps(self, executor):
        """PASS findings don't exist; no false remediation."""
        cfg = (SAMPLE_DIR / "secure.txt").read_text()
        result = executor.execute("test-remediation-secure", cfg)
        assert result.status == "completed"
        # Any finding (FAIL/REVIEW) must include remediation metadata
        for f in result.findings:
            assert f.remediation, f"finding {f.control_id} missing remediation"


class TestSeverityNormalization:
    """Findings API returns severity in uppercase (documented contract)."""

    def test_serializer_uppercases_severity(self):
        from app.api.v1.findings import _to_finding_response
        from types import SimpleNamespace

        finding = SimpleNamespace(
            id="00000000-0000-0000-0000-000000000001",
            audit_id=None,
            title="t",
            description="d",
            severity="high",
            confidence=0.9,
            status="open",
            evidence={},
            remediation={},
            affected_device=None,
            affected_vendor=None,
            affected_platform=None,
            compliance_result_id=None,
            created_at=None,
            updated_at=None,
        )
        resp = _to_finding_response(finding)
        assert resp.severity == "HIGH"

    def test_serializer_keeps_uppercase(self):
        from app.api.v1.findings import _to_finding_response
        from types import SimpleNamespace

        finding = SimpleNamespace(
            id="00000000-0000-0000-0000-000000000002",
            audit_id=None,
            title="t",
            description="d",
            severity="CRITICAL",
            confidence=0.9,
            status="open",
            evidence={},
            remediation={},
            affected_device=None,
            affected_vendor=None,
            affected_platform=None,
            compliance_result_id=None,
            created_at=None,
            updated_at=None,
        )
        resp = _to_finding_response(finding)
        assert resp.severity == "CRITICAL"
