"""Finding attribution regression tests (Issue #1).

Every finding must carry traceable provenance (hostname/device identity
in evidence + affected_device), so per-device aggregation never invents
"Unattributed" rows for findings whose origin is known.
"""

from __future__ import annotations

import pytest

from app.engines.compliance.executor import AuditExecutor


@pytest.fixture
def executor() -> AuditExecutor:
    return AuditExecutor()


CFG_A = (
    "hostname DEV-A\n!\n"
    "interface GigabitEthernet1/0/1\n ip proxy-arp\n!\n"
    "line vty 0 4\n transport input telnet\n"
)
CFG_B = (
    "hostname DEV-B\n!\n"
    "interface GigabitEthernet1/0/1\n ip redirects\n!\n"
    "line vty 0 4\n transport input ssh\n"
)


def _evidence_of(finding) -> dict:
    ev = finding.evidence
    if isinstance(ev, dict):
        return ev
    if hasattr(ev, "to_dict"):
        return ev.to_dict()
    return {}


class TestSingleDeviceAttribution:
    """Case 1: one configuration -> all findings attributed."""

    def test_evidence_carries_hostname(self, executor):
        r = executor.execute("attr-1", CFG_A)
        assert r.status == "completed"
        assert r.findings, "expected findings"
        for f in r.findings:
            ev = _evidence_of(f)
            assert ev.get("hostname") == "DEV-A", (
                f"finding {f.control_id} evidence lacks hostname: "
                f"{sorted(ev.keys())}")

    def test_evidence_carries_device_type(self, executor):
        r = executor.execute("attr-2", CFG_A)
        for f in r.findings:
            ev = _evidence_of(f)
            assert ev.get("device_type") in (
                "switch", "router", "firewall", "unknown"), (
                f"finding {f.control_id} evidence lacks device_type")


class TestMultiDeviceSeparation:
    """Cases 2+4: two configurations -> findings separated, no leakage."""

    def test_two_configs_separate(self, executor):
        ra = executor.execute("attr-a", CFG_A)
        rb = executor.execute("attr-b", CFG_B)
        hosts_a = {(_evidence_of(f).get("hostname")) for f in ra.findings}
        hosts_b = {(_evidence_of(f).get("hostname")) for f in rb.findings}
        assert hosts_a == {"DEV-A"}, hosts_a
        assert hosts_b == {"DEV-B"}, hosts_b

    def test_no_cross_device_leakage(self, executor):
        ra = executor.execute("attr-a2", CFG_A)
        for f in ra.findings:
            ev = _evidence_of(f)
            assert ev.get("hostname") != "DEV-B", (
                f"finding {f.control_id} leaked across devices")


class TestSameHostnameCollision:
    """Case 3: same hostname in two files -> file/config identity wins."""

    def test_same_hostname_files_distinguished(self, executor):
        cfg1 = CFG_A  # hostname DEV-A
        cfg2 = CFG_A.replace("DEV-A", "DEV-A")  # same hostname
        r1 = executor.execute("attr-same-1", cfg1, device_name="file-one.cfg")
        r2 = executor.execute("attr-same-2", cfg2, device_name="file-two.cfg")
        assert {f.affected_device for f in r1.findings} == {"file-one.cfg"}
        assert {f.affected_device for f in r2.findings} == {"file-two.cfg"}


class TestPersistenceRetrieval:
    """Case 5: persistence + retrieval preserves identity."""

    def test_finding_to_dict_round_trip(self, executor):
        r = executor.execute("attr-persist", CFG_A)
        assert r.findings
        for f in r.findings:
            d = f.to_dict()
            assert d["affected_device"] == f.affected_device
            ev = d["evidence"]
            if isinstance(ev, dict):
                assert ev.get("hostname") == "DEV-A"


class TestReportAggregation:
    """Case 6: report aggregation attributes by evidence identity."""

    def test_aggregation_by_evidence_hostname(self, executor):
        from collections import defaultdict
        r = executor.execute("attr-agg", CFG_A)
        by_host: dict[str, list] = defaultdict(list)
        for f in r.findings:
            ev = _evidence_of(f)
            by_host[ev.get("hostname") or "unknown"].append(f)
        assert set(by_host.keys()) == {"DEV-A"}, set(by_host.keys())
        assert sum(len(v) for v in by_host.values()) == len(r.findings)
