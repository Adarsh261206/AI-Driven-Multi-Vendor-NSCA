"""V3 adversarial matrix A-U (mission adversarial regression).

Each case pins deterministic scope-aware behavior on adversarial
Cisco IOS-XE input. No control-id hacks; all through AuditExecutor.
"""

from __future__ import annotations

import pytest

from app.engines.compliance.executor import AuditExecutor


@pytest.fixture
def ex() -> AuditExecutor:
    return AuditExecutor()


def _run(ex: AuditExecutor, cfg: str):
    r = ex.execute("v3-adv", cfg)
    assert r.status == "completed", f"audit failed: {r.status}"
    return {e.control_id: e for e in r.benchmark_result.evaluations}


BASE = "hostname ADV-V3-01\n!\n"


class TestV3Adversarial:
    def test_a_secure(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n no ip proxy-arp\n")
        assert m["2.1.15"].result == "PASS"

    def test_b_explicit_violation(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n ip proxy-arp\n")
        assert m["2.1.15"].result == "FAIL"

    def test_c_mixed(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n no ip proxy-arp\n"
                  "!\ninterface Gi1/0/2\n ip proxy-arp\n")
        assert m["2.1.15"].result == "FAIL"

    def test_d_conflicting_commands(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n ip proxy-arp\n no ip proxy-arp\n")
        # Last-wins: disabled -> PASS (documented IOS order semantics).
        assert m["2.1.15"].result == "PASS"

    def test_e_reverse_conflict(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n no ip proxy-arp\n ip proxy-arp\n")
        assert m["2.1.15"].result == "FAIL"

    def test_f_comments(self, ex):
        m = _run(ex, BASE + "! ip proxy-arp\ninterface Gi1/0/1\n switchport mode access\n")
        assert m["2.1.15"].result == "REVIEW"

    def test_g_remediation_description(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n description apply no ip proxy-arp fix\n")
        assert m["2.1.15"].result == "REVIEW"

    def test_h_shutdown_no_shutdown(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n shutdown\n no shutdown\n no ip redirects\n")
        assert m["2.1.13"].result == "PASS"

    def test_i_final_shutdown(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n no shutdown\n shutdown\n no ip redirects\n")
        # Shutdown interface excluded; nothing else applicable -> REVIEW.
        assert m["2.1.13"].result == "REVIEW"

    def test_j_secure_range_shutdown(self, ex):
        m = _run(ex, BASE + "interface range Gi1/0/1-10\n no ip redirects\n shutdown\n")
        assert m["2.1.13"].result == "REVIEW"

    def test_k_range_individual_override(self, ex):
        m = _run(ex, BASE + "interface range Gi1/0/1-10\n no ip redirects\n"
                  "!\ninterface Gi1/0/5\n ip redirects\n")
        assert m["2.1.13"].result == "FAIL"

    def test_l_individual_range(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/2\n no ip redirects\n"
                  "!\ninterface range Gi1/0/5-10\n ip redirects\n")
        assert m["2.1.13"].result == "FAIL"

    def test_m_command_ordering(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n ip redirects\n no ip redirects\n")
        assert m["2.1.13"].result == "PASS"

    def test_n_case_whitespace(self, ex):
        m = _run(ex, BASE + "interface   Gi1/0/1\n    NO    IP REDIRECTS\n")
        assert m["2.1.13"].result == "PASS"

    def test_o_trunk(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n switchport mode trunk\n no ip redirects\n")
        assert m["2.1.13"].result == "PASS"

    def test_p_shutdown_range(self, ex):
        m = _run(ex, BASE + "interface range Gi1/0/1-10\n shutdown\n")
        assert m["2.1.13"].result == "REVIEW"

    def test_q_unspecified_interface(self, ex):
        # No interface blocks at all (VTY anchor keeps Cisco detection
        # alive without affecting interface scope).
        m = _run(ex, BASE + "line vty 0 4\n transport input ssh\n")
        assert m["2.1.13"].result == "REVIEW"

    def test_r_noisy_conflicting(self, ex):
        m = _run(ex, BASE + "interface Gi1/0/1\n ip redirects\n ip redirects\n no ip redirects\n ip redirects\n")
        # Last statement wins -> enabled -> FAIL.
        assert m["2.1.13"].result == "FAIL"

    def test_s_svi(self, ex):
        m = _run(ex, BASE + "interface Vlan10\n no ip redirects\n")
        assert m["2.1.13"].result == "PASS"

    def test_t_loopback(self, ex):
        m = _run(ex, BASE + "interface Loopback0\n ip address 10.0.0.1 255.255.255.255\n")
        # Loopback excluded; nothing applicable -> REVIEW.
        assert m["2.1.13"].result == "REVIEW"

    def test_u_comment_only_global(self, ex):
        m = _run(ex, BASE + "! no ip source-route\n")
        assert m["2.1.16"].result == "REVIEW"
