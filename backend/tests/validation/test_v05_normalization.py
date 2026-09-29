"""Engine 05 — Universal Security Model / Normalization validation.

Scope: backend/app/engines/normalization.py, backend/app/engines/universal_model.py,
the contract those two have with docs/PROJECT_MASTER_SPEC.md (§10.5 Normalizer,
§11 Universal Security Model, §12.1 Core Data Types) and the way the compliance
pipeline consumes them (app/benchmarks/execution.py, app/engines/compliance/executor.py,
app/api/v1/audit_execution.py, app/ai/validators.py).

Methodology rules for this engine (user-mandated):
  * Detector output is NEVER ground truth. Categories B/C/D feed each mapper only
    content that IS of the vendor that mapper claims to handle.
  * Category G is the separate, explicitly-labelled record of what happens when the
    pipeline hands the normalizer content of a different or unsupported vendor.
  * `status` reports whether the REQUIREMENT is met: FAIL = the defect is present.
    Defect rows therefore assert `assert defect`; conformance rows assert `assert ok`.
  * Model/mapper/control numbers are recomputed from the code on every run; no value
    is copied from a report.
"""

from __future__ import annotations

import ast
import csv
import json
import statistics
import time
from pathlib import Path

import pytest

from app.engines.normalization import (
    NormalizationEngine,
    NormalizationMapping,
    NormalizationResult,
    NormalizationResultType,
)
from app.engines.universal_model import UniversalSecurityModel
from app.benchmarks.registry import ControlRegistry
from app.benchmarks.cisco_ios_xe_controls import get_registry as cisco_registry
from app.benchmarks.juniper_junos_controls import get_registry as junos_registry
from app.benchmarks.nist_sp800_53_controls import get_registry as nist_registry

BACKEND = Path(__file__).resolve().parents[2]
ARTIFACTS = BACKEND / "artifacts" / "engine_validation" / "05_normalization"
SPEC = BACKEND.parent / "docs" / "PROJECT_MASTER_SPEC.md"

# Spec §11.1 Model Structure — paths the specification requires in the model.
SPEC_S11_PATHS = [
    "device.hostname",
    "device.vendor",
    "device.platform",
    "device.firmware_version",
    "management.http.enabled",
    "management.http.port",
    "management.http.secure_only",
    "management.https.enabled",
    "management.https.port",
    "management.https.certificate_valid",
    "management.telnet.enabled",
    "management.ssh.enabled",
    "management.ssh.version",
    "management.ssh.port",
    "management.ssh.key_size",
    "management.ssh.timeout",
    "authentication.password_policy.min_length",
    "authentication.password_policy.complexity",
    "authentication.password_policy.expiration",
    "authentication.password_policy.history",
    "authentication.mfa_enabled",
    "authentication.lockout_policy.max_attempts",
    "authentication.lockout_policy.lockout_duration",
    "aaa.authentication_enabled",
    "aaa.authorization_enabled",
    "aaa.accounting_enabled",
    "aaa.radius_configured",
    "aaa.tacacs_configured",
    "logging.enabled",
    "logging.level",
    "logging.remote_enabled",
    "logging.remote_server",
    "logging.source_interface",
    "ntp.configured",
    "ntp.authenticated",
    "ntp.servers",
    "access_control.acl_applied",
    "access_control.default_action",
    "access_control.rules_count",
    "crypto.ssh_key_size",
    "crypto.https_cert_valid",
    "crypto.snmp_v3_auth",
    "services.snmp.enabled",
    "services.snmp.version",
    "services.snmp.community_string_type",
    "services.dns.configured",
    "services.dhcp.enabled",
    "interfaces.unused_interfaces_shutdown",
    "interfaces.management_interface_identified",
]

# Spec §12.1 NormalizedConfiguration / NormalizedValue members.
SPEC_NORMALIZED_CONFIG_FIELDS = {
    "id",
    "semantic_interpretation_id",
    "universal_model_version",
    "normalized_values",
    "unmapped_concepts",
}
SPEC_NORMALIZED_VALUE_FIELDS = {
    "model_path",
    "value",
    "confidence",
    "source_path",
    "vendor_specific_syntax",
}


def norm(lines, vendor="cisco", platform="ios"):
    return NormalizationEngine().normalize({"raw_lines": lines}, vendor, platform)


def flat(cfg: dict) -> dict:
    out: dict = {}

    def walk(d, prefix=""):
        for k, v in d.items():
            p = f"{prefix}{k}"
            if isinstance(v, dict):
                walk(v, p + ".")
            else:
                out[p] = v

    walk(cfg)
    return out


def get(result: NormalizationResult, path: str):
    return flat(result.universal_config).get(path, "<absent>")


def read(rel: str) -> str:
    return (BACKEND / rel).read_text(encoding="utf-8")


def control_registry() -> ControlRegistry:
    cr = ControlRegistry()
    cr.register_benchmark(cisco_registry())
    cr.register_benchmark(junos_registry())
    cr.register_benchmark(nist_registry())
    return cr


@pytest.fixture(scope="module")
def model() -> UniversalSecurityModel:
    return UniversalSecurityModel()


@pytest.fixture(scope="module")
def model_paths(model) -> set:
    return set(model.get_all_paths())


@pytest.fixture(scope="module")
def model_leaves(model, model_paths) -> set:
    return {p for p in model_paths if not model.get_children(p)}


@pytest.fixture(scope="module")
def mapper_keys() -> dict:
    engine = NormalizationEngine()
    return {
        "cisco": set(engine.vendor_mappers["cisco"]["ios"]),
        "juniper": set(engine.vendor_mappers["juniper"]["junos"]),
        "fortinet": set(engine.vendor_mappers["fortinet"]["fortios"]),
    }


# --------------------------------------------------------------------------
# A. Universal Security Model structure and spec §11 conformance
# --------------------------------------------------------------------------

def test_v05_01_model_loads(recorder, model, model_paths, model_leaves):
    ok = len(model_paths) > 0 and len(model_leaves) > 0
    recorder.add(
        "V05-01", "A", "UniversalSecurityModel loads a non-empty concept hierarchy",
        "UniversalSecurityModel()", "concepts>0 and leaves>0",
        f"concepts={len(model_paths)} leaves={len(model_leaves)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "universal_model.py:6-9 (concepts dict), probe: len(get_all_paths())",
    )
    assert ok


def test_v05_02_spec_s11_paths_present(recorder, model_paths):
    missing = [p for p in SPEC_S11_PATHS if p not in model_paths]
    ok = len(missing) == 0
    recorder.add(
        "V05-02", "A", "Every concept listed in spec §11.1 Model Structure exists in the model",
        f"spec §11.1 list of {len(SPEC_S11_PATHS)} paths",
        "0 missing",
        f"missing={len(missing)} {missing}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: universal_model.py implements the full §11.1 list "
        "(docs/PROJECT_MASTER_SPEC.md:605-696)",
        "",
    )
    assert ok


def test_v05_03_model_has_version_attribute(recorder, model):
    version = getattr(model, "version", None) or getattr(model, "model_version", None)
    import re as _re
    ok = isinstance(version, str) and bool(_re.match(r"^\d+\.\d+\.\d+$", version)) \
        and UniversalSecurityModel.VERSION == version
    recorder.add(
        "V05-03", "A", "The model carries a version identifier as required by spec §11.3",
        "UniversalSecurityModel().version",
        "a single authoritative major.minor.patch version",
        f"version={version!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3/F4: universal_model.py VERSION (spec §11.3); persisted by "
        "audit_execution.py instead of a hard-coded literal",
        "",
    )
    assert ok


def test_v05_04_parent_children_reciprocal(recorder, model, model_paths):
    bad = []
    for path, concept in model.concepts.items():
        for child in concept.children or []:
            child_concept = model.get_concept(child)
            if child_concept is None or child_concept.parent_path != path:
                bad.append((path, child))
        if concept.parent_path and concept.parent_path not in model_paths:
            bad.append((path, f"missing parent {concept.parent_path}"))
    ok = not bad
    recorder.add(
        "V05-04", "A", "Every parent/child relation is reciprocal and points at an existing concept",
        f"{len(model.concepts)} concepts walked", "0 broken relations", f"broken={bad[:5]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "universal_model.py:_add_concept",
    )
    assert ok


def test_v05_05_no_dangling_children(recorder, model, model_paths):
    dangling = [
        c for concept in model.concepts.values()
        for c in (concept.children or []) if c not in model_paths
    ]
    ok = not dangling
    recorder.add(
        "V05-05", "A", "No concept declares a child path that does not exist in the model",
        "children of every concept", "0 dangling children", f"dangling={dangling}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "universal_model.py:_initialize_model",
    )
    assert ok


def test_v05_06_data_type_vocabulary(recorder, model):
    allowed = {"boolean", "enum", "integer", "list", "object", "string"}
    seen = sorted({c.data_type for c in model.concepts.values()})
    ok = set(seen) <= allowed
    recorder.add(
        "V05-06", "A", "Every concept uses a declared data_type vocabulary",
        f"{len(model.concepts)} concepts", f"subset of {sorted(allowed)}",
        f"seen={seen}", "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "universal_model.py:data_type field",
    )
    assert ok


def test_v05_07_concepts_have_name_and_description(recorder, model):
    empty = [p for p, c in model.concepts.items() if not c.name or not c.description]
    ok = not empty
    recorder.add(
        "V05-07", "A", "Every concept has a non-empty name and description",
        f"{len(model.concepts)} concepts", "0 without name/description",
        f"empty={empty}", "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "universal_model.py:name/description fields",
    )
    assert ok


def test_v05_08_model_used_by_production_code(recorder):
    refs = []
    for path in BACKEND.rglob("*.py"):
        if "venv" in path.parts or "__pycache__" in path.parts:
            continue
        if "UniversalSecurityModel" in path.read_text(encoding="utf-8", errors="ignore"):
            refs.append(str(path.relative_to(BACKEND)))
    production = [r for r in refs if not r.startswith("tests") and "_probe" not in r
                   and not r.endswith("universal_model.py")]
    ok = len(production) > 0
    recorder.add(
        "V05-08", "A", "The Universal Security Model is instantiated by production code",
        "repo-wide reference scan for UniversalSecurityModel",
        ">=1 reference outside universal_model.py and tests",
        f"refs={refs}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: normalization.py (mapper registry validation), "
        "audit_execution.py (persisted version), ai/validators.py "
        "(model-backed path validation)",
        "",
    )
    assert ok


def test_v05_09_model_defaults_are_secure_by_default(recorder, model):
    http = model.get_concept("management.http.enabled")
    snmp = model.get_concept("services.snmp.version")
    ok = http is not None and http.default_value is False \
        and snmp is not None and snmp.default_value == 3
    recorder.add(
        "V05-09", "A", "Model defaults encode secure-by-default values",
        "management.http.enabled, services.snmp.version defaults",
        "http default False, snmp default 3",
        f"http={None if http is None else http.default_value} "
        f"snmp={None if snmp is None else snmp.default_value}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "universal_model.py:default_value",
    )
    assert ok


def test_v05_10_get_concept_round_trip(recorder, model, model_paths):
    mismatched = [p for p in model_paths if (c := model.get_concept(p)) is None or c.path != p]
    ok = not mismatched
    recorder.add(
        "V05-10", "A", "get_concept(path) resolves every path the model advertises",
        f"{len(model_paths)} paths", "0 unresolved or mismatched",
        f"bad={mismatched[:5]}", "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "universal_model.py:get_concept/get_all_paths",
    )
    assert ok


# --------------------------------------------------------------------------
# B. Cisco IOS / IOS-XE mapper on Cisco content
# --------------------------------------------------------------------------

def test_v05_11_cisco_hostname(recorder):
    r = norm(["hostname R1"])
    ok = get(r, "device.hostname") == "R1"
    recorder.add(
        "V05-11", "B", "'hostname <name>' is mapped to the normalized hostname",
        "['hostname R1']", "device.hostname=R1", f"device.hostname={get(r, 'device.hostname')!r} "
        f"({r.result_type.value}, {len(r.mappings)} mappings)",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: normalization.py device.hostname (model path, not a root key)",
        "",
    )
    assert ok


def test_v05_12_cisco_http_negation(recorder):
    r = norm(["no ip http server"])
    ok = get(r, "management.http.enabled") is False
    recorder.add(
        "V05-12", "B", "'no ip http server' normalizes to management.http.enabled=False",
        "['no ip http server']", "False",
        f"value={get(r, 'management.http.enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:79 (_is_negated)",
    )
    assert ok


def test_v05_13_cisco_exec_timeout_conversion(recorder):
    a = norm([" exec-timeout 5 0"])
    b = norm([" exec-timeout 10 30"])
    ok = get(a, "management.ssh.timeout") == 300 and get(b, "management.ssh.timeout") == 630
    recorder.add(
        "V05-13", "B", "'exec-timeout <m> <s>' converts to total seconds",
        "[' exec-timeout 5 0'], [' exec-timeout 10 30']", "300 and 630",
        f"5_0={get(a, 'management.ssh.timeout')!r} 10_30={get(b, 'management.ssh.timeout')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:491-515",
    )
    assert ok


def test_v05_14_cisco_vty_transport(recorder):
    r = norm(["line vty 0 4", " transport input ssh telnet", " exec-timeout 5 0"])
    ok = get(r, "management.vty.transport") == "ssh telnet" \
        and get(r, "management.ssh.enabled") is True
    recorder.add(
        "V05-14", "B", "A vty block with 'transport input ssh telnet' normalizes its transport",
        "line vty 0 4 / transport input ssh telnet",
        "management.vty.transport='ssh telnet', ssh.enabled=True",
        f"transport={get(r, 'management.vty.transport')!r} ssh={get(r, 'management.ssh.enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:517-553",
    )
    assert ok


def test_v05_15_cisco_telnet_exposure(recorder):
    r = norm(["line vty 0 4", " transport input ssh telnet", " exec-timeout 5 0"])
    telnet_allows = get(r, "management.vty.transport") == "ssh telnet"
    telnet_enabled = get(r, "management.telnet.enabled") is True
    ok = telnet_allows and telnet_enabled
    recorder.add(
        "V05-15", "B", "A vty block that permits telnet reports management.telnet.enabled=True",
        "line vty 0 4 / transport input ssh telnet",
        "telnet.enabled=True whenever transport permits telnet",
        f"vty.transport={get(r, 'management.vty.transport')!r} "
        f"telnet.enabled={get(r, 'management.telnet.enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F8: normalization.py parses the transport token list",
        "",
    )
    assert ok


def test_v05_16_cisco_ssh_hardening_flags(recorder):
    r = norm(["ip ssh version 2", "ip ssh authentication-retries 3", "ip ssh stricthostkeycheck"])
    ok = get(r, "management.ssh.version") == 2 \
        and get(r, "management.ssh.auth_retries") == 3 \
        and get(r, "management.ssh.strict_host_key_check") is True
    recorder.add(
        "V05-16", "B", "SSH version, auth retries and strict host key check are normalized",
        "ip ssh version 2 / authentication-retries 3 / stricthostkeycheck",
        "2 / 3 / True",
        f"version={get(r, 'management.ssh.version')!r} "
        f"retries={get(r, 'management.ssh.auth_retries')!r} "
        f"strict={get(r, 'management.ssh.strict_host_key_check')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:395-404,463-472,87",
    )
    assert ok


def test_v05_17_cisco_conflict_detection(recorder):
    r = norm([
        "line vty 0 4", " exec-timeout 5 0", " transport input ssh",
        "!",
        "line vty 5 15", " exec-timeout 10 30", " transport input ssh",
    ])
    conflicts = get(r, "config.conflicts")
    timeout_conflict = any(
        c["setting"] == "exec-timeout" and c["conflict"] for c in conflicts
    )
    matching_transport_not_flagged = any(
        c["setting"] == "transport input" and not c["conflict"] for c in conflicts
    )
    ok = timeout_conflict and matching_transport_not_flagged
    recorder.add(
        "V05-17", "B", "Differing exec-timeout across vty blocks is flagged, identical settings are not",
        "two vty blocks: exec-timeout 5 0 vs 10 30, same transport",
        "conflict=True for exec-timeout, conflict=False for transport",
        f"conflicts={conflicts}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05: comment-free evidence blocks; conflicts stay model-shaped "
        "(config.conflicts diagnostic leaf)",
        "",
    )
    assert ok


def test_v05_18_cisco_aaa_flags(recorder):
    r = norm(["aaa authentication login local", "aaa authorization exec local",
              "aaa accounting exec start-stop", "radius-server host 10.0.0.9"])
    ok = get(r, "aaa.authentication_enabled") is True \
        and get(r, "aaa.authorization_enabled") is True \
        and get(r, "aaa.accounting_enabled") is True \
        and get(r, "aaa.radius_configured") is True
    recorder.add(
        "V05-18", "B", "AAA authentication/authorization/accounting and RADIUS are detected",
        "aaa authentication/authorization/accounting + radius-server",
        "all four True",
        f"authn={get(r, 'aaa.authentication_enabled')!r} "
        f"authz={get(r, 'aaa.authorization_enabled')!r} "
        f"acct={get(r, 'aaa.accounting_enabled')!r} "
        f"radius={get(r, 'aaa.radius_configured')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:117-121",
    )
    assert ok


def test_v05_19_cisco_logging_level_and_remote(recorder):
    r = norm(["logging trap debugging", "logging host 10.0.0.5",
              "logging source-interface Loopback0"])
    ok = get(r, "logging.level") == "debugging" \
        and get(r, "monitoring.syslog.severity_level") == 7 \
        and get(r, "logging.remote_enabled") is True \
        and get(r, "monitoring.syslog.source_interface") == "Loopback0"
    recorder.add(
        "V05-19", "B", "logging trap level, remote host and source-interface normalize correctly",
        "logging trap debugging / logging host / logging source-interface",
        "level=debugging, severity=7, remote_enabled=True, source=Loopback0",
        f"level={get(r, 'logging.level')!r} "
        f"severity={get(r, 'monitoring.syslog.severity_level')!r} "
        f"remote={get(r, 'logging.remote_enabled')!r} "
        f"src={get(r, 'monitoring.syslog.source_interface')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "normalization.py:406-423,555-566,125",
    )
    assert ok


def test_v05_20_cisco_ntp_servers_never_extracted(recorder):
    r = norm(["ntp server 1.1.1.1", "ntp server 2.2.2.2", "ntp authentication"])
    configured = get(r, "ntp.configured") is True
    servers = get(r, "ntp.servers")
    ok = configured and servers == ["1.1.1.1", "2.2.2.2"]
    recorder.add(
        "V05-20", "B", "Every 'ntp server <addr>' line appears in ntp.servers",
        "['ntp server 1.1.1.1', 'ntp server 2.2.2.2', 'ntp authentication']",
        "ntp.servers=['1.1.1.1','2.2.2.2']",
        f"configured={configured!r} servers={servers!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F7: normalization.py matches multi-word keys across tokens",
        "",
    )
    assert ok


def test_v05_21_cisco_logging_remote_server_never_extracted(recorder):
    r = norm(["logging host 10.0.0.5"])
    remote_enabled = get(r, "logging.remote_enabled") is True
    remote_server = get(r, "logging.remote_server")
    ok = remote_enabled and remote_server == "10.0.0.5"
    recorder.add(
        "V05-21", "B", "The address in 'logging host <addr>' appears in logging.remote_server",
        "['logging host 10.0.0.5']",
        "logging.remote_server='10.0.0.5'",
        f"remote_enabled={remote_enabled!r} remote_server={remote_server!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F7: normalization.py extracts multi-word keys token-aware",
        "",
    )
    assert ok


def test_v05_22_cisco_snmp_normalized(recorder):
    r = norm(["snmp-server group v3 priv", "snmp-server community public ro"])
    ok = get(r, "services.snmp.version") == 3 \
        and get(r, "services.snmp.community_string_type") == "public" \
        and get(r, "services.snmp.enabled") is True
    recorder.add(
        "V05-22", "B", "SNMPv3 group and community normalize to version/type/enabled",
        "snmp-server group v3 priv + snmp-server community public ro",
        "version=3, community_string_type=public, enabled=True",
        f"version={get(r, 'services.snmp.version')!r} "
        f"type={get(r, 'services.snmp.community_string_type')!r} "
        f"enabled={get(r, 'services.snmp.enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "normalization.py:433-456",
    )
    assert ok


def test_v05_23_cisco_password_policy_types(recorder, model):
    r = norm(["security passwords min-length 15", "password complexity", "password history 5"])
    min_length = get(r, "authentication.password_policy.min_length")
    history = get(r, "authentication.password_policy.history")
    spec_type = model.get_concept("authentication.password_policy.min_length").data_type
    ok = min_length == 15 and isinstance(min_length, int) \
        and history == 5 and isinstance(history, int) and spec_type == "integer"
    recorder.add(
        "V05-23", "B", "Normalized password-policy numbers use the model's declared data_type",
        "['security passwords min-length 15', 'password history 5']",
        f"min_length/history normalized as {spec_type}",
        f"min_length={min_length!r} ({type(min_length).__name__}) "
        f"history={history!r} ({type(history).__name__})",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F13: normalization.py coerces numerics to the model data_type",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# C. Juniper Junos mapper on Junos content
# --------------------------------------------------------------------------

def test_v05_24_junos_hostname_both_syntaxes(recorder):
    flat_r = norm(["set system host-name R1"], "juniper", "junos")
    hier_r = norm(["system {", "    host-name R2;", "}"], "juniper", "junos")
    ok = get(flat_r, "device.hostname") == "R1" and get(hier_r, "device.hostname") == "R2"
    recorder.add(
        "V05-24", "C", "Hostname is extracted from both set-style and hierarchical Junos",
        "set system host-name R1 / system { host-name R2; }",
        "R1 and R2",
        f"flat={get(flat_r, 'device.hostname')!r} hier={get(hier_r, 'device.hostname')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: normalization.py device.hostname (model path)",
        "",
    )
    assert ok


def test_v05_25_junos_time_zone(recorder):
    r = norm(["set system time-zone UTC"], "juniper", "junos")
    ok = get(r, "device.time_zone") == "UTC"
    recorder.add(
        "V05-25", "C", "'set system time-zone UTC' normalizes to device.time_zone",
        "['set system time-zone UTC']", "UTC",
        f"time_zone={get(r, 'device.time_zone')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:1305-1317",
    )
    assert ok


def test_v05_26_junos_ssh_version_and_root_login(recorder):
    r = norm(["set system services ssh protocol-version v2",
              "set system services ssh root-login deny"], "juniper", "junos")
    ok = get(r, "management.ssh.version") == 2 and get(r, "management.ssh.root_login") == "deny"
    recorder.add(
        "V05-26", "C", "SSH protocol-version and root-login normalize to the model",
        "set system services ssh protocol-version v2 / root-login deny",
        "version=2, root_login='deny'",
        f"version={get(r, 'management.ssh.version')!r} "
        f"root_login={get(r, 'management.ssh.root_login')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:1158-1191",
    )
    assert ok


def test_v05_27_junos_password_policy(recorder, model):
    flat_r = norm(["set system login password minimum-length 12",
                   "set system login password format sha512"], "juniper", "junos")
    hier_r = norm(["system {", "    login {", "        password {",
                   "            minimum-length 12;", "            format sha512;",
                   "        }", "    }", "}"], "juniper", "junos")
    spec_type = model.get_concept("authentication.password_policy.min_length").data_type
    ok = get(flat_r, "authentication.password_policy.min_length") == 12 \
        and isinstance(get(flat_r, "authentication.password_policy.min_length"), int) \
        and get(flat_r, "authentication.password_policy.hash_algorithm") == "sha512" \
        and get(hier_r, "authentication.password_policy.min_length") == 12 \
        and get(hier_r, "authentication.password_policy.hash_algorithm") == "sha512" \
        and spec_type == "integer"
    recorder.add(
        "V05-27", "C", "Password minimum-length and hash format normalize in both syntaxes",
        "flat + hierarchical login password statements",
        "min_length=12 (int), hash_algorithm='sha512' in both",
        f"flat=({get(flat_r, 'authentication.password_policy.min_length')!r}, "
        f"{get(flat_r, 'authentication.password_policy.hash_algorithm')!r}) "
        f"hier=({get(hier_r, 'authentication.password_policy.min_length')!r}, "
        f"{get(hier_r, 'authentication.password_policy.hash_algorithm')!r})",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:1193-1246",
    )
    assert ok


def test_v05_28_junos_lockout_policy(recorder):
    r = norm(["set system login retry-options tries-before-disconnect 4",
              "set system login retry-options lockout-period 30"], "juniper", "junos")
    ok = get(r, "authentication.lockout_policy.max_attempts") == 4 \
        and get(r, "authentication.lockout_policy.lockout_duration") == 1800
    recorder.add(
        "V05-28", "C", "Lockout tries and period normalize (minutes converted to seconds)",
        "tries-before-disconnect 4 + lockout-period 30",
        "max_attempts=4, lockout_duration=1800",
        f"max_attempts={get(r, 'authentication.lockout_policy.max_attempts')!r} "
        f"lockout_duration={get(r, 'authentication.lockout_policy.lockout_duration')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:1248-1284",
    )
    assert ok


def test_v05_29_junos_ntp_hierarchical(recorder):
    r = norm(["protocols {", "    ntp {", "        server 1.1.1.1;",
              "        boot-server 2.2.2.2;",
              "        authentication-key 1 {", "            secret \"x\";", "        }",
              "    }", "}"], "juniper", "junos")
    servers = get(r, "ntp.servers")
    ok = get(r, "ntp.configured") is True \
        and servers == ["1.1.1.1"] \
        and get(r, "ntp.authenticated") is True
    recorder.add(
        "V05-29", "C", "Hierarchical NTP configures the section, lists servers, excludes boot-server",
        "protocols { ntp { server; boot-server; authentication-key } }",
        "configured=True, servers=['1.1.1.1'], authenticated=True",
        f"configured={get(r, 'ntp.configured')!r} servers={servers!r} "
        f"authenticated={get(r, 'ntp.authenticated')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:851-865,972+",
    )
    assert ok


def test_v05_30_junos_ntp_set_style_inconsistent(recorder):
    r = norm(["set system ntp server 1.1.1.1", "set system ntp server 2.2.2.2"],
             "juniper", "junos")
    servers = get(r, "ntp.servers")
    configured = get(r, "ntp.configured")
    ok = servers == ["1.1.1.1", "2.2.2.2"] and configured is True
    recorder.add(
        "V05-30", "C", "A set-style NTP configuration marks ntp.configured=True alongside its servers",
        "['set system ntp server 1.1.1.1', 'set system ntp server 2.2.2.2']",
        "configured=True with servers present",
        f"configured={configured!r} servers={servers!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F10: normalization.py treats set-style NTP as section evidence",
        "",
    )
    assert ok


def test_v05_31_junos_syslog_remote_server(recorder):
    r = norm(["system {", "    syslog {", "        host 10.0.0.5 {",
              "            user info;", "        }", "    }", "}"], "juniper", "junos")
    remote_enabled = get(r, "logging.remote_enabled") is True
    remote_server = get(r, "logging.remote_server")
    ok = remote_enabled and remote_server == "10.0.0.5"
    recorder.add(
        "V05-31", "C", "The syslog host address appears in logging.remote_server",
        "system { syslog { host 10.0.0.5 { ... } } }",
        "logging.remote_server='10.0.0.5'",
        f"remote_enabled={remote_enabled!r} remote_server={remote_server!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F7: normalization.py extracts multi-word keys token-aware",
        "",
    )
    assert ok


def test_v05_32_junos_services(recorder):
    r = norm(["system {", "    services {", "        ssh {",
              "            protocol-version v2;", "        }", "        telnet;", "    }",
              "}", "web-management {", "    http;", "}"], "juniper", "junos")
    ok = get(r, "management.ssh.enabled") is True \
        and get(r, "management.telnet.enabled") is True \
        and get(r, "management.http.enabled") is True \
        and get(r, "management.https.enabled") == "<absent>"
    recorder.add(
        "V05-32", "C", "SSH, telnet and web-management http flags normalize correctly",
        "services { ssh; telnet; } + web-management { http; }",
        "ssh=True, telnet=True, http=True, https absent (unobserved)",
        f"ssh={get(r, 'management.ssh.enabled')!r} "
        f"telnet={get(r, 'management.telnet.enabled')!r} "
        f"http={get(r, 'management.http.enabled')!r} "
        f"https={get(r, 'management.https.enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: absence is not materialized; token-aware service flags",
        "",
    )
    assert ok


def test_v05_33_junos_phantom_conflicts(recorder):
    r = norm(["set system login password minimum-length 12",
              "set system login password format sha512"], "juniper", "junos")
    conflicts = get(r, "config.conflicts")
    ok = conflicts == []
    recorder.add(
        "V05-33", "C", "Unrelated set-style statements are not reported as conflicting configuration",
        "two ordinary set lines (minimum-length, format)",
        "config.conflicts=[]",
        f"conflicts={conflicts}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F9: normalization.py groups flat statements by statement path",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# D. Fortinet FortiOS mapper on FortiOS content
# --------------------------------------------------------------------------

def test_v05_34_forti_hostname(recorder):
    r = norm(['config system global', '    set hostname "FGT-01"', "end"],
             "fortinet", "fortios")
    ok = get(r, "device.hostname") == "FGT-01"
    recorder.add(
        "V05-34", "D", "Quoted FortiOS hostname is extracted without quotes",
        'config system global / set hostname "FGT-01"',
        "device.hostname=FGT-01", f"device.hostname={get(r, 'device.hostname')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: normalization.py device.hostname (model path)",
        "",
    )
    assert ok


def test_v05_35_forti_https_only_sets_http(recorder):
    r = norm(["config system interface", '    edit "port1"', "        set allowaccess https",
              "        set status enable", "    next", "end"], "fortinet", "fortios")
    ok = get(r, "management.http.enabled") == "<absent>" \
        and get(r, "management.https.enabled") is True
    recorder.add(
        "V05-35", "D", "An interface that allows only https does not report management.http.enabled",
        "config system interface / set allowaccess https / set status enable",
        "http.enabled absent, https.enabled=True",
        f"http={get(r, 'management.http.enabled')!r} "
        f"https={get(r, 'management.https.enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F2/§12: normalization.py matches whole access tokens",
        "",
    )
    assert ok


def test_v05_36_forti_interface_allowaccess(recorder):
    r = norm(["config system interface", '    edit "port1"',
              "        set allowaccess http ssh https", "        set status enable",
              "    next", "end"], "fortinet", "fortios")
    ok = get(r, "management.http.enabled") is True \
        and get(r, "management.https.enabled") is True \
        and get(r, "management.ssh.enabled") is True \
        and get(r, "management.telnet.enabled") == "<absent>"
    recorder.add(
        "V05-36", "D", "Interface allowaccess flags normalize to the management.* model paths",
        "config system interface / set allowaccess http ssh https / set status enable",
        "http=True, https=True, ssh=True, telnet absent (unobserved)",
        f"http={get(r, 'management.http.enabled')!r} "
        f"https={get(r, 'management.https.enabled')!r} "
        f"ssh={get(r, 'management.ssh.enabled')!r} "
        f"telnet={get(r, 'management.telnet.enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F2: normalization.py token-aware allowaccess extraction",
        "",
    )
    assert ok


def test_v05_37_forti_password_policy_never_extracted(recorder):
    r = norm(["config system password-policy", "    set status enable",
              "    set min-length 10", "    set expire-days 90", "    set history 5",
              "    set complexity enable", "end"], "fortinet", "fortios")
    min_length = get(r, "authentication.password_policy.min_length")
    expiration = get(r, "authentication.password_policy.expiration")
    history = get(r, "authentication.password_policy.history")
    complexity = get(r, "authentication.password_policy.complexity")
    ok = min_length == 10 and isinstance(min_length, int) \
        and expiration == 90 and isinstance(expiration, int) \
        and history == 5 and isinstance(history, int) \
        and complexity is True
    recorder.add(
        "V05-37", "D", "FortiOS password-policy statements normalize to the password_policy model paths",
        "config system password-policy with set min-length/expire-days/history/complexity enable",
        "min_length=10, expiration=90, history=5 (ints), complexity=True",
        f"min_length={min_length!r} expiration={expiration!r} "
        f"history={history!r} complexity={complexity!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F2/F13: normalization.py section-scoped integer extraction",
        "",
    )
    assert ok


def test_v05_38_forti_policy_section_flags(recorder):
    r = norm(["config firewall policy", "    edit 0", '        set name "pol1"', "    next",
              "    edit 1", '        set name "pol2"', "    next", "end"],
             "fortinet", "fortios")
    rules = get(r, "access_control.rules_count")
    acl_applied = get(r, "access_control.acl_applied")
    ok = rules == 2 and acl_applied is True
    recorder.add(
        "V05-38", "D", "A populated 'config firewall policy' section reports acl_applied=True",
        "config firewall policy with two edit blocks",
        "rules_count=2, acl_applied=True",
        f"rules_count={rules!r} acl_applied={acl_applied!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F2: normalization.py section-presence detection",
        "",
    )
    assert ok


def test_v05_39_forti_ntp_section_flag(recorder):
    r = norm(["config system ntp", '    set ntpserver "1.1.1.1"', "    set ntpsync enable",
              "end"], "fortinet", "fortios")
    servers = get(r, "ntp.servers")
    configured = get(r, "ntp.configured")
    ok = servers == ["1.1.1.1"] and configured is True
    recorder.add(
        "V05-39", "D", "A populated 'config system ntp' section reports ntp.configured=True",
        "config system ntp with set ntpserver",
        "configured=True with servers present",
        f"configured={configured!r} servers={servers!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F2: normalization.py section-presence detection",
        "",
    )
    assert ok


def test_v05_40_forti_syslog_remote(recorder):
    r = norm(["config log syslogd setting", "    set status enable",
              "    set server 10.1.1.1", "end"], "fortinet", "fortios")
    remote_enabled = get(r, "logging.remote_enabled")
    remote_server = get(r, "logging.remote_server")
    ok = remote_enabled is True and remote_server == "10.1.1.1"
    recorder.add(
        "V05-40", "D", "An enabled remote syslog target normalizes remote_enabled and remote_server",
        "config log syslogd setting / set status enable / set server 10.1.1.1",
        "remote_enabled=True, remote_server='10.1.1.1'",
        f"remote_enabled={remote_enabled!r} remote_server={remote_server!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F2: normalization.py section-scoped syslog extraction",
        "",
    )
    assert ok


def test_v05_41_forti_aaa_sections(recorder):
    r = norm(["config user local", "    edit admin", "    next", "end",
              "config user group", '    edit "g1"', "    next", "end"],
             "fortinet", "fortios")
    authn = get(r, "aaa.authentication_enabled")
    authz = get(r, "aaa.authorization_enabled")
    ok = authn is True and authz is True
    recorder.add(
        "V05-41", "D", "'config user local' / 'config user group' sections are detected",
        "config user local + config user group",
        "authentication_enabled=True, authorization_enabled=True",
        f"authentication_enabled={authn!r} authorization_enabled={authz!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F2: normalization.py section-presence detection",
        "",
    )
    assert ok


def test_v05_42_forti_snmp_and_log_sections(recorder):
    r = norm(["config system snmp-community", '    edit "public"', "    next", "end",
              "config log setting", "    set status enable", "end"],
             "fortinet", "fortios")
    snmp = get(r, "services.snmp.enabled")
    logging_enabled = get(r, "logging.enabled")
    ok = snmp is True and logging_enabled is True
    recorder.add(
        "V05-42", "D", "'config system snmp-community' and 'config log setting' are detected",
        "config system snmp-community + config log setting",
        "snmp.enabled=True, logging.enabled=True",
        f"snmp.enabled={snmp!r} logging.enabled={logging_enabled!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F2: normalization.py section-presence detection",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# E. NormalizationResult contract vs spec §12.1
# --------------------------------------------------------------------------

def test_v05_43_result_missing_normalized_configuration_fields(recorder):
    fields = set(NormalizationResult.__dataclass_fields__)
    missing = sorted(SPEC_NORMALIZED_CONFIG_FIELDS - fields)
    ok = len(missing) == 0
    recorder.add(
        "V05-43", "E", "NormalizationResult exposes the NormalizedConfiguration members of spec §12.1",
        "dataclass field inspection",
        f"superset of {sorted(SPEC_NORMALIZED_CONFIG_FIELDS)}",
        f"actual={sorted(fields)} missing={missing}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4: normalization.py NormalizationResult envelope "
        "(docs/PROJECT_MASTER_SPEC.md:788-794)",
        "",
    )
    assert ok


def test_v05_44_mapping_missing_normalized_value_fields(recorder):
    fields = set(NormalizationMapping.__dataclass_fields__)
    missing = sorted(SPEC_NORMALIZED_VALUE_FIELDS - fields)
    extra = sorted(fields - SPEC_NORMALIZED_VALUE_FIELDS)
    ok = len(missing) == 0 and len(extra) == 0
    recorder.add(
        "V05-44", "E", "NormalizationMapping exposes the NormalizedValue members of spec §12.1",
        "dataclass field inspection",
        f"exactly {sorted(SPEC_NORMALIZED_VALUE_FIELDS)}",
        f"actual={sorted(fields)} missing={missing} unexpected={extra}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4: normalization.py NormalizationMapping == spec NormalizedValue "
        "(docs/PROJECT_MASTER_SPEC.md:797-803)",
        "",
    )
    assert ok


def test_v05_45_source_path_is_synthetic(recorder):
    r = norm(["hostname R1"])
    host = next((m for m in r.mappings if m.model_path == "device.hostname"), None)
    ok = host is not None and isinstance(host.source_path, list) \
        and host.source_path == ["line:1"] \
        and host.vendor_specific_syntax == "hostname R1"
    recorder.add(
        "V05-45", "E", "source_path points at the originating configuration text (spec §12.1 string[])",
        "['hostname R1'] normalized",
        "source_path ['line:1'] (a string list) with the vendor syntax preserved",
        f"sample={host.to_dict() if host else None}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4: normalization.py carries real source anchors + vendor syntax",
        "",
    )
    assert ok


def test_v05_46_confidence_is_constant(recorder):
    confidences = set()
    for lines, vendor, platform in (
        ([], "cisco", "ios"),
        (["hostname R1"], "cisco", "ios"),
        (["access-list 10 permit host 1.2.3.4"], "cisco", "ios"),
        (["set system host-name R1"], "juniper", "junos"),
    ):
        r = norm(lines, vendor, platform)
        confidences.update(m.confidence for m in r.mappings)
    ok = len(confidences) > 1 and confidences <= {0.95, 0.85, 0.75} \
        and 0.9 not in confidences
    recorder.add(
        "V05-46", "E", "Mapping confidence reflects the evidence behind the mapping",
        "empty, hostname, ACL and Junos inputs",
        "confidence varies by evidence class per the documented policy",
        f"observed confidences={sorted(confidences)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4/§21: normalization.py CONFIDENCE_POLICY "
        "(DIRECT 0.95 / STRUCTURED 0.85 / DERIVED 0.75)",
        "",
    )
    assert ok


def test_v05_47_success_does_not_imply_model_coverage(recorder, model_leaves):
    r = norm([])
    produced = set(flat(r.universal_config))
    missing = sorted(model_leaves - produced)
    fabrications = {
        "management.http.enabled": get(r, "management.http.enabled"),
        "services.snmp.version": get(r, "services.snmp.version"),
    }
    ok = r.result_type == NormalizationResultType.SUCCESS \
        and len(r.mappings) == 3 and r.unmapped_paths == [] \
        and all(v == "<absent>" for v in fabrications.values()) \
        and len(r.unmapped_concepts) > 0 and len(missing) > 0
    recorder.add(
        "V05-47", "E", "An empty configuration normalizes to SUCCESS with zero observed mappings",
        "empty configuration normalized for cisco/ios",
        "SUCCESS, only caller-identity mappings, no observed state, "
        "unmapped concepts recorded",
        f"result_type={r.result_type.value} mappings={len(r.mappings)} "
        f"unmapped_paths={r.unmapped_paths} "
        f"unmapped_concepts={len(r.unmapped_concepts)} "
        f"model_leaves_missing={len(missing)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1/F6/F15: absence is not observed state; SUCCESS with caller "
        "identity only; coverage gaps in unmapped_concepts",
        "",
    )
    assert ok


def test_v05_48_failed_for_unsupported_vendor(recorder):
    r = norm(["hostname X"], "arista", "eos")
    ok = r.result_type == NormalizationResultType.FAILED and r.mappings == [] \
        and r.universal_config == {}
    recorder.add(
        "V05-48", "E", "An unsupported vendor/platform returns result_type=failed with no mappings",
        "vendor='arista', platform='eos'", "failed, 0 mappings, empty config",
        f"result_type={r.result_type.value} mappings={len(r.mappings)} "
        f"config={r.universal_config}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:250-262",
    )
    assert ok


def test_v05_49_partial_only_reported_on_exception(recorder, model_leaves):
    garbage = norm([1, 2, 3])
    empty = norm([])
    empty_missing = sorted(model_leaves - set(flat(empty.universal_config)))
    ok = garbage.result_type == NormalizationResultType.FAILED \
        and garbage.mappings == [] and garbage.universal_config == {} \
        and empty.result_type == NormalizationResultType.SUCCESS \
        and len(empty_missing) > 0 and len(empty.unmapped_concepts) > 0
    recorder.add(
        "V05-49", "E", "Invalid payloads fail deterministically; empty input succeeds with no observations",
        "raw_lines=[1,2,3] and raw_lines=[]",
        "garbage=FAILED with no mappings; empty=SUCCESS with unmapped concepts",
        f"garbage={garbage.result_type.value} mappings={len(garbage.mappings)}; "
        f"empty={empty.result_type.value} unmapped_concepts={len(empty.unmapped_concepts)} "
        f"missing_model_leaves={len(empty_missing)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F6/F15/F17: typed payload validation; coverage gaps in "
        "unmapped_concepts, not in result_type",
        "",
    )
    assert ok


def test_v05_50_to_dict_round_trip(recorder):
    r = norm(["hostname R1"])
    d = r.to_dict()
    expected = {"id", "vendor", "platform", "universal_model_version",
                "semantic_interpretation_id", "universal_config", "mappings",
                "normalized_values", "unmapped_paths", "unmapped_concepts",
                "result_type"}
    ok = set(d) == expected and isinstance(d["mappings"], list) and d["mappings"] and \
        set(d["mappings"][0]) == {"model_path", "value", "confidence",
                                  "source_path", "vendor_specific_syntax"} and \
        d["normalized_values"] == d["mappings"] and \
        d["result_type"] == r.result_type.value and d["id"] == r.id
    recorder.add(
        "V05-50", "E", "to_dict() serializes every field of the result and its mappings",
        "['hostname R1'] normalized", "round-trip dict with all contract fields",
        f"keys={sorted(d)} mapping_keys={sorted(d['mappings'][0])}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4: normalization.py to_dict implements §12.1 shape",
        "",
    )
    assert ok


def test_v05_51_unmapped_paths_populated_on_exception(recorder):
    r = norm([1, 2, 3])
    ok = r.result_type == NormalizationResultType.FAILED and r.mappings == [] \
        and r.universal_config == {}
    recorder.add(
        "V05-51", "E", "Non-string payload content fails deterministically without crashing",
        "raw_lines=[1,2,3]", "FAILED with no mappings and no crash",
        f"result_type={r.result_type.value} unmapped={len(r.unmapped_paths)} "
        f"mappings={len(r.mappings)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F6/F17: payload validation rejects non-string lines "
        "(per-mapper try/except retained as defense in depth)",
        "",
    )
    assert ok


def test_v05_52_input_not_mutated(recorder):
    import copy
    config = {"raw_lines": ["hostname R1", "ip http server"]}
    before = copy.deepcopy(config)
    NormalizationEngine().normalize(config, "cisco", "ios")
    ok = config == before
    recorder.add(
        "V05-52", "E", "normalize() does not mutate the caller's configuration object",
        "{'raw_lines': ['hostname R1', 'ip http server']}",
        "object unchanged after normalization",
        f"unchanged={ok}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:233-302",
    )
    assert ok


# --------------------------------------------------------------------------
# F. Model <-> mapper <-> control registry consistency
# --------------------------------------------------------------------------

def test_v05_53_mapper_paths_exist_in_model(recorder, model_paths, mapper_keys):
    all_keys = set().union(*mapper_keys.values())
    outside = sorted(all_keys - model_paths)
    ok = len(outside) == 0
    recorder.add(
        "V05-53", "F", "Every path a vendor mapper can emit exists in the Universal Security Model",
        f"{sum(len(v) for v in mapper_keys.values())} mapper keys across 3 vendors",
        "0 paths outside the model",
        f"outside={len(outside)} {outside}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: normalization.py mapper dicts vs universal_model.py "
        "(registry validated at engine init)",
        "",
    )
    assert ok


def test_v05_54_every_model_leaf_is_producible(recorder, model_leaves, mapper_keys):
    union = set().union(*mapper_keys.values())
    unproducible = sorted(model_leaves - union)
    ok = len(unproducible) == 0
    recorder.add(
        "V05-54", "F", "Every model leaf can be produced by at least one vendor mapper",
        f"{len(model_leaves)} model leaves",
        "0 leaves no mapper can produce",
        f"unproducible={len(unproducible)} {unproducible}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: normalization.py mapper coverage vs universal_model.py "
        "(unsupported leaves carry documented None-mappers)",
        "",
    )
    assert ok


def _control_paths(vendor, platform):
    controls = control_registry().get_controls_by_vendor_platform(vendor, platform)
    return sorted({
        c.target_model_path for c in controls
        if getattr(c, "target_model_path", None)
    })


def test_v05_55_cisco_control_paths_in_model(recorder, model_paths):
    paths = _control_paths("cisco", "ios_xe")
    outside = sorted(set(paths) - model_paths)
    ok = len(outside) == 0
    recorder.add(
        "V05-55", "F", "Every CIS-Cisco control target path exists in the model",
        f"{len(paths)} distinct control paths", "0 outside the model",
        f"outside={outside}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: universal_model.py defines the session/vty-timeout leaves "
        "the CIS controls reference",
        "",
    )
    assert ok


def test_v05_56_cisco_control_paths_producible(recorder, mapper_keys):
    paths = set(_control_paths("cisco", "ios_xe"))
    not_producible = sorted(paths - mapper_keys["cisco"])
    ok = not not_producible
    recorder.add(
        "V05-56", "F", "Every CIS-Cisco control path can be produced by the Cisco mapper",
        f"{len(paths)} distinct control paths", "0 unproducible",
        f"unproducible={not_producible}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "benchmarks/cisco_ios_xe_controls.py vs normalization.py cisco mapper",
    )
    assert ok


def test_v05_57_junos_control_paths_in_model(recorder, model_paths):
    paths = set(_control_paths("juniper", "junos"))
    outside = sorted(paths - model_paths)
    ok = not outside
    recorder.add(
        "V05-57", "F", "Every Junos control target path exists in the model",
        f"{len(paths)} distinct control paths", "0 outside the model",
        f"outside={outside}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "benchmarks/juniper_junos_controls.py vs universal_model.py",
    )
    assert ok


def test_v05_58_nist_control_paths_in_model(recorder, model_paths):
    paths = set(_control_paths("universal", "network_device"))
    outside = sorted(paths - model_paths)
    ok = len(outside) == 0
    recorder.add(
        "V05-58", "F", "Every NIST control target path exists in the model",
        f"{len(paths)} distinct control paths", "0 outside the model",
        f"outside={outside}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: universal_model.py defines every NIST-referenced leaf",
        "",
    )
    assert ok


def test_v05_59_fortinet_controls_registered(recorder):
    controls = control_registry().get_controls_by_vendor_platform("fortinet", "fortios")
    nist_paths = {c.target_model_path for c in
                  control_registry().get_controls_by_vendor_platform("universal", "network_device")
                  if getattr(c, "target_model_path", None)}
    from app.engines.normalization import NormalizationEngine as _NE
    forti_keys = set(_NE().vendor_mappers["fortinet"]["fortios"])
    reachable = sorted(nist_paths & forti_keys)
    # No FortiOS-specific benchmark module exists (not fabricated here);
    # the documented integration is that FortiOS normalized values reach
    # the vendor-neutral NIST controls evaluated for every audit.
    ok = len(controls) == 0 and len(reachable) > 0
    recorder.add(
        "V05-59", "F", "FortiOS coverage limitation is explicit and FortiOS values reach vendor-neutral controls",
        "ControlRegistry.get_controls_by_vendor_platform('fortinet','fortios')",
        "0 fortios-specific controls (documented limitation); FortiOS mapper "
        "paths overlap NIST control paths",
        f"fortios_controls={len(controls)} nist_reachable={len(reachable)} {reachable[:8]}",
        "PASS" if ok else "FAIL", "DESIGN DECISION",
        "E05 F2/F3: no FortiOS benchmark module exists; the dual-baseline "
        "benchmark path evaluates universal NIST controls against FortiOS "
        "normalized values (see ENGINE_05_FIX_REPORT §45)",
        "",
    )
    assert ok


def test_v05_60_ai_path_validator_ignores_the_model(recorder, model_paths):
    from app.ai.validators import OutputValidator
    validator = OutputValidator()
    in_model = "monitoring.syslog.enabled"
    not_in_model = "management.vty.nonexistent_path"
    accepts_good = validator._validate_model_path(in_model)
    rejects_bad = not validator._validate_model_path(not_in_model)
    ok = accepts_good and rejects_bad and in_model in model_paths \
        and not_in_model not in model_paths
    recorder.add(
        "V05-60", "F", "AI output path validation accepts exactly the paths the model defines",
        f"validate({in_model!r}) and validate({not_in_model!r})",
        "accepts the in-model path, rejects the non-model path",
        f"in_model_accepted={accepts_good} non_model_rejected={rejects_bad}; "
        f"in_model={in_model in model_paths} non_model={not_in_model not in model_paths}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: app/ai/validators.py consults UniversalSecurityModel "
        "(no prefix list)",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# G. Wrong- or unsupported-vendor consequences (separate labelled record)
# --------------------------------------------------------------------------

def test_v05_61_junos_content_through_cisco_mapper(recorder):
    r = norm(["system {", "    host-name J1;", "}"], "cisco", "ios")
    ok = r.result_type == NormalizationResultType.FAILED and r.mappings == []
    recorder.add(
        "V05-61", "G", "Junos content handed to the Cisco mapper is reported as incompatible",
        "vendor='cisco', platform='ios', input is hierarchical Junos",
        "result_type=failed with no mappings",
        f"result_type={r.result_type.value} mappings={len(r.mappings)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3/F6: normalization.py foreign-content coherence check",
        "",
    )
    assert ok


def test_v05_62_cisco_content_through_juniper_mapper(recorder):
    wrong = norm(["hostname C1", "no ip http server"], "juniper", "junos")
    ok = wrong.result_type == NormalizationResultType.FAILED \
        and wrong.mappings == []
    recorder.add(
        "V05-62", "G", "Cisco content handed to the Junos mapper is reported as incompatible",
        "vendor='juniper', platform='junos', input is Cisco IOS",
        "result_type=failed with no mappings",
        f"result_type={wrong.result_type.value} mappings={len(wrong.mappings)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3/F6: normalization.py foreign-content coherence check",
        "",
    )
    assert ok


def test_v05_63_cisco_content_through_fortinet_mapper(recorder):
    wrong = norm(["hostname C1", "no ip http server"], "fortinet", "fortios")
    ok = wrong.result_type == NormalizationResultType.FAILED \
        and wrong.mappings == []
    recorder.add(
        "V05-63", "G", "Cisco content handed to the FortiOS mapper is reported as incompatible",
        "vendor='fortinet', platform='fortios', input is Cisco IOS",
        "result_type=failed with no mappings",
        f"result_type={wrong.result_type.value} mappings={len(wrong.mappings)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3/F6: normalization.py foreign-content coherence check",
        "",
    )
    assert ok


def test_v05_64_unsupported_platform_signals_failure(recorder):
    r = norm(["hostname C1"], "cisco", "nx-os")
    ok = r.result_type == NormalizationResultType.FAILED and r.mappings == []
    recorder.add(
        "V05-64", "G", "An unsupported platform for a supported vendor returns result_type=failed",
        "vendor='cisco', platform='nx-os'", "failed, 0 mappings",
        f"result_type={r.result_type.value} mappings={len(r.mappings)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "normalization.py:250-262",
    )
    assert ok


def test_v05_65_failed_normalization_still_evaluates(recorder):
    from app.benchmarks.execution import BenchmarkExecutionEngine
    result = BenchmarkExecutionEngine().execute(
        "hostname X\n", vendor="arista", platform="eos"
    )
    norm_failed = getattr(result.normalization_result, "result_type", None) == \
        NormalizationResultType.FAILED
    ok = norm_failed and result.evaluated == 0
    recorder.add(
        "V05-65", "G", "A failed normalization stops control evaluation instead of scoring empty state",
        "vendor='arista', platform='eos' through BenchmarkExecutionEngine",
        "no controls evaluated when normalization fails",
        f"normalization={getattr(result.normalization_result, 'result_type', None)!r} "
        f"evaluated={result.evaluated} score={result.score} "
        f"evaluations={len(result.evaluations)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F6: app/benchmarks/execution.py stops on failed normalization",
        "",
    )
    assert ok


def test_v05_66_lookup_is_case_sensitive(recorder):
    r = norm(["hostname C1"], "Cisco", "IOS")
    lower = norm(["hostname C1"], "cisco", "ios")
    ok = r.result_type == NormalizationResultType.SUCCESS \
        and lower.result_type == NormalizationResultType.SUCCESS \
        and r.to_dict() == lower.to_dict()
    recorder.add(
        "V05-66", "G", "Vendor/platform lookup accepts the identifier regardless of letter case",
        "vendor='Cisco', platform='IOS' vs 'cisco','ios'",
        "both normalize identically (canonicalized)",
        f"upper=({r.result_type.value}, {len(r.mappings)}) "
        f"lower=({lower.result_type.value}, {len(lower.mappings)})",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F6: normalization.py canonicalizes vendor/platform before lookup",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# H. Semantic fidelity: normalized state the input does not contain
# --------------------------------------------------------------------------

def test_v05_67_comment_negation_changes_state(recorder):
    r = norm(["! no ip http server"])
    ok = get(r, "management.http.enabled") == "<absent>"
    recorder.add(
        "V05-67", "H", "Commented-out commands do not alter normalized security state",
        "['! no ip http server']", "management.http.enabled absent (no mapping)",
        f"management.http.enabled={get(r, 'management.http.enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: normalization.py classifies vendor comments before extraction",
        "",
    )
    assert ok


def test_v05_68_comment_acl_marks_access_control(recorder):
    r = norm(["! access-list 10 permit host 1.2.3.4"])
    ok = get(r, "access_control.acl_applied") == "<absent>" \
        and get(r, "access_control.rules_count") == 0
    recorder.add(
        "V05-68", "H", "Commented-out access-list lines are not counted as applied ACLs",
        "['! access-list 10 permit host 1.2.3.4']",
        "acl_applied absent, rules_count 0",
        f"acl_applied={get(r, 'access_control.acl_applied')!r} "
        f"rules_count={get(r, 'access_control.rules_count')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1/F12: comments never enter evidence; only ACL syntax counts",
        "",
    )
    assert ok


def test_v05_69_comment_ntp_marks_configured(recorder):
    r = norm(["! ntp server 1.1.1.1"])
    ok = get(r, "ntp.configured") == "<absent>" \
        and get(r, "ntp.servers") == "<absent>"
    recorder.add(
        "V05-69", "H", "Commented-out NTP lines do not mark the device as NTP-configured",
        "['! ntp server 1.1.1.1']", "ntp.configured and ntp.servers absent",
        f"ntp.configured={get(r, 'ntp.configured')!r} "
        f"ntp.servers={get(r, 'ntp.servers')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: normalization.py classifies vendor comments before extraction",
        "",
    )
    assert ok


def test_v05_70_comment_logging_marks_remote(recorder):
    r = norm(["! logging host 10.0.0.5"])
    ok = get(r, "logging.remote_enabled") == "<absent>" \
        and get(r, "monitoring.syslog.enabled") == "<absent>"
    recorder.add(
        "V05-70", "H", "Commented-out 'logging host' does not enable remote logging",
        "['! logging host 10.0.0.5']",
        "logging.remote_enabled and syslog.enabled absent",
        f"logging.remote_enabled={get(r, 'logging.remote_enabled')!r} "
        f"monitoring.syslog.enabled={get(r, 'monitoring.syslog.enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: normalization.py classifies vendor comments before extraction",
        "",
    )
    assert ok


def test_v05_71_empty_config_fabricates_definite_state(recorder):
    r = norm([])
    fabrications = {
        "management.http.enabled": get(r, "management.http.enabled"),
        "services.snmp.version": get(r, "services.snmp.version"),
        "services.snmp.community_string_type": get(r, "services.snmp.community_string_type"),
        "management.ssh.port": get(r, "management.ssh.port"),
        "management.telnet.port": get(r, "management.telnet.port"),
        "interfaces.management_interface_identified":
            get(r, "interfaces.management_interface_identified"),
        "management.vty.transport": get(r, "management.vty.transport"),
        "logging.level": get(r, "logging.level"),
    }
    ok = r.result_type == NormalizationResultType.SUCCESS and all(
        v == "<absent>" for v in fabrications.values()
    )
    recorder.add(
        "V05-71", "H", "Absent configuration is not reported as definite observed state",
        "raw_lines=[]", "no values asserted for configuration that is not present",
        f"result_type={r.result_type.value} fabrications={fabrications}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: normalization.py emits values only where the input provides "
        "evidence (no materialized constants/defaults)",
        "",
    )
    assert ok


def test_v05_72_empty_config_satisfies_is_set_controls(recorder):
    controls = control_registry().get_controls_by_vendor_platform("cisco", "ios_xe") \
        + control_registry().get_controls_by_vendor_platform("juniper", "junos") \
        + control_registry().get_controls_by_vendor_platform("universal", "network_device")
    r = norm([])
    present = set(flat(r.universal_config))
    is_set_paths = {
        c.target_model_path for c in controls
        if getattr(c, "operator", None) == "is_set"
        and getattr(c, "target_model_path", None)
    }
    satisfied = sorted(is_set_paths & present)
    ok = len(satisfied) == 0
    recorder.add(
        "V05-72", "H", "An empty configuration satisfies no control",
        "raw_lines=[] evaluated against every is_set control path",
        "0 is_set paths present in the empty normalization",
        f"is_set_paths={len(is_set_paths)} satisfied={len(satisfied)} {satisfied[:6]}; "
        f"empty normalization carries no observed values",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: absent settings return None (never materialized), so is_set "
        "controls cannot be satisfied by emptiness",
        "",
    )
    assert ok


def test_v05_73_empty_config_snmp_version_conflicts_with_model(recorder, model):
    r = norm([])
    observed = get(r, "services.snmp.version")
    default = model.get_concept("services.snmp.version").default_value
    ok = observed == "<absent>"
    recorder.add(
        "V05-73", "H", "SNMP version on an absent configuration matches the model default",
        "raw_lines=[]", f"services.snmp.version absent (model default {default} lives in the model)",
        f"observed={observed!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: normalization.py returns None when SNMP is not configured",
        "",
    )
    assert ok


def test_v05_74_empty_config_http_flag_conflicts_with_model(recorder, model):
    r = norm([])
    observed = get(r, "management.http.enabled")
    default = model.get_concept("management.http.enabled").default_value
    ok = observed == "<absent>"
    recorder.add(
        "V05-74", "H", "HTTP flag on an absent configuration matches the secure model default",
        "raw_lines=[]", f"management.http.enabled absent (model default {default} lives in the model)",
        f"observed={observed!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: normalization.py returns None when the command is absent",
        "",
    )
    assert ok


def test_v05_75_description_text_counted_as_acl_rule(recorder):
    r = norm(["interface GigabitEthernet0/0", " description deny the bad guys"])
    ok = get(r, "access_control.rules_count") == 0 \
        and get(r, "access_control.acl_applied") == "<absent>"
    recorder.add(
        "V05-75", "H", "Interface description text is not counted as an access-list rule",
        "['interface GigabitEthernet0/0', ' description deny the bad guys']",
        "rules_count=0, acl_applied absent", f"rules_count={get(r, 'access_control.rules_count')!r} "
        f"acl_applied={get(r, 'access_control.acl_applied')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F12: normalization.py counts only ACL-syntax lines",
        "",
    )
    assert ok


def test_v05_76_hostname_lands_outside_the_model(recorder, model_paths):
    r = norm(["hostname R1"])
    root_hostname = get(r, "hostname")
    device_hostname = get(r, "device.hostname")
    ok = root_hostname == "<absent>" and device_hostname == "R1" \
        and "device.hostname" in model_paths and "hostname" not in model_paths
    recorder.add(
        "V05-76", "H", "The device hostname is written to the model path device.hostname",
        "['hostname R1']", "device.hostname='R1', no root 'hostname' key",
        f"hostname(root)={root_hostname!r} device.hostname={device_hostname!r} "
        f"'hostname' in model={'hostname' in model_paths}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: normalization.py emits device.hostname (model path)",
        "",
    )
    assert ok


def test_v05_77_comment_only_config_flips_controls(recorder):
    from app.benchmarks.execution import BenchmarkExecutionEngine
    engine = BenchmarkExecutionEngine()
    empty = engine.execute("", vendor="cisco", platform="ios_xe")
    comment = engine.execute("! access-list 10 permit host 1.2.3.4\n",
                             vendor="cisco", platform="ios_xe")
    passed_empty = {e.control_id for e in empty.evaluations if e.result == "PASS"}
    passed_comment = {e.control_id for e in comment.evaluations if e.result == "PASS"}
    gained = sorted(passed_comment - passed_empty)
    lost = sorted(passed_empty - passed_comment)
    ok = len(gained) == 0 and len(lost) == 0
    recorder.add(
        "V05-77", "H", "Controls do not pass because of commented-out configuration",
        "empty config vs '! access-list 10 permit host 1.2.3.4' (cisco/ios_xe)",
        "identical control results for both inputs",
        f"gained_PASS={gained} lost_PASS={lost} empty_passed={len(passed_empty)} "
        f"comment_passed={len(passed_comment)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: comments never enter normalization, so evaluation cannot "
        "be driven by them",
        "",
    )
    assert ok


def test_v05_78_junos_hostname_substring_enables_syslog(recorder):
    r = norm(["system {", "    host-name R2;", "}"], "juniper", "junos")
    ok = get(r, "device.hostname") == "R2" \
        and get(r, "logging.remote_enabled") == "<absent>"
    recorder.add(
        "V05-78", "H", "A Junos hostname does not enable remote syslog",
        "system { host-name R2; }",
        "device.hostname='R2', logging.remote_enabled absent",
        f"hostname={get(r, 'device.hostname')!r} "
        f"logging.remote_enabled={get(r, 'logging.remote_enabled')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F11: normalization.py matches target keywords as whole tokens",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# I. Pipeline integration, double normalization and persistence
# --------------------------------------------------------------------------

def test_v05_79_normalization_runs_twice(recorder, monkeypatch):
    from app.engines.compliance.executor import AuditExecutor
    from app.engines import normalization as norm_module
    calls = []
    real_normalize = norm_module.NormalizationEngine.normalize

    def spy(self, config, vendor, platform, semantic_interpretation=None):
        calls.append((vendor, platform))
        return real_normalize(self, config, vendor, platform,
                              semantic_interpretation)

    monkeypatch.setattr(norm_module.NormalizationEngine, "normalize", spy)
    config = (BACKEND / "tests" / "sample_configs" / "secure.txt").read_text(
        encoding="utf-8")
    result = AuditExecutor().execute("v05-probe-once", config, framework="CIS")
    bench_norm = getattr(getattr(result, "benchmark_result", None),
                         "normalization_result", None)
    # E05 F5: exactly one NormalizationEngine.normalize call per audit; the
    # benchmark consumes the executor's result (identity) on one platform.
    ok = len(calls) == 1 and result.normalization_result is not None \
        and bench_norm is result.normalization_result \
        and calls[0][0].lower() == "cisco" and calls[0][1].lower() == "ios_xe"
    recorder.add(
        "V05-79", "I", "A single audit normalizes the configuration once",
        "spied NormalizationEngine.normalize during AuditExecutor.execute",
        "1 call; benchmark consumes the executor's result object",
        f"calls={calls} benchmark_reuses={bench_norm is result.normalization_result} "
        f"status={result.status}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F5: executor.py normalizes once (canonical platform) and passes "
        "normalization_result into benchmarks/execution.py",
        "",
    )
    assert ok


def test_v05_80_normalization_parameter_unused(recorder):
    source = read("app/engines/compliance/executor.py")
    tree = ast.parse(source)
    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and \
                node.name == "_benchmark_to_compliance_evaluation":
            target = node
            break
    params = [a.arg for a in target.args.args] if target else []
    loaded = {
        n.id for n in ast.walk(target)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    } if target else set()
    ok = target is not None and "normalization" in params \
        and "normalization" in loaded
    recorder.add(
        "V05-80", "I", "The normalization result is consumed where it is passed",
        "AST of executor._benchmark_to_compliance_evaluation",
        "the 'normalization' parameter is read inside the function",
        f"params={params} normalization_read={'normalization' in loaded}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F5: executor.py attaches the authoritative normalization id and "
        "model version to the compliance evaluation",
        "",
    )
    assert ok


def test_v05_81_normalized_values_never_persisted(recorder):
    source = read("app/api/v1/audit_execution.py")
    lines = source.splitlines()
    has_empty_values = any("normalized_values=[]" in ln for ln in lines)
    has_empty_unmapped = any("unmapped_concepts=[]" in ln for ln in lines)
    uses_result = "result.normalization_result" in source \
        or "norm_result" in source
    ok = not has_empty_values and not has_empty_unmapped and uses_result
    recorder.add(
        "V05-81", "I", "Normalized values produced for an audit are written to storage",
        "audit_execution.py NormalizedConfiguration construction",
        "normalized_values and unmapped_concepts populated from the engine result",
        f"empty-values hard-code={has_empty_values} "
        f"empty-unmapped hard-code={has_empty_unmapped} "
        f"engine result consumed={uses_result}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F5: app/api/v1/audit_execution.py persists mappings/unmapped/version",
        "",
    )
    assert ok


def test_v05_82_model_version_hardcoded(recorder):
    source = read("app/api/v1/audit_execution.py")
    import re as _re
    match = _re.search(r'universal_model_version\s*=\s*"([^"]+)"', source)
    persisted = match.group(1) if match else None
    uses_model = "UniversalSecurityModel.VERSION" in source
    ok = persisted is None and uses_model
    recorder.add(
        "V05-82", "I", "The persisted model version comes from the versioned model (spec §11.3)",
        "audit_execution.py NormalizedConfiguration construction",
        "version read from UniversalSecurityModel",
        f"hard-coded literal={persisted!r} model VERSION used={uses_model}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4: audit_execution.py persists UniversalSecurityModel.VERSION "
        "(docs/PROJECT_MASTER_SPEC.md:700-706)",
        "",
    )
    assert ok


def test_v05_83_semantic_interpretation_persisted_empty(recorder):
    source = read("app/api/v1/audit_execution.py")
    lines = source.splitlines()
    empty_sections = any("semantic_sections=[]" in ln for ln in lines)
    uses_parse = "parse_result" in source and "semantic_interp" in source
    # Confidence scores stay honestly empty: deterministic parsing produces
    # no confidence scores to persist (no fabrication).
    ok = not empty_sections and uses_parse
    recorder.add(
        "V05-83", "I", "The semantic interpretation persisted for an audit carries the parsed content",
        "audit_execution.py SemanticInterpretation construction",
        "semantic_sections and unknown_meanings populated from the parser",
        f"semantic_sections=[] hard-coded={empty_sections} "
        f"parser content consumed={uses_parse}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4 (§10.5): app/api/v1/audit_execution.py persists parse-tree "
        "sections and unknowns; confidence_scores stays honestly empty",
        "",
    )
    assert ok


def test_v05_84_engine_input_type_vs_spec(recorder):
    import inspect
    params = list(inspect.signature(NormalizationEngine.normalize).parameters)
    normalization_src = read("app/engines/normalization.py")
    uses_semantic = "semantic_interpretation" in normalization_src
    ok = "semantic_interpretation" in params and uses_semantic
    recorder.add(
        "V05-84", "I", "The normalizer accepts a SemanticInterpretation as specified in §10.5",
        "NormalizationEngine.normalize signature and module references",
        "semantic_interpretation parameter consumed by the engine",
        f"params={params}; module references semantic_interpretation={uses_semantic}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4 (§10.5): normalization.py consumes the executor-built "
        "interpretation payload (parse-tree sections); raw_lines compat kept",
        "",
    )
    assert ok


def test_v05_85_knowledge_base_optional_and_never_fabricated(recorder):
    """E06 supersedes the E05 "no knowledge base exists" limitation.

    The honest contract now: the KB is OPTIONAL. With no KB supplied the
    deterministic mappers stand alone and the result carries no KB
    provenance (never a fabricated KB, never a false claim of KB usage);
    with a KB supplied only confirmed, trusted, path-valid, value-coercible
    hits are applied, and the mapping records kb:<id> provenance.
    """
    from types import SimpleNamespace

    from app.engines.normalization import NormalizationEngine

    lines = ["hostname R1", "some vendor specific knob value"]

    class StubKB:
        def __init__(self, hit):
            self._hit = hit
            self.calls = []

        def lookup(self, vendor, platform, raw_syntax, require_confirmed=True):
            self.calls.append((vendor, platform, raw_syntax, require_confirmed))
            return self._hit

    def hit(**kwargs):
        base = dict(id="kb-1", admin_confirmed=True, confidence=1.0,
                    universal_model_path="crypto.ssh_key_size",
                    semantic_meaning="2048")
        base.update(kwargs)
        return SimpleNamespace(**base)

    # 1. No KB: deterministic result, no KB provenance, no crash.
    without = NormalizationEngine().normalize(
        {"raw_lines": lines}, "cisco", "ios")
    plain_paths = {m.get("model_path") for m in without.normalized_values}
    plain_sources = [s for m in without.normalized_values
                     for s in (m.get("source_path") or [])]
    no_kb_claim = not any(str(s).startswith("kb:") for s in plain_sources)

    # 2. Unconfirmed / low-trust hits never become authoritative output.
    unconfirmed = StubKB(hit(admin_confirmed=False, confidence=1.0))
    r_unconfirmed = NormalizationEngine().normalize(
        {"raw_lines": lines}, "cisco", "ios", knowledge_base=unconfirmed)
    rejected_unconfirmed = get(r_unconfirmed, "crypto.ssh_key_size") == "<absent>"

    low_trust = StubKB(hit(admin_confirmed=True, confidence=0.5))
    r_low = NormalizationEngine().normalize(
        {"raw_lines": lines}, "cisco", "ios", knowledge_base=low_trust)
    rejected_low = get(r_low, "crypto.ssh_key_size") == "<absent>"

    # 3. A bogus model path is ignored, not written.
    bogus = StubKB(hit(universal_model_path="not.a.model.path"))
    r_bogus = NormalizationEngine().normalize(
        {"raw_lines": lines}, "cisco", "ios", knowledge_base=bogus)
    rejected_bogus = "not.a.model.path" not in flat(r_bogus.universal_config)

    # 4. A confirmed, trusted, path-valid, coercible hit IS applied with
    #    explicit kb:<id> provenance.
    good = StubKB(hit())
    r_good = NormalizationEngine().normalize(
        {"raw_lines": lines}, "cisco", "ios", knowledge_base=good)
    applied = get(r_good, "crypto.ssh_key_size") == 2048
    kb_sources = [s for m in r_good.normalized_values
                  for s in (m.get("source_path") or [])
                  if str(s).startswith("kb:")]
    confirmed_only = all(c[3] is True for c in good.calls)

    ok = (no_kb_claim and rejected_unconfirmed and rejected_low
          and rejected_bogus and applied and "kb:kb-1" in kb_sources
          and confirmed_only)
    recorder.add(
        "V05-85", "I",
        "Mapping rules are deterministic; the knowledge base is an optional, "
        "never-fabricated input that only confirmed+trusted hits can influence",
        "normalize the same config with no KB, an unconfirmed KB hit, a "
        "low-confidence hit, a bogus model path, and a confirmed trusted hit",
        "no KB: deterministic output with no kb: provenance; unconfirmed / "
        "low-trust / bogus-path hits ignored; confirmed trusted hit applied "
        "with kb:<id> provenance",
        f"no_kb_claim={no_kb_claim} rejected_unconfirmed={rejected_unconfirmed} "
        f"rejected_low_trust={rejected_low} rejected_bogus_path={rejected_bogus} "
        f"applied={applied} kb_sources={kb_sources} confirmed_only={confirmed_only} "
        f"deterministic_paths={len(plain_paths)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F1 (spec section 10.6 'provide lookup for normalization'): "
        "normalization.py consumes an injected knowledge base; "
        "_apply_kb_mappings applies only confirmed rows at/above the trust "
        "threshold whose model path is valid and whose meaning coerces, and "
        "records kb:<id> provenance. Supersedes the E05 'no knowledge base "
        "exists in this repository' limitation (ENGINE_05_FIX_REPORT §16).",
        "",
    )
    assert ok


def test_v05_86_platform_label_divergence(recorder):
    ios = norm(["hostname R1"], "cisco", "ios")
    ios_xe = norm(["hostname R1"], "cisco", "ios_xe")
    ok = ios.platform == ios_xe.platform == "ios_xe" \
        and ios.universal_config == ios_xe.universal_config
    recorder.add(
        "V05-86", "I", "One audit produces one consistent normalization record",
        "same input normalized as platform 'ios' and 'ios_xe'",
        "a single canonical platform label with identical output",
        f"platforms={ios.platform!r}/{ios_xe.platform!r} "
        f"identical_config={ios.universal_config == ios_xe.universal_config}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F5 (§25): normalization.py canonicalizes to ios_xe; the executor "
        "normalizes once on the canonical platform",
        "",
    )
    assert ok


def test_v05_87_end_to_end_audit_returns_normalization(recorder):
    from app.engines.compliance.executor import AuditExecutor
    config = (BACKEND / "tests" / "sample_configs" / "secure.txt").read_text(encoding="utf-8")
    started = time.perf_counter()
    result = AuditExecutor().execute("probe05", config, framework="CIS", device_name="probe")
    ms = (time.perf_counter() - started) * 1000
    norm_result = getattr(result, "normalization_result", None)
    ok = norm_result is not None and getattr(norm_result, "result_type", None) is not None
    recorder.add(
        "V05-87", "I", "An offline end-to-end audit completes with a normalization result attached",
        "tests/sample_configs/secure.txt through AuditExecutor.execute",
        "audit completes and exposes normalization_result",
        f"ok={ok} result_type={getattr(norm_result, 'result_type', None)!r} "
        f"mappings={len(getattr(norm_result, 'mappings', []))} status={result.status} "
        f"ms={ms:.0f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "app/engines/compliance/executor.py:130+ (execute), :231 "
        "(result.normalization_result = normalization)",
    )
    assert ok


# --------------------------------------------------------------------------
# J. Determinism
# --------------------------------------------------------------------------

def test_v05_88_repeat_runs_identical(recorder):
    results = [
        NormalizationEngine().normalize(
            {"raw_lines": ["hostname R1", "logging host 10.0.0.5", "access-list 10 permit host 1.2.3.4"]},
            "cisco", "ios",
        ).to_dict()
        for _ in range(5)
    ]
    ok = all(r == results[0] for r in results)
    recorder.add(
        "V05-88", "J", "Normalizing the same input repeatedly yields identical results",
        "5 repetitions of a fixed 3-line config", "all 5 results identical",
        f"identical={ok}", "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "normalization.py:233-302 (no randomness, no shared mutable state)",
    )
    assert ok


def test_v05_89_instances_agree(recorder):
    config = {"raw_lines": ["set system host-name R1", "set system ntp server 1.1.1.1"]}
    a = NormalizationEngine().normalize(config, "juniper", "junos").to_dict()
    b = NormalizationEngine().normalize(config, "juniper", "junos").to_dict()
    ok = a == b
    recorder.add(
        "V05-89", "J", "Two normalizer instances agree on the same input",
        "two NormalizationEngine() instances, Junos set-style config",
        "identical results", f"identical={ok}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "normalization.py:69-71 (mappers rebuilt identically per instance)",
    )
    assert ok


def test_v05_90_corpus_deterministic(recorder):
    summary_path = ARTIFACTS / "dataset_summary.json"
    if not summary_path.exists():
        recorder.add(
            "V05-90", "J", "Normalizing the dataset twice yields identical results per file",
            "artifacts/.../dataset_summary.json", "nondeterministic=0",
            "artifact missing", "NOT VERIFIABLE", "CONFIRMED BEHAVIOR",
            "scripts/engine_validation/sweep_normalization.py",
        )
        pytest.skip("dataset_summary.json not produced")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    nondet = summary["overall"]["nondeterministic"]
    ok = nondet == 0
    recorder.add(
        "V05-90", "J", "Normalizing the dataset twice yields identical results per file",
        f"{summary['overall']['files']} dataset files, two passes each",
        "nondeterministic=0",
        f"nondeterministic={nondet} files={summary['overall']['files']}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "artifacts/engine_validation/05_normalization/dataset_summary.json",
    )
    assert ok


# --------------------------------------------------------------------------
# K. Performance
# --------------------------------------------------------------------------

def _dataset_elapsed() -> list[float]:
    path = ARTIFACTS / "dataset_results.csv"
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return [float(row["elapsed_ms"]) for row in csv.DictReader(fh)
                if row.get("elapsed_ms")]


def test_v05_91_corpus_latency(recorder):
    elapsed = _dataset_elapsed()
    if not elapsed:
        recorder.add(
            "V05-91", "K", "Per-file normalization latency stays within interactive bounds",
            "artifacts/.../dataset_results.csv", "p50<10ms, p95<200ms, max<1000ms",
            "artifact missing", "NOT VERIFIABLE", "CONFIRMED BEHAVIOR",
            "scripts/engine_validation/sweep_normalization.py",
        )
        pytest.skip("dataset_results.csv not produced")
    p50 = statistics.median(elapsed)
    p95 = sorted(elapsed)[int(len(elapsed) * 0.95) - 1]
    maximum = max(elapsed)
    ok = p50 < 10 and p95 < 200 and maximum < 1000
    recorder.add(
        "V05-91", "K", "Per-file normalization latency stays within interactive bounds",
        f"{len(elapsed)} dataset files", "p50<10ms, p95<200ms, max<1000ms",
        f"p50={p50:.3f}ms p95={p95:.3f}ms max={maximum:.3f}ms",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "artifacts/engine_validation/05_normalization/dataset_results.csv",
    )
    assert ok


def test_v05_92_large_config_latency(recorder):
    lines = [f"interface GigabitEthernet0/{i}" for i in range(20000)]
    engine = NormalizationEngine()
    engine.normalize({"raw_lines": ["warmup"]}, "cisco", "ios")
    started = time.perf_counter()
    r = engine.normalize({"raw_lines": lines}, "cisco", "ios")
    ms = (time.perf_counter() - started) * 1000
    ok = ms < 5000 and r.result_type == NormalizationResultType.SUCCESS
    recorder.add(
        "V05-92", "K", "A 20k-line configuration normalizes within 5 seconds",
        "20000 interface lines", "<5000 ms and a successful result",
        f"ms={ms:.1f} result_type={r.result_type.value} mappings={len(r.mappings)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "normalization.py:233-302 (single pass per mapper key)",
    )
    assert ok


def test_v05_93_empty_config_latency(recorder):
    engine = NormalizationEngine()
    engine.normalize({"raw_lines": ["warmup"]}, "cisco", "ios")
    started = time.perf_counter()
    for _ in range(20):
        engine.normalize({"raw_lines": []}, "cisco", "ios")
    ms = (time.perf_counter() - started) * 1000 / 20
    ok = ms < 100
    recorder.add(
        "V05-93", "K", "Normalizing an empty configuration is effectively free",
        "20 runs over raw_lines=[]", "<100 ms per run",
        f"mean_ms={ms:.3f}", "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "normalization.py:264-286",
    )
    assert ok


# --------------------------------------------------------------------------
# L. Hostile / boundary input
# --------------------------------------------------------------------------

def test_v05_94_hostile_characters_do_not_crash(recorder):
    try:
        r = norm(["hostname A\x00B", "\x01\x02\x03", "iface \ud800x", "   \t  "])
        ok = r.result_type is not None
        detail = f"result_type={r.result_type.value} mappings={len(r.mappings)}"
        error = ""
    except Exception as exc:  # pragma: no cover - the defect being tested
        ok = False
        detail = ""
        error = f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V05-94", "L", "NUL, control, surrogate and whitespace-only lines do not raise",
        "['hostname A\\x00B', '\\x01\\x02\\x03', 'iface \\ud800x', '   \\t  ']",
        "normalization completes without an exception",
        f"{detail} {error}".strip(),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "normalization.py:316-431 (string operations only, per-mapper try/except)",
    )
    assert ok


def test_v05_95_nul_byte_kept_in_normalized_value(recorder):
    r = norm(["hostname A\x00B"])
    hostname = get(r, "device.hostname")
    ok = isinstance(hostname, str) and "\x00" not in hostname
    recorder.add(
        "V05-95", "L", "Control characters are rejected or sanitized in normalized values",
        "['hostname A\\x00B']", "hostname sanitized (NUL stripped), no crash",
        f"hostname={hostname!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F16: normalization.py sanitizes NUL/C0/surrogates deterministically",
        "",
    )
    assert ok


def test_v05_96_null_raw_lines(recorder):
    try:
        r = NormalizationEngine().normalize({"raw_lines": None}, "cisco", "ios")
        ok = r.result_type == NormalizationResultType.FAILED \
            and r.mappings == [] and r.universal_config == {}
        detail = (f"result_type={r.result_type.value} mappings={len(r.mappings)}")
        error = ""
    except Exception as exc:  # pragma: no cover
        ok = False
        detail = ""
        error = f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V05-96", "L", "raw_lines=None fails deterministically, not a crash",
        "{'raw_lines': None}", "FAILED with no mappings and no exception",
        f"{detail} {error}".strip(),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F6/F17: normalization.py typed payload validation",
        "",
    )
    assert ok


def test_v05_97_missing_raw_lines_key(recorder):
    r = NormalizationEngine().normalize({}, "cisco", "ios")
    ok = r.result_type == NormalizationResultType.FAILED and r.mappings == [] \
        and r.universal_config == {}
    recorder.add(
        "V05-97", "L", "A configuration object without any lines is not reported as a success",
        "normalize({}, 'cisco', 'ios')",
        "failed: there is no configuration to normalize",
        f"result_type={r.result_type.value} mappings={len(r.mappings)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F6/F17: normalization.py rejects payloads without lines",
        "",
    )
    assert ok


def test_v05_98_non_string_lines(recorder):
    try:
        r = NormalizationEngine().normalize({"raw_lines": [1, 2, 3]}, "cisco", "ios")
        ok = r.result_type == NormalizationResultType.FAILED \
            and r.mappings == [] and r.universal_config == {}
        detail = (f"result_type={r.result_type.value} mappings={len(r.mappings)}")
        error = ""
    except Exception as exc:  # pragma: no cover
        ok = False
        detail = ""
        error = f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V05-98", "L", "Non-string line elements fail deterministically without crashing",
        "{'raw_lines': [1, 2, 3]}", "FAILED with no mappings and no exception",
        f"{detail} {error}".strip(),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F6/F17: normalization.py typed payload validation",
        "",
    )
    assert ok


def test_v05_99_megabyte_single_line(recorder):
    payload = "x" * (1024 * 1024)
    engine = NormalizationEngine()
    engine.normalize({"raw_lines": ["warmup"]}, "cisco", "ios")
    started = time.perf_counter()
    try:
        r = engine.normalize({"raw_lines": [payload]}, "cisco", "ios")
        ms = (time.perf_counter() - started) * 1000
        ok = ms < 5000 and r.result_type is not None
        detail = f"ms={ms:.1f} result_type={r.result_type.value}"
        error = ""
    except Exception as exc:  # pragma: no cover
        ok = False
        detail = ""
        error = f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V05-99", "L", "A 1 MB single line normalizes without hanging or crashing",
        "one 1048576-character line", "<5000 ms and no exception",
        f"{detail} {error}".strip(),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "normalization.py:316-431",
    )
    assert ok


def test_v05_100_null_element_in_lines(recorder):
    try:
        r = NormalizationEngine().normalize({"raw_lines": ["hostname R1", None]},
                                            "cisco", "ios")
        ok = r.result_type == NormalizationResultType.FAILED \
            and r.mappings == [] and r.universal_config == {}
        detail = (f"result_type={r.result_type.value} mappings={len(r.mappings)}")
        error = ""
    except Exception as exc:  # pragma: no cover
        ok = False
        detail = ""
        error = f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V05-100", "L", "A null entry inside raw_lines fails deterministically without crashing",
        "{'raw_lines': ['hostname R1', None]}", "FAILED with no mappings and no exception",
        f"{detail} {error}".strip(),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F6/F17: normalization.py typed payload validation",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# E05 regression coverage added with the fix
# --------------------------------------------------------------------------

def test_v05_101_whitespace_only_config(recorder):
    r = norm(["   ", "\t", "  \n  "])
    observed = [m for m in r.mappings
                if m.model_path not in ("device.vendor", "device.platform",
                                        "access_control.rules_count")]
    rules = next((m for m in r.mappings
                  if m.model_path == "access_control.rules_count"), None)
    ok = r.result_type == NormalizationResultType.SUCCESS and observed == [] \
        and (rules is None or rules.value == 0)
    recorder.add(
        "V05-101", "H", "Whitespace-only input yields no observed mappings",
        "blank/whitespace lines", "SUCCESS with zero observed state",
        f"result_type={r.result_type.value} observed={len(observed)} "
        f"mappings={len(r.mappings)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1: whitespace carries no evidence (caller identity and the "
        "zero rule count are measurements, not observed state)",
        "",
    )
    assert ok


def test_v05_102_banner_payload_drives_no_state(recorder):
    r = norm(["hostname R1", "banner motd ^", "permit ip any any",
              "deny ip any any log", "^", "interface Gi0/0"])
    ok = get(r, "access_control.rules_count") == 0 \
        and get(r, "access_control.acl_applied") == "<absent>"
    recorder.add(
        "V05-102", "H", "Banner payload lines are not parsed as configuration",
        "banner body containing permit/deny lines",
        "rules_count=0, acl_applied absent",
        f"rules_count={get(r, 'access_control.rules_count')!r} "
        f"acl_applied={get(r, 'access_control.acl_applied')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F1/F5: normalization.py excludes banner payload spans",
        "",
    )
    assert ok


def test_v05_103_secure_only_derived(recorder):
    https_only = norm(["ip http secure-server"])
    with_http = norm(["ip http secure-server", "ip http server"])
    plain = norm(["hostname R1"])
    ok = get(https_only, "management.http.secure_only") is True \
        and get(with_http, "management.http.secure_only") is False \
        and get(plain, "management.http.secure_only") == "<absent>"
    recorder.add(
        "V05-103", "E", "management.http.secure_only derives from observed https/http state",
        "secure-server alone / with http server / neither",
        "True / False / absent",
        f"https-only={get(https_only, 'management.http.secure_only')!r} "
        f"with-http={get(with_http, 'management.http.secure_only')!r} "
        f"plain={get(plain, 'management.http.secure_only')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: secure_only is a documented DERIVED mapping",
        "",
    )
    assert ok


def test_v05_104_new_leaf_extraction(recorder):
    cisco = norm(["version 15.2", "ip name-server 8.8.8.8", "ip dhcp pool LAN",
                  "access-list 10 permit host 1.2.3.4"])
    forti = norm(["config system dns", "    set primary 8.8.8.8", "end",
                  "config system dhcp server", "    edit 1", "    next", "end",
                  "config firewall policy", "    edit 0", "    next", "end"],
                 "fortinet", "fortios")
    ok = get(cisco, "device.firmware_version") == "15.2" \
        and get(cisco, "services.dns.configured") is True \
        and get(cisco, "services.dhcp.enabled") is True \
        and get(cisco, "access_control.default_action") == "deny" \
        and get(forti, "services.dns.configured") is True \
        and get(forti, "services.dhcp.enabled") is True \
        and get(forti, "access_control.default_action") == "deny"
    recorder.add(
        "V05-104", "E", "Newly covered model leaves extract real evidence",
        "firmware/dns/dhcp/acl lines (cisco + fortios)",
        "firmware, dns, dhcp and derived default_action observed",
        f"cisco-fw={get(cisco, 'device.firmware_version')!r} "
        f"cisco-dns={get(cisco, 'services.dns.configured')!r} "
        f"cisco-dhcp={get(cisco, 'services.dhcp.enabled')!r} "
        f"cisco-default={get(cisco, 'access_control.default_action')!r} "
        f"forti-dns={get(forti, 'services.dns.configured')!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3: mapper coverage for the added §11.1 leaves",
        "",
    )
    assert ok


def test_v05_105_confidence_policy_classes(recorder):
    from app.engines.normalization import CONFIDENCE_POLICY
    r = norm(["hostname R1", "no ip http server", "exec-timeout 5 0",
              "ip http secure-server"])
    by_path = {m.model_path: m.confidence for m in r.mappings}
    ok = set(CONFIDENCE_POLICY) == {"DIRECT_EXACT", "DIRECT_NEGATED",
                                    "STRUCTURED_EXTRACTION", "DERIVED"} \
        and set(CONFIDENCE_POLICY.values()) == {0.95, 0.95, 0.85, 0.75} \
        and by_path.get("device.hostname") == 0.95 \
        and by_path.get("management.http.enabled") == 0.95 \
        and by_path.get("management.ssh.timeout") == 0.85 \
        and by_path.get("management.http.secure_only") == 0.75
    recorder.add(
        "V05-105", "E", "Confidence follows the documented evidence-class policy",
        "hostname + negation + converted + derived mappings",
        "0.95 direct, 0.85 structured, 0.75 derived; never a constant",
        f"policy={CONFIDENCE_POLICY} observed={by_path}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4/§21: normalization.py CONFIDENCE_POLICY",
        "",
    )
    assert ok


def test_v05_106_registry_rejects_stray_paths(recorder):
    from app.engines.normalization import NormalizationEngine as _NE
    engine = _NE()
    engine.vendor_mappers["cisco"]["ios"]["bogus.not_a_path"] = lambda ctx: None
    try:
        engine._validate_mapper_registry()
        raised = False
    except ValueError:
        raised = True
    finally:
        del engine.vendor_mappers["cisco"]["ios"]["bogus.not_a_path"]
    engine._validate_mapper_registry()
    ok = raised
    recorder.add(
        "V05-106", "F", "Mapper/model drift fails fast at initialization",
        "injected stray mapper path", "ValueError from registry validation",
        f"raised={raised} registry clean after removal",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3 (§43): NormalizationEngine._validate_mapper_registry",
        "",
    )
    assert ok


def test_v05_107_model_version_semver_and_persisted(recorder, model):
    import re as _re
    version = UniversalSecurityModel.VERSION
    source = read("app/api/v1/audit_execution.py")
    ok = bool(_re.match(r"^\d+\.\d+\.\d+$", version)) \
        and model.version == version \
        and "UniversalSecurityModel.VERSION" in source \
        and 'universal_model_version="1.0"' not in source \
        and 'universal_model_version="1.0",' not in source
    recorder.add(
        "V05-107", "I", "The model version is semver and the API persists it (spec §11.3)",
        "UniversalSecurityModel.VERSION + audit_execution.py",
        "major.minor.patch from the model, no hard-coded literal",
        f"version={version!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F3/F4: universal_model.py VERSION; audit_execution.py persistence",
        "",
    )
    assert ok


def test_v05_108_semantic_interpretation_flows_to_normalization(recorder):
    from app.engines.compliance.executor import AuditExecutor
    config = (BACKEND / "tests" / "sample_configs" / "secure.txt").read_text(
        encoding="utf-8")
    result = AuditExecutor().execute("v05-probe-semantic", config,
                                     framework="CIS")
    semi = getattr(result, "semantic_interpretation", None) or {}
    sections = semi.get("sections", []) if isinstance(semi, dict) else []
    norm_result = getattr(result, "normalization_result", None)
    ok = result.status == "completed" and len(sections) > 0 \
        and norm_result is not None \
        and getattr(norm_result, "semantic_interpretation_id", "unset") is None \
        and len(getattr(norm_result, "mappings", [])) > 0
    recorder.add(
        "V05-108", "I", "The executor builds the §10.5 interpretation and normalizes once from it",
        "secure.txt through AuditExecutor.execute",
        "non-empty parse-tree sections; normalization produced",
        f"status={result.status} sections={len(sections)} "
        f"mappings={len(getattr(norm_result, 'mappings', []) or [])}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E05 F4/F5 (§10.5): executor.py builds semantic_interpretation from "
        "the parse tree and passes it to a single normalize() call",
        "",
    )
    assert ok
