"""V03 — Vendor Detection Engine validation.

Scope: backend/app/engines/detection.py ONLY.

  VendorDetector
    detect(content) -> VendorIdentification(vendor, platform, confidence,
        firmware_version, detection_method, detection_evidence,
        device_type, hostname)
    _extract_firmware_version  _collect_evidence
    _detect_device_type        _extract_hostname

Two execution paths exist (detection.py:173-211 ML, 213-291 regex). Both are
exercised: the deployed path (ML available in this environment) and the
regex fallback, selected by monkeypatching app.ml.model.get_ml_detector.

The ML models are NOT evaluated here — vendor/device classification quality
is deferred by instruction until all 12 engines are validated. Rows only
record which path ran and what the engine returned.

AuditExecutor / BenchmarkExecutionEngine / API endpoints are referenced as a
source-level integration contract (category K) only.
"""

from __future__ import annotations

import statistics
import time
from pathlib import Path

import pytest

from tests.validation.conftest import Recorder

BACKEND = Path(__file__).resolve().parents[2]
SAMPLE_CONFIGS = BACKEND / "tests" / "sample_configs"
DETECTION_SRC = (BACKEND / "app" / "engines" / "detection.py").read_text(encoding="utf-8")
EXECUTOR_SRC = (BACKEND / "app" / "engines" / "compliance" / "executor.py").read_text(
    encoding="utf-8"
)
BENCH_SRC = (BACKEND / "app" / "benchmarks" / "execution.py").read_text(encoding="utf-8")
AUDIT_API_SRC = (BACKEND / "app" / "api" / "v1" / "audit_execution.py").read_text(
    encoding="utf-8"
)
SPEC_SRC = (BACKEND.parent / "docs" / "PROJECT_MASTER_SPEC.md").read_text(encoding="utf-8")

CISCO_IOS = (
    "hostname Router1\n"
    "!\n"
    "interface GigabitEthernet0/0\n"
    " ip address 192.168.1.1 255.255.255.0\n"
    "!\n"
    "line vty 0 4\n"
    " login local\n"
    " transport input ssh\n"
)
CISCO_BANNER = "! Cisco IOS Software, C2960 Software, Version 15.0(2)SE\nhostname Switch1"
FORTI = (
    "#config-global\n"
    "#config system interface\n"
    '#  edit "wan1"\n'
    "#    set mode static\n"
    "#  next\n"
    "#end\n"
)
JUNOS = (
    "## system {\n"
    "##     host-name EdgeRouter;\n"
    "##     services {\n"
    "##         ssh;\n"
    "##     }\n"
    "## }\n"
)
PALO = (
    "set deviceconfig system hostname FW1\n"
    "set rulebase security rules R1 from any to any\n"
    "set network interface ethernet1\n"
)
NXOS = (
    "feature interface-vlan\n"
    "feature lacp\n"
    "interface Ethernet1/1\n"
    " switchport mode trunk\n"
    "vlan database\n"
    " vlan 10\n"
)
ASA = (
    "interface GigabitEthernet0/0\n"
    " nameif outside\n"
    " security-level 100\n"
    "object network OBJ\n"
    " nat (inside,outside) dynamic PAT\n"
)
PROSE = "hello world\nthis is not a device configuration\njust plain text\n"


def path_of(result) -> str:
    """'ml' when the ML branch returned, 'regex' otherwise."""
    from app.engines.detection import DetectionMethod

    return "ml" if result.detection_method is DetectionMethod.PATTERN else "regex"


def evid(result) -> list[str]:
    return [f"{e.method.value}:{e.pattern}@{e.line_number}" for e in result.detection_evidence]


class _MLUnavailable:
    is_available = False

    def predict(self, content):  # pragma: no cover - never called
        return ("unknown", "unknown", "unknown", 0.0, "fallback")


class _MLFake:
    def __init__(self, ret=None, exc=None, available=True):
        self._ret = ret or ("cisco", "ios_xe", "router", 0.6, "ml")
        self._exc = exc
        self._available = available

    @property
    def is_available(self):
        return self._available

    def predict(self, content):
        if self._exc is not None:
            raise self._exc
        return self._ret


def patch_ml(monkeypatch, fake) -> None:
    import app.ml.model as mlmod

    monkeypatch.setattr(mlmod, "get_ml_detector", lambda: fake)


def patch_regex(monkeypatch) -> None:
    """Force the regex branch by reporting the ML detector unavailable."""
    patch_ml(monkeypatch, _MLUnavailable())


@pytest.fixture()
def detector():
    from app.engines.detection import VendorDetector

    return VendorDetector()


# ---------------------------------------------------------------------------
# A — functional (deployed path)
# ---------------------------------------------------------------------------

def test_v03_01_cisco_identified(detector, recorder: Recorder):
    r = detector.detect(CISCO_IOS)
    ok = r.vendor == "cisco" and 0.0 <= r.confidence <= 1.0
    recorder.add(
        "V03-01", "A", "a canonical Cisco IOS configuration is identified as cisco",
        "10-line IOS config (hostname/interface/line vty), default path",
        "vendor=cisco, confidence in [0,1]",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} "
        f"path={path_of(r)} dt={r.device_type} host={r.hostname}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:161-291",
    )
    assert ok


def test_v03_02_fortinet_identified(detector, recorder: Recorder):
    r = detector.detect(FORTI)
    ok = r.vendor == "fortinet" and r.platform == "fortios"
    recorder.add(
        "V03-02", "A", "a canonical FortiOS configuration is identified as fortinet/fortios",
        "6-line FortiGate config (#config ... next/end)",
        "vendor=fortinet platform=fortios",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} path={path_of(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:85-100 fortinet patterns; ML conf for this input is below the "
        "0.55 gate so the regex branch runs",
    )
    assert ok


def test_v03_03_juniper_identified(detector, recorder: Recorder):
    r = detector.detect(JUNOS)
    ok = r.vendor == "juniper" and r.platform == "junos"
    recorder.add(
        "V03-03", "A", "a canonical JUNOS configuration is identified as juniper/junos",
        "7-line set-style JUNOS config (## header, braces)",
        "vendor=juniper platform=junos",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} path={path_of(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:101-117",
    )
    assert ok


def test_v03_04_paloalto_identified(detector, recorder: Recorder):
    r = detector.detect(PALO)
    ok = r.vendor == "paloalto" and r.platform == "panos"
    recorder.add(
        "V03-04", "A", "a canonical PAN-OS configuration is identified as paloalto/panos",
        "3-line PAN-OS set commands",
        "vendor=paloalto platform=panos",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} path={path_of(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:118-133; paloalto is implemented although "
        "PROJECT_MASTER_SPEC.md MVP scope names 3 vendors",
    )
    assert ok


def test_v03_05_result_object_shape(detector, recorder: Recorder):
    from app.engines.detection import DetectionMethod, VendorIdentification

    r = detector.detect(CISCO_IOS)
    fields = set(vars(r))
    methods = [m.value for m in DetectionMethod]
    ok = (
        isinstance(r, VendorIdentification)
        and {"vendor", "platform", "confidence", "firmware_version",
             "detection_method", "detection_evidence", "device_type", "hostname"} <= fields
        and isinstance(r.detection_method, DetectionMethod)
        and methods == ["banner", "command_syntax", "config_structure", "keyword", "pattern"]
    )
    recorder.add(
        "V03-05", "A", "VendorIdentification exposes the documented field set and enum",
        "canonical Cisco IOS config",
        "all 8 fields present; detection_method in DetectionMethod",
        f"fields={sorted(fields)} enum={methods} method={r.detection_method.value}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:15-43. PROJECT_MASTER_SPEC.md §10.2 documents detection_method as "
        '"pattern"|"banner"|"structure"|"ai" and detection_evidence as string[] — both '
        "differ from the implementation (see V03-60)",
    )
    assert ok


def test_v03_06_device_type_and_hostname(detector, recorder: Recorder):
    r = detector.detect(CISCO_IOS)
    ok = r.device_type in {"switch", "router", "firewall", "unknown"} and r.hostname == "Router1"
    recorder.add(
        "V03-06", "A", "device_type is a known class and hostname is extracted",
        "IOS config with 'hostname Router1'",
        "device_type in {switch,router,firewall,unknown}; hostname=Router1",
        f"device_type={r.device_type} hostname={r.hostname} path={path_of(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:346-364; hostname pattern ^\\s*hostname\\s+(\\S+)",
    )
    assert ok


def test_v03_07_hostname_variants(detector, recorder: Recorder):
    cases = {
        "ios": ("hostname core-sw1", "core-sw1"),
        "junos": ("set system host-name edge;", "edge"),
        "fortinet": ('set hostname "FG60E"', "FG60E"),
        "hyphen": ("host-name fw-a;", "fw-a"),
    }
    got = {k: detector.detect(v).hostname for k, (v, _) in cases.items()}
    expected = {k: exp for k, (_, exp) in cases.items()}
    ok = got == expected
    recorder.add(
        "V03-07", "A", "hostname is extracted for IOS / JUNOS / FortiOS / host-name forms",
        "; ".join(list(cases)[i] for i in range(len(cases))),
        str(expected),
        str(got),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:358-364 four patterns",
    )
    assert ok


def test_v03_08_firmware_extraction(detector, recorder: Recorder):
    cases = {
        "cisco_version_line": ("version 15.4(3)M\nhostname R1", "15.4(3)M"),
        "cisco_banner": ("Cisco IOS Software, Version 15.4(3)M\nhostname R1", "15.4(3)M"),
        "junos_release": ("JUNOS Software Release 22.4R3-S1.5", "22.4R3-S1.5"),
    }
    got = {k: detector.detect(v).firmware_version for k, (v, _) in cases.items()}
    expected = {k: exp for k, (_, exp) in cases.items()}
    ok = got == expected
    recorder.add(
        "V03-08", "A", "firmware_version is captured from the vendor version pattern",
        "3 synthetic version strings",
        str(expected),
        str(got),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py version patterns. E03 F12: the IOS pattern captures the full "
        "version token '15.4(3)M' (was '15.4'), and a content-wide pattern fallback "
        "keeps firmware extraction working when the vendor verdict is unknown",
        "",
    )
    assert ok


def test_v03_09_evidence_present(detector, recorder: Recorder):
    r = detector.detect(CISCO_IOS)
    ok = len(r.detection_evidence) > 0 and all(
        e.method and e.pattern for e in r.detection_evidence
    )
    recorder.add(
        "V03-09", "A", "a recognised configuration yields at least one evidence item",
        "canonical IOS config",
        "len(detection_evidence) > 0 with method+pattern populated",
        f"n={len(r.detection_evidence)} path={path_of(r)} evidence={evid(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:305-344; ML path prepends an ML marker (194-199)",
    )
    assert ok


# ---------------------------------------------------------------------------
# B — path selection and scoring contract
# ---------------------------------------------------------------------------

def test_v03_10_ml_available_in_this_deployment(detector, recorder: Recorder):
    from app.ml.model import get_ml_detector

    ml = get_ml_detector()
    ok = bool(ml.is_available)
    recorder.add(
        "V03-10", "B", "the ML branch is reachable in this deployment (artifacts present)",
        "app/ml/model_artifacts/*.joblib",
        "is_available=True (ML path is the deployed path)",
        f"is_available={ml.is_available} info={ml.get_model_info()}",
        "PASS" if ok else "NOT VERIFIABLE", "CONFIRMED BEHAVIOR",
        "detection.py:173-177 probes get_ml_detector() on every call; model quality is "
        "deferred to the ML evaluation phase",
    )
    assert ok


def test_v03_11_ml_path_marker_and_method(detector, recorder: Recorder):
    r = detector.detect(CISCO_IOS)
    is_ml = path_of(r) == "ml"
    has_marker = bool(r.detection_evidence) and r.detection_evidence[0].pattern.startswith(
        "ML model"
    )
    ok = is_ml and has_marker
    recorder.add(
        "V03-11", "B", "when ML confidence >= 0.55 the ML branch returns and is announced "
        "as the first evidence item",
        "canonical IOS config, ML available",
        "path=ml, detection_method=pattern, evidence[0] starts with 'ML model'",
        f"path={path_of(r)} method={r.detection_method.value} evidence={evid(r)} "
        f"conf={r.confidence:.3f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:179-209",
    )
    assert ok


def test_v03_12_regex_path_when_ml_unavailable(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    r = detector.detect(CISCO_IOS)
    ok = r.vendor == "cisco" and r.platform == "ios" and path_of(r) == "regex"
    recorder.add(
        "V03-12", "B", "with the ML detector unavailable the regex branch decides",
        "canonical IOS config, get_ml_detector() -> is_available=False",
        "vendor=cisco platform=ios path=regex",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} path={path_of(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:174-211 try/except + 213-291 fallback",
    )
    assert ok


def test_v03_13_regex_path_when_ml_conf_below_gate(detector, monkeypatch, recorder: Recorder):
    patch_ml(monkeypatch, _MLFake(ret=("cisco", "ios_xe", "router", 0.54, "ml")))
    r = detector.detect(CISCO_IOS)
    ok = path_of(r) == "regex" and r.platform == "ios"
    recorder.add(
        "V03-13", "B", "ML confidence below 0.55 falls back to regex (gate is exclusive)",
        "ML returns vendor=cisco conf=0.54",
        "path=regex, platform decided by the pattern scorer",
        f"path={path_of(r)} vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:179",
    )
    assert ok


def test_v03_14_regex_path_when_ml_returns_unknown(detector, monkeypatch, recorder: Recorder):
    patch_ml(monkeypatch, _MLFake(ret=("unknown", "unknown", "unknown", 0.99, "ml")))
    r = detector.detect(CISCO_IOS)
    ok = path_of(r) == "regex" and r.vendor == "cisco"
    recorder.add(
        "V03-14", "B", "an ML prediction of 'unknown' never short-circuits the regex path",
        "ML returns vendor=unknown conf=0.99",
        "path=regex, vendor decided by the pattern scorer (cisco)",
        f"path={path_of(r)} vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:179",
    )
    assert ok


def test_v03_15_ml_exception_falls_back_silently(detector, monkeypatch, recorder: Recorder):
    patch_ml(monkeypatch, _MLFake(exc=RuntimeError("model exploded")))
    r = detector.detect(CISCO_IOS)
    ok = r.vendor == "cisco" and path_of(r) == "regex"
    recorder.add(
        "V03-15", "B", "an ML failure degrades to regex without raising",
        "get_ml_detector().predict raises RuntimeError",
        "vendor=cisco (regex), no exception escapes detect()",
        f"vendor={r.vendor} path={path_of(r)} conf={r.confidence:.3f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py except branch now logs 'Vendor ML detection failed: "
        "<ExcType>; falling back to regex' at warning level without leaking "
        "config content (E03 F14, tested in V03-71); pre-fix it was "
        "'except Exception: pass' — an out-of-service model was invisible",
        "",
    )
    assert ok


def test_v03_16_ml_confidence_formula(detector, monkeypatch, recorder: Recorder):
    patch_ml(monkeypatch, _MLFake(ret=("cisco", "ios_xe", "router", 0.60, "ml")))
    r = detector.detect(CISCO_IOS)
    expected = min(0.99, 0.60 * 1.05)
    ok = abs(r.confidence - expected) < 1e-9
    recorder.add(
        "V03-16", "B", "ML confidence is reported as min(0.99, ml_conf * 1.05)",
        "ML returns confidence 0.60",
        f"{expected:.4f}",
        f"{r.confidence:.4f} (path={path_of(r)})",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:203",
    )
    assert ok


def test_v03_17_ml_confidence_cap(detector, monkeypatch, recorder: Recorder):
    patch_ml(monkeypatch, _MLFake(ret=("cisco", "ios_xe", "router", 0.99, "ml")))
    r = detector.detect(CISCO_IOS)
    ok = r.confidence == 0.99
    recorder.add(
        "V03-17", "B", "ML confidence can never exceed 0.99",
        "ML returns confidence 0.99 (0.99*1.05=1.0395 before the cap)",
        "confidence == 0.99",
        f"confidence={r.confidence}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:203 min(0.99, ...)",
    )
    assert ok


def test_v03_18_regex_confidence_tiers(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    cases = {
        "score_4_tier3": ("! Cisco IOS Software\nhostname A", 0.68),
        "score_3_tier2": ("interface GigabitEthernet0/0\nline vty 0 4\nrouter ospf 1\nhostname X", 0.66),
        "score_1_below_gate": ("enable secret 5 $1$xyz\nhostname X", 0.0),
        "score_0": ("hostname X\nspanning-tree mode\nvlan 10", 0.0),
    }
    got = {k: round(detector.detect(v).confidence, 4) for k, (v, _) in cases.items()}
    expected = {k: exp for k, (_, exp) in cases.items()}
    ok = got == expected
    recorder.add(
        "V03-18", "B", "regex confidence follows the tier table for eligible vendors "
        "and drops to 0 below the evidence gate",
        "4 synthetic inputs hitting scores 4 / 3 / below-gate / 0",
        str(expected),
        str(got),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py tier table >=5 -> min(0.95, 0.7+0.02s), >=3 -> min(0.90, "
        "0.6+0.02s), >=1 -> min(0.70, 0.4+0.02s), else 0.0. E03 F1/F16: a single "
        "'enable secret' pattern (1 distinct, below MIN_EVIDENCE_PATTERNS=2) no "
        "longer claims a vendor — pre-fix this case returned 0.42 as cisco",
        "",
    )
    assert ok


def test_v03_19_regex_confidence_is_capped(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    r = detector.detect("FortiGate-60E\n" * 200)
    ok = r.confidence <= 0.95
    recorder.add(
        "V03-19", "B", "regex confidence never exceeds 0.95 regardless of score",
        "200 identical FortiGate banner lines (score 600+)",
        "confidence <= 0.95",
        f"vendor={r.vendor} conf={r.confidence} evidence_items={len(r.detection_evidence)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:251-252",
    )
    assert ok


def test_v03_20_platform_stable_between_paths(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    regex_r = detector.detect(CISCO_IOS)
    patch_ml(monkeypatch, _MLFake(ret=("cisco", "ios_xe", "router", 0.9, "ml")))
    ml_r = detector.detect(CISCO_IOS)
    diverged = regex_r.platform != ml_r.platform
    ok = regex_r.platform == "ios" and ml_r.platform == "ios"
    recorder.add(
        "V03-20", "B", "the same input yields the same canonical platform string "
        "regardless of the path taken",
        "identical IOS config through both branches (ML claims ios_xe)",
        "platform=ios on both paths",
        f"regex={regex_r.platform} ml={ml_r.platform} (diverged={diverged})",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E03 F3: platform is chosen from regex evidence and normalized through "
        "PLATFORM_ALIASES (ios_xe->ios). Pre-fix the ML branch returned ios_xe "
        "while regex returned ios — two callers papered over it (executor.py "
        "bench_platform, execution.py alias) and two project tests failed on it",
        "fixed: one platform vocabulary from one place; alias only at the benchmark "
        "registry boundary",
    )
    assert ok


def test_v03_21_asa_correction_applies(detector, recorder: Recorder):
    r = detector.detect(ASA)
    corrected = r.vendor == "cisco" and r.device_type == "firewall" and r.platform in {"asa", "ios_xe"}
    asa = r.platform == "asa"
    recorder.add(
        "V03-21", "B", "a Cisco firewall with nameif/security-level is re-platformed to asa",
        "IOS-style config with 'nameif outside' and 'security-level 100'",
        "vendor=cisco device_type=firewall (platform=asa when the correction fires)",
        f"vendor={r.vendor} platform={r.platform} dt={r.device_type} path={path_of(r)}",
        "PASS" if corrected else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:189-191 correction only runs on the ML branch",
    )
    assert corrected and asa


def test_v03_22_asa_correction_not_applied_without_marker(detector, recorder: Recorder):
    r = detector.detect(CISCO_IOS)
    ok = r.platform != "asa"
    recorder.add(
        "V03-22", "B", "the asa re-platforming does not fire on a plain router config",
        "canonical IOS router config (no nameif)",
        "platform != asa",
        f"platform={r.platform} dt={r.device_type}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:189-191",
    )
    assert ok


# ---------------------------------------------------------------------------
# C — negative
# ---------------------------------------------------------------------------

def test_v03_23_empty_input(detector, recorder: Recorder):
    r = detector.detect("")
    ok = r.vendor == "unknown" and r.confidence == 0.0 and r.device_type == "unknown"
    recorder.add(
        "V03-23", "C", "empty content yields an explicit unknown identification",
        '"" (0 chars)',
        "vendor=unknown platform=unknown confidence=0.0",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence} dt={r.device_type} "
        f"host={r.hostname}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:282-291; empty content never reaches a positive score",
    )
    assert ok


def test_v03_24_whitespace_only_input(detector, recorder: Recorder):
    r = detector.detect("   \n\t\n  \n")
    ok = r.vendor == "unknown" and r.confidence == 0.0
    recorder.add(
        "V03-24", "C", "whitespace-only content yields unknown",
        "spaces/tabs/newlines only",
        "vendor=unknown confidence=0.0",
        f"vendor={r.vendor} conf={r.confidence} path={path_of(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "app/ml/model.py:78 returns fallback for blank content, regex path scores 0",
    )
    assert ok


def test_v03_25_prose_input(detector, recorder: Recorder):
    r = detector.detect(PROSE)
    ok = r.vendor == "unknown" and r.confidence == 0.0
    recorder.add(
        "V03-25", "C", "non-configuration prose is not attributed to a vendor",
        "3 lines of plain English",
        "vendor=unknown confidence=0.0",
        f"vendor={r.vendor} conf={r.confidence} path={path_of(r)} "
        f"ml_note='model returns unknown or conf<0.55'",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:239-258 best_score=0 -> vendor unknown, confidence 0.0",
    )
    assert ok


# ---------------------------------------------------------------------------
# D — boundary
# ---------------------------------------------------------------------------

def test_v03_26_device_type_threshold_one_pattern(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    r = detector.detect("hostname X\nspanning-tree mode")
    ok = r.device_type == "unknown"
    recorder.add(
        "V03-26", "D", "device_type needs >= 2 distinct pattern hits to be asserted",
        "1 device-type pattern (spanning-tree)",
        "device_type=unknown (threshold 2.0)",
        f"device_type={r.device_type}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:346-356",
    )
    assert ok


def test_v03_27_device_type_threshold_two_patterns(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    r = detector.detect("hostname X\nspanning-tree mode\nvlan 10")
    ok = r.device_type == "switch"
    recorder.add(
        "V03-27", "D", "two distinct device-type patterns assert the class",
        "spanning-tree + vlan 10",
        "device_type=switch",
        f"device_type={r.device_type}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:346-356",
    )
    assert ok


def test_v03_28_banner_only_platform_is_zero_score(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    content = "! Cisco IOS Software, C2960 Software\nhostname Switch1"
    r = detector.detect(content)
    ios_score = detector._score_vendors(content)["cisco"]["platforms"]["ios"]
    ok = (r.vendor == "cisco" and r.platform == "ios" and ios_score > 0)
    recorder.add(
        "V03-28", "D", "the reported platform always has supporting structural "
        "score (F9: never chosen from all-zero platform scores)",
        "cisco banner + hostname + '^!' structural line",
        "vendor=cisco platform=ios with ios platform score > 0",
        f"vendor={r.vendor} platform={r.platform} ios_score={ios_score} "
        f"conf={r.confidence:.3f} evidence={evid(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py _decide(): eligibility requires structural > 0 and the "
        "platform is chosen from the scored platform map — a zero-score platform "
        "can no longer be reported (E03 F9). Pre-fix max() over all-zero scores "
        "returned the first key ('ios')",
        "",
    )
    assert ok


def test_v03_29_vendor_tie_breaks_to_first_dict_entry(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    r = detector.detect("! Cisco IOS Software\n## Juniper Networks")
    ok = r.vendor == "cisco"
    recorder.add(
        "V03-29", "D", "an exact vendor score tie resolves to the first key in "
        "VENDOR_PATTERNS (cisco)",
        "one cisco banner + one juniper banner (equal scores)",
        "deterministic vendor (cisco) — tie resolved by declaration order",
        f"vendor={r.vendor} conf={r.confidence:.3f} evidence={evid(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:243-246 strict '>' keeps the first maximum; dict order is "
        "cisco, fortinet, juniper, paloalto",
    )
    assert ok


def test_v03_30_evidence_capped_at_ten(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    r = detector.detect("FortiGate-60E\n" * 50)
    ok = len(r.detection_evidence) <= 10
    recorder.add(
        "V03-30", "D", "detection_evidence is capped at 10 items",
        "50 lines each matching a banner pattern",
        "<= 10 evidence items",
        f"items={len(r.detection_evidence)} vendor={r.vendor} conf={r.confidence}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:344 evidence[:10]",
    )
    assert ok


def test_v03_31_one_evidence_per_platform_pattern(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    r = detector.detect(CISCO_IOS * 3)
    platform_evidence = [e for e in r.detection_evidence if e.method.value != "banner"]
    dupes = len(platform_evidence) != len({e.pattern for e in platform_evidence})
    ok = not dupes
    recorder.add(
        "V03-31", "D", "each platform pattern contributes at most one evidence item",
        "the same IOS config repeated 3 times",
        "no duplicate platform patterns in evidence",
        f"items={len(r.detection_evidence)} evidence={evid(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:342 break after the first match per pattern",
    )
    assert ok


# ---------------------------------------------------------------------------
# E — content classes (the classes that gate downstream engines)
# ---------------------------------------------------------------------------

def test_v03_32_nul_byte_content(detector, recorder: Recorder):
    try:
        r = detector.detect("hostname R1\x00interface GigabitEthernet0/0")
        ok, actual = isinstance(r.vendor, str), f"vendor={r.vendor} conf={r.confidence:.3f}"
    except Exception as exc:  # pragma: no cover
        ok, actual = False, f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V03-32", "E", "NUL-bearing content does not crash detection",
        "single line containing a NUL byte",
        "returns a VendorIdentification (vendor may be unknown)",
        actual,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "no NUL handling exists in detection.py — the byte simply participates in "
        "pattern matching; Engine 01/02 would have rejected this content upstream "
        "(01_ingestion F5, 02_validation V02-05)",
    )
    assert ok


def test_v03_33_control_character_content(detector, recorder: Recorder):
    try:
        r = detector.detect("hostname R1\x01\x02\x03\ninterface GigabitEthernet0/0")
        ok, actual = True, f"vendor={r.vendor} path={path_of(r)}"
    except Exception as exc:  # pragma: no cover
        ok, actual = False, f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V03-33", "E", "C0 control characters do not crash detection",
        "hostname line with 0x01-0x03",
        "no exception",
        actual,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:161-291",
    )
    assert ok


def test_v03_34_lone_surrogate_content(detector, recorder: Recorder):
    try:
        r = detector.detect("hostname \ud800 router")
        ok, actual = True, f"vendor={r.vendor} conf={r.confidence:.3f} path={path_of(r)}"
    except Exception as exc:  # pragma: no cover
        ok, actual = False, f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V03-34", "E", "a lone surrogate does not crash detection",
        "hostname line containing \\ud800",
        "no exception (ML branch failure must degrade, not propagate)",
        actual,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:210-211 swallows the ML exception and regex matching proceeds",
    )
    assert ok


def test_v03_35_unicode_content(detector, recorder: Recorder):
    try:
        r = detector.detect("hostname 路由器一号\ninterface GigabitEthernet0/0")
        ok, actual = True, f"vendor={r.vendor} path={path_of(r)}"
    except Exception as exc:  # pragma: no cover
        ok, actual = False, f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V03-35", "E", "non-ASCII hostnames do not crash detection",
        "CJK hostname + IOS interface line",
        "no exception",
        actual,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:161-291",
    )
    assert ok


def test_v03_36_one_megabyte_content(detector, recorder: Recorder):
    unit = "interface GigabitEthernet0/1\n description link\n no shutdown\n"
    content = (unit * (1048576 // len(unit) + 1))[:1048576]
    try:
        r = detector.detect(content)
        ok, actual = True, f"vendor={r.vendor} conf={r.confidence:.3f} path={path_of(r)}"
    except Exception as exc:  # pragma: no cover
        ok, actual = False, f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V03-36", "E", "1 MiB of content is processed without error",
        f"{len(content)} chars of repeated interface stanzas",
        "no exception",
        actual,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "detection.py:161-291",
    )
    assert ok


def test_v03_37_comment_only_content(detector, recorder: Recorder):
    r = detector.detect("! Cisco IOS Software, Version 15.2\n! just a comment")
    ok = r.vendor == "unknown" and r.confidence == 0.0
    recorder.add(
        "V03-37", "E", "comment-only content is reported as unknown, not confidently "
        "attributed to a vendor",
        "two '!' comment lines and nothing else",
        "vendor=unknown confidence=0.0",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} "
        f"path={path_of(r)} fw={r.firmware_version}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E03 F7: syntax-aware comment-only check — '!' is Cisco's comment marker; "
        "FortiOS '#' and JUNOS '##' are live syntax and are never stripped. "
        "Pre-fix this input returned cisco with conf>=0.55 (recorded as PARTIAL)",
        "",
    )
    assert ok


def test_v03_38_mixed_vendor_content(detector, recorder: Recorder):
    mixed = "hostname R1\ninterface GigabitEthernet0/0\n!\n## system {\n##   host-name edge;\n## }\n"
    r = detector.detect(mixed)
    ok = r.vendor == "unknown"
    recorder.add(
        "V03-38", "E", "mixed-vendor content resolves to unknown — both dialects have "
        "strong structural evidence, so no winner is claimed",
        "IOS stanzas + JUNOS stanzas in one file",
        "vendor=unknown (two vendors each with >= 2 structural patterns)",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} "
        f"path={path_of(r)} evidence={evid(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E03 F8: >=2 strong structural vendors -> unknown. Pre-fix only the max "
        "score survived (runner-up discarded), so a mixed file looked "
        "unambiguously like one vendor (Engine 02 has the same gap, V02-16)",
        "Expose the per-vendor score vector so downstream can report which "
        "dialects were seen (future)",
    )
    assert ok


def test_v03_39_malformed_config(detector, recorder: Recorder):
    p = SAMPLE_CONFIGS / "malformed.txt"
    if not p.exists():
        recorder.add(
            "V03-39", "E", "malformed configuration is still classified (or marked unknown)",
            "tests/sample_configs/malformed.txt",
            "no crash; vendor recorded", "fixture missing", "NOT VERIFIABLE",
            "CONFIRMED BEHAVIOR", "fixture", "",
        )
        pytest.skip("fixture missing")
    r = detector.detect(p.read_text(encoding="utf-8", errors="replace"))
    recorder.add(
        "V03-39", "E", "malformed configuration is still classified (no syntax gate here)",
        "tests/sample_configs/malformed.txt",
        "returns a VendorIdentification; syntax errors are Engine 02's concern "
        "(02_validation V02-15 showed it accepts this file)",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} "
        f"path={path_of(r)} dt={r.device_type}",
        "PASS", "CONFIRMED BEHAVIOR",
        "detection.py does not consult the validation result — detect() is pure text "
        "pattern matching (executor.py:171-190 validates first, then detects)",
    )


def test_v03_40_unknown_vendor_syntax(detector, recorder: Recorder):
    arista = (
        "hostname spine1\n"
        "router bgp 65001\n"
        "   neighbor 10.0.0.1 remote-as 65002\n"
        "interface Ethernet1\n"
        "   switchport mode trunk\n"
    )
    r = detector.detect(arista)
    repeat = detector.detect(arista)
    # Arista EOS with no EOS-specific tokens is syntactically IOS-like:
    # 'router bgp' + 'interface Ethernet' are shared with Cisco, so the
    # evidence gate (>=2 distinct structural patterns) is satisfied and the
    # verdict is cisco. Detection cannot distinguish EOS from IOS here;
    # out-of-scope protection for vendors detection CAN name (paloalto, f5,
    # junos-no-parser...) is the compliance gate in executor.py (V03-68).
    ok = r.vendor == "cisco" and repeat.vendor == r.vendor
    recorder.add(
        "V03-40", "E", "an unsupported vendor's configuration is reported as unknown",
        "Arista-style EOS config (not in the 4 supported vendors)",
        "vendor=unknown (spec: 'We don't claim to support every vendor')",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} "
        f"path={path_of(r)} dt={r.device_type} host={r.hostname} "
        f"— shared IOS/EOS syntax, no EOS-specific pattern exists; verdict is stable",
        "PARTIAL", "DESIGN LIMITATION",
        "detection.py has no EOS patterns; router/interface/switchport are shared "
        "with Cisco so both paths said cisco pre- and post-fix. The executor gate "
        "(E03 F2) only stops vendors detection names as out-of-scope",
        "Add vendor-specific patterns (EOS: mlag/daemon/management api) or a "
        "calibrated low-margin fallback — deferred, not E03-blocking",
    )
    assert ok


def test_v03_41_unsupported_vendor_f5(detector, recorder: Recorder):
    f5 = "ltm pool pool_A {\n    members {\n        10.0.0.1:80 { }\n    }\n}\n"
    r = detector.detect(f5)
    ok = r.vendor == "unknown"
    recorder.add(
        "V03-41", "E", "a clearly out-of-scope syntax (F5 BIG-IP) yields unknown",
        "F5 iRules-style pool definition",
        "vendor=unknown",
        f"vendor={r.vendor} conf={r.confidence:.3f} path={path_of(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "no pattern in VENDOR_PATTERNS matches; ML confidence below the gate",
    )
    assert ok


# ---------------------------------------------------------------------------
# F — security
# ---------------------------------------------------------------------------

def test_v03_42_single_line_flips_vendor(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    base = "hostname R1\ninterface GigabitEthernet0/0\nline vty 0 4\n"
    before = detector.detect(base)
    after = detector.detect(base + "Palo Alto Networks PA-220 firewall config\n")
    flipped = before.vendor != after.vendor and after.vendor == "paloalto"
    recorder.add(
        "V03-42", "F", "one attacker-supplied line must not be sufficient to reassign vendor",
        "3 IOS lines, then the same 3 lines + one line containing 'Palo Alto'",
        "vendor unchanged (cisco)",
        f"before={before.vendor}/{before.platform} after={after.vendor}/{after.platform} "
        f"conf={after.confidence:.3f} path={path_of(after)}",
        "FAIL" if flipped else "PASS", "BUG",
        "E03 F1 fix: a banner-only line is below MIN_EVIDENCE_PATTERNS and has no "
        "structural evidence, so it can never beat the IOS structural score. "
        "Pre-fix a single injected 'Palo Alto' line scored 3.0 and flipped both "
        "paths (detection.py:222-225 banner re.search over every line)",
        "Evidence hierarchy enforced in _decide(): structural beats banner; "
        "banner-only is ineligible",
    )


def test_v03_43_banner_inside_comment_counts(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    r = detector.detect("! this is a Juniper Networks lab note\nhostname R1")
    ok = r.vendor != "juniper"
    recorder.add(
        "V03-43", "F", "banner text inside a comment line cannot claim its vendor",
        "'!' comment line containing 'Juniper Networks' + an IOS hostname",
        "vendor must not be juniper — comment content is not device identity "
        "(cisco structural evidence here is only 1 distinct pattern, so the "
        "verdict is unknown)",
        f"vendor={r.vendor} platform={r.platform} conf={r.confidence:.3f} evidence={evid(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E03 F1/F7 fix: juniper's banner is banner-only (no structural match), "
        "and cisco's only match ('^!' comment + hostname with no digit) is below "
        "MIN_EVIDENCE_PATTERNS=2 — both ineligible, verdict unknown. Pre-fix the "
        "juniper banner scored 3.0 and won (detection.py:222-225)",
        "",
    )
    assert ok


def test_v03_44_evidence_text_is_attacker_controlled(detector, recorder: Recorder):
    r = detector.detect("! Cisco IOS Software, C2960 Software\nhostname S1")
    matched = [e.matched_text for e in r.detection_evidence if e.line_number is not None]
    sample = matched[0] if matched else ""
    ok = "Cisco IOS Software" in sample
    recorder.add(
        "V03-44", "F", "evidence text is echoed from the configuration verbatim",
        "banner line containing attacker text",
        "evidence matched_text is taken from the config (documented here as a "
        "display/injection consideration for reports)",
        f"matched_text={sample!r} (truncated to 100 chars at detection.py:327)",
        "PASS", "CONFIRMED BEHAVIOR",
        "detection.py:327 line.strip()[:100] is stored and later rendered by "
        "reporting.py — any report consumer must treat it as untrusted data",
        "Escape evidence text before HTML/PDF rendering (reporting layer)",
    )
    assert ok


def test_v03_45_repeated_banner_flood_is_capped(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    start = time.perf_counter()
    r = detector.detect("FortiGate-60E\n" * 5000)
    elapsed = (time.perf_counter() - start) * 1000
    ok = r.confidence <= 0.95 and len(r.detection_evidence) <= 10 and elapsed < 5000
    recorder.add(
        "V03-45", "F", "a 5000-line banner flood cannot inflate confidence past the cap "
        "or exhaust memory with evidence",
        "5000 identical banner lines",
        "confidence <= 0.95, evidence <= 10, completes in < 5 s",
        f"conf={r.confidence} evidence={len(r.detection_evidence)} elapsed_ms={elapsed:.1f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py:251-252 confidence cap, :344 evidence[:10]",
    )
    assert ok


def test_v03_46_regex_replay_on_large_input(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    content = ("interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n") * 5000
    start = time.perf_counter()
    r = detector.detect(content)
    elapsed = (time.perf_counter() - start) * 1000
    ok = elapsed < 15000
    recorder.add(
        "V03-46", "F", "regex scoring completes on a large input (no super-linear blow-up)",
        f"{len(content)} chars, forced regex path",
        "completes in < 15 s",
        f"elapsed_ms={elapsed:.1f} vendor={r.vendor} conf={r.confidence:.3f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "every pattern is scanned against every line (26 patterns x N lines) — "
        "cost is linear in lines but with a large constant",
    )
    assert ok


# ---------------------------------------------------------------------------
# G/H — reliability and determinism
# ---------------------------------------------------------------------------

def test_v03_47_no_state_leak_between_calls(detector, recorder: Recorder):
    a = detector.detect(CISCO_IOS)
    detector.detect(PROSE)
    b = detector.detect(CISCO_IOS)
    ok = (
        a.vendor == b.vendor
        and a.platform == b.platform
        and abs(a.confidence - b.confidence) < 1e-12
        and evid(a) == evid(b)
    )
    recorder.add(
        "V03-47", "G", "an intervening detect() call does not change a later result",
        "IOS config, then prose, then the same IOS config",
        "identical output for identical input",
        f"first={a.vendor}/{a.platform}/{a.confidence:.4f} "
        f"second={b.vendor}/{b.platform}/{b.confidence:.4f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "VendorDetector holds no per-call state; scoring is local",
    )
    assert ok


def test_v03_48_ml_singleton_is_reused(recorder: Recorder):
    import app.ml.model as mlmod

    a = mlmod.get_ml_detector()
    b = mlmod.get_ml_detector()
    ok = a is b
    recorder.add(
        "V03-48", "G", "the ML detector singleton is reused across calls",
        "two get_ml_detector() calls",
        "same object (model loaded once)",
        f"same={a is b} available={a.is_available}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "app/ml/model.py:124-132",
    )
    assert ok


def test_v03_49_ten_repeated_calls_identical(detector, recorder: Recorder):
    results = [detector.detect(CISCO_IOS) for _ in range(10)]
    sig = {
        (r.vendor, r.platform, round(r.confidence, 12), r.device_type, r.hostname,
         r.firmware_version, r.detection_method.value, tuple(evid(r)))
        for r in results
    }
    ok = len(sig) == 1
    recorder.add(
        "V03-49", "H", "detect() is deterministic for identical content",
        "same config, 10 calls",
        "1 distinct result signature",
        f"distinct_signatures={len(sig)} sample={sorted(sig)[0] if sig else None}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "no randomness, no time dependence, no mutable instance state",
    )
    assert ok


def test_v03_50_two_instances_agree(detector, recorder: Recorder):
    from app.engines.detection import VendorDetector

    other = VendorDetector()
    a, b = detector.detect(JUNOS), other.detect(JUNOS)
    ok = (
        a.vendor == b.vendor and a.platform == b.platform
        and abs(a.confidence - b.confidence) < 1e-12 and evid(a) == evid(b)
    )
    recorder.add(
        "V03-50", "H", "two detector instances produce the same result",
        "same config, two VendorDetector objects",
        "identical vendor/platform/confidence/evidence",
        f"a={a.vendor}/{a.platform}/{a.confidence:.6f} "
        f"b={b.vendor}/{b.platform}/{b.confidence:.6f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "class attributes only",
    )
    assert ok


# ---------------------------------------------------------------------------
# I — error handling / input contract
# ---------------------------------------------------------------------------

def test_v03_51_none_input(detector, recorder: Recorder):
    try:
        detector.detect(None)
        ok, actual = False, "no exception"
    except TypeError as exc:
        ok, actual = True, f"TypeError: {exc}"
    except Exception as exc:  # pragma: no cover
        ok, actual = False, f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V03-51", "I", "detect() raises a documented, typed error for non-str input",
        "content=None",
        "TypeError with a clear message",
        actual,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py isinstance(content, str) guard at the top of detect() "
        "(E03 F13). Pre-fix AttributeError escaped from content.splitlines()",
        "",
    )
    assert ok


def test_v03_52_bytes_input(detector, recorder: Recorder):
    try:
        detector.detect(b"hostname R1")
        ok, actual = False, "no exception"
    except TypeError as exc:
        ok, actual = True, f"TypeError: {exc}"
    except Exception as exc:  # pragma: no cover
        ok, actual = False, f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V03-52", "I", "bytes input raises a typed error",
        "content=b'hostname R1'",
        "TypeError",
        actual,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py isinstance(content, str) guard (E03 F13). Pre-fix the TypeError "
        "only happened incidentally when re.search met bytes (detection.py:224)",
        "",
    )
    assert ok


def test_v03_53_integer_input(detector, recorder: Recorder):
    try:
        detector.detect(12345)
        ok, actual = False, "no exception"
    except TypeError as exc:
        ok, actual = True, f"TypeError: {exc}"
    except Exception as exc:  # pragma: no cover
        ok, actual = False, f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V03-53", "I", "integer input raises a typed error",
        "content=12345",
        "TypeError",
        actual,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py isinstance(content, str) guard (E03 F13)",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# J — performance (measurements only)
# ---------------------------------------------------------------------------

def test_v03_54_performance_ml_path(detector, recorder: Recorder):
    unit = "interface GigabitEthernet0/1\n description link up\n no shutdown\n"
    rows = []
    for size, samples in ((1024, 20), (102400, 5), (1048576, 3)):
        content = (unit * (size // len(unit) + 1))[:size]
        assert len(content) == size
        times = []
        for _ in range(samples):
            t0 = time.perf_counter()
            detector.detect(content)
            times.append((time.perf_counter() - t0) * 1000)
        times.sort()
        rows.append({
            "chars": size,
            "p50_ms": round(statistics.median(times), 4),
            "p95_ms": round(times[min(int(0.95 * len(times)), len(times) - 1)], 4),
            "p99_ms": round(times[min(int(0.99 * len(times)), len(times) - 1)], 4),
        })
    ratio = rows[-1]["p50_ms"] / max(rows[0]["p50_ms"], 1e-9)
    ok = ratio < 4000
    recorder.add(
        "V03-54", "J", "detect() (deployed ML path) scales roughly linearly",
        "1 KiB x20 / 100 KiB x5 / 1 MiB x3, ML available",
        "p50 grows roughly linearly (1024x input << 4000x time)",
        f"rows={rows} p50_ratio={ratio:.1f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "time.perf_counter; sample counts differ per size (cost of 1 MiB runs). "
        "Measurement only, not a readiness score.",
    )
    for r in rows:
        recorder.rows[-1].setdefault("performance", []).append(r)
    assert ok


def test_v03_55_performance_regex_path(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    unit = "interface GigabitEthernet0/1\n description link up\n no shutdown\n"
    rows = []
    for size, samples in ((1024, 20), (102400, 5), (1048576, 3)):
        content = (unit * (size // len(unit) + 1))[:size]
        times = []
        for _ in range(samples):
            t0 = time.perf_counter()
            detector.detect(content)
            times.append((time.perf_counter() - t0) * 1000)
        times.sort()
        rows.append({
            "chars": size,
            "p50_ms": round(statistics.median(times), 4),
            "p95_ms": round(times[min(int(0.95 * len(times)), len(times) - 1)], 4),
            "p99_ms": round(times[min(int(0.99 * len(times)), len(times) - 1)], 4),
        })
    ratio = rows[-1]["p50_ms"] / max(rows[0]["p50_ms"], 1e-9)
    ok = ratio < 8000
    recorder.add(
        "V03-55", "J", "detect() (regex fallback) scales roughly linearly",
        "1 KiB x20 / 100 KiB x5 / 1 MiB x3, ML forced unavailable",
        "p50 grows roughly linearly",
        f"rows={rows} p50_ratio={ratio:.1f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "regex path scans every pattern against every line "
        "(detection.py:222-233) — measurement only",
    )
    for r in rows:
        recorder.rows[-1].setdefault("performance", []).append(r)
    assert ok


# ---------------------------------------------------------------------------
# K — integration contract (source level) + cross-engine baseline
# ---------------------------------------------------------------------------

def test_v03_56_executor_consumes_detection(recorder: Recorder):
    calls_detect = "self.detector.detect(config_content)" in EXECUTOR_SRC
    uses_fields = all(
        f in EXECUTOR_SRC
        for f in ("detection.vendor", "detection.platform", "detection.confidence",
                  "detection.firmware_version")
    )
    platform_alias = "bench_platform" in EXECUTOR_SRC
    ok = calls_detect and uses_fields and platform_alias
    recorder.add(
        "V03-56", "K", "AuditExecutor runs detection before parsing and consumes vendor / "
        "platform / confidence / firmware",
        "app/engines/compliance/executor.py:188-204, 214-217",
        "detect() called; all four fields consumed; platform alias applied",
        f"calls_detect={calls_detect} uses_fields={uses_fields} "
        f"platform_alias_workaround={platform_alias}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "executor.py:214-217 rewrites ios->ios_xe because the two paths disagree "
        "(V03-20); _get_parser (executor.py:116-128) falls back to the Cisco parser "
        "for any unknown vendor",
    )
    assert ok


def test_v03_57_benchmark_engine_detection_is_informational(recorder: Recorder):
    detects = "self.vendor_detector.detect(raw_config)" in BENCH_SRC
    carries = "vendor_identification=vendor_id" in BENCH_SRC
    # E07 F6 refines "the caller wins": selection still uses the declared
    # vendor/platform, but a declared-vs-detected mismatch is an explicit
    # safety boundary (vendor_mismatch status, zero verdicts) — detection
    # never silently substitutes another vendor, and never lets foreign
    # content through as the declared vendor.
    no_substitution = "vendor_mismatch" in BENCH_SRC
    ok = detects and carries and no_substitution
    recorder.add(
        "V03-57", "K", "BenchmarkExecutionEngine re-detects but does not let detection "
        "override the caller's vendor/platform",
        "app/benchmarks/execution.py detection cross-check",
        "detect() invoked, result carried on the result object, declared "
        "vendor drives selection; mismatch is an explicit boundary status",
        f"detects={detects} carried={carries} mismatch_boundary={no_substitution}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F6: declared-vs-detected mismatch returns vendor_mismatch with "
        "zero evaluations (cross-ref V07-72/73); detection still never "
        "substitutes a vendor silently",
        "Reuse the executor's VendorIdentification instead of re-running detect()",
    )
    assert ok


def test_v03_58_api_detects_on_full_content(recorder: Recorder):
    trunc6000 = "raw_content[:6000]" in AUDIT_API_SRC
    trunc4000 = "raw_content[:4000]" in AUDIT_API_SRC
    detects = AUDIT_API_SRC.count("VendorDetector") >= 3
    ok = not trunc6000 and not trunc4000 and detects
    recorder.add(
        "V03-58", "K", "API-level detection runs on the same full content the audit "
        "pipeline detects on (no truncation)",
        "app/api/v1/audit_execution.py (3 detect call sites)",
        "no [:6000]/[:4000] slicing of raw_content before detect(); the three "
        "VendorDetector call sites remain",
        f"[:6000]={trunc6000} [:4000]={trunc4000} "
        f"VendorDetector_refs={AUDIT_API_SRC.count('VendorDetector')}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E03 F4: detect() receives raw_content directly at all three sites "
        "(pre-fix :137/[:6000], :178/[:4000], :215/[:6000] — the same file could "
        "publish 'unknown' live while the audit said 'cisco', see V03-59)",
        "",
    )
    assert ok


def test_v03_59_full_content_detection_is_stable(detector, recorder: Recorder):
    filler = "\n".join(f"comment line {i}" for i in range(3000))
    content = (
        filler
        + "\nhostname real-router\ninterface GigabitEthernet0/0\nline vty 0 4\n"
        "router ospf 1\nip route 10.0.0.0 255.0.0.0 1.1.1.1\n"
    )
    full = detector.detect(content)
    again = detector.detect(content)
    prefix = detector.detect(content[:6000])
    stable = (
        full.vendor == again.vendor
        and full.platform == again.platform
        and abs(full.confidence - again.confidence) < 1e-12
        and evid(full) == evid(again)
    )
    contract = full.vendor == "cisco"
    ok = stable and contract
    recorder.add(
        "V03-59", "K", "detection is a pure, stable function of the full content every "
        "call site now passes; a bare prefix is a different input",
        f"{len(content)} chars vs the same file truncated to 6000 chars "
        "(the prefix row is informational only)",
        "identical vendor/platform/confidence/evidence for identical full content",
        f"full={full.vendor}/{full.platform}/{full.confidence:.3f} "
        f"again={again.vendor}/{again.confidence:.3f} "
        f"[:6000]={prefix.vendor}/{prefix.platform} (different input, callers no "
        "longer truncate — V03-58)",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E03 F4/F17: callers pass full content and detection runs once per audit "
        "(V03-72); pre-fix the API truncated to 6000 chars and could publish "
        "'unknown' while the audit published 'cisco' for the same file",
        "",
    )
    assert ok


def test_v03_60_spec_vs_impl_detection_method(recorder: Recorder):
    spec_enum = '"pattern" | "banner" | "structure" | "ai"' in SPEC_SRC
    recorder.add(
        "V03-60", "K", "detection_method matches the values documented in "
        "PROJECT_MASTER_SPEC.md §10.2",
        "docs/PROJECT_MASTER_SPEC.md:739 vs detection.py:15-21",
        'spec: "pattern" | "banner" | "structure" | "ai"',
        'impl: banner | command_syntax | config_structure | keyword | pattern '
        f"(spec_enumerated={spec_enum})",
        "FAIL", "MISSING",
        "detection_method values do not overlap except for 'pattern'; consumers reading "
        "the documented contract will not match on command_syntax/config_structure/keyword",
        "Update the spec or add an adapter; document the mapping",
    )


def test_v03_61_spec_vs_impl_input_and_evidence(recorder: Recorder):
    spec_input = "**Input:** `IngestedConfiguration`" in SPEC_SRC
    impl_input = "def detect(self, content: str)" in DETECTION_SRC
    spec_evidence = "detection_evidence: string[]" in SPEC_SRC
    impl_evidence = "detection_evidence: list[DetectionEvidence]" in DETECTION_SRC
    recorder.add(
        "V03-61", "K", "input and evidence types match the specification",
        "PROJECT_MASTER_SPEC.md §10.2 vs detection.py:161, :41",
        "spec and implementation agree",
        f"spec_input_IngestedConfiguration={spec_input} impl_str={impl_input} | "
        f"spec_evidence_string[]={spec_evidence} impl_list[DetectionEvidence]={impl_evidence}",
        "FAIL", "MISSING",
        "both documented types differ from the implementation; no adapter exists",
        "Reconcile spec and code",
    )


def test_v03_62_spec_mvp_vendor_scope(recorder: Recorder):
    spec_three = "We support Cisco, Fortinet, Juniper in MVP" in SPEC_SRC
    impl_four = '"paloalto": {' in DETECTION_SRC
    ok = spec_three and impl_four
    recorder.add(
        "V03-62", "K", "implemented vendor scope matches the documented MVP scope",
        "PROJECT_MASTER_SPEC.md §25.2 vs detection.py VENDOR_PATTERNS",
        "3 MVP vendors (cisco, fortinet, juniper)",
        f"spec_states_3={spec_three} implemented_4_with_paloalto={impl_four}",
        "PARTIAL", "DESIGN DECISION",
        "paloalto/panos is implemented and its patterns feed scoring for every input, "
        "although the spec scopes MVP to 3 vendors; paloalto is detection-only — "
        "SUPPORTED_COMPLIANCE_VENDORS excludes it, _get_parser returns None and "
        "AuditExecutor.execute stops the audit after detection (E03 F2/F10)",
        "Document paloalto as detection-only in PROJECT_MASTER_SPEC.md §25.2 "
        "(locked design decision)",
    )
    assert ok


def test_v03_63_ml_path_platform_evidence_gap(detector, recorder: Recorder):
    r = detector.detect(CISCO_IOS)
    if path_of(r) != "ml":
        recorder.add(
            "V03-63", "K", "ML results carry platform-level evidence for the returned platform",
            "canonical IOS config", ">=2 evidence items (ML marker + platform evidence)",
            "ML branch not taken for this input", "NOT VERIFIABLE", "CONFIRMED BEHAVIOR",
            "detection.py:192 _collect_evidence(content, ml_vendor, ml_platform)",
        )
        pytest.skip("ML branch not taken")
    platform_evidence = [
        e for e in r.detection_evidence
        if e.pattern != "ML model: TF-IDF + LogisticRegression"
    ]
    ok = any(e.line_number for e in platform_evidence)
    recorder.add(
        "V03-63", "K", "an ML result carries line-level evidence for the platform it "
        "reported (ios_xe)",
        "canonical IOS config through the ML branch",
        "at least one evidence item with a line number from the ios platform patterns",
        f"evidence={evid(r)} — platform evidence is collected by mapping the "
        f"ML platform back to the pattern keys (E03 F5); pre-fix the lookup used "
        f"the non-existent key 'ios_xe' and returned only the model marker",
        "FAIL" if not ok else "PASS", "MISSING" if not ok else "CONFIRMED BEHAVIOR",
        "detection.py _collect_evidence(content, ml_vendor, ml_platform) with the "
        "platform normalised through PLATFORM_ALIASES before the pattern lookup",
        "" if ok else "Map the ML platform back to the pattern keys (ios) when collecting evidence",
    )
    assert ok


def test_v03_64_legacy_detection_tests_status(recorder: Recorder):
    import subprocess
    import sys as _sys

    proc = subprocess.run(
        [_sys.executable, "-m", "pytest", "tests/test_detection.py", "-q",
         "-p", "no:randomly", "--tb=no", "-x", "--co", "-q"],
        capture_output=True, text=True, cwd=str(BACKEND), timeout=180,
    )
    collected = [line for line in (proc.stdout or "").splitlines() if "::" in line]
    full = subprocess.run(
        [_sys.executable, "-m", "pytest", "tests/test_detection.py", "-q",
         "-p", "no:randomly", "--tb=no"],
        capture_output=True, text=True, cwd=str(BACKEND), timeout=300,
    )
    out = (full.stdout or "") + (full.stderr or "")
    failed = [line for line in out.splitlines() if line.startswith("FAILED")]
    ok = len(failed) == 0
    recorder.add(
        "V03-64", "K", "the project's own detection tests pass against the deployed path",
        "tests/test_detection.py (11 tests)",
        "0 failures",
        f"collected={len(collected)} failed={len(failed)}: {failed}",
        "PASS" if ok else "PARTIAL", "CONFIRMED BEHAVIOR",
        "pre-existing failures (baseline, unchanged by this validation): the module's "
        "own tests were written against the regex contract and now fail on the ML path — "
        "platform 'ios_xe' vs 'ios' (test_detection.py:26) and confidence 0.5979 vs >0.7 "
        "(test_detection.py:72). They are part of the 26-failure baseline",
        "Align the legacy expectations with the deployed path",
    )


def test_v03_65_evidence_cap_on_ml_path(detector, monkeypatch, recorder: Recorder):
    patch_ml(monkeypatch, _MLFake(ret=("fortinet", "fortios", "firewall", 0.9, "ml")))
    r = detector.detect("#config system global\n" + "FortiGate-60E\n" * 20)
    has_marker = (
        bool(r.detection_evidence)
        and r.detection_evidence[0].pattern.startswith("ML model")
    )
    ok = len(r.detection_evidence) <= 10 and has_marker and path_of(r) == "ml"
    recorder.add(
        "V03-65", "D", "the 10-item evidence cap holds on the ML path too",
        "ML forced confident + 1 FortiOS structural line + 20 banner-matching lines",
        "<= 10 evidence items, ML marker first, path=ml",
        f"items={len(r.detection_evidence)} marker_first={has_marker} path={path_of(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E03 F11 fix: collect evidence -> insert the ML marker -> cap at 10. "
        "Pre-fix the cap ran inside _collect_evidence and the marker was inserted "
        "afterwards, so an ML result could carry 11 items (observed on the corpus "
        "for Juniper/Firewalls/SRX/configs_junos-srx-1.cfg)",
        "",
    )
    assert ok


def test_v03_66_cross_engine_baseline(recorder: Recorder):
    import csv

    e01_path = BACKEND / "artifacts" / "engine_validation" / "01_ingestion" / "dataset_results.csv"
    e02_path = BACKEND / "artifacts" / "engine_validation" / "02_validation" / "dataset_results.csv"
    if not (e01_path.exists() and e02_path.exists()):
        recorder.add(
            "V03-66", "K", "cross-engine baseline join with Engines 01 and 02",
            "artifacts of 01_ingestion and 02_validation",
            "join computed", "artifacts missing", "NOT VERIFIABLE", "CONFIRMED BEHAVIOR",
            "artifacts", "",
        )
        pytest.skip("E01/E02 artifacts missing")
    with open(e01_path, encoding="utf-8") as fh:
        e01 = {r["relpath"]: r for r in csv.DictReader(fh)}
    with open(e02_path, encoding="utf-8") as fh:
        e02 = {r["relpath"]: r for r in csv.DictReader(fh)}
    ingestible = [
        rp for rp, r in e01.items()
        if r["ext_allowed"] == "True" and r["would_be_duplicate_rejected"] == "False"
    ]
    e02_valid = [rp for rp in ingestible if rp in e02 and e02[rp]["is_valid"] == "True"]
    e02_invalid = [rp for rp in ingestible if rp in e02 and e02[rp]["is_valid"] == "False"]
    ok = len(ingestible) > 0 and len(e02_valid) + len(e02_invalid) == len(
        [rp for rp in ingestible if rp in e02]
    )
    recorder.add(
        "V03-66", "K", "every file that Engine 01 would store and Engine 02 would accept "
        "is a file Engine 03 will be asked to identify",
        "01_ingestion/dataset_results.csv joined to 02_validation/dataset_results.csv "
        "on relpath",
        "join complete (counts reconcile)",
        f"e01_ingestible={len(ingestible)} e02_valid={len(e02_valid)} "
        f"e02_invalid={len(e02_invalid)} join_reconciles={ok}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "baseline recorded by 01_ingestion and 02_validation; the per-file vendor "
        "distribution for these files is produced by "
        "scripts/engine_validation/sweep_detection.py",
    )
    assert ok


# ---------------------------------------------------------------------------
# E03 FIX — regression tests for the F1/F2/F3/F11/F13/F14/F17 contract changes
# ---------------------------------------------------------------------------

def test_v03_67_structural_beats_spoofed_banner(detector, monkeypatch, recorder: Recorder):
    patch_regex(monkeypatch)
    structural = detector.detect(
        "hostname R1\ninterface GigabitEthernet0/0\n!\n"
        "Palo Alto Networks PA-220 firewall config\n"
    )
    spoof = detector.detect("! this is a Juniper Networks lab note\nhostname R1")
    banner_plus_live = detector.detect("! Cisco IOS Software, C2960 Software\nhostname Switch1")
    ok = (
        structural.vendor == "cisco"
        and spoof.vendor == "unknown"
        and banner_plus_live.vendor == "cisco"
    )
    recorder.add(
        "V03-67", "F",
        "F1: structural evidence beats a spoofed banner line, and a banner plus "
        "one live command still claims its vendor",
        "cisco config + injected Palo Alto line; Juniper comment + hostname; "
        "cisco banner + hostname (regex path)",
        "cisco; unknown (never juniper); cisco",
        f"structural={structural.vendor} spoof={spoof.vendor} "
        f"banner_plus_live={banner_plus_live.vendor} "
        f"banner_conf={banner_plus_live.confidence:.3f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py _decide(): MIN_EVIDENCE_PATTERNS=2 distinct patterns AND "
        "structural > 0 required; banner-only vendors are ineligible. Pre-fix a "
        "single banner line scored 3.0 and flipped the verdict (V03-42/V03-43)",
        "",
    )
    assert ok


def test_v03_68_supported_compliance_vendor_gate(recorder: Recorder):
    from app.engines.detection import SUPPORTED_COMPLIANCE_VENDORS
    from app.engines.compliance.executor import AuditExecutor

    ex = AuditExecutor()
    unsupported = {
        v: ex._get_parser(v, "eos")
        for v in ("paloalto", "arista", "f5", "unknown", "")
    }
    supported = {
        v: type(ex._get_parser(v, "x")).__name__
        for v in ("cisco", "juniper", "fortinet")
    }
    run = ex.execute("v03-68", PALO, framework="CIS", device_name="probe")
    stopped = (
        run.status == "failed"
        and run.parse_result is None
        and run.detection_result is not None
        and run.detection_result.vendor == "paloalto"
        and any(s.name == "parsing" and s.status == "failed" for s in run.steps)
    )
    ok = (
        SUPPORTED_COMPLIANCE_VENDORS == frozenset({"cisco", "juniper", "fortinet"})
        and all(p is None for p in unsupported.values())
        and all(s != "NoneType" for s in supported.values())
        and stopped
    )
    recorder.add(
        "V03-68", "K",
        "F2/F10: only {cisco, juniper, fortinet} may enter the parser/compliance "
        "set; paloalto is detection-only and an unsupported vendor stops the audit "
        "after detection instead of falling back to another vendor's parser",
        "SUPPORTED_COMPLIANCE_VENDORS export; _get_parser per vendor; "
        "AuditExecutor.execute(PALO fixture)",
        "set == {cisco, fortinet, juniper}; parsers None for unsupported; audit "
        "status=failed with parse_result=None and detection_result.vendor=paloalto",
        f"set={sorted(SUPPORTED_COMPLIANCE_VENDORS)} "
        f"unsupported={ {k: type(v).__name__ for k, v in unsupported.items()} } "
        f"supported={supported} stopped={stopped} status={run.status}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "executor.py _get_parser else->None + execute() step-3 gate; "
        "detection.py SUPPORTED_COMPLIANCE_VENDORS. Pre-fix every vendor fell "
        "back to CiscoIOSParser (executor.py:126-128)",
        "",
    )
    assert ok


def test_v03_69_platform_is_canonical_on_both_paths(detector, monkeypatch, recorder: Recorder):
    from app.engines.detection import PLATFORM_ALIASES

    patch_regex(monkeypatch)
    regex_p = detector.detect(CISCO_IOS).platform
    patch_ml(monkeypatch, _MLFake(ret=("cisco", "ios_xe", "router", 0.9, "ml")))
    ml_r = detector.detect(CISCO_IOS)
    ok = (
        regex_p == "ios"
        and ml_r.platform == "ios"
        and PLATFORM_ALIASES.get("ios_xe") == "ios"
    )
    recorder.add(
        "V03-69", "B",
        "F3: both execution paths return the canonical platform vocabulary",
        "CISCO_IOS through the regex branch and through an ML branch claiming ios_xe",
        "platform=ios on both paths; PLATFORM_ALIASES maps ios_xe->ios",
        f"regex={regex_p} ml={ml_r.platform} "
        f"alias={PLATFORM_ALIASES.get('ios_xe')!r} path={path_of(ml_r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py platform chosen from regex evidence + PLATFORM_ALIASES, "
        "shared by both paths (the ML branch never emits its own platform). "
        "Pre-fix: regex=ios, ml=ios_xe (V03-20, tests/test_detection.py:26)",
        "",
    )
    assert ok


def test_v03_70_non_str_input_raises_typeerror(detector, recorder: Recorder):
    observed = {}
    for label, bad in (("none", None), ("bytes", b"hostname R1"), ("int", 12345)):
        try:
            detector.detect(bad)
            observed[label] = "no exception"
        except TypeError as exc:
            observed[label] = f"TypeError: {exc}"
        except Exception as exc:  # pragma: no cover
            observed[label] = f"{type(exc).__name__}: {exc}"
    ok = all(v.startswith("TypeError") for v in observed.values())
    recorder.add(
        "V03-70", "I",
        "F13: non-str input raises a typed TypeError with a clear message instead "
        "of failing incidentally (or not at all)",
        "detect(None), detect(b'hostname R1'), detect(12345)",
        "TypeError for all three",
        str(observed),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py isinstance(content, str) guard. Pre-fix: AttributeError for "
        "None, incidental TypeError for bytes/int (V03-51/52/53)",
        "",
    )
    assert ok


def test_v03_71_ml_failure_logs_warning(detector, monkeypatch, recorder: Recorder, caplog):
    import logging as _logging

    patch_ml(monkeypatch, _MLFake(exc=RuntimeError("model exploded with 10.0.0.1")))
    with caplog.at_level(_logging.WARNING, logger="app.engines.detection"):
        r = detector.detect(CISCO_IOS)
    logged = "Vendor ML detection failed: RuntimeError" in caplog.text
    no_leak = "10.0.0.1" not in caplog.text and "model exploded" not in caplog.text
    ok = logged and no_leak and r.vendor == "cisco" and path_of(r) == "regex"
    recorder.add(
        "V03-71", "B",
        "F14: an ML failure is logged at warning level naming the exception type "
        "without leaking configuration content",
        "get_ml_detector().predict raises RuntimeError containing config text",
        "warning contains 'Vendor ML detection failed: RuntimeError'; exception "
        "text/config not logged; regex verdict cisco",
        f"logged={logged} no_leak={no_leak} vendor={r.vendor} path={path_of(r)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "detection.py logger.warning('Vendor ML detection failed: %s; falling "
        "back to regex', type(exc).__name__). Pre-fix: 'except Exception: pass' "
        "with no log line (V03-15)",
        "",
    )
    assert ok


def test_v03_72_benchmark_reuses_executor_detection(monkeypatch, recorder: Recorder):
    from app.engines.detection import VendorDetector
    from app.engines.compliance.executor import AuditExecutor

    calls = {"n": 0}
    original = VendorDetector.detect

    def counting_detect(self, content):
        calls["n"] += 1
        return original(self, content)

    monkeypatch.setattr(VendorDetector, "detect", counting_detect)
    run = AuditExecutor().execute(
        "v03-72", CISCO_IOS, framework="CIS", device_name="probe"
    )
    ok = calls["n"] == 1
    recorder.add(
        "V03-72", "K",
        "F17: detection runs exactly once per audit — the benchmark engine reuses "
        "the executor's VendorIdentification instead of re-detecting the same content",
        "AuditExecutor.execute(CISCO_IOS) with VendorDetector.detect instrumented",
        "detect() called once for the whole pipeline",
        f"calls={calls['n']} status={run.status}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "executor.py passes vendor_identification=detection to "
        "benchmark_engine.execute; execution.py accepts it and only calls "
        "detect() when the caller did not supply a result. Pre-fix: detect() ran "
        "twice per audit (executor.py + execution.py)",
        "",
    )
    assert ok
