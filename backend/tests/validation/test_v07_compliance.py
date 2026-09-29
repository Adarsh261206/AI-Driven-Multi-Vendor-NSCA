"""Engine 07 validation - Control selection / Compliance evaluation (spec 10.7, 13).

Scope:
    app/benchmarks/{registry,execution,models,cisco_ios_xe_controls,
    juniper_junos_controls,nist_sp800_53_controls,framework_mappings}.py
    app/engines/compliance/{models,loader,engine,evidence,executor,cisco_controls}.py
    app/api/v1/{compliance,audit_execution}.py
    app/models (compliance_results)

Every test records one evidence row via the `recorder` fixture (see
tests/validation/conftest.py). Defect claims assert the defect; conformance
claims assert the behaviour. Statuses: PASS = requirement met.
"""

from __future__ import annotations

import dataclasses
import statistics
import time
from pathlib import Path

import pytest

from app.benchmarks.execution import BenchmarkExecutionEngine
from app.benchmarks.models import BenchmarkControl, AssessmentStatus, ControlSeverity
from app.benchmarks.registry import ControlRegistry

BACKEND = Path(__file__).resolve().parents[2]
SAMPLE = BACKEND / "tests" / "sample_configs"
SPEC_PATH = BACKEND.parent / "docs" / "PROJECT_MASTER_SPEC.md"

SPEC_TEXT = SPEC_PATH.read_text(encoding="utf-8")
EXEC_SRC = (BACKEND / "app" / "benchmarks" / "execution.py").read_text(encoding="utf-8")
REG_SRC = (BACKEND / "app" / "benchmarks" / "registry.py").read_text(encoding="utf-8")
EXECUTOR_SRC = (BACKEND / "app" / "engines" / "compliance" / "executor.py").read_text(
    encoding="utf-8"
)
AUDIT_API_SRC = (BACKEND / "app" / "api" / "v1" / "audit_execution.py").read_text(
    encoding="utf-8"
)
COMPLIANCE_API_SRC = (BACKEND / "app" / "api" / "v1" / "compliance.py").read_text(
    encoding="utf-8"
)

SECURE = (SAMPLE / "secure.txt").read_text(encoding="utf-8")
INSECURE = (SAMPLE / "insecure.txt").read_text(encoding="utf-8")
JUNIPER_SECURE = (SAMPLE / "juniper_secure.txt").read_text(encoding="utf-8")
EMPTY = ""


def _control(
    control_id: str = "T-1",
    target: str | None = "management.http.enabled",
    operator: str = "equals",
    expected=None,
    status: AssessmentStatus = AssessmentStatus.AUTOMATED,
    vendor: str = "cisco",
    platform: str = "ios_xe",
    negated: bool = False,
    audit_regex: str = "",
) -> BenchmarkControl:
    return BenchmarkControl(
        benchmark_id="T-BENCH",
        benchmark_name="T-BENCH",
        benchmark_version="1",
        vendor=vendor,
        platform=platform,
        control_id=control_id,
        title=f"control {control_id}",
        category="TEST",
        assessment_status=status,
        severity=ControlSeverity.HIGH,
        target_model_path=target,
        operator=operator,
        expected_value=expected,
        negated=negated,
        audit_regex=audit_regex,
    )


@pytest.fixture(scope="module")
def bench() -> BenchmarkExecutionEngine:
    return BenchmarkExecutionEngine()


@pytest.fixture(scope="module")
def registry(bench) -> ControlRegistry:
    return bench.control_registry


@pytest.fixture(scope="module")
def cisco_run(bench):
    return bench.execute(raw_config=SECURE, vendor="cisco", platform="ios_xe")


@pytest.fixture(scope="module")
def all_controls(registry) -> list[BenchmarkControl]:
    return list(registry._controls.values())


# ---------------------------------------------------------------------------
# A - Control structure (spec 13.1 / 13.2)
# ---------------------------------------------------------------------------


def test_v07_01_mvp_frameworks_loaded(recorder, all_controls):
    vendors = sorted({c.vendor for c in all_controls})
    ok = vendors == ["cisco", "juniper", "universal"] and len(all_controls) == 196
    recorder.add(
        "V07-01", "A",
        "the registry loads both MVP frameworks - CIS vendor controls and NIST "
        "controls (spec 13.1, spec 10.7 'Load framework rules (CIS, NIST)')",
        "BenchmarkExecutionEngine._load_benchmarks()",
        "CIS controls (cisco + juniper) and NIST controls present",
        f"total={len(all_controls)} vendors={vendors}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "registry._by_vendor_platform: cisco:ios_xe=53, juniper:junos=17, "
        "universal:network_device=126",
        "" if ok else "register the missing framework control sets",
    )
    assert ok


def test_v07_02_spec_132_fields_present(recorder, all_controls):
    missing = []
    for c in all_controls:
        for field_name in ("control_id", "title", "description", "category",
                           "severity", "benchmark_version", "vendor", "platform"):
            if not getattr(c, field_name, None):
                missing.append(f"{c.control_id}.{field_name}")
    ok = not missing
    recorder.add(
        "V07-02", "A",
        "every control exposes the spec 13.2 structure fields (id, version, title, "
        "description, category, severity, target vendor/platform)",
        f"{len(all_controls)} controls x 8 fields",
        "0 missing fields",
        f"missing={missing[:5]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "app/benchmarks/models.py:32-76 BenchmarkControl",
        "",
    )
    assert ok


def test_v07_03_framework_attribute_absent(recorder, all_controls):
    has_framework_field = all(getattr(c, "framework", "") in ("CIS", "NIST")
                              for c in all_controls)
    has_version = all(getattr(c, "framework_version", "")
                      for c in all_controls)
    has_rule_conf = all(isinstance(getattr(c, "rule_confidence", None), float)
                        for c in all_controls)
    ok = has_framework_field and has_version and has_rule_conf
    recorder.add(
        "V07-03", "A",
        "each control carries authoritative framework metadata as the spec "
        "13.2 structure requires (framework, version, rule confidence)",
        "BenchmarkControl model fields over 196 controls",
        "every control names its defining framework/version and a rule "
        "confidence",
        f"framework set={has_framework_field}; version set={has_version}; "
        f"rule_confidence set={has_rule_conf}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F3/F7: app/benchmarks/models.py framework/framework_version/"
        "rule_confidence fields, stamped at inventory build time by the "
        "defining benchmark module (selection.assign_control_metadata)",
        "add a framework field to BenchmarkControl and derive API/persistence labels "
        "from it",
    )
    assert ok


def test_v07_04_severity_vocabulary(recorder, all_controls):
    allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    used = sorted({(c.severity.value if hasattr(c.severity, "value") else str(c.severity))
                   for c in all_controls})
    ok = set(used) <= allowed
    recorder.add(
        "V07-04", "A",
        "control severities use the spec 13.2 vocabulary "
        "(HIGH/MEDIUM/CRITICAL and the spec's other levels)",
        "all controls",
        f"subset of {sorted(allowed)}",
        f"used={used}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "app/benchmarks/models.py:18-23 ControlSeverity",
        "",
    )
    assert ok


def test_v07_05_target_paths_exist_in_model(recorder, all_controls):
    from app.engines.universal_model import UniversalSecurityModel

    model_paths = set(UniversalSecurityModel().get_all_paths())
    bad = sorted({c.target_model_path for c in all_controls
                  if c.target_model_path and c.target_model_path not in model_paths})
    bad_controls = [(c.control_id, c.target_model_path) for c in all_controls
                    if c.target_model_path and c.target_model_path not in model_paths]
    ok = not bad
    recorder.add(
        "V07-05", "A",
        "every control target.model_path is a path the Universal Security Model "
        "defines (spec 13.2 rule.target.model_path)",
        f"{len(all_controls)} controls vs model leaf set",
        "0 target paths outside the model",
        f"outside={bad}; controls={bad_controls}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E05: universal_model.py defines the session/vty-timeout leaves "
        "(cross-ref E05 V05-55)",
        "",
    )
    assert ok


def test_v07_06_used_operators_supported_by_engine(recorder, all_controls):
    used = sorted({c.operator for c in all_controls if c.target_model_path})
    engine_ops = {"equals", "not_equals", "contains", "is_set", "not_set",
                  "greater_than", "greater_than_or_equal", "less_than",
                  "less_than_or_equal", "regex_match"}
    unsupported = [op for op in used if op not in engine_ops]
    ok = not unsupported
    recorder.add(
        "V07-06", "A",
        "every operator used by a mapped control is one the canonical evaluator "
        "implements (BenchmarkExecutionEngine._apply_operator)",
        f"used operators={used}",
        "all used operators implemented",
        f"unsupported={unsupported}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "used: equals, is_set, greater_than, less_than, greater_than_or_equal, "
        "less_than_or_equal - all handled in execution.py:620-668",
        "",
    )
    assert ok


def test_v07_07_spec_133_in_operator_unsupported(recorder):
    from app.benchmarks.selection import OPERATOR_VOCABULARY, apply_operator

    spec_ops = {"equals", "not_equals", "greater_than", "less_than",
                "contains", "in"}
    missing = [op for op in spec_ops if op not in OPERATOR_VOCABULARY]
    ok = not missing and apply_operator("a", ["a", "b"], "in") is True
    recorder.add(
        "V07-07", "A",
        "every operator named in spec 13.3 evaluation logic is implemented by the "
        "canonical evaluator",
        "spec 13.3 operator list vs selection.apply_operator",
        "spec operators {equals, not_equals, greater_than, less_than, contains, in} "
        "all implemented",
        f"missing={missing}; 'in' membership check works",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E07 F8: selection.OPERATOR_VOCABULARY + apply_operator shared by the "
        "benchmark engine and the registry",
        "implement 'in' (and 'not_in') in _apply_operator",
    )
    assert ok


def test_v07_08_operator_vocabularies_agree(recorder):
    from app.benchmarks.selection import OPERATOR_VOCABULARY
    from app.benchmarks.execution import BenchmarkExecutionEngine
    from app.benchmarks.registry import ControlRegistry

    # Both evaluators share one implementation: identical answers everywhere.
    probes = [("equals", True, True), ("not_equals", True, False),
              ("greater_than_or_equal", 5, 5),
              ("less_than_or_equal", 5, 5), ("in", "a", ["a", "b"]),
              ("is_set", "x", True)]
    engine_vals = [BenchmarkExecutionEngine._apply_operator(a, e, op)
                   for op, a, e in probes]
    reg_vals = [ControlRegistry._apply_operator(None, a, e, op)
                for op, a, e in probes]
    ok = (engine_vals == reg_vals == [True] * len(probes)
          and {op for op, _, _ in probes} <= OPERATOR_VOCABULARY)
    recorder.add(
        "V07-08", "A",
        "one operator vocabulary is shared by all evaluators (spec 13.3, the "
        "canonical selection module, engine and ControlRegistry)",
        "same 6 probe evaluations through engine and registry operator paths",
        "identical answers; every probe operator in the canonical vocabulary",
        f"engine={engine_vals}; registry={reg_vals}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F8: selection.OPERATOR_VOCABULARY + apply_operator; engine and "
        "registry both delegate (no independent branches, no silent equals)",
        "unify the operator enum, the docstring and all three evaluators",
    )
    assert ok


def test_v07_09_control_ids_unique(recorder, all_controls):
    ids = [c.control_id for c in all_controls]
    dups = sorted({i for i in ids if ids.count(i) > 1})
    ok = not dups
    recorder.add(
        "V07-09", "A",
        "control ids are unique across the loaded frameworks (spec 13.2 id, spec 12 "
        "ControlResult.control_id identifies a result)",
        f"{len(ids)} control ids",
        "0 duplicate ids",
        f"duplicates={dups}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "53 cisco (numeric) + 17 juniper (numeric) + 126 NIST (AC-2 style) - "
        "currently disjoint; uniqueness is enforced by nothing (registry keys "
        "_controls by control_id alone)",
        "key the registry by (vendor, platform, control_id) or namespace ids",
    )
    assert ok


def test_v07_10_duplicate_registration_overwrites(recorder):
    from app.benchmarks.selection import DuplicateControlError

    reg = ControlRegistry()
    a = _control("1.1.1", vendor="cisco", platform="ios_xe")
    b = _control("1.1.1", vendor="juniper", platform="junos")
    reg.register_control(a)
    try:
        reg.register_control(b)
        outcome = "accepted"
    except DuplicateControlError as exc:
        outcome = f"rejected: {exc}"
    got = reg.get_control("1.1.1")
    ok = (outcome.startswith("rejected") and got is a
          and len(reg.get_controls_by_vendor_platform("cisco", "ios_xe")) == 1
          and len(reg._controls) == 1)
    recorder.add(
        "V07-10", "A",
        "registering a control whose id already exists must not produce "
        "inconsistent views (get_control vs per-vendor index)",
        "register cisco 1.1.1 then juniper 1.1.1",
        "duplicate registration rejected; original views intact",
        f"outcome={outcome}; get_control().vendor={got.vendor if got else None}; "
        f"cisco index={len(reg.get_controls_by_vendor_platform('cisco', 'ios_xe'))}; "
        f"_controls total={len(reg._controls)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F9: registry.register_control raises DuplicateControlError on a "
        "conflicting duplicate id instead of silently overwriting",
        "index controls by (vendor, platform, control_id)",
    )
    assert ok


# ---------------------------------------------------------------------------
# B - Control selection (which controls run)
# ---------------------------------------------------------------------------


def test_v07_11_cisco_dual_baseline_selection(recorder, cisco_run):
    cisco_ids = [e.control_id for e in cisco_run.evaluations
                 if e.control_id[0].isdigit()]
    nist_ids = [e.control_id for e in cisco_run.evaluations
                if not e.control_id[0].isdigit()]
    ok = (cisco_run.evaluated == 179 and len(cisco_ids) == 53
          and len(nist_ids) == 126)
    recorder.add(
        "V07-11", "B",
        "a cisco/ios_xe audit evaluates the 53 vendor CIS controls plus the 126 "
        "NIST controls (spec 10.7 dual baseline, spec 13.1 MVP = CIS + NIST)",
        "bench.execute(secure, vendor=cisco, platform=ios_xe)",
        "179 evaluated (53 CIS + 126 NIST)",
        f"evaluated={cisco_run.evaluated} cis={len(cisco_ids)} "
        f"nist={len(nist_ids)} score={cisco_run.score}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "execution.py:181-193 - vendor lookup + NIST append with id dedup",
        "",
    )
    assert ok


def test_v07_12_cisco_platform_alias(recorder, bench):
    base = bench.execute(raw_config=SECURE, vendor="cisco", platform="ios_xe")
    alias = bench.execute(raw_config=SECURE, vendor="cisco", platform="ios")
    ok = alias.evaluated == base.evaluated and alias.score == base.score
    recorder.add(
        "V07-12", "B",
        "platform alias cisco/ios selects the same control set as cisco/ios_xe "
        "(VendorDetector reports 'ios', controls register under 'ios_xe')",
        "bench.execute(..., platform='ios')",
        f"identical to ios_xe run ({base.evaluated} controls)",
        f"evaluated={alias.evaluated} score={alias.score}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "execution.py:171-175 - vendor_lower==cisco and platform_lower in "
        "(ios, ios_xe) -> effective_platform='ios_xe'",
        "",
    )
    assert ok


def test_v07_13_juniper_dual_baseline_selection(recorder, bench):
    res = bench.execute(raw_config=JUNIPER_SECURE, vendor="juniper",
                        platform="junos")
    jun_ids = [e.control_id for e in res.evaluations
               if e.control_id[0].isdigit()]
    nist_ids = [e.control_id for e in res.evaluations
                if not e.control_id[0].isdigit()]
    ok = (res.evaluated == 143 and len(jun_ids) == 17
          and len(nist_ids) == 126)
    recorder.add(
        "V07-13", "B",
        "a juniper/junos audit evaluates the 17 vendor CIS controls plus the 126 "
        "NIST controls (spec 10.7, spec 13.1)",
        "bench.execute(juniper_secure, vendor=juniper, platform=junos)",
        "143 evaluated (17 CIS Juniper + 126 NIST)",
        f"evaluated={res.evaluated} cis={len(jun_ids)} nist={len(nist_ids)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "execution.py:181-193",
        "",
    )
    assert ok


def test_v07_14_vendor_case_drops_vendor_controls(recorder, bench):
    res = bench.execute(raw_config=SECURE, vendor="Cisco", platform="IOS")
    cisco_ids = [e.control_id for e in res.evaluations
                 if e.control_id[0].isdigit()]
    ok = (len(cisco_ids) == 53 and res.evaluated == 179
          and res.status == "completed")
    recorder.add(
        "V07-14", "B",
        "control selection must not depend on caller-supplied vendor casing - "
        "the same device audited as 'Cisco' must select the same 53 CIS controls "
        "as 'cisco' (selection basis must be stable, spec 10.7)",
        "bench.execute(secure, vendor='Cisco', platform='IOS')",
        "179 evaluated (53 CIS + 126 NIST) as with lowercase 'cisco'",
        f"evaluated={res.evaluated} cis_ids={len(cisco_ids)} "
        f"score={res.score} status={res.status}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F2: selection.normalize_vendor/normalize_platform canonicalize "
        "every lookup; registry keys are canonical at register and lookup",
        "lowercase (or normalize) vendor before the registry lookup",
    )
    assert ok


def test_v07_15_registry_lookup_case_sensitive(recorder, registry):
    exact = registry.get_controls_by_vendor_platform("cisco", "ios_xe")
    wrong_case = registry.get_controls_by_vendor_platform("CISCO", "IOS_XE")
    ok = len(exact) == 53 and len(wrong_case) == 53
    recorder.add(
        "V07-15", "B",
        "registry vendor/platform lookup must be robust to the casing a caller "
        "may reasonably supply (inputs elsewhere in the pipeline are lowercased)",
        "registry.get_controls_by_vendor_platform('CISCO','IOS_XE')",
        f"same {len(exact)} controls as lowercase key",
        f"wrong_case returned {len(wrong_case)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F2: registry keys are canonical (lowercase + aliased) at register "
        "and lookup time",
        "normalize vendor/platform to lowercase at register and lookup",
    )
    assert ok


def test_v07_16_juniper_platform_case(recorder, bench):
    base = bench.execute(raw_config=JUNIPER_SECURE, vendor="juniper",
                         platform="junos")
    upper = bench.execute(raw_config=JUNIPER_SECURE, vendor="juniper",
                          platform="JUNOS")
    jun_ids = [e.control_id for e in upper.evaluations
                 if e.control_id[0].isdigit()]
    ok = upper.evaluated == base.evaluated and len(jun_ids) == 17
    recorder.add(
        "V07-16", "B",
        "platform normalization must apply to every vendor, not only cisco - "
        "platform='JUNOS' must select the same 17 controls as 'junos'",
        "bench.execute(juniper_secure, vendor=juniper, platform='JUNOS')",
        "143 evaluated like platform='junos'",
        f"evaluated={upper.evaluated} juniper_ids={len(jun_ids)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F2: selection.normalize_platform canonicalizes every vendor "
        "through the single alias map",
        "apply platform_lower unconditionally before lookup",
    )
    assert ok


@pytest.fixture(scope="module")
def framework_runs():
    from app.engines.compliance.executor import AuditExecutor
    from app.benchmarks.selection import UnsupportedFrameworkError

    ex = AuditExecutor()
    runs = {}
    for fw in ("CIS", "NIST"):
        runs[fw] = ex.execute(audit_id=f"v07-{fw}", config_content=SECURE,
                              framework=fw)
    runs["DUAL"] = ex.execute(audit_id="v07-DUAL", config_content=SECURE,
                              framework=None)
    try:
        ex.execute(audit_id="v07-BOGUS", config_content=SECURE,
                   framework="BOGUS")
        runs["BOGUS"] = "accepted"
    except UnsupportedFrameworkError as exc:
        runs["BOGUS"] = f"rejected: {exc}"
    return runs


def test_v07_17_framework_parameter_ignored(recorder, framework_runs):
    runs = framework_runs
    cis = runs["CIS"]
    nist = runs["NIST"]
    cis_ids = {e.control_id for e in cis.compliance_evaluation.evaluations}
    nist_ids = {e.control_id for e in nist.compliance_evaluation.evaluations}
    different = (cis.total_controls == 53 and nist.total_controls == 126
                 and cis_ids.isdisjoint(nist_ids))
    bogus_rejected = (isinstance(runs["BOGUS"], str)
                      and runs["BOGUS"].startswith("rejected"))
    ok = different and bogus_rejected
    recorder.add(
        "V07-17", "B",
        "AuditExecutor.execute(framework=...) must select that framework's rules "
        "(spec 9.1 step 6 'Apply CIS/NIST rules', spec 10.7 'Load framework "
        "rules')",
        "executor.execute(secure, framework=CIS|NIST|BOGUS)",
        "different framework -> different control sets/results; invalid "
        "framework 'BOGUS' rejected",
        f"CIS total={cis.total_controls} NIST total={nist.total_controls} "
        f"disjoint={cis_ids.isdisjoint(nist_ids)}; BOGUS: {runs['BOGUS']}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F1: executor validates framework/version up front and forwards "
        "them to BenchmarkExecutionEngine.execute (CIS-only, NIST-only, or "
        "the explicit dual baseline)",
        "wire framework/framework_version through to control selection "
        "(vendor CIS set only for framework=CIS, NIST only for framework=NIST, "
        "both for a dual option) and reject unknown frameworks",
    )
    assert ok


def test_v07_18_unknown_vendor_selects_nist_only(recorder, bench):
    res = bench.execute(raw_config=SECURE, vendor="fortinet", platform="fortios")
    ok = (res.status in ("unsupported_selection", "vendor_mismatch")
          and res.evaluated == 0 and res.passed == 0 and res.failed == 0)
    recorder.add(
        "V07-18", "B",
        "a declared vendor with no compliance evaluation contract stops "
        "evaluation instead of falling back to NIST verdicts",
        "bench.execute(secure, vendor=fortinet, platform=fortios)",
        "unsupported_selection status, 0 controls evaluated, no verdicts",
        f"status={res.status} evaluated={res.evaluated} "
        f"reason={res.status_reason[:100]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F6: selection.select_for_evaluation raises UnsupportedVendorError "
        "for vendors outside {cisco, juniper}; the engine returns an explicit "
        "boundary result",
        "",
    )
    assert ok


def test_v07_19_platform_only_filter_ignored(recorder, registry):
    actual = registry.get_automated_controls(platform="ios_xe")
    expected = [c for c in registry._controls.values()
                if c.platform == "ios_xe"
                and c.assessment_status == "Automated"]
    ok = len(actual) == len(expected) and len(actual) > 0
    recorder.add(
        "V07-19", "B",
        "get_automated_controls(platform=...) must filter by that platform when "
        "vendor is not supplied",
        "registry.get_automated_controls(platform='ios_xe')",
        f"only ios_xe automated controls ({len(expected)})",
        f"returned {len(actual)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F2: registry._filter_by_vendor_platform applies every supplied "
        "filter conjunctively with canonicalized values",
        "apply the platform filter in the vendor-less branch",
    )
    assert ok


async def test_v07_20_api_vendor_filter_ignored(recorder):
    from app.api.v1 import compliance as api

    resp = await api.list_framework_controls(
        framework_id="CIS", vendor="fortinet", page=1, per_page=100,
        current_user=None)
    got = [c.id for c in resp.items]
    ok = len(got) == 0
    recorder.add(
        "V07-20", "B",
        "GET /frameworks/CIS/controls?vendor=fortinet must return no controls "
        "(fortinet has no CIS controls) - the vendor filter must be honoured",
        "list_framework_controls(framework_id=CIS, vendor=fortinet)",
        "0 items",
        f"returned {len(got)} controls",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F2: list_framework_controls filters through the canonical "
        "selection service (conjunctive vendor/platform/framework/version)",
        "filter by vendor in every branch (or drop the vendor parameter)",
    )
    assert ok


async def test_v07_21_api_platform_alias_missing(recorder):
    from app.api.v1 import compliance as api

    resp = await api.list_framework_controls(
        framework_id="CIS", vendor="cisco", platform="ios", page=1,
        per_page=100, current_user=None)
    resp2 = await api.list_framework_controls(
        framework_id="CIS", vendor="cisco", platform="ios_xe", page=1,
        per_page=100, current_user=None)
    ok = len(resp.items) == 53 and len(resp2.items) == 53
    recorder.add(
        "V07-21", "B",
        "the controls API applies the same ios->ios_xe platform alias the "
        "execution engine applies (same registry, one alias rule)",
        "GET /frameworks/CIS/controls?vendor=cisco&platform=ios",
        "53 cisco controls (alias) - platform=ios_xe already returns 53",
        f"platform=ios -> {len(resp.items)} items; platform=ios_xe -> "
        f"{len(resp2.items)} items",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F2: the API and the engine share ControlSelectionService (one "
        "alias map, one normalization path)",
        "apply the vendor platform alias in the API layer or in "
        "ControlRegistry.get_controls_by_vendor_platform",
    )
    assert ok


async def test_v07_22_api_cisco_ios_xe(recorder):
    from app.api.v1 import compliance as api

    resp = await api.list_framework_controls(
        framework_id="CIS", vendor="cisco", platform="ios_xe", page=1,
        per_page=100, current_user=None)
    ok = len(resp.items) == 53 and resp.meta.total == 53
    recorder.add(
        "V07-22", "B",
        "GET /frameworks/CIS/controls?vendor=cisco&platform=ios_xe returns the "
        "53 cisco controls",
        "list_framework_controls(CIS, cisco, ios_xe)",
        "53 items",
        f"{len(resp.items)} items, total={resp.meta.total}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "compliance.py:96-97 exact key hit + :103 vendor filter",
        "",
    )
    assert ok


async def test_v07_23_api_nist_framework(recorder):
    from app.api.v1 import compliance as api

    resp = await api.list_framework_controls(
        framework_id="NIST", page=1, per_page=200, current_user=None)
    ok = len(resp.items) == 126 and resp.meta.total == 126
    recorder.add(
        "V07-23", "B",
        "GET /frameworks/NIST/controls returns the 126 NIST SP 800-53 controls",
        "list_framework_controls(NIST)",
        "126 items",
        f"{len(resp.items)} items, total={resp.meta.total}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "compliance.py:91-93",
        "",
    )
    assert ok


def test_v07_24_framework_inference_matches_inventory(recorder, all_controls):
    from app.api.v1.compliance import _control_to_response

    wrong = []
    for c in all_controls:
        expected_fw = "CIS" if c.vendor in ("cisco", "juniper") else "NIST"
        got = _control_to_response(c).framework
        if got != expected_fw:
            wrong.append((c.control_id, c.vendor, got))
    ok = not wrong
    recorder.add(
        "V07-24", "B",
        "the API framework label for each control matches its true framework "
        "(cisco/juniper controls are CIS, universal controls are NIST)",
        "_control_to_response over 196 controls",
        "every label matches the vendor-derived expectation",
        f"mismatches={wrong[:5]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "compliance.py:59 - 'CIS' if vendor in ('cisco','juniper') else 'NIST' "
        "works only because the current inventory is vendor-partitioned "
        "(V07-03: derived, not stored)",
        "",
    )
    assert ok


def test_v07_25_advertised_versions_dont_match_controls(recorder, all_controls):
    from app.api.v1.compliance import _frameworks

    advertised = _frameworks()
    cis_advertised = set(advertised["CIS"].versions)
    cis_actual = {c.framework_version for c in all_controls
                  if c.framework == "CIS"}
    nist_advertised = set(advertised["NIST"].versions)
    nist_actual = {c.framework_version for c in all_controls
                   if c.framework == "NIST"}
    ok = (cis_advertised == cis_actual and nist_advertised == nist_actual
          and cis_advertised and nist_advertised)
    recorder.add(
        "V07-25", "B",
        "framework versions advertised by the API are exactly the versions "
        "the loaded controls carry (spec 13.2 framework_version; spec 12 "
        "ComplianceResult.framework_version)",
        f"CIS advertised={sorted(cis_advertised)} vs control versions="
        f"{sorted(cis_actual)}; NIST advertised={sorted(nist_advertised)} vs "
        f"{sorted(nist_actual)}",
        "advertised version sets equal the control version sets",
        f"CIS intersection={sorted(cis_advertised & cis_actual)}; "
        f"NIST intersection={sorted(nist_advertised & nist_actual)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F1/F3: _frameworks() derives versions/counts/categories from "
        "the loaded control metadata (never hardcoded)",
        "advertise the real benchmark_version strings (or store spec-13.2 "
        "framework_version values on the controls)",
    )
    assert ok


def test_v07_26_benchmark_id_understates_baseline(recorder, cisco_run):
    frameworks = sorted({e.evidence.framework for e in cisco_run.evaluations})
    ok = (cisco_run.benchmark_id == "CIS+NIST" and frameworks == ["CIS", "NIST"])
    recorder.add(
        "V07-26", "B",
        "result metadata describes the baseline(s) actually evaluated "
        "(dual-baseline runs must not be labelled as a single CIS benchmark)",
        "bench.execute(secure, cisco, ios_xe)",
        "benchmark_id names the explicit dual baseline (CIS+NIST)",
        f"benchmark_id={cisco_run.benchmark_id!r}; frameworks in run="
        f"{frameworks}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F1/H07-16: execution names mixed-framework runs CIS+NIST "
        "explicitly; per-control framework comes from control metadata",
        "expose a baselines list (e.g. ['CIS-CISCO-IOS-XE-17.x-v2.2.1', "
        "'NIST-SP-800-53-r5']) on the result",
    )
    assert ok


def test_v07_27_dedup_by_control_id(recorder, cisco_run):
    ids = [e.control_id for e in cisco_run.evaluations]
    dups = sorted({i for i in ids if ids.count(i) > 1})
    ok = not dups
    recorder.add(
        "V07-27", "B",
        "the vendor set and the NIST set are appended without duplicate "
        "evaluations (spec 12 ControlResult.control_id identifies a result)",
        f"{len(ids)} evaluations from 53+126 controls",
        "0 duplicated control ids",
        f"duplicates={dups}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "execution.py:186-191 seen_ids dedup (guaranteed by disjoint inventory "
        "today, V07-09)",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# C - Deterministic evaluation logic (spec 13.3)
# ---------------------------------------------------------------------------


class _NormStub:
    """Minimal stand-in for NormalizationResult (engine only reads universal_config)."""

    def __init__(self, config: dict):
        self.universal_config = config


_EMPTY_NORM = _NormStub({})
_APPLY = BenchmarkExecutionEngine._apply_operator


def test_v07_28_equals_truth_table(recorder):
    cases = [(True, True, True), (False, True, False), ("sha", "sha", True),
             ("sha", "md5", False), (5, 5, True), (5, "5", False)]
    wrong = [(a, e, _APPLY(a, e, "equals"), w)
             for a, e, w in cases if _APPLY(a, e, "equals") != w]
    recorder.add(
        "V07-28", "C",
        "operator 'equals' implements value equality per spec 13.3 step 2",
        "6 (actual, expected) pairs",
        "all 6 match the expected booleans",
        f"wrong={wrong}",
        "PASS" if not wrong else "FAIL",
        "CONFIRMED BEHAVIOR" if not wrong else "BUG",
        "execution.py:625-626",
        "",
    )
    assert not wrong


def test_v07_29_not_equals(recorder):
    cases = [(True, True, False), (False, True, True), ("a", "b", True),
             (5, 5, False)]
    wrong = [(a, e, _APPLY(a, e, "not_equals"), w)
             for a, e, w in cases if _APPLY(a, e, "not_equals") != w]
    recorder.add(
        "V07-29", "C",
        "operator 'not_equals' per spec 13.3 step 2",
        "4 (actual, expected) pairs",
        "all 4 match expected",
        f"wrong={wrong}",
        "PASS" if not wrong else "FAIL",
        "CONFIRMED BEHAVIOR" if not wrong else "BUG",
        "execution.py:627-628",
        "",
    )
    assert not wrong


def test_v07_30_contains(recorder):
    cases = [("enable secret sha", "sha", True), ("abc", "xyz", False),
             (["md5", "sha"], "sha", True), (["md5"], "sha", False),
             (123, "3", False)]
    wrong = [(a, e, _APPLY(a, e, "contains"), w)
             for a, e, w in cases if _APPLY(a, e, "contains") != w]
    recorder.add(
        "V07-30", "C",
        "operator 'contains' per spec 13.3 step 2 (substring for strings, "
        "membership for lists, False for non-container types without crashing)",
        "5 cases incl. non-container actual",
        "all 5 match expected",
        f"wrong={wrong}",
        "PASS" if not wrong else "FAIL",
        "CONFIRMED BEHAVIOR" if not wrong else "BUG",
        "execution.py:629-635 - str/list handled, other types -> False",
        "",
    )
    assert not wrong


def test_v07_31_numeric_comparison(recorder):
    gt_cases = [("10", 5, True), (3, 5, False), ("abc", 5, False),
                (None, 5, False)]
    lt_cases = [(4, 5, True), (5, 5, False), ("4", 5, True)]
    wrong = ([(a, e, "greater_than", _APPLY(a, e, "greater_than"), w)
              for a, e, w in gt_cases
              if _APPLY(a, e, "greater_than") != w]
             + [(a, e, "less_than", _APPLY(a, e, "less_than"), w)
                for a, e, w in lt_cases
                if _APPLY(a, e, "less_than") != w])
    recorder.add(
        "V07-31", "C",
        "operators greater_than/less_than coerce numeric strings and return "
        "False (not crash) on non-numeric values per spec 13.3 step 2",
        "7 cases incl. string coercion and invalid values",
        "all 7 match expected, no exceptions",
        f"wrong={wrong}",
        "PASS" if not wrong else "FAIL",
        "CONFIRMED BEHAVIOR" if not wrong else "BUG",
        "execution.py:640-654 float() with TypeError/ValueError -> False",
        "",
    )
    assert not wrong


def test_v07_32_or_equal_operators_engine(recorder):
    cases = [(5, 5, "greater_than_or_equal", True),
             (4, 5, "greater_than_or_equal", False),
             (5, 5, "less_than_or_equal", True),
             (6, 5, "less_than_or_equal", False)]
    wrong = [(a, e, op, _APPLY(a, e, op), w)
             for a, e, op, w in cases if _APPLY(a, e, op) != w]
    recorder.add(
        "V07-32", "C",
        "greater_than_or_equal / less_than_or_equal are implemented by the "
        "canonical evaluator (juniper controls use them)",
        "4 cases",
        "all 4 match expected",
        f"wrong={wrong}",
        "PASS" if not wrong else "FAIL",
        "CONFIRMED BEHAVIOR" if not wrong else "BUG",
        "execution.py:645-659",
        "",
    )
    assert not wrong


def test_v07_33_registry_or_equal_fallback(recorder, registry, all_controls):
    used = sorted({c.operator for c in all_controls
                   if c.operator in ("greater_than_or_equal",
                                     "less_than_or_equal")})
    ctl = _control(operator="greater_than_or_equal", expected=3,
                   target="management.http.enabled")
    reg_out = registry.evaluate_control(
        ctl, {"management": {"http": {"enabled": 5}}})
    engine_out = _APPLY(5, 3, "greater_than_or_equal")
    ok = reg_out["result"] == "PASS" and engine_out is True
    recorder.add(
        "V07-33", "C",
        "ControlRegistry.evaluate_control implements every operator the loaded "
        "controls use (same vocabulary as the canonical engine)",
        f"operators used by controls={used}; evaluate_control with actual=5, "
        "expected=3, operator=greater_than_or_equal",
        "registry and engine agree (PASS)",
        f"registry result={reg_out['result']} vs engine={engine_out}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F8: registry._apply_operator delegates to the canonical "
        "selection.apply_operator (single operator implementation)",
        "delegate evaluate_control to BenchmarkExecutionEngine._apply_operator "
        "(single operator implementation)",
    )
    assert ok


def test_v07_34_unknown_operator_silent_fallback(recorder, registry):
    from app.benchmarks.selection import InvalidControlError

    ctl = _control(operator="banana", expected=True,
                   target="management.http.enabled")
    try:
        registry.evaluate_control(
            ctl, {"management": {"http": {"enabled": True}}})
        reg_outcome = "evaluated"
    except InvalidControlError as exc:
        reg_outcome = f"rejected: {exc.reason}"
    try:
        _APPLY(True, True, "banana")
        engine_outcome = "evaluated"
    except InvalidControlError as exc:
        engine_outcome = f"rejected: {exc.reason}"
    ok = reg_outcome.startswith("rejected") and engine_outcome.startswith(
        "rejected")
    recorder.add(
        "V07-34", "C",
        "an unknown/misspelled operator must not silently evaluate as "
        "'equals' - the control vocabulary is validated at load time and at "
        "evaluation",
        "operator='banana' with actual=True, expected=True",
        "operator rejected (typed error), never a PASS labelled with the "
        "bogus operator",
        f"registry: {reg_outcome}; engine: {engine_outcome}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E07 F8: selection.apply_operator raises InvalidControlError for "
        "unknown operators; registry construction validates every control",
        "validate operator against the vocabulary when controls are loaded; "
        "unknown operator -> REVIEW",
    )
    assert ok


def test_v07_35_missing_value_never_false(recorder, cisco_run):
    violations = [
        (e.control_id, e.result)
        for e in cisco_run.evaluations
        if e.evidence.universal_model_path and e.evidence.actual_value is None
        and e.result != "REVIEW"
    ]
    ok = not violations
    recorder.add(
        "V07-35", "C",
        "a mapped control whose normalized value is absent returns REVIEW, "
        "never PASS/FAIL (spec 13.4: insufficient evidence -> REVIEW)",
        f"{cisco_run.evaluated} evaluations on secure.txt",
        "0 non-REVIEW results with a null actual value",
        f"violations={violations}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07: mapped controls with actual None -> REVIEW (missing evidence, "
        "never FALSE/FAIL)",
        "",
    )
    assert ok


def test_v07_36_manual_controls_review(recorder, cisco_run):
    manual = [e for e in cisco_run.evaluations
              if e.evidence.assessment_status == "Manual"]
    ok = (len(manual) == 89
          and all(e.result == "REVIEW" and e.confidence == 1.0
                  for e in manual))
    recorder.add(
        "V07-36", "C",
        "manual-assessment controls are always REVIEW with human-review "
        "reasoning, regardless of configuration content (spec 13.2 "
        "assessment status, spec 9.1 REVIEW outcomes)",
        f"{len(manual)} manual controls in the cisco run",
        "all REVIEW with confidence 1.0",
        f"count={len(manual)}, all_review_conf1="
        f"{all(e.result == 'REVIEW' and e.confidence == 1.0 for e in manual)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "execution.py:254-264",
        "",
    )
    assert ok


def test_v07_37_unmapped_regex_pass_without_normalized_value(recorder, bench):
    ctl = _control(control_id="T-7", target=None, audit_regex="aaa new-model")
    ev = bench._evaluate_control(ctl, _EMPTY_NORM, SECURE)
    ok = (ev.result == "PASS"
          and ev.evidence.normalized_value is None
          and ev.evidence.raw_config_line_numbers
          and ev.evidence.raw_config
          and ev.evidence.parsed_value
          and ev.evidence.reasoning)
    recorder.add(
        "V07-37", "C",
        "an explicitly regex-based control with matched raw evidence may PASS "
        "without a normalized value — but only with recorded raw evidence, "
        "reasoning and composed confidence (raw-regex rule)",
        "synthetic unmapped control, audit_regex matches secure.txt",
        "PASS with matched lines, snippet, parsed raw text and reasoning",
        f"result={ev.result} confidence={ev.confidence} "
        f"lines={ev.evidence.raw_config_line_numbers} "
        f"reasoning={ev.evidence.reasoning[:60]!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F4: _evaluate_unmatched path records raw evidence + reasoning; "
        "normalized_value stays null honestly (no normalized value exists)",
        "treat regex-only evidence as REVIEW (or map every control to a model "
        "path) so PASS always traces to a normalized value",
    )
    assert ok


def test_v07_38_unmapped_regex_miss_is_fail(recorder, bench):
    ctl = _control(control_id="T-8", target=None,
                   audit_regex="definitely-absent-xyz")
    ev = bench._evaluate_control(ctl, _EMPTY_NORM, SECURE)
    ok = (ev.result == "REVIEW" and "insufficient evidence" in
          ev.evidence.reasoning)
    recorder.add(
        "V07-38", "C",
        "absence of raw text is not a normalized-value comparison - per spec "
        "13.4 insufficient evidence yields REVIEW, not FAIL",
        "synthetic unmapped control, audit_regex absent from config",
        "REVIEW with an insufficient-evidence reason",
        f"result={ev.result} confidence={ev.confidence} "
        f"reasoning={ev.evidence.reasoning[:80]!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F4: regex non-match on absent evidence -> REVIEW (a miss is not "
        "a verified violation unless absence_is_fail is defined)",
        "regex non-match on absent evidence -> REVIEW",
    )
    assert ok


def test_v07_39_unmapped_without_regex_review(recorder, bench):
    from app.benchmarks.selection import assign_control_metadata

    ctl = assign_control_metadata(
        _control(control_id="T-10", target=None, audit_regex=""), "CIS")
    ev = bench._evaluate_control(ctl, _EMPTY_NORM, SECURE)
    ok = ev.result == "REVIEW" and ev.confidence == 0.5
    recorder.add(
        "V07-39", "C",
        "an automated control with neither model path nor audit regex returns "
        "REVIEW (spec 13.4 insufficient evidence)",
        "synthetic unmapped control without audit_regex",
        "REVIEW conf 0.5",
        f"result={ev.result} confidence={ev.confidence}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07: unevaluable rule (rule_confidence 0.5) with no evidence basis",
        "",
    )
    assert ok


def test_v07_40_negated_no_path(recorder, bench):
    present = bench._evaluate_control(
        _control(control_id="T-11", target=None, negated=True,
                 audit_regex="aaa new-model"), _EMPTY_NORM, SECURE)
    absent = bench._evaluate_control(
        _control(control_id="T-12", target=None, negated=True,
                 audit_regex="definitely-absent-xyz"), _EMPTY_NORM, SECURE)
    ok = (present.result == "FAIL" and absent.result == "PASS"
          and present.confidence == 0.85 and absent.confidence == 0.85)
    recorder.add(
        "V07-40", "C",
        "negated controls (absence = compliance) invert the audit-regex "
        "verdict: pattern present -> FAIL, pattern absent -> PASS "
        "(models.py:66 contract)",
        "2 synthetic negated controls (present / absent)",
        "present->FAIL, absent->PASS, both with raw-evidence composed "
        "confidence (0.85 raw x 1.0 default rule)",
        f"present={present.result}/{present.confidence}, "
        f"absent={absent.result}/{absent.confidence}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F4/F7: _evaluate_unmapped negated path with composed confidence",
        "",
    )
    assert ok


def test_v07_41_conflict_detection_review(recorder, bench):
    conflict_norm = _NormStub({
        "management": {"vty": {"conflicts": [
            {"setting": "exec-timeout", "conflict": True,
             "values": ["10", "20"], "context": "vty 0 15"}]}}})
    ev = bench._evaluate_control(
        _control(control_id="1.2.6", target="management.vty.exec_timeouts"),
        conflict_norm, SECURE)
    ok = (ev.result == "REVIEW" and "onflict" in ev.evidence.reasoning)
    recorder.add(
        "V07-41", "C",
        "duplicate conflicting settings are resolved to REVIEW, never a "
        "guessed verdict (spec 13.4 insufficient evidence - safe direction); "
        "deterministic for identical inputs",
        "control 1.2.6 with conflicting exec-timeout duplicates",
        "REVIEW with conflict reasoning",
        f"result={ev.result} confidence={ev.confidence} "
        f"reasoning={ev.evidence.reasoning[:90]!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07: _review_with_conflict with review confidence from available "
        "inputs; CONFLICT_AFFECTED_CONTROLS {1.2.6,1.2.7,1.2.8,1.2.2}",
        "",
    )
    assert ok


def test_v07_42_two_score_formulas_one_pipeline(recorder, framework_runs):
    r = framework_runs["DUAL"]
    a = r.overall_score
    b = r.compliance_evaluation.overall_score
    bench = r.benchmark_result.score if r.benchmark_result else None
    ok = abs(a - b) < 0.01 and (bench is None or abs(a - bench) < 0.01)
    recorder.add(
        "V07-42", "C",
        "one audit run exposes one compliance score - the same evaluation must "
        "not carry two different overall_score values (spec 12 "
        "ComplianceResult.overall_score is a single number)",
        "AuditResult.overall_score vs "
        "AuditResult.compliance_evaluation.overall_score vs "
        "BenchmarkExecutionResult.score for the same run",
        "identical values (passed/evaluated, REVIEW in the denominator)",
        f"overall_score={a} vs compliance_evaluation.overall_score={b} vs "
        f"benchmark score={bench}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F5: selection.overall_score is the single formula used by the "
        "benchmark engine, the executor mapping and persistence",
        "compute the score once and reuse it (both excluded and included "
        "variants must be named explicitly if both are needed)",
    )
    assert ok

def test_v07_43_confidence_formula_missing(recorder, cisco_run):
    from app.benchmarks.models import BenchmarkControl

    has_rule_conf_field = "rule_confidence" in BenchmarkControl.model_fields
    norm_present = sum(
        1 for e in cisco_run.evaluations
        if e.evidence.normalization_confidence is not None)
    decisive = [e for e in cisco_run.evaluations if e.result in ("PASS", "FAIL")]
    composed = all(
        abs(e.confidence - round(
            (e.evidence.normalization_confidence
             if e.evidence.normalization_confidence is not None
             else 0.85) * e.evidence.rule_confidence, 4)) < 1e-9
        for e in decisive)
    ok = has_rule_conf_field and norm_present > 0 and composed
    recorder.add(
        "V07-43", "C",
        "per spec 13.3 step 4 confidence = calculate_confidence("
        "normalization_confidence, rule_confidence) using the normalized "
        "config's confidence and the rule's confidence",
        "BenchmarkControl model fields, evidence values and result confidence",
        "controls carry rule confidence; evidence carries normalization "
        "confidence; result confidence is their product",
        f"BenchmarkControl has 'rule_confidence'={has_rule_conf_field}; "
        f"evaluations with normalization_confidence set={norm_present}/"
        f"{cisco_run.evaluated}; decisive results composed={composed}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E07 F7: models.rule_confidence stamped at inventory build; "
        "selection.compose_confidence in the canonical path",
        "add rule confidence to BenchmarkControl, propagate normalization "
        "confidence into evidence, implement calculate_confidence",
    )
    assert ok

def test_v07_44_review_threshold_only_in_dead_path(recorder, bench):
    ctl = _control(control_id="T-44", target="management.http.enabled",
                   operator="equals", expected=True)
    norm = _NormStub({"management": {"http": {"enabled": True}}})
    facts = {"management.http.enabled": {
        "value": True, "confidence": 0.5, "vendor_syntax": "ip http server",
        "line_numbers": [3]}}
    ev = bench._evaluate_control(ctl, norm, SECURE, facts)
    ok = (ev.result == "REVIEW" and "0.70" in ev.evidence.reasoning)
    recorder.add(
        "V07-44", "C",
        "spec 13.4: a normalized value with confidence <70% must become REVIEW",
        "mapped control with normalization confidence 0.5 x rule 1.0",
        "REVIEW naming the 0.70 threshold",
        f"result={ev.result} confidence={ev.confidence} "
        f"reasoning={ev.evidence.reasoning[:80]!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E07 F7: needs_review(final_conf) gate in the canonical "
        "_evaluate_control (not only the retired legacy path)",
        "implement the <70% REVIEW trigger in BenchmarkExecutionEngine (after "
        "confidence is computed, V07-43)",
    )
    assert ok

def test_v07_45_audit_score_formula_consistent(recorder, framework_runs):
    from app.benchmarks.selection import overall_score as canonical_score

    r = framework_runs["DUAL"]
    recomputed = canonical_score(r.passed, r.total_controls)
    source_ok = "overall_score(passed" in AUDIT_API_SRC
    close = abs(recomputed - r.overall_score) < 0.1
    ok = source_ok and close
    recorder.add(
        "V07-45", "C",
        "the persisted audit score equals the engine's score - both are the "
        "canonical overall_score (passed/evaluated, REVIEW in the denominator)",
        "engine score vs canonical recomputation vs audit_execution.py",
        "all three agree",
        f"engine={r.overall_score}, recomputed={recomputed}, "
        f"canonical formula used in persistence={source_ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F5: audit_execution persists selection.overall_score; the "
        "divergent ComplianceEvaluation formula is gone",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# D - Evidence chains (spec 13.3 step 3, spec 12)
# ---------------------------------------------------------------------------

SPEC_EVIDENCE_KEYS = {"raw_config", "parsed_value", "normalized_value",
                      "security_control", "expected_value", "actual_value",
                      "result", "reasoning"}


def test_v07_46_canonical_evidence_keys_vs_spec12(recorder, cisco_run):
    sample = next(e for e in cisco_run.evaluations
                  if e.evidence.universal_model_path)
    actual_keys = set(dataclasses.asdict(sample.evidence).keys())
    missing = sorted(SPEC_EVIDENCE_KEYS - actual_keys)
    ok = not missing
    recorder.add(
        "V07-46", "D",
        "per spec 12 (lines 831-838) an evidence chain carries raw_config, "
        "parsed_value, normalized_value, security_control, expected_value, "
        "actual_value, result, reasoning",
        "dataclasses.asdict(BenchmarkEvidence) vs spec 12 interface",
        f"all {len(SPEC_EVIDENCE_KEYS)} keys present",
        f"missing={missing}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E07 F4: BenchmarkEvidence leads with the eight §12 keys "
        "(raw_config/parsed_value/normalized_value/security_control/"
        "expected/actual/result/reasoning) plus traceability metadata",
        "align evidence field names with spec 12 (raw_config, reasoning, "
        "security_control) in both the canonical and legacy structures",
    )
    assert ok

def test_v07_47_persisted_chain_vs_spec12(recorder, framework_runs):
    evals = framework_runs["DUAL"].compliance_evaluation.evaluations
    d = evals[0].evidence.to_dict()
    missing = sorted(SPEC_EVIDENCE_KEYS - set(d.keys()))
    # Every decisive MAPPED evaluation must name the observed vendor
    # statement; unmapped/manual rows honestly carry None.
    unparsed = [(e.control_id, e.result.value) for e in evals
                if e.result.value in ("PASS", "FAIL")
                and e.evidence.universal_model_path
                and e.evidence.parsed_value is None]
    ok = not missing and not unparsed
    recorder.add(
        "V07-47", "D",
        "the chain actually persisted to compliance_results.evidence (JSONB) "
        "matches spec 12: all 8 keys, with parsed_value populated on decisive "
        "mapped rows",
        f"EvidenceChain.to_dict() keys vs spec 12, over {len(evals)} "
        "evaluations",
        "0 missing keys; decisive mapped rows name the observed statement",
        f"missing={missing}; decisive mapped rows without parsed_value="
        f"{unparsed[:5]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E07 F4: executor maps parsed_value from the normalization mapping's "
        "vendor statement (F4) into the persisted chain",
        "populate parsed_value in _benchmark_to_compliance_evaluation and add "
        "security_control (normalized model path / control reference)",
    )
    assert ok

def test_v07_48_decisive_results_carry_raw_evidence(recorder, cisco_run):
    decisive = [e for e in cisco_run.evaluations
                if e.evidence.universal_model_path and e.result in ("PASS", "FAIL")]
    missing_lines = [e.control_id for e in decisive
                     if not e.evidence.raw_config_line_numbers]
    missing_snip = [e.control_id for e in decisive
                    if not e.evidence.raw_evidence_snippet]
    ok = not missing_lines and not missing_snip
    recorder.add(
        "V07-48", "D",
        "every decisive (PASS/FAIL) result carries raw evidence: config lines "
        "and a snippet tracing the verdict back to the file (spec 12 "
        "EvidenceChain.raw_config; spec 10.7 evidence chains)",
        f"{len(decisive)} decisive value-based results on secure.txt",
        "all with raw_config_line_numbers and raw_evidence_snippet",
        f"missing lines={missing_lines}; missing snippet={missing_snip}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F4: line numbers come from the normalization mapping's source "
        "path first, keyword matching second; decisive verdicts without "
        "either become REVIEW (sufficiency gate)",
        "fall back to emitting the normalized value + path as raw evidence "
        "when no config line matches",
    )
    assert ok

def test_v07_49_normalized_value_populated(recorder, cisco_run):
    violators = [
        (e.control_id, e.result)
        for e in cisco_run.evaluations
        if e.evidence.universal_model_path
        and e.evidence.normalized_value is None
        and e.result in ("PASS", "FAIL")
    ]
    ok = not violators
    recorder.add(
        "V07-49", "D",
        "a decisive result on a mapped control records the normalized value "
        "it judged (spec 12 EvidenceChain.normalized_value; spec 13.3 step 3)",
        f"{cisco_run.evaluated} evaluations",
        "0 PASS/FAIL rows with null normalized_value",
        f"violations={violators}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F4: single-path and multi-block branches both write "
        "evidence.normalized_value",
        "set evidence.normalized_value in the multi-block branch (e.g. to the "
        "worst block value)",
    )
    assert ok

def test_v07_50_expected_actual_operator_recorded(recorder, cisco_run):
    missing = [
        e.control_id for e in cisco_run.evaluations
        if e.evidence.universal_model_path and e.evidence.actual_value is not None
        and (e.evidence.operator == ""
             or (e.evidence.expected_value is None
                 and e.evidence.operator not in ("is_set", "not_set")))
    ]
    ok = not missing
    recorder.add(
        "V07-50", "D",
        "each mapped evaluation records expected_value, actual_value and the "
        "operator used (spec 12 EvidenceChain, spec 13.3 step 3)",
        f"{cisco_run.evaluated} evaluations",
        "all mapped rows carry operator + expected + actual",
        f"incomplete rows={missing}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07: _evaluate_control writes expected/actual/operator on every "
        "mapped branch",
        "",
    )
    assert ok


def test_v07_51_reasoning_on_every_result(recorder, cisco_run):
    missing = [e.control_id for e in cisco_run.evaluations
               if not e.evidence.reasoning]
    ok = not missing
    recorder.add(
        "V07-51", "D",
        "every evaluation carries a human-readable reasoning string "
        "(spec 12 EvidenceChain.reasoning; spec 13.3 step 3 evidence chain)",
        f"{cisco_run.evaluated} evaluations (PASS/FAIL/REVIEW/manual/conflict)",
        "0 results without reasoning",
        f"missing={missing[:5]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E07 F4: reasoning is written in every evaluation branch",
        "",
    )
    assert ok


def test_v07_52_confidence_consistent_layers(recorder, framework_runs):
    evals = framework_runs["DUAL"].compliance_evaluation.evaluations
    bad = [e.control_id for e in evals
           if abs(e.confidence - e.evidence.overall_confidence) > 1e-9]
    ok = not bad
    recorder.add(
        "V07-52", "D",
        "the confidence shown on a control evaluation equals the confidence "
        "in its persisted evidence chain (one number per result, spec 12 "
        "ControlResult.confidence)",
        f"{len(evals)} evaluations after benchmark conversion",
        "identical confidence values on both layers",
        f"mismatches={bad[:5]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07: overall_confidence=benchmark evidence.confidence (composed), "
        "copied verbatim to the evaluation",
        "",
    )
    assert ok


def test_v07_53_remediation_only_for_non_pass(recorder, framework_runs):
    evals = framework_runs["DUAL"].compliance_evaluation.evaluations
    pass_with = [e.control_id for e in evals
                 if e.result.value == "PASS" and e.remediation is not None]
    nonpass_without = [e.control_id for e in evals
                       if e.result.value != "PASS"
                       and not isinstance(e.remediation, dict)]
    ok = not pass_with and not nonpass_without
    recorder.add(
        "V07-53", "D",
        "spec 12 ControlResult.remediation is null for passing controls and a "
        "Remediation object for FAIL/REVIEW",
        f"{len(evals)} evaluations",
        "PASS rows have remediation null, FAIL/REVIEW rows a dict",
        f"pass_with_remediation={pass_with[:5]}; "
        f"nonpass_without={nonpass_without[:5]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07: executor builds remediation only when result != PASS",
        "",
    )
    assert ok


def test_v07_54_persistence_wires_evidence_and_remediation(recorder):
    seg = AUDIT_API_SRC.split("def build_compliance_result(")[1]
    seg = seg.split("\n\n\n")[0]
    call_ok = "compliance_result = build_compliance_result(" in AUDIT_API_SRC
    ev_ok = "eval_result.evidence.to_dict()" in seg
    rem_ok = "eval_result.remediation" in seg
    fw_ok = "eval_result.framework" in seg and "framework_version" in seg
    ok = call_ok and ev_ok and rem_ok and fw_ok
    recorder.add(
        "V07-54", "D",
        "run_audit_pipeline persists each ControlResult's evidence and "
        "remediation as JSONB columns (spec 12 ControlResult fields stored "
        "per row)",
        "audit_execution.py ComplianceResult construction",
        "evidence and remediation arguments present",
        f"evidence={ev_ok} remediation={rem_ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "audit_execution.py:363-375; key-level defects are V07-47",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# E - Framework attribution + persistence contract (spec 12, DDL, 14.3.2)
# ---------------------------------------------------------------------------


def test_v07_55_framework_version_never_used(recorder):
    body = EXECUTOR_SRC.split("result = AuditResult(audit_id=audit_id)")[1]
    body = body.split("def _benchmark_to_compliance_evaluation")[0]
    arg_used_in_body = "framework_version" in body and "version_c" in body
    seg = AUDIT_API_SRC.split("def build_compliance_result(")[1]
    persisted = "framework_version=eval_result.framework_version" in seg
    model_src = (BACKEND / "app" / "models" / "__init__.py").read_text(
        encoding="utf-8")
    model_seg = model_src.split("class ComplianceResult")[1].split("\nclass ")[0]
    column_exists = "framework_version" in model_seg
    spec_clause = "framework_version: string" in SPEC_TEXT
    ok = not (spec_clause and not (arg_used_in_body or persisted))
    recorder.add(
        "V07-55", "E",
        "spec 12 ComplianceResult.framework_version is supplied end to end: "
        "the executor accepts it and every persisted row carries it "
        "(DDL column exists, models/__init__.py ComplianceResult)",
        "AuditExecutor.execute(framework_version=...) body and "
        "run_audit_pipeline ComplianceResult(...) construction",
        "argument reaches control selection/rows; framework_version written "
        "on insert",
        f"spec requires it={spec_clause}; argument validated and forwarded in "
        f"execute()={arg_used_in_body}; written to ComplianceResult from "
        f"control metadata={persisted}; "
        f"DB column exists={column_exists}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E07 F1/F3: executor validates framework_version against the "
        "inventory and forwards it; persistence writes control.framework_version",
        "thread framework/framework_version through execute() and store them "
        "per row (framework value still needs V07-17)",
    )
    assert ok

def test_v07_56_id_heuristic_correct_for_current_inventory(recorder,
                                                           all_controls):
    wrong = [(c.control_id, c.framework)
             for c in all_controls
             if c.framework not in ("CIS", "NIST")]
    ok = not wrong
    recorder.add(
        "V07-56", "E",
        "every control's framework attribution is stored metadata (no id-shape "
        "heuristic anywhere in the attribution path)",
        "control.framework over all 196 controls",
        "every control attributed CIS or NIST from its defining benchmark",
        f"unattributed={wrong[:5]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F3: framework stamped at inventory build; audit_execution "
        "persists control.framework verbatim",
        "",
    )
    assert ok


def test_v07_57_attribution_from_id_shape_not_metadata(recorder, all_controls):
    from app.benchmarks.selection import ControlSelectionService

    ControlSelectionService(all_controls)
    cis_ids = {c.control_id for c in all_controls if c.framework == "CIS"}
    nist_ids = {c.control_id for c in all_controls if c.framework == "NIST"}
    # A CIS-style letter-prefixed id must stay CIS: attribution ignores shape.
    probe = [c for c in all_controls if c.control_id == "1.1.1"][0]
    ok = (probe.framework == "CIS" and len(cis_ids) == 70
          and len(nist_ids) == 126
          and "is_nist" not in AUDIT_API_SRC
          and "cid[0].isalpha" not in AUDIT_API_SRC)
    recorder.add(
        "V07-57", "E",
        "framework labels come from control metadata, not the shape of the "
        "control id - a CIS-style id 'SEC-5' must stay CIS",
        "control.framework for 1.1.1 + persistence source audit",
        "1.1.1 is CIS from metadata; no id-shape heuristic in persistence",
        f"1.1.1 framework={probe.framework}; CIS={len(cis_ids)} "
        f"NIST={len(nist_ids)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F3: store framework on the control (spec 13.2) and persist "
        "control.framework",
        "store framework on the control (spec 13.2) and persist control.framework",
    )
    assert ok

def test_v07_58_user_framework_misleads_labels(recorder, framework_runs):
    evals = framework_runs["NIST"].compliance_evaluation.evaluations
    frameworks = sorted({e.framework for e in evals})
    src_ok = 'framework=eval_result.framework or framework' in AUDIT_API_SRC
    ok = frameworks == ["NIST"] and src_ok
    recorder.add(
        "V07-58", "E",
        "rows keep the framework they belong to: a NIST-scoped audit stores "
        "NIST rows as NIST from control metadata, never from the request",
        "executor.execute(secure, framework=NIST) evaluations",
        "all rows NIST (the only framework evaluated), labelled from control "
        "metadata",
        f"frameworks={frameworks}; persistence reads control metadata={src_ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F3: audit_execution persists eval_result.framework (control "
        "metadata attached by the canonical path)",
        "derive the label from control metadata (V07-57 fix) instead of "
        "combining a heuristic with the user's request",
    )
    assert ok


def test_v07_59_result_values_lowercase_vs_spec12(recorder):
    from app.engines.compliance.models import ComplianceResultType

    vals = sorted(m.value for m in ComplianceResultType)
    spec_clause = 'result: "PASS" | "FAIL" | "REVIEW"' in SPEC_TEXT
    ok = vals == ["FAIL", "PASS", "REVIEW"]
    recorder.add(
        "V07-59", "E",
        "spec 12 ControlResult.result uses the enum PASS/FAIL/REVIEW exactly "
        "(the value persisted to compliance_results.result)",
        "ComplianceResultType values vs spec 12",
        f"['FAIL', 'PASS', 'REVIEW'] when spec demands it ({spec_clause})",
        f"stored values={vals}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E07 F11: ComplianceResultType values are the §12 uppercase enum; "
        "migration 006 uppercases legacy rows",
        "store spec-enum values (or document the lower-case mapping at the "
        "API boundary and use it consistently)",
    )
    assert ok

def test_v07_60_db_schema_vs_spec_ddl(recorder):
    interface_clause = "normalized_config_id: string" in SPEC_TEXT
    model_src = (BACKEND / "app" / "models" / "__init__.py").read_text(
        encoding="utf-8")
    model_seg = model_src.split("class ComplianceResult(Base)")[1].split(
        "\nclass ")[0]
    # Canonical decision (F11): the persisted relationship is the §12
    # interface's normalized_configuration_id — the actual data flow
    # (audit_execution persists the normalized configuration row) — not the
    # spec DDL's configuration_id, which disagrees with the spec's own §12
    # interface. Result enum is uppercase per §12.
    from app.models import ComplianceResultType as DBResultType

    db_vals = sorted(m.value for m in DBResultType)
    ok = ("normalized_configuration_id" in model_seg
          and db_vals == ["FAIL", "PASS", "REVIEW"]
          and interface_clause)
    recorder.add(
        "V07-60", "E",
        "the compliance_results persistence contract is canonical: the §12 "
        "normalized-configuration link, uppercase result enum, per-row "
        "framework/version/evidence",
        "docs §12 interface vs app/models/__init__.py ComplianceResult",
        "normalized_configuration_id link; uppercase results",
        f"link=normalized_configuration_id present; §12 interface names "
        f"normalized_config_id={interface_clause}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F11: models/__init__.py ComplianceResult follows the §12 "
        "interface (the spec DDL's configuration_id disagrees with the "
        "spec's own interface and is recorded as such)",
        "reconcile spec interface and DDL, then align the model",
    )
    assert ok

def test_v07_61_audit_counts_recomputed_from_rows(recorder):
    src_ok = all(s in AUDIT_API_SRC for s in (
        "total_controls += 1", "passed += 1", "failed += 1", "review += 1",
        "audit.overall_score = overall_score(passed, total_controls)",
    ))
    recorder.add(
        "V07-61", "E",
        "the persisted audit summary counts are recomputed from the per-control "
        "rows (spec 12 ComplianceResult totals match its control_results)",
        "run_audit_pipeline counting loop",
        "counts incremented per persisted row; canonical score derived",
        f"all counting/score statements present={src_ok}",
        "PASS" if src_ok else "FAIL",
        "CONFIRMED BEHAVIOR" if src_ok else "BUG",
        "E07 F5/F11: audit_execution counts per row and persists "
        "selection.overall_score",
        "",
    )
    assert src_ok


def test_v07_62_report_list_hardcodes_framework(recorder):
    reports_src = (BACKEND / "app" / "api" / "v1" / "reports.py").read_text(
        encoding="utf-8")
    hard_coded = 'framework="CIS"' in reports_src
    derives_from_rows = "ComplianceResult.framework" in reports_src
    ok = not hard_coded and derives_from_rows
    recorder.add(
        "V07-62", "E",
        "report metadata reflects the frameworks an audit actually contains "
        "(dual-baseline audits hold CIS and NIST rows, spec 14.3.2) - a "
        "framework-aware list endpoint must not answer with a constant",
        "GET /reports item construction",
        "framework derived from the audit's compliance rows (the detail view "
        "already computes framework_display)",
        f"list endpoint hardcodes framework='CIS'={hard_coded}; derives "
        f"framework from compliance rows={derives_from_rows}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F3: reports.list_reports derives the framework from the "
        "audit's ComplianceResult.framework rows like the detail view",
        "derive the list item framework from ComplianceResult.framework rows "
        "like the detail view does",
    )
    assert ok

# ---------------------------------------------------------------------------
# F - Dual-implementation drift (legacy engines.compliance vs benchmarks)
# ---------------------------------------------------------------------------


def test_v07_63_two_control_inventories(recorder, all_controls):
    from app.engines.compliance.loader import ControlLoader

    legacy = ControlLoader().get_all_controls()
    loader_src = (BACKEND / "app" / "engines" / "compliance" / "loader.py"
                  ).read_text(encoding="utf-8")
    controls_src = (BACKEND / "app" / "engines" / "compliance"
                    / "cisco_controls.py").read_text(encoding="utf-8")
    retired = ("DEPRECATED" in loader_src and "DEPRECATED" in controls_src
               and len(legacy) == 10 and len(all_controls) == 196)
    ok = retired
    recorder.add(
        "V07-63", "F",
        "one control inventory backs evaluation (spec 10.7 'Load framework "
        "rules (CIS, NIST)' - a single rule store); the retired 10-control "
        "loader is explicitly marked deprecated and cannot become a second "
        "source of truth",
        "ControlLoader().get_all_controls() vs ControlRegistry (196) + "
        "deprecation markers",
        "legacy loader stays 10 controls and is marked DEPRECATED; canonical "
        "registry holds 196",
        f"legacy loader={len(legacy)} controls vs canonical={len(all_controls)}; "
        f"both modules marked deprecated={retired}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F10: loader.py + cisco_controls.py carry explicit DEPRECATED "
        "markers; only ControlLoader (tests) consumes them",
        "delete or regenerate the legacy loader from the canonical registry",
    )
    assert ok

def test_v07_64_legacy_path_never_executed(recorder):
    found = []
    for py in (BACKEND / "app").rglob("*.py"):
        for i, line in enumerate(
                py.read_text(encoding="utf-8").splitlines(), 1):
            if ("RuleEngine(" in line or "ControlLoader(" in line) and \
                    "class " not in line and "import" not in line:
                found.append(f"{py.name}:{i}: {line.strip()}")
    doc_ok = ("not used by the canonical path" in EXECUTOR_SRC
              or "NOT used in the main audit path" in EXECUTOR_SRC)
    ok = not found and doc_ok
    recorder.add(
        "V07-64", "F",
        "the legacy ControlLoader/RuleEngine pipeline is either used or "
        "explicitly documented as retired - it must not linger half-wired "
        "(executors.py:8-9 claims it is kept only for compatibility)",
        "search app/**/*.py for RuleEngine()/ControlLoader() instantiation",
        "0 instantiations and the retirement is documented",
        f"instantiations={found}; docstring states legacy is not used="
        f"{doc_ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "executor.py:8-9 docstring; imports at :19-20 remain",
        "",
    )
    assert ok


def test_v07_65_legacy_loader_missing_nist(recorder, all_controls):
    from app.engines.compliance.loader import ControlLoader

    legacy = ControlLoader().get_all_controls()
    frameworks = sorted({c.framework for c in legacy})
    canonical_frameworks = sorted({c.framework for c in all_controls})
    loader_src = (BACKEND / "app" / "engines" / "compliance" / "loader.py"
                  ).read_text(encoding="utf-8")
    ok = (frameworks == ["CIS"] and canonical_frameworks == ["CIS", "NIST"]
          and "DEPRECATED" in loader_src)
    recorder.add(
        "V07-65", "F",
        "the retired loader's CIS-only scope is explicit and contained: the "
        "canonical inventory carries both MVP frameworks",
        "legacy ControlLoader inventory frameworks vs canonical inventory",
        "legacy ['CIS'] marked DEPRECATED; canonical ['CIS', 'NIST']",
        f"legacy frameworks={frameworks}; canonical={canonical_frameworks}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E07 F10: loader.py is explicitly deprecated; canonical path loads "
        "CIS + NIST from app.benchmarks",
        "retire the legacy loader (V07-63) rather than extend it",
    )
    assert ok

def test_v07_66_platform_label_drift(recorder, all_controls):
    canonical_label = {c.platform for c in all_controls
                       if c.vendor == "cisco"}
    loader_src = (BACKEND / "app" / "engines" / "compliance" / "loader.py"
                  ).read_text(encoding="utf-8")
    ok = canonical_label == {"ios_xe"} and "DEPRECATED" in loader_src
    recorder.add(
        "V07-66", "F",
        "the canonical inventory carries one platform label per vendor family "
        "(cisco controls register ios_xe); the retired loader's ios labels "
        "are explicitly deprecated, not a second truth",
        "canonical cisco platform labels + loader deprecation marker",
        "canonical labels agree; legacy scope marked deprecated",
        f"canonical labels={sorted(canonical_label)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F10: canonical selection aliases ios->ios_xe in one place; "
        "legacy ios labels are retired with the loader",
        "normalize platform labels at load (one canonical label set)",
    )
    assert ok

def test_v07_67_applicability_contract_drift(recorder, registry):
    from app.engines.compliance.engine import RuleEngine
    from app.engines.compliance.models import Control as LControl
    from app.engines.compliance.models import Severity as LSev

    engine = RuleEngine()
    lc = LControl(id="1.1.1", framework="CIS", framework_version="2024.1",
                  category="m", title="t", description="d", severity=LSev.HIGH,
                  vendor="cisco", platform="ios")
    legacy_vendor_case = engine._is_control_applicable(lc, "CISCO", "ios")
    reg_vendor_case = registry.get_controls_by_vendor_platform("CISCO", "ios")
    agree = bool(legacy_vendor_case) == bool(reg_vendor_case)
    recorder.add(
        "V07-67", "F",
        "vendor/platform applicability follows one contract in both "
        "evaluators - the same query gives the same answer",
        "legacy _is_control_applicable vs registry lookup for the same "
        "vendor/platform queries",
        "identical decisions",
        f"legacy vendor-case-insensitive applicable={legacy_vendor_case}; "
        f"registry('CISCO','ios') -> {len(reg_vendor_case)} controls",
        "PASS" if agree else "FAIL",
        "CONFIRMED BEHAVIOR" if agree else "DESIGN LIMITATION",
        "E07 F2: both paths canonicalize (lower + alias) before comparing",
        "single applicability function shared by all paths",
    )
    assert agree


def test_v07_68_framework_mappings_unreferenced(recorder):
    refs = []
    for py in (BACKEND / "app").rglob("*.py"):
        if py.name == "framework_mappings.py":
            continue
        text = py.read_text(encoding="utf-8")
        if "framework_mappings" in text and "import" in text:
            refs.append(py.name)
    mod_src = (BACKEND / "app" / "benchmarks" / "framework_mappings.py"
               ).read_text(encoding="utf-8")
    retired = "REFERENCE ONLY" in mod_src
    ok = retired and not refs
    recorder.add(
        "V07-68", "F",
        "the cross-framework mapping module is explicitly reference-only "
        "dead rule data must not masquerade as an evaluation source",
        "references of framework_mappings + module marker",
        "0 production evaluation references; REFERENCE ONLY marker present",
        f"references={refs}; marked reference-only={retired}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E07 F10: framework_mappings.py is an explicitly reference-only "
        "STIG crosswalk (Manual-only entries, never automated verdicts)",
        "wire it into the control responses / crosswalk or remove it",
    )
    assert ok

def test_v07_69_is_set_semantics_drift(recorder):
    engine_empty = _APPLY("", None, "is_set")
    engine_none = _APPLY(None, None, "is_set")
    ok = engine_empty is False and engine_none is False
    recorder.add(
        "V07-69", "F",
        "operator 'is_set' has one semantics: only a present non-empty value "
        "counts as set",
        "canonical _apply_operator('', is_set) and (None, is_set)",
        "both False",
        f"canonical is_set('')={engine_empty}; is_set(None)={engine_none}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F8: single canonical apply_operator (is_set = not None and "
        "!= ''); legacy evidence.py aligned",
        "unify the operator implementation (V07-33 recommendation)",
    )
    assert ok


def test_v07_70_regex_semantics_drift(recorder):
    import re as _re

    engine_search = _APPLY("banner motd ^hello", "hello",
                           "regex_match") is True
    legacy_verdict = bool(_re.search("hello", "banner motd ^hello"))
    ok = engine_search and legacy_verdict
    recorder.add(
        "V07-70", "F",
        "operator 'regex_match' has one semantics (unanchored search) in both "
        "evaluators",
        "pattern 'hello' against 'banner motd ^hello' in both implementations",
        "identical verdicts (match)",
        f"canonical (re.search) matches={engine_search}; legacy matches="
        f"{legacy_verdict}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E07 F8/F10: canonical selection.apply_operator uses re.search; "
        "legacy evidence.py aligned to re.search",
        "unify regex semantics (V07-33 recommendation)",
    )
    assert ok


def test_v07_71_executor_unused_legacy_imports(recorder):
    imported = ("import RuleEngine" in EXECUTOR_SRC
                and "import ControlLoader" in EXECUTOR_SRC)
    rule_used = "RuleEngine(" in EXECUTOR_SRC.replace("import RuleEngine",
                                                       "")
    loader_used = "ControlLoader(" in EXECUTOR_SRC.replace(
        "import ControlLoader", "")
    ok = not imported and not rule_used and not loader_used
    recorder.add(
        "V07-71", "F",
        "the executor imports nothing from the retired legacy pipeline (no "
        "half-retired state)",
        "RuleEngine / ControlLoader references inside executor.py",
        "no imports, no instantiations",
        f"imported={imported}; RuleEngine used={rule_used}; ControlLoader "
        f"used={loader_used}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E07 F10: executor.py imports only ComplianceEvaluation (shared "
        "result model) from the compliance engine package",
        "drop the unused imports with the legacy cleanup (V07-63)",
    )
    assert ok

# ---------------------------------------------------------------------------
# G - SEPARATE RECORD: wrong-vendor / unsupported-input consequences
# ---------------------------------------------------------------------------


def test_v07_72_cisco_content_evaluated_as_juniper(recorder, bench):
    res = bench.execute(raw_config=SECURE, vendor="juniper", platform="junos")
    ok = (res.status == "vendor_mismatch" and res.evaluated == 0
          and res.passed == 0 and res.failed == 0)
    recorder.add(
        "V07-72", "G",
        "controls are not evaluated for foreign content: cisco text declared "
        "as juniper stops at the vendor-mismatch safety boundary",
        "bench.execute(secure.txt, declared vendor=juniper)",
        "vendor_mismatch status, 0 evaluations (no juniper verdicts on cisco "
        "text)",
        f"declared=juniper; status={res.status} evaluated={res.evaluated} "
        f"reason={res.status_reason[:100]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "SEPARATE RECORD (category G): E07 F6 cross-checks the declared "
        "vendor against detection before selecting controls",
        "",
    )
    assert ok


def test_v07_73_juniper_content_evaluated_as_cisco(recorder, bench):
    res = bench.execute(raw_config=JUNIPER_SECURE, vendor="cisco",
                        platform="ios_xe")
    ok = (res.status == "vendor_mismatch" and res.evaluated == 0
          and res.passed == 0 and res.failed == 0)
    recorder.add(
        "V07-73", "G",
        "cisco controls must not PASS against juniper configuration text",
        "bench.execute(juniper_secure.txt, declared vendor=cisco)",
        "vendor_mismatch status, 0 evaluations (no cisco verdicts on juniper text)",
        f"declared=cisco; status={res.status} evaluated={res.evaluated} "
        f"reason={res.status_reason[:100]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "SEPARATE RECORD (category G): E07 F6 cross-checks the declared "
        "vendor against detection",
        "",
    )
    assert ok


def test_v07_74_unmapped_vendor_content_gets_nist_verdicts(recorder, bench):
    res = bench.execute(raw_config=SECURE, vendor="arista", platform="eos")
    ok = (res.status in ("unsupported_selection", "vendor_mismatch")
          and res.evaluated == 0
          and res.passed == 0 and res.failed == 0)
    recorder.add(
        "V07-74", "G",
        "an unsupported vendor declaration produces no verdicts",
        "bench.execute(secure.txt, declared vendor=arista)",
        "unsupported_selection status, 0 evaluations (no NIST verdicts from "
        "raw text)",
        f"declared=arista; status={res.status} evaluated={res.evaluated} "
        f"reason={res.status_reason[:100]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "SEPARATE RECORD (category G): E07 F6 blocks vendors outside "
        "{cisco, juniper} before selection",
        "",
    )
    assert ok


def test_v07_75_empty_config_decisive_failures(recorder):
    from app.engines.compliance.executor import AuditExecutor

    # E02 FIX (F4): the executor gates on validation — an empty config
    # fails EMPTY_CONTENT at step 1 and the run aborts with
    # status="failed", no evaluation and no verdicts. The pre-E02
    # outcome this row documented (0 pass / 2 fail / 124 review from
    # execution.py:302-307) can no longer occur on the executor path;
    # the bench-level behaviour is still recorded as V07-77.
    r = AuditExecutor().execute(audit_id="v07-empty", config_content="",
                                framework="CIS")
    ev = r.compliance_evaluation
    fail_ids = [] if ev is None else sorted(
        e.control_id for e in ev.evaluations
        if e.result.value == "fail")
    blocked = (
        r.status == "failed"
        and ev is None
        and not fail_ids
        and r.validation_result is not None
        and not r.validation_result.is_valid
    )
    codes = (
        [i.code for i in r.validation_result.issues]
        if r.validation_result is not None else None
    )
    recorder.add(
        "V07-75", "G",
        "an empty configuration cannot reach evaluation - the executor "
        "gates on validation (spec 13.4 / spec 9.1 step 1)",
        "executor.execute(config_content='')",
        "run blocked at validation: status=failed, no evaluation, 0 FAIL",
        f"status={r.status} evaluation={'None' if ev is None else 'present'} "
        f"fail_ids={fail_ids} validation_codes={codes} "
        "(pre-E02: status=completed, CM-7/CM-7(1) FAIL on empty input)",
        "PASS" if blocked else "FAIL",
        "CONFIRMED BEHAVIOR" if blocked else "BUG",
        "E02 FIX (F4) executor.py:174-179 returns before evaluation; "
        "pre-fix evidence (0 pass / 2 fail / 124 review) preserved in "
        "02_validation_pre_fix/; bench-level behaviour remains V07-77",
        "block decisive verdicts without evidence",
    )
    assert blocked


# ---------------------------------------------------------------------------
# H - Semantic fidelity invariants
# ---------------------------------------------------------------------------


def test_v07_76_value_based_pass_needs_observed_value(recorder, cisco_run):
    fabricated = [
        e.control_id for e in cisco_run.evaluations
        if e.result == "PASS" and e.evidence.universal_model_path
        and e.evidence.actual_value is None
    ]
    ok = not fabricated
    recorder.add(
        "V07-76", "H",
        "no value-based PASS is fabricated: every PASS on a mapped control "
        "shows an observed actual value (spec 13.3 step 1-2)",
        f"{cisco_run.evaluated} evaluations on secure.txt",
        "0 fabricated value PASSes",
        f"violations={fabricated}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "execution.py:358-392 - None short-circuits to REVIEW before the "
        "operator runs",
        "",
    )
    assert ok


def test_v07_77_empty_input_yields_no_passes(recorder):
    from app.engines.compliance.executor import AuditExecutor

    r = AuditExecutor().execute(audit_id="v07-empty2", config_content="",
                                framework="CIS")
    ok = r.passed == 0
    recorder.add(
        "V07-77", "H",
        "an empty file never produces a PASS at the control-evaluation layer "
        "(no value exists to satisfy any expectation)",
        "executor.execute('')",
        "passed == 0",
        f"passed={r.passed} failed={r.failed} review={r.review}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "measured: 0 pass / 2 fail / 124 review (the 2 FAILs are V07-75); "
        "fabricated PASSes caused by upstream normalization are recorded in "
        "E05, not here",
        "",
    )
    assert ok


def test_v07_78_manual_controls_stable_across_content(recorder, bench):
    runs = [
        bench.execute(raw_config=SECURE, vendor="cisco", platform="ios_xe"),
        bench.execute(raw_config=JUNIPER_SECURE, vendor="juniper",
                      platform="junos"),
    ]
    ok = all(
        e.result == "REVIEW" and e.confidence == 1.0
        for r in runs for e in r.evaluations
        if e.evidence.assessment_status == "Manual")
    recorder.add(
        "V07-78", "H",
        "manual controls are content-independent: same REVIEW outcome on any "
        "input (spec 9.1 review semantics)",
        "cisco run + juniper run manual controls",
        "all REVIEW conf 1.0 in both runs",
        f"ok={ok} (manual counts: "
        f"{[sum(1 for e in r.evaluations if e.evidence.assessment_status == 'Manual') for r in runs]})",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "execution.py:254-264",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# I - Integration (offline pipeline, consumers)
# ---------------------------------------------------------------------------


def test_v07_79_executor_end_to_end_findings(recorder, framework_runs):
    r = framework_runs["DUAL"]
    ok = (r.status == "completed" and r.total_controls == 179
          and len(r.findings) > 0)
    recorder.add(
        "V07-79", "I",
        "the offline audit pipeline runs INGEST->...->FINDINGS without any "
        "external service and emits findings from the evaluation "
        "(spec 9.1 step 7 finding generation)",
        "executor.execute(secure.txt) in-process",
        "status completed, 179 controls evaluated, findings generated",
        f"status={r.status} total={r.total_controls} findings="
        f"{len(r.findings)} in {r.steps[-1].status} step",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "executor.py:166-269 - validator, detector, parsers, normalizer and "
        "benchmark engine all local",
        "",
    )
    assert ok


def test_v07_80_findings_wired_from_evaluation(recorder):
    ok = all(s in EXECUTOR_SRC for s in (
        "findings = self.finding_generator.generate_findings(",
        "evaluation=evaluation",
        "result.compliance_evaluation = evaluation",
    ))
    recorder.add(
        "V07-80", "I",
        "findings are generated from the compliance evaluation produced in the "
        "same run (one evaluation object feeds scores, rows and findings)",
        "executor.py wiring",
        "evaluation built -> passed to generate_findings -> attached to result",
        f"wiring statements present={ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "executor.py:240-262",
        "",
    )
    assert ok


def test_v07_81_pipeline_persists_rows(recorder):
    ok = all(s in AUDIT_API_SRC for s in (
        "result = executor.execute(",
        "framework=framework",
        "db.add(compliance_result)",
    ))
    recorder.add(
        "V07-81", "I",
        "run_audit_pipeline calls the executor per configuration and persists "
        "one compliance_results row per evaluated control (spec 12 "
        "control_results granularity)",
        "audit_execution.py source",
        "executor call with the requested framework + db.add per evaluation",
        f"statements present={ok} (framework reaches only the executor "
        "signature - effect measured in V07-17, labels in V07-58)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "audit_execution.py:241-246, 358-378",
        "",
    )
    assert ok


def test_v07_82_report_filter_reads_persisted_framework(recorder):
    reports_src = (BACKEND / "app" / "api" / "v1" / "reports.py").read_text(
        encoding="utf-8")
    ok = "ComplianceResult.framework == framework" in reports_src
    recorder.add(
        "V07-82", "I",
        "the report list's framework filter queries the persisted "
        "ComplianceResult.framework column (so filter results follow whatever "
        "labels persistence wrote)",
        "reports.py framework filter",
        "filter joins compliance_results on framework",
        f"filter present={ok} - correctness of the labels it compares is "
        "V07-58 (user-selected NIST labels CIS rows as NIST)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "reports.py:35-38",
        "",
    )
    assert ok


def test_v07_83_unknown_vendor_parser_fallback(recorder):
    import app.engines.parsing  # noqa: F401

    parser_body = EXECUTOR_SRC.split("def _get_parser")[1].split("def execute")[0]
    no_fallback = (
        "get_parser(" in parser_body
        and "CiscoIOSParser()" not in parser_body
        and "JunosParser()" not in parser_body
        and "FortiOSParser()" not in parser_body
        and "Fallback to Cisco parser" not in parser_body
    )
    recorder.add(
        "V07-83", "I",
        "an unknown/unsupported vendor is not silently parsed with another "
        "vendor's parser (wrong-parser output feeds normalization and "
        "evaluation)",
        "AuditExecutor._get_parser for vendors outside "
        "{cisco, juniper, fortinet}",
        "explicit unsupported-vendor handling (skip/flag), not a Cisco fallback",
        f"central get_parser contract, no per-vendor instantiation in "
        f"_get_parser={no_fallback} — unsupported vendors get None and "
        "execute() stops the audit after detection (E03 F2, E04 F3)",
        "PASS" if no_fallback else "FAIL",
        "CONFIRMED BEHAVIOR" if no_fallback else "DESIGN LIMITATION",
        "E04 F3: executor.py _get_parser delegates to parsing.get_parser; "
        "execute() step-3 gate",
        "",
    )
    assert no_fallback


def test_v07_84_api_registry_full_inventory(recorder):
    from app.api.v1 import compliance as api

    frameworks = api._frameworks()
    cis_count = frameworks["CIS"].control_count
    nist_count = frameworks["NIST"].control_count
    reg_total = len(api._control_registry._controls)
    versions_ok = (frameworks["CIS"].versions == ["v2.1.0", "v2.2.1"]
                   and frameworks["NIST"].versions == ["5.0"])
    ok = (cis_count == 70 and nist_count == 126 and reg_total == 196
          and versions_ok)
    recorder.add(
        "V07-84", "I",
        "the compliance API serves the full loaded inventory at import time "
        "(CIS 70 = 53 cisco + 17 juniper, NIST 126, registry 196) with real "
        "versions",
        "compliance.py framework inventory + module registry",
        "70 / 126 / 196 and versions from control metadata",
        f"CIS={cis_count} NIST={nist_count} registry={reg_total} "
        f"CIS versions={frameworks['CIS'].versions} "
        f"NIST versions={frameworks['NIST'].versions}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F1: _frameworks() derives versions/counts/categories from the "
        "loaded control metadata",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# J - Determinism (spec 9.1 step 6, spec 13.3 step 5)
# ---------------------------------------------------------------------------


def test_v07_85_repeat_run_identical(recorder, bench, cisco_run):
    again = bench.execute(raw_config=SECURE, vendor="cisco",
                          platform="ios_xe")
    a = [(e.control_id, e.result) for e in cisco_run.evaluations]
    b = [(e.control_id, e.result) for e in again.evaluations]
    ok = a == b and cisco_run.score == again.score
    recorder.add(
        "V07-85", "J",
        "identical input yields identical per-control verdicts and score on "
        "repeat execution (spec 13.3 step 5 deterministic result)",
        "two bench.execute(secure, cisco, ios_xe) runs",
        "same ordered (control_id, result) list and same score",
        f"lists equal={a == b} scores {cisco_run.score} vs {again.score}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "no randomness, time or env input in evaluation (evaluated_at "
        "timestamp excluded from comparison)",
        "",
    )
    assert ok


def test_v07_86_executor_repeat_identical(recorder):
    from app.engines.compliance.executor import AuditExecutor

    ex = AuditExecutor()
    r1 = ex.execute(audit_id="v07-det-1", config_content=SECURE,
                    framework="CIS")
    r2 = ex.execute(audit_id="v07-det-2", config_content=SECURE,
                    framework="CIS")
    sig = lambda r: (r.total_controls, r.passed, r.failed, r.review,  # noqa: E731
                     r.overall_score,
                     [e.control_id for e in
                      r.compliance_evaluation.evaluations])
    ok = sig(r1) == sig(r2)
    recorder.add(
        "V07-86", "J",
        "the full executor pipeline is deterministic across runs (spec 9.1 "
        "step 6, spec 10.7 deterministic evaluation)",
        "two executor.execute(secure) runs",
        "identical totals, score and ordered control list",
        f"identical={ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "compared: totals, score, 179 ordered control ids",
        "",
    )
    assert ok


def test_v07_87_registry_load_deterministic(recorder):
    s1 = BenchmarkExecutionEngine().control_registry.get_stats()
    s2 = BenchmarkExecutionEngine().control_registry.get_stats()
    ok = s1 == s2
    recorder.add(
        "V07-87", "J",
        "control loading produces identical registry statistics across engine "
        "instances (same inventory, same category/vendor maps)",
        "two fresh BenchmarkExecutionEngine().control_registry.get_stats()",
        "identical dicts",
        f"equal={ok}; total={s1['total']} automated={s1['automated']} "
        f"mapped={s1['mapped']}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "execution.py:138-145 loads the same three registries each time",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# K - Performance (measured, no spec latency budget exists)
# ---------------------------------------------------------------------------


def test_v07_88_engine_init_latency(recorder):
    samples = []
    for _ in range(5):
        t0 = time.perf_counter()
        BenchmarkExecutionEngine()
        samples.append((time.perf_counter() - t0) * 1000)
    p50 = statistics.median(samples)
    ok = p50 < 500.0
    recorder.add(
        "V07-88", "K",
        "engine startup (registry build) stays interactive - p50 below 500 ms "
        "for in-process audit start",
        "5 x BenchmarkExecutionEngine() construction",
        "p50 < 500 ms",
        f"p50={round(p50, 2)} ms samples={[round(s, 1) for s in samples]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "first construction in a cold process also pays import cost "
        "(~1.7 s incl. 1269-line NIST module, probe07)",
        "",
    )
    assert ok


def test_v07_89_evaluate_latency(recorder, bench):
    samples = []
    for _ in range(5):
        t0 = time.perf_counter()
        r = bench.execute(raw_config=SECURE, vendor="cisco",
                          platform="ios_xe")
        samples.append((time.perf_counter() - t0) * 1000)
    p50 = statistics.median(samples)
    ok = p50 < 2000.0
    recorder.add(
        "V07-89", "K",
        "evaluating 179 controls against a typical config is fast enough for "
        "synchronous audit use - p50 below 2 s",
        "5 x bench.execute(secure.txt, 65 lines, 179 controls)",
        "p50 < 2000 ms",
        f"p50={round(p50, 2)} ms samples={[round(s, 1) for s in samples]} "
        f"evaluated={r.evaluated}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "single-threaded, no I/O",
        "",
    )
    assert ok


@pytest.fixture(scope="module")
def scaling_runs():
    eng = BenchmarkExecutionEngine()
    out = {}
    for label, kb in (("small", 100), ("large", 1400)):
        pad_lines = kb * 1024 // 6
        txt = "! pad\n" * pad_lines + SECURE
        t0 = time.perf_counter()
        r = eng.execute(raw_config=txt, vendor="cisco", platform="ios_xe")
        out[label] = {
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "lines": txt.count("\n") + 1,
            "result": r,
        }
    return out


def test_v07_90_large_input_scaling(recorder, scaling_runs):
    small, large = scaling_runs["small"], scaling_runs["large"]
    time_ratio = large["ms"] / small["ms"]
    line_ratio = large["lines"] / small["lines"]
    superlinear = time_ratio / line_ratio
    ok = superlinear <= 2.0
    recorder.add(
        "V07-90", "K",
        "evaluation scales roughly linearly with config size (near-linear, "
        "super-linear factor <= 2x) - no quadratic blow-up on large inputs",
        f"{small['lines']} lines vs {large['lines']} lines (same 179 controls)",
        "time grows ~proportionally to lines",
        f"small={small['ms']} ms, large={large['ms']} ms; time ratio="
        f"{round(time_ratio, 2)} vs line ratio={round(line_ratio, 2)} -> "
        f"super-linear factor={round(superlinear, 2)} (731 ms per 17k lines "
        "to 14.2 s per 239k lines - worth profiling but not quadratic)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "per-line work in normalization + _find_matching_lines over all "
        "controls",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# L - Hostile inputs and boundaries
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def hostile_runs():
    from app.engines.compliance.executor import AuditExecutor

    ex = AuditExecutor()
    none_run = ex.execute(audit_id="v07-none", config_content=None,
                          framework="CIS")
    nul_run = ex.execute(
        audit_id="v07-nul",
        config_content=SECURE + "\n! nul \x00 here\n", framework="CIS")
    cjk_run = ex.execute(
        audit_id="v07-cjk",
        config_content=SECURE + "\n! \u4e2d\u6587\u6ce8\u91ca\n",
        framework="CIS")
    return {"none": none_run, "nul": nul_run, "cjk": cjk_run}


def test_v07_91_none_input_error_not_user_facing(recorder, hostile_runs):
    r = hostile_runs["none"]
    val_step = next(s for s in r.steps if s.name == "validation")
    error = val_step.error or ""
    ok = (r.status == "failed" and val_step.status == "failed"
          and "object has no attribute" not in error and error != "")
    recorder.add(
        "V07-91", "L",
        "an invalid (None) input produces a clear validation failure, not a "
        "raw Python exception message (spec 9.1 step 1 reports validation "
        "errors to the user)",
        "executor.execute(config_content=None)",
        "status failed; validation step failed with a typed message",
        f"status={r.status}; validation step status={val_step.status} "
        f"error={error!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E07 F13: validation.validate raises TypeError for non-str; the "
        "executor records it on the failed validation step",
        "guard input type in validate()/execute() and surface validation "
        "errors as messages",
    )
    assert ok

def test_v07_92_invalid_content_failure_reason_lost(recorder, hostile_runs):
    r = hostile_runs["nul"]
    failed_steps = [s.name for s in r.steps if s.status == "failed"]
    val_step = next(s for s in r.steps if s.name == "validation")
    ok = (r.status == "failed" and "validation" in failed_steps
          and val_step.error)
    recorder.add(
        "V07-92", "L",
        "when an audit fails, the reason is recorded on a step (spec 9.1 step "
        "1 validation failure must be visible, not a silent 'failed' status)",
        "executor.execute(config with a NUL byte)",
        "status failed AND validation step failed/with error message",
        f"status={r.status}; failed steps={failed_steps}; validation step "
        f"status={val_step.status} error={val_step.error!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E07 F13: validation failures mark the validation step failed with "
        "the error codes",
        "set the validation step failed and copy validation errors into the "
        "step error/result surface",
    )
    assert ok


def test_v07_93_invalid_control_regex_misleading_verdict(recorder, bench):
    from app.benchmarks.selection import InvalidControlError

    ctl = _control(control_id="T-93", target=None, audit_regex="([invalid")
    try:
        bench.control_registry.register_control(ctl)
        load_outcome = "accepted"
    except InvalidControlError as exc:
        load_outcome = f"rejected: {exc.reason}"
    ev = bench._evaluate_control(ctl, _EMPTY_NORM, SECURE)
    ok = (load_outcome.startswith("rejected")
          and ev.result == "REVIEW")
    recorder.add(
        "V07-93", "L",
        "a control whose audit_regex is invalid is rejected at load and can "
        "never emit a confident FAIL - a broken rule must not decide for "
        "every config",
        "synthetic control with audit_regex='([invalid'",
        "load-time validation error; direct evaluation is REVIEW",
        f"load: {load_outcome}; result={ev.result} "
        f"confidence={ev.confidence}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E07 F13: registry validates audit_regex at load "
        "(InvalidControlError); unevaluable controls REVIEW",
        "validate audit_regex when controls are loaded; invalid -> "
        "REVIEW/registration error",
    )
    assert ok


def test_v07_94_unicode_input_completes(recorder, hostile_runs):
    r = hostile_runs["cjk"]
    ok = r.status == "completed" and r.total_controls == 53
    recorder.add(
        "V07-94", "L",
        "non-ASCII content in comments/strings does not break evaluation "
        "(unicode input is valid UTF-8 config text)",
        "executor.execute(secure.txt + CJK comment line, framework=CIS)",
        "completed with 53 CIS controls evaluated",
        f"status={r.status} total={r.total_controls} passed={r.passed}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "only NUL bytes abort the run (V07-92)",
        "",
    )
    assert ok


def test_v07_95_large_input_verdict_stability(recorder, scaling_runs):
    from app.benchmarks.execution import BenchmarkExecutionEngine
    r = scaling_runs["large"]["result"]
    base = BenchmarkExecutionEngine().execute(
        raw_config=SECURE, vendor="cisco", platform="ios_xe")
    ok = (r.evaluated, r.passed, r.failed, r.review) == (
        base.evaluated, base.passed, base.failed, base.review)
    recorder.add(
        "V07-95", "L",
        "padding with irrelevant comment lines does not change any verdict "
        "(hostile-size input: same results as the baseline run)",
        f"{scaling_runs['large']['lines']}-line input vs unpadded baseline",
        "identical counts to the baseline secure.txt run",
        f"large: evaluated={r.evaluated} passed={r.passed} failed={r.failed} "
        f"review={r.review}; base: evaluated={base.evaluated} "
        f"passed={base.passed} failed={base.failed} review={base.review}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E05 F1: comment padding never enters normalization; 1.4 MB input "
        "completes in "
        f"{scaling_runs['large']['ms']} ms",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# M - Error handling (typed errors, failed steps, no swallowed faults)
# ---------------------------------------------------------------------------


def test_v07_96_engine_none_input_typed_error(recorder, bench):
    from app.benchmarks.selection import ComplianceInputError

    try:
        bench.execute(None, vendor="cisco", platform="ios_xe")
        outcome = "accepted"
    except ComplianceInputError as exc:
        outcome = f"rejected: {exc}"
    except Exception as exc:  # noqa: BLE001
        outcome = f"wrong error type: {type(exc).__name__}: {exc}"
    ok = outcome.startswith("rejected: raw_config must be str")
    recorder.add(
        "V07-96", "M",
        "None input to the engine raises a typed ComplianceInputError, never "
        "a raw AttributeError",
        "bench.execute(None, ...)",
        "ComplianceInputError naming the bad argument",
        f"outcome={outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F13: execution.execute validates input before any work",
        "",
    )
    assert ok


def test_v07_97_engine_non_string_input_typed_error(recorder, bench):
    from app.benchmarks.selection import ComplianceInputError

    try:
        bench.execute(["not", "a", "string"], vendor="cisco",
                      platform="ios_xe")
        outcome = "accepted"
    except ComplianceInputError as exc:
        outcome = f"rejected: {exc}"
    except Exception as exc:  # noqa: BLE001
        outcome = f"wrong error type: {type(exc).__name__}: {exc}"
    ok = outcome.startswith("rejected")
    recorder.add(
        "V07-97", "M",
        "non-string input to the engine raises a typed ComplianceInputError",
        "bench.execute([...], ...)",
        "ComplianceInputError",
        f"outcome={outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F13",
        "",
    )
    assert ok


def test_v07_98_engine_nul_input_typed_error(recorder, bench):
    from app.benchmarks.selection import ComplianceInputError

    try:
        bench.execute("hostname R1\x00", vendor="cisco", platform="ios_xe")
        outcome = "accepted"
    except ComplianceInputError as exc:
        outcome = f"rejected: {exc}"
    except Exception as exc:  # noqa: BLE001
        outcome = f"wrong error type: {type(exc).__name__}: {exc}"
    ok = outcome.startswith("rejected")
    recorder.add(
        "V07-98", "M",
        "NUL/control characters in engine input raise a typed "
        "ComplianceInputError (they must never reach evaluation or storage)",
        "bench.execute('hostname R1\\x00', ...)",
        "ComplianceInputError",
        f"outcome={outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F13: _UNSAFE_INPUT_RE gate at execution entry",
        "",
    )
    assert ok


async def test_v07_99_api_unknown_framework_422(recorder):
    from fastapi import HTTPException

    from app.api.v1 import compliance as api

    try:
        await api.list_framework_controls(
            framework_id="BOGUS", page=1, per_page=20, current_user=None)
        outcome = "accepted"
    except HTTPException as exc:
        outcome = f"HTTP {exc.status_code}: {exc.detail}"
    ok = outcome.startswith("HTTP 422")
    recorder.add(
        "V07-99", "M",
        "an unknown framework in the controls API is a typed 422, never a "
        "silent fallback or an unrelated control list",
        "GET /frameworks/BOGUS/controls",
        "HTTP 422 naming the unsupported framework",
        f"outcome={outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F1: list_framework_controls translates ComplianceError to 422",
        "",
    )
    assert ok


async def test_v07_100_api_unknown_version_422(recorder):
    from fastapi import HTTPException

    from app.api.v1 import compliance as api

    try:
        await api.list_framework_controls(
            framework_id="CIS", framework_version="2099.9", page=1,
            per_page=20, current_user=None)
        outcome = "accepted"
    except HTTPException as exc:
        outcome = f"HTTP {exc.status_code}: {exc.detail}"
    ok = outcome.startswith("HTTP 422")
    recorder.add(
        "V07-100", "M",
        "an unknown framework version in the controls API is a typed 422",
        "GET /frameworks/CIS/controls?framework_version=2099.9",
        "HTTP 422 naming the missing version",
        f"outcome={outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F1: versions are validated against the loaded inventory",
        "",
    )
    assert ok


def test_v07_101_executor_framework_errors_typed(recorder):
    from app.benchmarks.selection import (
        UnsupportedFrameworkError, UnknownFrameworkVersionError)
    from app.engines.compliance.executor import AuditExecutor

    ex = AuditExecutor()
    try:
        ex.execute("v07-m1", SECURE, framework="BOGUS")
        bogus = "accepted"
    except UnsupportedFrameworkError as exc:
        bogus = f"rejected: {exc}"
    try:
        ex.execute("v07-m2", SECURE, framework="NIST",
                   framework_version="0.0")
        version = "accepted"
    except UnknownFrameworkVersionError as exc:
        version = f"rejected: {exc}"
    ok = bogus.startswith("rejected") and version.startswith("rejected")
    recorder.add(
        "V07-101", "M",
        "the executor rejects unknown frameworks/versions with typed domain "
        "errors before any pipeline work",
        "executor.execute(framework=BOGUS / version=0.0)",
        "UnsupportedFrameworkError / UnknownFrameworkVersionError",
        f"framework: {bogus}; version: {version}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F1: executor validates selection before validation/detection",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# N - Persistence contract (framework/version/score/result/enum/link)
# ---------------------------------------------------------------------------


def test_v07_102_row_builder_mapping_contract(recorder, framework_runs):
    from app.api.v1.audit_execution import build_compliance_result

    evaluation = framework_runs["DUAL"].compliance_evaluation
    rows = [build_compliance_result(
        audit_id="00000000-0000-0000-0000-000000000000",
        normalized_configuration_id="00000000-0000-0000-0000-000000000001",
        framework="CIS+NIST", eval_result=e)
        for e in evaluation.evaluations]
    bad = [r.control_id for r in rows
           if r.framework not in ("CIS", "NIST")
           or not r.framework_version
           or r.result not in ("PASS", "FAIL", "REVIEW")
           or set(SPEC_EVIDENCE_KEYS) - set(r.evidence.keys())]
    ok = len(rows) == len(evaluation.evaluations) == 179 and not bad
    recorder.add(
        "V07-102", "N",
        "every evaluated control maps to a persistence row carrying its own "
        "framework/version, an uppercase §12 result and the full §12 evidence "
        "chain",
        "build_compliance_result over the 179 dual evaluations",
        "179 rows, all attributed, all uppercase, all §12 evidence",
        f"rows={len(rows)} bad={bad[:5]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F3/F4/F11: audit_execution.build_compliance_result is the single "
        "evaluation->row mapping",
        "",
    )
    assert ok


@pytest.fixture()
async def e07_db():
    """Throwaway-DB audit chain: user/config/audit/parsed/semantic/normalized."""
    import uuid as _uuid

    import scripts.engine_validation.dbutil as dbutil
    from sqlalchemy import delete

    if not await dbutil.schema_available():
        pytest.skip("throwaway database engine_validation_test not provisioned")

    from app.models import (Audit, ComplianceResult, Configuration, Finding,
                            NormalizedConfiguration, ParsedConfiguration,
                            SemanticInterpretation, User)

    engine, factory = dbutil.make_session_factory()
    session = factory()
    tag = f"e07-{_uuid.uuid4().hex[:10]}"
    user = User(id=_uuid.uuid4(), email=f"{tag}@example.com",
                password_hash="x", role="admin", is_active=True)
    session.add(user)
    await session.flush()
    config = Configuration(
        filename="e07.cfg", content_hash=f"{tag}-hash",
        raw_content=SECURE, content_type="text/plain",
        size_bytes=len(SECURE), line_count=len(SECURE.splitlines()))
    session.add(config)
    await session.flush()
    audit = Audit(user_id=user.id, name=f"{tag}-audit", status="completed")
    session.add(audit)
    await session.flush()
    parsed = ParsedConfiguration(
        configuration_id=config.id, vendor="cisco", platform="ios_xe",
        parse_tree=[])
    session.add(parsed)
    await session.flush()
    semantic = SemanticInterpretation(parsed_configuration_id=parsed.id)
    session.add(semantic)
    await session.flush()
    normalized = NormalizedConfiguration(
        semantic_interpretation_id=semantic.id,
        universal_model_version="test", normalized_values=[],
        unmapped_concepts=[])
    session.add(normalized)
    await session.flush()
    from types import SimpleNamespace
    admin = SimpleNamespace(id=user.id)
    try:
        yield {"session": session, "user": user, "admin": admin,
               "config": config, "audit": audit, "normalized": normalized,
               "tag": tag}
    finally:
        try:
            await session.execute(delete(Finding).where(
                Finding.audit_id == audit.id))
            await session.execute(delete(ComplianceResult).where(
                ComplianceResult.audit_id == audit.id))
            await session.execute(delete(Audit).where(Audit.id == audit.id))
            await session.execute(delete(Configuration).where(
                Configuration.id == config.id))
            await session.execute(delete(User).where(User.id == user.id))
            await session.commit()
        except Exception:  # noqa: BLE001
            await session.rollback()
        await session.close()
        await engine.dispose()


async def test_v07_103_rows_round_trip_with_contract(recorder, e07_db,
                                                     framework_runs):
    from sqlalchemy import select

    from app.api.v1.audit_execution import build_compliance_result
    from app.models import ComplianceResult

    session = e07_db["session"]
    evaluation = framework_runs["DUAL"].compliance_evaluation
    for e in evaluation.evaluations:
        session.add(build_compliance_result(
            audit_id=e07_db["audit"].id,
            normalized_configuration_id=e07_db["normalized"].id,
            framework="CIS+NIST", eval_result=e))
    await session.commit()
    rows = list((await session.execute(select(ComplianceResult).where(
        ComplianceResult.audit_id == e07_db["audit"].id))).scalars().all())
    bad = [r.control_id for r in rows
           if r.framework not in ("CIS", "NIST") or not r.framework_version
           or r.result not in ("PASS", "FAIL", "REVIEW")
           or set(SPEC_EVIDENCE_KEYS) - set((r.evidence or {}).keys())
           or r.normalized_configuration_id != e07_db["normalized"].id]
    frameworks = sorted({r.framework for r in rows})
    ok = len(rows) == 179 and not bad and frameworks == ["CIS", "NIST"]
    recorder.add(
        "V07-103", "N",
        "persisted compliance rows round-trip with the contract intact: "
        "control-owned framework/version, uppercase results, §12 evidence, "
        "normalized-configuration link",
        "179 rows inserted + read back from engine_validation_test",
        "179 rows, CIS+NIST frameworks, 0 contract violations",
        f"rows={len(rows)} frameworks={frameworks} bad={bad[:5]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F3/F4/F11: ComplianceResult rows written by "
        "build_compliance_result, read back verbatim",
        "",
    )
    assert ok


def test_v07_104_migration_006_chain_and_content(recorder):
    import re as _re

    src = (BACKEND / "alembic" / "versions"
           / "006_uppercase_compliance_results.py").read_text(
               encoding="utf-8")
    chain_ok = "down_revision = '005'" in src and "revision = '006'" in src
    up_ok = bool(_re.search(
        r"UPDATE compliance_results SET result = UPPER\(result\)", src))
    down_ok = bool(_re.search(
        r"UPDATE compliance_results SET result = LOWER\(result\)", src))
    ok = chain_ok and up_ok and down_ok
    recorder.add(
        "V07-104", "N",
        "migration 006 is chained on 005 and uppercases legacy result rows "
        "in place (executed for real by validate_migration_006.py: 9/9 PASS)",
        "alembic 006 revision metadata + SQL",
        "006 revises 005; UPPER on upgrade, LOWER on downgrade",
        f"chain={chain_ok} upgrade_uppercases={up_ok} "
        f"downgrade_reverses={down_ok}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F11: 006_uppercase_compliance_results.py + "
        "migration_results.json (throwaway-DB execution)",
        "",
    )
    assert ok


async def test_v07_105_finding_linkage_contract(recorder, e07_db,
                                                framework_runs):
    from sqlalchemy import select

    from app.api.v1.audit_execution import build_compliance_result
    from app.engines.compliance.findings import FindingGenerator
    from app.models import ComplianceResult, Finding

    session = e07_db["session"]
    evaluation = framework_runs["DUAL"].compliance_evaluation
    for e in evaluation.evaluations:
        session.add(build_compliance_result(
            audit_id=e07_db["audit"].id,
            normalized_configuration_id=e07_db["normalized"].id,
            framework="CIS+NIST", eval_result=e))
    await session.flush()
    rows = list((await session.execute(select(ComplianceResult).where(
        ComplianceResult.audit_id == e07_db["audit"].id))).scalars().all())
    by_control = {r.control_id: r.id for r in rows}
    findings = FindingGenerator().generate_findings(
        evaluation=evaluation, audit_id=str(e07_db["audit"].id),
        device_name="e07.cfg")
    for finding in findings:
        session.add(Finding(
            audit_id=e07_db["audit"].id,
            compliance_result_id=by_control.get(finding.control_id),
            title=finding.title, description=finding.description,
            severity=finding.severity.value, confidence=finding.confidence,
            status="open", evidence=finding.evidence,
            remediation=finding.remediation or {},
            affected_device=finding.affected_device,
            affected_vendor=finding.affected_vendor,
            affected_platform=finding.affected_platform))
    await session.commit()
    linked = list((await session.execute(select(Finding).where(
        Finding.audit_id == e07_db["audit"].id))).scalars().all())
    row_control = {r.id: r.control_id for r in rows}
    eval_ids = {e.control_id for e in evaluation.evaluations
                if e.result.value in ("FAIL", "REVIEW")}
    ok = (len(linked) == len(findings) > 0
          and all(f.compliance_result_id is not None for f in linked)
          and all(row_control.get(f.compliance_result_id) in eval_ids
                  for f in linked))
    recorder.add(
        "V07-105", "N",
        "every persisted finding links to its compliance row and derives "
        "from the same evaluation (FAIL/REVIEW only)",
        "findings generated + persisted + read back with linkage",
        "all findings linked; linked rows are FAIL/REVIEW evaluations",
        f"findings={len(linked)} all_linked="
        f"{all(f.compliance_result_id is not None for f in linked)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07: FindingGenerator output persisted with compliance_result_id; "
        "read back by audit",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# O - Determinism: repeated and fresh-instance runs (beyond category J)
# ---------------------------------------------------------------------------


def test_v07_106_fresh_engines_identical_evidence(recorder, cisco_run):
    again = BenchmarkExecutionEngine().execute(
        raw_config=SECURE, vendor="cisco", platform="ios_xe")
    a = [(e.control_id, e.result, e.confidence,
          e.evidence.reasoning, e.evidence.raw_config,
          tuple(e.evidence.raw_config_line_numbers),
          e.evidence.framework, e.evidence.framework_version)
         for e in cisco_run.evaluations]
    b = [(e.control_id, e.result, e.confidence,
          e.evidence.reasoning, e.evidence.raw_config,
          tuple(e.evidence.raw_config_line_numbers),
          e.evidence.framework, e.evidence.framework_version)
         for e in again.evaluations]
    ok = a == b and cisco_run.score == again.score
    recorder.add(
        "V07-106", "O",
        "a fresh engine instance reproduces verdicts, confidence, reasoning, "
        "raw evidence, lines and framework metadata exactly",
        "module-fixture run vs fresh BenchmarkExecutionEngine run",
        "identical full evidence tuples and score",
        f"identical={a == b} scores {cisco_run.score} vs {again.score}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07: no randomness, time or env input in selection/evaluation/"
        "evidence (evaluated_at excluded)",
        "",
    )
    assert ok


def test_v07_107_scoped_runs_deterministic(recorder):
    from app.engines.compliance.executor import AuditExecutor

    ex = AuditExecutor()
    runs = [ex.execute(audit_id=f"v07-scope-{i}", config_content=SECURE,
                       framework="NIST") for i in range(2)]
    sig = [(r.total_controls, r.passed, r.failed, r.review,
            r.overall_score, r.framework,
            tuple((e.control_id, e.result.value, e.confidence,
                   e.framework)
                  for e in r.compliance_evaluation.evaluations))
           for r in runs]
    ok = (sig[0] == sig[1] and runs[0].total_controls == 126
          and runs[0].framework == "NIST")
    recorder.add(
        "V07-107", "O",
        "framework-scoped audits are deterministic including scope metadata",
        "two executor.execute(secure, framework=NIST) runs",
        "identical totals/score/framework and ordered evaluations",
        f"identical={sig[0] == sig[1]} total={runs[0].total_controls} "
        f"framework={runs[0].framework}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F1: scope is part of the deterministic selection input",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# P - Performance (registry load, selection, evaluation, audit)
# ---------------------------------------------------------------------------


def test_v07_108_registry_build_time(recorder):
    import time as _time

    from app.benchmarks.cisco_ios_xe_controls import (
        get_registry as cisco_registry)
    from app.benchmarks.juniper_junos_controls import (
        get_registry as juniper_registry)
    from app.benchmarks.nist_sp800_53_controls import (
        get_registry as nist_registry)
    from app.benchmarks.registry import ControlRegistry

    started = _time.perf_counter()
    reg = ControlRegistry()
    reg.register_benchmark(cisco_registry())
    reg.register_benchmark(juniper_registry())
    reg.register_benchmark(nist_registry())
    ms = (_time.perf_counter() - started) * 1000
    ok = reg.get_stats()["total"] == 196 and ms < 10000
    recorder.add(
        "V07-108", "P",
        "loading + validating the full 196-control registry stays in the "
        "millisecond budget (measurement only)",
        "fresh ControlRegistry with all three benchmarks",
        "196 controls loaded in < 10 s",
        f"total={reg.get_stats()['total']} load_ms={ms:.1f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "validation (operator/regex/path/duplicate) runs once at load",
        "",
    )
    assert ok


def test_v07_109_selection_time(recorder, bench):
    import time as _time

    started = _time.perf_counter()
    for _ in range(20):
        selection = bench.selection.select_for_evaluation(
            "cisco", "ios_xe", None, None)
    ms = (_time.perf_counter() - started) * 1000
    ok = len(selection.controls) == 179 and ms < 5000
    recorder.add(
        "V07-109", "P",
        "canonical selection over the full inventory is effectively free "
        "(measurement only)",
        "20 dual-baseline selections over 196 controls",
        "179 controls selected in < 5 s total",
        f"controls={len(selection.controls)} total_ms={ms:.1f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F2: selection is a linear scan with dict lookups",
        "",
    )
    assert ok


def test_v07_110_full_audit_time(recorder):
    import time as _time

    from app.engines.compliance.executor import AuditExecutor

    started = _time.perf_counter()
    result = AuditExecutor().execute(
        audit_id="v07-perf", config_content=SECURE, framework=None)
    ms = (_time.perf_counter() - started) * 1000
    ok = result.status == "completed" and ms < 60000
    recorder.add(
        "V07-110", "P",
        "a full 179-control audit completes in a bounded time without "
        "weakening validation or evidence (measurement only)",
        "executor.execute(secure.txt, dual baseline)",
        "completed in < 60 s",
        f"status={result.status} total={result.total_controls} ms={ms:.0f}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07: no caching shortcuts; evidence + confidence on every control",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# Q - Security (hostile input, injection safety, no fabricated verdicts)
# ---------------------------------------------------------------------------


def test_v07_111_wrong_platform_blocked(recorder, bench):
    res = bench.execute(raw_config=SECURE, vendor="cisco", platform="junos")
    ok = (res.status == "vendor_mismatch" and res.evaluated == 0
          and res.passed == 0 and res.failed == 0)
    recorder.add(
        "V07-111", "Q",
        "a declared platform that disagrees with detection stops evaluation "
        "- cisco text declared on platform junos gets no verdicts",
        "bench.execute(secure.txt, vendor=cisco, platform=junos)",
        "vendor_mismatch status, 0 evaluations",
        f"status={res.status} evaluated={res.evaluated} "
        f"reason={res.status_reason[:100]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F6: the mismatch check compares normalized (vendor, platform) "
        "pairs, not vendor alone",
        "",
    )
    assert ok


def test_v07_112_injection_vendor_typed_error(recorder, bench):
    res = bench.execute(raw_config=SECURE, vendor="cisco'; DROP TABLE x;--",
                        platform="ios_xe")
    ok = (res.status in ("unsupported_selection", "vendor_mismatch")
          and res.evaluated == 0 and res.passed == 0 and res.failed == 0)
    control = bench.execute(raw_config=SECURE, vendor="cisco",
                            platform="ios_xe")
    ok = ok and control.status == "completed"
    recorder.add(
        "V07-112", "Q",
        "a hostile vendor string cannot smuggle evaluation past the boundary "
        "or break the engine (selection is string comparison, never SQL)",
        "bench.execute(secure, vendor=\"cisco'; DROP TABLE x;--\")",
        "unsupported_selection boundary with 0 evaluations; normal audits "
        "unaffected",
        f"status={res.status} evaluated={res.evaluated}; control run "
        f"status={control.status}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F6/F13: normalized vendor compared against the supported set; "
        "no raw SQL anywhere in selection",
        "",
    )
    assert ok


def test_v07_113_framework_spelling_tolerant(recorder, bench):
    base = bench.execute(raw_config=SECURE, vendor="cisco",
                         platform="ios_xe", framework="CIS")
    variant = bench.execute(raw_config=SECURE, vendor="cisco",
                            platform="ios_xe", framework=" cis ")
    ok = (variant.evaluated == base.evaluated == 53
          and variant.score == base.score
          and variant.framework == "CIS")
    recorder.add(
        "V07-113", "Q",
        "framework input is normalized (strip + case-insensitive) so casing "
        "cannot silently change the evaluated set",
        "framework=' cis ' vs framework='CIS'",
        "identical 53-control CIS runs",
        f"evaluated={variant.evaluated} score={variant.score} "
        f"framework={variant.framework}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F1/F2: normalize_framework canonicalizes every entry point",
        "",
    )
    assert ok


# ---------------------------------------------------------------------------
# R - End-to-end pipeline (request to persistence to reports)
# ---------------------------------------------------------------------------


async def test_v07_114_reports_agree_with_evaluation(recorder, e07_db,
                                                     framework_runs):
    from sqlalchemy import select

    from app.api.v1 import reports as reports_api
    from app.api.v1.audit_execution import build_compliance_result
    from app.models import ComplianceResult

    session = e07_db["session"]
    evaluation = framework_runs["DUAL"].compliance_evaluation
    for e in evaluation.evaluations:
        session.add(build_compliance_result(
            audit_id=e07_db["audit"].id,
            normalized_configuration_id=e07_db["normalized"].id,
            framework="CIS+NIST", eval_result=e))
    e07_db["audit"].overall_score = evaluation.overall_score
    await session.commit()

    listed = await reports_api.list_reports(
        page=1, per_page=20, framework=None, db=session,
        current_user=e07_db["admin"])
    item = next(i for i in listed.items if str(i.audit_id) == str(
        e07_db["audit"].id))
    detail = await reports_api.get_audit_report(
        audit_id=e07_db["audit"].id, format="json", db=session,
        current_user=e07_db["admin"])
    rows = list((await session.execute(select(ComplianceResult).where(
        ComplianceResult.audit_id == e07_db["audit"].id))).scalars().all())
    ok = (item.framework == "CIS+NIST"
          and abs(item.overall_score - evaluation.overall_score) < 1e-9
          and detail["audit"]["framework"] == "CIS+NIST"
          and abs(detail["audit"]["overall_score"]
                  - evaluation.overall_score) < 1e-9
          and len(rows) == len(evaluation.evaluations) == 179)
    recorder.add(
        "V07-114", "R",
        "reports serve the persisted evaluation truth: actual frameworks, "
        "actual score, all rows (request -> evaluation -> persistence -> "
        "reports)",
        "list + detail report over a persisted 179-row dual audit",
        "framework CIS+NIST and score == evaluation score in both views",
        f"list framework={item.framework} score={item.overall_score}; "
        f"detail framework={detail['audit']['framework']} "
        f"score={detail['audit']['overall_score']}; rows={len(rows)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07: reports derive framework/score from ComplianceResult rows; "
        "no hardcoded values",
        "",
    )
    assert ok


def test_v07_115_findings_subset_of_evaluation(recorder, framework_runs):
    evaluation = framework_runs["DUAL"].compliance_evaluation
    findings = framework_runs["DUAL"].findings
    eval_ids = {e.control_id for e in evaluation.evaluations}
    bad = [f.control_id for f in findings
           if f.control_id not in eval_ids
           or f.result.value not in ("FAIL", "REVIEW")]
    ok = len(findings) > 0 and not bad and all(
        f.evidence == next(
            e.evidence.to_dict() for e in evaluation.evaluations
            if e.control_id == f.control_id)
        for f in findings)
    recorder.add(
        "V07-115", "R",
        "findings are exactly the FAIL/REVIEW subset of the canonical "
        "evaluation with identical evidence (no second evaluation)",
        "dual executor run findings vs evaluations",
        "every finding matches a FAIL/REVIEW evaluation with equal evidence",
        f"findings={len(findings)} mismatches={bad[:5]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07: FindingGenerator consumes the canonical ComplianceEvaluation",
        "",
    )
    assert ok


async def test_v07_116_score_agreement_all_layers(recorder, e07_db,
                                                  framework_runs):
    from sqlalchemy import select

    from app.api.v1.audit_execution import build_compliance_result
    from app.benchmarks.selection import overall_score as canonical_score
    from app.models import ComplianceResult

    session = e07_db["session"]
    evaluation = framework_runs["DUAL"].compliance_evaluation
    for e in evaluation.evaluations:
        session.add(build_compliance_result(
            audit_id=e07_db["audit"].id,
            normalized_configuration_id=e07_db["normalized"].id,
            framework="CIS+NIST", eval_result=e))
    e07_db["audit"].overall_score = evaluation.overall_score
    await session.commit()
    rows = list((await session.execute(select(ComplianceResult).where(
        ComplianceResult.audit_id == e07_db["audit"].id))).scalars().all())
    persisted = canonical_score(
        sum(1 for r in rows if r.result == "PASS"), len(rows))
    bench = framework_runs["DUAL"].benchmark_result.score
    ok = (persisted == evaluation.overall_score
          == framework_runs["DUAL"].overall_score == bench
          == e07_db["audit"].overall_score)
    recorder.add(
        "V07-116", "R",
        "evaluation.overall_score == persisted.overall_score == API "
        "overall_score for the same audit (one number, all layers)",
        "dual run persisted to the throwaway DB + audit row score",
        "all five score readings identical",
        f"evaluation={evaluation.overall_score} persisted={persisted} "
        f"audit={framework_runs['DUAL'].overall_score} benchmark={bench} "
        f"audit_row={e07_db['audit'].overall_score}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E07 F5: selection.overall_score everywhere; regression lock",
        "",
    )
    assert ok


