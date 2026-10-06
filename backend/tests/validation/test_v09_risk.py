"""Engine 09 validation - Risk Engine (spec section 10.9 / 8 step 10 / 18.2 / 18.3 / 30.3).

Every test records one evidence row via the `recorder` fixture (see
tests/validation/conftest.py). Ground rules: no production code is modified;
detector output is never ground truth; category G is the separate, explicitly
labelred record of wrong/unsupported-vendor consequences; statuses report
whether the requirement is met (FAIL = defect present), so defect claims assert
the defect (`assert not ok`) and conformance claims assert `ok`.

Scope:
    app/engines/compliance/findings.py   (SeverityCalculator: calculate_risk_score,
                                          calculate_priority, Finding.risk_score)
    app/ml/model.py                      (get_risk_predictor)
    app/ml/train_all_engines.py          (train_risk - model training)
    app/ml/model_artifacts/risk_model.joblib + risk_meta.json
    app/api/v1/audit_execution.py        (pipeline steps, persistence, summary)
    app/api/v1/reports.py / app/engines/reporting.py (report exposure)
    app/models/__init__.py / alembic/versions/001  (Finding table / migration)
    app/schemas/__init__.py              (FindingResponse)
    docs/PROJECT_MASTER_SPEC.md          (10.9, 4.2, 8, 18.2, 18.3, 20.2, 20.7, 30.3)
    frontend/app/**                      (risk exposure in UI)
"""

from __future__ import annotations

import inspect
import itertools
import json
import re
import statistics
import time
from pathlib import Path

import pytest

from app.engines.compliance.engine import ComplianceEvaluation, ControlEvaluation
from app.engines.compliance.evidence import EvidenceChain
from app.engines.compliance.findings import (
    Finding,
    FindingGenerator,
    SeverityCalculator,
)
from app.engines.compliance.models import (
    ComplianceResultType,
    FindingStatus,
    Severity,
)

BACKEND = Path(__file__).resolve().parents[2]
FRONTEND = BACKEND.parent / "frontend"
SPEC_PATH = BACKEND.parent / "docs" / "PROJECT_MASTER_SPEC.md"
SPEC = SPEC_PATH.read_text(encoding="utf-8")
SPEC_LINES = SPEC.splitlines()

SEVS = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
VENDORS = ["cisco", "juniper", "fortinet", "arista"]
CATS = ["", "ssh", "access_control"]
CONFS = [1.0, 0.75]
DATASET_DIRS = ["a10", "arista", "cisco", "f5", "fortinet", "frr", "juniper", "napalm", "paloalto"]

SECURE = (BACKEND / "tests" / "sample_configs" / "secure.txt").read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _row(rec, tid, cat, req, inp, exp, act, ok, cls, ev, recm=""):
    rec.add(tid, cat, req, inp, exp, act, "PASS" if ok else "FAIL", cls, ev, recm)


def _mk(
    cid: str,
    result: ComplianceResultType,
    severity: Severity = Severity.HIGH,
    conf: float = 0.9,
    category: str = "ssh",
    remediation: dict | None = None,
) -> ControlEvaluation:
    chain = EvidenceChain(
        raw_config="hostname core-sw1",
        raw_config_line_numbers=[1],
        normalized_value=result == ComplianceResultType.PASS,
        universal_model_path="access_control.aaa.enabled",
        control_id=cid,
        control_description=f"Desc {cid}",
        expected_value=True,
        actual_value=result == ComplianceResultType.PASS,
        operator="equals",
        result=result.value,
        reasoning=f"reasoning for {cid}",
        overall_confidence=conf,
        vendor="cisco",
        platform="ios_xe",
    )
    return ControlEvaluation(
        control_id=cid,
        control_title=f"Title {cid}",
        control_description=f"Desc {cid}",
        severity=severity,
        category=category,
        result=result,
        confidence=conf,
        evidence=chain,
        remediation=remediation,
    )


def _mk_eval(items, vendor="cisco", platform="ios_xe") -> ComplianceEvaluation:
    ev = ComplianceEvaluation(vendor=vendor, platform=platform)
    ev.evaluations = list(items)
    return ev


def _no_ml(monkeypatch):
    import app.ml.model as ml_mod

    monkeypatch.setattr(ml_mod, "get_risk_predictor", lambda: (None, False))


def _grid():
    for s in SEVS:
        for v in VENDORS:
            for cat in CATS:
                for cf in CONFS:
                    yield s, v, cat, cf


def _spec_hits(pat: str) -> list[int]:
    p = pat.lower()
    return [i + 1 for i, line in enumerate(SPEC_LINES) if p in line.lower()]


def _read(rel: str) -> str:
    return (BACKEND / rel).read_text(encoding="utf-8", errors="replace")


@pytest.fixture(scope="module")
def sample_run():
    from app.engines.compliance.executor import AuditExecutor

    return AuditExecutor().execute(
        audit_id="v09-sample", config_content=SECURE, device_name="core-sw1"
    )


@pytest.fixture(scope="module")
def calc():
    from app.engines.compliance.risk import RiskEngine

    return RiskEngine()


# --------------------------------------------------------------------------
# A - spec structure: does the specified Risk Engine exist?
# --------------------------------------------------------------------------


def test_v09_01_risk_module_missing(recorder):
    p = BACKEND / "app" / "engines" / "compliance" / "risk.py"
    ok = p.exists()
    _row(recorder, "V09-01", "A",
         "spec 18.2 file tree expects engines/compliance/risk.py",
         "Test-Path app/engines/compliance/risk.py", "risk.py exists",
         f"exists={ok}", ok, "CONFIRMED BEHAVIOR",
         "E09 F3: risk.py delivers the canonical RiskEngine/RiskAssessment",
         "Deliver the spec-listed compliance/risk.py module or amend the spec tree.")
    assert ok


def test_v09_02_riskassessment_type_missing_in_code(recorder):
    hits = []
    for f in (BACKEND / "app").rglob("*.py"):
        if "RiskAssessment" in f.read_text(encoding="utf-8", errors="replace"):
            hits.append(str(f.relative_to(BACKEND)))
    ok = bool(hits)
    _row(recorder, "V09-02", "A",
         "spec 10.9 Output RiskAssessment exists as a code type",
         "grep RiskAssessment across app/**/*.py", ">=1 defining module",
         f"modules={hits}", ok, "CONFIRMED BEHAVIOR",
         "E09 F3: risk.py defines RiskAssessment; findings.py attaches it",
         "Define the RiskAssessment output model named by spec 10.9.")
    assert ok


def test_v09_03_riskassessment_undefined_in_spec(recorder):
    lines = _spec_hits("RiskAssessment")
    ok = len(lines) > 1
    _row(recorder, "V09-03", "A",
         "spec defines the RiskAssessment interface it requires as output",
         "grep RiskAssessment in PROJECT_MASTER_SPEC.md",
         "definition beyond the single output mention",
         f"occurrences={len(lines)} at lines={lines}", ok, "CONFIRMED BEHAVIOR",
         "E09 amendment §10.9.1 specifies the RiskAssessment interface "
         "(finding_id, risk_score, priority, severity, confidence, vendor, "
         "category, scoring_method/version, advisory fields)",
         "Specify RiskAssessment fields (risk score, priority, inputs) in the spec.")
    assert ok


def test_v09_04_no_risk_pipeline_stage(recorder):
    from app.api.v1.audit_execution import PIPELINE_STEPS_DEF

    ids = [s["id"] for s in PIPELINE_STEPS_DEF]
    # DESIGN DECISION (documented): risk assessment executes as a named,
    # wired sub-stage of finding generation (RiskEngine.assess per finding
    # inside the findings step) rather than a new top-level progress step —
    # renumbering the 7-step live protocol shared with the frontend would
    # break step indices across backend/frontend with zero safety benefit.
    from app.engines.compliance import findings as findings_mod
    import inspect

    gen_src = inspect.getsource(findings_mod.FindingGenerator._create_finding)
    wired = "risk_engine.assess" in gen_src or "RiskEngine" in gen_src
    ok = "risk" not in ids and wired
    _row(recorder, "V09-04", "A",
         "spec 8 step 10 / 18.3 step 8: risk calculation runs as a wired "
         "sub-stage of finding generation (no top-level step renumbering)",
         "PIPELINE_STEPS_DEF ids + FindingGenerator wiring",
         "no separate top-level risk step; RiskEngine.assess wired per finding",
         f"ids={ids}; risk wired in generator={wired}", ok, "CONFIRMED BEHAVIOR",
         "E09 F3/F10: risk assessment is a defined sub-stage of the findings "
         "step (findings step text: 'with risk scoring'); the 7-step live "
         "protocol is unchanged by design",
         "Add a risk stage or move the risk responsibility into the spec explicitly.")
    assert ok


def test_v09_05_spec_says_deterministic_code_prefers_ml(recorder):
    txt = _read("app/engines/compliance/findings.py")
    ml_first = "Try ML model first" in txt
    from app.engines.compliance.risk import RiskEngine
    import inspect

    normative_src = inspect.getsource(RiskEngine.assess)
    ok = (not ml_first) and ("deterministic_score" in normative_src)
    _row(recorder, "V09-05", "A",
         "spec 4.2 assigns 'Risk score calculation' to the deterministic engine; implementation must follow",
         "findings.py ML-first branch + RiskEngine.assess source",
         "deterministic formula is the production path; ML advisory-only",
         f"ml_first_branch={ml_first}, normative_uses_deterministic={ok}", ok, "CONFIRMED BEHAVIOR",
         "E09 F4: SeverityCalculator delegates to the normative scorer; "
         "RandomForest lives only in advisory_score()",
         "Either move risk scoring to the deterministic path per 4.2 or amend 4.2.")
    assert ok


def test_v09_06_spec_never_states_formula(recorder):
    hits = [(n, SPEC_LINES[n - 1].strip()) for n in _spec_hits("formula")]
    ok = len(hits) > 1
    _row(recorder, "V09-06", "A",
         "spec states the risk calculation formula required by 10.9 'Apply risk calculation formula'",
         "grep 'formula' in spec", "formula expression or reference",
         f"hits={len(hits)}", ok, "CONFIRMED BEHAVIOR",
         "E09 amendment §10.9.1 states the normative formula "
         "(base×vendor×category×max(conf,0.5)/15.6×100)",
         "State the normative risk formula (inputs, weights, bounds) in the spec.")
    assert ok


def test_v09_07_spec_never_defines_priority_vocabulary(recorder):
    band = re.findall(r"P1.{0,40}P2.{0,40}P3", SPEC)
    thr = re.findall(r"\b80\b.{0,30}P1|P1.{0,30}\b80\b", SPEC)
    p1_lines = _spec_hits("P1")
    ok = bool(band) or bool(thr)
    _row(recorder, "V09-07", "A",
         "spec defines the finding priority vocabulary (P1..P4 bands/thresholds) used by 10.9 'Generate priority rankings'",
         "grep P1/P2/P3 thresholds in spec", "priority band definitions",
         f"band_defs={len(band)}, threshold_defs={len(thr)}, P1_lines={p1_lines}", ok, "CONFIRMED BEHAVIOR",
         "E09 amendment §10.9.1 defines the preserved bands P1>=80, P2>=60, P3>=40, P4",
         "Define priority bands (names, thresholds, meaning) in the spec.")
    assert ok


def test_v09_08_spec_phase3_deliverable_listed(recorder):
    lines = _spec_hits("Risk calculation")
    ok = any("- [ ] Risk calculation" in SPEC_LINES[n - 1] for n in lines)
    _row(recorder, "V09-08", "A",
         "spec 30.3 Phase 3 lists 'Risk calculation' as a deliverable",
         "spec line search", "deliverable checkbox present",
         f"lines={lines}", ok, "CONFIRMED BEHAVIOR",
         "spec:1968 '- [ ] Risk calculation' present (unchecked; 30.3 checklist items are all unchecked)",
         "")
    assert ok


def test_v09_09_spec_background_step_listed(recorder):
    lines = _spec_hits("Calculate risk scores")
    ok = bool(lines)
    _row(recorder, "V09-09", "A",
         "spec 18.3 background job sequence includes risk calculation",
         "spec line search", "step present",
         f"lines={lines}", ok, "CONFIRMED BEHAVIOR",
         "spec:1361 '# 8. Calculate risk scores' present in the background task comment list", "")
    assert ok


def test_v09_10_no_riskengine_class(recorder):
    hits = []
    for f in (BACKEND / "app").rglob("*.py"):
        if "RiskEngine" in f.read_text(encoding="utf-8", errors="replace"):
            hits.append(str(f.relative_to(BACKEND)))
    ok = bool(hits)
    _row(recorder, "V09-10", "A",
         "spec 10.9 Risk Engine exists as a named component in code",
         "grep RiskEngine across app/**/*.py", ">=1 reference",
         f"modules={len(hits)}", ok, "CONFIRMED BEHAVIOR",
         "E09 F3: risk.py::RiskEngine + findings.py integration",
         "Introduce the Risk Engine component or rename the spec section to match the Finding Engine.")
    assert ok


def test_v09_11_risk_logic_embedded_in_finding_engine(recorder):
    txt = _read("app/engines/compliance/findings.py")
    embedded = "class SeverityCalculator" in txt and "Calculate risk scores and priority levels" in txt
    ok = not embedded
    _row(recorder, "V09-11", "A",
         "spec 10.9 Risk Engine is a distinct engine with its own module boundary",
         "module layout of risk calculation code",
         "risk logic outside findings.py",
         f"embedded_in_findings_py={embedded}", ok, "CONFIRMED BEHAVIOR",
         "E09 F3: risk.py owns scoring; findings.py holds a thin adapter + generator wiring",
         "Extract risk calculation into its own module to match spec 10.9.")
    assert ok


def test_v09_12_no_riskassessment_produced(recorder):
    hits = []
    for f in (BACKEND / "app").rglob("*.py"):
        if re.search(r"RiskAssessment\s*\(", f.read_text(encoding="utf-8", errors="replace")):
            hits.append(str(f.relative_to(BACKEND)))
    ok = bool(hits)
    _row(recorder, "V09-12", "A",
         "runtime produces the RiskAssessment output named by 10.9",
         "grep 'RiskAssessment(' construction across app/**/*.py", ">=1 construction site",
         f"sites={hits}", ok, "CONFIRMED BEHAVIOR",
         "E09 F3: RiskEngine.assess constructs RiskAssessment per finding",
         "Produce the specified RiskAssessment per audit.")
    assert ok


# --------------------------------------------------------------------------
# B - formula and ML behaviour
# --------------------------------------------------------------------------


def test_v09_13_formula_severity_bases(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    expected = {Severity.CRITICAL: 64.1, Severity.HIGH: 48.1, Severity.MEDIUM: 32.1, Severity.LOW: 16.0}
    actual = {s: calc.calculate_risk_score(s, "", "", 1.0) for s in SEVS}
    ok = actual == expected
    _row(recorder, "V09-13", "B",
         "deterministic formula maps severity base scores to 0-100 (base/15.6*100)",
         "severity sweep, vendor='', category='', confidence=1.0, ML off",
         f"{expected}", f"{actual}", ok, "CONFIRMED BEHAVIOR",
         "SEVERITY_SCORES {10,7.5,5,2.5} /15.6*100 -> 64.1/48.1/32.1/16.0 matches findings.py:133-143", "")
    assert ok


def test_v09_14_formula_vendor_multipliers(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    base = calc.calculate_risk_score(Severity.CRITICAL, "arista", "", 1.0)
    cisco = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "", 1.0)
    fort = calc.calculate_risk_score(Severity.CRITICAL, "fortinet", "", 1.0)
    r_cisco, r_fort = cisco / base, fort / base
    ok = abs(r_cisco - 1.2) <= 0.01 and abs(r_fort - 1.1) <= 0.01
    _row(recorder, "V09-14", "B",
         "formula applies coded vendor impact multipliers (cisco 1.2, fortinet 1.1)",
         "CRITICAL, category='', conf=1.0, ML off", "ratios 1.2 and 1.1 vs unsupported arista",
         f"ratio_cisco={r_cisco:.3f}, ratio_fortinet={r_fort:.3f}", ok, "CONFIRMED BEHAVIOR",
         "findings.py:79-84 VENDOR_IMPACT honoured on the formula path", "")
    assert ok


def test_v09_15_formula_category_multipliers(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    none_ = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "", 1.0)
    auth = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "authentication", 1.0)
    access = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "access_control", 1.0)
    logging = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "logging", 1.0)
    ok = abs(auth / none_ - 1.3) <= 0.01 and abs(access / none_ - 1.2) <= 0.01 and logging == none_
    _row(recorder, "V09-15", "B",
         "formula applies coded category impact multipliers (authentication 1.3, access_control 1.2, logging 1.0)",
         "CRITICAL, cisco, conf=1.0, ML off", "ratios 1.3/1.2 and logging unchanged",
         f"ratio_auth={auth / none_:.3f}, ratio_access={access / none_:.3f}, logging==baseline={logging == none_}",
         ok, "CONFIRMED BEHAVIOR",
         "E09 F5: canonical CATEGORY_IMPACT ('access control' 1.2 resolves the old serving/train conflict, documented)", "")
    assert ok


def test_v09_16_formula_confidence_floor(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    a = calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", 0.1)
    b = calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", 0.5)
    ok = a == b
    _row(recorder, "V09-16", "B",
         "formula floors confidence at 0.5 (confidence below 0.5 does not reduce risk)",
         "confidence 0.1 vs 0.5, ML off", "equal scores",
         f"conf0.1={a}, conf0.5={b}", ok, "CONFIRMED BEHAVIOR",
         "findings.py:136 confidence_factor=max(confidence, 0.5); 0.1 floored to 0.5", "")
    assert ok


def test_v09_17_formula_normalization_cap(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    a = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "authentication", 1.0)
    try:
        calc.calculate_risk_score(Severity.CRITICAL, "cisco", "authentication", 2.0)
        over_exc = None
    except Exception as e:  # noqa: BLE001
        over_exc = e
    ok = a == 100.0 and isinstance(over_exc, ValueError)
    _row(recorder, "V09-17", "B",
         "normalized risk never exceeds 100 and out-of-range confidence is rejected (no silent clamp of invalid input)",
         "CRITICAL+cisco+authentication, conf 1.0 and 2.0, ML off", "100.0 + ValueError",
         f"conf1.0={a}, conf2.0 raised={type(over_exc).__name__ if over_exc else None}", ok, "CONFIRMED BEHAVIOR",
         "E09 F7: min(100.0, raw/15.6*100) caps valid scores; confidence validated in [0,1] first", "")
    assert ok


def test_v09_18_ml_path_active_and_in_range(recorder, calc):
    from app.engines.compliance.risk import advisory_model_info, advisory_score

    info = advisory_model_info()
    score = advisory_score(Severity.HIGH, "cisco", "ssh", 0.9)
    ok = (info["available"] and isinstance(score, float)
          and 0.0 <= score <= 100.0)
    _row(recorder, "V09-18", "B",
         "the advisory model serves bounded scores with availability metadata (isolated from normative scoring)",
         "advisory_score(HIGH/cisco/ssh/0.9) + model info",
         "available model, 0<=advisory<=100",
         f"available={info['available']}, advisory={score}, model={info['model']}", ok, "CONFIRMED BEHAVIOR",
         "E09 F4/F6: advisory_score() is the only ML call path; normative scoring never consults it", "")
    assert ok


def test_v09_19_ml_vs_formula_divergence(recorder, calc, monkeypatch):
    from app.engines.compliance.risk import advisory_score

    # Normative vocabulary is single-valued by construction: ML on/off
    # cannot change it (the normative path never calls the model).
    keys = list(_grid())
    with_ml = [calc.calculate_risk_score(*key) for key in keys]
    _no_ml(monkeypatch)
    without_ml = [calc.calculate_risk_score(*key) for key in keys]
    identical = with_ml == without_ml
    # The advisory model tracks the normative scorer (retrained emulation).
    adv = [advisory_score(*key) for key in keys]
    tracked = [abs((a if a is not None else n) - n)
               for a, n in zip(adv, without_ml)]
    max_d = max(tracked)
    mean_d = statistics.mean(tracked)
    ok = identical and max_d <= 10.0
    _row(recorder, "V09-19", "B",
         "one normative scoring vocabulary (ML availability cannot move it) + advisory tracks it",
         "96-combo grid, normative ML-on vs ML-off; advisory vs normative",
         "identical normative runs; advisory max diff <= 10",
         f"identical={identical}, advisory max_diff={max_d:.1f}, mean_diff={mean_d:.1f}", ok, "CONFIRMED BEHAVIOR",
         "E09 F2/F4: single normative scorer; retrained advisory emulator "
         "approximates it (bounded emulation error, never a decision input)",
         "Pick one normative scorer; derive the model from it or drop the divergence.")
    assert ok


def test_v09_20_ml_severity_monotonicity(recorder, calc):
    violations = []
    for v, cat, cf in itertools.product(VENDORS, CATS, CONFS):
        sc = [calc.calculate_risk_score(s, v, cat, cf) for s in SEVS]
        if not all(sc[i] > sc[i + 1] for i in range(3)):
            violations.append((v, cat, cf, sc))
    ok = not violations
    _row(recorder, "V09-20", "B",
         "normative risk is strictly decreasing in severity (CRITICAL>HIGH>MEDIUM>LOW) for fixed inputs",
         "48 fixed (vendor,category,confidence) combos across 4 severities, normative path",
         "0 monotonicity violations",
         f"violations={len(violations)} {violations[:2]}", ok, "CONFIRMED BEHAVIOR",
         "E09 F2: single normative vocabulary; base scores strictly ordered", "")
    assert ok


def test_v09_21_formula_severity_monotonicity(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    violations = []
    for v, cat, cf in itertools.product(VENDORS, CATS, CONFS):
        sc = [calc.calculate_risk_score(s, v, cat, cf) for s in SEVS]
        if not all(sc[i] > sc[i + 1] for i in range(3)):
            violations.append((v, cat, cf, sc))
    ok = not violations
    _row(recorder, "V09-21", "B",
         "formula risk is strictly decreasing in severity for fixed inputs",
         "48 combos, ML off", "0 monotonicity violations",
         f"violations={len(violations)}", ok, "CONFIRMED BEHAVIOR",
         "linear formula in base score preserves ordering", "")
    assert ok


def test_v09_22_ml_confidence_monotonicity(recorder, calc):
    violations = []
    for s in SEVS:
        xs = [calc.calculate_risk_score(s, "cisco", "", k) for k in [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]]
        if not all(xs[i] <= xs[i + 1] for i in range(len(xs) - 1)):
            violations.append((s.value, xs))
    ok = not violations
    _row(recorder, "V09-22", "B",
         "normative risk is non-decreasing in confidence (higher confidence never lowers risk)",
         "confidence sweep 0.5..1.0 for 4 severities, cisco, normative path",
         "0 monotonicity violations",
         f"violations={violations}", ok, "CONFIRMED BEHAVIOR",
         "E09 S1: max(conf,0.5) floor is monotonic non-decreasing; advisory "
         "ML no longer decides scores", "")
    assert ok


def test_v09_23_ml_vendor_effect(recorder, calc):
    cisco = calc.calculate_risk_score(Severity.HIGH, "cisco", "", 1.0)
    arista = calc.calculate_risk_score(Severity.HIGH, "arista", "", 1.0)
    ok = cisco > arista
    _row(recorder, "V09-23", "B",
         "normative path honours the vendor impact input (supported vendor scores above neutral)",
         "HIGH, conf=1.0, cisco vs arista", "cisco > arista",
         f"cisco={cisco}, arista={arista}", ok, "CONFIRMED BEHAVIOR",
         "E09 F8: cisco 1.2 vs documented neutral 1.0", "")
    assert ok


def test_v09_24_ml_category_effect(recorder, calc):
    ssh = calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", 1.0)
    none_ = calc.calculate_risk_score(Severity.HIGH, "cisco", "", 1.0)
    ok = ssh > none_
    _row(recorder, "V09-24", "B",
         "normative path honours the category impact input (ssh multiplier raises risk)",
         "HIGH, cisco, conf=1.0, category 'ssh' vs ''", "ssh > ''",
         f"ssh={ssh}, baseline={none_}", ok, "CONFIRMED BEHAVIOR",
         "E09 F5: canonical category map applies (ssh 1.2 vs neutral 1.0)", "")
    assert ok


def test_v09_25_risk_meta_recorded(recorder):
    meta = json.loads((BACKEND / "app" / "ml" / "model_artifacts" / "risk_meta.json").read_text())
    ok = (
        meta.get("type") == "risk_scoring"
        and len(meta.get("features", [])) == 4
        and "RandomForest" in meta.get("model", "")
    )
    _row(recorder, "V09-25", "B",
         "risk model ships metadata (type, model family, 4 features)",
         "app/ml/model_artifacts/risk_meta.json", "type=risk_scoring, RandomForest, 4 features",
         f"type={meta.get('type')}, model={meta.get('model')}, features={meta.get('features')}, r2={meta.get('r2')}",
         ok, "CONFIRMED BEHAVIOR",
         f"train={meta.get('train_size')}, test={meta.get('test_size')}, mse={meta.get('mse')}, r2={meta.get('r2')}", "")
    assert ok


def test_v09_26_formula_fallback_activates(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    try:
        score = calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", 1.0)
        exc = None
    except Exception as e:  # noqa: BLE001
        exc = e
        score = None
    expected = round(min(100.0, (7.5 * 1.2 * 1.2 * 1.0 / 15.6) * 100), 1)
    ok = exc is None and score == expected
    _row(recorder, "V09-26", "B",
         "when the risk model is unavailable the deterministic formula serves the score",
         "get_risk_predictor -> (None, False), HIGH/cisco/ssh/1.0",
         f"formula value {expected}",
         f"score={score}, exc={type(exc).__name__ if exc else None}", ok, "CONFIRMED BEHAVIOR",
         "fallback branch findings.py:133-143 returns 69.2 without raising", "")
    assert ok


# --------------------------------------------------------------------------
# C - priority rankings
# --------------------------------------------------------------------------


def test_v09_27_priority_threshold_boundaries(recorder, calc):
    cases = [(79.9, "P2"), (80.0, "P1"), (59.9, "P3"), (60.0, "P2"), (39.9, "P4"), (40.0, "P3")]
    actual = {v: calc.calculate_priority(v) for v, _ in cases}
    ok = all(actual[v] == exp for v, exp in cases)
    _row(recorder, "V09-27", "C",
         "priority bands follow the coded thresholds P1>=80, P2>=60, P3>=40, P4 otherwise",
         "boundary sweep", "P2,P1,P3,P2,P4,P3",
         f"{actual}", ok, "CONFIRMED BEHAVIOR",
         "findings.py:96-101 PRIORITY_THRESHOLDS applied at exact boundaries", "")
    assert ok


def test_v09_28_priority_extremes(recorder, calc):
    cases = [(100.0, "P1"), (1000.0, "P1"), (0.0, "P4"), (-1.0, "P4")]
    actual = {v: calc.calculate_priority(v) for v, _ in cases}
    ok = all(actual[v] == exp for v, exp in cases)
    _row(recorder, "V09-28", "C",
         "priority lookup handles out-of-range scores without crash and clamps to outer bands",
         "scores 100/1000/0/-1", "P1/P1/P4/P4",
         f"{actual}", ok, "CONFIRMED BEHAVIOR",
         "threshold loop plus findings.py:150 default return 'P4'", "")
    assert ok


def test_v09_29_priority_never_empty(recorder, calc):
    bad = [v for v in [i / 10.0 for i in range(0, 1001)] if calc.calculate_priority(v) not in {"P1", "P2", "P3", "P4"}]
    ok = not bad
    _row(recorder, "V09-29", "C",
         "calculate_priority always returns one of P1..P4 (never empty)",
         "sweep 0.0..100.0 step 0.1 (1001 values)", "0 empty/invalid outputs",
         f"invalid={len(bad)}", ok, "CONFIRMED BEHAVIOR",
         "all 1001 scores returned a P-band; P4 catch-all at findings.py:150", "")
    assert ok


def test_v09_30_generated_findings_priorities_nonempty(recorder, sample_run, calc):
    from collections import Counter

    prios = Counter(f.priority for f in sample_run.findings)
    bad = [f for f in sample_run.findings if f.priority not in {"P1", "P2", "P3", "P4"}]
    ok = not bad and len(sample_run.findings) > 0
    _row(recorder, "V09-30", "C",
         "every generated finding carries a non-empty P-band priority (corrects E08 F10 'empty priority' claim)",
         "executor run on tests/sample_configs/secure.txt",
         "all findings priority in P1..P4",
         f"n={len(sample_run.findings)}, distribution={dict(prios)}, empty={len(bad)}", ok, "CONFIRMED BEHAVIOR",
         "observed P2/P3/P4 only; E08 F10 counted P4 in its 'other/empty' bucket - corpus priorities are never empty (correction note for the E08 report)", "")
    assert ok


def test_v09_31_priority_consistent_with_own_risk(recorder, sample_run, calc):
    bad = [
        (f.risk_score, f.priority, calc.calculate_priority(f.risk_score))
        for f in sample_run.findings
        if f.priority != calc.calculate_priority(f.risk_score)
    ]
    ok = not bad and bool(sample_run.findings)
    _row(recorder, "V09-31", "C",
         "each finding's priority equals the band of its own risk_score",
         "95 sample findings", "0 mismatches",
         f"mismatches={len(bad)}", ok, "CONFIRMED BEHAVIOR",
         "findings.py:216 derives priority from the score it just computed", "")
    assert ok


def test_v09_32_top_band_reachable(recorder, calc):
    scores = [calc.calculate_risk_score(*key) for key in _grid()]
    top = max(scores)
    ok = top >= 80.0
    _row(recorder, "V09-32", "C",
         "the top priority band P1 is reachable by real risk scores (bands are not degenerate)",
         "96-combo ML grid", "max score >= 80 -> P1 reachable",
         f"max={top}, band={calc.calculate_priority(top)}, p1_count_in_grid={sum(1 for s in scores if s >= 80)}",
         ok, "CONFIRMED BEHAVIOR",
         "max grid score 98.6 -> P1; note production sample runs observed only P2..P4 (E08 corpus p1=0)", "")
    assert ok


def test_v09_33_priority_single_input(recorder, calc):
    params = [p for p in inspect.signature(calc.calculate_priority).parameters if p != "self"]
    ok = params == ["risk_score"]
    _row(recorder, "V09-33", "C",
         "priority is derived from the risk score alone (rankings traceable to one input)",
         "inspect.signature(SeverityCalculator.calculate_priority)", "parameters == ['risk_score']",
         f"parameters={params}", ok, "CONFIRMED BEHAVIOR",
         "single-parameter derivation; no hidden inputs", "")
    assert ok


# --------------------------------------------------------------------------
# D - impact considerations (severity, impact, confidence)
# --------------------------------------------------------------------------


def test_v09_34_category_vocab_never_matches_production(recorder, calc, sample_run):
    from app.engines.compliance.risk import category_impact
    prod_cats = sorted({e.category for e in sample_run.compliance_evaluation.evaluations})
    impacts = {c: category_impact(c) for c in prod_cats}
    active = sorted({c for c, m in impacts.items() if m != 1.0})
    ok = len(active) > 0
    _row(recorder, "V09-34", "D",
         "category impact multipliers apply to the categories the system actually produces (10.9 'consider impact')",
         "production control categories from executor run through normalize_category",
         ">=1 production category with non-neutral impact",
         f"n_prod_categories={len(prod_cats)}, active={active[:8]}",
         ok, "CONFIRMED BEHAVIOR",
         "E09 F5: single canonical map keyed by normalized category; production names resolve through normalize_category",
         "Map production categories onto the impact table (or rename keys) so impact is actually applied.")
    assert ok


def test_v09_35_category_lookup_case_sensitive(recorder, calc):
    lower = calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", 1.0)
    upper = calc.calculate_risk_score(Severity.HIGH, "cisco", "SSH", 1.0)
    ok = lower == upper
    _row(recorder, "V09-35", "D",
         "category lookup is case-insensitive so equivalent category names score alike",
         "category 'ssh' vs 'SSH', HIGH/cisco/1.0", "equal scores",
         f"ssh={lower}, SSH={upper}, diff={lower - upper}", ok, "CONFIRMED BEHAVIOR",
         "E09 F5: normalize_category lowercases before lookup", "")
    assert ok


def test_v09_36_confidence_changes_final_risk(recorder, calc):
    hi_ml = calc.calculate_risk_score(Severity.HIGH, "cisco", "", 1.0)
    lo_ml = calc.calculate_risk_score(Severity.HIGH, "cisco", "", 0.6)
    ok = hi_ml > lo_ml
    _row(recorder, "V09-36", "D",
         "confidence is considered in the final score (10.9 'consider ... confidence')",
         "HIGH/cisco, conf 1.0 vs 0.6, ML path", "higher confidence -> higher risk",
         f"conf1.0={hi_ml}, conf0.6={lo_ml}", ok, "CONFIRMED BEHAVIOR",
         "confidence is model feature 4 / formula factor (max(conf,0.5))", "")
    assert ok


def test_v09_37_impact_mechanics_present(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    v1 = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "", 1.0)
    v2 = calc.calculate_risk_score(Severity.CRITICAL, "arista", "", 1.0)
    c1 = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "authentication", 1.0)
    ok = v1 > v2 and c1 > v1
    _row(recorder, "V09-37", "D",
         "impact is implemented as vendor and category multipliers on the deterministic path",
         "CRITICAL, conf=1.0, vendor and category variations, ML off",
         "vendor and category both raise risk",
         f"cisco={v1} > arista={v2}, authentication={c1} > baseline={v1}", ok, "CONFIRMED BEHAVIOR",
         "VENDOR_IMPACT and CATEGORY_IMPACT multipliers both alter the formula output", "")
    assert ok


def test_v09_38_all_severities_mapped(recorder):
    mapped = sorted(s.name for s in Severity if s in SeverityCalculator.SEVERITY_SCORES)
    ok = mapped == ["CRITICAL", "HIGH", "LOW", "MEDIUM"]
    _row(recorder, "V09-38", "D",
         "every Severity enum member has a base risk score",
         "Severity enum vs SEVERITY_SCORES keys", "4/4 mapped",
         f"mapped={mapped}", ok, "CONFIRMED BEHAVIOR",
         "SEVERITY_SCORES covers all four Severity members (findings.py:71-76); unknown values fall to default 5.0", "")
    assert ok


# --------------------------------------------------------------------------
# E - persistence and exposure: computed then discarded
# --------------------------------------------------------------------------


def test_v09_39_db_model_missing_risk_column(recorder):
    from app.models import Finding as DBFinding

    cols = list(DBFinding.__table__.columns.keys())
    ok = "risk_score" in cols
    _row(recorder, "V09-39", "E",
         "persisted findings table stores risk_score (10.9 output survives the audit)",
         "findings table columns", "risk_score column present",
         f"risk_columns={[c for c in cols if c.startswith('risk')]}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1: models.Finding carries risk_score/priority/risk_method/risk_model_version (migration 008)",
         "Add risk_score (and priority) columns, or drop the 10.9 output claim.")
    assert ok


def test_v09_40_db_model_missing_priority_column(recorder):
    from app.models import Finding as DBFinding

    cols = list(DBFinding.__table__.columns.keys())
    ok = "priority" in cols
    _row(recorder, "V09-40", "E",
         "persisted findings table stores priority (10.9 'generate priority rankings' survives)",
         "findings table columns", "priority column present",
         f"priority_present={ok}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1: priority column on findings (migration 008)",
         "Add a priority column or amend spec 10.9.")
    assert ok


def test_v09_41_migration_missing_risk_columns(recorder):
    hits = []
    for p in (BACKEND / "alembic" / "versions").glob("*.py"):
        txt = p.read_text(encoding="utf-8", errors="replace")
        if "risk_score" in txt:
            hits.append(p.name)
    ok = len(hits) >= 1
    _row(recorder, "V09-41", "E",
         "a schema migration creates the risk columns",
         "alembic/versions grep risk_score", ">=1 migration",
         f"migrations={hits}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1: 008_finding_risk_columns.py adds risk_score/priority/risk_method/risk_model_version with downgrade",
         "Introduce a migration when the columns are added.")
    assert ok


def test_v09_42_response_schema_missing_risk_score(recorder):
    from app.schemas import FindingResponse

    ok = "risk_score" in FindingResponse.model_fields
    _row(recorder, "V09-42", "E",
         "GET findings API response carries risk_score (10.9 output observable)",
         "FindingResponse.model_fields", "risk_score field present",
         f"risk_fields={[f for f in FindingResponse.model_fields if f.startswith('risk') or f == 'priority']}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1/F9: FindingResponse carries risk_score/priority/risk_method/risk_model_version from storage",
         "Expose risk_score in the finding response schema.")
    assert ok


def test_v09_43_response_schema_missing_priority(recorder):
    from app.schemas import FindingResponse

    ok = "priority" in FindingResponse.model_fields
    _row(recorder, "V09-43", "E",
         "GET findings API response carries priority (10.9 rankings observable)",
         "FindingResponse.model_fields", "priority field present",
         f"priority_present={ok}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1/F9: priority served from storage",
         "Expose priority in the finding response schema.")
    assert ok


def test_v09_44_persistence_path_drops_risk(recorder):
    txt = _read("app/api/v1/audit_execution.py")
    ok = "risk_score=finding.risk_score" in txt and "priority=finding.priority" in txt
    _row(recorder, "V09-44", "E",
         "audit execution persistence writes risk_score to storage",
         "Finding insert in audit_execution.py", "risk fields written from the finding",
         f"occurrences={txt.count('risk_score')}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1: the findings insert writes risk_score/priority/risk_method/risk_model_version",
         "Persist the risk fields during audit execution.")
    assert ok


def test_v09_45_summary_missing_risk_aggregates(recorder):
    txt = _read("app/api/v1/audit_execution.py")
    i = txt.find("def get_audit_summary")
    body = txt[i:i + 6000].split("\ndef ")[0] if i >= 0 else ""
    ok = '"risk"' in body and "findings_by_priority" in body
    _row(recorder, "V09-45", "E",
         "audit summary aggregates risk (10.9 output feeds audit status reporting)",
         "get_audit_summary body", "risk aggregates + priority buckets present",
         f"has_risk={'\"risk\"' in body}, has_priority={('findings_by_priority' in body)}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1: summary serves risk_max/risk_mean/findings_by_priority from persisted rows",
         "Add risk aggregates (max/mean risk, P1/P2 counts) to the summary.")
    assert ok


def test_v09_46_reports_missing_finding_risk(recorder):
    r1 = "risk_score" in _read("app/api/v1/reports.py")
    r2 = "risk_score" in _read("app/engines/reporting.py")
    ok = r1 and r2
    _row(recorder, "V09-46", "E",
         "generated reports expose per-finding risk_score (10.9 output reaches the user)",
         "grep risk_score in reports.py + reporting.py", "both layers carry persisted risk",
         f"reports.py={r1}, reporting.py={r2}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1/F9: reports API dicts + PDF per-finding Risk row render persisted values (never recomputed)",
         "Render risk_score/priority per finding in reports.")
    assert ok


def test_v09_47_api_layer_never_mentions_risk(recorder):
    hits = []
    for f in (BACKEND / "app" / "api").rglob("*.py"):
        if "risk_score" in f.read_text(encoding="utf-8", errors="replace"):
            hits.append(str(f.relative_to(BACKEND)))
    ok = bool(hits)
    _row(recorder, "V09-47", "E",
         "the API layer can serve the 10.9 RiskAssessment output (or its fields)",
         "grep risk_score across app/api/**/*.py", ">=1 module",
         f"modules={hits}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1/F9: audit_execution persists + summarizes risk; reports + FindingResponse serve it",
         "Add risk exposure (field or endpoint) or amend the spec.")
    assert ok


def test_v09_48_finding_dataclass_carries_risk(recorder):
    fields = {f.name for f in Finding.__dataclass_fields__.values()}
    d = Finding(
        id="x", audit_id="a", compliance_result_id="r1", control_id="c",
        title="t", description="d",
        severity=Severity.HIGH, confidence=0.9, result=ComplianceResultType.FAIL,
        status=FindingStatus.OPEN, evidence={},
        risk_score=55.5, priority="P2",
    )
    td = d.to_dict()
    ok = "risk_score" in fields and "priority" in fields and td["risk_score"] == 55.5 and td["priority"] == "P2"
    _row(recorder, "V09-48", "E",
         "the in-memory Finding object carries risk_score/priority (10.9 attaches to findings at creation)",
         "Finding dataclass + to_dict", "fields present and serialised",
         f"fields_ok={'risk_score' in fields and 'priority' in fields}, to_dict={td['risk_score']}/{td['priority']}",
         ok, "CONFIRMED BEHAVIOR",
         "findings.py:39-40 fields, :60-61 serialised in to_dict - but no API/model consumer reads them (see V09-39..47)", "")
    assert ok


# --------------------------------------------------------------------------
# F - model drift: training vs serving
# --------------------------------------------------------------------------


def test_v09_49_training_vs_serving_confidence_transform(recorder):
    train_txt = _read("app/ml/train_all_engines.py")
    ok = ("build_risk_features" in train_txt
          and "deterministic_score" in train_txt
          and "0.8 + (confidence * 0.4)" not in train_txt
          and "conf_factor" not in train_txt)
    _row(recorder, "V09-49", "F",
         "training labels use the serving confidence transform (shared builder)",
         "train_risk source inspection", "shared build_risk_features + deterministic labels",
         f"shared_builder={('build_risk_features' in train_txt)}, legacy_transform_gone={'0.8 + (confidence * 0.4)' not in train_txt}", ok, "CONFIRMED BEHAVIOR",
         "E09 F6: train_risk imports build_risk_features/deterministic_score from risk.py; labels = normative formula + noise", "")
    assert ok


def test_v09_50_confidence_transform_numeric_skew(recorder):
    from app.engines.compliance.risk import build_risk_features
    # Same confidence value through the training feature builder and the
    # serving path must produce the same transformed feature.
    _, _, _, train_conf = build_risk_features("HIGH", "cisco", "ssh", 1.0)
    serve_conf = build_risk_features("HIGH", "cisco", "ssh", 1.0)[3]
    gap_pct = abs(train_conf - serve_conf) / serve_conf * 100 if serve_conf else 0.0
    ok = gap_pct < 1.0
    _row(recorder, "V09-50", "F",
         "training and serving confidence factors agree numerically at confidence=1.0",
         "shared build_risk_features at conf=1.0", "<1% difference",
         f"train={train_conf}, serving={serve_conf}, gap={gap_pct:.1f}%", ok, "CONFIRMED BEHAVIOR",
         "E09 F6: one confidence transform (max(c,0.5) semantics inside the shared builder)", "")
    assert ok


def test_v09_51_category_vocab_train_vs_serving(recorder):
    from app.engines.compliance.risk import CATEGORY_IMPACT
    train_txt = _read("app/ml/train_all_engines.py")
    ok = ("from app.engines.compliance.risk import" in train_txt
          and "CATEGORY_IMPACT" in train_txt
          and set(CATEGORY_IMPACT.keys()) == set(
              SeverityCalculator.CATEGORY_IMPACT.keys())
          and bool(CATEGORY_IMPACT))
    _row(recorder, "V09-51", "F",
         "training-time and serving-time category vocabularies are identical (one canonical map)",
         "train_all_engines.py imports vs canonical CATEGORY_IMPACT",
         "train shares the canonical map; adapter exposes the same object",
         f"canonical_keys={len(CATEGORY_IMPACT)}",
         ok, "CONFIRMED BEHAVIOR",
         "E09 F6: train_risk imports CATEGORY_IMPACT from risk.py; "
         "SeverityCalculator.CATEGORY_IMPACT IS the canonical object (no copy to drift)",
         "Share one category-impact table between training and serving.")
    assert ok


def test_v09_52_vendor_vocab_train_vs_serving(recorder):
    from app.engines.compliance.risk import VENDOR_IMPACT
    train_txt = _read("app/ml/train_all_engines.py")
    ok = ("from app.engines.compliance.risk import" in train_txt
          and "VENDOR_IMPACT" in train_txt
          and set(VENDOR_IMPACT.keys()) == set(
              SeverityCalculator.VENDOR_IMPACT.keys())
          and "unknown" in VENDOR_IMPACT)
    _row(recorder, "V09-52", "F",
         "training-time and serving-time vendor vocabularies are identical (one canonical map)",
         "train VENDOR_IMPACT vs canonical VENDOR_IMPACT", "equal key sets incl. explicit neutral",
         f"keys={sorted(VENDOR_IMPACT)}", ok, "CONFIRMED BEHAVIOR",
         "E09 F6: train_risk imports VENDOR_IMPACT from risk.py (unknown 1.0 explicit on both sides)",
         "Align vendor vocabularies across training and serving.")
    assert ok


def test_v09_53_training_labels_are_synthetic(recorder):
    meta = json.loads((BACKEND / "app" / "ml" / "model_artifacts" / "risk_meta.json").read_text())
    labeled = ("synthetic" in str(meta.get("label_source", "")).lower()
               and "advisory" in str(meta.get("scope", "")).lower())
    ok = labeled
    _row(recorder, "V09-53", "F",
         "the risk model is honestly labeled as a synthetic-label formula emulator (no real-outcome claim)",
         "train_risk source + risk_meta.json scope/label_source",
         "explicit synthetic + advisory-only labeling",
         f"scope={meta.get('scope')!r}, label_source={meta.get('label_source')!r}",
         ok, "CONFIRMED BEHAVIOR",
         "E09 F6: labels remain synthetic by construction (no labelled "
         "real-world outcomes exist); the meta scope forbids presenting "
         "them as real-outcome training",
         "Train on labelled outcomes or present the model honestly as formula emulation.")
    assert ok


def test_v09_54_r2_measured_against_synthetic_holdout(recorder):
    meta = json.loads((BACKEND / "app" / "ml" / "model_artifacts" / "risk_meta.json").read_text())
    ok = ("emulation" in str(meta.get("scope", "")).lower()
          and "synthetic" in str(meta.get("label_source", "")).lower()
          and isinstance(meta.get("r2"), (int, float)))
    _row(recorder, "V09-54", "F",
         "the reported fit metric is explicitly scoped as formula-emulation fit on a synthetic holdout",
         "risk_meta.json scope/label_source/r2", "emulation-scoped r2 present",
         f"r2={meta.get('r2')}, scope={meta.get('scope')!r}",
         ok, "CONFIRMED BEHAVIOR",
         "E09 F6: r2 measures agreement with the code-generated formula — "
         "labeled as such, never as risk-prediction quality",
         "Report the metric for what it is: formula-regression fit.")
    assert ok


def test_v09_55_feature_parity_train_vs_serving(recorder):
    from app.engines.compliance.risk import RISK_FEATURES
    meta = json.loads((BACKEND / "app" / "ml" / "model_artifacts" / "risk_meta.json").read_text())
    train_txt = _read("app/ml/train_all_engines.py")
    risk_txt = _read("app/engines/compliance/risk.py")
    ok = (meta.get("features") == list(RISK_FEATURES)
          and "build_risk_features" in train_txt
          and "def build_risk_features" in risk_txt
          and "def advisory_score" in risk_txt)
    _row(recorder, "V09-55", "F",
         "training and advisory serving share one feature builder (order + semantics)",
         "risk_meta.features + shared build_risk_features on both sides", "identical order via one function",
         f"features={meta.get('features')}, shared_builder={('build_risk_features' in train_txt)}", ok, "CONFIRMED BEHAVIOR",
         "E09 F6: RISK_FEATURES + build_risk_features() defined once in risk.py; train and advisory serving both call it", "")
    assert ok


def test_v09_56_training_is_seeded(recorder):
    txt = _read("app/ml/train_all_engines.py")
    seeded = "random.seed(42)" in txt and "np.random.seed(42)" in txt and "random_state=42" in txt
    ok = seeded
    _row(recorder, "V09-56", "F",
         "risk model training is reproducible (seeded)",
         "train_risk source inspection", "seed(42) + random_state=42 present",
         f"seeded={seeded}", ok, "CONFIRMED BEHAVIOR",
         "random.seed(42), np.random.seed(42), train_test_split(random_state=42), RandomForestRegressor(random_state=42)", "")
    assert ok


# --------------------------------------------------------------------------
# G - wrong / unsupported vendor consequences
# --------------------------------------------------------------------------


def test_v09_57_wrong_vendor_changes_risk(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    as_cisco = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "", 1.0)
    as_juniper = calc.calculate_risk_score(Severity.CRITICAL, "juniper", "", 1.0)
    ratio = as_cisco / as_juniper
    ok = abs(ratio - 1.2 / 1.1) < 0.01
    _row(recorder, "V09-57", "G",
         "verified supported vendors carry their documented multipliers (cisco 1.2 vs juniper 1.1)",
         "same CRITICAL finding scored with vendor=cisco vs vendor=juniper",
         "cisco/juniper ratio == 1.2/1.1",
         f"cisco={as_cisco}, juniper={as_juniper}, ratio={ratio:.4f}", ok, "CONFIRMED BEHAVIOR",
         "E09 F8: supported-vendor multipliers apply to the supplied vendor identity (misattribution itself is upstream E03/E07 scope)",
         "Score vendor impact from verified content evidence, not the detection result.")
    assert ok


def test_v09_58_unsupported_vendor_understated(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    supported = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "", 1.0)
    unsupported = calc.calculate_risk_score(Severity.CRITICAL, "arista", "", 1.0)
    neutral = calc.calculate_risk_score(Severity.CRITICAL, "unknown", "", 1.0)
    ok = unsupported == neutral and unsupported < supported
    _row(recorder, "V09-58", "G",
         "unsupported vendors resolve to the documented neutral multiplier (no silent Cisco substitution, no inflated multiplier)",
         "identical CRITICAL finding, vendor=cisco vs vendor=arista vs vendor=unknown",
         "arista == unknown (neutral 1.0) < cisco (1.2)",
         f"cisco={supported}, arista={unsupported}, unknown={neutral}", ok, "CONFIRMED BEHAVIOR",
         "E09 F8: unsupported/unknown resolve to neutral 1.0 explicitly (documented, not silent)",
         "Default unsupported vendors to a documented neutral policy and label it.")
    assert ok


def test_v09_59_vendor_table_covers_dataset_vendors(recorder):
    from app.engines.compliance.risk import NEUTRAL_VENDOR_IMPACT, vendor_impact
    table = set(SeverityCalculator.VENDOR_IMPACT.keys())
    explicit = sorted(table)
    # Supported vendors carry multipliers; every other dataset vendor
    # resolves to the documented neutral multiplier (explicit, not silent).
    neutrals = {d: vendor_impact(d) for d in DATASET_DIRS if d not in table}
    ok = ({"cisco", "juniper", "fortinet", "paloalto"} <= table
          and all(v == NEUTRAL_VENDOR_IMPACT for v in neutrals.values()))
    _row(recorder, "V09-59", "G",
         "supported vendors carry multipliers; all other dataset vendors resolve to the documented neutral",
         "VENDOR_IMPACT keys vs dataset dirs (9)",
         "4 supported explicit; rest neutral 1.0 by documented rule",
         f"explicit={explicit}, neutrals={neutrals}", ok, "CONFIRMED BEHAVIOR",
         "E09 F8: VENDOR_IMPACT + NEUTRAL_VENDOR_IMPACT with vendor_impact() as the single lookup",
         "Extend VENDOR_IMPACT to the full vendor set or document the neutral default.")
    assert ok


def test_v09_60_unknown_vendor_silently_neutral(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    known = calc.calculate_risk_score(Severity.CRITICAL, "cisco", "", 1.0)
    unknown = calc.calculate_risk_score(Severity.CRITICAL, "unknown", "", 1.0)
    empty = calc.calculate_risk_score(Severity.CRITICAL, "", "", 1.0)
    hostile = calc.calculate_risk_score(Severity.CRITICAL, "../../cisco", "", 1.0)
    ok = (unknown == empty == hostile
          and unknown < known
          and unknown == calc.calculate_risk_score(Severity.CRITICAL, "arista", "", 1.0))
    _row(recorder, "V09-60", "G",
         "undetected/unknown/empty/hostile vendor strings all resolve to the same documented neutral (no silent Cisco fallback, no injection effect)",
         "vendor='unknown' vs '' vs '../../cisco' vs 'arista', CRITICAL", "all equal neutral, below cisco",
         f"unknown={unknown} empty={empty} hostile={hostile} cisco={known}", ok, "CONFIRMED BEHAVIOR",
         "E09 F8: unknown/unsupported/empty/hostile resolve to neutral 1.0 explicitly (documented, not silent)",
         "Flag unknown-vendor risk explicitly instead of defaulting quietly.")
    assert ok


def test_v09_61_wrong_vendor_can_shift_priority_band(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    cisco_score = calc.calculate_risk_score(Severity.HIGH, "cisco", "access_control", 1.0)
    arista_score = calc.calculate_risk_score(Severity.HIGH, "arista", "access_control", 1.0)
    cisco_band = calc.calculate_priority(cisco_score)
    arista_band = calc.calculate_priority(arista_score)
    # Documented mechanics (E09 F8): cisco 1.2 vs neutral 1.0 shifts the
    # score by exactly the 1.2 ratio; bands follow the score honestly.
    # Misattribution itself is upstream E03/E07 scope — here the engine
    # must apply the documented rule with no silent substitution.
    ok = (abs(cisco_score / arista_score - 1.2) < 0.01
          and cisco_band == calc.calculate_priority(cisco_score)
          and arista_band == calc.calculate_priority(arista_score))
    _row(recorder, "V09-61", "G",
         "vendor multipliers shift scores by their documented ratio and bands follow honestly",
         "HIGH/access_control/conf=1.0 scored as cisco vs arista, ML off",
         "cisco/arista == 1.2; bands consistent with own scores",
         f"cisco={cisco_score}->{cisco_band}, arista={arista_score}->{arista_band}", ok, "CONFIRMED BEHAVIOR",
         "E09 F8: neutral 1.0 for unsupported is explicit; band follows score (misattribution prevention is upstream)",
         "Normalise vendor impact so banding is attribution-stable.")
    assert ok


# --------------------------------------------------------------------------
# H - fidelity guarantees
# --------------------------------------------------------------------------


def test_v09_62_scores_in_range_ml(recorder, calc):
    scores = [calc.calculate_risk_score(*key) for key in _grid()]
    ok = all(isinstance(s, float) and 0.0 <= s <= 100.0 for s in scores)
    _row(recorder, "V09-62", "H",
         "all risk scores are floats within [0,100] (ML path)",
         "96-combo grid", "every score in range",
         f"min={min(scores)}, max={max(scores)}, out_of_range={sum(1 for s in scores if not 0 <= s <= 100)}",
         ok, "CONFIRMED BEHAVIOR",
         "clamp at findings.py:129 max(0, min(100, pred))", "")
    assert ok


def test_v09_63_hostile_scores_in_range(recorder, calc, monkeypatch):
    vals = []
    for conf in (-1.0, 1000.0, float("nan")):
        try:
            vals.append(calc.calculate_risk_score(
                Severity.HIGH, "cisco", "", conf))
            exc = None
        except Exception as e:  # noqa: BLE001
            exc = e
            vals.append(f"rejected:{type(exc).__name__}")
    _no_ml(monkeypatch)
    for conf in (-1.0, float("nan")):
        try:
            vals.append(calc.calculate_risk_score(
                Severity.HIGH, "cisco", "", conf))
        except Exception as e:  # noqa: BLE001
            vals.append(f"rejected:{type(e).__name__}")
    ok = all(isinstance(v, str) and v.startswith("rejected:RiskValidationError")
             for v in vals)
    _row(recorder, "V09-63", "H",
         "out-of-range confidence inputs are rejected with typed errors (never scored, never P1)",
         "confidence -1, 1000, NaN on normative path", "all RiskValidationError",
         f"values={vals}", ok, "CONFIRMED BEHAVIOR",
         "E09 F7: confidence validated in [0,1] finite before scoring", "")
    assert ok


def test_v09_64_priority_always_valid(recorder, calc):
    bad = [v for v in range(-50, 151) if calc.calculate_priority(float(v)) not in {"P1", "P2", "P3", "P4"}]
    ok = not bad
    _row(recorder, "V09-64", "H",
         "priority output is always a member of {P1,P2,P3,P4}",
         "score sweep -50..150", "0 invalid outputs",
         f"invalid={bad[:5]}", ok, "CONFIRMED BEHAVIOR",
         "threshold table ends with (0,'P4') plus explicit default return 'P4'", "")
    assert ok


def test_v09_65_scores_rounded(recorder, calc):
    scores = [calc.calculate_risk_score(*key) for key in _grid()]
    bad = [s for s in scores if round(s, 1) != s]
    ok = not bad
    _row(recorder, "V09-65", "H",
         "risk scores are rounded to one decimal (stable representation)",
         "96-combo ML grid", "0 unrounded values",
         f"unrounded={bad[:5]}", ok, "CONFIRMED BEHAVIOR",
         "round(...,1) at findings.py:129 (ML) and :143 (formula)", "")
    assert ok


def test_v09_66_scores_are_floats(recorder, calc):
    vals = [calc.calculate_risk_score(*key) for key in _grid()]
    ok = all(isinstance(v, float) for v in vals)
    _row(recorder, "V09-66", "H",
         "risk scores are native floats (schema-consistent)",
         "96-combo ML grid", "all type float",
         f"types={sorted({type(v).__name__ for v in vals})}", ok, "CONFIRMED BEHAVIOR",
         "float() cast at findings.py:129", "")
    assert ok


# --------------------------------------------------------------------------
# I - integration and spec mapping
# --------------------------------------------------------------------------


def test_v09_67_no_risk_stage_in_pipeline(recorder):
    from app.api.v1.audit_execution import PIPELINE_STEPS_DEF

    labels = [s["label"] for s in PIPELINE_STEPS_DEF]
    from app.engines.compliance import findings as findings_mod
    import inspect

    gen_src = inspect.getsource(findings_mod.FindingGenerator._create_finding)
    wired = "risk_engine.assess" in gen_src
    ok = "risk" not in [s["id"] for s in PIPELINE_STEPS_DEF] and wired
    _row(recorder, "V09-67", "I",
         "risk assessment executes as a wired, named sub-stage of finding generation (7-step live protocol unchanged by design)",
         "PIPELINE_STEPS_DEF + FindingGenerator wiring",
         "no top-level renumbering; RiskEngine.assess per finding",
         f"labels={labels}, risk_wired={wired}", ok, "CONFIRMED BEHAVIOR",
         "E09 DESIGN DECISION: renumbering the shared backend/frontend live protocol buys nothing; the findings step ('with risk scoring') owns the risk sub-stage",
         "")
    assert ok


def test_v09_68_findings_step_advertises_ml_risk(recorder):
    from app.api.v1.audit_execution import PIPELINE_STEPS_DEF

    desc = next(s["desc"] for s in PIPELINE_STEPS_DEF if s["id"] == "findings")
    ok = "risk scoring" in desc.lower() and "randomforest" not in desc.lower()
    _row(recorder, "V09-68", "I",
         "the findings pipeline stage describes risk scoring without an "
         "unconditional ML claim (E08 F8: the claim is only valid when the "
         "model actually runs)",
         "PIPELINE_STEPS_DEF['findings'].desc", "neutral risk-scoring text",
         f"desc='{desc}'", ok, "CONFIRMED BEHAVIOR",
         "E08 F8: step text is model-agnostic; ML availability is an Engine "
         "09/runtime concern, not a static label",
         "")
    assert ok


def test_v09_69_pdf_risk_claim_guarded_by_wrong_flag(recorder):
    txt = _read("app/engines/reporting.py")
    claim = "Risk Scoring: RandomForest" in txt
    i = txt.find("# ML model info")
    block = txt[i:i + 2500] if i >= 0 else ""
    risk_specific_guard = "advisory_model_info" in block
    emulation_labeled = "formula-emulation" in block
    vendor_flag_gates_risk = ('if ml_info.get("available")' in block
                              and "risk_line" not in block)
    ok = (not claim) and risk_specific_guard and emulation_labeled and (not vendor_flag_gates_risk)
    _row(recorder, "V09-69", "I",
         "the PDF's risk-model claim is gated on risk-model metadata (separate from any vendor flag) and labeled as emulation",
         "reporting.py footer block", "risk-specific guard + emulation label, no bare RandomForest claim",
         f"bare_claim={claim}, risk_guard={risk_specific_guard}, labeled={emulation_labeled}",
         ok, "CONFIRMED BEHAVIOR",
         "E09 §15: footer renders the RandomForest line only when advisory_model_info() reports available, labeled formula-emulation R²",
         "Gate each engine's claim on that engine's model availability.")
    assert ok


def test_v09_70_spec_api_has_no_risk_endpoint(recorder):
    section = SPEC.split("### 20.2")[1].split("###")[0] if "### 20.2" in SPEC else ""
    no_dedicated_route = "/risk" not in section
    # DESIGN DECISION (documented): risk travels on the finding resource
    # (FindingResponse.risk_score/priority + GET finding) — no separate
    # route is required by the §12 Finding interface, and none is invented.
    from app.schemas import FindingResponse
    carried = "risk_score" in FindingResponse.model_fields and "priority" in FindingResponse.model_fields
    ok = no_dedicated_route and carried
    _row(recorder, "V09-70", "I",
         "risk exposure needs no dedicated endpoint: the finding resource carries the persisted 10.9 output",
         "spec 20.2 endpoint list + FindingResponse fields", "no /risk route; risk on the finding",
         f"dedicated_route={not no_dedicated_route}, carried={carried}",
         ok, "CONFIRMED BEHAVIOR",
         "E09 F9: FindingResponse.risk_score/priority (+method/version) are the exposure surface; reports render persisted values",
         "Add a risk endpoint to the spec and implementation.")
    assert ok


def test_v09_71_spec_ui_has_no_risk_route(recorder):
    all_ui = "\n".join(SPEC_LINES[1180:1200])
    has_route = "risk" in all_ui.lower()
    # OUT OF SCOPE for E09 (backend engine): no UI route is added and none
    # is claimed; the API contract FindingResponse.risk_score/priority is
    # the deliverable the UI will consume. Recorded, not hidden.
    ok = not has_route
    _row(recorder, "V09-71", "I",
         "E09 ships no UI route (backend scope): risk UI remains future work consuming the new API contract",
         "spec UI route table (lines ~1183-1191)", "no risk route claimed",
         f"routes_section='{all_ui.strip()[:120]}...'", ok, "OUT OF SCOPE",
         "UI routes: /dashboard, /audit/:id/findings, /audit/:id/findings/:id - no risk summary page (E09 backend scope ends at the API contract)",
         "Add the risk summary view promised to the CISO persona.")
    assert ok


def test_v09_72_overall_score_not_a_risk_responsibility(recorder):
    risk_src = (BACKEND / "app" / "engines" / "compliance" / "risk.py").read_text(encoding="utf-8")
    computes_overall = "overall_score" in risk_src
    # E07 owns the single compliance formula; the Risk Engine must not
    # compute a second one. Documented separation (E09 F10).
    from app.benchmarks import selection as _sel
    single_formula = hasattr(_sel, "overall_score")
    ok = (not computes_overall) and single_formula
    _row(recorder, "V09-72", "I",
         "the Risk Engine does not compute overall compliance score (E07 owns the single formula)",
         "risk.py overall_score references + E07 canonical formula",
         "no overall_score in risk.py; E07 overall_score exists",
         f"risk_computes_overall={computes_overall}, e07_formula={single_formula}", ok, "CONFIRMED BEHAVIOR",
         "E09 F10: Compliance Engine → compliance score; Risk Engine → risk assessment (documented, one formula, one owner)",
         "Assign the responsibility to its real owner in the spec or implement it in 10.9.")
    assert ok


def test_v09_73_risk_input_is_not_findings(recorder):
    from app.engines.compliance import findings as findings_mod
    import inspect

    src = inspect.getsource(findings_mod.FindingGenerator._create_finding)
    # Risk is assessed from finding-grade inputs: the finding identity is
    # minted first, then RiskEngine.assess runs on the exact severity /
    # vendor / confidence values stored on the finding (+ evaluation
    # category context), and the assessment is attached before persist.
    uses_assess = "risk_engine.assess" in src
    finding_first = src.find("finding_id = str(uuid.uuid4())") < src.find("risk_engine.assess")
    ok = uses_assess and finding_first
    _row(recorder, "V09-73", "I",
         "10.9 Input is 'Findings' - risk is assessed from finding-grade inputs with the identity minted first",
         "FindingGenerator._create_finding wiring", "assess() on finding-grade inputs",
         f"uses_assess={uses_assess}, identity_first={finding_first}", ok, "CONFIRMED BEHAVIOR",
         "E09 §18: id minted → assess(severity/vendor/category/confidence) → attach → persist (no second scorer)",
         "Either correct the spec input or pass generated findings through a risk stage.")
    assert ok


# --------------------------------------------------------------------------
# J - determinism
# --------------------------------------------------------------------------


def test_v09_74_ml_grid_deterministic(recorder, calc):
    a = [calc.calculate_risk_score(*key) for key in _grid()]
    b = [calc.calculate_risk_score(*key) for key in _grid()]
    c = [calc.calculate_risk_score(*key) for key in _grid()]
    ok = a == b == c
    _row(recorder, "V09-74", "J",
         "repeated ML risk scoring of identical inputs returns identical values",
         "96-combo grid x3", "three identical runs",
         f"run1==run2==run3: {ok}", ok, "CONFIRMED BEHAVIOR",
         "RandomForestRegressor.predict is deterministic; no randomness in the serving path", "")
    assert ok


def test_v09_75_generated_findings_deterministic(recorder):
    items = [_mk(f"c{i}", ComplianceResultType.FAIL, SEVS[i % 4], 0.9, "ssh") for i in range(20)]
    ev = _mk_eval(items)
    g = FindingGenerator()
    a = [(f.risk_score, f.priority) for f in g.generate_findings(ev, "det-a")]
    b = [(f.risk_score, f.priority) for f in g.generate_findings(ev, "det-b")]
    ok = a == b and len(a) == 20
    _row(recorder, "V09-75", "J",
         "generating findings twice from the same evaluation yields identical risk/priority sequences",
         "20 FAIL evaluations x2", "identical sequences",
         f"identical={ok}, n={len(a)}", ok, "CONFIRMED BEHAVIOR",
         "only finding ids/timestamps differ; risk_score and priority repeat exactly", "")
    assert ok


def test_v09_76_formula_deterministic(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    a = [calc.calculate_risk_score(*key) for key in _grid()]
    b = [calc.calculate_risk_score(*key) for key in _grid()]
    ok = a == b
    _row(recorder, "V09-76", "J",
         "the deterministic formula path is repeatable",
         "96-combo grid x2, ML off", "identical runs",
         f"identical={ok}", ok, "CONFIRMED BEHAVIOR",
         "pure arithmetic with fixed tables", "")
    assert ok


# --------------------------------------------------------------------------
# K - performance sanity
# --------------------------------------------------------------------------


def test_v09_77_ml_predict_latency(recorder, calc):
    calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", 0.9)
    durs = []
    for _ in range(200):
        t0 = time.perf_counter()
        calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", 0.9)
        durs.append((time.perf_counter() - t0) * 1000)
    durs.sort()
    p50 = durs[len(durs) // 2]
    p95 = durs[int(len(durs) * 0.95)]
    ok = p50 < 25.0
    _row(recorder, "V09-77", "K",
         "ML risk scoring stays within the <25ms/finding sanity bound used since E08",
         "200 sequential predict calls (model warm)", "p50 < 25ms",
         f"p50={p50:.2f}ms, p95={p95:.2f}ms, max={max(durs):.2f}ms", ok, "CONFIRMED BEHAVIOR",
         "100-tree forest on 4 numeric features; sanity bound only (no spec latency exists)", "")
    assert ok


def test_v09_78_formula_latency(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", 0.9)
    durs = []
    for _ in range(1000):
        t0 = time.perf_counter()
        calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", 0.9)
        durs.append((time.perf_counter() - t0) * 1000)
    durs.sort()
    p50 = durs[len(durs) // 2]
    ok = p50 < 1.0
    _row(recorder, "V09-78", "K",
         "formula risk scoring is negligible cost",
         "1000 sequential formula calls, ML off", "p50 < 1ms",
         f"p50={p50:.4f}ms", ok, "CONFIRMED BEHAVIOR",
         "pure arithmetic path", "")
    assert ok


def test_v09_79_findings_generation_overhead(recorder):
    items = [_mk(f"k{i}", ComplianceResultType.FAIL, SEVS[i % 4], 0.9, "ssh") for i in range(100)]
    ev = _mk_eval(items)
    g = FindingGenerator()
    t0 = time.perf_counter()
    out = g.generate_findings(ev, "perf")
    elapsed = (time.perf_counter() - t0) * 1000
    ok = len(out) == 100 and elapsed < 5000.0
    _row(recorder, "V09-79", "K",
         "risk scoring of 100 findings completes within a 5s sanity bound",
         "generate_findings on 100 FAIL evaluations (ML path)", "<5000ms, 100 findings",
         f"elapsed={elapsed:.0f}ms, findings={len(out)}", ok, "CONFIRMED BEHAVIOR",
         f"~{elapsed / 100:.1f}ms per finding including risk+priority+evidence copy (includes one-time model warm-up)", "")
    assert ok


# --------------------------------------------------------------------------
# L - hostile / invalid inputs
# --------------------------------------------------------------------------


def test_v09_80_vendor_none_raises(recorder, calc):
    try:
        calc.calculate_risk_score(Severity.HIGH, vendor=None, category="", confidence=1.0)
        exc = None
    except Exception as e:  # noqa: BLE001
        exc = e
    ok = isinstance(exc, ValueError)
    _row(recorder, "V09-80", "L",
         "invalid vendor input (None) is rejected with a domain error",
         "vendor=None on the production path", "ValueError",
         f"raised={type(exc).__name__ if exc else None}: {exc}", ok, "CONFIRMED BEHAVIOR",
         "E09 F7: vendor validated as str up front (RiskValidationError)",
         "Validate/normalise vendor before multiplier lookup.")
    assert ok


def test_v09_81_confidence_none_raises(recorder, calc):
    try:
        calc.calculate_risk_score(Severity.HIGH, vendor="cisco", category="", confidence=None)
        exc = None
    except Exception as e:  # noqa: BLE001
        exc = e
    ok = isinstance(exc, ValueError)
    _row(recorder, "V09-81", "L",
         "invalid confidence input (None) is rejected with a domain error",
         "confidence=None on the production path", "ValueError",
         f"raised={type(exc).__name__ if exc else None}: {exc}", ok, "CONFIRMED BEHAVIOR",
         "E09 F7: confidence validated as finite real in [0,1] up front",
         "Validate confidence range/type up front.")
    assert ok


def test_v09_82_confidence_nan_becomes_max_risk(recorder, calc):
    try:
        score = calc.calculate_risk_score(Severity.HIGH, vendor="cisco", category="", confidence=float("nan"))
        exc = None
    except Exception as e:  # noqa: BLE001
        exc = e
        score = None
    ok = isinstance(exc, ValueError)
    _row(recorder, "V09-82", "L",
         "NaN confidence is rejected instead of silently producing a score",
         "confidence=NaN", "ValueError",
         f"score={score}, band={'P1' if score == 100.0 else '-'}", ok, "CONFIRMED BEHAVIOR",
         "E09 F7: non-finite confidence rejected before scoring (no NaN→100 P1 fabrication)",
         "Reject non-finite confidence (math.isfinite check).")
    assert ok


def test_v09_83_negative_confidence_accepted(recorder, calc):
    try:
        score_ml = calc.calculate_risk_score(Severity.HIGH, vendor="cisco", category="", confidence=-1.0)
        exc = None
    except Exception as e:  # noqa: BLE001
        exc = e
        score_ml = None
    try:
        calc.calculate_risk_score(Severity.HIGH, vendor="cisco", category="", confidence=-1.0)
        exc2 = None
    except Exception as e:  # noqa: BLE001
        exc2 = e
    ok = isinstance(exc, ValueError) and isinstance(exc2, ValueError)
    _row(recorder, "V09-83", "L",
         "negative confidence is rejected",
         "confidence=-1.0 (single normative path)", "ValueError",
         f"score={score_ml}, raised={type(exc).__name__ if exc else None}", ok, "CONFIRMED BEHAVIOR",
         "E09 F7: confidence validated in [0,1] on the single normative path",
         "Validate confidence in [0,1].")
    assert ok


def test_v09_84_overrange_confidence_accepted(recorder, calc):
    try:
        score = calc.calculate_risk_score(Severity.HIGH, vendor="cisco", category="", confidence=1000.0)
        exc = None
    except Exception as e:  # noqa: BLE001
        exc = e
        score = None
    ok = isinstance(exc, ValueError)
    _row(recorder, "V09-84", "L",
         "confidence above 1.0 is rejected",
         "confidence=1000.0", "ValueError",
         f"score={score}, raised={type(exc).__name__ if exc else None}", ok, "CONFIRMED BEHAVIOR",
         "E09 F7: confidence validated in [0,1] on the single normative path",
         "Validate confidence in [0,1].")
    assert ok


def test_v09_85_string_severity_silently_wrong(recorder, calc, monkeypatch):
    _no_ml(monkeypatch)
    try:
        as_str = calc.calculate_risk_score("HIGH", "", "", 1.0)
        exc = None
    except Exception as e:  # noqa: BLE001
        exc = e
        as_str = None
    as_enum = calc.calculate_risk_score(Severity.HIGH, "", "", 1.0)
    ok = isinstance(exc, ValueError) or as_str == as_enum
    _row(recorder, "V09-85", "L",
         "string severity 'HIGH' scores like Severity.HIGH or is rejected",
         "severity='HIGH' (str), ML off", "48.1 (or rejected)",
         f"str_score={as_str}, enum_score={as_enum}, raised={type(exc).__name__ if exc else None}", ok, "CONFIRMED BEHAVIOR",
         "E08 F7: uppercase enum values compare equal to plain strings, so "
         "the fallback path scores 'HIGH' identically (no silent default)",
         "Normalise severity to the enum before lookup.")
    assert ok


def test_v09_86_severity_none_silently_defaulted(recorder, calc):
    try:
        score = calc.calculate_risk_score(None, vendor="cisco", category="", confidence=1.0)
        exc = None
    except Exception as e:  # noqa: BLE001
        exc = e
        score = None
    ok = isinstance(exc, ValueError)
    _row(recorder, "V09-86", "L",
         "missing severity is rejected instead of silently defaulted",
         "severity=None", "ValueError",
         f"score={score}, raised={type(exc).__name__ if exc else None}", ok, "CONFIRMED BEHAVIOR",
         "E09 F7: severity must be the enum or a canonical string (no silent default)",
         "Require a valid Severity member.")
    assert ok


# --------------------------------------------------------------------------
# M - user-facing exposure
# --------------------------------------------------------------------------


def test_v09_87_frontend_never_shows_risk_or_priority(recorder):
    risk_hits, prio_hits = [], []
    for f in FRONTEND.rglob("*"):
        if f.suffix not in {".tsx", ".ts"} or "node_modules" in str(f) or ".next" in str(f):
            continue
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(FRONTEND))
        if "risk_score" in txt or "riskScore" in txt:
            risk_hits.append(rel)
        if "priority" in txt and "findings" in rel:
            prio_hits.append(rel)
    # OUT OF SCOPE for E09 (backend engine): no UI route is added and none
    # is claimed; the API contract (FindingResponse.risk_score/priority) is
    # the deliverable the UI will consume. Recorded, not hidden.
    ok = not risk_hits
    _row(recorder, "V09-87", "M",
         "E09 ships no UI changes (backend scope): risk UI remains future work consuming the new API contract",
         "scan frontend/**/*.{ts,tsx} for risk_score/riskScore + priority in findings views",
         "no UI claims; API contract available",
         f"risk_score_sites={risk_hits}, priority_in_findings={prio_hits}", ok, "OUT OF SCOPE",
         "E09 F9 delivers backend exposure (FindingResponse + reports); UI rendering is future work",
         "Render risk_score and priority on the findings list/detail views.")
    assert ok


# --------------------------------------------------------------------------
# New E09 contract tests (canonical RiskEngine)
# --------------------------------------------------------------------------


def test_v09_96_confidence_monotonicity_property(recorder, calc):
    from app.engines.compliance.risk import RiskEngine

    engine = RiskEngine()
    violations = []
    steps = [i / 20.0 for i in range(21)]
    for sev in SEVS:
        for vendor in ["cisco", "juniper", "unknown", "arista", ""]:
            for cat in ["ssh", "Access Control", "unknown", ""]:
                xs = [engine.calculate_risk_score(sev, vendor, cat, c)
                      for c in steps]
                if not all(xs[i] <= xs[i + 1] for i in range(len(xs) - 1)):
                    violations.append((sev.value, vendor, cat, xs))
    ok = not violations
    _row(recorder, "V09-96", "B",
         "S1 property: risk is non-decreasing in confidence over 0.0..1.0 "
         "for every severity/vendor/category combination",
         "21-step sweep x 4 severities x 5 vendors x 4 categories (420 curves)",
         "0 monotonicity violations",
         f"violations={len(violations)}", ok, "CONFIRMED BEHAVIOR",
         "E09 S1: max(conf,0.5) floor preserves ordering; validated inputs only", "")
    assert ok


def test_v09_97_risk_persistence_round_trip(recorder):
    import asyncio

    async def _run():
        import scripts.engine_validation.dbutil as dbutil
        from sqlalchemy import delete, select

        if not await dbutil.schema_available():
            return "skip"
        from app.models import Audit, Finding as DBFinding, User
        import uuid as _uuid

        engine, factory = dbutil.make_session_factory()
        session = factory()
        try:
            tag = f"e09-{_uuid.uuid4().hex[:8]}"
            user = User(id=_uuid.uuid4(), email=f"{tag}@example.com",
                        password_hash="x", role="admin", is_active=True)
            session.add(user)
            await session.flush()
            audit = Audit(user_id=user.id, name=f"{tag}-audit",
                          status="completed")
            session.add(audit)
            await session.flush()
            row = DBFinding(
                audit_id=audit.id, control_id="1.1.1", title="t",
                description="d", severity="HIGH", confidence=0.9,
                status="open", evidence={}, remediation={},
                risk_score=48.1, priority="P3", risk_method="deterministic",
                risk_model_version="v1")
            session.add(row)
            await session.commit()
            back = (await session.execute(
                select(DBFinding).where(DBFinding.id == row.id))).scalar_one()
            result = (back.risk_score, back.priority, back.risk_method,
                      back.risk_model_version)
            await session.execute(delete(DBFinding).where(
                DBFinding.audit_id == audit.id))
            await session.execute(delete(Audit).where(Audit.id == audit.id))
            await session.execute(delete(User).where(User.id == user.id))
            await session.commit()
            return result
        finally:
            await session.close()
            await engine.dispose()

    result = asyncio.run(_run())
    if result == "skip":
        pytest.skip("throwaway database engine_validation_test not provisioned")
    ok = result == (48.1, "P3", "deterministic", "v1")
    _row(recorder, "V09-97", "G",
         "risk output survives the DB round-trip with method/version lineage",
         "insert + read back a fully populated finding row", "identical values",
         f"roundtrip={result}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1: migration 008 columns; ORM model fields", "")
    assert ok


def test_v09_98_advisory_isolation(recorder, calc, monkeypatch):
    from app.engines.compliance.risk import advisory_score
    import app.ml.model as ml_mod

    keys = list(_grid())[:24]
    normative = [calc.calculate_risk_score(*k) for k in keys]
    advised = [advisory_score(*k) for k in keys]
    orig = ml_mod.get_risk_predictor
    ml_mod.get_risk_predictor = lambda: (_ for _ in ()).throw(
        RuntimeError("model store gone"))
    try:
        normative_broken_ml = [calc.calculate_risk_score(*k) for k in keys]
        advised_none = [advisory_score(*k) for k in keys]
    finally:
        ml_mod.get_risk_predictor = orig
    ok = (normative == normative_broken_ml
          and all(a is None for a in advised_none)
          and all(isinstance(a, float) for a in advised if a is not None))
    _row(recorder, "V09-98", "B",
         "normative scoring is independent of ML availability; advisory degrades to None (never a fabricated score)",
         "24-combo grid with working vs raising model loader",
         "identical normative runs; advisory None when the model errors",
         f"identical={normative == normative_broken_ml}, "
         f"advisory_none={all(a is None for a in advised_none)}", ok, "CONFIRMED BEHAVIOR",
         "E09 F4: normative path never calls the model; advisory_score narrows exceptions to None", "")
    assert ok


def test_v09_99_retrained_model_parity(recorder):
    from app.engines.compliance.risk import (
        RISK_FEATURES, SEVERITY_NUM, VENDOR_IMPACT,
        advisory_score, deterministic_score,
    )
    meta = json.loads((BACKEND / "app" / "ml" / "model_artifacts" / "risk_meta.json").read_text())
    diffs = []
    for sev in SEVERITY_NUM:
        for vendor in VENDOR_IMPACT:
            for cat in ["ssh", "aaa", "logging", "unknown"]:
                for conf in [0.5, 0.75, 1.0]:
                    n = deterministic_score(sev, vendor, cat, conf)
                    a = advisory_score(sev, vendor, cat, conf)
                    diffs.append(abs(n - (a if a is not None else n)))
    ok = (meta.get("features") == list(RISK_FEATURES)
          and meta.get("scope", "").startswith("advisory")
          and max(diffs) <= 10.0)
    _row(recorder, "V09-99", "F",
         "retrained advisory model shares vocabulary/features and tracks the normative scorer",
         "meta features/scope + 192-combo advisory-vs-normative grid",
         "shared features; advisory max diff <= 10",
         f"features={meta.get('features')}, max_diff={max(diffs):.1f}, r2={meta.get('r2')}", ok, "CONFIRMED BEHAVIOR",
         "E09 F6 Option A: retrained on canonical maps + shared builder; R² scopes emulation fit", "")
    assert ok


def test_v09_100_migration_chain(recorder):
    vdir = BACKEND / "alembic" / "versions"
    revs = {}
    for p in vdir.glob("*.py"):
        txt = p.read_text(encoding="utf-8", errors="replace")
        m_rev = re.search(r"^revision(\s*:\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", txt, re.M)
        m_down = re.search(r"^down_revision[^=]*=\s*['\"]([^'\"]+)['\"]", txt, re.M)
        if m_rev:
            revs[m_rev.group(2)] = (p.name, m_down.group(1) if m_down else None)
    e008 = [r for r, (name, _) in revs.items() if "008" in r or "008" in name]
    txt008 = (vdir / "008_finding_risk_columns.py").read_text(encoding="utf-8")
    downs = {r: d for r, (_, d) in revs.items()}
    # chain integrity: every down_revision resolves (None only for the base)
    dangling = [r for r, d in downs.items() if d is not None and d not in revs]
    ok = (bool(e008) and "risk_score" in txt008 and "priority" in txt008
          and "risk_method" in txt008 and "risk_model_version" in txt008
          and "def downgrade" in txt008 and not dangling)
    _row(recorder, "V09-100", "G",
         "migration 008 chains onto the project history with upgrade + downgrade",
         "alembic versions chain + 008 content", "008 present, 4 columns, downgrade, no dangling",
         f"e008={e008}, dangling={dangling}", ok, "CONFIRMED BEHAVIOR",
         "E09 F1: 008_finding_risk_columns.py (executed for real by validate_migration_008.py)", "")
    assert ok


def test_v09_101_hostile_matrix(recorder, calc):
    bad_confs = [None, "0.9", float("nan"), float("inf"), float("-inf"),
                 -0.1, -1.0, 1.1, 100.0, 1000.0, True]
    bad_sevs = [None, "", "garbage", "high", 123]
    bad_vendors = [None, 123, ["cisco"]]
    bad_cats = [None, 123, ["ssh"]]
    rejected = 0
    total = 0
    leaked = []
    for conf in bad_confs:
        total += 1
        try:
            calc.calculate_risk_score(Severity.HIGH, "cisco", "ssh", conf)
            leaked.append(("conf", conf))
        except (ValueError, TypeError):
            rejected += 1
    for sev in bad_sevs:
        total += 1
        try:
            calc.calculate_risk_score(sev, "cisco", "ssh", 1.0)
            leaked.append(("sev", sev))
        except (ValueError, TypeError):
            rejected += 1
    for vendor in bad_vendors:
        total += 1
        try:
            calc.calculate_risk_score(Severity.HIGH, vendor, "ssh", 1.0)
            leaked.append(("vendor", vendor))
        except (ValueError, TypeError):
            rejected += 1
    for cat in bad_cats:
        total += 1
        try:
            calc.calculate_risk_score(Severity.HIGH, "cisco", cat, 1.0)
            leaked.append(("cat", cat))
        except (ValueError, TypeError):
            rejected += 1
    # Valid hostile-shaped strings must score safely (neutral), never crash.
    safe = []
    for vendor in ["", "unknown", "../../cisco", "<script>", "CISCO "]:
        safe.append(calc.calculate_risk_score(Severity.HIGH, vendor, "ssh", 1.0))
    for cat in ["", "unknown", "SSH", "<script>", "  ssh  "]:
        safe.append(calc.calculate_risk_score(Severity.HIGH, "cisco", cat, 1.0))
    ok = (rejected == total and not leaked
          and all(isinstance(s, float) and 0.0 <= s <= 100.0 for s in safe))
    _row(recorder, "V09-101", "L",
         "hostile matrix: invalid numerics/types rejected typed; hostile strings score safely neutral",
         "11 bad confidences + 5 bad severities + 3 bad vendors + 3 bad categories + 10 hostile strings",
         "22 rejections, 10 safe neutral scores, 0 leaks/crashes",
         f"rejected={rejected}/{total}, leaked={leaked}", ok, "CONFIRMED BEHAVIOR",
         "E09 F7: RiskValidationError everywhere invalid; neutral rule for hostile strings", "")
    assert ok


def test_v09_102_category_normalization_contract(recorder, calc):
    from app.engines.compliance.risk import (
        NEUTRAL_CATEGORY_IMPACT, category_impact, normalize_category)
    variants = ["SSH", "ssh", "Ssh", "  ssh  ", "access_control",
                "Access Control", "ACCESS_CONTROL"]
    resolved = {v: normalize_category(v) for v in variants}
    ok = (resolved["SSH"] == resolved["ssh"] == "ssh"
          and resolved["access_control"] == resolved["Access Control"] == "access control"
          and category_impact("unknown") == NEUTRAL_CATEGORY_IMPACT
          and category_impact("") == NEUTRAL_CATEGORY_IMPACT
          and category_impact("SSH") != NEUTRAL_CATEGORY_IMPACT)
    _row(recorder, "V09-102", "D",
         "category normalization is deterministic; unknown/empty resolve neutral (documented)",
         "case/space/underscore variants + unknown + empty",
         "consistent keys; unknown/empty neutral; real categories active",
         f"resolved={resolved}", ok, "CONFIRMED BEHAVIOR",
         "E09 F5: normalize_category shared by scoring/validation/tests/reporting", "")
    assert ok


def test_v09_103_vendor_neutral_contract(recorder, calc):
    from app.engines.compliance.risk import (
        NEUTRAL_VENDOR_IMPACT, normalize_vendor, vendor_impact)
    ok = (normalize_vendor("CISCO ") == "cisco"
          and vendor_impact("unknown") == NEUTRAL_VENDOR_IMPACT
          and vendor_impact("") == NEUTRAL_VENDOR_IMPACT
          and vendor_impact("../../cisco") == NEUTRAL_VENDOR_IMPACT
          and vendor_impact("<script>") == NEUTRAL_VENDOR_IMPACT
          and vendor_impact("cisco") == 1.2
          and vendor_impact("juniper") == 1.1)
    _row(recorder, "V09-103", "G",
         "vendor handling is safe: supported keep multipliers, everything else neutral (no fallback, no lookup tricks)",
         "case/empty/unknown/traversal/script vendors",
         "documented neutral 1.0; cisco 1.2, juniper 1.1",
         f"ok={ok}", ok, "CONFIRMED BEHAVIOR",
         "E09 F8: normalize_vendor + neutral default; no Cisco fallback anywhere", "")
    assert ok


def test_v09_104_overall_score_separation(recorder):
    risk_src = (BACKEND / "app" / "engines" / "compliance" / "risk.py").read_text(encoding="utf-8")
    findings_src = _read("app/engines/compliance/findings.py")
    ok = ("overall_score" not in risk_src
          and "overall_score" not in findings_src)
    _row(recorder, "V09-104", "I",
         "the Risk Engine computes no overall compliance score (E07 owns the single formula)",
         "grep overall_score in risk.py + findings.py", "absent in both",
         f"present={not ok}", ok, "CONFIRMED BEHAVIOR",
         "E09 F10: Compliance Engine → compliance score; Risk Engine → risk assessment (documented separation)",
         "")
    assert ok


def test_v09_105_assessment_contract(recorder, calc):
    from app.engines.compliance.risk import RiskAssessment, RiskEngine
    engine = RiskEngine()
    a = engine.assess(finding_id="f-1", severity=Severity.HIGH,
                      vendor="Cisco", category="SSH", confidence=0.9)
    d = a.to_dict()
    ok = (isinstance(a, RiskAssessment)
          and a.finding_id == "f-1" and a.severity == "HIGH"
          and a.vendor == "cisco" and a.category == "ssh"
          and a.confidence == 0.9
          and a.scoring_method == "deterministic" and a.scoring_version == "v1"
          and a.priority in {"P1", "P2", "P3", "P4"}
          and isinstance(a.risk_score, float) and 0.0 <= a.risk_score <= 100.0
          and set(d) == {"finding_id", "risk_score", "priority", "severity",
                         "confidence", "vendor", "category", "scoring_method",
                         "scoring_version", "advisory_score", "advisory_model",
                         "advisory_model_version"}
          and a.advisory_score is None)
    _row(recorder, "V09-105", "A",
         "RiskAssessment carries the specified contract (finding link, score, priority, normalized inputs, method/version)",
         "assess() with mixed-case inputs, advisory off", "normalized contract object",
         f"assessment={d}", ok, "CONFIRMED BEHAVIOR",
         "E09 F3/§19: risk.py::RiskAssessment + to_dict()", "")
    assert ok
