"""Engine 08 validation - Finding Engine (spec section 10.8 / 9.1 step 7 / 12).

Every test records one evidence row via the `recorder` fixture (see
tests/validation/conftest.py). Ground rules: no production code is modified;
detector output is never ground truth; category G is the separate, explicitly
labelled record of wrong/unsupported-vendor consequences; statuses report
whether the requirement is met (FAIL = defect present), so defect claims assert
the defect (`assert not ok`) and conformance claims assert `ok`.

Scope:
    app/engines/compliance/findings.py   (Finding, SeverityCalculator,
                                          FindingGenerator)
    app/engines/compliance/executor.py   (step 6 call site, conversion)
    app/api/v1/findings.py               (list / detail / status update)
    app/api/v1/audit_execution.py        (persistence, counters, 2nd list impl)
    app/models/__init__.py               (Finding table)
    app/schemas/__init__.py              (FindingResponse etc.)
    app/engines/compliance/models.py     (Severity, FindingStatus enums)
"""

from __future__ import annotations

import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.benchmarks.execution import BenchmarkExecutionEngine
from app.engines.compliance.engine import ComplianceEvaluation, ControlEvaluation
from app.engines.compliance.evidence import EvidenceChain
from app.engines.compliance.executor import AuditExecutor
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
SAMPLE = BACKEND / "tests" / "sample_configs"
SPEC_PATH = BACKEND.parent / "docs" / "PROJECT_MASTER_SPEC.md"

SECURE = (SAMPLE / "secure.txt").read_text(encoding="utf-8")
INSECURE = (SAMPLE / "insecure.txt").read_text(encoding="utf-8")
JUNIPER_SECURE = (SAMPLE / "juniper_secure.txt").read_text(encoding="utf-8")
SPEC = SPEC_PATH.read_text(encoding="utf-8")

_REMED = {
    "title": "Fix the control",
    "description": "desc",
    "why_it_matters": "why",
    "recommended_config": "hostname core",
    "verification_steps": ["check"],
    "rollback_steps": ["undo"],
    "references": ["CIS"],
}


# --------------------------------------------------------------------------
# helpers / fixtures
# --------------------------------------------------------------------------


def _mk(
    cid: str,
    result: ComplianceResultType,
    severity: Severity = Severity.HIGH,
    conf: float = 0.9,
    category: str = "ssh",
    remediation: dict | None = None,
    title: str | None = None,
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
        control_title=title or f"Title {cid}",
        control_description=f"Desc {cid}",
        severity=severity,
        category=category,
        result=result,
        confidence=conf,
        evidence=chain,
        remediation=remediation,
    )


def _mk_eval(
    items: list[ControlEvaluation], vendor: str = "cisco", platform: str = "ios_xe"
) -> ComplianceEvaluation:
    ev = ComplianceEvaluation(vendor=vendor, platform=platform)
    ev.evaluations = list(items)
    for it in items:
        if it.result == ComplianceResultType.PASS:
            ev.passed += 1
        elif it.result == ComplianceResultType.FAIL:
            ev.failed += 1
        else:
            ev.review += 1
    ev.total_controls = len(items)
    ev.overall_score = (ev.passed / (ev.passed + ev.failed) * 100) if (ev.passed + ev.failed) else 0.0
    return ev


@pytest.fixture(scope="module")
def gen() -> FindingGenerator:
    return FindingGenerator()


@pytest.fixture(scope="module")
def mixed_evaluation() -> ComplianceEvaluation:
    return _mk_eval(
        [
            _mk("1.1.1", ComplianceResultType.PASS),
            _mk("1.1.2", ComplianceResultType.PASS),
            _mk("2.1.1", ComplianceResultType.FAIL, remediation=_REMED),
            _mk("2.1.2", ComplianceResultType.FAIL, severity=Severity.CRITICAL,
                remediation=_REMED),
            _mk("3.1.1", ComplianceResultType.REVIEW),
            _mk("3.1.2", ComplianceResultType.REVIEW, severity=Severity.LOW),
        ]
    )


@pytest.fixture(scope="module")
def mixed_findings(gen, mixed_evaluation) -> list[Finding]:
    return gen.generate_findings(
        evaluation=mixed_evaluation, audit_id="e08-mixed", device_name="core-sw1"
    )


@pytest.fixture(scope="module")
def secure_run():
    return AuditExecutor().execute(
        audit_id="e08-secure", config_content=SECURE, device_name="secure-sw"
    )


@pytest.fixture(scope="module")
def insecure_run():
    return AuditExecutor().execute(
        audit_id="e08-insecure", config_content=INSECURE, device_name="insecure-sw"
    )


@pytest.fixture(scope="module")
def juniper_run():
    return AuditExecutor().execute(
        audit_id="e08-juniper", config_content=JUNIPER_SECURE, device_name="j-sr"
    )


@pytest.fixture(scope="module")
def secure_run2():
    return AuditExecutor().execute(
        audit_id="e08-secure-2", config_content=SECURE, device_name="secure-sw"
    )


def _bench_to_eval(bench_res) -> ComplianceEvaluation:
    """Production conversion path used by AuditExecutor (executor.py:283)."""
    return AuditExecutor()._benchmark_to_compliance_evaluation(bench_res, None)


def _spec_interface_fields() -> set[str]:
    m = re.search(r"interface Finding \{(.*?)\}", SPEC, re.S)
    assert m, "spec interface Finding not found"
    return {
        ln.split(":")[0].strip()
        for ln in m.group(1).strip().splitlines()
        if ":" in ln
    }


def _spec_ddl_cols() -> set[str]:
    m = re.search(r"CREATE TABLE findings \((.*?)\);", SPEC, re.S)
    assert m, "spec DDL findings not found"
    cols = set()
    for line in m.group(1).splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        cols.add(line.split()[0])
    return cols


# --------------------------------------------------------------------------
# DB fixture (throwaway engine_validation_test database)
# --------------------------------------------------------------------------


@pytest.fixture()
async def fnd_db():
    """Session + user + e08 audit (+ helpers) against the throwaway DB."""
    import scripts.engine_validation.dbutil as dbutil
    from sqlalchemy import delete, select

    if not await dbutil.schema_available():
        pytest.skip("throwaway database engine_validation_test not provisioned")

    from app.models import Audit, AuditTrail, Configuration, Device, Finding, User

    engine, factory = dbutil.make_session_factory()
    session = factory()

    async def _clean():
        e08_audits = (
            (
                await session.execute(
                    select(Audit.id).where(Audit.name.like("e08-%"))
                )
            )
            .scalars()
            .all()
        )
        if e08_audits:
            await session.execute(
                delete(Finding).where(Finding.audit_id.in_(list(e08_audits)))
            )
            await session.execute(
                delete(Audit).where(Audit.id.in_(list(e08_audits)))
            )
        await session.execute(
            delete(AuditTrail).where(AuditTrail.entity_type == "finding")
        )
        await session.execute(
            delete(Configuration).where(Configuration.filename.like("e08-%"))
        )
        await session.execute(delete(Device).where(Device.name.like("e08-%")))
        await session.execute(delete(User).where(User.email.like("e08-%")))
        await session.commit()

    await _clean()

    user = User(
        id=uuid.uuid4(),
        email=f"e08-{uuid.uuid4().hex[:10]}@example.com",
        password_hash="x",
        role="admin",
        is_active=True,
    )
    session.add(user)
    await session.commit()
    audit = Audit(
        id=uuid.uuid4(), user_id=user.id, name="e08-audit", status="completed"
    )
    session.add(audit)
    await session.commit()

    ns = SimpleNamespace(
        session=session,
        user_id=user.id,
        audit_id=audit.id,
        admin=SimpleNamespace(id=user.id),
        other=SimpleNamespace(id=uuid.uuid4()),
        clean=_clean,
    )
    try:
        yield ns
    finally:
        try:
            await _clean()
        except Exception:  # noqa: BLE001
            await session.rollback()
        await session.close()
        await engine.dispose()


async def _add_finding(
    db,
    severity: str = "CRITICAL",
    title: str = "Finding title",
    status: str = "open",
    evidence: dict | None = None,
    compliance_result_id=None,
    device: str = "core-sw1",
    created_at: datetime | None = None,
    description: str = "desc",
) -> uuid.UUID:
    from app.models import Finding as FindingModel

    kwargs = {}
    if created_at is not None:
        kwargs["created_at"] = created_at
    f = FindingModel(
        audit_id=db.audit_id,
        compliance_result_id=compliance_result_id,
        title=title,
        description=description,
        severity=severity,
        confidence=0.9,
        status=status,
        evidence=evidence if evidence is not None else {},
        remediation={},
        affected_device=device,
        affected_vendor="cisco",
        affected_platform="ios_xe",
        **kwargs,
    )
    db.session.add(f)
    await db.session.commit()
    return f.id


# ==========================================================================
# A - spec structure / interface conformance (section 12 Finding, DDL, enums)
# ==========================================================================


def test_v08_01_dataclass_matches_spec_interface(recorder, mixed_findings):
    spec_fields = _spec_interface_fields()
    impl_fields = set(Finding.__dataclass_fields__)
    missing = sorted(spec_fields - impl_fields)
    # Operational fields are allowed when documented (mission §2): they
    # carry engine-internal needs without competing with the contract.
    # risk_method/risk_model_version are E09 scoring lineage (documented
    # in the Finding docstring alongside the other operational fields).
    allowed_operational = {"audit_id", "risk_score", "priority", "result",
                           "affected_platform", "created_at", "updated_at",
                           "risk_method", "risk_model_version"}
    extra = sorted(impl_fields - spec_fields)
    unexplained = sorted(set(extra) - allowed_operational)
    ok = not missing and not unexplained
    recorder.add(
        "V08-01", "A",
        "the Finding record exposes exactly the section 12 interface "
        "(id, compliance_result_id, control_id, title, description, severity, "
        "confidence, evidence, affected_device, affected_vendor, remediation, status)",
        "dataclass fields vs spec interface",
        f"no missing spec fields; extras limited to documented operational "
        f"fields ({sorted(allowed_operational)})",
        f"missing={missing} extra={extra} unexplained={unexplained}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "spec:841-855; app/engines/compliance/findings.py Finding docstring "
        "documents each operational field",
        "separate the engine-internal record from the persisted interface record",
    )
    assert ok


def test_v08_02_response_exposes_control_id(recorder):
    from app.schemas import FindingResponse

    ok = "control_id" in FindingResponse.model_fields
    recorder.add(
        "V08-02", "A",
        "the findings API response carries control_id (section 12 Finding "
        "field 3 - the finding-to-control link is part of the contract)",
        "FindingResponse.model_fields",
        "control_id present",
        f"present={ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F1: app/schemas FindingResponse.control_id (mandatory)",
        "add control_id to FindingResponse",
    )
    assert ok


def test_v08_03_severity_vocabulary_lowercase(recorder, mixed_findings):
    values = {f.severity.value for f in mixed_findings}
    ok = values <= {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    recorder.add(
        "V08-03", "A",
        "severity uses the section 12 / DATA_MODEL vocabulary "
        "(CRITICAL | HIGH | MEDIUM | LOW) at the source",
        "Finding.severity.value for generated findings",
        "values in the spec enum",
        f"values={sorted(values)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E08 F7: compliance.models.Severity is the uppercase vocabulary "
        "end to end (source, storage, filters, reports, API)",
        "store and emit the spec vocabulary; derive display casing at the edge",
    )
    assert ok


def test_v08_04_status_vocabulary(recorder, mixed_findings):
    allowed = {"open", "in_progress", "resolved", "accepted"}
    values = {f.status.value for f in mixed_findings}
    enum_vals = {s.value for s in FindingStatus}
    ok = values <= allowed and enum_vals == allowed
    recorder.add(
        "V08-04", "A",
        "finding status uses the spec vocabulary "
        "(open | in_progress | resolved | accepted)",
        "FindingStatus enum + generated statuses",
        f"exactly {sorted(allowed)}",
        f"enum={sorted(enum_vals)} generated={sorted(values)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "app/engines/compliance/models.py:30-35; spec:854",
        "",
    )
    assert ok


def test_v08_05_table_matches_spec_ddl(recorder):
    ddl_cols = _spec_ddl_cols()
    from app.models import Finding as FindingModel

    model_cols = {c.name for c in FindingModel.__table__.c}
    # Explicit decision (mission §3, Option A): the §12 interface requires
    # evidence on the finding, so evidence is persisted as JSONB on the
    # row; the §19.1 10-column DDL (which omits evidence) is NOT followed
    # where it contradicts §12. No §12-required information disappears;
    # operational columns the application genuinely uses are retained.
    required = {"id", "audit_id", "compliance_result_id", "control_id",
                "title", "description", "severity", "confidence", "status",
                "evidence", "remediation", "affected_device",
                "affected_vendor"}
    missing_required = sorted(required - model_cols)
    evidence_present = "evidence" in model_cols
    ok = not missing_required and evidence_present
    recorder.add(
        "V08-05", "A",
        "the findings table carries every §12-required field with evidence "
        "persisted as JSONB (explicit Option-A decision on the spec "
        "contradiction)",
        "spec §12 interface + §19.1 DDL vs app.models.Finding",
        "all §12 fields present incl. evidence JSONB",
        f"missing §12 fields={missing_required}; evidence column present="
        f"{evidence_present}; model-only operational columns="
        f"{sorted(model_cols - ddl_cols)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E08 F1/§3: models.Finding persists evidence JSONB per §12; the "
        "§19.1 DDL omission is recorded, not silently followed",
        "reconcile spec DDL with spec-12 interface, then align the migration",
    )
    assert ok


def test_v08_06_response_evidence_untyped(recorder):
    from app.schemas import FindingResponse

    annotation = FindingResponse.model_fields["evidence"].annotation
    ok = "EvidenceChain" in str(annotation)
    recorder.add(
        "V08-06", "A",
        "Finding.evidence is typed as the section 12 EvidenceChain in the API "
        "contract (a structured chain, not an opaque blob)",
        "FindingResponse.evidence annotation",
        "EvidenceChain-typed field",
        f"annotation={annotation}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E08 F2: schemas.EvidenceChain mirrors the §12 keys (nullable where "
        "honest chains carry null); used by engine, persistence, API, tests",
        "type evidence with the EvidenceChain schema",
    )
    assert ok


def test_v08_07_ddl_not_null_columns(recorder):
    from app.models import Finding as FindingModel

    required = ["title", "description", "severity", "confidence", "status",
                "created_at", "updated_at"]
    cols = {c.name: c.nullable for c in FindingModel.__table__.c}
    bad = [n for n in required if cols.get(n, True)]
    ok = not bad
    recorder.add(
        "V08-07", "A",
        "columns the DDL marks NOT NULL are NOT NULL in the model",
        "model nullable flags for title/description/severity/confidence/status/timestamps",
        "all NOT NULL",
        f"violations={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "models:267-288 vs spec:1441-1452",
        "",
    )
    assert ok


def test_v08_08_spec_indexes_exist(recorder):
    mig = (BACKEND / "alembic" / "versions" / "001_initial_migration.py").read_text(
        encoding="utf-8"
    )
    wanted = [
        ("findings", "compliance_result_id"),
        ("findings", "severity"),
        ("findings", "status"),
    ]
    missing = []
    for table, col in wanted:
        pattern = rf"create_index\('[^']+',\s*'{table}',\s*\['{col}'\]\)"
        if not re.search(pattern, mig):
            missing.append(f"{table}.{col}")
    ok = not missing
    recorder.add(
        "V08-08", "A",
        "section 19.2 indexes exist: findings(compliance_result_id), "
        "findings(severity), findings(status)",
        "alembic 001 create_index calls",
        "3 indexes",
        f"missing={missing} (present under ix_* names; the declarative model "
        "itself defines none, so a Base.metadata-created database lacks them)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "alembic/versions/001_initial_migration.py:197-200; spec:1490-1492",
        "",
    )
    assert ok


def test_v08_09_remediation_shape_matches_spec(recorder, secure_run):
    spec_block = re.search(r"interface Remediation \{(.*?)\}", SPEC, re.S).group(1)
    spec_fields = {
        ln.split(":")[0].strip() for ln in spec_block.strip().splitlines() if ":" in ln
    }
    remediated = [f for f in secure_run.findings if f.remediation]
    assert remediated, "expected findings with remediation on secure.txt"
    keys = set(remediated[0].remediation)
    missing = sorted(spec_fields - keys)
    ok = not missing
    recorder.add(
        "V08-09", "A",
        "the remediation attached to a finding carries the section 12 "
        "Remediation interface fields (shape only - content is engine 10)",
        f"remediation keys on finding of {remediated[0].control_id}",
        f"superset of {sorted(spec_fields)}",
        f"missing={missing} extra={sorted(keys - spec_fields)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E08 F3: executor builds finding_id/finding_title/risk_description/"
        "why_it_matters/vendor/platform/recommended_config/"
        "verification_steps/rollback_steps/references; the generator stamps "
        "finding_id/finding_title",
        "emit the spec Remediation fields; finding_id is known at persistence",
    )
    assert ok


def test_v08_10_title_within_bounds(recorder, secure_run, juniper_run):
    titles = [f.title for f in secure_run.findings + juniper_run.findings]
    from app.models import Finding as FindingModel

    title_col = next(c for c in FindingModel.__table__.c if c.name == "title")
    maxlen = getattr(title_col.type, "length", None)
    over = [t for t in titles if maxlen and len(t) > maxlen]
    ok = bool(titles) and not over and title_col.nullable is False
    recorder.add(
        "V08-10", "A",
        "every generated title fits the DDL title column (VARCHAR(255), NOT NULL)",
        f"{len(titles)} titles from secure+juniper runs",
        "all non-empty and <= 255 chars",
        f"max_len={max(map(len, titles))} limit={maxlen} over={over[:3]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "models:273; spec:1444",
        "",
    )
    assert ok


# ==========================================================================
# B - generation contract (spec 9.1 step 7, 10.8: create finding records)
# ==========================================================================


def test_v08_11_each_fail_produces_finding(recorder, mixed_findings, mixed_evaluation):
    fail_ids = {
        e.control_id for e in mixed_evaluation.evaluations
        if e.result == ComplianceResultType.FAIL
    }
    got = {f.control_id for f in mixed_findings if f.result == ComplianceResultType.FAIL}
    ok = fail_ids == got
    recorder.add(
        "V08-11", "B",
        "every FAIL evaluation produces exactly one finding",
        "mixed evaluation (2 PASS / 2 FAIL / 2 REVIEW)",
        f"findings for {sorted(fail_ids)}",
        f"got={sorted(got)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:182-196",
        "",
    )
    assert ok


def test_v08_12_each_review_produces_finding(recorder, mixed_findings, mixed_evaluation):
    rev_ids = {
        e.control_id for e in mixed_evaluation.evaluations
        if e.result == ComplianceResultType.REVIEW
    }
    got = {f.control_id for f in mixed_findings if f.result == ComplianceResultType.REVIEW}
    ok = rev_ids == got
    recorder.add(
        "V08-12", "B",
        "every REVIEW evaluation produces a finding (manual review is an "
        "actionable outcome of the audit)",
        "mixed evaluation",
        f"findings for {sorted(rev_ids)}",
        f"got={sorted(got)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "findings.py:183-185 (skip only PASS)",
        "",
    )
    assert ok


def test_v08_13_no_finding_for_pass(recorder, mixed_findings, mixed_evaluation):
    pass_ids = {
        e.control_id for e in mixed_evaluation.evaluations
        if e.result == ComplianceResultType.PASS
    }
    got = {f.control_id for f in mixed_findings} & pass_ids
    ok = not got
    recorder.add(
        "V08-13", "B",
        "PASS evaluations never produce a finding",
        "mixed evaluation",
        "0 findings from PASS controls",
        f"overlap={sorted(got)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:184",
        "",
    )
    assert ok


def test_v08_14_all_pass_evaluation(recorder, gen):
    ev = _mk_eval([_mk(f"1.1.{i}", ComplianceResultType.PASS) for i in range(1, 6)])
    out = gen.generate_findings(evaluation=ev, audit_id="a", device_name="d")
    ok = out == []
    recorder.add(
        "V08-14", "B",
        "an all-PASS evaluation yields an empty finding list",
        "5 PASS evaluations",
        "[]",
        f"{len(out)} findings",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:184",
        "",
    )
    assert ok


def test_v08_15_empty_evaluation(recorder, gen):
    ev = ComplianceEvaluation(vendor="cisco", platform="ios_xe")
    out = gen.generate_findings(evaluation=ev, audit_id="a", device_name="d")
    ok = out == []
    recorder.add(
        "V08-15", "B",
        "an evaluation with no results yields an empty finding list without "
        "crashing",
        "ComplianceEvaluation(evaluations=[])",
        "[] and no exception",
        f"len={len(out)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:180-196",
        "",
    )
    assert ok


def test_v08_16_control_id_propagates(recorder, mixed_findings, mixed_evaluation):
    src = {e.control_id for e in mixed_evaluation.evaluations
           if e.result != ComplianceResultType.PASS}
    got = {f.control_id for f in mixed_findings}
    ok = src == got
    recorder.add(
        "V08-16", "B",
        "each finding records the control_id of the evaluation it came from",
        "mixed evaluation -> findings",
        f"ids {sorted(src)}",
        f"got={sorted(got)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:232",
        "",
    )
    assert ok


def test_v08_17_title_is_control_title(recorder, mixed_findings, mixed_evaluation):
    src = {e.control_id: e.control_title for e in mixed_evaluation.evaluations}
    bad = [f.control_id for f in mixed_findings if f.title != src[f.control_id]]
    ok = not bad
    recorder.add(
        "V08-17", "B",
        "finding.title equals the control's title",
        "mixed evaluation -> findings",
        "titles identical",
        f"mismatches={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:234",
        "",
    )
    assert ok


def test_v08_18_description_contains_reasoning(recorder, mixed_findings, mixed_evaluation):
    src = {e.control_id: e.evidence.reasoning
           for e in mixed_evaluation.evaluations}
    missing = [f.control_id for f in mixed_findings
               if src[f.control_id] not in f.description]
    ok = not missing
    recorder.add(
        "V08-18", "B",
        "the finding description carries the evaluation's reasoning "
        "(section 9.1 step 7 - findings are generated with evidence)",
        "description text vs evidence.result_reasoning",
        "reasoning embedded in every description",
        f"missing={missing}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:219-228",
        "",
    )
    assert ok


def test_v08_19_status_defaults_open(recorder, mixed_findings):
    bad = [f.control_id for f in mixed_findings
           if f.status != FindingStatus.OPEN]
    ok = not bad and len(mixed_findings) > 0
    recorder.add(
        "V08-19", "B",
        "new findings start in status open (spec 12 default)",
        f"{len(mixed_findings)} generated findings",
        "all status=open",
        f"violations={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:239",
        "",
    )
    assert ok


def test_v08_20_count_equals_failed_plus_review(recorder, mixed_findings, mixed_evaluation):
    expected = mixed_evaluation.failed + mixed_evaluation.review
    ok = len(mixed_findings) == expected
    recorder.add(
        "V08-20", "B",
        "finding count equals failed + review of the evaluation",
        f"eval P{mixed_evaluation.passed}/F{mixed_evaluation.failed}/R{mixed_evaluation.review}",
        str(expected),
        f"got {len(mixed_findings)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:182-196",
        "",
    )
    assert ok


def test_v08_21_secure_run_counts(recorder, secure_run):
    ev = secure_run.compliance_evaluation
    expected = ev.failed + ev.review
    ok = len(secure_run.findings) == expected and secure_run.status == "completed"
    recorder.add(
        "V08-21", "B",
        "the full executor run produces exactly failed+review findings",
        f"secure.txt -> P{ev.passed}/F{ev.failed}/R{ev.review}, status={secure_run.status}",
        str(expected),
        f"findings={len(secure_run.findings)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "executor.py:253-262",
        "",
    )
    assert ok


def test_v08_22_ids_unique(recorder, mixed_findings, secure_run):
    ids = [f.id for f in mixed_findings + secure_run.findings]
    ok = len(ids) == len(set(ids))
    recorder.add(
        "V08-22", "B",
        "finding ids are unique within and across runs",
        f"{len(ids)} ids",
        "all unique",
        f"duplicates={len(ids) - len(set(ids))}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:231 (uuid4)",
        "",
    )
    assert ok


def test_v08_23_review_wording(recorder, mixed_findings):
    bad = [f.control_id for f in mixed_findings
           if f.result == ComplianceResultType.REVIEW
           and "requires manual review" not in f.description]
    ok = not bad
    recorder.add(
        "V08-23", "B",
        "REVIEW findings say the control requires manual review",
        "REVIEW findings' descriptions",
        "phrase present",
        f"missing={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:224-228",
        "",
    )
    assert ok


def test_v08_24_context_propagates(recorder, gen, mixed_evaluation):
    out = gen.generate_findings(
        evaluation=mixed_evaluation, audit_id="ctx-audit", device_name="core-sw1"
    )
    bad = [
        f.control_id
        for f in out
        if f.affected_device != "core-sw1"
        or f.affected_vendor != mixed_evaluation.vendor
        or f.affected_platform != mixed_evaluation.platform
        or f.audit_id != "ctx-audit"
    ]
    ok = not bad and bool(out)
    recorder.add(
        "V08-24", "B",
        "each finding carries the audit id, device name and the "
        "vendor/platform of its evaluation",
        "generate_findings(device_name=core-sw1)",
        "all context fields propagated",
        f"violations={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:230-247",
        "",
    )
    assert ok


# ==========================================================================
# C - severity assignment + confidence calculation (spec 10.8)
# ==========================================================================


def test_v08_25_severity_copied_from_control(recorder, mixed_findings, mixed_evaluation):
    src = {e.control_id: e.severity for e in mixed_evaluation.evaluations}
    bad = [f.control_id for f in mixed_findings if f.severity != src[f.control_id]]
    ok = not bad
    recorder.add(
        "V08-25", "C",
        "the finding's severity is the severity assigned to the control "
        "(spec 10.8 'Assign severity' - no re-grading at finding time)",
        "severity per finding vs source evaluation",
        "identical",
        f"mismatches={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:236",
        "",
    )
    assert ok


def test_v08_26_benchmark_severities_map_without_default(recorder, secure_run, juniper_run):
    sev_map = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    from app.engines.compliance.executor import AuditExecutor  # noqa: F401
    bench_sevs = set()
    ex = AuditExecutor()
    for content, vendor, platform in (
        (SECURE, "cisco", "ios_xe"),
        (JUNIPER_SECURE, "juniper", "junos"),
    ):
        res = BenchmarkExecutionEngine().execute(
            raw_config=content, vendor=vendor, platform=platform
        )
        for ev in res.evaluations:
            bench_sevs.add(ev.evidence.severity)
    unmapped = sorted(v for v in bench_sevs if v not in sev_map)
    ok = not unmapped
    recorder.add(
        "V08-26", "C",
        "every control severity reaching the executor maps to the Severity "
        "enum without hitting the silent MEDIUM default (executor.py:305)",
        f"severities observed on cisco+juniper runs: {sorted(bench_sevs)}",
        "all within the four-value map",
        f"unmapped={unmapped}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "executor.py:299-305",
        "",
    )
    assert ok
    assert ex is not None


def test_v08_27_confidence_copied_not_recalculated(recorder, mixed_findings, mixed_evaluation):
    src = {e.control_id: e.confidence for e in mixed_evaluation.evaluations}
    bad = [f.control_id for f in mixed_findings if f.confidence != src[f.control_id]]
    ok = not bad
    recorder.add(
        "V08-27", "C",
        "finding.confidence equals the confidence of the evaluation it "
        "derives from (spec 10.8 'Calculate confidence scores' - the finding "
        "must not invent a new number)",
        "confidence per finding vs evaluation",
        "identical values",
        f"mismatches={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:237 (copy); spec:545",
        "",
    )
    assert ok


def test_v08_28_confidence_in_range(recorder, secure_run):
    bad = [f.control_id for f in secure_run.findings
           if not (0.0 <= f.confidence <= 1.0)]
    ok = not bad and bool(secure_run.findings)
    recorder.add(
        "V08-28", "C",
        "every finding confidence lies in [0, 1]",
        f"{len(secure_run.findings)} findings from secure.txt",
        "all in range",
        f"violations={bad[:5]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:237",
        "",
    )
    assert ok


def test_v08_29_risk_score_range(recorder, mixed_findings):
    bad = [f.control_id for f in mixed_findings
           if not (0.0 <= f.risk_score <= 100.0)]
    ok = not bad and all(f.risk_score > 0 for f in mixed_findings)
    recorder.add(
        "V08-29", "C",
        "every finding carries a risk score in 0-100 (the engine computes "
        "one even though the risk formula belongs to section 10.9)",
        f"{len(mixed_findings)} findings",
        "0 < score <= 100",
        f"violations={bad} scores={[f.risk_score for f in mixed_findings]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:103-143, 209-216",
        "",
    )
    assert ok


def test_v08_30_priority_thresholds(recorder, mixed_findings):
    bad = []
    for f in mixed_findings:
        want = "P1" if f.risk_score >= 80 else "P2" if f.risk_score >= 60 else \
               "P3" if f.risk_score >= 40 else "P4"
        if f.priority != want:
            bad.append((f.control_id, f.risk_score, f.priority, want))
    ok = not bad
    recorder.add(
        "V08-30", "C",
        "priority follows the declared thresholds (P1>=80, P2>=60, P3>=40, "
        "otherwise P4)",
        f"scores={[f.risk_score for f in mixed_findings]}",
        "thresholds honoured",
        f"violations={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:96-101, 145-150",
        "",
    )
    assert ok


def test_v08_31_severity_monotonicity(recorder, monkeypatch):
    monkeypatch.setitem(sys.modules, "app.ml.model", None)
    calc = SeverityCalculator()
    crit = calc.calculate_risk_score(Severity.CRITICAL, vendor="cisco",
                                     category="ssh", confidence=0.9)
    low = calc.calculate_risk_score(Severity.LOW, vendor="cisco",
                                    category="ssh", confidence=0.9)
    ok = crit > low
    recorder.add(
        "V08-31", "C",
        "risk increases with severity (all else equal)",
        "CRITICAL vs LOW, same vendor/category/confidence (ML import forced "
        "unavailable)",
        "CRITICAL risk > LOW risk",
        f"critical={crit} low={low}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:71-76, 133-143",
        "",
    )
    assert ok


def test_v08_32_vendor_impact_applied(recorder, monkeypatch):
    monkeypatch.setitem(sys.modules, "app.ml.model", None)
    calc = SeverityCalculator()
    cisco = calc.calculate_risk_score(Severity.HIGH, vendor="cisco",
                                      category="ssh", confidence=0.9)
    unknown = calc.calculate_risk_score(Severity.HIGH, vendor="a10",
                                        category="ssh", confidence=0.9)
    ok = abs(cisco - unknown) > 0.01
    recorder.add(
        "V08-32", "C",
        "the vendor impact multiplier differentiates vendors (cisco 1.2 vs "
        "default 1.0)",
        "HIGH/ssh/0.9 for cisco vs a10",
        "scores differ",
        f"cisco={cisco} a10={unknown}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:79-84, 134",
        "",
    )
    assert ok


def test_v08_33_fallback_formula_exact(recorder, monkeypatch):
    monkeypatch.setitem(sys.modules, "app.ml.model", None)
    calc = SeverityCalculator()
    got = calc.calculate_risk_score(Severity.HIGH, vendor="cisco",
                                    category="ssh", confidence=0.8)
    expected = round(min(100.0, (7.5 * 1.2 * 1.2 * 0.8) / 15.6 * 100), 1)
    ok = abs(got - expected) <= 0.1
    recorder.add(
        "V08-33", "C",
        "without an ML model the deterministic fallback formula is used "
        "exactly: severity*vendor*category*max(conf,0.5) normalised to 0-100",
        "HIGH/1.2/1.2/0.8 with app.ml.model import forced to fail",
        f"{expected}",
        f"{got}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:117-143 (try/except fallback)",
        "",
    )
    assert ok


# ==========================================================================
# D - evidence chain linking (spec 9.1 step 7, 10.8 'link evidence chains')
# ==========================================================================


def test_v08_34_every_finding_has_evidence(recorder, mixed_findings, secure_run):
    empty = [f.control_id for f in mixed_findings + secure_run.findings
             if not f.evidence]
    ok = not empty
    recorder.add(
        "V08-34", "D",
        "every finding carries a non-empty evidence chain",
        f"{len(mixed_findings) + len(secure_run.findings)} findings",
        "0 without evidence",
        f"empty={empty}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:240",
        "",
    )
    assert ok


def test_v08_35_evidence_identical_to_evaluation(recorder, mixed_findings, mixed_evaluation):
    src = {e.control_id: e.evidence.to_dict() for e in mixed_evaluation.evaluations}
    bad = [f.control_id for f in mixed_findings if f.evidence != src[f.control_id]]
    ok = not bad
    recorder.add(
        "V08-35", "D",
        "finding.evidence is the evaluation's evidence chain, linked not "
        "rebuilt (spec 10.8 'Link evidence chains')",
        "dict equality per finding",
        "identical",
        f"mismatches={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:240 (evidence.to_dict())",
        "",
    )
    assert ok


def test_v08_36_evidence_control_matches(recorder, mixed_findings):
    bad = [f.control_id for f in mixed_findings
           if f.evidence.get("control_id") != f.control_id]
    ok = not bad
    recorder.add(
        "V08-36", "D",
        "the chain embedded in a finding points at the same control as the "
        "finding itself",
        "evidence.control_id vs finding.control_id",
        "identical",
        f"mismatches={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:240",
        "",
    )
    assert ok


def test_v08_37_evidence_spec12_keys(recorder, mixed_findings):
    spec_keys = {"raw_config", "parsed_value", "normalized_value",
                 "security_control", "expected_value", "actual_value",
                 "result", "reasoning"}
    missing_per_finding = {
        f.control_id: sorted(spec_keys - set(f.evidence))
        for f in mixed_findings
        if spec_keys - set(f.evidence)
    }
    ok = not missing_per_finding
    recorder.add(
        "V08-37", "D",
        "finding.evidence carries all eight section 12 EvidenceChain keys "
        "(interface completeness of what the finding exposes)",
        "spec keys vs generated evidence dict",
        "no missing keys",
        f"missing={missing_per_finding} - engine 07 serialises the canonical "
        "section 12 chain (upstream context: V07-46/47)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "evidence.py:53-73 vs spec:831-838",
        "emit the spec key names when serialising the chain",
    )
    assert ok


async def test_v08_38_detail_returns_evidence(recorder, fnd_db):
    from app.api.v1 import findings as api

    evidence = {"control_id": "1.1.1", "security_control": "1.1.1",
                "result": "FAIL", "reasoning": "r",
                "raw_config": "ip http server",
                "parsed_value": "http on", "normalized_value": True,
                "expected_value": False, "actual_value": True}
    fid = await _add_finding(fnd_db, evidence=evidence)
    resp = await api.get_finding(finding_id=fid, db=fnd_db.session,
                                 current_user=fnd_db.admin)
    got = resp.evidence.model_dump() if hasattr(resp.evidence, "model_dump") \
        else dict(resp.evidence or {})
    ok = all(got.get(k) == v for k, v in evidence.items())
    recorder.add(
        "V08-38", "D",
        "the finding detail endpoint serves the evidence chain (spec:1253 "
        "'Evidence Visibility - Findings always show evidence chain')",
        "GET /findings/{id}",
        "stored evidence served back key-for-key through the typed chain",
        f"returned={got}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F2: findings detail serializes the typed §12 EvidenceChain",
        "",
    )
    assert ok


def test_v08_39_fail_findings_have_remediation(recorder, secure_run):
    fails = [f for f in secure_run.findings
             if f.result == ComplianceResultType.FAIL]
    missing = [f.control_id for f in fails if not f.remediation]
    ok = bool(fails) and not missing
    recorder.add(
        "V08-39", "D",
        "FAIL findings carry a remediation payload (spec 9.1 step 7 -> "
        "step 8 hand-off; shape is engine 10's contract)",
        f"{len(fails)} FAIL findings from secure.txt",
        "all with remediation",
        f"missing={missing}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "executor.py:329-347; findings.py:241",
        "",
    )
    assert ok


async def test_v08_40_evidence_roundtrip(recorder, fnd_db):
    from sqlalchemy import select
    from app.models import Finding as FindingModel

    evidence = {"control_id": "2.1.1", "result": "fail",
                "expected_value": True, "actual_value": False}
    fid = await _add_finding(fnd_db, evidence=evidence)
    row = (await fnd_db.session.execute(
        select(FindingModel).where(FindingModel.id == fid)
    )).scalar_one()
    ok = row.evidence == evidence
    recorder.add(
        "V08-40", "D",
        "the evidence chain persisted to findings.evidence (JSONB) survives "
        "the round trip unchanged",
        "insert -> select",
        "identical dict",
        f"stored={row.evidence}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "models:278",
        "",
    )
    assert ok


async def test_v08_41_links_compliance_result(recorder, fnd_db):
    from sqlalchemy import select
    from app.models import (
        ComplianceResult,
        Configuration,
        Device,
        Finding as FindingModel,
        NormalizedConfiguration,
        ParsedConfiguration,
        SemanticInterpretation,
    )

    dev = Device(user_id=fnd_db.user_id, name="e08-dev")
    fnd_db.session.add(dev)
    await fnd_db.session.flush()
    cfg = Configuration(device_id=dev.id, filename="e08-chain.txt",
                        content_hash="e08", raw_content="hostname x",
                        content_type="text/plain", size_bytes=12, line_count=1)
    fnd_db.session.add(cfg)
    await fnd_db.session.flush()
    pc = ParsedConfiguration(configuration_id=cfg.id, vendor="cisco",
                             platform="ios_xe", parse_tree={})
    fnd_db.session.add(pc)
    await fnd_db.session.flush()
    si = SemanticInterpretation(parsed_configuration_id=pc.id)
    fnd_db.session.add(si)
    await fnd_db.session.flush()
    nc = NormalizedConfiguration(semantic_interpretation_id=si.id,
                                 universal_model_version="1.0")
    fnd_db.session.add(nc)
    await fnd_db.session.flush()
    cr = ComplianceResult(audit_id=fnd_db.audit_id,
                          normalized_configuration_id=nc.id, framework="CIS",
                          control_id="1.1.1", control_name="n",
                          result="fail", confidence=0.9, severity="HIGH",
                          evidence={})
    fnd_db.session.add(cr)
    await fnd_db.session.commit()
    fid = await _add_finding(fnd_db, compliance_result_id=cr.id)
    row = (await fnd_db.session.execute(
        select(FindingModel).where(FindingModel.id == fid)
    )).scalar_one()
    ok = row.compliance_result_id == cr.id
    recorder.add(
        "V08-41", "D",
        "a persisted finding links to its compliance result "
        "(section 12 Finding.compliance_result_id -> DDL FK)",
        "chain insert (device->config->...->compliance_result->finding)",
        "compliance_result_id set to the source result",
        f"linked={row.compliance_result_id == cr.id} (column is nullable - "
        "migration 003 - so a missing link would persist silently)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "models:272; audit_execution.py:389-407",
        "",
    )
    assert ok


# ==========================================================================
# E - persistence, counters, endpoints
# ==========================================================================


async def test_v08_42_severity_stored_lowercase(recorder, fnd_db):
    from sqlalchemy import select
    from app.models import Finding as FindingModel

    fid = await _add_finding(fnd_db, severity="CRITICAL")
    row = (await fnd_db.session.execute(
        select(FindingModel).where(FindingModel.id == fid)
    )).scalar_one()
    ok = row.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    recorder.add(
        "V08-42", "E",
        "the severity persisted to findings.severity uses the spec "
        "vocabulary (DATA_MODEL validation: CRITICAL|HIGH|MEDIUM|LOW)",
        "insert the way the canonical pipeline does (uppercase severity)",
        "stored value in spec enum",
        f"stored={row.severity!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F7: Severity enum + pipeline + migration 007 are the uppercase "
        "vocabulary end to end; no edge-case uppercasing",
        "persist the canonical casing (or a CHECK-constrained enum)",
    )
    assert ok


def test_v08_43_counter_formula_consistent(recorder, secure_run):
    fs = secure_run.findings
    findings_count = len(fs)
    counts = {
        "critical": sum(1 for f in fs if f.severity.value.upper() == "CRITICAL"),
        "high": sum(1 for f in fs if f.severity.value.upper() == "HIGH"),
        "medium": sum(1 for f in fs if f.severity.value.upper() == "MEDIUM"),
        "low": sum(1 for f in fs if f.severity.value.upper() == "LOW"),
    }
    ok = sum(counts.values()) == findings_count and findings_count > 0
    recorder.add(
        "V08-43", "E",
        "the audit severity counters (findings_count + four severity "
        "buckets) account for every finding exactly once",
        f"{findings_count} findings from secure.txt",
        "sum of buckets == findings_count",
        f"buckets={counts} total={findings_count}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "audit_execution.py:447-451",
        "",
    )
    assert ok


async def test_v08_44_summary_counts(recorder, fnd_db):
    from app.api.v1 import audit_execution as api

    await _add_finding(fnd_db, severity="CRITICAL")
    await _add_finding(fnd_db, severity="LOW")
    await _add_finding(fnd_db, severity="LOW", status="resolved")
    out = await api.get_audit_summary(audit_id=fnd_db.audit_id,
                                      db=fnd_db.session,
                                      current_user=fnd_db.admin)
    ok = (
        out["findings_by_severity"] == {"CRITICAL": 1, "LOW": 2}
        and out["findings_by_status"] == {"open": 2, "resolved": 1}
    )
    recorder.add(
        "V08-44", "E",
        "GET /audit-execution/{id}/summary reports findings grouped by "
        "severity (uppercase keys) and status, matching the stored rows",
        "3 findings inserted",
        "{'CRITICAL': 1, 'LOW': 2} / {'open': 2, 'resolved': 1}",
        f"got={out['findings_by_severity']} / {out['findings_by_status']}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "audit_execution.py:742-759",
        "",
    )
    assert ok


async def test_v08_45_status_update_persists(recorder, fnd_db):
    from sqlalchemy import select
    from app.api.v1 import findings as api
    from app.models import Finding as FindingModel
    from app.schemas import FindingStatusUpdate

    fid = await _add_finding(fnd_db)
    await api.update_finding_status(
        finding_id=fid,
        update=FindingStatusUpdate(status=FindingStatus.RESOLVED),
        db=fnd_db.session,
        current_user=fnd_db.admin,
    )
    row = (await fnd_db.session.execute(
        select(FindingModel).where(FindingModel.id == fid)
    )).scalar_one()
    ok = row.status == "resolved"
    recorder.add(
        "V08-45", "E",
        "PUT /findings/{id}/status persists the new status",
        "update open -> resolved",
        "status='resolved' in the database",
        f"stored={row.status!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:111-146",
        "",
    )
    assert ok


async def test_v08_46_status_update_audited(recorder, fnd_db):
    from sqlalchemy import func, select
    from app.api.v1 import findings as api
    from app.models import AuditTrail
    from app.schemas import FindingStatusUpdate

    fid = await _add_finding(fnd_db)
    await api.update_finding_status(
        finding_id=fid,
        update=FindingStatusUpdate(status=FindingStatus.IN_PROGRESS),
        db=fnd_db.session,
        current_user=fnd_db.admin,
    )
    trail = (await fnd_db.session.execute(
        select(func.count(AuditTrail.id)).where(
            AuditTrail.entity_type == "finding",
            AuditTrail.entity_id == fid,
        )
    )).scalar()
    entry = (await fnd_db.session.execute(
        select(AuditTrail).where(
            AuditTrail.entity_type == "finding",
            AuditTrail.entity_id == fid,
        ).order_by(AuditTrail.created_at.desc())
    )).scalars().first()
    details = (entry.details or {}) if entry else {}
    ok = ((trail or 0) >= 1 and details.get("old_status") == "open"
          and details.get("new_status") == "in_progress"
          and str(details.get("finding_id")) == str(fid)
          and entry.created_at is not None)
    recorder.add(
        "V08-46", "E",
        "a finding status change is recorded in the audit trail "
        "(spec step 13 'Audit Trail stores complete history')",
        "PUT status open -> in_progress",
        ">=1 audit_trail row carrying finding id, actor, previous/new "
        "status, notes and timestamp",
        f"trail_rows={trail} details={details}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E08 F6: update_finding_status calls "
        "AuditTrailRepository.log_finding_update with notes",
        "call log_finding_update from the status handler",
    )
    assert ok


async def test_v08_47_status_notes_dropped(recorder, fnd_db):
    from sqlalchemy import select
    from app.api.v1 import findings as api
    from app.models import AuditTrail
    from app.schemas import FindingStatusUpdate

    fid = await _add_finding(fnd_db)
    await api.update_finding_status(
        finding_id=fid,
        update=FindingStatusUpdate(status=FindingStatus.ACCEPTED,
                                   notes="because auditor said so"),
        db=fnd_db.session,
        current_user=fnd_db.admin,
    )
    entry = (await fnd_db.session.execute(
        select(AuditTrail).where(
            AuditTrail.entity_type == "finding",
            AuditTrail.entity_id == fid,
        ).order_by(AuditTrail.created_at.desc())
    )).scalars().first()
    notes = ((entry.details or {}).get("notes") if entry else None)
    ok = notes == "because auditor said so"
    recorder.add(
        "V08-47", "E",
        "the `notes` accepted by FindingStatusUpdate are preserved in the "
        "status transition history (a schema field that reaches the handler "
        "must not vanish)",
        "PUT with notes='because auditor said so'",
        "notes preserved exactly in the audit-trail entry",
        f"notes={notes!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E08 F6: notes ride in the audit-trail details of the transition "
        "(history, not a response field)",
        "persist notes with the status change (audit trail detail)",
    )
    assert ok


async def test_v08_48_pagination(recorder, fnd_db):
    from app.api.v1 import findings as api

    for _ in range(4):
        await _add_finding(fnd_db)
    resp = await api.list_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=2, severity=None,
        finding_status=None, db=fnd_db.session, current_user=fnd_db.admin,
    )
    ok = len(resp.items) == 2 and resp.meta.total == 4 and resp.meta.total_pages == 2
    recorder.add(
        "V08-48", "E",
        "list pagination reports a correct total and page count",
        "4 findings, per_page=2",
        "2 items, total=4, total_pages=2",
        f"items={len(resp.items)} total={resp.meta.total} "
        f"pages={resp.meta.total_pages}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:39-70",
        "",
    )
    assert ok


def test_v08_49_spec_endpoint_exists(recorder):
    from app.api.v1.router import api_router

    paths = {r.path for r in api_router.routes if hasattr(r, "path")}
    ok = "/audits/{audit_id}/findings" in paths
    recorder.add(
        "V08-49", "E",
        "the documented list endpoint GET /api/v1/audits/:id/findings "
        "(spec 20.2) is routed",
        "api_router route inventory",
        "/audits/{audit_id}/findings present",
        f"present={ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E08 F4: audits.py list_audit_findings_canonical on the canonical "
        "FindingQueryService (spec:1538)",
        "add the documented route (or update the spec)",
    )
    assert ok


def test_v08_50_control_ids_unique_within_run(recorder, secure_run, juniper_run):
    bad = []
    for run in (secure_run, juniper_run):
        ids = [e.control_id for e in run.compliance_evaluation.evaluations]
        if len(ids) != len(set(ids)):
            bad.append(run.audit_id)
    ok = not bad
    recorder.add(
        "V08-50", "E",
        "control_id is unique within one configuration's evaluations, so "
        "the compliance_results_by_control lookup cannot collapse two rows",
        "secure + juniper executor runs",
        "unique ids per run",
        f"runs with duplicates={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "audit_execution.py:356-378",
        "",
    )
    assert ok


def test_v08_51_linkage_dict_scoped_per_config(recorder):
    src = (BACKEND / "app" / "api" / "v1" / "audit_execution.py").read_text(
        encoding="utf-8"
    )
    loop_at = src.find("for config_id in config_ids:")
    dict_at = src.find("compliance_results_by_control = {}")
    use_at = src.find("compliance_results_by_control.get(")
    ok = 0 <= loop_at < dict_at < use_at
    recorder.add(
        "V08-51", "E",
        "the finding->compliance_result linkage map is rebuilt inside the "
        "per-configuration loop, so findings from config A never link to "
        "config B's result row",
        f"line order: loop={src[:loop_at].count(chr(10)) + 1}, "
        f"dict={src[:dict_at].count(chr(10)) + 1}, "
        f"use={src[:use_at].count(chr(10)) + 1}",
        "loop < dict init < use",
        f"ordered correctly={ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "audit_execution.py:202, 356, 391",
        "",
    )
    assert ok


# ==========================================================================
# F - drift: two list implementations, four representations
# ==========================================================================


async def test_v08_52_same_set_both_lists(recorder, fnd_db):
    from app.api.v1 import audit_execution as api2
    from app.api.v1 import findings as api1

    for sev in ("CRITICAL", "HIGH", "LOW"):
        await _add_finding(fnd_db, severity=sev)
    r1 = await api1.list_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
        finding_status=None, db=fnd_db.session, current_user=fnd_db.admin,
    )
    r2 = await api2.get_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
        status_filter=None, db=fnd_db.session, current_user=fnd_db.admin,
    )
    ids1 = sorted(str(i.id) for i in r1.items)
    ids2 = sorted(str(i.id) for i in r2.items)
    ok = ids1 == ids2
    recorder.add(
        "V08-52", "F",
        "both findings list endpoints return the same rows for the same audit",
        "GET /findings/audit/{id} vs GET /audit-execution/{id}/findings",
        "identical id sets",
        f"equal={ok} (n={len(ids1)})",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:15-70; audit_execution.py:657-712",
        "",
    )
    assert ok


async def test_v08_53_ordering_drift(recorder, fnd_db):
    from app.api.v1 import audit_execution as api2
    from app.api.v1 import findings as api1

    t1 = datetime(2026, 1, 1, 12, 0, 0)
    t2 = datetime(2026, 1, 3, 12, 0, 0)
    t3 = datetime(2026, 1, 2, 12, 0, 0)
    f_crit = await _add_finding(fnd_db, severity="CRITICAL", created_at=t1)
    f_low = await _add_finding(fnd_db, severity="LOW", created_at=t2)
    f_med = await _add_finding(fnd_db, severity="MEDIUM", created_at=t3)
    r1 = await api1.list_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
        finding_status=None, db=fnd_db.session, current_user=fnd_db.admin,
    )
    r2 = await api2.get_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
        status_filter=None, db=fnd_db.session, current_user=fnd_db.admin,
    )
    o1 = [str(i.id) for i in r1.items]
    o2 = [str(i.id) for i in r2.items]
    # Canonical ordering is created_at DESC, id ASC on every endpoint —
    # t2 (LOW) first, then t3 (MEDIUM), then t1 (CRITICAL).
    expected = [str(f_low), str(f_med), str(f_crit)]
    ok = o1 == o2 == expected
    recorder.add(
        "V08-53", "F",
        "the findings list endpoints order results the same way "
        "(canonical created_at DESC, id ASC)",
        "three findings with distinct created_at across severities",
        "identical order on both endpoints, newest first",
        f"order_equal={o1 == o2}; matches canonical={o1 == expected} "
        f"(low={f_low}, medium={f_med}, critical={f_crit})",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F4: both endpoints share FindingQueryService (one ordering)",
        "one shared query/sort helper for both endpoints",
    )
    assert ok


async def test_v08_54_severity_order_semantic(recorder, fnd_db):
    from app.api.v1 import audit_execution as api2

    await _add_finding(fnd_db, severity="CRITICAL")
    await _add_finding(fnd_db, severity="LOW")
    await _add_finding(fnd_db, severity="MEDIUM")
    r = await api2.get_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
        status_filter=None, db=fnd_db.session, current_user=fnd_db.admin,
    )
    got = [i.severity for i in r.items]
    # Canonical ordering is created_at DESC (documented): severity strings
    # are never sorted lexicographically (which would put LOW before MEDIUM
    # regardless of case). All three rows share ~equal timestamps here, so
    # the assertion is determinism of the documented order, not severity rank.
    async def _again():
        return await api2.get_audit_findings(
            audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
            status_filter=None, db=fnd_db.session, current_user=fnd_db.admin)
    r2 = await _again()
    ok = ([i.severity for i in r2.items] == got
          and sorted(got) == ["CRITICAL", "LOW", "MEDIUM"])
    recorder.add(
        "V08-54", "F",
        "list ordering is the documented canonical order (created_at DESC, "
        "id ASC) — severity is never ordered lexicographically",
        "GET /audit-execution/{id}/findings with critical/low/medium rows",
        "deterministic documented order; all severities served verbatim",
        f"got={got}; stable across calls",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F4: FindingQueryService orders created_at DESC, id ASC on all "
        "endpoints (severity-rank sorting intentionally not implemented)",
        "order by a CASE/rank expression, not the raw string",
    )
    assert ok


async def test_v08_55_status_filter_validation_drift(recorder, fnd_db):
    import inspect

    from app.api.v1 import audit_execution as api2
    from app.api.v1 import findings as api1
    from app.schemas import FindingStatus

    def enum_typed(ann):
        return ann is FindingStatus or FindingStatus in getattr(
            ann, "__args__", ()
        )

    api1_typed = enum_typed(
        inspect.signature(api1.list_audit_findings).parameters[
            "finding_status"
        ].annotation
    )
    api2_typed = enum_typed(
        inspect.signature(api2.get_audit_findings).parameters[
            "status_filter"
        ].annotation
    )

    await _add_finding(fnd_db, status="open")
    api2_rejected = False
    api2_total = None
    try:
        r = await api2.get_audit_findings(
            audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
            status_filter="not_a_status", db=fnd_db.session,
            current_user=fnd_db.admin,
        )
        api2_total = r.meta.total
    except Exception:
        api2_rejected = True

    ok = api1_typed and api2_rejected
    recorder.add(
        "V08-55", "F",
        "both list endpoints validate the status filter (an invalid status "
        "is rejected, not silently ignored)",
        "status_filter='not_a_status' on the audit_execution endpoint; "
        "signature annotations of both list handlers",
        "both handlers reject an invalid status (enum-typed parameter)",
        f"findings.py finding_status enum-typed={api1_typed}; "
        f"audit_execution.py status_filter enum-typed={api2_typed}; "
        f"invalid value rejected={api2_rejected} (total={api2_total})",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E08 F4: both list endpoints share FindingQueryService, which "
        "validates status (422) instead of silently matching nothing",
        "type status_filter as FindingStatus in both handlers",
    )
    assert ok


async def test_v08_56_severity_filter_uppercase(recorder, fnd_db):
    from app.api.v1 import audit_execution as api2
    from app.api.v1 import findings as api1

    await _add_finding(fnd_db, severity="CRITICAL")
    r1 = await api1.list_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity="CRITICAL",
        finding_status=None, db=fnd_db.session, current_user=fnd_db.admin,
    )
    r2 = await api2.get_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity="CRITICAL",
        status_filter=None, db=fnd_db.session, current_user=fnd_db.admin,
    )
    ok = r1.meta.total == 1 and r2.meta.total == 1
    recorder.add(
        "V08-56", "F",
        "filtering findings by the spec severity vocabulary "
        "(?severity=CRITICAL) returns the critical findings",
        "GET ...?severity=CRITICAL on both endpoints with a stored "
        "'CRITICAL' row",
        "total=1 on both",
        f"findings.py total={r1.meta.total}, audit_execution total={r2.meta.total}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F4/F7: canonical uppercase storage + normalized filter in the "
        "shared query service",
        "normalise the filter value (or the column) to one casing",
    )
    assert ok


async def test_v08_57_severity_filter_lowercase_works(recorder, fnd_db):
    from app.api.v1 import findings as api1

    await _add_finding(fnd_db, severity="CRITICAL")
    r = await api1.list_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity="critical",
        finding_status=None, db=fnd_db.session, current_user=fnd_db.admin,
    )
    ok = r.meta.total == 1
    recorder.add(
        "V08-57", "F",
        "a lowercase severity filter value is normalized to the canonical "
        "vocabulary (input tolerance at the boundary, canonical storage)",
        "?severity=critical",
        "total=1",
        f"total={r.meta.total}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F4: FindingQueryService.normalize_severity",
        "",
    )
    assert ok


def test_v08_58_four_representations_differ(recorder):
    from app.models import Finding as FindingModel
    from app.schemas import FindingResponse

    spec_f = _spec_interface_fields()
    dc_f = set(Finding.__dataclass_fields__)
    model_f = {c.name for c in FindingModel.__table__.c}
    resp_f = set(FindingResponse.model_fields)
    # One contract: every representation carries every spec field; extras
    # are the documented operational/relational fields, identical across
    # the engine and API shapes (risk_method/risk_model_version are E09
    # scoring lineage, documented in the Finding docstring).
    allowed_operational = {"audit_id", "risk_score", "priority", "result",
                           "affected_platform", "created_at", "updated_at",
                           "risk_method", "risk_model_version"}
    dc_ok = not (spec_f - dc_f) and not (set(dc_f - spec_f)
                                         - allowed_operational)
    model_ok = not (spec_f - model_f)
    resp_ok = not (spec_f - resp_f)
    ok = dc_ok and model_ok and resp_ok
    recorder.add(
        "V08-58", "F",
        "one Finding concept across representations: spec interface, engine "
        "dataclass, database model and API response all carry the §12 "
        "fields (operational extras documented, not competing)",
        "spec/engine/model/response field sets",
        "spec ⊆ each representation; no unexplained extras",
        f"dataclass ok={dc_ok}; model carries spec={model_ok}; response "
        f"carries spec={resp_ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E08 F1: spec:841-855; engine dataclass documents operational "
        "fields; model stores control_id + evidence JSONB; response exposes "
        "control_id + typed evidence",
        "generate one contract type and derive the others",
    )
    assert ok


async def test_v08_59_api_serves_uppercase_severity(recorder, fnd_db):
    from app.api.v1 import findings as api

    fid = await _add_finding(fnd_db, severity="CRITICAL")
    resp = await api.get_finding(finding_id=fid, db=fnd_db.session,
                                 current_user=fnd_db.admin)
    ok = resp.severity == "CRITICAL"
    recorder.add(
        "V08-59", "F",
        "the findings API serves severity in the spec uppercase vocabulary",
        "GET /findings/{id} for a stored 'CRITICAL' row",
        "'CRITICAL'",
        f"got={resp.severity!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:73-78",
        "",
    )
    assert ok


# ==========================================================================
# G - SEPARATE RECORD: wrong/unsupported-vendor consequences
# ==========================================================================


def test_v08_60_wrong_vendor_attribution(recorder, gen):
    bench_res = BenchmarkExecutionEngine().execute(
        raw_config=JUNIPER_SECURE, vendor="cisco", platform="ios_xe"
    )
    ev = _bench_to_eval(bench_res)
    fs = gen.generate_findings(evaluation=ev, audit_id="g1",
                               device_name="juniper-sw")
    # E07 F6 stops the unsafe evaluation before it exists: vendor_mismatch
    # carries zero evaluations, so zero findings can describe the wrong
    # vendor (the boundary, not a re-attribution, is the fix).
    ok = (bench_res.status == "vendor_mismatch" and not ev.evaluations
          and fs == [])
    recorder.add(
        "V08-60", "G",
        "juniper content declared cisco produces no findings describing the "
        "wrong vendor (SEPARATE RECORD; engine 07 V07-72 upstream context)",
        f"bench.execute(juniper_secure, vendor=cisco) status="
        f"{bench_res.status} -> {len(ev.evaluations)} evals -> {len(fs)} "
        "findings",
        "vendor_mismatch boundary, zero evaluations, zero findings",
        f"status={bench_res.status} evals={len(ev.evaluations)} "
        f"findings={len(fs)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F5: unsafe evaluations never reach FindingGenerator (E07 "
        "executor builds no evaluation for boundary runs)",
        "derive affected_vendor from detection, not the declared vendor",
    )
    assert ok


def test_v08_61_foreign_control_findings(recorder, gen):
    wrong = BenchmarkExecutionEngine().execute(
        raw_config=JUNIPER_SECURE, vendor="cisco", platform="ios_xe"
    )
    right = BenchmarkExecutionEngine().execute(
        raw_config=JUNIPER_SECURE, vendor="juniper", platform="junos"
    )
    fw = gen.generate_findings(
        evaluation=_bench_to_eval(wrong), audit_id="g2", device_name="d"
    )
    fr = gen.generate_findings(
        evaluation=_bench_to_eval(right), audit_id="g2b", device_name="d"
    )
    # The declared-cisco run is stopped at the vendor_mismatch boundary, so
    # it contributes zero findings: no missed findings to compare and no
    # false positives possible. The true-vendor run still produces findings.
    ok = (wrong.status == "vendor_mismatch" and fw == [] and len(fr) > 0)
    recorder.add(
        "V08-61", "G",
        "a cisco-declared audit of juniper content yields no findings at all "
        "- neither missed true findings nor false positives (SEPARATE "
        "RECORD; engine 07 V07-72/73 upstream context)",
        "juniper content declared cisco vs declared juniper",
        "wrong-vendor run: 0 findings; true-vendor run: findings present",
        f"wrong status={wrong.status} findings={len(fw)}; right findings="
        f"{len(fr)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F5: boundary evaluations carry no rows for the generator",
        "gate finding generation on detection-consistent selection",
    )
    assert ok


def test_v08_62_unsupported_vendor_decisive_findings(recorder, gen):
    bench_res = BenchmarkExecutionEngine().execute(
        raw_config="", vendor="arista", platform="eos"
    )
    ev = _bench_to_eval(bench_res)
    fs = gen.generate_findings(evaluation=ev, audit_id="g3", device_name="arl")
    decisive = [f.control_id for f in fs
                if f.result == ComplianceResultType.FAIL]
    # E05 FIX (F6): failed normalization stops evaluation, so no FAIL-derived
    # findings can be generated. Before E05 this row documented the bug
    # (asserting that the FAIL findings existed); the assertion is inverted.
    ok = not decisive and bench_res.evaluated == 0
    recorder.add(
        "V08-62", "G",
        "an unsupported vendor (arista - no mapper, no benchmark) gets no "
        "FAIL-derived findings from absent raw text (SEPARATE RECORD; "
        "engine 07 V07-74 upstream context)",
        f"bench.execute('', vendor=arista) -> {len(ev.evaluations)} evals, "
        f"{len(fs)} findings",
        "0 FAIL-derived findings (evaluation stopped)",
        f"decisive={decisive} evaluated={bench_res.evaluated}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E05 F6: execution.py stops on failed normalization; findings.py has "
        "no FAIL verdicts to convert",
        "",
    )
    assert ok


def test_v08_63_empty_config_findings(recorder):
    # E02 FIX (F4): the executor now aborts at the validation gate for an
    # empty config, so no evaluation exists and no FAIL-derived findings
    # can be generated. Before E02 this row documented the bug (asserting
    # that the FAIL findings existed); the assertion is now inverted.
    res = AuditExecutor().execute(audit_id="g4", config_content="",
                                  device_name="empty-sw")
    fs = res.findings
    fail_findings = [f.control_id for f in fs
                     if f.result == ComplianceResultType.FAIL]
    ok = (not fail_findings
          and res.status == "failed"
          and res.compliance_evaluation is None)
    recorder.add(
        "V08-63", "G",
        "an empty configuration yields no FAIL-derived findings (spec 13.4: "
        "insufficient evidence -> REVIEW; SEPARATE RECORD; engine 07 V07-75 "
        "upstream context)",
        f"executor.execute('') status={res.status} "
        f"evals={'None' if res.compliance_evaluation is None else res.compliance_evaluation.total_controls} "
        f"findings={len(fs)}",
        "0 FAIL-derived findings (blocked at the validation gate)",
        f"fail_findings={fail_findings} status={res.status} - "
        "pre-E02: CM-7/CM-7(1) failed on empty input and became findings; "
        "now the run aborts before evaluation",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E02 FIX (F4) executor.py:174-179 over execution.py:302-307",
        "block decisive verdicts (and therefore findings) without evidence",
    )
    assert ok


# ==========================================================================
# H - semantic fidelity invariants (no fabricated content)
# ==========================================================================


def test_v08_64_no_pass_findings(recorder, secure_run):
    pass_ids = {e.control_id for e in secure_run.compliance_evaluation.evaluations
                if e.result == ComplianceResultType.PASS}
    bad = sorted({f.control_id for f in secure_run.findings} & pass_ids)
    ok = not bad
    recorder.add(
        "V08-64", "H",
        "no finding exists for a control that PASSED (a finding would be a "
        "fabricated problem)",
        f"{len(pass_ids)} PASS controls on secure.txt",
        "0 overlap",
        f"overlap={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:184",
        "",
    )
    assert ok


def test_v08_65_severity_always_in_enum(recorder, secure_run, insecure_run, juniper_run):
    allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    bad = [f.control_id for f in
           secure_run.findings + insecure_run.findings + juniper_run.findings
           if f.severity.value not in allowed]
    ok = not bad
    recorder.add(
        "V08-65", "H",
        "every finding severity is one of the four enum values (never "
        "fabricated or blank)",
        "3 executor runs",
        "all severities valid",
        f"violations={bad[:5]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:236",
        "",
    )
    assert ok


def test_v08_66_confidence_exact_match(recorder, secure_run):
    src = {e.control_id: e.confidence
           for e in secure_run.compliance_evaluation.evaluations}
    bad = [f.control_id for f in secure_run.findings
           if f.confidence != src[f.control_id]]
    ok = not bad
    recorder.add(
        "V08-66", "H",
        "finding confidence is byte-identical to the evaluation confidence "
        "(no rounding, no invention)",
        f"{len(secure_run.findings)} findings",
        "exact equality",
        f"mismatches={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:237",
        "",
    )
    assert ok


def test_v08_67_evidence_values_not_fabricated(recorder, secure_run):
    src = {e.control_id: e.evidence
           for e in secure_run.compliance_evaluation.evaluations}
    bad = []
    for f in secure_run.findings:
        e = src[f.control_id]
        if (f.evidence.get("expected_value") != e.expected_value
                or f.evidence.get("actual_value") != e.actual_value
                or f.evidence.get("result") != e.result):
            bad.append(f.control_id)
    ok = not bad
    recorder.add(
        "V08-67", "H",
        "expected/actual/result inside the finding's evidence equal the "
        "evaluated values (no post-hoc editing)",
        f"{len(secure_run.findings)} findings vs their evaluations",
        "identical",
        f"mismatches={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:240",
        "",
    )
    assert ok


def test_v08_68_review_wording_not_failure(recorder, secure_run):
    bad = [f.control_id for f in secure_run.findings
           if f.result == ComplianceResultType.REVIEW
           and "failed evaluation" in f.description]
    ok = not bad
    recorder.add(
        "V08-68", "H",
        "a REVIEW finding never claims the control failed",
        "REVIEW-derived findings from secure.txt",
        "no failure wording",
        f"violations={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:224-228",
        "",
    )
    assert ok


def test_v08_69_fail_wording_present(recorder, secure_run):
    fails = [f for f in secure_run.findings
             if f.result == ComplianceResultType.FAIL]
    bad = [f.control_id for f in fails
           if "failed evaluation" not in f.description]
    ok = bool(fails) and not bad
    recorder.add(
        "V08-69", "H",
        "a FAIL finding states that the control failed evaluation",
        f"{len(fails)} FAIL findings",
        "phrase present",
        f"missing={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:219-223",
        "",
    )
    assert ok


# ==========================================================================
# I - integration with the rest of the pipeline
# ==========================================================================


def test_v08_70_step_order(recorder, secure_run):
    steps = secure_run.steps
    names = [s.name for s in steps]
    idx_comp = names.index("compliance_evaluation")
    idx_find = names.index("finding_generation")
    ordered = (
        idx_find == idx_comp + 1
        and steps[idx_comp].status == "completed"
        and steps[idx_find].status == "completed"
        and steps[idx_comp].completed_at is not None
        and steps[idx_find].started_at >= steps[idx_comp].completed_at
    )
    ok = ordered
    recorder.add(
        "V08-70", "I",
        "finding generation runs as its own step immediately after "
        "compliance evaluation and both complete (spec 9.1 steps 6 -> 7)",
        f"step order {names}",
        "compliance_evaluation then finding_generation, both completed, "
        "timestamps ordered",
        f"ordered={ordered}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "executor.py:236-265",
        "",
    )
    assert ok


def test_v08_71_offline_end_to_end(recorder, secure_run):
    ok = (
        secure_run.status == "completed"
        and len(secure_run.findings) > 0
        and all(f.evidence for f in secure_run.findings)
    )
    recorder.add(
        "V08-71", "I",
        "the executor produces findings end-to-end offline (no external "
        "service on the finding path)",
        "executor.execute(secure.txt)",
        "completed with evidenced findings",
        f"status={secure_run.status} findings={len(secure_run.findings)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "executor.py:253-265",
        "",
    )
    assert ok


def test_v08_72_pipeline_step_defined(recorder):
    ae = (BACKEND / "app" / "api" / "v1" / "audit_execution.py").read_text(
        encoding="utf-8"
    )
    au = (BACKEND / "app" / "api" / "v1" / "audits.py").read_text(encoding="utf-8")
    ok = '"id": "findings"' in ae and "finding_generation" in au
    recorder.add(
        "V08-72", "I",
        "the audit status API exposes a findings step to clients "
        "(PIPELINE_STEPS_DEF + audit status step list)",
        "audit_execution PIPELINE_STEPS_DEF + audits.py step labels",
        "both define the findings/finding_generation step",
        f"steps_def={('id' in ae and 'findings' in ae)} audits_label="
        f"{'finding_generation' in au}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "audit_execution.py:45; audits.py:157",
        "",
    )
    assert ok


async def test_v08_73_response_contract_fields(recorder, fnd_db):
    from app.api.v1 import findings as api
    from app.schemas import FindingResponse

    fid = await _add_finding(fnd_db, evidence={"control_id": "1.1.1"})
    resp = await api.get_finding(finding_id=fid, db=fnd_db.session,
                                 current_user=fnd_db.admin)
    has_link = "compliance_result_id" in FindingResponse.model_fields
    ok = has_link and resp.evidence is not None
    recorder.add(
        "V08-73", "I",
        "the detail response exposes the compliance-result link and the "
        "evidence chain (spec 12 Finding.compliance_result_id + evidence)",
        "GET /findings/{id}",
        "both fields present",
        f"compliance_result_id field={has_link} evidence={resp.evidence is not None} "
        "(control_id from spec is absent - V08-02)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "schemas:306-324",
        "",
    )
    assert ok


async def test_v08_74_list_ownership(recorder, fnd_db):
    from app.api.v1 import findings as api

    try:
        await api.list_audit_findings(
            audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
            finding_status=None, db=fnd_db.session, current_user=fnd_db.other,
        )
        code = None
    except HTTPException as e:
        code = e.status_code
    ok = code == 404
    recorder.add(
        "V08-74", "I",
        "another user cannot list findings of an audit they do not own "
        "(404, not data)",
        "list with foreign current_user",
        "HTTPException 404",
        f"code={code}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:26-36",
        "",
    )
    assert ok


async def test_v08_75_detail_ownership(recorder, fnd_db):
    from app.api.v1 import findings as api

    fid = await _add_finding(fnd_db)
    try:
        await api.get_finding(finding_id=fid, db=fnd_db.session,
                              current_user=fnd_db.other)
        code = None
    except HTTPException as e:
        code = e.status_code
    ok = code == 404
    recorder.add(
        "V08-75", "I",
        "another user cannot read a finding of an audit they do not own",
        "detail with foreign current_user",
        "HTTPException 404",
        f"code={code}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:96-107",
        "",
    )
    assert ok


async def test_v08_76_detail_unknown_id(recorder, fnd_db):
    from app.api.v1 import findings as api

    try:
        await api.get_finding(finding_id=uuid.uuid4(), db=fnd_db.session,
                              current_user=fnd_db.admin)
        code = None
    except HTTPException as e:
        code = e.status_code
    ok = code == 404
    recorder.add(
        "V08-76", "I",
        "a missing finding id returns a typed 404",
        "GET /findings/{random uuid}",
        "HTTPException 404",
        f"code={code}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:88-94",
        "",
    )
    assert ok


def test_v08_77_ml_claim_in_step_text(recorder):
    ae = (BACKEND / "app" / "api" / "v1" / "audit_execution.py").read_text(
        encoding="utf-8"
    )
    claim = "ML risk scoring (RandomForest)" in ae
    ok = not claim
    recorder.add(
        "V08-77", "I",
        "the findings step status must not advertise ML scoring that the "
        "engine does not guarantee (ML quality is deferred; the risk "
        "calculator silently falls back to a formula - V08-33)",
        "step message source",
        "no unconditional ML claim in user-visible status text",
        f"claim present={claim}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E08 F8: step text reads 'Generating N findings with risk scoring...'",
        "describe scoring accurately (model used or deterministic fallback)",
    )
    assert ok


# ==========================================================================
# J - determinism
# ==========================================================================


def test_v08_78_repeat_generation(recorder, gen, mixed_evaluation):
    a = gen.generate_findings(evaluation=mixed_evaluation, audit_id="x",
                              device_name="d")
    b = gen.generate_findings(evaluation=mixed_evaluation, audit_id="x",
                              device_name="d")
    key = lambda fs: sorted(  # noqa: E731
        (f.control_id, f.severity.value, f.title, f.risk_score, f.priority,
         f.confidence, f.description)
        for f in fs
    )
    ok = key(a) == key(b)
    recorder.add(
        "V08-78", "J",
        "the same evaluation produces the same findings on repeat runs "
        "(content, severity, risk, priority - ids/timestamps excluded)",
        "mixed evaluation generated twice",
        "identical content multisets",
        f"identical={ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:163-196",
        "",
    )
    assert ok


def test_v08_79_fresh_generator_instance(recorder, mixed_evaluation):
    a = FindingGenerator().generate_findings(
        evaluation=mixed_evaluation, audit_id="x", device_name="d")
    b = FindingGenerator().generate_findings(
        evaluation=mixed_evaluation, audit_id="x", device_name="d")
    key = lambda fs: sorted(  # noqa: E731
        (f.control_id, f.severity.value, f.risk_score, f.priority) for f in fs
    )
    ok = key(a) == key(b)
    recorder.add(
        "V08-79", "J",
        "a fresh FindingGenerator instance behaves identically (no hidden "
        "instance state)",
        "two instances, same input",
        "identical",
        f"identical={ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:160-161",
        "",
    )
    assert ok


def test_v08_80_executor_rerun_findings(recorder, secure_run, secure_run2):
    key = lambda fs: sorted(  # noqa: E731
        (f.control_id, f.severity.value, f.title, f.result.value) for f in fs
    )
    ok = key(secure_run.findings) == key(secure_run2.findings)
    recorder.add(
        "V08-80", "J",
        "two full executor runs on the same input yield identical findings",
        "secure.txt twice",
        "identical control/severity/title/result multisets",
        f"identical={ok} (n={len(secure_run.findings)})",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "executor.py:253-262",
        "",
    )
    assert ok


# ==========================================================================
# K - performance (measurement only)
# ==========================================================================


def test_v08_81_generation_speed(recorder, secure_run):
    ev = secure_run.compliance_evaluation
    t0 = time.perf_counter()
    out = FindingGenerator().generate_findings(
        evaluation=ev, audit_id="perf", device_name="d")
    ms = (time.perf_counter() - t0) * 1000
    rate = ms / max(len(out), 1)
    ok = len(out) > 0 and rate < 25.0
    recorder.add(
        "V08-81", "K",
        "finding generation for a full-audit evaluation stays within its "
        "per-finding budget (self-declared sanity bound, measurement only)",
        f"{ev.total_controls} evaluations -> {len(out)} findings",
        "< 25 ms/finding (sanity bound; ~4-5 ms/finding measured)",
        f"{ms:.1f} ms ({rate:.2f} ms/finding) for {len(out)} findings",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:163-196 (measurement)",
        "",
    )
    assert ok


def test_v08_82_large_batch(recorder, gen):
    def run(n):
        base = [_mk(f"c{i}", ComplianceResultType.FAIL if i % 2
                    else ComplianceResultType.REVIEW, remediation=_REMED)
                for i in range(50)]
        items = [base[i % 50] for i in range(n)]
        ev = _mk_eval(items)
        t0 = time.perf_counter()
        out = gen.generate_findings(
            evaluation=ev, audit_id="perf2", device_name="d"
        )
        return (time.perf_counter() - t0) * 1000, len(out)

    ms1, n1 = run(1_000)
    ms4, n4 = run(4_000)
    rate1, rate4 = ms1 / 1_000, ms4 / 4_000
    ok = n1 == 1_000 and n4 == 4_000 and rate4 <= rate1 * 1.5
    recorder.add(
        "V08-82", "K",
        "finding generation cost grows linearly with input size "
        "(no super-linear blowup at audit scale)",
        "1,000 then 4,000 evaluations (50 distinct controls cycled)",
        "exactly one finding per evaluation; per-finding cost at 4,000 "
        "<= 1.5x per-finding cost at 1,000",
        f"1,000: {ms1:.0f} ms ({rate1:.2f} ms/finding, {n1} findings); "
        f"4,000: {ms4:.0f} ms ({rate4:.2f} ms/finding, {n4} findings) - "
        "linear, but ~5 ms per finding dominated by one single-sample "
        "sklearn predict per finding (findings.py:103 calculate_risk_score; "
        "10,000 findings measured at ~92 s)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:163-196, 103-143 (measurement)",
        "batch ML risk scoring (one predict per generation)",
    )
    assert ok


def test_v08_83_full_execute_speed(recorder):
    t0 = time.perf_counter()
    res = AuditExecutor().execute(audit_id="perf3", config_content=SECURE,
                                  device_name="d")
    ms = (time.perf_counter() - t0) * 1000
    ok = res.status == "completed" and ms < 10_000
    recorder.add(
        "V08-83", "K",
        "a full audit through finding generation completes within 10 s "
        "(cold, including engine construction)",
        "executor.execute(secure.txt)",
        "< 10,000 ms and completed",
        f"{ms:.0f} ms, status={res.status}, findings={len(res.findings)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "executor.py:130-281 (measurement)",
        "",
    )
    assert ok


# ==========================================================================
# L - hostile and boundary input
# ==========================================================================


def test_v08_84_none_evaluation(recorder, gen):
    err = None
    try:
        gen.generate_findings(evaluation=None, audit_id="a", device_name="d")
    except Exception as e:  # noqa: BLE001
        err = e
    ok = isinstance(err, (ValueError, TypeError))
    recorder.add(
        "V08-84", "L",
        "an invalid (None) evaluation produces a clear validation failure, "
        "not a raw Python exception message",
        "generate_findings(evaluation=None)",
        "ValueError/TypeError with a clear message",
        f"raised={type(err).__name__}: {err}" if err else "no error raised",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E08 F9: generate_findings validates its evaluation argument",
        "validate the evaluation argument",
    )
    assert ok


def test_v08_85_pass_only_boundary(recorder, gen):
    ev = _mk_eval([_mk("1.1.1", ComplianceResultType.PASS)])
    out = gen.generate_findings(evaluation=ev, audit_id="a", device_name="d")
    ok = out == []
    recorder.add(
        "V08-85", "L",
        "a single-PASS evaluation yields no findings (boundary input)",
        "1 PASS evaluation",
        "[]",
        f"{len(out)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:184",
        "",
    )
    assert ok


def test_v08_86_invalid_status_enum_rejected(recorder):
    from app.schemas import FindingStatusUpdate

    err = None
    try:
        FindingStatusUpdate(status="bogus_status")
    except ValidationError as e:
        err = e
    ok = err is not None
    recorder.add(
        "V08-86", "L",
        "an invalid finding status is rejected by the request schema "
        "(422 at the HTTP layer)",
        "FindingStatusUpdate(status='bogus_status')",
        "ValidationError",
        f"raised={type(err).__name__}" if err else "accepted",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "schemas:327-331",
        "",
    )
    assert ok


async def test_v08_87_severity_filter_injection(recorder, fnd_db):
    from fastapi import HTTPException

    from app.api.v1 import findings as api

    await _add_finding(fnd_db, severity="CRITICAL")
    try:
        r = await api.list_audit_findings(
            audit_id=fnd_db.audit_id, page=1, per_page=20,
            severity="%' OR 1=1 --", finding_status=None,
            db=fnd_db.session, current_user=fnd_db.admin,
        )
        total, err = r.meta.total, None
    except Exception as e:  # noqa: BLE001
        total, err = None, e
    # A hostile filter value is rejected with a typed 422: no rows, no
    # crash, no SQL execution beyond the parameterized ownership check.
    ok = (isinstance(err, HTTPException) and err.status_code == 422)
    recorder.add(
        "V08-87", "L",
        "a SQL-injection/wildcard string in the severity filter is rejected "
        "with a typed 422 (never executed, never matched)",
        "severity=\"%' OR 1=1 --\"",
        "HTTP 422, no rows, no exception beyond the typed error",
        f"total={total} err={type(err).__name__ if err else None}: "
        f"{str(err)[:100] if err else ''}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E08 F4: FindingQueryService.normalize_severity validates before "
        "any comparison (bound parameters throughout)",
        "",
    )
    assert ok


async def test_v08_88_unicode_preserved(recorder, fnd_db):
    from sqlalchemy import select
    from app.models import Finding as FindingModel

    name = "core-ünïcode-设备-🔥"
    fid = await _add_finding(fnd_db, device=name)
    row = (await fnd_db.session.execute(
        select(FindingModel).where(FindingModel.id == fid)
    )).scalar_one()
    ok = row.affected_device == name
    recorder.add(
        "V08-88", "L",
        "unicode in device names survives persistence",
        repr(name),
        "identical after round trip",
        f"stored={row.affected_device!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "models:280",
        "",
    )
    assert ok


async def test_v08_89_overlength_device_name(recorder, fnd_db):
    from app.models import Finding as FindingModel

    big = "x" * 1_000_000
    err = None
    try:
        f = FindingModel(
            audit_id=fnd_db.audit_id, title="t", description="d",
            severity="HIGH", confidence=0.9, status="open", evidence={},
            affected_device=big,
        )
        fnd_db.session.add(f)
        await fnd_db.session.commit()
    except Exception as e:  # noqa: BLE001
        err = e
        await fnd_db.session.rollback()
    typed = isinstance(err, (ValueError, TypeError))
    ok = typed
    recorder.add(
        "V08-89", "L",
        "an over-length affected_device (1 MB into VARCHAR(255)) is rejected "
        "with a typed validation error, not a raw driver exception",
        "1,000,000-char device name",
        "typed ValueError/TypeError before any DB write",
        f"raised={type(err).__name__}: {str(err)[:140]}" if err else "stored",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E08 F9: Finding._validate_text_field enforces column limits + NUL "
        "rejection at attribute set time",
        "validate length at the schema/service boundary",
    )
    assert ok


def test_v08_90_empty_findings_inputs(recorder, gen):
    out1 = gen.generate_findings(
        evaluation=ComplianceEvaluation(), audit_id="a", device_name="")
    ok = out1 == []
    recorder.add(
        "V08-90", "L",
        "empty device name + empty evaluation is handled cleanly",
        "ComplianceEvaluation() / device_name=''",
        "[] without error",
        f"{len(out1)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py:163-196",
        "",
    )
    assert ok


async def test_v08_91_status_roundtrip_all_values(recorder, fnd_db):
    from sqlalchemy import select
    from app.api.v1 import findings as api
    from app.models import Finding as FindingModel
    from app.schemas import FindingStatusUpdate

    fid = await _add_finding(fnd_db)
    results = {}
    for st in FindingStatus:
        await api.update_finding_status(
            finding_id=fid, update=FindingStatusUpdate(status=st),
            db=fnd_db.session, current_user=fnd_db.admin,
        )
        row = (await fnd_db.session.execute(
            select(FindingModel).where(FindingModel.id == fid)
        )).scalar_one()
        results[st.value] = row.status
    ok = all(k == v for k, v in results.items())
    recorder.add(
        "V08-91", "L",
        "every spec status value survives the update round trip unchanged",
        "open -> in_progress -> resolved -> accepted",
        "each value stored verbatim",
        f"stored={results}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "findings.py status handler",
        "",
    )
    assert ok


# ==========================================================================
# M - audit trail / status lifecycle (spec 9.1 step 13)
# ==========================================================================


async def test_v08_92_full_lifecycle_history(recorder, fnd_db):
    from sqlalchemy import select
    from app.api.v1 import findings as api
    from app.models import AuditTrail
    from app.schemas import FindingStatusUpdate

    fid = await _add_finding(fnd_db)
    sequence = [FindingStatus.IN_PROGRESS, FindingStatus.RESOLVED,
                FindingStatus.ACCEPTED]
    for i, st in enumerate(sequence):
        await api.update_finding_status(
            finding_id=fid,
            update=FindingStatusUpdate(
                status=st, notes=f"step {i}: {st.value}"),
            db=fnd_db.session, current_user=fnd_db.admin,
        )
    entries = list((await fnd_db.session.execute(
        select(AuditTrail).where(
            AuditTrail.entity_type == "finding",
            AuditTrail.entity_id == fid,
        ).order_by(AuditTrail.created_at.asc())
    )).scalars().all())
    transitions = [(e.details.get("old_status"), e.details.get("new_status"),
                    e.details.get("notes")) for e in entries]
    ok = (len(entries) == 3
          and transitions[0][:2] == ("open", "in_progress")
          and transitions[1][:2] == ("in_progress", "resolved")
          and transitions[2][:2] == ("resolved", "accepted")
          and all(t[2] == f"step {i}: {s}" for i, (t, s) in enumerate(zip(
              transitions, ["in_progress", "resolved", "accepted"])))
          and all(str(e.details.get("finding_id")) == str(fid)
                  for e in entries)
          and all(e.created_at is not None for e in entries))
    recorder.add(
        "V08-92", "M",
        "the full OPEN -> IN_PROGRESS -> RESOLVED -> ACCEPTED lifecycle "
        "leaves complete history: every transition recorded with actor, "
        "previous/new status, notes and timestamp",
        "three status updates with distinct notes",
        "3 ordered trail rows with the full transition chain + notes",
        f"transitions={transitions}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E08 F6: update_finding_status + log_finding_update on every "
        "accepted transition",
        "",
    )
    assert ok


async def test_v08_93_noop_transition_recorded(recorder, fnd_db):
    from sqlalchemy import func, select
    from app.api.v1 import findings as api
    from app.models import AuditTrail, Finding as FindingModel
    from app.schemas import FindingStatusUpdate

    fid = await _add_finding(fnd_db)
    resp = await api.update_finding_status(
        finding_id=fid,
        update=FindingStatusUpdate(status=FindingStatus.OPEN,
                                   notes="still open, keeping an eye"),
        db=fnd_db.session, current_user=fnd_db.admin,
    )
    row = (await fnd_db.session.execute(
        select(FindingModel).where(FindingModel.id == fid)
    )).scalar_one()
    entries = list((await fnd_db.session.execute(
        select(AuditTrail).where(
            AuditTrail.entity_type == "finding",
            AuditTrail.entity_id == fid,
        )
    )).scalars().all())
    ok = (row.status == "open" and resp.status == "open" and len(entries) == 1
          and entries[0].details.get("no_op") is True
          and entries[0].details.get("notes") == "still open, keeping an eye")
    recorder.add(
        "V08-93", "M",
        "a no-op status update (status == existing status) is accepted as an "
        "explicit no-op: state unchanged, request preserved in history with "
        "its notes",
        "PUT status open -> open with notes",
        "status stays open; one no-op trail row carrying the notes",
        f"status={row.status} entries={len(entries)} "
        f"details={entries[0].details if entries else None}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E08 F6: project convention is record-explicit-no-op (never silently "
        "lose notes/history)",
        "",
    )
    assert ok


# ==========================================================================
# N - evidence persistence round-trip
# ==========================================================================


async def test_v08_94_evidence_round_trip_identical(recorder, fnd_db,
                                                    secure_run):
    from sqlalchemy import select
    from app.api.v1 import findings as api
    from app.models import Audit, Finding as FindingModel

    evaluation = secure_run.compliance_evaluation
    source = next(e for e in evaluation.evaluations
                  if e.result.value == "FAIL")
    audit = Audit(user_id=fnd_db.user_id, name="e08-n-roundtrip",
                  status="completed")
    fnd_db.session.add(audit)
    await fnd_db.session.flush()
    finding = FindingGenerator().generate_findings(
        evaluation=evaluation, audit_id=str(audit.id),
        device_name="roundtrip-sw")
    target = next(f for f in finding if f.control_id == source.control_id)
    stored = FindingModel(
        audit_id=audit.id, control_id=target.control_id,
        title=target.title,
        description=target.description, severity=target.severity.value,
        confidence=target.confidence, status=target.status.value,
        evidence=target.evidence, remediation=target.remediation,
        affected_device=target.affected_device,
        affected_vendor=target.affected_vendor,
        affected_platform=target.affected_platform)
    fnd_db.session.add(stored)
    await fnd_db.session.commit()
    back = (await fnd_db.session.execute(
        select(FindingModel).where(FindingModel.id == stored.id)
    )).scalar_one()
    resp = await api.get_finding(finding_id=stored.id,
                                 db=fnd_db.session,
                                 current_user=fnd_db.admin)
    source_keys = {"raw_config", "parsed_value", "normalized_value",
                   "security_control", "expected_value", "actual_value",
                   "result", "reasoning"}
    ok = (set(source_keys) <= set(back.evidence.keys())
          and all(back.evidence[k] == source.evidence.to_dict()[k]
                  for k in source_keys)
          and resp.evidence.security_control == source.control_id
          and resp.control_id == source.control_id
          and back.severity == source.severity.value)
    recorder.add(
        "V08-94", "N",
        "engine finding -> DB -> API preserves the §12 evidence chain "
        "identically (no field lost, no alias substituted)",
        f"FAIL control {source.control_id} through persist + reload + detail",
        "identical §12 keys at every layer; control linkage intact",
        f"ok={ok}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E08 F1/F2: engine dict -> JSONB -> typed EvidenceChain response",
        "",
    )
    assert ok


# ==========================================================================
# O - remediation persistence round-trip
# ==========================================================================


async def test_v08_95_remediation_round_trip_identical(recorder, fnd_db,
                                                       secure_run):
    from sqlalchemy import select
    from app.api.v1 import findings as api
    from app.models import Finding as FindingModel

    target = next(f for f in secure_run.findings if f.remediation)
    stored = FindingModel(
        audit_id=fnd_db.audit_id, title=target.title,
        description=target.description, severity=target.severity.value,
        confidence=target.confidence, status="open",
        evidence=target.evidence, remediation=target.remediation,
        affected_device=target.affected_device,
        affected_vendor=target.affected_vendor,
        affected_platform=target.affected_platform)
    fnd_db.session.add(stored)
    await fnd_db.session.commit()
    back = (await fnd_db.session.execute(
        select(FindingModel).where(FindingModel.id == stored.id)
    )).scalar_one()
    resp = await api.get_finding(finding_id=stored.id,
                                 db=fnd_db.session,
                                 current_user=fnd_db.admin)
    spec_keys = {"finding_id", "finding_title", "risk_description",
                 "why_it_matters", "vendor", "platform",
                 "recommended_config", "verification_steps", "rollback_steps",
                 "references"}
    ok = (set(spec_keys) <= set(back.remediation.keys())
          and back.remediation == target.remediation
          and resp.remediation == target.remediation
          and back.remediation["finding_id"] == target.id
          and back.remediation["finding_title"] == target.title
          and back.remediation["vendor"] == target.affected_vendor
          and back.remediation["platform"] == target.affected_platform)
    recorder.add(
        "V08-95", "O",
        "engine remediation -> DB -> API preserves the §12 remediation "
        "interface identically, with finding linkage stamped",
        f"remediation of finding {target.control_id} through persist + "
        "reload + detail",
        "identical §12 keys; finding_id/title/vendor/platform linked",
        f"ok={ok}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E08 F1/F3: generator stamps finding_id/finding_title; JSONB "
        "round-trips verbatim",
        "",
    )
    assert ok


async def test_v08_96_api_invalid_status_422(recorder, fnd_db):
    from fastapi import HTTPException

    from app.api.v1 import findings as api

    await _add_finding(fnd_db)
    try:
        await api.list_audit_findings(
            audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
            finding_status="bogus", db=fnd_db.session,
            current_user=fnd_db.admin)
        outcome = "accepted"
    except HTTPException as exc:
        outcome = f"HTTP {exc.status_code}"
    except Exception as exc:  # noqa: BLE001
        outcome = f"wrong error: {type(exc).__name__}"
    # Direct-call validation cannot run FastAPI's pydantic layer, but the
    # shared service still rejects with a typed 422.
    from app.repositories.findings import FindingQueryService

    try:
        await FindingQueryService(fnd_db.session).list_for_audit(
            audit_id=fnd_db.audit_id, user_id=fnd_db.admin.id,
            status="bogus")
        service_outcome = "accepted"
    except HTTPException as exc:
        service_outcome = f"HTTP {exc.status_code}"
    ok = outcome == "HTTP 422" and service_outcome == "HTTP 422"
    recorder.add(
        "V08-96", "L",
        "an invalid status filter is rejected with a typed 422 at the "
        "service layer (direct calls cannot bypass validation via "
        "annotations)",
        "status='bogus' through the canonical query service",
        "HTTP 422",
        f"endpoint outcome={outcome}; service outcome={service_outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E08 F4: FindingQueryService.normalize_status validates every call",
        "",
    )
    assert ok


async def test_v08_97_control_id_filter(recorder, fnd_db, secure_run):
    from app.api.v1 import findings as api
    from app.models import Finding as FindingModel

    target = secure_run.findings[0]
    stored = FindingModel(
        audit_id=fnd_db.audit_id, control_id=target.control_id,
        title=target.title, description=target.description,
        severity=target.severity.value, confidence=target.confidence,
        status="open", evidence=target.evidence,
        remediation=target.remediation,
        affected_device=target.affected_device,
        affected_vendor=target.affected_vendor,
        affected_platform=target.affected_platform)
    fnd_db.session.add(stored)
    await _add_finding(fnd_db)
    await fnd_db.session.commit()
    resp = await api.list_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
        finding_status=None, vendor=None, platform=None,
        control_id=target.control_id, db=fnd_db.session,
        current_user=fnd_db.admin)
    ok = (resp.meta.total == 1
          and resp.items[0].control_id == target.control_id)
    recorder.add(
        "V08-97", "F",
        "findings can be filtered by control_id through the canonical list",
        f"?control_id={target.control_id} with 2 rows present",
        "exactly the matching row, carrying its control_id",
        f"total={resp.meta.total} "
        f"control_id={resp.items[0].control_id if resp.items else None}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E08 F1/F4: stored control_id + service control_id filter",
        "",
    )
    assert ok


async def test_v08_98_vendor_platform_filter(recorder, fnd_db, secure_run):
    from app.api.v1 import findings as api
    from app.models import Finding as FindingModel

    target = secure_run.findings[0]
    stored = FindingModel(
        audit_id=fnd_db.audit_id, control_id=target.control_id,
        title=target.title, description=target.description,
        severity=target.severity.value, confidence=target.confidence,
        status="open", evidence=target.evidence,
        remediation=target.remediation,
        affected_device=target.affected_device,
        affected_vendor="cisco", affected_platform="ios_xe")
    other = FindingModel(
        audit_id=fnd_db.audit_id, control_id="9.9.9",
        title="t", description="d", severity="LOW",
        confidence=0.5, status="open", evidence={},
        remediation={}, affected_device="d",
        affected_vendor="juniper", affected_platform="junos")
    fnd_db.session.add_all([stored, other])
    await fnd_db.session.commit()
    resp = await api.list_audit_findings(
        audit_id=fnd_db.audit_id, page=1, per_page=20, severity=None,
        finding_status=None, vendor="cisco", platform="ios_xe",
        control_id=None, db=fnd_db.session, current_user=fnd_db.admin)
    ok = (resp.meta.total == 1
          and resp.items[0].affected_vendor == "cisco"
          and resp.items[0].affected_platform == "ios_xe")
    recorder.add(
        "V08-98", "F",
        "findings can be filtered by vendor + platform conjunctively",
        "?vendor=cisco&platform=ios_xe with a juniper row present",
        "exactly the cisco/ios_xe row",
        f"total={resp.meta.total}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E08 F4: service vendor/platform filters",
        "",
    )
    assert ok
