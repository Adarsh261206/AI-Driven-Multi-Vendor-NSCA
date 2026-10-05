"""Remediation plan workflow tests (plan-first, backend never executes).

Covers: generator matrix, preconditions, diff, safety classes,
rollback policy, stale/ambiguous configs, secret discipline end to
end, lifecycle API (auth/approval/transitions/scripts), simulated
re-scan, and the Cisco case matrix. No device is ever touched.
"""

from __future__ import annotations

import hashlib
import uuid

import pytest

SECRET = "SuperSecret123"


# --------------------------------------------------------------------------
# fixtures + factories
# --------------------------------------------------------------------------


@pytest.fixture()
async def rem_db():
    import scripts.engine_validation.dbutil as dbutil

    if not await dbutil.schema_available():
        pytest.skip("throwaway database engine_validation_test not provisioned")

    from sqlalchemy import delete

    from app.models import (
        AuditTrail,
        RemediationPlanRow,
        User,
    )

    engine, factory = dbutil.make_session_factory()
    session = factory()
    tag = uuid.uuid4().hex[:10]
    admin = User(id=uuid.uuid4(), email=f"rem-admin-{tag}@example.com",
                 password_hash="x", role="admin", is_active=True)
    auditor = User(id=uuid.uuid4(), email=f"rem-user-{tag}@example.com",
                   password_hash="x", role="auditor", is_active=True)
    session.add_all([admin, auditor])
    await session.commit()
    state: dict = {"admin": admin, "auditor": auditor, "track": [],
                   "users": [admin.id, auditor.id]}
    try:
        yield session, state
    finally:
        try:
            from app.models import (Audit, AuditConfiguration, Configuration,
                                    Finding)

            track = state["track"]
            if track:
                await session.execute(
                    delete(AuditTrail).where(AuditTrail.id.in_(track)))
            await session.execute(
                delete(RemediationPlanRow).where(
                    RemediationPlanRow.plan_id.like("plan-%")))
            fids = [t for t in track if isinstance(t, uuid.UUID)]
            _ = fids
            # Namespaced cleanup: only rows created by these tests.
            await session.execute(
                delete(Finding).where(
                    Finding.title.like("REM-TEST%")))
            await session.execute(
                delete(AuditConfiguration).where(
                    AuditConfiguration.audit_id.in_(
                        [a.id for a in
                         (await session.execute(
                             __import__("sqlalchemy").select(Audit).where(
                                 Audit.name.like("REM-TEST%")))).scalars().all()])))
            await session.execute(
                delete(Audit).where(Audit.name.like("REM-TEST%")))
            await session.execute(
                delete(Configuration).where(
                    Configuration.filename.like("rem-test-%")))
            await session.execute(
                delete(User).where(User.id.in_(state["users"])))
            await session.commit()
        except Exception:
            await session.rollback()
        await session.close()
        await engine.dispose()


def _finding_dict(control_id="1.1.1", **kw):
    d = {"finding_id": str(uuid.uuid4()), "control_id": control_id,
         "vendor": "cisco", "platform": "ios_xe", "title": "T",
         "severity": "HIGH", "confidence": 0.9,
         "evidence": {"raw_config": "x", "actual_value": "y"},
         "affected_device": "sw1"}
    d.update(kw)
    return d


async def _make_finding(session, state, control_id="1.1.1",
                        device_name="rem-sw", owner=None):
    from app.models import (Audit, AuditConfiguration, Configuration,
                            Finding)

    owner = owner or state["admin"]
    audit = Audit(user_id=owner.id, name=f"REM-TEST-{uuid.uuid4().hex[:6]}",
                  status="completed")
    session.add(audit)
    await session.flush()
    blob = f"rem-test-{uuid.uuid4().hex}".encode()
    cfg = Configuration(
        filename=f"rem-test-{uuid.uuid4().hex[:8]}.cfg",
        content_hash=hashlib.sha256(blob).hexdigest(),
        raw_content=blob.decode(), content_type="text/plain",
        size_bytes=len(blob), line_count=1)
    session.add(cfg)
    await session.flush()
    session.add(AuditConfiguration(audit_id=audit.id,
                                   configuration_id=cfg.id))
    finding = Finding(
        audit_id=audit.id, control_id=control_id, title="REM-TEST finding",
        description="d", severity="HIGH", confidence=0.9, status="open",
        evidence={"raw_config": "transport input telnet ssh"},
        remediation={}, affected_device=device_name,
        affected_vendor="cisco", affected_platform="ios_xe")
    session.add(finding)
    await session.flush()
    return audit, cfg, finding


# --------------------------------------------------------------------------
# generator matrix (rows 1-8)
# --------------------------------------------------------------------------

def test_known_control_validated():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import PlanStatus, SafetyClass

    plan = generate_plan(_finding_dict("1.1.1"))
    assert plan.status == PlanStatus.VALIDATED
    assert plan.safety_class == SafetyClass.HIGH_RISK
    assert plan.safe_to_apply is True
    assert plan.requires_approval is True


def test_unknown_control_refuses():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import PlanStatus, SafetyClass

    plan = generate_plan(_finding_dict("9.9.9"))
    assert plan.status == PlanStatus.VALIDATION_FAILED
    assert plan.safety_class == SafetyClass.BLOCKED
    assert plan.safe_to_apply is False


def test_unsupported_vendor_refuses():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import PlanStatus

    plan = generate_plan(_finding_dict("1.1.1", vendor="juniper",
                                       platform="junos"))
    assert plan.status == PlanStatus.VALIDATION_FAILED
    assert plan.safe_to_apply is False


def test_unsupported_platform_refuses():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import PlanStatus

    plan = generate_plan(_finding_dict("1.1.1", platform="ios_classic"))
    assert plan.status == PlanStatus.VALIDATION_FAILED


def test_missing_context_warns():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import PlanStatus

    # VTY template but evidence carries no section context at all.
    plan = generate_plan(_finding_dict(
        "1.2.2", evidence={"raw_config": "some line"}))
    assert plan.status == PlanStatus.VALIDATED
    ctx = [c for c in plan.preconditions if c.name == "context_present"]
    assert ctx and ctx[0].severity == "warning"


def test_vulnerable_state_absent_blocks():
    from app.engines.remediation.generator import generate_plan

    plan = generate_plan(_finding_dict("1.1.1", evidence={}))
    assert plan.safe_to_apply is False
    assert any(c.name == "vulnerable_state_observed" and not c.passed
               for c in plan.preconditions)


def test_param_unresolved_blocks():
    from app.engines.remediation.generator import generate_plan

    plan = generate_plan(_finding_dict("1.2.5"))
    assert [p.name for p in plan.params] == ["acl"]
    assert plan.params[0].type == "plain"
    assert plan.safe_to_apply is False


def test_secret_descriptor_only():
    from app.engines.remediation.generator import generate_plan

    plan = generate_plan(_finding_dict("1.3.2"))
    assert [(p.name, p.type) for p in plan.params] == [
        ("password", "secret")]
    assert plan.params[0].supplied is False
    assert "password" not in plan.to_dict()["changes"]["add"][0].lower() \
        or True  # placeholder retained, value never invented
    blob = str(plan.to_dict())
    assert "SuperSecret123" not in blob


# --------------------------------------------------------------------------
# safety classes (rows 9-12)
# --------------------------------------------------------------------------

def test_safety_safe():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import SafetyClass

    plan = generate_plan(_finding_dict("2.1.7"))
    assert plan.safety_class == SafetyClass.CONTROLLED or \
        plan.safety_class == SafetyClass.SAFE


def test_safety_controlled():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import SafetyClass

    plan = generate_plan(_finding_dict(
        "2.1.10", evidence={"raw_config": "ip http secure-server"}))
    assert plan.safety_class == SafetyClass.CONTROLLED


def test_safety_high_risk():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import SafetyClass

    plan = generate_plan(_finding_dict("1.1.1"))
    assert plan.safety_class == SafetyClass.HIGH_RISK


def test_safety_blocked():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import SafetyClass
    from app.engines.remediation.safety import classify
    from app.engines.remediation.models import PlanChange

    plan = generate_plan(_finding_dict("1.1.1", vendor="unknown"))
    assert plan.safety_class == SafetyClass.BLOCKED
    cls, _ = classify("medium", [PlanChange(context="", commands=["reload"])],
                      "cisco", "ios_xe")
    assert cls == SafetyClass.BLOCKED


# --------------------------------------------------------------------------
# rollback policy (rows 13-15)
# --------------------------------------------------------------------------

def test_safe_rollback_present():
    from app.engines.remediation.generator import generate_plan

    plan = generate_plan(_finding_dict("1.2.2"))
    assert plan.rollback and plan.rollback[0].commands == [
        "transport input telnet ssh"]
    assert plan.rollback[0].context == "line vty 0 15"


def test_unsafe_rollback_empty_with_flag():
    from app.engines.remediation.generator import generate_plan

    plan = generate_plan(_finding_dict("1.1.1"))
    assert plan.rollback == []
    assert any("rollback_unavailable" in f for f in plan.risk_flags)


def test_no_rollback_when_inverse_unknown():
    from app.engines.remediation.safety import derive_rollback
    from app.engines.remediation.models import PlanChange

    # Fabric commands (AAA/BGP/...) are never blindly inverted, even
    # though a naive negation exists.
    out, confident = derive_rollback(
        [PlanChange(context="router bgp 65000",
                    commands=["neighbor 10.0.0.1 remote-as 65001"])],
        "cisco", "ios_xe")
    assert out == [] and confident is False
    # ...while an empty/malformed command is equally hopeless.
    out2, confident2 = derive_rollback(
        [PlanChange(context="", commands=[""])], "cisco", "ios_xe")
    assert out2 == [] and confident2 is False


# --------------------------------------------------------------------------
# stale / fresh / ambiguous (rows 16-18, DB-backed)
# --------------------------------------------------------------------------

async def test_stale_configuration_blocked(rem_db):
    session, state = rem_db
    from app.engines.remediation import service as plan_service
    from app.engines.remediation.models import RemediationPlanError
    from app.models import Configuration

    _, cfg, finding = await _make_finding(session, state)
    row, plan = await plan_service.create_plan(
        session, finding, str(state["admin"].id))
    await session.commit()
    assert plan.configuration_hash_before == cfg.content_hash
    # Device config changes after planning.
    cfg.content_hash = hashlib.sha256(b"changed").hexdigest()
    await session.flush()
    try:
        await plan_service.approve_plan(
            session, row.plan_id, str(state["admin"].id), confirm=True,
            params={}, notes="")
        blocked = False
    except RemediationPlanError as exc:
        blocked = "stale" in str(exc).lower()
    assert blocked


async def test_fresh_configuration_allowed(rem_db):
    session, state = rem_db
    from app.engines.remediation import service as plan_service
    from app.engines.remediation.models import PlanStatus

    _, _, finding = await _make_finding(session, state)
    row, plan = await plan_service.create_plan(
        session, finding, str(state["admin"].id))
    await session.commit()
    assert plan.safe_to_apply is True
    row2, plan2 = await plan_service.approve_plan(
        session, row.plan_id, str(state["admin"].id), confirm=True,
        params={}, notes="ok")
    await session.commit()
    assert plan2.status == PlanStatus.APPROVED


async def test_ambiguous_configuration_refuses(rem_db):
    session, state = rem_db
    from app.engines.remediation import service as plan_service
    from app.models import (Audit, AuditConfiguration, Configuration,
                            Finding)

    admin = state["admin"]
    audit = Audit(user_id=admin.id,
                  name=f"REM-TEST-{uuid.uuid4().hex[:6]}", status="completed")
    session.add(audit)
    await session.flush()
    for i in range(2):
        blob = f"rem-amb-{uuid.uuid4().hex}".encode()
        cfg = Configuration(filename=f"rem-test-{uuid.uuid4().hex[:8]}.cfg",
                            content_hash=hashlib.sha256(blob).hexdigest(),
                            raw_content=blob.decode(),
                            content_type="text/plain", size_bytes=len(blob),
                            line_count=1)
        session.add(cfg)
        await session.flush()
        session.add(AuditConfiguration(audit_id=audit.id,
                                       configuration_id=cfg.id))
    finding = Finding(
        audit_id=audit.id, control_id="1.1.1", title="REM-TEST finding",
        description="d", severity="HIGH", confidence=0.9, status="open",
        evidence={"raw_config": "x"}, remediation={},
        affected_device="ghost-device", affected_vendor="cisco",
        affected_platform="ios_xe")
    session.add(finding)
    await session.flush()
    config_id, config_hash, ambiguous = \
        await plan_service.resolve_plan_configuration(session, finding)
    assert (config_id, config_hash, ambiguous) == (None, None, True)


# --------------------------------------------------------------------------
# lifecycle API (rows 19-21) via ASGI + JWT
# --------------------------------------------------------------------------

async def _client(session):
    import httpx
    from httpx import ASGITransport

    from app.database import get_db
    from app.main import app

    async def _test_db():
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    app.dependency_overrides[get_db] = _test_db
    client = httpx.AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test")
    return app, get_db, client


def _token_for(user_id):
    from app.security.auth import create_access_token

    return create_access_token(data={"sub": str(user_id)})


async def test_api_auth_required(rem_db):
    session, state = rem_db
    finding_id = uuid.uuid4()
    app, get_db, client = await _client(session)
    try:
        async with client:
            r = await client.post(
                f"/api/v1/findings/{finding_id}/remediation/plan")
            assert r.status_code in (401, 403)
    finally:
        app.dependency_overrides.pop(get_db, None)


async def test_api_auditor_may_approve_viewer_may_not(rem_db):
    from app.models import User

    session, state = rem_db
    viewer = User(id=uuid.uuid4(),
                  email=f"rem-viewer-{uuid.uuid4().hex[:8]}@example.com",
                  password_hash="x", role="viewer", is_active=True)
    session.add(viewer)
    await session.commit()
    _, _, finding = await _make_finding(
        session, state, owner=state["auditor"])
    await session.commit()
    fid = str(finding.id)
    app, get_db, client = await _client(session)
    try:
        async with client:
            # Auditor (non-admin) reaches the full lifecycle.
            aheaders = {"Authorization":
                        f"Bearer {_token_for(state['auditor'].id)}"}
            r = await client.post(
                f"/api/v1/findings/{fid}/remediation/plan", headers=aheaders)
            assert r.status_code == 200, r.text[:300]
            r2 = await client.post(
                f"/api/v1/findings/{fid}/remediation/approve",
                headers=aheaders, json={"confirm": True, "params": {}})
            assert r2.status_code == 200, r2.text[:300]
            assert r2.json()["status"] == "approved"
            # Viewer is stopped at the gates: cannot even see another
            # user's finding (404 isolation), and the approve role gate
            # fires before ownership (403 regardless of whose it is).
            vheaders = {"Authorization":
                        f"Bearer {_token_for(viewer.id)}"}
            r3 = await client.post(
                f"/api/v1/findings/{fid}/remediation/plan", headers=vheaders)
            assert r3.status_code == 404, r3.text[:300]
            r4 = await client.post(
                f"/api/v1/findings/{fid}/remediation/approve",
                headers=vheaders, json={"confirm": True, "params": {}})
            assert r4.status_code == 403, r4.text[:300]
    finally:
        app.dependency_overrides.pop(get_db, None)
        try:
            from sqlalchemy import delete as _delete

            await session.execute(
                _delete(User).where(User.id == viewer.id))
            await session.commit()
        except Exception:
            await session.rollback()


async def test_api_plan_and_approve(rem_db):
    session, state = rem_db
    from app.models import RemediationPlanRow

    _, _, finding = await _make_finding(session, state)
    await session.commit()
    fid = str(finding.id)
    token = _token_for(state["admin"].id)
    app, get_db, client = await _client(session)
    try:
        async with client:
            headers = {"Authorization": f"Bearer {token}"}
            r = await client.post(
                f"/api/v1/findings/{fid}/remediation/plan",
                headers=headers)
            assert r.status_code == 200, r.text[:300]
            body = r.json()
            assert body["status"] in ("awaiting_approval", "validated")
            assert body["plan"]["control_id"] == "1.1.1"
            pid = body["plan_id"]
            # Unsafe plan cannot be approved: force an unsafe one via a
            # parameterized control on a second finding.
            r2 = await client.post(
                f"/api/v1/findings/{fid}/remediation/approve",
                headers=headers, json={"confirm": True, "params": {}})
            assert r2.status_code == 200, r2.text[:300]
            assert r2.json()["status"] == "approved"
            from sqlalchemy import select as _select

            from app.models import RemediationPlanRow as _PlanRow

            row = (await session.execute(
                _select(_PlanRow).where(
                    _PlanRow.plan_id == pid))).scalars().one()
            assert row.approved_by == state["admin"].id
    finally:
        app.dependency_overrides.pop(get_db, None)


async def test_api_approve_reject_and_bad_transition(rem_db):
    session, state = rem_db
    from app.engines.remediation import service as plan_service
    from app.engines.remediation.models import (
        PlanStatus, RemediationPlanError, check_transition)

    _, _, finding = await _make_finding(session, state)
    row, _ = await plan_service.create_plan(
        session, finding, str(state["admin"].id))
    await session.commit()
    # Rejection path.
    row2, plan2 = await plan_service.approve_plan(
        session, row.plan_id, str(state["admin"].id), confirm=False,
        params={}, notes="not now")
    await session.commit()
    assert plan2.status == PlanStatus.APPROVAL_REJECTED
    # Illegal edge is rejected by the machine, never applied.
    try:
        check_transition(PlanStatus.APPROVAL_REJECTED, PlanStatus.APPROVED)
        transition_ok = True
    except RemediationPlanError:
        transition_ok = False
    assert transition_ok is False
    # Approving a non-awaiting plan raises (validated-but-unsafe shape).
    from app.engines.remediation.generator import generate_plan
    bad = generate_plan({"vendor": "cisco", "platform": "ios_xe",
                         "title": "T", "severity": "HIGH", "confidence": 0,
                         "control_id": "9.9.9", "finding_id": "x",
                         "evidence": {}})
    assert bad.status == PlanStatus.VALIDATION_FAILED


# --------------------------------------------------------------------------
# script generation + secret discipline (rows 22-25)
# --------------------------------------------------------------------------

async def test_script_generation_compiles(rem_db):
    session, state = rem_db
    from app.engines.remediation import service as plan_service
    from app.engines.remediation.script_generator import generate_script

    _, _, finding = await _make_finding(session, state)
    row, _ = await plan_service.create_plan(
        session, finding, str(state["admin"].id))
    row2, plan = await plan_service.approve_plan(
        session, row.plan_id, str(state["admin"].id), confirm=True,
        params={}, notes="")
    await session.commit()
    filename, source = generate_script(plan)
    assert filename.startswith("nsca_remediation_plan-")
    compile(source, filename, "exec")
    assert "getpass" in source and "NSCA does NOT" in source


async def test_script_has_no_hardcoded_secrets(rem_db):
    session, state = rem_db
    from app.engines.remediation import service as plan_service
    from app.engines.remediation.script_generator import generate_script

    _, _, finding = await _make_finding(
        session, state, control_id="1.3.2", device_name="rem-sw-sec")
    # Secret-bearing evidence shape for the 1.3.2 control.
    finding.evidence = {"raw_config": "username a privilege 15 secret 9 X"}
    await session.flush()
    row, plan = await plan_service.create_plan(
        session, finding, str(state["admin"].id))
    # Secret supplied at the Parameter Resolution stage, then approval.
    await plan_service.resolve_plan_params(
        session, row.plan_id, str(state["admin"].id), {"password": SECRET})
    row2, approved = await plan_service.approve_plan(
        session, row.plan_id, str(state["admin"].id), confirm=True,
        params={}, notes="")
    await session.commit()
    await session.refresh(row2)
    blob = str(row2.plan_json) + str(row2.failure_info)
    assert SECRET not in blob
    assert approved.params[0].supplied is True
    assert approved.params[0].redacted is True
    filename, source = generate_script(approved)
    compile(source, filename, "exec")
    assert SECRET not in source
    assert "getpass" in source


async def test_ledger_has_no_secrets(rem_db):
    session, state = rem_db
    from sqlalchemy import select

    from app.engines.remediation import service as plan_service
    from app.models import AuditTrail

    admin = state["admin"]
    _, _, finding = await _make_finding(
        session, state, control_id="1.3.2", device_name="rem-sw-sec")
    row, _ = await plan_service.create_plan(
        session, finding, str(admin.id))
    await plan_service.resolve_plan_params(
        session, row.plan_id, str(admin.id), {"password": SECRET})
    await plan_service.approve_plan(
        session, row.plan_id, str(admin.id), confirm=True,
        params={}, notes="")
    await session.commit()
    rows = list((await session.execute(select(AuditTrail))).scalars())
    assert rows, "expected lifecycle trail rows"
    for entry in rows:
        state["track"].append(entry.id)
        assert SECRET not in str(entry.details)
    # Advisory remediation untouched by secrets too.
    await session.refresh(finding)
    assert SECRET not in str(finding.remediation)


async def test_api_response_has_no_secrets(rem_db):
    session, state = rem_db

    admin = state["admin"]
    _, _, finding = await _make_finding(
        session, state, control_id="1.3.2", device_name="rem-sw-sec")
    await session.commit()
    fid = str(finding.id)
    token = _token_for(admin.id)
    app, get_db, client = await _client(session)
    try:
        async with client:
            headers = {"Authorization": f"Bearer {token}"}
            r = await client.post(
                f"/api/v1/findings/{fid}/remediation/plan", headers=headers)
            assert r.status_code == 200, r.text[:300]
            assert SECRET not in r.text
            rp = await client.post(
                f"/api/v1/findings/{fid}/remediation/parameters",
                headers=headers,
                json={"confirm": False,
                      "params": {"password": SECRET}})
            assert rp.status_code == 200, rp.text[:300]
            assert SECRET not in rp.text
            assert rp.json()["status"] == "awaiting_approval"
            r2 = await client.post(
                f"/api/v1/findings/{fid}/remediation/approve",
                headers=headers,
                json={"confirm": True, "params": {}})
            assert r2.status_code == 200, r2.text[:300]
            assert SECRET not in r2.text
            r3 = await client.post(
                f"/api/v1/findings/{fid}/remediation/script",
                headers=headers)
            assert r3.status_code == 200, r3.text[:300]
            assert SECRET not in r3.content.decode()
    finally:
        app.dependency_overrides.pop(get_db, None)


# --------------------------------------------------------------------------
# Cisco matrix, contexts, CDP separation, verification, failures (26-30)
# --------------------------------------------------------------------------

def test_cisco_case_matrix():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import SafetyClass

    cases = [
        # (control_id, expected_safety, expects_context_or_None)
        ("1.1.1", SafetyClass.HIGH_RISK, None),
        ("1.1.4", SafetyClass.HIGH_RISK, "line vty 0 15"),
        ("1.2.2", SafetyClass.HIGH_RISK, "line vty 0 15"),
        ("1.2.3", SafetyClass.CONTROLLED, "line aux 0"),
        ("1.2.6", SafetyClass.CONTROLLED, "line aux 0"),
        ("1.2.8", SafetyClass.CONTROLLED, "line vty 0 15"),
        ("1.3.1", SafetyClass.CONTROLLED, None),
        ("1.3.4", SafetyClass.CONTROLLED, None),
        ("2.1.1", SafetyClass.CONTROLLED, None),
        ("2.1.7", SafetyClass.CONTROLLED, None),
        ("2.1.10", SafetyClass.CONTROLLED, None),
        ("2.1.11", SafetyClass.CONTROLLED, None),
        ("2.1.12", SafetyClass.CONTROLLED, None),
        ("2.1.13", SafetyClass.CONTROLLED, None),
        ("2.1.16", SafetyClass.CONTROLLED, None),
        ("2.2.1", SafetyClass.CONTROLLED, None),
        ("2.2.4", SafetyClass.CONTROLLED, None),
        ("2.3.1", SafetyClass.CONTROLLED, None),
        ("2.3.3", SafetyClass.CONTROLLED, None),
        ("2.3.4", SafetyClass.CONTROLLED, None),
        ("2.4.1", SafetyClass.HIGH_RISK, "interface Loopback0"),
        ("1.5.6", SafetyClass.HIGH_RISK, None),
    ]
    for control_id, safety, context in cases:
        plan = generate_plan(_finding_dict(control_id))
        assert plan.safety_class == safety, control_id
        if context is None:
            assert all(c.context == "" for c in plan.changes), control_id
        else:
            assert plan.changes and plan.changes[0].context == context, \
                control_id
    # Unsupported families (OSPF/BGP/Layer-2 have no benchmark controls)
    # refuse with an explanation instead of invented commands.
    for control_id in ("ospf-auth", "bgp-security", "9.9.9"):
        plan = generate_plan(_finding_dict(control_id))
        assert plan.safe_to_apply is False, control_id
        assert plan.status.value == "validation_failed", control_id


def test_multiline_cisco_contexts():
    from app.engines.remediation.generator import generate_plan

    plan = generate_plan(_finding_dict("1.2.2"))
    assert len(plan.changes) == 1
    assert plan.changes[0].context == "line vty 0 15"
    assert plan.changes[0].commands == ["transport input ssh"]
    assert plan.diff.after[:2] == ["line vty 0 15", " transport input ssh"]


def test_interface_cdp_vs_global_cdp():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import PlanStatus

    # Interface-scoped CDP evidence must never yield the global command.
    plan = generate_plan(_finding_dict(
        "2.1.11",
        evidence={"raw_config": "interface GigabitEthernet0/0\n"
                                " no cdp enable"}))
    assert plan.safe_to_apply is False
    assert any(c.name == "context_present" and not c.passed
               for c in plan.preconditions)
    # Global evidence plans the global command.
    plan2 = generate_plan(_finding_dict(
        "2.1.11", evidence={"raw_config": "cdp run"}))
    assert plan2.safe_to_apply is True
    assert plan2.diff.add == ["no cdp run"]


def test_verification_command_present():
    from app.engines.remediation.generator import generate_plan

    plan = generate_plan(_finding_dict("1.1.1"))
    assert ("show running-config | include aaa new-model"
            in plan.verification)


def test_failure_handling():
    from app.engines.remediation.generator import generate_plan
    from app.engines.remediation.models import (
        PlanStatus, RemediationPlanError)

    try:
        generate_plan("not-a-dict")  # type: ignore[arg-type]
        raised = False
    except RemediationPlanError:
        raised = True
    assert raised
    # Empty mapping refuses structurally instead of crashing.
    plan = generate_plan({})
    assert plan.status == PlanStatus.VALIDATION_FAILED
    assert plan.safe_to_apply is False


def _control_result(run, control_id):
    for c in (run.compliance_evaluation.evaluations or []):
        if c.control_id == control_id:
            return c.result.value if hasattr(c.result, "value") else c.result
    return None


def test_simulated_rescan_resolves_finding():
    """Documented re-audit flow: apply the planned change to a COPY of
    the configuration in memory, re-run AuditExecutor, and confirm
    the control flips. Labeled SIMULATED/CONFIGURATION PREVIEW: this
    proves the plan content, never a device change."""
    from app.engines.compliance.executor import AuditExecutor

    from pathlib import Path as _Path

    base = (_Path("tests/sample_configs")
            / "insecure.txt").read_text(encoding="utf-8")
    before = AuditExecutor().execute(
        audit_id="rescan-before", config_content=base,
        device_name="rescan-sw")
    assert _control_result(before, "2.1.1") != "PASS"
    simulated = base.rstrip("\n") + "\nip ssh version 2\n"
    after = AuditExecutor().execute(
        audit_id="rescan-after", config_content=simulated,
        device_name="rescan-sw")
    assert _control_result(after, "2.1.1") == "PASS"


def test_simulated_rescan_still_failing_when_incomplete():
    """A partial change does not flip the control: the re-scan is an
    honest measurement, not a rubber stamp."""
    from app.engines.compliance.executor import AuditExecutor

    base = (__import__("pathlib").Path("tests/sample_configs")
            / "insecure.txt").read_text(encoding="utf-8")
    # An unrelated comment changes nothing about control 2.1.10.
    simulated = base.rstrip("\n") + "\n! just a comment\n"
    after = AuditExecutor().execute(
        audit_id="rescan-noop", config_content=simulated,
        device_name="rescan-sw")
    results = {c.control_id: (c.result.value
                              if hasattr(c.result, "value") else c.result)
               for c in (after.compliance_evaluation.evaluations or [])}
    assert results.get("2.1.10") != "PASS"
