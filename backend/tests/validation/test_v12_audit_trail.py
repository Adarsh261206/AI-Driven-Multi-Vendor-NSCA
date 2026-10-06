"""Engine 12 validation - Audit Trail (spec 10.12).

Every test records one evidence row via the `recorder` fixture (see
tests/validation/conftest.py). Ground rules: no production code is modified;
detector output is never ground truth; category G is the separate, explicitly
labelled record of wrong/unsupported-vendor consequences; statuses report
whether the requirement is met (FAIL = defect present), so defect claims assert
the defect (`assert not ok`) and conformance claims assert `ok`.

Scope:
    app/repositories/audit_trail.py (AuditTrailError, normalize_action,
        normalize_uuid, sanitize_details, log/log_ai_interaction/
        log_compliance_evaluation/log_finding_update/log_audit_event/
        log_mapping_event/get_entries/count_entries)
    app/api/v1/audit_trail.py       (GET /audit-trail query surface)
    app/api/v1/audits.py            (AUDIT_CREATED/CANCELLED)
    app/api/v1/audit_execution.py   (AUDIT_STARTED/COMPLETED/FAILED)
    app/api/v1/configurations.py    (CONFIG_UPLOADED fresh + replay)
    app/api/v1/training.py          (MAPPING_CREATED/UPDATED)
    app/models/__init__.py          (AuditAction vocabulary, AuditTrail row)
    app/schemas/__init__.py         (AuditTrailResponse/ListResponse)

DB-backed rows use the throwaway `engine_validation_test` database via a
namespaced fixture (tracked-id cleanup, no residue). Pure-contract rows
call validators with db=None (validation precedes any session use).
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _row(rec, tid, cat, req, inp, exp, act, ok, cls, ev, recm=""):
    rec.add(tid, cat, req, inp, exp, act, "PASS" if ok else "FAIL", cls, ev, recm)


def _read(rel: str) -> str:
    return (BACKEND / rel).read_text(encoding="utf-8")


@pytest.fixture()
async def trail_db():
    """Session + admin/auditor users; tracked-id teardown (no residue)."""
    import scripts.engine_validation.dbutil as dbutil

    if not await dbutil.schema_available():
        pytest.skip("throwaway database engine_validation_test not provisioned")

    from sqlalchemy import delete

    from app.models import AuditTrail, TrainingMapping, User

    engine, factory = dbutil.make_session_factory()
    session = factory()
    tag = uuid.uuid4().hex[:10]
    admin = User(id=uuid.uuid4(), email=f"e12-admin-{tag}@example.com",
                 password_hash="x", role="admin", is_active=True)
    user = User(id=uuid.uuid4(), email=f"e12-user-{tag}@example.com",
                password_hash="x", role="auditor", is_active=True)
    session.add_all([admin, user])
    await session.commit()
    tracked: list = []
    try:
        yield session, admin, user, tracked
    finally:
        try:
            if tracked:
                await session.execute(
                    delete(AuditTrail).where(AuditTrail.id.in_(tracked)))
            # Backup: any row still pointing at our users (endpoint- or
            # helper-created rows are all tracked, but never leak).
            await session.execute(
                delete(AuditTrail).where(AuditTrail.user_id.in_(
                    [admin.id, user.id])))
            # V12-22 training rows (mapping_versions cascade at the DB).
            await session.execute(
                delete(TrainingMapping).where(
                    TrainingMapping.raw_syntax.like("e12-cmd-%")))
            await session.execute(
                delete(User).where(User.id.in_([admin.id, user.id])))
            await session.commit()
        except Exception:
            await session.rollback()
        await session.close()
        await engine.dispose()


async def _log(session, tracked, **kw):
    from app.repositories.audit_trail import AuditTrailRepository

    entry = await AuditTrailRepository(session).log(**kw)
    tracked.append(entry.id)
    return entry


# --------------------------------------------------------------------------
# A - spec structure (§10.12 responsibilities)
# --------------------------------------------------------------------------


def test_v12_01_boundary_exists(recorder):
    import app.repositories.audit_trail as trail_mod
    from app.repositories.audit_trail import AuditTrailError

    names = ["normalize_action", "normalize_uuid", "sanitize_details",
             "log_audit_event", "log_mapping_event", "count_entries",
             "get_entries", "log_compliance_evaluation",
             "log_finding_update", "log_ai_interaction"]
    ok = (issubclass(AuditTrailError, ValueError)
          and all(callable(getattr(trail_mod.AuditTrailRepository, n, None))
                  for n in names[3:])
          and all(callable(getattr(trail_mod, n, None)) for n in names[:3]))
    _row(recorder, "V12-01", "A",
         "spec 10.12 Audit Trail exists as a named boundary: typed error, "
         "validators, lifecycle/mapping helpers, list + count queries",
         "imports + callability from app.repositories.audit_trail",
         "AuditTrailError(ValueError) + all 10 members callable",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: the repository owns the §10.12 contract",
         "")
    assert ok


def test_v12_02_action_vocabulary_covers_responsibilities(recorder):
    from app.models import AuditAction

    values = {a.value for a in AuditAction}
    lifecycle = {"audit_created", "audit_started", "audit_completed",
                 "audit_failed", "audit_cancelled"}
    config = {"config_uploaded", "config_validated", "config_parsed"}
    results = {"compliance_evaluated", "finding_created", "finding_updated"}
    versions = {"mapping_created", "mapping_confirmed", "mapping_rejected",
                "mapping_updated", "ai_hypothesis_received"}
    ok = (lifecycle <= values and config <= values and results <= values
          and versions <= values)
    _row(recorder, "V12-02", "A",
         "the AuditAction vocabulary covers every §10.12 responsibility "
         "(results, configuration changes, version history, AI inputs/"
         "outputs per AI_ARCHITECTURE)",
         "AuditAction members vs responsibility areas",
         "lifecycle + config + results + version vocabularies present",
         f"lifecycle={lifecycle <= values} config={config <= values} "
         f"results={results <= values} versions={versions <= values}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: 18-action vocabulary (6 emission sites + helpers)",
         "")
    assert ok


def test_v12_03_methods_map_to_responsibilities(recorder):
    src = _read("app/repositories/audit_trail.py")
    mapping = {
        "Store all audit results": "log_compliance_evaluation",
        "Track configuration changes": '"configuration"',
        "Maintain version history": "log_mapping_event",
        "Support audit queries": "count_entries",
    }
    missing = [k for k, v in mapping.items() if v not in src]
    ok = not missing
    _row(recorder, "V12-03", "A",
         "each §10.12 responsibility has an owning repository member",
         "source scan of audit_trail.py",
         "results/config-changes/versions/queries members present",
         f"missing={missing}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: responsibility -> member mapping",
         "")
    assert ok


def test_v12_04_query_endpoint_registered(recorder):
    import app.api.v1.audit_trail as trail_api
    from app.api.v1.router import api_router

    routes = [r.path_format if hasattr(r, "path_format") else r.path
              for r in api_router.routes]
    has_prefix = any("/audit-trail" in p for p in routes)
    ok = callable(trail_api.list_trail_entries) and has_prefix
    _row(recorder, "V12-04", "A",
         "\"Support audit queries\" has an HTTP surface: GET /audit-trail "
         "is registered on the v1 router",
         "router routes + endpoint callable",
         "endpoint exists and /audit-trail is routed",
         f"endpoint={callable(trail_api.list_trail_entries)} "
         f"routed={has_prefix}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: app/api/v1/audit_trail.py + router.py registration",
         "")
    assert ok


def test_v12_05_row_model_holds_history(recorder):
    from app.models import AuditTrail

    cols = {c.name for c in AuditTrail.__table__.columns}
    need = {"id", "action", "entity_type", "entity_id", "user_id",
            "details", "ip_address", "user_agent", "created_at"}
    details_type = str(AuditTrail.__table__.c.details.type)
    ok = need <= cols and "JSONB" in details_type
    _row(recorder, "V12-05", "A",
         "the audit_trail row holds actor/action/entity/details/timestamp "
         "with JSONB details",
         "AuditTrail columns + details type",
         "all 9 columns present, details is JSONB",
         f"missing={sorted(need - cols)} details={details_type}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: models.AuditTrail (+ user FK SET NULL: history survives "
         "user deletion)",
         "")
    assert ok


# --------------------------------------------------------------------------
# B - functional logging contract
# --------------------------------------------------------------------------


async def test_v12_06_full_field_round_trip(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.models import AuditAction

    eid = uuid.uuid4()
    entry = await _log(
        session, tracked, action=AuditAction.COMPLIANCE_EVALUATED,
        entity_type="audit", entity_id=eid,
        user_id=str(admin.id),
        details={"audit_id": str(eid), "total_controls": 10},
        ip_address="10.0.0.1", user_agent="v12-agent")
    await session.flush()
    await session.refresh(entry)
    ok = (entry.action == AuditAction.COMPLIANCE_EVALUATED
          and entry.entity_type == "audit" and entry.entity_id == eid
          and entry.user_id == admin.id
          and entry.details == {"audit_id": str(eid), "total_controls": 10}
          and entry.ip_address == "10.0.0.1"
          and entry.user_agent == "v12-agent"
          and entry.created_at is not None
          and isinstance(entry.id, uuid.UUID))
    _row(recorder, "V12-06", "B",
         "a fully populated entry persists verbatim (action, entity, "
         "actor, details, network metadata, timestamp, UUID id)",
         "log() with every field set",
         "all fields round-trip exactly",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: log() write path",
         "")
    assert ok


async def test_v12_07_defaults_for_absent_fields(recorder, trail_db):
    session, _, _, tracked = trail_db
    from app.models import AuditAction

    entry = await _log(session, tracked,
                       action=AuditAction.AUDIT_STARTED,
                       entity_type="audit")
    await session.flush()
    await session.refresh(entry)
    ok = (entry.details == {} and entry.entity_id is None
          and entry.user_id is None and entry.ip_address is None
          and entry.user_agent is None)
    _row(recorder, "V12-07", "B",
         "absent fields degrade to explicit defaults ({} / NULL), never "
         "to crashes or invented values",
         "log() with only action + entity_type",
         "details={}, ids/metadata NULL",
         f"ok={ok} details={entry.details!r}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: sanitize_details(None)={}; ids/metadata nullable by design",
         "")
    assert ok


def test_v12_08_invalid_actions_are_typed(recorder):
    from app.repositories.audit_trail import (
        AuditTrailError, normalize_action)
    from app.models import AuditAction

    bad = 0
    for action in (None, "nope", 123, b"audit_created", ""):
        try:
            normalize_action(action)
        except AuditTrailError:
            bad += 1
    ok_coerce = (normalize_action("compliance_evaluated")
                 == AuditAction.COMPLIANCE_EVALUATED
                 and normalize_action(AuditAction.AUDIT_CREATED)
                 == AuditAction.AUDIT_CREATED)
    ok = bad == 5 and ok_coerce
    _row(recorder, "V12-08", "B",
         "invalid actions raise AuditTrailError; exact-value strings "
         "coerce to the enum (pre-fix None reached the DB as "
         "IntegrityError)",
         "normalize_action over None/'nope'/123/bytes/empty + coercions",
         "5/5 typed, enum + value-string accepted",
         f"typed={bad}/5 coerce={ok_coerce}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: normalize_action gate in log()/get_entries()",
         "")
    assert ok


def test_v12_09_uuid_inputs_are_typed(recorder):
    from app.repositories.audit_trail import AuditTrailError, normalize_uuid

    good_uuid = uuid.uuid4()
    ok_vals = (normalize_uuid(None, "entity_id") is None
               and normalize_uuid(good_uuid, "entity_id") == good_uuid
               and normalize_uuid(str(good_uuid), "entity_id") == good_uuid)
    bad = 0
    for val in ("zzz", "123", 123, b"x", ["x"]):
        try:
            normalize_uuid(val, "entity_id")
        except AuditTrailError:
            bad += 1
    ok = ok_vals and bad == 5
    _row(recorder, "V12-09", "B",
         "UUID inputs accept None/UUID/exact strings (pre-fix a UUID "
         "object raised AttributeError) and reject the rest typed "
         "(pre-fix ValueError)",
         "normalize_uuid over 3 valid + 5 invalid shapes",
         "valid coerce, 5/5 invalid typed",
         f"valid={ok_vals} typed={bad}/5",
         ok, "CONFIRMED BEHAVIOR",
         "E12: normalize_uuid gate on entity_id/user_id (log + query)",
         "")
    assert ok


def test_v12_10_structural_misuse_is_typed(recorder):
    from app.repositories.audit_trail import (
        AuditTrailError, AuditTrailRepository)

    repo = AuditTrailRepository(None)
    checks = 0
    try:
        repo._checked_entity_type("  ")
    except AuditTrailError:
        checks += 1
    try:
        repo._checked_entity_type("x" * 51)
    except AuditTrailError:
        checks += 1
    try:
        from app.repositories.audit_trail import sanitize_details
        sanitize_details(["x"])
    except AuditTrailError:
        checks += 1
    try:
        from app.repositories.audit_trail import _check_text
        _check_text("ip_address", 123, allow_none=True)
    except AuditTrailError:
        checks += 1
    ok = checks == 4
    _row(recorder, "V12-10", "B",
         "empty/overlong entity_type, non-dict details and non-string "
         "metadata raise AuditTrailError (pre-fix: flush-time DB errors)",
         "4 structural misuses",
         "4/4 typed",
         f"typed={checks}/4",
         ok, "CONFIRMED BEHAVIOR",
         "E12: program-controlled vocabulary is strict; client metadata "
         "truncates instead (V12-29)",
         "")
    assert ok


# --------------------------------------------------------------------------
# C - serialization (the trail never breaks the audited operation)
# --------------------------------------------------------------------------


async def test_v12_11_decimal_confidence_persists(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.models import AuditAction

    # Exact KB-hit shape: training.py passes Numeric confidence straight
    # from the ORM row. Pre-fix this raised StatementError(TypeError) at
    # flush — the audit interaction was LOST.
    entry = await _log(
        session, tracked, action=AuditAction.AI_HYPOTHESIS_RECEIVED,
        entity_type="ai_interaction", user_id=str(admin.id),
        details={"raw_syntax": "ntp server 1.1.1.1", "vendor": "cisco",
                 "platform": "ios",
                 "hypothesis": {"meaning": "upstream NTP",
                                "confidence": Decimal("0.85")},
                 "confidence": Decimal("0.85")})
    await session.flush()
    await session.refresh(entry)
    ok = (entry.details["confidence"] == 0.85
          and entry.details["hypothesis"]["confidence"] == 0.85)
    _row(recorder, "V12-11", "C",
         "Decimal payloads (Numeric confidence from KB rows) persist as "
         "floats instead of aborting the flush",
         "KB-hit details with Decimal('0.85')",
         "stored as 0.85/0.85",
         f"details={entry.details}",
         ok, "CONFIRMED BEHAVIOR",
         "E12 F2: _sanitize_value Decimal->float (live bug, probed "
         "pre-fix as StatementError)",
         "")
    assert ok


async def test_v12_12_exotic_types_sanitized(recorder, trail_db):
    import datetime as dt

    session, _, _, tracked = trail_db
    from app.models import AuditAction

    entry = await _log(
        session, tracked, action=AuditAction.COMPLIANCE_EVALUATED,
        entity_type="audit",
        details={"when": dt.datetime(2026, 1, 1, 12, 0, 0),
                 "day": dt.date(2026, 1, 2),
                 "tags": {"b", "a"},
                 "tup": (1, 2),
                 "en": AuditAction.COMPLIANCE_EVALUATED,
                 "uid": uuid.uuid4(),
                 "blob": b"\xff\xfe hi",
                 "nan": float("nan"),
                 "inf": float("inf"),
                 "nested": {"deep": [Decimal("1.5"), None]}})
    await session.flush()
    await session.refresh(entry)
    d = entry.details
    ok = (d["when"] == "2026-01-01T12:00:00"
          and d["day"] == "2026-01-02" and d["tags"] == ["a", "b"]
          and d["tup"] == [1, 2] and d["en"] == "compliance_evaluated"
          and d["blob"] == "\ufffd\ufffd hi" and d["nan"] == "nan"
          and d["nan"] == "nan"
          and d["inf"] == "inf"
          and d["nested"] == {"deep": [1.5, None]})
    import json as _json
    ok = ok and isinstance(_json.dumps(d), str)
    _row(recorder, "V12-12", "C",
         "datetime/enum/UUID/set/tuple/bytes/non-finite/nested payloads "
         "sanitize to JSONB-safe values (pre-fix: datetime/set/NaN each "
         "aborted the flush)",
         "kitchen-sink details dict",
         "ISO/sorted/value/str forms + re-serializable",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E12 F2: recursive _sanitize_value (sets sorted for stable "
         "history)",
         "")
    assert ok


async def test_v12_13_nul_bytes_stripped(recorder, trail_db):
    session, _, _, tracked = trail_db
    from app.models import AuditAction

    entry = await _log(
        session, tracked, action=AuditAction.COMPLIANCE_EVALUATED,
        entity_type="audit",
        details={"note": "ab\x00cd", "bad\x00key": "v"})
    await session.flush()
    await session.refresh(entry)
    ok = (entry.details == {"note": "abcd", "badkey": "v"}
          and "\x00" not in str(entry.details))
    _row(recorder, "V12-13", "C",
         "NUL bytes are stripped from details values and keys "
         "(pre-fix: asyncpg UntranslatableCharacterError at flush)",
         "details with \\x00 in a value and a key",
         "stored NUL-free",
         f"details={entry.details!r}",
         ok, "CONFIRMED BEHAVIOR",
         "E12 F2: Postgres cannot store NUL — strip, never crash",
         "")
    assert ok


async def test_v12_14_ai_interaction_kb_hit_shape(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    entry = await AuditTrailRepository(session).log_ai_interaction(
        action=AuditAction.AI_HYPOTHESIS_RECEIVED,
        raw_syntax="ip http server",
        vendor="cisco", platform="ios",
        hypothesis={"meaning": "m", "confidence": Decimal("0.7"),
                    "source": "knowledge_base"},
        user_id=str(admin.id),
        confidence=Decimal("0.7"))
    tracked.append(entry.id)
    await session.flush()
    await session.refresh(entry)
    ok = (entry.entity_type == "ai_interaction"
          and entry.details["confidence"] == 0.7
          and entry.details["hypothesis"]["confidence"] == 0.7)
    _row(recorder, "V12-14", "C",
         "the log_ai_interaction helper (training KB-hit path) persists "
         "Decimal confidences end to end",
         "helper call with Decimal hypothesis",
         "ai_interaction row, float confidences",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: helper delegates to sanitizing log()",
         "")
    assert ok


# --------------------------------------------------------------------------
# D - queries
# --------------------------------------------------------------------------


async def test_v12_15_filters_and_count_agree(recorder, trail_db):
    session, admin, user, tracked = trail_db
    from sqlalchemy import select

    from app.models import AuditAction, AuditTrail
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    eid = uuid.uuid4()
    marker = f"e12-{uuid.uuid4().hex[:8]}"
    for i in range(3):
        e = await repo.log(action=AuditAction.FINDING_UPDATED,
                           entity_type="finding", entity_id=eid,
                           user_id=str(admin.id),
                           details={"e12": marker, "i": i})
        tracked.append(e.id)
    e = await repo.log(action=AuditAction.COMPLIANCE_EVALUATED,
                       entity_type="audit", user_id=str(user.id),
                       details={"e12": marker})
    tracked.append(e.id)
    await session.flush()

    by_entity = await repo.get_entries(entity_type="finding",
                                       entity_id=str(eid))
    by_user = await repo.get_entries(user_id=str(user.id))
    by_action = await repo.get_entries(action="finding_updated")
    by_action_enum = await repo.get_entries(
        action=AuditAction.FINDING_UPDATED)
    combo = await repo.get_entries(entity_type="finding",
                                   entity_id=str(eid),
                                   user_id=str(admin.id),
                                   action=AuditAction.FINDING_UPDATED)
    n_count = await repo.count_entries(entity_type="finding",
                                       entity_id=str(eid))
    n_list = len(await repo.get_entries(entity_type="finding",
                                        entity_id=str(eid)))
    ours = [r for r in by_entity
            if (r.details or {}).get("e12") == marker]
    enum_ids = [r.id for r in by_action_enum]
    str_ids = [r.id for r in by_action]
    ok = (len(ours) == 3 and len(by_user) >= 1
          and len(by_action) >= 3 and enum_ids == str_ids
          and len(combo) == 3 and n_count == n_list == 3
          and all(r.entity_id == eid for r in combo))
    # cross-check against a direct ORM query (repo is not its own truth)
    direct = list((await session.execute(select(AuditTrail).where(
        AuditTrail.entity_type == "finding",
        AuditTrail.entity_id == eid))).scalars())
    ok = ok and len(direct) == 3
    _row(recorder, "V12-15", "D",
         "entity/user/action/combined filters return exact sets and "
         "count_entries agrees with get_entries (cross-checked by a "
         "direct ORM query)",
         "3 finding rows + 1 audit row, 6 filter shapes",
         "exact sets; count == len(list) == direct == 3",
         f"ours={len(ours)} combo={len(combo)} count={n_count} "
         f"direct={len(direct)}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: _filter_conditions shared by list + count",
         "")
    assert ok


async def test_v12_16_newest_first(recorder, trail_db):
    import asyncio as _asyncio

    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    marker = f"e12-{uuid.uuid4().hex[:8]}"
    ids = []
    for i in range(3):
        e = await repo.log(action=AuditAction.AUDIT_STARTED,
                           entity_type="audit",
                           user_id=str(admin.id),
                           details={"e12": marker, "seq": i})
        tracked.append(e.id)
        ids.append(e.id)
        await session.flush()
        await _asyncio.sleep(0.01)
    rows = await repo.get_entries(user_id=str(admin.id))
    ours = [r.id for r in rows if (r.details or {}).get("e12") == marker]
    ok = ours == list(reversed(ids))
    _row(recorder, "V12-16", "D",
         "entries serve newest-first (created_at desc)",
         "3 sequential rows, read back",
         "reverse insertion order",
         f"ordered={ours == list(reversed(ids))}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: get_entries order_by created_at desc",
         "")
    assert ok


async def test_v12_17_pagination_is_clamped(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    e = await repo.log(action=AuditAction.AUDIT_STARTED,
                       entity_type="audit", user_id=str(admin.id),
                       details={"e12": "clamp"})
    tracked.append(e.id)
    await session.flush()
    huge = await repo.get_entries(user_id=str(admin.id), limit=99999)
    neg = await repo.get_entries(user_id=str(admin.id), offset=-5)
    zero = await repo.get_entries(user_id=str(admin.id), limit=0)
    one = await repo.get_entries(user_id=str(admin.id), limit=1)
    ok = (len(huge) >= 1 and len(huge) <= 1000 and len(neg) >= 1
          and zero == [] and len(one) == 1)
    _row(recorder, "V12-17", "D",
         "hostile pagination is clamped (limit 99999 bounded, negative "
         "offset treated as 0, limit 0 returns []) instead of 500ing",
         "limit=99999 / offset=-5 / limit=0 / limit=1",
         "bounded results, no errors",
         f"huge={len(huge)} neg={len(neg)} zero={len(zero)} one={len(one)}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: limit clamped to [0, MAX_TRAIL_PAGE=1000], offset >= 0",
         "")
    assert ok


def test_v12_18_query_misuse_is_typed(recorder):
    from app.repositories.audit_trail import (
        AuditTrailError, AuditTrailRepository)
    import asyncio

    repo = AuditTrailRepository(None)  # validation precedes session use
    bad = 0

    async def _probe():
        nonlocal bad
        for fn in (lambda: repo.get_entries(entity_id="zzz"),
                   lambda: repo.get_entries(user_id="zzz"),
                   lambda: repo.get_entries(action="nope"),
                   lambda: repo.get_entries(limit="many")):
            try:
                await fn()
            except AuditTrailError:
                bad += 1

    asyncio.run(_probe())
    ok = bad == 4
    _row(recorder, "V12-18", "D",
         "malformed query filters raise AuditTrailError (pre-fix: bare "
         "ValueError from uuid on the query path)",
         "bad entity_id/user_id/action/limit filters",
         "4/4 typed",
         f"typed={bad}/4",
         ok, "CONFIRMED BEHAVIOR",
         "E12: get_entries validates before executing",
         "")
    assert ok


# --------------------------------------------------------------------------
# E - coverage wiring (results / changes / versions / lifecycle)
# --------------------------------------------------------------------------


def test_v12_19_lifecycle_emissions_wired(recorder):
    audits_src = _read("app/api/v1/audits.py")
    exec_src = _read("app/api/v1/audit_execution.py")
    sites = {
        "AUDIT_CREATED in audits.create_audit":
            "AUDIT_CREATED" in audits_src,
        "AUDIT_CANCELLED in audits.cancel_audit":
            "AUDIT_CANCELLED" in audits_src,
        "AUDIT_STARTED in execute_audit":
            "AUDIT_STARTED" in exec_src,
        "AUDIT_COMPLETED in run_audit_pipeline":
            "AUDIT_COMPLETED" in exec_src,
        "AUDIT_FAILED in run_audit_pipeline":
            "AUDIT_FAILED" in exec_src,
    }
    missing = [k for k, v in sites.items() if not v]
    ok = not missing
    _row(recorder, "V12-19", "E",
         "every audit-lifecycle transition emits its trail event "
         "(pre-fix all five AUDIT_* actions were dead enum values)",
         "emission sites in audits.py + audit_execution.py",
         "created/started/completed/failed/cancelled all wired",
         f"missing={missing}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: log_audit_event at the five lifecycle sites (failure path "
         "best-effort so the trail never masks the pipeline error)",
         "")
    assert ok


def test_v12_20_change_and_version_emissions_wired(recorder):
    cfg_src = _read("app/api/v1/configurations.py")
    tr_src = _read("app/api/v1/training.py")
    sites = {
        "CONFIG_UPLOADED on fresh ingest": cfg_src.count(
            "CONFIG_UPLOADED") >= 2,
        "CONFIG_UPLOADED on idempotent replay":
            '"duplicate": True' in cfg_src,
        "MAPPING_CREATED on create": "MAPPING_CREATED" in tr_src,
        "MAPPING_UPDATED on edit": "MAPPING_UPDATED" in tr_src,
        "edit logs only on real change (version compare)":
            "fresh.version != before.version" in tr_src,
    }
    missing = [k for k, v in sites.items() if not v]
    ok = not missing
    _row(recorder, "V12-20", "E",
         "configuration changes and KB version events emit trail rows "
         "(pre-fix CONFIG_* and MAPPING_UPDATED/CREATED were dead; EDIT "
         "changed versions with no history entry)",
         "emission sites in configurations.py + training.py",
         "upload fresh+replay, mapping create/edit wired; no-op edits "
         "still record nothing",
         f"missing={missing}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: upload logs duplicate-flagged replays (E08 no-op "
         "convention); edit compares versions (E06 F7 no-op convention)",
         "")
    assert ok


async def test_v12_21_helper_action_guards(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import (
        AuditTrailError, AuditTrailRepository)

    repo = AuditTrailRepository(session)
    guards = 0
    try:
        await repo.log_audit_event(action=AuditAction.COMPLIANCE_EVALUATED,
                                   audit_id=str(uuid.uuid4()))
    except AuditTrailError:
        guards += 1
    try:
        await repo.log_mapping_event(action=AuditAction.AUDIT_CREATED,
                                     mapping_id=str(uuid.uuid4()))
    except AuditTrailError:
        guards += 1
    e1 = await repo.log_audit_event(action="audit_completed",
                                    audit_id=str(uuid.uuid4()),
                                    user_id=str(admin.id))
    tracked.append(e1.id)
    e2 = await repo.log_mapping_event(
        action=AuditAction.MAPPING_UPDATED, mapping_id=str(uuid.uuid4()),
        user_id=str(admin.id), details={"version": 3})
    tracked.append(e2.id)
    await session.flush()
    ok = (guards == 2 and e1.entity_type == "audit"
          and e1.action == AuditAction.AUDIT_COMPLETED
          and e2.entity_type == "training_mapping"
          and e2.details == {"mapping_id": str(e2.details["mapping_id"]),
                             "version": 3})
    _row(recorder, "V12-21", "E",
         "lifecycle/mapping helpers reject foreign actions and stamp the "
         "right entity types (string actions coerce)",
         "cross-action calls + valid audit/mapping events",
         "2/2 guards trip; entities audit/training_mapping",
         f"guards={guards}/2 ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: log_audit_event/log_mapping_event vocabulary guards",
         "")
    assert ok


async def test_v12_22_mapping_edit_history_end_to_end(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import AuditTrail
    from app.schemas import TrainingMappingCreate, TrainingMappingUpdate

    created = await api.create_mapping(
        mapping=TrainingMappingCreate(
            vendor="cisco", platform="ios",
            raw_syntax=f"e12-cmd-{uuid.uuid4().hex[:8]}",
            semantic_meaning="m",
            universal_model_path="device.hostname"),
        db=session, current_user=admin)
    await session.flush()
    rows = list((await session.execute(select(AuditTrail).where(
        AuditTrail.entity_type == "training_mapping",
        AuditTrail.entity_id == created.id))).scalars())
    for r in rows:
        tracked.append(r.id)
    created_logged = any(r.action == "mapping_created" for r in rows)

    before_n = len(rows)
    await api.update_mapping(
        mapping_id=created.id,
        mapping_update=TrainingMappingUpdate(
            semantic_meaning="m2", change_reason="e12-test"),
        db=session, current_user=admin)
    await session.flush()
    rows2 = list((await session.execute(select(AuditTrail).where(
        AuditTrail.entity_type == "training_mapping",
        AuditTrail.entity_id == created.id))).scalars())
    for r in rows2:
        if r.id not in tracked:
            tracked.append(r.id)
    edited_logged = any(r.action == "mapping_updated" for r in rows2)

    # No-op edit records nothing (E06 F7 convention preserved).
    await api.update_mapping(
        mapping_id=created.id,
        mapping_update=TrainingMappingUpdate(semantic_meaning="m2"),
        db=session, current_user=admin)
    await session.flush()
    rows3 = list((await session.execute(select(AuditTrail).where(
        AuditTrail.entity_type == "training_mapping",
        AuditTrail.entity_id == created.id))).scalars())
    ok = (created_logged and len(rows2) == before_n + 1 and edited_logged
          and len(rows3) == len(rows2))
    _row(recorder, "V12-22", "E",
         "mapping create/edit flows write version history to the trail; "
         "a no-op edit writes nothing",
         "create -> real edit -> no-op edit via training endpoints",
         "mapping_created + exactly one mapping_updated; no-op silent",
         f"created={created_logged} after_edit={len(rows2)} "
         f"after_noop={len(rows3)}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: MAPPING_CREATED (create) + version-compared MAPPING_UPDATED "
         "(edit)",
         "")
    assert ok


# --------------------------------------------------------------------------
# F - determinism
# --------------------------------------------------------------------------


def test_v12_23_sanitize_is_deterministic(recorder):
    from app.repositories.audit_trail import sanitize_details

    payload = {"s": {3, 1, 2}, "d": {"b": 1, "a": [Decimal("0.1"), None]},
               "n": "x\x00y"}
    outs = [sanitize_details(payload) for _ in range(3)]
    ok = outs[0] == outs[1] == outs[2] and outs[0]["s"] == [1, 2, 3]
    _row(recorder, "V12-23", "F",
         "sanitization is deterministic (sets sort; repeated calls agree)",
         "same payload sanitized 3x",
         "identical outputs, sets sorted",
         f"stable={outs[0] == outs[1] == outs[2]}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: pure function, no clock/randomness; set order normalized",
         "")
    assert ok


async def test_v12_24_ids_unique_query_sets_stable(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    marker = f"e12-{uuid.uuid4().hex[:8]}"
    ids = set()
    for _ in range(3):
        e = await repo.log(action=AuditAction.AUDIT_STARTED,
                           entity_type="audit", user_id=str(admin.id),
                           details={"e12": marker})
        tracked.append(e.id)
        ids.add(e.id)
    await session.flush()
    first = {r.id for r in await repo.get_entries(user_id=str(admin.id))
             if (r.details or {}).get("e12") == marker}
    second = {r.id for r in await repo.get_entries(user_id=str(admin.id))
              if (r.details or {}).get("e12") == marker}
    ok = len(ids) == 3 and first == second == ids
    _row(recorder, "V12-24", "F",
         "entry ids are unique per call and repeated queries return the "
         "same set (order-by ties compared as sets)",
         "3 rows, queried twice",
         "3 unique ids, stable sets",
         f"unique={len(ids) == 3} stable={first == second == ids}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: uuid4 ids; set-based determinism assertion",
         "")
    assert ok


# --------------------------------------------------------------------------
# G - wrong/unsupported vendors (separate record)
# --------------------------------------------------------------------------


async def test_v12_25_unknown_vendor_lifecycle_persists(recorder, trail_db):
    session, _, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    aid = str(uuid.uuid4())
    e = await repo.log_audit_event(
        action=AuditAction.AUDIT_COMPLETED, audit_id=aid,
        details={"vendor": "unknown", "detection": "none"})
    tracked.append(e.id)
    await session.flush()
    rows = await repo.get_entries(entity_type="audit", entity_id=aid)
    ok = (len(rows) == 1
          and rows[0].details["vendor"] == "unknown")
    _row(recorder, "V12-25", "G",
         "audits the detector could not identify still leave complete "
         "lifecycle history (labeled unknown, never blocked)",
         "lifecycle event with vendor=unknown",
         "persisted + queryable with the label intact",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "G record: unsupported vendors flow through history, not around it",
         "")
    assert ok


async def test_v12_26_hostile_details_round_trip(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.models import AuditAction

    hostile = ("<script>alert(1)</script> & \"quotes\" 'squiggles' "
               "café \U0001F525 <b>bold</b>")
    entry = await _log(
        session, tracked, action=AuditAction.FINDING_UPDATED,
        entity_type="finding", entity_id=uuid.uuid4(),
        user_id=str(admin.id),
        details={"notes": hostile, "raw": hostile})
    await session.flush()
    await session.refresh(entry)
    ok = (entry.details["notes"] == hostile
          and entry.details["raw"] == hostile)
    _row(recorder, "V12-26", "G",
         "hostile text in history (markup, entities, unicode, emoji) "
         "round-trips verbatim — the trail stores evidence, it does not "
         "interpret it",
         "script/unicode/emoji payload in details",
         "byte-identical on read-back",
         f"verbatim={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "G record: JSONB storage is injection-inert (rendering layers "
         "escape per E11)",
         "")
    assert ok


async def test_v12_27_endpoint_scoping(recorder, trail_db):
    session, admin, user, tracked = trail_db
    from types import SimpleNamespace

    from app.api.v1.audit_trail import list_trail_entries
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    for owner in (admin, user):
        e = await repo.log(action=AuditAction.AUDIT_STARTED,
                           entity_type="audit",
                           user_id=str(owner.id),
                           details={"e12": "scope"})
        tracked.append(e.id)
    await session.flush()

    as_user = await list_trail_entries(
        page=1, per_page=100, entity_type=None, entity_id=None,
        action=None, db=session,
        current_user=SimpleNamespace(id=user.id, role="auditor"))
    as_admin = await list_trail_entries(
        page=1, per_page=100, entity_type=None, entity_id=None,
        action=None, db=session,
        current_user=SimpleNamespace(id=admin.id, role="admin"))
    user_ids_seen = {i.user_id for i in as_user.items}
    admin_sees_user = any(i.user_id == user.id for i in as_admin.items)
    admin_sees_admin = any(i.user_id == admin.id for i in as_admin.items)
    ok = (user_ids_seen == {user.id} and admin_sees_user
          and admin_sees_admin and as_user.meta.total >= 1)
    _row(recorder, "V12-27", "G",
         "non-admin callers see only their own entries; admins see all "
         "(per-row user_id scoping, not just documentation)",
         "admin + auditor rows, queried as each",
         "auditor sees 1 user_id; admin sees both",
         f"user_scope={user_ids_seen == {user.id}} "
         f"admin_sees_both={admin_sees_user and admin_sees_admin}",
         ok, "CONFIRMED BEHAVIOR",
         "G record: history is per-actor isolated (admin override for "
         "audit duty)",
         "")
    assert ok


# --------------------------------------------------------------------------
# H - hostile and boundary input
# --------------------------------------------------------------------------


async def test_v12_28_megabyte_details(recorder, trail_db):
    import time as _time

    session, admin, _, tracked = trail_db
    from app.models import AuditAction

    big = "R" * (1024 * 1024)
    start = _time.perf_counter()
    entry = await _log(session, tracked,
                       action=AuditAction.COMPLIANCE_EVALUATED,
                       entity_type="audit", user_id=str(admin.id),
                       details={"blob": big})
    await session.flush()
    elapsed = _time.perf_counter() - start
    await session.refresh(entry)
    ok = entry.details["blob"] == big and elapsed < 30
    _row(recorder, "V12-28", "H",
         "a 1 MB details payload persists and reads back exactly",
         "1 MB string in details",
         "verbatim round-trip",
         f"match={entry.details['blob'] == big} elapsed_s={elapsed:.2f}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: JSONB carries large evidence payloads",
         "")
    assert ok


async def test_v12_29_metadata_truncation(recorder, trail_db):
    session, _, _, tracked = trail_db
    from app.models import AuditAction

    entry = await _log(session, tracked,
                       action=AuditAction.AUDIT_STARTED,
                       entity_type="audit", ip_address="1" * 60,
                       user_agent="A" * 600)
    await session.flush()
    await session.refresh(entry)
    ok = (entry.ip_address == "1" * 45 and entry.user_agent == "A" * 500)
    _row(recorder, "V12-29", "H",
         "overlong client metadata truncates to column widths "
         "(pre-fix: StringDataRightTruncationError at flush)",
         "60-char IP + 600-char User-Agent",
         "stored as 45 + 500 chars",
         f"ip={len(entry.ip_address or '')} "
         f"ua={len(entry.user_agent or '')}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: truncate client-controlled metadata (program vocabulary "
         "stays strict, V12-10)",
         "")
    assert ok


async def test_v12_30_endpoint_rejects_bad_filters(recorder, trail_db):
    session, admin, _, _ = trail_db
    from types import SimpleNamespace

    from fastapi import HTTPException

    from app.api.v1.audit_trail import list_trail_entries

    me = SimpleNamespace(id=admin.id, role="admin")
    bad = 0
    for kw in ({"entity_id": "zzz"}, {"action": "nope"}):
        try:
            await list_trail_entries(
                page=1, per_page=20, entity_type=None,
                entity_id=kw.get("entity_id"), action=kw.get("action"),
                db=session, current_user=me)
        except HTTPException as e:
            if e.status_code == 422:
                bad += 1
    ok = bad == 2
    _row(recorder, "V12-30", "H",
         "malformed trail-query filters are HTTP 422, never 500",
         "entity_id='zzz' + action='nope' through the endpoint",
         "2/2 responses are 422",
         f"422s={bad}/2",
         ok, "CONFIRMED BEHAVIOR",
         "E12: AuditTrailError -> 422 at the endpoint boundary",
         "")
    assert ok


def test_v12_31_numeric_validation_is_typed(recorder):
    from app.repositories.audit_trail import (
        AuditTrailError, AuditTrailRepository)
    import asyncio

    repo = AuditTrailRepository(None)  # validation precedes session use

    async def _probe():
        bad = 0
        argv = dict(audit_id=str(uuid.uuid4()), total_controls=10,
                    passed=1, failed=0, review=0, overall_score=1.0)
        for mutate in (dict(passed=True), dict(passed=-1),
                       dict(overall_score=float("nan")),
                       dict(overall_score="high"),
                       dict(total_controls=1.5)):
            args = dict(argv)
            args.update(mutate)
            try:
                await repo.log_compliance_evaluation(**args)
            except AuditTrailError:
                bad += 1
        try:
            await repo.log_finding_update(
                finding_id=str(uuid.uuid4()), audit_id=str(uuid.uuid4()),
                old_status="open", new_status="open", notes=None, no_op=0)
        except AuditTrailError:
            bad += 1
        return bad

    bad = asyncio.run(_probe())
    ok = bad == 6
    _row(recorder, "V12-31", "H",
         "bool/negative/NaN/string numerics and non-bool no_op are "
         "typed errors (a NaN score previously reached Postgres JSONB "
         "as InvalidTextRepresentationError)",
         "6 numeric misuses across compliance + finding helpers",
         "6/6 typed before any session use",
         f"typed={bad}/6",
         ok, "CONFIRMED BEHAVIOR",
         "E12: numeric guards (bools excluded explicitly)",
         "")
    assert ok


# --------------------------------------------------------------------------
# I - integration with the rest of the pipeline (§9.1)
# --------------------------------------------------------------------------


async def test_v12_32_finding_update_shape(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    fid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    e1 = await repo.log_finding_update(
        finding_id=fid, audit_id=aid, old_status="open",
        new_status="in_progress", user_id=str(admin.id),
        notes="looking into it")
    tracked.append(e1.id)
    e2 = await repo.log_finding_update(
        finding_id=fid, audit_id=aid, old_status="in_progress",
        new_status="in_progress", user_id=str(admin.id), notes="",
        no_op=True)
    tracked.append(e2.id)
    await session.flush()
    rows = await repo.get_entries(entity_type="finding", entity_id=fid)
    ours = [r for r in rows if r.id in set(tracked)]
    by_action = all(r.action == AuditAction.FINDING_UPDATED for r in ours)
    notes_kept = {r.details["notes"] for r in ours} == {"looking into it",
                                                        ""}
    noop_flag = any(r.details["no_op"] is True for r in ours)
    transition = any(r.details["old_status"] == "open"
                     and r.details["new_status"] == "in_progress"
                     for r in ours)
    ok = len(ours) == 2 and by_action and notes_kept and noop_flag \
        and transition
    _row(recorder, "V12-32", "I",
         "finding transitions (change + explicit no-op) persist with "
         "actor, previous/new status and undropped notes, queryable by "
         "finding id",
         "change + no-op updates, read back by entity",
         "2 rows, notes kept, no_op flagged, transition intact",
         f"rows={len(ours)} notes={notes_kept} noop={noop_flag}",
         ok, "CONFIRMED BEHAVIOR",
         "E08 F6 flow through the E12-hardened helper (V08 re-passing "
         "post-fix)",
         "")
    assert ok


async def test_v12_33_compliance_evaluation_shape(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    aid = str(uuid.uuid4())
    e = await repo.log_compliance_evaluation(
        audit_id=aid, total_controls=53, passed=10, failed=30, review=13,
        overall_score=18.9, user_id=str(admin.id))
    tracked.append(e.id)
    await session.flush()
    await session.refresh(e)
    ok = (e.action == AuditAction.COMPLIANCE_EVALUATED
          and e.entity_type == "audit" and str(e.entity_id) == aid
          and e.details["passed"] == 10 and e.details["failed"] == 30
          and e.details["review"] == 13
          and e.details["overall_score"] == 18.9)
    _row(recorder, "V12-33", "I",
         "the stored audit result carries counts + score under the "
         "audit entity (the pipeline's log_compliance_evaluation call "
         "shape)",
         "53/10/30/13 @ 18.9",
         "exact stored shape",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: §10.12 'store all audit results' member",
         "")
    assert ok


async def test_v12_34_endpoint_item_schema(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from types import SimpleNamespace

    from app.api.v1.audit_trail import list_trail_entries
    from app.models import AuditAction

    e = await _log(session, tracked,
                   action=AuditAction.AUDIT_COMPLETED, entity_type="audit",
                   entity_id=uuid.uuid4(), user_id=str(admin.id),
                   details={"k": "v"}, ip_address="127.0.0.1")
    await session.flush()
    resp = await list_trail_entries(
        page=1, per_page=10, entity_type="audit",
        entity_id=str(e.entity_id), action=None, db=session,
        current_user=SimpleNamespace(id=admin.id, role="admin"))
    item = next((i for i in resp.items if i.id == e.id), None)
    ok = (item is not None and item.action == "audit_completed"
          and item.entity_type == "audit" and item.details == {"k": "v"}
          and item.ip_address == "127.0.0.1"
          and resp.meta.total >= 1 and resp.meta.page == 1)
    _row(recorder, "V12-34", "I",
         "endpoint items validate against AuditTrailResponse with "
         "consistent page meta",
         "one audit row, filtered query as admin",
         "item fields + meta correct",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: schema + meta contract of GET /audit-trail",
         "")
    assert ok


def test_v12_35_finding_status_wiring(recorder):
    src = _read("app/api/v1/findings.py")
    ok = (src.count("log_finding_update") >= 2
          and "no_op=True" in src
          and "previous_status" in src
          and "notes = update.notes or" in src)
    _row(recorder, "V12-35", "I",
         "the finding-status endpoint logs both branches (change + "
         "explicit no-op) with actor/previous/new/notes",
         "findings.py status-update wiring",
         "both branches + no_op flag + notes preserved",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E08 F6 behavior runs on the hardened helper (V08 98/98 "
         "post-fix); wiring pinned here",
         "")
    assert ok


# --------------------------------------------------------------------------
# J - performance (measurement only)
# --------------------------------------------------------------------------


async def test_v12_36_log_throughput(recorder, trail_db):
    import time as _time

    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    elapsed = []
    for i in range(30):
        start = _time.perf_counter()
        e = await repo.log(action=AuditAction.AUDIT_STARTED,
                           entity_type="audit", user_id=str(admin.id),
                           details={"i": i})
        tracked.append(e.id)
        await session.flush()
        elapsed.append((_time.perf_counter() - start) * 1000.0)
    elapsed.sort()
    p95 = elapsed[int(len(elapsed) * 0.95)]
    ok = p95 < 5000
    _row(recorder, "V12-36", "J",
         "single-row trail writes stay in milliseconds (p95 budget 5 s, "
         "measurement only)",
         "30 sequential log+flush",
         "p95 < 5000 ms",
         f"p50_ms={elapsed[len(elapsed) // 2]:.1f} p95_ms={p95:.1f} "
         f"max_ms={elapsed[-1]:.1f}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: one INSERT + flush per event; no N+1 in the helper",
         "")
    assert ok


async def test_v12_37_query_timing(recorder, trail_db):
    import time as _time

    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    for i in range(10):
        e = await repo.log(action=AuditAction.AUDIT_STARTED,
                           entity_type="audit", user_id=str(admin.id),
                           details={"e12": "perf", "i": i})
        tracked.append(e.id)
    await session.flush()
    start = _time.perf_counter()
    rows = await repo.get_entries(user_id=str(admin.id), limit=100)
    total = await repo.count_entries(user_id=str(admin.id))
    elapsed = (_time.perf_counter() - start) * 1000.0
    ok = len(rows) >= 10 and total >= 10 and elapsed < 5000
    _row(recorder, "V12-37", "J",
         "filtered list + count serve in milliseconds (measurement only)",
         "10 rows, list + count",
         "correct sets, < 5000 ms",
         f"rows={len(rows)} total={total} elapsed_ms={elapsed:.1f}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: indexed equality filters + bounded pages",
         "")
    assert ok


# --------------------------------------------------------------------------
# K - content spot checks
# --------------------------------------------------------------------------


async def test_v12_38_identity_and_timestamp(recorder, trail_db):
    session, _, _, tracked = trail_db
    from app.models import AuditAction

    e = await _log(session, tracked,
                   action=AuditAction.TRAINING_COMPLETED,
                   entity_type="ai_interaction")
    await session.flush()
    await session.refresh(e)
    import datetime as dt

    age = (dt.datetime.utcnow() - e.created_at).total_seconds()
    ok = (isinstance(e.id, uuid.UUID) and 0 <= age < 60
          and e.action == "training_completed")
    _row(recorder, "V12-38", "K",
         "every entry carries a fresh UUID id and a current created_at "
         "(string actions store as their value)",
         "minimal log()",
         "UUID id, timestamp < 60 s old, action value stored",
         f"age_s={age:.1f} action={e.action!r}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: identity/timestamp invariants",
         "")
    assert ok


async def test_v12_39_system_entries_without_user(recorder, trail_db):
    session, _, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    e = await repo.log(action=AuditAction.AUDIT_FAILED, entity_type="audit",
                       entity_id=uuid.uuid4(), user_id=None,
                       details={"error": "boom"})
    tracked.append(e.id)
    await session.flush()
    rows = await repo.get_entries(entity_id=str(e.entity_id))
    ok = len(rows) == 1 and rows[0].user_id is None
    _row(recorder, "V12-39", "K",
         "system entries (NULL user, e.g. background pipeline failure) "
         "persist and stay queryable by entity",
         "user_id=None failure entry",
         "stored with NULL user, found by entity_id",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: user FK nullable + SET NULL (history survives users)",
         "")
    assert ok


async def test_v12_40_finding_linkage_round_trip(recorder, trail_db):
    session, admin, _, tracked = trail_db
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    fid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    e = await repo.log_finding_update(
        finding_id=fid, audit_id=aid, old_status="open",
        new_status="resolved", user_id=str(admin.id), notes="fixed")
    tracked.append(e.id)
    await session.flush()
    rows = await repo.get_entries(entity_type="finding", entity_id=fid)
    ours = [r for r in rows if r.id == e.id]
    ok = (len(ours) == 1 and ours[0].details["audit_id"] == aid
          and ours[0].user_id == admin.id)
    _row(recorder, "V12-40", "K",
         "a finding's history links finding id -> audit id -> actor in "
         "one queryable entry",
         "finding update, read back by finding id",
         "audit_id + actor linked",
         f"ok={ok}",
         ok, "CONFIRMED BEHAVIOR",
         "E12: the entry reconstructs who did what to which finding",
         "")
    assert ok


async def test_v12_41_date_range_filters(recorder, trail_db):
    import datetime as _dt

    session, admin, _, tracked = trail_db
    from app.models import AuditAction
    from app.repositories.audit_trail import AuditTrailRepository

    repo = AuditTrailRepository(session)
    marker = f"e12-{uuid.uuid4().hex[:8]}"
    for i in range(3):
        e = await repo.log(action=AuditAction.AUDIT_STARTED,
                           entity_type="audit", user_id=str(admin.id),
                           details={"e12": marker, "i": i})
        tracked.append(e.id)
    await session.flush()
    now = _dt.datetime.utcnow()
    wide_from = (now - _dt.timedelta(hours=1)).isoformat()
    wide_to = (now + _dt.timedelta(hours=1)).isoformat()
    in_range = await repo.get_entries(user_id=str(admin.id),
                                      from_date=wide_from, to_date=wide_to)
    ours_in = [r for r in in_range
               if (r.details or {}).get("e12") == marker]
    future = await repo.get_entries(
        user_id=str(admin.id),
        from_date=(now + _dt.timedelta(hours=1)).isoformat(),
        to_date=(now + _dt.timedelta(hours=2)).isoformat())
    ours_future = [r for r in future
                   if (r.details or {}).get("e12") == marker]
    ancient = await repo.get_entries(
        user_id=str(admin.id),
        from_date="2020-01-01T00:00:00", to_date="2020-01-02T00:00:00")
    ours_ancient = [r for r in ancient
                    if (r.details or {}).get("e12") == marker]
    n_list = len(await repo.get_entries(
        user_id=str(admin.id), from_date=wide_from, to_date=wide_to))
    n_count = await repo.count_entries(
        user_id=str(admin.id), from_date=wide_from, to_date=wide_to)
    ok = (len(ours_in) == 3 and not ours_future and not ours_ancient
          and n_list == n_count and n_list >= 3)
    _row(recorder, "V12-41", "D",
         "half-open UTC date bounds return exact sets and count agrees "
         "with list (wide window hits, future/ancient windows miss)",
         "3 fresh rows; ±1h window vs future vs 2020 windows",
         "3 hits, 0 + 0 misses, count == len",
         f"in={len(ours_in)} future={len(ours_future)} "
         f"ancient={len(ours_ancient)} count={n_count}",
         ok, "CONFIRMED BEHAVIOR",
         "ledger date-range filters ([from, to) UTC)",
         "")
    assert ok


async def test_v12_42_malformed_dates_are_typed(recorder, trail_db):
    session, admin, _, _ = trail_db
    from types import SimpleNamespace

    from fastapi import HTTPException

    from app.api.v1.audit_trail import list_trail_entries
    from app.repositories.audit_trail import (
        AuditTrailError, AuditTrailRepository)

    repo = AuditTrailRepository(None)  # validation precedes session use
    typed = 0
    for fn in (lambda: repo.get_entries(from_date="not-a-date"),
               lambda: repo.get_entries(to_date="2026-13-99"),
               lambda: repo.get_entries(from_date=12345)):
        try:
            await fn()
        except AuditTrailError:
            typed += 1
    me = SimpleNamespace(id=admin.id, role="admin")
    http_422 = 0
    for kw in ({"from_date": "yesterday"}, {"to_date": "zzz"}):
        try:
            await list_trail_entries(
                page=1, per_page=20, entity_type=None, entity_id=None,
                action=None, from_date=kw.get("from_date"),
                to_date=kw.get("to_date"), db=session, current_user=me)
        except HTTPException as e:
            if e.status_code == 422:
                http_422 += 1
    ok = typed == 3 and http_422 == 2
    _row(recorder, "V12-42", "D",
         "malformed date filters raise AuditTrailError at the repo and "
         "surface as HTTP 422 at the endpoint (never 500)",
         "3 bad repo filters + 2 bad endpoint filters",
         "3/3 typed, 2/2 are 422",
         f"typed={typed}/3 http422={http_422}/2",
         ok, "CONFIRMED BEHAVIOR",
         "ledger date validation (same typed-error convention as UUIDs)",
         "")
    assert ok
