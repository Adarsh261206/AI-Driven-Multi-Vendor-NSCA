"""Engine 06 - Knowledge Base validation.

Scope: the Knowledge Base as a contract: app/ai/knowledge_base.py (in-memory),
app/repositories/knowledge_base.py (SQLAlchemy), app/api/v1/training.py (REST),
app/ai/adaptive.py (workflow), app/models/__init__.py + alembic 001 (schema),
and the way the rest of the system consumes it (app/engines/normalization.py,
app/ai/semantic.py) - against docs/PROJECT_MASTER_SPEC.md section 10.6 (Knowledge
Base), 9.2 (Adaptive Learning Workflow), 15 (Adaptive Learning Architecture),
the section 12 TrainingMapping interface and 14.1/14.3 (AI boundaries).

Methodology rules for this engine (user-mandated):
  * No production code is modified. Engine 05's findings are UPSTREAM CONTEXT:
    cited where they touch section 10.6 responsibilities ("normalization uses
    mapping"), never assumed fixed.
  * Category G is the separate, explicitly-labelled record of wrong /
    unsupported-vendor behaviour (vendor/platform isolation, wildcard filters).
  * `status` reports whether the REQUIREMENT is met: FAIL = the defect is present.
    Defect rows assert `assert defect`; conformance rows assert `assert ok`.
  * Every number is recomputed from code, schema or runtime on each run.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.ai.knowledge_base import KnowledgeBase, TrainingMapping as DataclassMapping

BACKEND = Path(__file__).resolve().parents[2]
SPEC = BACKEND.parent / "docs" / "PROJECT_MASTER_SPEC.md"

# 10-token syntaxes that differ in exactly one token (Jaccard 10/12 > 0.8)
SYN_A = "ip access-list extended ACL permit tcp host 10.1.1.1 host 10.2.2.2 eq 443"
SYN_B = "ip access-list extended ACL permit tcp host 10.1.1.1 host 10.2.2.2 eq 8443"
# 7/8 = 0.875 pair used for the create-absorption defect
ACL_X = "access-list 10 permit ip host 1.1.1.1 any"
ACL_Y = "access-list 10 permit ip host 1.1.1.1 any log"


def src(rel: str) -> str:
    return (BACKEND / rel).read_text(encoding="utf-8")


def spec_text() -> str:
    return SPEC.read_text(encoding="utf-8")


def _mapping_table():
    from app.models import Base

    return Base.metadata.tables["semantic_mappings"]


def _col_map() -> dict:
    """Column metadata in the shape the reflection API would return."""
    return {
        c.name: {
            "name": c.name,
            "nullable": c.nullable,
            "default": None if c.default is None else getattr(c.default, "arg", c.default),
            "type": str(c.type),
        }
        for c in _mapping_table().c
    }


@pytest.fixture()
def kb() -> KnowledgeBase:
    return KnowledgeBase()


@pytest.fixture()
def adaptive():
    from app.ai.adaptive import AdaptiveLearningEngine

    return AdaptiveLearningEngine(ai_client=None, knowledge_base=KnowledgeBase())


@pytest.fixture()
async def kb_db():
    """Session + admin user against the throwaway validation database."""
    import scripts.engine_validation.dbutil as dbutil
    from sqlalchemy import delete

    if not await dbutil.schema_available():
        pytest.skip("throwaway database engine_validation_test not provisioned")

    from app.models import MappingVersion, TrainingMapping, User

    engine, factory = dbutil.make_session_factory()
    session = factory()
    for model in (TrainingMapping, MappingVersion):
        await session.execute(delete(model))
    await session.execute(delete(User).where(User.email.like("e06-%")))
    await session.commit()

    user = User(
        id=uuid.uuid4(),
        email=f"e06-{uuid.uuid4().hex[:10]}@example.com",
        password_hash="x",
        role="admin",
        is_active=True,
    )
    session.add(user)
    await session.commit()
    uid = user.id
    admin = SimpleNamespace(id=uid)
    try:
        yield session, uid, admin
    finally:
        try:
            for model in (TrainingMapping, MappingVersion):
                await session.execute(delete(model))
            await session.execute(delete(User).where(User.email.like("e06-%")))
            await session.commit()
        except Exception:  # noqa: BLE001
            await session.rollback()
        await session.close()
        await engine.dispose()


# ==========================================================================
# A - spec schema/structure conformance (section 15.1 SQL, section 12 interface)
# ==========================================================================


def test_v06_01_unique_constraint_per_spec_15_1(recorder):
    from sqlalchemy import UniqueConstraint

    table = _mapping_table()
    uniques = [c for c in table.constraints if isinstance(c, UniqueConstraint)]
    unique_cols = sorted(
        tuple(sorted(c.columns.keys())) for c in uniques)
    indexes = sorted(i.name for i in table.indexes)
    migration_files = sorted(
        (BACKEND / "alembic" / "versions").glob("*.py"))
    migration_has_unique = any(
        ("UNIQUE" in text or "UniqueConstraint" in text
         or "create_unique_constraint" in text)
        and "semantic_mappings" in text
        for text in (p.read_text(encoding="utf-8")
                     for p in migration_files))
    spec_unique = "UNIQUE(vendor, platform, raw_syntax, version)" in spec_text()

    ok = (spec_unique and tuple(sorted(("vendor", "platform", "raw_syntax",
                                        "version"))) in [tuple(t) for t in unique_cols]
          and migration_has_unique)
    recorder.add(
        "V06-01", "A",
        "semantic_mappings enforces UNIQUE(vendor, platform, raw_syntax, version) (section 15.1)",
        "Base.metadata + alembic version chain + spec section 15.1",
        "1 unique constraint over (vendor, platform, raw_syntax, version)",
        f"model uniques={uniques}; unique cols={unique_cols}; "
        f"indexes={indexes}; "
        f"migration declares UNIQUE in a semantic_mappings block={migration_has_unique}; "
        f"spec requires it={spec_unique}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "models/__init__.py uq_semantic_mappings_identity_version; "
        "alembic/versions/005_kb_contract.py (history is append-only: the "
        "constraint lives in 005, not 001)",
        "",
    )
    assert ok


def test_v06_02_universal_model_path_nullability(recorder):
    from sqlalchemy import inspect

    from app.models import Base

    col = _col_map()
    model_nullable = col["universal_model_path"]["nullable"]
    migration_text = src("alembic/versions/005_kb_contract.py")
    migration_not_null = "universal_model_path" in migration_text
    spec = spec_text()
    spec_not_null = "universal_model_path VARCHAR(255) NOT NULL" in spec
    interface_nonnull = "universal_model_path: string;" in spec

    ok = (spec_not_null or interface_nonnull) and not model_nullable
    recorder.add(
        "V06-02", "A",
        "universal_model_path is NOT NULL (section 15.1) / non-null string (section 12 interface)",
        "column nullability", "nullable=False",
        f"model nullable={model_nullable}; migration 005 alters nullability={migration_not_null}; "
        f"spec NOT NULL={spec_not_null}; section 12 non-null={interface_nonnull}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "models/__init__.py TrainingMapping/MappingVersion; "
        "alembic/versions/005_kb_contract.py (backfills legacy NULLs)",
        "",
    )
    assert ok


def test_v06_03_required_columns_not_null(recorder):
    from sqlalchemy import inspect

    from app.models import Base

    cols = _col_map()
    required = ["vendor", "platform", "raw_syntax", "semantic_meaning", "confidence", "version"]
    bad = [n for n in required if cols[n]["nullable"]]
    ok = not bad
    recorder.add(
        "V06-03", "A",
        "spec section 15.1 NOT NULL columns are non-nullable",
        str(required), "all nullable=False", f"nullable={bad}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "models/__init__.py:293-303",
    )
    assert ok


def test_v06_04_admin_confirmed_default_false(recorder):
    from sqlalchemy import inspect

    from app.models import Base

    cols = _col_map()
    model_default = cols["admin_confirmed"]["default"]
    migration_ok = "sa.Column('admin_confirmed', sa.Boolean, server_default='false')" in src(
        "alembic/versions/001_initial_migration.py"
    )
    ok = model_default is False and migration_ok
    recorder.add(
        "V06-04", "A",
        "admin_confirmed defaults to FALSE (section 15.1)",
        "model default + migration server_default", "False / 'false'",
        f"model={model_default!r}; migration={migration_ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "models/__init__.py:301; 001_initial_migration.py:212",
    )
    assert ok


def test_v06_05_version_default_one(recorder):
    from sqlalchemy import inspect

    from app.models import Base

    cols = _col_map()
    model_default = cols["version"]["default"]
    migration_ok = "sa.Column('version', sa.Integer, nullable=False, server_default='1')" in src(
        "alembic/versions/001_initial_migration.py"
    )
    ok = model_default == 1 and migration_ok
    recorder.add(
        "V06-05", "A",
        "version defaults to 1 (section 15.1)",
        "model default + migration server_default", "1",
        f"model={model_default!r}; migration={migration_ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "models/__init__.py:303; 001_initial_migration.py:213",
    )
    assert ok


def test_v06_06_confidence_type(recorder):
    from sqlalchemy import inspect

    from app.models import Base

    cols = _col_map()
    model_type = str(cols["confidence"]["type"])
    spec_decimal = "confidence DECIMAL(5,2) NOT NULL" in spec_text()
    ok = spec_decimal and "numeric" in model_type.lower()
    recorder.add(
        "V06-06", "A",
        "confidence column type matches spec DECIMAL(5,2) (section 15.1)",
        "column type", "NUMERIC(5,2)",
        f"model type={model_type}; spec DECIMAL={spec_decimal} "
        "(domain values stay Python float; converted at the ORM boundary)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "models/__init__.py Numeric(5,2); alembic/versions/005_kb_contract.py; "
        "spec:1083",
        "",
    )
    assert ok


def test_v06_07_created_by_type(recorder):
    from sqlalchemy import inspect

    from app.models import Base

    cols = _col_map()
    model_type = str(cols["created_by"]["type"])
    not_null = not cols["created_by"]["nullable"]
    has_legacy_fk = "created_by_id" in cols
    spec_varchar = "created_by VARCHAR(100) NOT NULL" in spec_text()
    ok = spec_varchar and "VARCHAR(100)" in model_type.upper() \
        and not_null and not has_legacy_fk
    recorder.add(
        "V06-07", "A",
        "created_by column type matches spec VARCHAR(100) (section 15.1)",
        "column type + nullability", "VARCHAR(100) NOT NULL, no UUID FK",
        f"model type={model_type} NOT NULL={not_null}; legacy created_by_id "
        f"removed={not has_legacy_fk}; spec VARCHAR={spec_varchar}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "models/__init__.py created_by String(100); "
        "alembic/versions/005_kb_contract.py (actor identity survives user "
        "deletion; no join needed to read mappings)",
        "",
    )
    assert ok


def test_v06_08_spec_interface_fields_in_response(recorder):
    from app.schemas import TrainingMappingResponse

    block = spec_text().split("interface TrainingMapping {")[1].split("}")[0]
    spec_fields = [
        ln.strip().split(":")[0].strip()
        for ln in block.splitlines()
        if ":" in ln and not ln.strip().startswith("//")
    ]
    response_fields = set(TrainingMappingResponse.model_fields)
    missing = [f for f in spec_fields if f not in response_fields and f != "created_at"]
    ok = not missing
    recorder.add(
        "V06-08", "A",
        "every field of spec section 12 interface TrainingMapping is exposed by the API response",
        f"spec fields={spec_fields}", "response exposes all fields",
        f"response fields={sorted(response_fields)}; missing={missing}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "spec:871-885; schemas/__init__.py TrainingMappingResponse "
        "(created_by included)",
        "",
    )
    assert ok


# ==========================================================================
# B - in-memory KnowledgeBase semantics (app/ai/knowledge_base.py)
# ==========================================================================


def test_v06_09_lookup_exact_hit(kb, recorder):
    kb.create("cisco", "ios", "hostname edge-1", "sets hostname",
              universal_model_path="device.hostname", actor="test-admin")
    got = kb.lookup("cisco", "ios", "hostname edge-1")
    ok = got is not None and got.semantic_meaning == "sets hostname"
    recorder.add(
        "V06-09", "B", "exact lookup returns the stored mapping",
        "cisco/ios 'hostname edge-1'", "mapping meaning='sets hostname'",
        f"found={got is not None}; meaning={getattr(got, 'semantic_meaning', None)!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py:109-118 exact pass",
    )
    assert ok


def test_v06_10_lookup_miss_returns_none(kb, recorder):
    kb.create("cisco", "ios", "hostname edge-1", "sets hostname",
              universal_model_path="device.hostname", actor="test-admin")
    got = kb.lookup("cisco", "ios", "no-such-command")
    ok = got is None
    recorder.add(
        "V06-10", "B", "lookup miss returns None",
        "unknown syntax, same vendor/platform", "None", f"got={got!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py:120-133 fuzzy pass finds no similarity >0.8",
    )
    assert ok


def test_v06_11_lookup_case_and_strip_tolerant(kb, recorder):
    kb.create("CISCO", "IOS", "  hostname edge-1  ", "sets hostname",
              universal_model_path="device.hostname", actor="test-admin")
    got = kb.lookup("cisco", "ios", "hostname edge-1")
    stored = kb.lookup("cisco", "ios", "hostname edge-1",
                       require_confirmed=False)
    ok = got is not None and got.semantic_meaning == "sets hostname" \
        and stored is not None and stored.vendor == "cisco" \
        and stored.raw_syntax == "hostname edge-1"
    recorder.add(
        "V06-11", "B",
        "lookup is case-insensitive on vendor/platform and tolerant of whitespace (own docstring)",
        "create 'CISCO'/'IOS' with padded syntax; query 'cisco'/'ios' unpadded",
        "mapping returned; stored canonically (lowercase, stripped)",
        f"found={got is not None}; stored vendor={getattr(stored, 'vendor', None)!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "kb_domain.canonical_identity on write and lookup; one representation "
        "(Cisco/cisco can never be two identities)",
        "",
    )
    assert ok


def test_v06_12_create_defaults(kb, recorder):
    m = kb.create("cisco", "ios", "ntp server 1.1.1.1", "upstream NTP",
                  universal_model_path="ntp.servers",
                  actor="test-admin")
    ok = (
        m.admin_confirmed is True
        and m.confidence == 1.0
        and m.version == 1
        and len(m.id) == 36
        and m.vendor == "cisco"
        and m.created_by == "test-admin"
    )
    recorder.add(
        "V06-12", "B",
        "create() default: admin-confirmed mapping, confidence 1.0, version 1, unique id",
        "create without flags", "confirmed=True conf=1.0 v1 uuid id",
        f"confirmed={m.admin_confirmed} conf={m.confidence} v={m.version} id={m.id}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py create(); actor recorded",
        "",
    )
    assert ok


def test_v06_13_create_unconfirmed_confidence(kb, recorder):
    m = kb.create("cisco", "ios", "mystery cmd", "guess",
                  universal_model_path="device.hostname",
                  admin_confirmed=False, actor="test-admin")
    ok = m.admin_confirmed is False and m.confidence == 0.5
    recorder.add(
        "V06-13", "B",
        "unconfirmed create stores confidence 0.5 (hypothesis, not fact)",
        "create(admin_confirmed=False)", "confirmed=False conf=0.5",
        f"confirmed={m.admin_confirmed} conf={m.confidence}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py estimated-confidence default",
        "",
    )
    assert ok


def test_v06_14_create_exact_duplicate_updates_not_duplicates(kb, recorder):
    kb.create("cisco", "ios", "hostname a", "first meaning",
              universal_model_path="device.hostname", actor="test-admin")
    m2 = kb.create("cisco", "ios", "hostname a", "second meaning",
                   universal_model_path="device.hostname", actor="test-admin")
    allm = kb.list_mappings()
    ok = len(allm) == 1 and m2.version == 2 and allm[0].semantic_meaning == "second meaning"
    recorder.add(
        "V06-14", "B",
        "re-creating an identical syntax updates the existing mapping (no duplicate row)",
        "same vendor/platform/syntax created twice",
        "1 mapping, version 2, new meaning",
        f"rows={len(allm)} version={m2.version} meaning={allm[0].semantic_meaning!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py exact-identity dedupe then versioned update",
        "",
    )
    assert ok


def test_v06_15_create_absorbs_similar_syntax(kb, recorder):
    from app.ai import kb_domain as dom

    kb.create("cisco", "ios", ACL_X, "meaning for X",
              universal_model_path="access_control.rules_count",
              actor="test-admin")
    kb.create("cisco", "ios", ACL_Y, "meaning for Y",
              universal_model_path="access_control.rules_count",
              actor="test-admin")
    allm = kb.list_mappings()
    sim = dom.jaccard_similarity(dom.normalize_tokens(ACL_X),
                                 dom.normalize_tokens(ACL_Y))
    y_stored = any(m.raw_syntax == ACL_Y for m in allm)
    x_stored = any(m.raw_syntax == ACL_X for m in allm)
    ok = sim > 0.8 and len(allm) == 2 and y_stored and x_stored
    recorder.add(
        "V06-15", "B",
        "create() of a distinct but similar syntax stores that syntax independently",
        f"create X then Y (Jaccard={sim:.3f})", "2 mappings, both raw_syntax values stored",
        f"rows={len(allm)} stored={[m.raw_syntax for m in allm]} y_stored={y_stored}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F5: exact identity only; similarity is suggestion-only and "
        "never mutates storage",
        "",
    )
    assert ok


def test_v06_16_fuzzy_lookup_returns_other_mappings_meaning(kb, recorder):
    from app.ai import kb_domain as dom

    kb.create("cisco", "ios", SYN_B, "meaning belongs to eq 8443 rule",
              universal_model_path="access_control.rules_count",
              actor="test-admin")
    got = kb.lookup("cisco", "ios", SYN_A)
    sim = dom.jaccard_similarity(dom.normalize_tokens(SYN_A),
                                 dom.normalize_tokens(SYN_B))
    suggestions = kb.lookup_suggestions("cisco", "ios", SYN_A)
    ok = sim > 0.8 and got is None and any(
        s.raw_syntax == SYN_B for s, _ in suggestions)
    recorder.add(
        "V06-16", "B",
        "exact lookup never returns another command's mapping; suggestions do",
        f"query A vs stored B (Jaccard={sim:.3f})",
        "lookup None; suggestions name B as a non-authoritative candidate",
        f"lookup={got!r}; suggestions={[s.raw_syntax for s, _ in suggestions]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F5: lookup() exact-only; lookup_suggestions() ranks candidates "
        "without mutating storage",
        "",
    )
    assert ok


def test_v06_17_edit_promotes_unconfirmed_to_confirmed(kb, recorder):
    m = kb.create("cisco", "ios", "mystery cmd", "guess",
                  universal_model_path="device.hostname",
                  admin_confirmed=False, actor="test-admin")
    before = (m.admin_confirmed, m.confidence, m.version)
    kb.update(mapping_id=m.id, admin_notes="note only, no confirm action",
              actor="test-admin")
    after = (m.admin_confirmed, m.confidence, m.version)
    ok = before == (False, 0.5, 1) and after == (False, 0.5, 2)
    recorder.add(
        "V06-17", "B",
        "an edit must not confirm a mapping (section 9.2 step 3: CONFIRM / EDIT / REJECT are "
        "distinct admin actions; section 14.3.3 human-in-the-loop)",
        "update(admin_notes=...) on an unconfirmed mapping",
        "still unconfirmed, confidence unchanged, version bumped",
        f"before={before} after={after}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F3: update() preserves confirmation state and confidence",
        "",
    )
    assert ok


def test_v06_18_no_version_record_on_create(kb, recorder):
    m = kb.create("cisco", "ios", "cmd v", "meaning",
                  universal_model_path="device.hostname", actor="test-admin")
    versions = kb.get_versions(m.id)
    ok = len(versions) == 1 and versions[0].version == 1 \
        and versions[0].change_reason == "Initial creation"
    recorder.add(
        "V06-18", "B",
        "a stored mapping is versioned from creation (section 9.2 step 4; section 15.2 step 3d)",
        "create then inspect version history",
        "1 version record for the initial state",
        f"records={[(v.version, v.change_reason) for v in versions]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F7: create() appends the v1 post-change record",
        "",
    )
    assert ok


def test_v06_19_update_appends_version_record(kb, recorder):
    m = kb.create("cisco", "ios", "cmd v", "v1 meaning",
                  universal_model_path="device.hostname", actor="test-admin")
    kb.update(mapping_id=m.id, semantic_meaning="v2 meaning",
              actor="test-admin")
    versions = kb.get_versions(m.id)
    ok = len(versions) == 2 and versions[0].version == 1 \
        and versions[1].version == 2 \
        and versions[1].semantic_meaning == "v2 meaning"
    recorder.add(
        "V06-19", "B", "update() appends a post-change version record (section 15.2 step 3d)",
        "create then update", "v1 initial + v2 post-change records",
        f"records={[(v.version, v.semantic_meaning) for v in versions]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F7: one post-change convention everywhere (create v1, edit v2); "
        "supersedes the old pre-change-snapshot convention",
        "",
    )
    assert ok


def test_v06_20_update_unknown_id_raises(kb, recorder):
    try:
        kb.update(mapping_id="nope", semantic_meaning="x")
        outcome = "no error"
    except ValueError:
        outcome = "ValueError"
    ok = outcome == "ValueError"
    recorder.add(
        "V06-20", "B", "update() of an unknown id raises a typed error",
        "mapping_id='nope'", "ValueError", f"outcome={outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py:211-213",
    )
    assert ok


def test_v06_21_get_versions_unknown_id(kb, recorder):
    out = kb.get_versions("nope")
    ok = out == []
    recorder.add(
        "V06-21", "B", "get_versions() of an unknown id returns []",
        "unknown id", "[]", f"got={out!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py:246-248",
    )
    assert ok


def test_v06_22_list_filters(kb, recorder):
    kb.create("cisco", "ios", "a", "A", universal_model_path="device.hostname",
              actor="t")
    kb.create("cisco", "ios", "b", "B", universal_model_path="device.hostname",
              admin_confirmed=False, actor="t")
    kb.create("juniper", "junos", "c", "C", universal_model_path="device.hostname",
              actor="t")
    by_vendor = len(kb.list_mappings(vendor="cisco"))
    confirmed = len(kb.list_mappings(confirmed_only=True))
    by_platform = len(kb.list_mappings(platform="junos"))
    ok = by_vendor == 2 and confirmed == 2 and by_platform == 1
    recorder.add(
        "V06-22", "B", "list_mappings filters by vendor/platform/confirmed_only",
        "3 mappings across 2 vendors, 2 confirmed",
        "vendor=2 confirmed=2 platform=junos=1",
        f"vendor={by_vendor} confirmed={confirmed} platform={by_platform}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py list_mappings (canonical literal filters, "
        "canonical order)",
        "",
    )
    assert ok


def test_v06_23_get_stats_counts(kb, recorder):
    kb.create("cisco", "ios", "a", "A", universal_model_path="device.hostname",
              actor="t")
    kb.create("cisco", "ios", "b", "B", universal_model_path="device.hostname",
              admin_confirmed=False, actor="t")
    kb.create("juniper", "junos", "c", "C", universal_model_path="device.hostname",
              actor="t")
    stats = kb.get_stats()
    ok = (
        stats["total_mappings"] == 3
        and stats["confirmed_mappings"] == 2
        and stats["pending_mappings"] == 1
        and sorted(stats["vendors"]) == ["cisco", "juniper"]
    )
    recorder.add(
        "V06-23", "B", "get_stats reports totals, confirmed/pending, vendors, platforms",
        "3 mappings", "total=3 confirmed=2 pending=1 vendors=[cisco,juniper]",
        f"stats={stats}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py get_stats (deterministic ordering)",
        "",
    )
    assert ok


def test_v06_24_reject_confirmed_mapping_marks(adaptive, recorder):
    m = adaptive.confirm_mapping(
        raw_syntax="conf-cmd", vendor="cisco", platform="ios",
        semantic_meaning="real",
        universal_model_path="device.hostname", user_id="admin-1",
    )
    rejected = adaptive.reject_mapping(raw_syntax="conf-cmd", vendor="cisco",
                                       platform="ios", user_id="admin-1",
                                       reason="wrong meaning")
    still = adaptive.kb.lookup("cisco", "ios", "conf-cmd",
                               require_confirmed=False)
    versions = adaptive.kb.get_versions(m.id)
    ok = rejected is True and still is not None \
        and still.admin_confirmed is False \
        and still.admin_notes.startswith("REJECTED:") \
        and len(versions) == 2
    recorder.add(
        "V06-24", "B",
        "REJECT works on a confirmed mapping (section 9.2 step 3: CONFIRM / EDIT / REJECT)",
        "reject a confirmed mapping",
        "True; row kept, unconfirmed, REJECTED note, versioned",
        f"returned={rejected}; still_present={still is not None}; "
        f"state={None if still is None else (still.admin_confirmed, still.admin_notes)}; "
        f"versions={len(versions)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F3: reject marks (never deletes) with actor/version history",
        "",
    )
    assert ok


def test_v06_25_reject_pending_mapping_marks(adaptive, recorder):
    adaptive.kb.create("cisco", "ios", "pend-cmd", "pending",
                       universal_model_path="device.hostname",
                       admin_confirmed=False, actor="admin-1")
    rejected = adaptive.reject_mapping(raw_syntax="pend-cmd", vendor="cisco",
                                       platform="ios", user_id="admin-1",
                                       reason="not useful")
    row = adaptive.kb.lookup("cisco", "ios", "pend-cmd",
                             require_confirmed=False)
    ok = rejected is True and row is not None \
        and row.admin_confirmed is False \
        and (row.admin_notes or "").startswith("REJECTED:")
    recorder.add(
        "V06-25", "B", "REJECT marks an unconfirmed mapping rejected (never deletes)",
        "reject an unconfirmed mapping",
        "True; row kept, unconfirmed, REJECTED note (audit history survives)",
        f"returned={rejected}; notes={getattr(row, 'admin_notes', None)!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F3/F7: reject marks + versions instead of deleting; supersedes "
        "the old delete-unconfirmed behaviour which destroyed history",
        "",
    )
    assert ok


# ==========================================================================
# C - KnowledgeBaseRepository (SQLAlchemy, production storage path)
# ==========================================================================


async def test_v06_26_repo_create_persists(kb_db, recorder):
    from sqlalchemy import select

    from app.models import TrainingMapping
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    m = await repo.create(
        "cisco", "ios", "ntp server 1.1.1.1", "upstream NTP",
        universal_model_path="ntp.servers", actor=str(uid),
    )
    await session.commit()
    row = (
        await session.execute(select(TrainingMapping).where(TrainingMapping.id == m.id))
    ).scalar_one()
    ok = (
        row.raw_syntax == "ntp server 1.1.1.1"
        and row.admin_confirmed is True
        and row.confidence == 1.0
        and row.version == 1
        and row.created_by == str(uid)
        and row.universal_model_path == "ntp.servers"
    )
    recorder.add(
        "V06-26", "C", "repository create persists every field",
        "repo.create with user id", "row with all values stored",
        f"syntax={row.raw_syntax!r} confirmed={row.admin_confirmed} conf={row.confidence} "
        f"v={row.version} path={row.universal_model_path!r} created_by={row.created_by!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "repositories/knowledge_base.py:96-144 (flush at :142)",
    )
    assert ok


async def test_v06_27_repo_create_without_user_fails_late(kb_db, recorder):
    from app.ai import kb_domain as dom
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)

    async def _attempt_missing_actor(actor, call):
        try:
            await call(actor)
            await session.commit()
            return "committed"
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            # typed domain error, never a raw driver IntegrityError
            return type(exc).__name__ if isinstance(exc, dom.KBError) else "RAW:" + type(exc).__name__

    create_outcome = await _attempt_missing_actor(
        None, lambda actor: repo.create("cisco", "ios", "no-user-cmd", "meaning",
                                        universal_model_path="device.hostname",
                                        actor=actor))
    m = await repo.create("cisco", "ios", "with-user-cmd", "meaning",
                          universal_model_path="device.hostname",
                          actor=str(uid))
    await session.commit()
    update_outcome = await _attempt_missing_actor(
        None, lambda actor: repo.update(mapping_id=str(m.id),
                                        admin_notes="no actor", actor=actor))

    ok = (create_outcome == "KBValidationError"
          and update_outcome == "KBValidationError")
    recorder.add(
        "V06-27", "C",
        "missing-actor writes are rejected with a typed error before any flush "
        "(spec 15.1 created_by/changed_by NOT NULL)",
        "repo.create(actor=None) then repo.update(actor=None)",
        "typed KBValidationError before any flush (never a raw IntegrityError)",
        f"create={create_outcome}; update={update_outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F7: repository validates actors via the canonical domain "
        "contract (uniform with the in-memory twin)",
        "",
    )
    assert ok


async def test_v06_28_repo_lookup_hit_and_miss(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "hostname edge-1", "sets hostname",
                      universal_model_path="device.hostname", actor=str(uid))
    await session.commit()
    hit = await repo.lookup("cisco", "ios", "hostname edge-1")
    miss = await repo.lookup("cisco", "ios", "unknown cmd")
    ok = hit is not None and hit.semantic_meaning == "sets hostname" and miss is None
    recorder.add(
        "V06-28", "C", "repository lookup returns exact hits and None on miss",
        "stored syntax + unknown syntax", "hit with meaning; miss None",
        f"hit={getattr(hit, 'semantic_meaning', None)!r}; miss={miss!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "repositories/knowledge_base.py:44-55 (equality + strip, scalar_one_or_none)",
    )
    assert ok


async def test_v06_29_repo_lookup_case_insensitive(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("Cisco", "IOS", "hostname edge-1", "sets hostname",
                      universal_model_path="device.hostname", actor=str(uid))
    await session.commit()
    got = await repo.lookup("cisco", "ios", "hostname edge-1")
    ok = got is not None
    recorder.add(
        "V06-29", "C", "repository lookup is case-insensitive on vendor/platform",
        "stored 'Cisco'/'IOS', queried 'cisco'/'ios'", "mapping returned",
        f"found={got is not None}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "repositories/knowledge_base.py:45-46 ilike both columns",
    )
    assert ok


async def test_v06_30_unstripped_row_unreachable(kb_db, recorder):
    from sqlalchemy import select

    from app.models import TrainingMapping
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    session.add(TrainingMapping(
        id=uuid.uuid4(), vendor="cisco", platform="ios",
        raw_syntax="hostname edge-sw1 ", semantic_meaning="spaced row",
        universal_model_path="device.hostname",
        confidence=1.0, admin_confirmed=True, version=1, created_by=str(uid),
    ))
    await session.commit()
    repo = KnowledgeBaseRepository(session)
    plain = await repo.lookup("cisco", "ios", "hostname edge-sw1")
    spaced = await repo.lookup("cisco", "ios", "hostname edge-sw1 ")
    stored = (
        await session.execute(select(TrainingMapping.raw_syntax).where(
            TrainingMapping.semantic_meaning == "spaced row"))
    ).scalar_one()
    ok = plain is not None and spaced is not None \
        and plain.id == spaced.id
    recorder.add(
        "V06-30", "C",
        "a stored mapping is reachable by every syntactic variant of its raw_syntax",
        "legacy row stored with trailing space (pre-canonicalization)",
        "lookup finds it for 'hostname edge-sw1' and 'hostname edge-sw1 '",
        f"lookup(plain)={plain is not None}; lookup(spaced)={spaced is not None}; "
        f"stored={stored!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F12: repository compares canonical(trimmed) stored syntax; the "
        "write path canonicalizes and migration 005 reconciles legacy rows",
        "",
    )
    assert ok


async def test_v06_31_duplicate_rows_crash_lookup(kb_db, recorder):
    from sqlalchemy import select

    from app.models import TrainingMapping
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "dup-cmd", "lower meaning",
                      universal_model_path="device.hostname", actor=str(uid))
    session.add(TrainingMapping(
        id=uuid.uuid4(), vendor="Cisco", platform="ios", raw_syntax="dup-cmd",
        semantic_meaning="upper meaning", universal_model_path="device.hostname",
        confidence=1.0, admin_confirmed=True,
        version=1, created_by=str(uid),
    ))
    await session.commit()
    rows = (await session.execute(select(TrainingMapping).where(
        TrainingMapping.raw_syntax == "dup-cmd"))).scalars().all()
    try:
        got = await repo.lookup("cisco", "ios", "dup-cmd")
        outcome = f"ok:{getattr(got, 'semantic_meaning', None)}"
    except Exception as exc:  # noqa: BLE001
        outcome = f"{type(exc).__name__}: {str(exc)[:90]}"
    ok = len(rows) == 2 and outcome.startswith("ok:")
    recorder.add(
        "V06-31", "C",
        "lookup stays total when duplicate rows exist (unique constraint, section 15.1)",
        "two rows differing only in vendor case, queried by name",
        "one deterministic mapping returned, never an unhandled crash",
        f"rows={len(rows)}; outcome={outcome}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F4: canonical equality + earliest-row tiebreak instead of "
        "ilike + scalar_one_or_none; migration 005 reconciles legacy rows",
        "",
    )
    assert ok


def test_v06_32_suggestion_path_is_wired(recorder):
    hits = []
    for py in sorted((BACKEND / "app").rglob("*.py")):
        text = py.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            if "lookup_suggestions" in line and "def lookup_suggestions" not in line:
                hits.append(f"{py.relative_to(BACKEND)}:{i}")
    has_def = any("def lookup_suggestions" in
                  (BACKEND / p).read_text(encoding="utf-8", errors="replace")
                  for p in ("app/ai/knowledge_base.py",
                            "app/repositories/knowledge_base.py"))
    ok = has_def and len(hits) > 0
    recorder.add(
        "V06-32", "C",
        "suggestion-only similarity search exists in both stores and has "
        "callers (section 10.6 'provide lookup for normalization')",
        "all call sites of lookup_suggestions in app/",
        "defined in both stores; called from the hypothesis paths",
        f"defined={has_def}; callers={hits or 'none'}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F2/F5: exact lookup() is authoritative everywhere; "
        "lookup_suggestions() ranks non-authoritative candidates without "
        "mutating storage (supersedes the old uncalled fuzzy_lookup)",
        "",
    )
    assert ok


async def test_v06_33_repo_vs_inmemory_fuzzy_divergence(kb_db, kb, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", SYN_B, "meaning for B",
                      universal_model_path="access_control.rules_count",
                      actor=str(uid))
    await session.commit()
    repo_hit = await repo.lookup("cisco", "ios", SYN_A)

    kb2 = KnowledgeBase()
    kb2.create("cisco", "ios", SYN_B, "meaning for B",
               universal_model_path="access_control.rules_count",
               actor="t")
    mem_hit = kb2.lookup("cisco", "ios", SYN_A)

    ok = repo_hit is None and mem_hit is None
    recorder.add(
        "V06-33", "C",
        "the two knowledge-base implementations answer the same query the same way",
        f"same near-duplicate query",
        "both miss (exact-only contract)",
        f"repo={repo_hit is not None}; in-memory={mem_hit is not None}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F2: exact canonical lookup in both stores; similarity lives in "
        "lookup_suggestions only",
        "",
    )
    assert ok


async def test_v06_34_repo_update_auto_confirms(kb_db, recorder):
    from sqlalchemy import select

    from app.models import TrainingMapping
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    session.add(TrainingMapping(
        id=uuid.uuid4(), vendor="cisco", platform="ios", raw_syntax="mystery cmd",
        semantic_meaning="guess", universal_model_path="device.hostname",
        confidence=0.5, admin_confirmed=False, version=1,
        created_by=str(uid),
    ))
    await session.commit()
    repo = KnowledgeBaseRepository(session)
    m = await repo.update(mapping_id=str((await session.execute(
        select(TrainingMapping.id).where(TrainingMapping.raw_syntax == "mystery cmd")
    )).scalar_one()), admin_notes="note only", actor=str(uid))
    await session.commit()
    ok = m.admin_confirmed is False and m.confidence == 0.5
    recorder.add(
        "V06-34", "C",
        "an edit must not confirm a mapping (section 9.2 step 3 / section 14.3.3)",
        "repo.update(admin_notes only) on an unconfirmed row",
        "stays unconfirmed, confidence unchanged",
        f"after: confirmed={m.admin_confirmed} conf={m.confidence} v={m.version}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F3: update() preserves confirmation state and confidence",
        "",
    )
    assert ok


async def test_v06_35_repo_update_appends_version_record(kb_db, recorder):
    from sqlalchemy import select

    from app.models import MappingVersion
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    m = await repo.create("cisco", "ios", "cmd v", "v1 meaning",
                          universal_model_path="device.hostname",
                          actor=str(uid))
    await session.commit()
    await repo.update(mapping_id=str(m.id), semantic_meaning="v2 meaning",
                      actor=str(uid))
    await session.commit()
    versions = list((await session.execute(select(MappingVersion).where(
        MappingVersion.mapping_id == m.id))).scalars().all())
    ordered = sorted(versions, key=lambda v: v.version)
    ok = (
        len(ordered) == 2
        and ordered[0].version == 1
        and ordered[0].semantic_meaning == "v1 meaning"
        and ordered[1].version == 2
        and ordered[1].semantic_meaning == "v2 meaning"
        and ordered[1].changed_by == str(uid)
    )
    recorder.add(
        "V06-35", "C", "update() appends a post-change version record (section 15.2 step 3d)",
        "create then update meaning v1 -> v2",
        "v1 initial + v2 post-change records naming the acting user",
        f"records={[(v.version, v.semantic_meaning, str(v.changed_by)) for v in ordered]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F7: one post-change convention everywhere (supersedes the old "
        "pre-change snapshot; see V06-69)",
        "",
    )
    assert ok


async def test_v06_36_list_default_limit_truncates(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    from sqlalchemy import delete

    from app.models import TrainingMapping

    await session.execute(delete(TrainingMapping))
    await session.commit()
    for i in range(105):
        session.add(TrainingMapping(
            id=uuid.uuid4(), vendor="cisco", platform="ios", raw_syntax=f"cmd-{i}",
            semantic_meaning=f"m{i}", universal_model_path="device.hostname",
            confidence=1.0, admin_confirmed=True, version=1,
            created_by=str(uid),
        ))
    await session.commit()
    listed = await repo.list_mappings()
    total = await repo.count_mappings()
    mem = KnowledgeBase()
    for i in range(105):
        mem.create("cisco", "ios", f"cmd-{i}", f"m{i}",
                   universal_model_path="device.hostname", actor="t")
    mem_listed = len(mem.list_mappings())
    ok = total == 105 and len(listed) == 105 and mem_listed == 105
    recorder.add(
        "V06-36", "C",
        "both implementations return the same rows for an unfiltered list",
        "105 mappings, list() with no arguments",
        "105 rows from both (no silent truncation)",
        f"repo total={total} returned={len(listed)}; "
        f"in-memory returned={mem_listed}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F2: repository has no default cap; in-memory returns all",
        "",
    )
    assert ok


async def test_v06_37_repo_count_filters(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "a", "A",
                      universal_model_path="device.hostname", actor=str(uid))
    await repo.create("cisco", "ios", "b", "B",
                      universal_model_path="device.hostname", actor=str(uid),
                      admin_confirmed=False)
    await repo.create("juniper", "junos", "c", "C",
                      universal_model_path="device.hostname", actor=str(uid))
    await session.commit()
    total = await repo.count_mappings()
    vendor = await repo.count_mappings(vendor="cisco")
    confirmed = await repo.count_mappings(confirmed_only=True)
    ok = total == 3 and vendor == 2 and confirmed == 2
    recorder.add(
        "V06-37", "C", "count_mappings honours vendor/platform/confirmed filters",
        "3 mappings", "3 / 2 / 2",
        f"total={total} vendor={vendor} confirmed={confirmed}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "repositories/knowledge_base.py:236-257",
    )
    assert ok


async def test_v06_38_repo_stats_shape(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "a", "A",
                      universal_model_path="device.hostname", actor=str(uid))
    await repo.create("juniper", "junos", "b", "B",
                      universal_model_path="device.hostname", actor=str(uid),
                      admin_confirmed=False)
    await session.commit()
    stats = await repo.get_stats()
    ok = (
        stats["total_mappings"] == 2
        and stats["confirmed_mappings"] == 1
        and stats["pending_mappings"] == 1
        and sorted(stats["vendors"]) == ["cisco", "juniper"]
        and set(stats) == {"total_mappings", "confirmed_mappings", "pending_mappings",
                           "vendors", "platforms"}
    )
    recorder.add(
        "V06-38", "C", "repository get_stats has the same shape and values as the in-memory twin",
        "2 mappings", "total=2 confirmed=1 pending=1, same 5 keys",
        f"stats={stats}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "repositories/knowledge_base.py:259-279 vs knowledge_base.py:268-279",
    )
    assert ok


# ==========================================================================
# D - REST API (app/api/v1/training.py) called directly with a real session
# ==========================================================================


async def test_v06_39_post_create_full_contract(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import MappingVersion
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    # Default: a stored proposal (unconfirmed, hypothesis estimate) - it
    # enters the review queue and is NOT auto-reused.
    proposal = await api.create_mapping(
        mapping=TrainingMappingCreate(
            vendor="cisco", platform="ios", raw_syntax="ntp server 1.1.1.1",
            semantic_meaning="upstream NTP", universal_model_path="ntp.servers",
        ),
        db=session, current_user=admin,
    )
    # Explicit administrator assertion: confirmed, full trust.
    asserted = await api.create_mapping(
        mapping=TrainingMappingCreate(
            vendor="cisco", platform="ios", raw_syntax="ntp server 2.2.2.2",
            semantic_meaning="upstream NTP", universal_model_path="ntp.servers",
            admin_confirmed=True,
        ),
        db=session, current_user=admin,
    )
    await session.commit()
    versions = list((await session.execute(select(MappingVersion).where(
        MappingVersion.mapping_id.in_([proposal.id, asserted.id]))
        .order_by(MappingVersion.mapping_id, MappingVersion.version))).scalars().all())
    per_mapping = {}
    for v in versions:
        per_mapping.setdefault(str(v.mapping_id), []).append(
            (v.version, v.change_reason))
    ok = (
        proposal.version == 1 and proposal.admin_confirmed is False
        and proposal.confidence == 0.5
        and asserted.version == 1 and asserted.admin_confirmed is True
        and asserted.confidence == 1.0
        and all(recs == [(1, "Initial creation")]
                for recs in per_mapping.values()) and len(per_mapping) == 2
    )
    recorder.add(
        "V06-39", "D",
        "POST /training/mappings stores a version-1 mapping with an initial version "
        "record; trust depends on what the administrator asserted (section 9.2 step 4, "
        "section 14.3.2 review routing)",
        "POST default, then POST with admin_confirmed=True",
        "proposal: v1, confirmed=False, conf=0.5; asserted: v1, confirmed=True, "
        "conf=1.0; one v1 record each",
        f"proposal: v={proposal.version} confirmed={proposal.admin_confirmed} "
        f"conf={proposal.confidence}; asserted: v={asserted.version} "
        f"confirmed={asserted.admin_confirmed} conf={asserted.confidence}; "
        f"records={per_mapping}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F10: TrainingMappingCreate.admin_confirmed defaults False "
        "(hypothesis estimate 0.5 < 0.7 trust threshold); an explicit "
        "administrator assertion stores confirmed/1.0; both write the v1 "
        "post-change record (training.py create_mapping + repositories create)",
        "",
    )
    assert ok


async def test_v06_40_post_exact_duplicate_409(kb_db, recorder):
    from fastapi import HTTPException

    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    payload = dict(vendor="cisco", platform="ios", raw_syntax="ntp server 1.1.1.1",
                   semantic_meaning="first",
                   universal_model_path="ntp.servers")
    await api.create_mapping(mapping=TrainingMappingCreate(**payload), db=session,
                             current_user=admin)
    await session.commit()
    try:
        await api.create_mapping(
            mapping=TrainingMappingCreate(**{**payload, "semantic_meaning": "second"}),
            db=session, current_user=admin,
        )
        await session.commit()
        outcome = "created"
    except HTTPException as exc:
        await session.rollback()
        outcome = f"HTTPException {exc.status_code}"
    ok = outcome == "HTTPException 409"
    recorder.add(
        "V06-40", "D", "POST rejects an identical vendor/platform/raw_syntax with 409",
        "same payload twice", "409 CONFLICT", f"outcome={outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "training.py:81-94 exact equality duplicate check",
    )
    assert ok


async def test_v06_41_post_case_variant_duplicate_then_lookup_crashes(kb_db, recorder):
    from fastapi import HTTPException

    from app.api.v1 import training as api
    from app.repositories.knowledge_base import KnowledgeBaseRepository
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="hostname edge-1", semantic_meaning="a",
                                      universal_model_path="device.hostname",
                                      admin_confirmed=True),
        db=session, current_user=admin,
    )
    await session.commit()
    try:
        await api.create_mapping(
            mapping=TrainingMappingCreate(vendor="Cisco", platform="ios",
                                          raw_syntax="hostname edge-1", semantic_meaning="b",
                                          universal_model_path="device.hostname",
                                          admin_confirmed=True),
            db=session, current_user=admin,
        )
        await session.commit()
        outcome = "created"
    except HTTPException as exc:
        await session.rollback()
        outcome = f"HTTPException {exc.status_code}"
    repo = KnowledgeBaseRepository(session)
    got = await repo.lookup("cisco", "ios", "hostname edge-1")
    ok = outcome == "HTTPException 409" and got is not None \
        and got.semantic_meaning == "a"
    recorder.add(
        "V06-41", "D",
        "duplicates cannot be created in a form that later crashes lookup",
        "POST with vendor 'cisco' then 'Cisco' (same syntax)",
        "second POST rejected with 409; lookup stays total",
        f"second POST outcome={outcome}; lookup meaning={getattr(got, 'semantic_meaning', None)!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F4: canonical identity on write + lookup; UNIQUE constraint "
        "as the backstop",
        "",
    )
    assert ok


async def test_v06_42_post_unvalidated_model_path(kb_db, recorder):
    from fastapi import HTTPException

    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, _, admin = kb_db
    try:
        await api.create_mapping(
            mapping=TrainingMappingCreate(
                vendor="cisco", platform="ios", raw_syntax="mystery cmd",
                semantic_meaning="whatever", universal_model_path="does.not.exist.in.model",
            ),
            db=session, current_user=admin,
        )
        await session.commit()
        outcome = "created"
    except HTTPException as exc:
        await session.rollback()
        outcome = f"HTTPException {exc.status_code}"
    repo = KnowledgeBaseRepository(session)
    stored = await repo.lookup("cisco", "ios", "mystery cmd")
    ok = outcome == "HTTPException 422" and stored is None
    recorder.add(
        "V06-42", "D",
        "universal_model_path is validated against the Universal Security Model before storage "
        "(section 12 interface: it is a model path; section 15.2 step 4)",
        "POST with universal_model_path='does.not.exist.in.model'",
        "422 rejection; nothing stored",
        f"outcome={outcome}; stored={stored!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F9: canonical domain validation at the API boundary",
        "",
    )
    assert ok


async def test_v06_43_post_empty_raw_syntax(kb_db, recorder):
    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    try:
        resp = await api.create_mapping(
            mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                          raw_syntax="", semantic_meaning="empty syntax"),
            db=session, current_user=admin,
        )
        await session.commit()
        outcome = f"created v{resp.version}"
    except Exception as exc:  # noqa: BLE001
        await session.rollback()
        outcome = type(exc).__name__
    ok = outcome in ("ValidationError", "HTTPException")
    recorder.add(
        "V06-43", "D",
        "POST rejects a mapping whose raw_syntax is the empty string",
        "raw_syntax=''", "422 (validation error)",
        f"outcome={outcome}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "schemas TrainingMappingCreate min_length=1 (FastAPI 422); "
        "service-level empty rejection as defense in depth",
        "",
    )
    assert ok


def test_v06_44_post_vendor_length_guarded(recorder):
    from pydantic import ValidationError

    from app.schemas import TrainingMappingCreate

    try:
        TrainingMappingCreate(vendor="v" * 51, platform="ios", raw_syntax="x",
                              semantic_meaning="y")
        outcome = "accepted"
    except ValidationError:
        outcome = "ValidationError"
    ok = outcome == "ValidationError"
    recorder.add(
        "V06-44", "D",
        "vendor longer than the section 15.1 VARCHAR(50) is rejected at the schema boundary",
        "vendor of 51 characters", "ValidationError (FastAPI 422)", f"outcome={outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "schemas/__init__.py:343 max_length=50",
    )
    assert ok


async def test_v06_45_put_noop_creates_phantom_version(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import MappingVersion, TrainingMapping
    from app.schemas import TrainingMappingCreate, TrainingMappingUpdate

    session, _, admin = kb_db
    created = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="cmd", semantic_meaning="meaning",
                                      universal_model_path="device.hostname"),
        db=session, current_user=admin,
    )
    await session.commit()
    await api.update_mapping(mapping_id=created.id, mapping_update=TrainingMappingUpdate(),
                             db=session, current_user=admin)
    await session.commit()
    version = (await session.execute(select(TrainingMapping.version).where(
        TrainingMapping.id == created.id))).scalar()
    records = list((await session.execute(select(MappingVersion).where(
        MappingVersion.mapping_id == created.id))).scalars().all())
    ok = version == 1 and len(records) == 1
    recorder.add(
        "V06-45", "D",
        "PUT with no changed fields must not create a version (a version records a change)",
        "PUT with an empty TrainingMappingUpdate",
        "version stays 1, no new record",
        f"version={version}; records={[(v.version, v.change_reason) for v in records]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F7: no-op writes bump nothing and record nothing",
        "",
    )
    assert ok


async def test_v06_46_put_change_recorded(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import MappingVersion
    from app.schemas import TrainingMappingCreate, TrainingMappingUpdate

    session, _, admin = kb_db
    created = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="cmd", semantic_meaning="old",
                                      universal_model_path="device.hostname"),
        db=session, current_user=admin,
    )
    await session.commit()
    await api.update_mapping(
        mapping_id=created.id,
        mapping_update=TrainingMappingUpdate(semantic_meaning="new", change_reason="fix"),
        db=session, current_user=admin,
    )
    await session.commit()
    records = list((await session.execute(select(MappingVersion).where(
        MappingVersion.mapping_id == created.id).order_by(MappingVersion.version))).scalars())
    ok = (
        len(records) == 2
        and records[-1].version == 2
        and records[-1].semantic_meaning == "new"
        and records[-1].change_reason == "fix"
    )
    recorder.add(
        "V06-46", "D", "PUT records the change with reason in version history",
        "PUT meaning old->new", "record v2 with new meaning + reason",
        f"records={[(v.version, v.semantic_meaning, v.change_reason) for v in records]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "training.py:170-187",
    )
    assert ok


async def test_v06_47_put_does_not_confirm(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import TrainingMapping
    from app.schemas import TrainingMappingUpdate

    session, uid, admin = kb_db
    row_id = uuid.uuid4()
    session.add(TrainingMapping(
        id=row_id, vendor="cisco", platform="ios", raw_syntax="mystery",
        semantic_meaning="guess", universal_model_path="device.hostname",
        confidence=0.5, admin_confirmed=False, version=1,
        created_by=str(uid),
    ))
    await session.commit()
    await api.update_mapping(
        mapping_id=row_id,
        mapping_update=TrainingMappingUpdate(admin_notes="edit only"),
        db=session, current_user=admin,
    )
    await session.commit()
    row = (await session.execute(select(TrainingMapping).where(
        TrainingMapping.id == row_id))).scalar_one()
    ok = row.admin_confirmed is False and row.confidence == 0.5
    recorder.add(
        "V06-47", "D",
        "PUT (EDIT) does not confirm an unconfirmed mapping (section 9.2 step 3)",
        "PUT admin_notes on an unconfirmed row",
        "stays unconfirmed, confidence unchanged",
        f"confirmed={row.admin_confirmed} conf={row.confidence}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "training.py:164-168 only sets schema fields (semantic_meaning, "
        "universal_model_path, admin_notes) - contrasts with both repository twins (F-71)",
    )
    assert ok


async def test_v06_48_confirm_endpoint_full_contract(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import AuditTrail, MappingVersion
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    created = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="ntp server 1.1.1.1",
                                      semantic_meaning="upstream NTP",
                                      universal_model_path="ntp.servers"),
        db=session, current_user=admin,
    )
    await session.commit()
    conf = await api.confirm_mapping(mapping_id=created.id, db=session, current_user=admin)
    await session.commit()
    records = list((await session.execute(select(MappingVersion).where(
        MappingVersion.mapping_id == created.id))).scalars())
    audits = list((await session.execute(select(AuditTrail))).scalars())
    ok = (
        conf.admin_confirmed is True and conf.confidence == 1.0 and conf.version == 2
        and len(records) == 2 and records[-1].change_reason == "Admin confirmation"
        and any(a.action == "mapping_confirmed" for a in audits)
    )
    recorder.add(
        "V06-48", "D",
        "confirm: confirmed=True, confidence 1.0, version bump, version record, audit row "
        "(section 14.3.4 audit trail; section 15.2 step 3c)",
        "POST /mappings/{id}/confirm",
        "v2 + 'Admin confirmation' record + mapping_confirmed audit row",
        f"v={conf.version} confirmed={conf.admin_confirmed}; "
        f"records={[(v.version, v.change_reason) for v in records]}; "
        f"audit actions={[a.action for a in audits]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "training.py:334-406 (fields :363-371, record :374-383, audit :390-403)",
    )
    assert ok


async def test_v06_49_reject_unconfirms_and_notes(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import TrainingMapping
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    created = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="cmd", semantic_meaning="m",
                                      universal_model_path="device.hostname"),
        db=session, current_user=admin,
    )
    await session.commit()
    await api.reject_mapping(mapping_id=created.id, reason="wrong", db=session,
                             current_user=admin)
    await session.commit()
    row = (await session.execute(select(TrainingMapping).where(
        TrainingMapping.id == created.id))).scalar_one()
    ok = row.admin_confirmed is False and (row.admin_notes or "").startswith("REJECTED:")
    recorder.add(
        "V06-49", "D", "REJECT marks the mapping unconfirmed with a REJECTED note",
        "POST /mappings/{id}/reject reason='wrong'",
        "confirmed=False, notes start with REJECTED:",
        f"confirmed={row.admin_confirmed} notes={row.admin_notes!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "training.py:445-447 (row is kept, not deleted)",
    )
    assert ok


async def test_v06_50_reject_creates_no_version_record(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import MappingVersion, TrainingMapping
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    created = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="cmd", semantic_meaning="m",
                                      universal_model_path="device.hostname"),
        db=session, current_user=admin,
    )
    await session.commit()
    before = len(list((await session.execute(select(MappingVersion).where(
        MappingVersion.mapping_id == created.id))).scalars()))
    await api.reject_mapping(mapping_id=created.id, db=session, current_user=admin)
    await session.commit()
    after_rows = list((await session.execute(select(MappingVersion).where(
        MappingVersion.mapping_id == created.id))).scalars())
    reasons = [v.change_reason for v in after_rows]
    row_v = (await session.execute(select(TrainingMapping.version).where(
        TrainingMapping.id == created.id))).scalar()
    ok = len(after_rows) == before + 1 and row_v == 2 \
        and any((r or "").startswith("Admin rejection") for r in reasons)
    recorder.add(
        "V06-50", "D",
        "every state change is versioned (section 9.2 step 4 'Version the mapping'; "
        "section 15.2 step 3d)",
        "reject after create", "a new version record for the rejection",
        f"records before={before} after={len(after_rows)} row version={row_v}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F7: reject bumps the version and appends a post-change record "
        "like every other mutation",
        "",
    )
    assert ok


async def test_v06_51_reject_audit_row(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import AuditTrail
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    created = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="cmd", semantic_meaning="m",
                                      universal_model_path="device.hostname"),
        db=session, current_user=admin,
    )
    await session.commit()
    await api.reject_mapping(mapping_id=created.id, reason="bad", db=session,
                             current_user=admin)
    await session.commit()
    audits = list((await session.execute(select(AuditTrail))).scalars())
    ok = any(a.action == "mapping_rejected" for a in audits)
    recorder.add(
        "V06-51", "D", "REJECT is audit-logged (section 14.3.4)",
        "reject with reason", "mapping_rejected audit row",
        f"actions={[a.action for a in audits]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "training.py:430-443",
    )
    assert ok


def test_v06_52_no_admin_role_enforcement(recorder):
    text = src("app/api/v1/training.py")
    uses_role = "require_admin" in text or "require_auditor" in text or "require_role" in text
    auth_available = "require_admin = require_role" in src("app/security/auth.py")
    convention = "Depends(require_auditor)" in src("app/api/v1/configurations.py") and \
        "Depends(require_admin)" in src("app/api/v1/configurations.py")
    spec_admin = "Support administrator updates" in spec_text() and \
        "Admin confirms/edits/rejects" in spec_text()
    defect = spec_admin and auth_available and convention and not uses_role
    ok = not defect
    recorder.add(
        "V06-52", "D",
        "training endpoints require an administrator (section 10.6 'administrator updates'; "
        "section 14.1 admin confirms/rejects; section 15.2 step 3c)",
        "all 8 endpoints in training.py",
        "Depends(require_admin) on every state-changing endpoint",
        f"uses role dependency={uses_role}; require_admin exists={auth_available}; "
        f"sibling router uses roles={convention}; spec requires admin={spec_admin}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F6: training.py create/update/confirm/reject depend on "
        "require_admin; read-only list/get/versions/hypothesis stay "
        "authenticated (get_current_user)",
        "",
    )
    assert ok


def test_v06_53_get_list_case_filter_diverges(recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository  # noqa: F401

    text = src("app/api/v1/training.py")
    delegates = "repo.list_mappings" in text or "repository.list_mappings" in text
    no_inline_ilike = "TrainingMapping.vendor.ilike" not in text
    no_exact_only = "TrainingMapping.vendor == vendor" not in text
    ok = delegates and no_inline_ilike and no_exact_only
    recorder.add(
        "V06-53", "D",
        "GET /training/mappings?vendor= uses the same case handling as lookup",
        "list filter vs lookup filter",
        "both canonical (case-insensitive, literal): API delegates to the repository",
        f"delegates to repository={delegates}; no inline ilike={no_inline_ilike}; "
        f"no inline exact =={no_exact_only}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F2/F13: training.py list delegates filtering to "
        "KnowledgeBaseRepository (canonical ==, literal %/_)",
        "",
    )
    assert ok


def test_v06_54_input_schemas_exclude_trust_fields(recorder):
    from app.schemas import TrainingMappingCreate, TrainingMappingUpdate

    create_fields = set(TrainingMappingCreate.model_fields)
    update_fields = set(TrainingMappingUpdate.model_fields)
    # Trust elevation stays server-side: version/id/created_by are never
    # client-settable; admin_confirmed is an explicit, admin-gated creation
    # flag (default True); confidence is an optional validated ESTIMATE
    # (0.0-1.0), never an authoritative override.
    forbidden = {"version", "id", "created_by"}
    bad_create = (create_fields & forbidden) | ({"admin_confirmed"} - create_fields)
    bad_update = (update_fields & (forbidden | {"admin_confirmed", "confidence"}))
    conf = TrainingMappingCreate.model_fields["confidence"]
    bounds = {k: v for m in conf.metadata
              for k, v in (("ge", getattr(m, "ge", None)),
                           ("le", getattr(m, "le", None))) if v is not None}
    conf_ok = (not conf.is_required()) and bounds.get("ge") == 0.0 \
        and bounds.get("le") == 1.0
    ok = not bad_create and not bad_update and conf_ok
    recorder.add(
        "V06-54", "D",
        "clients cannot set trust fields (version/id/created_by) through the API; "
        "confidence is an optional validated estimate",
        f"Create fields={sorted(create_fields)}; Update={sorted(update_fields)}",
        "no forbidden field accepted; confidence optional in [0,1] on Create only",
        f"bad_create={sorted(bad_create)} bad_update={sorted(bad_update)} "
        f"confidence_ranged={conf_ok}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "schemas/__init__.py TrainingMappingCreate/Update (E06 F10: estimated "
        "confidence accepted on create; elevation stays admin-gated)",
        "",
    )
    assert ok


async def test_v06_55_hypothesis_kb_hit_offline(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import AuditTrail
    from app.repositories.knowledge_base import KnowledgeBaseRepository
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    resp = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="mystery cmd", semantic_meaning="it does X",
                                      universal_model_path="ntp.servers",
                                      admin_confirmed=True),
        db=session, current_user=admin,
    )
    await session.commit()
    resp = await api.get_ai_hypothesis(vendor="cisco", platform="ios",
                                       raw_syntax="mystery cmd", db=session,
                                       current_user=admin)
    await session.commit()
    audits = list((await session.execute(select(AuditTrail))).scalars())
    ok = (
        resp.suggested_meaning == "it does X"
        and resp.universal_model_path == "ntp.servers"
        and any(a.action == "ai_hypothesis_received" for a in audits)
    )
    recorder.add(
        "V06-55", "D",
        "/training/hypothesis serves a confirmed KB mapping without contacting AI "
        "(section 14.3.5 fallback; section 15.2 step 2)",
        "POST /hypothesis for a stored syntax, AI unavailable",
        "meaning + model path returned from KB, audit row written",
        f"meaning={resp.suggested_meaning!r} path={resp.universal_model_path!r}; "
        f"audit actions={[a.action for a in audits]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "training.py:254-287 KB check short-circuits before create_ai_client(); audit at :263-275",
    )
    assert ok


def test_v06_56_kb_hit_security_relevance_hardcoded(recorder):
    text = src("app/api/v1/training.py")
    hardcoded_literal = 'security_relevance="medium"' in text
    derived = "relevance_for_path" in text
    ok = not hardcoded_literal and derived
    recorder.add(
        "V06-56", "D",
        "a KB-served hypothesis carries the mapping's own security relevance, not a constant",
        "KB-hit response", "relevance derived from the mapping's model path",
        f"hardcoded 'medium' literal={hardcoded_literal}; "
        f"model-derived relevance={derived}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E06 F15: training.py + adaptive.py derive relevance from the "
        "mapping's universal_model_path via the canonical domain helper "
        "(documented 'medium' fallback only when no valid path exists)",
        "",
    )
    assert ok


# ==========================================================================
# E - Workflow contract (section 9.2 five-step loop, section 14.3, section 15.3)
# ==========================================================================


def test_v06_57_confirm_edit_reject_endpoints_exist(recorder):
    text = src("app/api/v1/training.py")
    routes = ["@router.post", "@router.put", "confirm", "reject", "hypothesis"]
    present = {r: (r in text) for r in routes}
    ok = all(present.values())
    recorder.add(
        "V06-57", "E",
        "the administrator workflow (CONFIRM / EDIT / REJECT) has API endpoints "
        "(section 14.3.1-3)",
        "training.py routes", "all three actions routable",
        f"present={present}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "training.py:196 (PUT), :341 (confirm), :414 (reject)",
    )
    assert ok


async def test_v06_58_confirm_persists_versioned_vendor_row(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import MappingVersion, TrainingMapping
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    created = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="confirm me", semantic_meaning="m",
                                      universal_model_path="device.hostname"),
        db=session, current_user=admin,
    )
    await session.commit()
    await api.confirm_mapping(mapping_id=created.id, db=session, current_user=admin)
    await session.commit()
    row = (await session.execute(select(TrainingMapping).where(
        TrainingMapping.id == created.id))).scalar_one()
    versions = len(list((await session.execute(select(MappingVersion).where(
        MappingVersion.mapping_id == created.id))).scalars()))
    ok = row.admin_confirmed and row.vendor and versions == 2
    recorder.add(
        "V06-58", "E",
        "confirmed mappings are stored with vendor + version (section 9.2 step 4-5: "
        "reusable mapping)",
        "create + confirm", "row confirmed with version history",
        f"confirmed={row.admin_confirmed} vendor={row.vendor!r} version_records={versions}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "training.py:363-383",
    )
    assert ok


def test_v06_59_step5_normalization_rerun_absent(recorder):
    kb_refs = []
    for py in sorted((BACKEND / "app").rglob("*.py")):
        text = py.read_text(encoding="utf-8", errors="replace")
        if "knowledge_base" in text or "KnowledgeBase" in text:
            kb_refs.append(py.name)
    norm_refs = "normalization.py" in kb_refs
    sem_refs = "semantic.py" in kb_refs
    adaptive_refs = "adaptive.py" in kb_refs
    ok = norm_refs and sem_refs and adaptive_refs
    recorder.add(
        "V06-59", "E",
        "section 9.2 step 5: after a mapping is confirmed, normalization re-runs against "
        "the updated knowledge base (project's own spec contract)",
        "KB references across app/",
        "normalization.py, semantic.py and adaptive.py all consult the KB",
        f"app/ modules referencing the KB={kb_refs or 'none'}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F1: NormalizationEngine.normalize(knowledge_base=...) applies "
        "confirmed mappings; SemanticAnalyzer.analyze(knowledge_base=...) "
        "resolves unknowns; AdaptiveLearningEngine orchestrates re-analysis",
        "",
    )
    assert ok


def test_v06_60_step5_compliance_rerun_absent(recorder):
    text = src("app/api/v1/training.py")
    has_reanalyze = "reanalyze" in text and "AdaptiveLearningEngine" in text
    norm_hook = "knowledge_base" in src("app/engines/normalization.py")
    ok = has_reanalyze and norm_hook
    recorder.add(
        "V06-60", "E",
        "section 9.2 step 5: compliance results are re-run after a mapping update",
        "confirm/reject endpoint follow-on + reanalyze endpoint",
        "a re-analysis path applying confirmed mappings end to end",
        f"reanalyze endpoint with adaptive orchestration={has_reanalyze}; "
        f"normalization KB hook={norm_hook}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F1/§24: POST /training/mappings/{id}/reanalyze re-runs semantic "
        "analysis + normalization with the confirmed mapping active; audit "
        "re-execution (compliance) uses the existing audit orchestration",
        "",
    )
    assert ok


def test_v06_61_audit_ai_io_both_branches_logged(recorder):
    text = src("app/api/v1/training.py")
    has_input = "log_ai_interaction" in text
    both = text.count("log_ai_interaction") >= 2
    spec_clause = "audit AI inputs and outputs" in spec_text() or \
        "audit trail" in spec_text().lower()
    ok = spec_clause and has_input and both
    recorder.add(
        "V06-61", "E",
        "section 14.3.4: AI inputs and outputs are written to the audit trail, both when "
        "AI succeeds and when it falls back",
        "training.py /hypothesis branches", "log_ai_interaction in both branches",
        f"calls={text.count('log_ai_interaction')}; spec clause present={spec_clause}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "training.py:263 (KB branch) and :299 (AI branch); helper at :305-331",
    )
    assert ok


def test_v06_62_quality_scoring_absent(recorder):
    from app.ai import kb_domain as dom

    kb = KnowledgeBase()
    new = kb.create("cisco", "ios", "q-new", "new meaning",
                    universal_model_path="device.hostname",
                    admin_confirmed=False, actor="t")
    q_new = kb.quality(new.id)
    conf = kb.create("cisco", "ios", "q-conf", "conf meaning",
                     universal_model_path="device.hostname", actor="t")
    kb.confirm(conf.id, actor="t")
    q_conf = kb.quality(conf.id)
    kb.update(mapping_id=conf.id, admin_notes="edit", actor="t")
    kb.update(mapping_id=conf.id, admin_notes="edit2", actor="t")
    q_edited = kb.quality(conf.id)
    kb.reject(conf.id, actor="t", reason="bad")
    q_rejected = kb.quality(conf.id)
    ok = (
        q_new["score"] < q_conf["score"]
        and q_edited["score"] >= q_conf["score"]
        and q_rejected["score"] < q_conf["score"]
        and set(q_conf) == {"score", "axes"}
        and set(q_conf["axes"]) == {"confirmations", "consistency",
                                    "history", "ai_confidence_at_creation"}
    )
    recorder.add(
        "V06-62", "E",
        "section 15.3: mappings are quality-scored on the four spec axes (admin "
        "confirmations, consistency, age/version history, AI confidence at creation)",
        "new vs confirmed vs edited vs rejected mappings",
        "confirmed > new; edited non-decreasing; rejected drops",
        f"new={q_new['score']} confirmed={q_conf['score']} "
        f"edited={q_edited['score']} rejected={q_rejected['score']}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F11: app/ai/kb_domain.quality_score (deterministic weights "
        "documented in the report; no wall clock)",
        "",
    )
    assert ok


async def test_v06_106_quality_three_way_drift(kb_db, recorder):
    """§15.3 quality must come out of the same domain function in all three
    implementations - one contract, no drift."""
    from app.repositories.knowledge_base import KnowledgeBaseRepository
    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    actor = str(await _first_user_id(session))

    # in-memory twin
    kb = KnowledgeBase()
    mem = kb.create("cisco", "ios", "drift-q", "sets the hostname",
                    universal_model_path="device.hostname", actor="admin-1")
    mem_confirmed = kb.quality(mem.id)
    kb.confirm(mem.id, actor="admin-1")
    mem_after_confirm = kb.quality(mem.id)

    # SQL store
    repo = KnowledgeBaseRepository(session)
    row = await repo.create("juniper", "junos", "drift-q", "sets the hostname",
                            universal_model_path="device.hostname", actor=actor)
    await session.commit()
    sql_new = await repo.quality(row.id)
    await repo.confirm(row.id, actor=actor)
    await session.commit()
    sql_confirmed = await repo.quality(row.id)

    # HTTP API: the same facts through the admin endpoint
    api_row = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="arista", platform="eos",
                                      raw_syntax="drift-q",
                                      semantic_meaning="sets the hostname",
                                      universal_model_path="device.hostname",
                                      admin_confirmed=True),
        db=session, current_user=admin,
    )
    await session.commit()
    api_confirmed = (await repo.quality(str(api_row.id))
                     if api_row.admin_confirmed else {})

    ok = (
        mem_confirmed["score"] == sql_new["score"] == api_confirmed["score"]
        and mem_after_confirm["score"] == sql_confirmed["score"]
        and set(mem_confirmed["axes"]) == set(sql_new["axes"]) == {
            "confirmations", "consistency", "history", "ai_confidence_at_creation"}
        and hasattr(repo, "quality") and hasattr(api, "confirm_mapping")
    )
    recorder.add(
        "V06-106", "F",
        "the §15.3 quality score is identical in the in-memory store, the SQL "
        "store and the API path (one contract, no drift)",
        "score a new mapping and a confirmed mapping through all three layers",
        "identical score and identical axis set for identical recorded facts",
        f"memory new/confirmed={mem_confirmed['score']}/{mem_after_confirm['score']}; "
        f"repo new/confirmed={sql_new['score']}/{sql_confirmed['score']}; "
        f"api confirmed={api_confirmed.get('score')}; "
        f"axes={sorted(mem_confirmed['axes'])}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F11/F2: KnowledgeBaseRepository.quality and KnowledgeBase.quality "
        "both delegate to kb_domain.quality_score with the same four recorded "
        "fact axes (confirmations, consistency, history, ai_confidence_at_creation)",
        "",
    )
    assert ok


def test_v06_63_ai_confidence_never_persisted(recorder):
    from app.schemas import TrainingMappingCreate, TrainingMappingUpdate

    text = src("app/api/v1/training.py")
    schema_accepts = "confidence" in TrainingMappingCreate.model_fields
    schema_update_clean = "confidence" not in TrainingMappingUpdate.model_fields
    model_has = "confidence" in src("app/models/__init__.py")
    no_hardcode = "confidence=1.0" not in text
    ok = model_has and schema_accepts and schema_update_clean and no_hardcode
    recorder.add(
        "V06-63", "E",
        "an AI hypothesis's confidence is stored when the mapping is created from it "
        "(section 15.1 confidence column; section 14.1 'Estimate confidence'; "
        "section 15.3 axis 'AI confidence at creation')",
        "hypothesis -> POST /training/mappings flow",
        "confidence accepted as an estimate on create, preserved on confirm",
        f"model has confidence column={model_has}; Create schema accepts "
        f"confidence={schema_accepts}; Update schema clean={schema_update_clean}; "
        f"POST hardcode removed={no_hardcode}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F10: schemas accept an optional estimate; confirm() preserves "
        "the stored estimate (never fabricates 1.0); update_confidence() "
        "versions estimate changes",
        "",
    )
    assert ok


def test_v06_64_no_confidence_update_method(recorder):
    text = src("app/ai/knowledge_base.py") + src("app/repositories/knowledge_base.py")
    present = "def update_confidence" in text
    kb = KnowledgeBase()
    m = kb.create("cisco", "ios", "conf-cmd", "m",
                  universal_model_path="device.hostname", actor="t")
    v0, c0 = m.version, m.confidence
    kb.update_confidence(m.id, 0.72, actor="t", reason="new evidence")
    versions = kb.get_versions(m.id)
    ok = present and v0 == 1 and c0 == 1.0 and m.version == 2 \
        and m.confidence == 0.72 and len(versions) == 2 \
        and versions[-1].change_reason == "new evidence"
    recorder.add(
        "V06-64", "E",
        "the knowledge base can update a mapping's confidence as evidence accumulates",
        "update_confidence(0.72) on a confirmed mapping",
        "versioned confidence change with reason",
        f"present={present}; v{v0}/{c0} -> v{m.version}/{m.confidence}; "
        f"records={len(versions)}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E06 F10: update_confidence() in both stores (versioned, actor, reason)",
        "",
    )
    assert ok


def test_v06_65_no_unknowns_review_endpoint(recorder):
    from app.schemas import TrainingMappingCreate

    text = src("app/api/v1/training.py")
    list_block = text.split("async def list_mappings")[1].split("async def ")[0]
    create_block = text.split("async def create_mapping")[1].split("async def ")[0]
    hypothesis_block = (text.split("async def get_ai_hypothesis")[1]
                        .split("async def ")[0])
    has_confirmed_filter = "confirmed" in list_block
    has_confidence_filter = "confidence_min" in list_block and "confidence_max" in list_block
    # POST must pass the client's flag through, not hard-force confirmation.
    post_forces_confirmed = "admin_confirmed=True" in create_block
    post_passes_flag = "admin_confirmed=mapping.admin_confirmed" in create_block
    # A stored proposal starts unconfirmed (spec 14.3.2: low confidence ->
    # REVIEW), so the review queue is reachable instead of empty.
    create_default_unconfirmed = TrainingMappingCreate.model_fields[
        "admin_confirmed"].default is False
    # The AI hypothesis stays a proposal until an administrator stores it.
    hypothesis_persists = "db.add" in hypothesis_block
    spec_review = "Low confidence triggers REVIEW" in spec_text()
    ok = (spec_review and has_confirmed_filter and has_confidence_filter
          and not post_forces_confirmed and post_passes_flag
          and create_default_unconfirmed and not hypothesis_persists)
    recorder.add(
        "V06-65", "E",
        "a mapping awaiting review can be listed: low confidence triggers REVIEW, not "
        "PASS/FAIL (section 14.3.2; section 9.2 step 3 'Present suggestion to "
        "administrator')",
        "GET /training/mappings params + POST /mappings confirmation policy",
        "a queue reachable by confirmed/confidence filters; POST cannot mass-confirm",
        f"confirmed filter={has_confirmed_filter}; confidence range filters="
        f"{has_confidence_filter}; POST forces admin_confirmed=True={post_forces_confirmed}; "
        f"POST passes the client flag={post_passes_flag}; create default unconfirmed="
        f"{create_default_unconfirmed}; hypothesis endpoint persists={hypothesis_persists}; "
        f"spec 14.3.2 clause present={spec_review}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F10: TrainingMappingCreate.admin_confirmed defaults False (0.5 "
        "hypothesis estimate, below the 0.7 trust threshold) and only "
        "POST /mappings/{id}/confirm promotes a mapping; list_mappings "
        "exposes confirmed + confidence_min/confidence_max for the REVIEW queue",
        "",
    )
    assert ok


def test_v06_66_spec_step_orderings_covered_by_endpoints(recorder):
    text = src("app/api/v1/training.py")
    steps = {
        "step2 hypothesis (AI/KB)": "hypothesis" in text,
        "step3 confirm": "confirm_mapping" in text,
        "step3 edit": "update_mapping" in text,
        "step3 reject": "reject_mapping" in text,
        "step4 version": "MappingVersion" in text,
        "step4 store": "create_mapping" in text,
    }
    missing = [k for k, v in steps.items() if not v]
    ok = not missing
    recorder.add(
        "V06-66", "E",
        "every step of section 9.2 has a corresponding code path (1-5)",
        "step -> endpoint map", "all steps covered",
        f"missing={missing or 'none'} (note: step 5 re-run is covered separately by "
        "V06-59/V06-60)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "training.py:73/196/341/414 + MappingVersion writes at :115, :171, :374",
    )
    assert ok


# ==========================================================================
# F - Drift: in-memory twin vs SQLAlchemy repository vs REST API
# ==========================================================================


def test_v06_67_lookup_contract_drift(kb, recorder):
    mem = KnowledgeBase()
    mem.create("cisco", "ios", SYN_B, "B meaning",
               universal_model_path="access_control.rules_count",
               actor="t")
    mem_hit = mem.lookup("cisco", "ios", SYN_A)
    suggestions = mem.lookup_suggestions("cisco", "ios", SYN_A)
    ok = mem_hit is None and any(s.raw_syntax == SYN_B for s, _ in suggestions)
    recorder.add(
        "V06-67", "F",
        "one lookup contract across implementations (exact everywhere; similarity suggestion-only)",
        "in-memory near-duplicate query",
        "exact lookup misses; suggestions name the neighbour",
        f"in-memory exact_hit={mem_hit is not None}; suggestions="
        f"{[s.raw_syntax for s, _ in suggestions]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E06 F2/F5: lookup() exact-only; lookup_suggestions() non-mutating",
        "",
    )
    assert ok


async def test_v06_68_version_on_create_drift(kb_db, kb, recorder):
    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    resp = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="x", semantic_meaning="y",
                                      universal_model_path="device.hostname"),
        db=session, current_user=admin,
    )
    await session.commit()
    api_versions = (await api.get_mapping_versions(mapping_id=resp.id, db=session,
                                                   current_user=admin)).items
    mem = KnowledgeBase()
    mem.create("cisco", "ios", "x", "y",
               universal_model_path="device.hostname", actor="t")
    mem_row = mem.lookup("cisco", "ios", "x")
    mem_versions = mem.get_versions(mem_row.id)
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    repo = KnowledgeBaseRepository(session)
    repo_row = await repo.create("juniper", "junos", "repo-x", "repo y",
                                 universal_model_path="device.hostname",
                                 actor=str(await _first_user_id(session)))
    await session.commit()
    repo_versions = await repo.get_versions(str(repo_row.id))
    ok = (len(api_versions) == 1 and api_versions[0].version == 1
          and len(mem_versions) == 1 and mem_versions[0].version == 1
          and len(repo_versions) == 1 and repo_versions[0].version == 1
          and mem_row.version == 1 and repo_row.version == 1)
    recorder.add(
        "V06-68", "F",
        "after create, all implementations expose the same version history",
        "one mapping created through each of the three paths",
        "1 version-1 record and version=1 everywhere",
        f"API={len(api_versions)} record(s); in-memory={len(mem_versions)}; "
        f"repository={len(repo_versions)} (create() writes the v1 post-change "
        "record in both stores; the API reports the same rows)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DRIFT",
        "E06 F7: one post-change convention - create() records v1 in memory, "
        "repository and API",
        "",
    )
    assert ok


async def test_v06_69_version_content_drift(kb_db, kb, recorder):
    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate, TrainingMappingUpdate

    session, _, admin = kb_db
    created = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="vcontent", semantic_meaning="old",
                                      universal_model_path="device.hostname"),
        db=session, current_user=admin,
    )
    await session.commit()
    await api.update_mapping(
        mapping_id=created.id,
        mapping_update=TrainingMappingUpdate(semantic_meaning="new"),
        db=session, current_user=admin,
    )
    await session.commit()
    api_versions = (await api.get_mapping_versions(mapping_id=created.id, db=session,
                                                   current_user=admin)).items

    mem = KnowledgeBase()
    mem.create("cisco", "ios", "vcontent", "old",
               universal_model_path="device.hostname", actor="t")
    mem_row = mem.lookup("cisco", "ios", "vcontent")
    mem.update(mapping_id=mem_row.id, semantic_meaning="new", actor="t")
    mem_records = mem.get_versions(mem_row.id)

    from app.repositories.knowledge_base import KnowledgeBaseRepository
    repo = KnowledgeBaseRepository(session)
    repo_row = await repo.create("cisco", "ios", "vcontent-repo", "old",
                                 universal_model_path="device.hostname",
                                 actor=str(await _first_user_id(session)))
    await session.commit()
    await repo.update(mapping_id=str(repo_row.id), semantic_meaning="new",
                      actor=str(await _first_user_id(session)))
    await session.commit()
    repo_records = await repo.get_versions(str(repo_row.id))

    api_v2 = next(v for v in api_versions if v.version == 2)
    mem_v2 = next(v for v in mem_records if v.version == 2)
    repo_v2 = next(v for v in repo_records if v.version == 2)
    ok = (api_v2.semantic_meaning == "new" and mem_v2.semantic_meaning == "new"
          and repo_v2.semantic_meaning == "new"
          and [v.semantic_meaning for v in mem_records] == ["old", "new"]
          and [v.semantic_meaning for v in repo_records] == ["old", "new"])
    recorder.add(
        "V06-69", "F",
        "a version record captures the same content in every implementation",
        "create 'old' then update to 'new' through each path",
        "v2 record = post-change state (history of states) everywhere",
        f"API v2={api_v2.semantic_meaning!r}; in-memory v2={mem_v2.semantic_meaning!r}; "
        f"repository v2={repo_v2.semantic_meaning!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DRIFT",
        "E06 F7: one post-change convention everywhere; superseded the old "
        "pre-change snapshot in knowledge_base.py and repositories",
        "",
    )
    assert ok


async def test_v06_70_reject_three_way_drift(kb_db, kb, recorder):
    from app.ai.adaptive import AdaptiveLearningEngine
    from app.api.v1 import training as api
    from app.repositories.knowledge_base import KnowledgeBaseRepository
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    created = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                      raw_syntax="rej", semantic_meaning="m",
                                      universal_model_path="device.hostname",
                                      admin_confirmed=True),
        db=session, current_user=admin,
    )
    await session.commit()
    await api.reject_mapping(mapping_id=created.id, db=session, current_user=admin)
    await session.commit()
    api_row = await api.get_mapping(mapping_id=created.id, db=session,
                                    current_user=admin)

    engine = AdaptiveLearningEngine(ai_client=None, knowledge_base=KnowledgeBase())
    engine.kb.create("cisco", "ios", "rej", "m",
                     universal_model_path="device.hostname",
                     admin_confirmed=True, actor="admin-1")
    adaptive_rejected = engine.reject_mapping(raw_syntax="rej", vendor="cisco",
                                              platform="ios", user_id="admin-1",
                                              reason="wrong")
    adaptive_row = engine.kb.lookup("cisco", "ios", "rej", require_confirmed=False)

    repo = KnowledgeBaseRepository(session)
    repo_row = await repo.create("juniper", "junos", "rej", "m",
                                 universal_model_path="device.hostname",
                                 actor=str(await _first_user_id(session)))
    await session.commit()
    repo_rejected = await repo.reject(mapping_id=str(repo_row.id),
                                      actor=str(await _first_user_id(session)),
                                      reason="wrong")
    await session.commit()

    kb_methods = [n for n in dir(KnowledgeBase) if "reject" in n.lower()]
    repo_methods = [n for n in dir(KnowledgeBaseRepository) if "reject" in n.lower()]
    ok = (
        api_row.admin_confirmed is False
        and (api_row.admin_notes or "").startswith("REJECTED:")
        and adaptive_rejected is True
        and adaptive_row is not None and adaptive_row.admin_confirmed is False
        and (adaptive_row.admin_notes or "").startswith("REJECTED:")
        and repo_rejected.admin_confirmed is False
        and (repo_rejected.admin_notes or "").startswith("REJECTED:")
        and kb_methods and repo_methods
    )
    recorder.add(
        "V06-70", "F",
        "REJECT behaves the same in every implementation",
        "reject a confirmed mapping through API, adaptive workflow, storage layers",
        "row kept everywhere, unconfirmed, REJECTED note",
        f"API confirmed={api_row.admin_confirmed} notes={api_row.admin_notes!r}; "
        f"adaptive returned {adaptive_rejected} confirmed="
        f"{getattr(adaptive_row, 'admin_confirmed', None)} notes="
        f"{getattr(adaptive_row, 'admin_notes', None)!r}; repository confirmed="
        f"{repo_rejected.admin_confirmed} notes={repo_rejected.admin_notes!r}; "
        f"KnowledgeBase reject={kb_methods}; repository reject={repo_methods}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DRIFT",
        "E06 F3: reject() marks (never deletes) with actor + version history in "
        "both stores; the adaptive workflow delegates to the same store method "
        "(supersedes the old delete-unconfirmed/no-op-on-confirmed behaviour)",
        "",
    )
    assert ok


async def test_v06_71_autoconfirm_three_way_drift(kb_db, recorder):
    from sqlalchemy import select

    from app.api.v1 import training as api
    from app.models import TrainingMapping
    from app.repositories.knowledge_base import KnowledgeBaseRepository
    from app.schemas import TrainingMappingUpdate

    session, uid, admin = kb_db
    rid = uuid.uuid4()
    session.add(TrainingMapping(
        id=rid, vendor="cisco", platform="ios", raw_syntax="auto",
        semantic_meaning="g", universal_model_path="device.hostname",
        confidence=0.5, admin_confirmed=False, version=1,
        created_by=str(uid),
    ))
    await session.commit()
    await api.update_mapping(mapping_id=rid,
                             mapping_update=TrainingMappingUpdate(admin_notes="n"),
                             db=session, current_user=admin)
    await session.commit()
    api_state = (await session.execute(select(
        TrainingMapping.admin_confirmed, TrainingMapping.confidence).where(
        TrainingMapping.id == rid))).one()

    repo = KnowledgeBaseRepository(session)
    await repo.update(mapping_id=str(rid), admin_notes="n2", actor=str(uid))
    await session.commit()
    repo_state = (await session.execute(select(
        TrainingMapping.admin_confirmed, TrainingMapping.confidence).where(
        TrainingMapping.id == rid))).one()

    mem = KnowledgeBase()
    mem.create("cisco", "ios", "auto", "g",
               universal_model_path="device.hostname",
               admin_confirmed=False, actor="t")
    mem_row = mem.lookup("cisco", "ios", "auto", require_confirmed=False)
    mem.update(mapping_id=mem_row.id, admin_notes="n", actor="t")
    mem_state = (mem.lookup("cisco", "ios", "auto", require_confirmed=False)
                 .admin_confirmed, mem_row.confidence)

    ok = (api_state[0] is False and repo_state[0] is False and mem_state[0] is False
          and float(api_state[1]) == 0.5 and float(repo_state[1]) == 0.5
          and float(mem_state[1]) == 0.5)
    recorder.add(
        "V06-71", "F",
        "editing never confirms, in any implementation (section 9.2 step 3 / 14.3.3)",
        "same edit through API, repository, in-memory twin",
        "all three stay unconfirmed with the stored estimate",
        f"API confirmed={api_state[0]} conf={api_state[1]}; repository confirmed="
        f"{repo_state[0]} conf={repo_state[1]}; in-memory confirmed={mem_state[0]} "
        f"conf={mem_state[1]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DRIFT",
        "E06 F3: update() is confirmation-neutral in all three paths",
        "",
    )
    assert ok


async def test_v06_72_dedup_three_way_drift(kb_db, kb, recorder):
    from fastapi import HTTPException

    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    payload = dict(vendor="cisco", platform="ios", raw_syntax="dedup",
                   semantic_meaning="a", universal_model_path="device.hostname")
    await api.create_mapping(mapping=TrainingMappingCreate(**payload), db=session,
                             current_user=admin)
    await session.commit()
    try:
        await api.create_mapping(
            mapping=TrainingMappingCreate(**{**payload, "semantic_meaning": "b"}),
            db=session, current_user=admin)
        await session.commit()
        api_outcome = "created"
    except HTTPException as exc:
        await session.rollback()
        api_outcome = "409" if exc.status_code == 409 else f"HTTP {exc.status_code}"
    api_kept = (await api.get_mapping(mapping_id=(
        await api.list_mappings(page=1, per_page=100, db=session,
                                current_user=admin)).items[0].id,
        db=session, current_user=admin)).semantic_meaning

    mem = KnowledgeBase()
    mem.create("cisco", "ios", "dedup", "a",
               universal_model_path="device.hostname", actor="t")
    mem_dup = mem.create("cisco", "ios", "dedup", "b",
                         universal_model_path="device.hostname", actor="t")
    mem_kept = mem.lookup("cisco", "ios", "dedup").semantic_meaning
    mem_rows = len(mem.list_mappings())

    near_dup_api = None
    try:
        await api.create_mapping(
            mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                          raw_syntax=SYN_A, semantic_meaning="near",
                                          universal_model_path="access_control.rules_count"),
            db=session, current_user=admin)
        await session.commit()
        near_dup_api = "created"
    except Exception:  # noqa: BLE001
        await session.rollback()
        near_dup_api = "rejected"
    mem2 = KnowledgeBase()
    mem2.create("cisco", "ios", SYN_B, "base",
                universal_model_path="access_control.rules_count", actor="t")
    mem2.create("cisco", "ios", SYN_A, "near",
                universal_model_path="access_control.rules_count", actor="t")
    mem2_base = mem2.lookup("cisco", "ios", SYN_B, require_confirmed=False)

    # One row per canonical identity in both stores; the HTTP boundary
    # reports the conflict instead of rewriting the administrator's row.
    ok = (api_outcome == "409" and api_kept == "a"
          and mem_rows == 1 and mem_kept == "b" and mem_dup.version == 2
          and near_dup_api == "created"
          and mem2_base is not None and mem2_base.semantic_meaning == "base"
          and len(mem2.list_mappings()) == 2)
    recorder.add(
        "V06-72", "F",
        "duplicate detection behaves the same in every implementation",
        "exact duplicate + near duplicate through API and in-memory twin",
        "one row per identity, near-duplicates never absorbed",
        f"API exact dup={api_outcome} (row keeps {api_kept!r}); in-memory exact dup -> "
        f"{mem_rows} row, version {mem_dup.version}, meaning {mem_kept!r}; "
        f"API near-dup={near_dup_api} (new row); in-memory near-dup kept base="
        f"{mem2_base.semantic_meaning if mem2_base else None!r}, rows="
        f"{len(mem2.list_mappings())}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DRIFT",
        "E06 F2/F5: store create() is an idempotent upsert on the exact "
        "canonical identity (never similarity); POST /mappings answers 409 for "
        "an existing identity so the HTTP contract never silently rewrites an "
        "administrator's row",
        "",
    )
    assert ok


async def test_v06_73_list_limit_drift(kb_db, kb, recorder):
    from sqlalchemy import delete

    from app.models import TrainingMapping
    from app.api.v1 import training as api
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, _, admin = kb_db
    await session.execute(delete(TrainingMapping))
    await session.commit()
    actor = str(await _first_user_id(session))
    for i in range(103):
        session.add(TrainingMapping(
            id=uuid.uuid4(), vendor="cisco", platform="ios", raw_syntax=f"lim-{i}",
            semantic_meaning=f"m{i}", universal_model_path="device.hostname",
            confidence=1.0, admin_confirmed=True, version=1, created_by=actor,
        ))
    await session.commit()
    api_page1 = await api.list_mappings(page=1, per_page=100, db=session,
                                       current_user=admin)
    api_page2 = await api.list_mappings(page=2, per_page=100, db=session,
                                       current_user=admin)
    repo = KnowledgeBaseRepository(session)
    repo_all = await repo.list_mappings()
    repo_total = await repo.count_mappings()
    repo_limited = await repo.list_mappings(limit=100, offset=0)
    mem = KnowledgeBase()
    for i in range(103):
        mem.create("cisco", "ios", f"lim-{i}", f"m{i}",
                   universal_model_path="device.hostname", actor="t")
    mem_rows = mem.list_mappings()
    ok = (len(api_page1.items) == 100 and len(api_page2.items) == 3
          and api_page1.meta.total == 103 and api_page2.meta.total == 103
          and api_page2.meta.total_pages == 2
          and len(repo_all) == 103 and repo_total == 103
          and len(repo_limited) == 100
          and len(mem_rows) == 103
          and [m.raw_syntax for m in repo_all] == [m.raw_syntax for m in mem_rows])
    recorder.add(
        "V06-73", "F",
        "list() returns the same rows in every implementation",
        "103 mappings, unfiltered list through repository, API pages and memory",
        "103 rows everywhere; explicit limits are honoured; order matches",
        f"API page 1={len(api_page1.items)} page 2={len(api_page2.items)} "
        f"total={api_page1.meta.total} pages={api_page1.meta.total_pages}; "
        f"repository all={len(repo_all)} count={repo_total} limit(100)="
        f"{len(repo_limited)}; in-memory={len(mem_rows)}; same order="
        f"{[m.raw_syntax for m in repo_all] == [m.raw_syntax for m in mem_rows]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DRIFT",
        "E06 F2/F13/F14: repository has no default cap (limit=None = all), the "
        "API paginates with a truthful total, both order canonically",
        "",
    )
    assert ok


def test_v06_74_two_classes_not_interchangeable(recorder):
    from sqlalchemy import inspect

    from app.models import TrainingMapping as DbMapping
    from app.schemas import TrainingMappingResponse

    mem = KnowledgeBase().create("cisco", "ios", "x", "y",
                                 universal_model_path="device.hostname",
                                 actor="t")
    orm_fields = {a.key for a in inspect(DbMapping).mapper.column_attrs}
    response_fields = set(TrainingMappingResponse.model_fields)
    # Layer split is explicit: the domain object is not the ORM row, and the
    # repository converts between them (no isinstance mixing, one converter).
    repo_src = src("app/repositories/knowledge_base.py")
    has_converter = "def _to_domain(" in repo_src
    ok = not isinstance(mem, DbMapping) and has_converter \
        and orm_fields.issuperset({"vendor", "platform", "raw_syntax",
                                   "semantic_meaning", "universal_model_path",
                                   "confidence", "admin_confirmed", "version",
                                   "created_by"})
    recorder.add(
        "V06-74", "F",
        "the in-memory domain object, the ORM row and the API response are "
        "clearly separated by one documented conversion boundary",
        "in-memory instance vs app.models instance vs response schema",
        "distinct types; one ORM->domain converter; ORM carries every field "
        "the response needs",
        f"isinstance(in_memory, models.TrainingMapping)={isinstance(mem, DbMapping)}; "
        f"domain type={type(mem).__module__}.{type(mem).__name__}; "
        f"ORM->domain converter={has_converter}; "
        f"response fields missing from ORM="
        f"{sorted(response_fields - orm_fields) or 'none'}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DRIFT",
        "app.ai.kb_domain + app.ai.knowledge_base (domain), app.models (ORM), "
        "app.schemas (API); repositories/knowledge_base.py:_to_domain is the "
        "single conversion point, so the two same-named classes can no longer "
        "be mixed silently",
        "",
    )
    assert ok


# ==========================================================================
# G - Wrong / unsupported vendor consequences
# ==========================================================================


async def _first_user_id(session):
    from sqlalchemy import select

    from app.models import User

    row = (await session.execute(select(User.id).limit(1))).scalar()
    return row


async def test_v06_75_vendor_isolation(kb, recorder):
    kb.create("cisco", "ios", "hostname edge-1", "cisco meaning",
              universal_model_path="device.hostname", actor="t")
    kb.create("juniper", "junos", "hostname edge-1", "juniper meaning",
              universal_model_path="device.hostname", actor="t")
    got_c = kb.lookup("cisco", "ios", "hostname edge-1")
    got_j = kb.lookup("juniper", "junos", "hostname edge-1")
    other = kb.lookup("arista", "eos", "hostname edge-1")
    ok = (
        got_c is not None and got_c.semantic_meaning == "cisco meaning"
        and got_j is not None and got_j.semantic_meaning == "juniper meaning"
        and other is None
    )
    recorder.add(
        "V06-75", "G",
        "a mapping stored for one vendor can never answer a query for another vendor",
        "same syntax stored for cisco + juniper; query from each and from arista",
        "per-vendor meanings; unrelated vendor gets None",
        f"cisco={getattr(got_c, 'semantic_meaning', None)!r}; juniper="
        f"{getattr(got_j, 'semantic_meaning', None)!r}; arista={other}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "knowledge_base.py:109-133 (vendor in key); repositories:43-46 both columns",
        "Isolation holds - G-category finding: vendor keying is correct at both layers.",
    )
    assert ok


async def test_v06_76_platform_isolation(kb, recorder):
    kb.create("cisco", "ios", "show version", "IOS meaning",
              universal_model_path="device.firmware_version", actor="t")
    kb.create("cisco", "ios_xe", "show version", "IOS-XE meaning",
              universal_model_path="device.firmware_version", actor="t")
    a = kb.lookup("cisco", "ios", "show version")
    b = kb.lookup("cisco", "ios_xe", "show version")
    wrong = kb.lookup("cisco", "nxos", "show version")
    ok = (
        a and b and a.semantic_meaning == "IOS meaning"
        and b.semantic_meaning == "IOS-XE meaning" and wrong is None
    )
    recorder.add(
        "V06-76", "G",
        "platform variants of the same vendor do not bleed into each other",
        "ios vs ios_xe same syntax", "distinct meanings; nxos gets None",
        f"ios={getattr(a, 'semantic_meaning', None)!r}; ios_xe="
        f"{getattr(b, 'semantic_meaning', None)!r}; nxos={wrong}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "knowledge_base.py:111 key includes platform",
    )
    assert ok


async def test_v06_77_repo_vendor_isolation(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "iso cmd", "cisco meaning",
                      universal_model_path="device.hostname", actor=str(uid))
    await repo.create("juniper", "junos", "iso cmd", "juniper meaning",
                      universal_model_path="device.hostname", actor=str(uid))
    await session.commit()
    a = await repo.lookup("cisco", "ios", "iso cmd")
    b = await repo.lookup("juniper", "junos", "iso cmd")
    other = await repo.lookup("fortinet", "fortios", "iso cmd")
    ok = a and b and a.semantic_meaning == "cisco meaning" and \
        b.semantic_meaning == "juniper meaning" and other is None
    recorder.add(
        "V06-77", "G", "repository lookup enforces the same vendor isolation",
        "same syntax, two vendors", "per-vendor rows, unknown vendor None",
        f"cisco={getattr(a, 'semantic_meaning', None)!r}; juniper="
        f"{getattr(b, 'semantic_meaning', None)!r}; fortinet={other}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "repositories/knowledge_base.py:43-46 filters on both columns",
    )
    assert ok


async def test_v06_78_case_variant_vendor_leaks(kb, recorder):
    kb.create("Cisco", "ios", "case cmd", "upper vendor meaning",
              universal_model_path="device.hostname", actor="t")
    stored = kb.lookup("cisco", "ios", "case cmd", require_confirmed=False)
    ok = (stored is not None
          and stored.vendor == "cisco"
          and kb.lookup("CISCO", "IOS", "case cmd") is not None
          and len(kb.list_mappings(vendor="CISCO")) == 1)
    recorder.add(
        "V06-78", "G",
        "vendor strings are normalized so 'Cisco' and 'cisco' are the same vendor",
        "stored with 'Cisco', queried 'cisco' and 'CISCO'",
        "one identity: matched, stored lowercase, case-insensitive filters",
        f"matched={stored is not None}; stored vendor={getattr(stored, 'vendor', None)!r}; "
        f"upper query matched={kb.lookup('CISCO', 'IOS', 'case cmd') is not None}; "
        "kb_domain.canonical_vendor/platform lower+strip on write and read",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F4/F12: one canonical identity in memory, repository, API and "
        "migration 005 - 'Cisco' and 'cisco' can no longer be two vendors for "
        "dedup while being one for lookup (the old V06-41 asymmetry)",
        "",
    )
    assert ok


async def test_v06_79_wildcard_returns_wrong_vendor(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("juniper", "junos", "show version", "juniper meaning",
                      universal_model_path="device.firmware_version",
                      actor=str(uid))
    await repo.create("cisco", "ios", "show something", "cisco meaning",
                      universal_model_path="device.firmware_version",
                      actor=str(uid))
    await session.commit()
    syntax_pattern = await repo.lookup("cisco", "ios", "show%")
    vendor_pattern = await repo.lookup("%", "%", "show version")
    underscore = await repo.lookup("cisco", "ios", "show_version")
    ok = syntax_pattern is None and vendor_pattern is None \
        and underscore is None
    recorder.add(
        "V06-79", "G",
        "a query containing SQL wildcard characters can never return another vendor's row",
        "lookup('cisco','ios','show%') / ('%','%','show version') / ('cisco','ios','show_version')",
        "None for all (literal filters)",
        f"syntax pattern -> {getattr(syntax_pattern, 'semantic_meaning', None)!r}; "
        f"vendor pattern -> {getattr(vendor_pattern, 'vendor', None)!r}; "
        f"underscore -> {getattr(underscore, 'semantic_meaning', None)!r}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E06 F4/F13: canonical == filters (no ilike); '%' and '_' are literal",
        "",
    )
    assert ok


async def test_v06_80_wildcard_multi_row_crash(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "show version", "A",
                      universal_model_path="device.firmware_version",
                      actor=str(uid))
    await repo.create("juniper", "junos", "show version", "B",
                      universal_model_path="device.firmware_version",
                      actor=str(uid))
    await session.commit()
    try:
        got = await repo.lookup("%", "%", "show version")
        outcome = f"ok:{getattr(got, 'vendor', None)}" if got is not None else "ok:None"
    except Exception as exc:  # noqa: BLE001
        await session.rollback()
        outcome = type(exc).__name__
    ok = outcome == "ok:None"
    recorder.add(
        "V06-80", "G",
        "any query that matches several rows yields a typed result, not an unhandled crash",
        "lookup('%','%','show version') matching the same syntax on two vendors",
        "None (literal filters match nothing) without raising",
        f"outcome={outcome}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F4: canonical == filters treat '%' literally; earliest-row "
        "tiebreak replaces scalar_one_or_none (see V06-31)",
        "",
    )
    assert ok


async def test_v06_81_unsupported_vendor_stored_and_retrieved(kb_db, kb, recorder):
    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    resp = await api.create_mapping(
        mapping=TrainingMappingCreate(vendor="arista", platform="eos",
                                      raw_syntax="show version", semantic_meaning="arista",
                                      universal_model_path="device.firmware_version"),
        db=session, current_user=admin,
    )
    await session.commit()
    mem = KnowledgeBase()
    mem.create("fortinet", "fortios", "show version", "fortinet",
               universal_model_path="device.firmware_version", actor="t")
    ok = resp is not None and mem.lookup("fortinet", "fortios", "show version") is not None
    recorder.add(
        "V06-81", "G",
        "vendors/platforms outside any known list are accepted (the KB is a learning store, "
        "spec §10.6 does not restrict the vendor set)",
        "POST arista/eos + in-memory fortinet/fortios",
        "accepted and retrievable",
        f"API created={resp is not None} vendor={getattr(resp, 'vendor', None)!r}; "
        f"in-memory stored={mem.lookup('fortinet', 'fortios', 'show version') is not None}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "training.py:73-127 no vendor enumeration; schemas allow any string <=50; "
        "cross-ref E03 (parser vendor coverage) - storing a vendor no parser reads is "
        "allowed but harmless here",
        "G-category positive: no false rejection of new vendors.",
    )
    assert ok


# ==========================================================================
# H - Semantic fidelity of stored meanings
# ==========================================================================


async def test_v06_82_empty_meaning_accepted(kb_db, kb, recorder):
    from fastapi import HTTPException

    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    try:
        await api.create_mapping(
            mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                          raw_syntax="empty meaning cmd", semantic_meaning=""),
            db=session, current_user=admin,
        )
        await session.commit()
        api_outcome = "created"
    except HTTPException as exc:
        await session.rollback()
        api_outcome = f"HTTPException {exc.status_code}"
    except Exception as exc:  # noqa: BLE001
        await session.rollback()
        api_outcome = type(exc).__name__
    try:
        KnowledgeBase().create("cisco", "ios", "empty mem cmd", "",
                               universal_model_path="device.hostname",
                               actor="t")
        mem_outcome = "stored"
    except Exception as exc:  # noqa: BLE001
        mem_outcome = type(exc).__name__
    ok = api_outcome == "ValidationError" and mem_outcome == "KBValidationError"
    recorder.add(
        "V06-82", "H",
        "a mapping with an empty semantic_meaning is rejected (it cannot teach "
        "normalization anything)",
        "POST semantic_meaning=''; in-memory create with ''",
        "422 / KBValidationError",
        f"API outcome={api_outcome}; in-memory outcome={mem_outcome}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "RECOMMENDATION",
        "E06 F9: schema min_length=1 + canonical domain validation at every "
        "entry point",
        "",
    )
    assert ok


async def test_v06_83_model_path_unvalidated_everywhere(kb_db, kb, recorder):
    from fastapi import HTTPException

    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate

    session, _, admin = kb_db
    try:
        await api.create_mapping(
            mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                          raw_syntax="bogus path cmd", semantic_meaning="m",
                                          universal_model_path="not.a.real.path"),
            db=session, current_user=admin,
        )
        await session.commit()
        api_outcome = "created"
    except HTTPException as exc:
        await session.rollback()
        api_outcome = f"HTTPException {exc.status_code}"
    try:
        KnowledgeBase().create("cisco", "ios", "bogus mem cmd", "m",
                               universal_model_path="also.not.real", actor="t")
        mem_outcome = "stored"
    except Exception as exc:  # noqa: BLE001
        mem_outcome = type(exc).__name__
    from app.repositories.knowledge_base import KnowledgeBaseRepository
    try:
        await KnowledgeBaseRepository(session).create(
            "cisco", "ios", "bogus repo cmd", "m",
            universal_model_path="still.not.real", actor="test-admin")
        await session.commit()
        repo_outcome = "stored"
    except Exception as exc:  # noqa: BLE001
        await session.rollback()
        repo_outcome = type(exc).__name__
    ok = api_outcome == "HTTPException 422" and mem_outcome == "KBValidationError" \
        and repo_outcome == "KBValidationError"
    recorder.add(
        "V06-83", "H",
        "universal_model_path is validated at EVERY entry point (POST, update, "
        "in-memory create, repository create)",
        "bogus paths at all entry points",
        "rejected everywhere with typed errors",
        f"POST={api_outcome}; in-memory={mem_outcome}; repository={repo_outcome}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F9: canonical domain validation backed by UniversalSecurityModel",
        "",
    )
    assert ok


async def test_v06_84_independent_rows_keep_provenance(kb, recorder):
    row_a = kb.create("cisco", "ios", SYN_B, "A's meaning",
                      universal_model_path="access_control.rules_count",
                      actor="author-A")
    row_b = kb.create("cisco", "ios", SYN_A, "B's meaning",
                      universal_model_path="access_control.rules_count",
                      actor="author-B")
    stored_a = kb.lookup("cisco", "ios", SYN_B)
    stored_b = kb.lookup("cisco", "ios", SYN_A)
    versions_b = kb.get_versions(row_b.id)
    ok = (
        stored_a is not None and stored_a.semantic_meaning == "A's meaning"
        and stored_a.created_by == "author-A"
        and stored_b is not None and stored_b.semantic_meaning == "B's meaning"
        and stored_b.created_by == "author-B"
        and row_b.version == 1 and len(versions_b) == 1
    )
    recorder.add(
        "V06-84", "H",
        "near-duplicate creates store independent rows, each with its own "
        "provenance and version history (section 9.2 step 4)",
        "create as author-A, near-duplicate create as author-B (Jaccard > 0.8)",
        "two rows; each keeps its author, meaning and v1 record",
        f"a_meaning={getattr(stored_a, 'semantic_meaning', None)!r} "
        f"b_meaning={getattr(stored_b, 'semantic_meaning', None)!r}; "
        f"records_b={[(v.version, v.change_reason) for v in versions_b]}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F5: exact identity only — similarity never merges, absorbs or "
        "rewrites another row (supersedes the old absorption-consistency test)",
        "",
    )
    assert ok


# ==========================================================================
# I - Integration with the rest of the pipeline (section 9.2 / section 10.5)
# ==========================================================================


def test_v06_85_normalization_has_no_kb_reference(recorder):
    norm = src("app/engines/normalization.py")
    refs = [t for t in ("knowledge_base", "KnowledgeBase", "repositories.knowledge") if t in norm]
    has_hook = "def _apply_kb_mappings" in norm
    ok = bool(refs) and has_hook
    recorder.add(
        "V06-85", "I",
        "spec §10.6: the knowledge base exists to 'provide lookup for normalization' - "
        "normalization must call it",
        "app/engines/normalization.py KB hook",
        "knowledge_base consulted; confirmed trusted hits applied to unmapped paths",
        f"references={refs or 'none'}; apply hook present={has_hook}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F1: NormalizationEngine.normalize(knowledge_base=...) applies "
        "confirmed, trust-gated mappings to otherwise-unmapped model paths "
        "(unconfirmed/low-confidence rows never authoritative)",
        "",
    )
    assert ok


def test_v06_86_semantic_layer_has_no_kb_reference(recorder):
    sem = src("app/ai/semantic.py")
    import_lines = [ln for ln in sem.splitlines()
                    if ln.startswith(("from ", "import "))]
    refs = [t for t in ("knowledge_base", "KnowledgeBase", "TrainingMapping")
            if any(t in ln for ln in import_lines)]
    body_refs = [t for t in ("knowledge_base", "KnowledgeBase") if t in sem]
    has_hook = "def _apply_kb_mappings" in sem
    ok = bool(body_refs) and has_hook
    recorder.add(
        "V06-86", "I",
        "the semantic-analysis layer reuses confirmed KB mappings (spec 9.2 step 1-2, "
        "10.6 'Provide lookup for normalization')",
        "app/ai/semantic.py analyze(knowledge_base=...)",
        "KB consult resolving unknowns with kb_mapping_id attached",
        f"import refs={refs or 'none'}; body refs={body_refs or 'none'}; "
        f"hook present={has_hook}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F1: SemanticAnalyzer.analyze(knowledge_base=...) resolves "
        "unknown sections from confirmed, trust-gated mappings (no AI call)",
        "",
    )
    assert ok


def test_v06_87_reanalyze_hardcodes_cisco_parser(recorder):
    text = src("app/ai/adaptive.py")
    hardcoded = "CiscoIOSParser" in text
    dispatched = "get_parser(" in text
    spec_neutral = "multi-vendor" in spec_text().lower()
    fixed = (not hardcoded) and dispatched and spec_neutral
    recorder.add(
        "V06-87", "I",
        "re-analyzing with an edited mapping uses the parser for THAT mapping's vendor "
        "(spec: multi-vendor platform)",
        "adaptive.reanalyze_with_mapping body",
        "parser selected by mapping.vendor",
        f"hardcoded CiscoIOSParser={hardcoded} vendor-dispatched={dispatched}; "
        f"spec declares multi-vendor={spec_neutral}",
        "PASS" if fixed else "FAIL",
        "CONFIRMED BEHAVIOR",
        "E04 F3/F10: adaptive.py reanalyze_with_mapping dispatches on the "
        "vendor argument via parsing.get_parser; unsupported vendors get a "
        "safe empty result",
        "",
    )
    assert fixed


def test_v06_88_adaptive_engine_unwired(recorder):
    refs = []
    for py in sorted((BACKEND / "app").rglob("*.py")):
        t = py.read_text(encoding="utf-8", errors="replace")
        if "AdaptiveLearningEngine" in t and py.name != "adaptive.py":
            refs.append(py.name)
    test_refs = []
    for py in sorted((BACKEND / "tests").rglob("*.py")):
        if "AdaptiveLearningEngine" in py.read_text(encoding="utf-8", errors="replace"):
            test_refs.append(py.name)
    defect = not refs
    ok = "training.py" in refs
    recorder.add(
        "V06-88", "I",
        "the adaptive-learning engine is reachable from the product (routes, service, or "
        "background job)",
        "all non-adaptive app/ references",
        "at least one caller (training reanalyze endpoint)",
        f"app/ callers={refs or 'none'}; test-only callers={test_refs}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F1 (§9.2 step 5): POST /training/mappings/{id}/reanalyze "
        "orchestrates AdaptiveLearningEngine for mapping-driven re-analysis",
        "",
    )
    assert ok


def test_v06_89_no_confidence_review_routing(recorder):
    from app.schemas import TrainingMappingCreate, TrainingMappingUpdate

    text = src("app/api/v1/training.py")
    list_block = text.split("async def list_mappings")[1].split("@router.post")[0]
    has_confidence_param = "confidence_min" in list_block \
        or "confidence_max" in list_block
    schema_stores = "confidence" in TrainingMappingCreate.model_fields
    schema_update_clean = "confidence" not in TrainingMappingUpdate.model_fields
    spec_threshold = "Low confidence triggers REVIEW" in spec_text()
    spec_confidence_row = "Estimate confidence" in spec_text()
    trust_gate = "KB_TRUST_THRESHOLD" in src("app/ai/kb_domain.py")
    ok = spec_threshold and has_confidence_param and schema_stores \
        and schema_update_clean and trust_gate
    recorder.add(
        "V06-89", "I",
        "confidence flows end-to-end into review routing: low confidence triggers REVIEW "
        "and thresholds are enforced (section 14.3.2; section 14.1 'Estimate confidence' / "
        "'Threshold enforcement')",
        "training.py list params + create schema + trust gate + spec clauses",
        "confidence stored, queryable by range, and gating automatic reuse",
        f"spec 14.3.2 present={spec_threshold}; spec 14.1 confidence row="
        f"{spec_confidence_row}; list endpoint accepts confidence range="
        f"{has_confidence_param}; schemas store confidence={schema_stores}; "
        f"trust threshold enforced={trust_gate}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "E06 F10: list_mappings confidence_min/max (review queue); Create "
        "accepts estimates; kb_domain trust policy gates automatic reuse "
        "(unconfirmed/low-confidence never authoritative)",
        "",
    )
    assert ok


def test_v06_90_hypothesis_endpoint_exists_and_offline_capable(kb, recorder):
    text = src("app/api/v1/training.py")
    has_route = "hypothesis" in text
    kb_short_circuit = "kb.lookup" in text or "knowledge_base" in text
    ok = has_route and kb_short_circuit
    recorder.add(
        "V06-90", "I",
        "spec §14.3.5 fallback: a hypothesis can be produced without a configured LLM "
        "(KB-backed path)",
        "training.py /hypothesis", "route exists and consults the KB first",
        f"route={has_route}; KB short-circuit={kb_short_circuit}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "MISSING",
        "training.py:232-331; KB branch at :254-287 runs before create_ai_client() (:290)",
        "Positive finding: this path worked offline in probe (no API key needed).",
    )
    assert ok


# ==========================================================================
# J - Determinism
# ==========================================================================


async def test_v06_91_repeated_inmemory_operations_identical(recorder):
    a = KnowledgeBase()
    b = KnowledgeBase()
    for kb in (a, b):
        kb.create("cisco", "ios", "cmd1", "m1",
                  universal_model_path="device.hostname", actor="t")
        kb.create("juniper", "junos", "cmd2", "m2",
                  universal_model_path="device.hostname", actor="t")
        kb.update(mapping_id=kb.lookup("cisco", "ios", "cmd1").id,
                  semantic_meaning="m1 v2", actor="t")
        kb.create("cisco", "ios", SYN_B, "base",
                  universal_model_path="access_control.rules_count",
                  actor="t")
        kb.create("cisco", "ios", SYN_A, "near",
                  universal_model_path="access_control.rules_count",
                  actor="t")
    sa = [(m.raw_syntax, m.semantic_meaning, m.version, m.admin_confirmed)
          for m in a.list_mappings()]
    sb = [(m.raw_syntax, m.semantic_meaning, m.version, m.admin_confirmed)
          for m in b.list_mappings()]
    la = a.lookup("cisco", "ios", SYN_A)
    lb = b.lookup("cisco", "ios", SYN_A)
    ok = sa == sb and la.semantic_meaning == lb.semantic_meaning
    recorder.add(
        "V06-91", "J", "identical operation sequences yield identical KB state",
        "two fresh KnowledgeBase instances, same 5 ops",
        "identical listings and lookups",
        f"state_equal={sa == sb}; lookup meanings equal="
        f"{la.semantic_meaning == lb.semantic_meaning} ({la.semantic_meaning!r})",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "no randomness/time dependence in knowledge_base.py (confidence constants, "
        "deterministic similarity)",
    )
    assert ok


async def test_v06_92_stats_vendor_order_unstable(kb, recorder):
    import asyncio
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent("""
        from app.ai.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        for v, p, s in [
            ("cisco", "ios", "c1"), ("juniper", "junos", "j1"),
            ("fortinet", "fortios", "f1"), ("arista", "eos", "a1"),
            ("paloalto", "panos", "p1"),
        ]:
            kb.create(v, p, s, "m", universal_model_path="device.hostname",
                      actor="t")
        print(",".join(kb.get_stats()["vendors"]))
    """)
    results = set()
    for _ in range(3):
        proc = await asyncio.to_thread(
            subprocess.run, [sys.executable, "-c", script],
            cwd=str(BACKEND), capture_output=True, text=True, timeout=120,
        )
        results.add(proc.stdout.strip())
    repo_has_order = "order_by" in src("app/repositories/knowledge_base.py")
    mem_sorted = "sorted(" in src("app/ai/knowledge_base.py")
    ok = len(results) == 1 and repo_has_order and mem_sorted
    recorder.add(
        "V06-92", "J",
        "stats/list outputs are deterministically ordered (report snapshots must be stable)",
        "3 subprocess runs of get_stats with 5 vendors + repo query shape",
        "identical order every run",
        f"distinct outputs across runs={len(results)}: {sorted(results)}; "
        f"repo uses order_by={repo_has_order}; in-memory sorts={mem_sorted}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F14: canonical ordering (vendor, platform, syntax, id) in both "
        "stores; versions chronological",
        "",
    )
    assert ok


async def test_v06_93_repeated_db_lookup_stable(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "stable cmd", "stable",
                      universal_model_path="device.hostname", actor=str(uid))
    await session.commit()
    results = [await repo.lookup("cisco", "ios", "stable cmd") for _ in range(5)]
    ids = [r.id for r in results if r is not None]
    ok = len(ids) == 5 and len(set(ids)) == 1
    recorder.add(
        "V06-93", "J", "repeated identical DB lookups return the same row",
        "5 identical lookups", "same id each time",
        f"distinct ids={len(set(ids))} of {len(ids)} hits",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "single-row equality match; unstable-order risk applies only to list/stats (V06-92)",
    )
    assert ok


# ==========================================================================
# K - Performance (probe baseline: 5000 in-memory creates = 16.6s, i.e. quadratic)
# ==========================================================================


async def test_v06_94_inmemory_create_scaling(recorder):
    import time

    small = KnowledgeBase()
    t0 = time.perf_counter()
    for i in range(200):
        small.create("cisco", "ios", f"perf-a-{i}", "m",
                     universal_model_path="device.hostname", actor="t")
    t_small = time.perf_counter() - t0

    large = KnowledgeBase()
    t0 = time.perf_counter()
    for i in range(800):
        large.create("cisco", "ios", f"perf-b-{i}", "m",
                     universal_model_path="device.hostname", actor="t")
    t_large = time.perf_counter() - t0

    ratio_time = t_large / max(t_small, 1e-9)
    ratio_input = 4.0
    ok = ratio_time <= 8  # indexed identity: ~linear scaling
    recorder.add(
        "V06-94", "K",
        "KnowledgeBase.create scales at most linearly with store size",
        f"200 creates={t_small * 1000:.0f}ms; 800 creates={t_large * 1000:.0f}ms",
        "time ratio <= ~8x for 4x input (linear plus noise)",
        f"time ratio={ratio_time:.1f}x for {ratio_input:.0f}x input",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "DESIGN LIMITATION",
        "E06 F16: canonical-identity dict index (O(1) dedupe); similarity "
        "scans only run on explicit suggestion calls",
        "",
    )
    assert ok


async def test_v06_95_inmemory_lookup_speed(recorder):
    import time

    kb = KnowledgeBase()
    for i in range(1000):
        kb.create("cisco", "ios", f"lookup-{i}", f"m{i}",
                  universal_model_path="device.hostname", actor="t")
    t0 = time.perf_counter()
    for i in range(1000):
        kb.lookup("cisco", "ios", f"lookup-{i}")
    elapsed = time.perf_counter() - t0
    ok = elapsed < 2.0
    recorder.add(
        "V06-95", "K", "1000 lookups against a 1000-row KB stay interactive (<2s)",
        "1000 sequential lookups", "< 2000 ms",
        f"{elapsed * 1000:.0f} ms ({elapsed * 1000 / 1000:.2f} ms/lookup) "
        "(probe: 1000 lookups = 77ms)",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "knowledge_base.py:109-133 linear scan - fine at current dataset scale",
    )
    assert ok


async def test_v06_96_repo_lookup_speed(kb_db, recorder):
    import time

    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    from sqlalchemy import delete

    from app.models import TrainingMapping

    await session.execute(delete(TrainingMapping))
    await session.commit()
    for i in range(200):
        session.add(TrainingMapping(
            id=uuid.uuid4(), vendor="cisco", platform="ios", raw_syntax=f"spd-{i}",
            semantic_meaning=f"m{i}", universal_model_path="device.hostname",
            confidence=1.0, admin_confirmed=True, version=1,
            created_by=str(uid),
        ))
    await session.commit()
    t0 = time.perf_counter()
    for i in range(50):
        await repo.lookup("cisco", "ios", f"spd-{i}")
    elapsed = time.perf_counter() - t0
    ok = elapsed < 2.0
    recorder.add(
        "V06-96", "K",
        "repository lookup is fast on an indexed/vendor-filtered table (probe: 200 lookups "
        "= 164ms)",
        "50 lookups over 200 rows", "< 2000 ms",
        f"{elapsed * 1000:.0f} ms total, {elapsed * 1000 / 50:.1f} ms/lookup; "
        "only index is ix_semantic_mappings_vendor_platform "
        "(001_initial_migration.py:219) - raw_syntax is unindexed",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "repositories/knowledge_base.py:31-55",
    )
    assert ok


# ==========================================================================
# L - Hostile / edge-case input
# ==========================================================================


def test_v06_97_nul_byte_stored_inmemory(recorder):
    from app.ai import kb_domain as dom

    try:
        kb = KnowledgeBase()
        kb.create("cisco", "ios", "show\x00version", "nul meaning",
                  universal_model_path="device.hostname", actor="t")
        outcome = "stored"
    except dom.KBValidationError as exc:
        outcome = f"KBValidationError: {exc}"
    except Exception as exc:  # noqa: BLE001
        outcome = f"{type(exc).__name__}: {exc}"
    ok = outcome.startswith("KBValidationError") \
        and "\x00" not in KnowledgeBase().list_mappings()  # nothing stored either way
    recorder.add(
        "V06-97", "L",
        "NUL bytes in raw_syntax are rejected (spec §15.1 column semantics; "
        "CWE-158 improper neutralization)",
        "'show\\x00version'", "typed KBValidationError, nothing stored",
        outcome,
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "kb_domain.check_text rejects C0 control characters (except tab/newline) "
        "for vendor/platform/raw_syntax/meaning/notes, shared by both stores "
        "and the API schemas",
        "",
    )
    assert ok


async def test_v06_98_nul_byte_repo_unguarded(kb_db, recorder):
    from app.ai import kb_domain as dom
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    try:
        await repo.create("cisco", "ios", "nul\x00cmd", "meaning",
                          universal_model_path="device.hostname", actor=str(uid))
        await session.commit()
        outcome = "stored"
    except dom.KBValidationError as exc:
        await session.rollback()
        outcome = f"KBValidationError: {exc}"
    except Exception as exc:  # noqa: BLE001
        await session.rollback()
        outcome = f"unhandled {type(exc).__name__}: {str(exc)[:80]}"
    rows = await repo.list_mappings()
    ok = outcome.startswith("KBValidationError") and not any(
        "\x00" in (r.raw_syntax or "") for r in rows)
    recorder.add(
        "V06-98", "L",
        "NUL bytes are rejected with a typed, client-safe error before hitting the driver",
        "repo.create with '\\x00' in raw_syntax",
        "KBValidationError -> API 422, never a driver error",
        f"outcome={outcome}; rows_containing_nul="
        f"{sum(1 for r in rows if chr(0) in (r.raw_syntax or ''))}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F17: kb_domain.check_text runs before any SQL is built, so asyncpg "
        "never sees a NUL; training.py maps KBValidationError to 422",
        "",
    )
    assert ok


async def test_v06_99_one_megabyte_raw_syntax(kb_db, kb, recorder):
    from fastapi import HTTPException
    from pydantic import ValidationError

    from app.api.v1 import training as api
    from app.schemas import TrainingMappingCreate

    big = "x" * (1024 * 1024)
    from app.ai import kb_domain as dom

    try:
        KnowledgeBase().create("cisco", "ios", big, "big",
                               universal_model_path="device.hostname",
                               actor="t")
        mem_ok = True
        mem_note = "in-memory stored 1 MiB"
    except dom.KBValidationError as exc:
        mem_ok = False
        mem_note = f"in-memory KBValidationError: {str(exc)[:60]}"

    try:
        TrainingMappingCreate(vendor="cisco", platform="ios", raw_syntax=big,
                              semantic_meaning="big")
        schema_ok = True
        schema_note = "schema accepted 1 MiB"
    except ValidationError as exc:
        schema_ok = False
        schema_note = f"schema ValidationError: {exc.error_count()} error(s)"

    session, _, admin = kb_db
    try:
        resp = await api.create_mapping(
            mapping=TrainingMappingCreate(vendor="cisco", platform="ios",
                                          raw_syntax=big, semantic_meaning="big",
                                          universal_model_path="device.hostname"),
            db=session, current_user=admin,
        )
        await session.commit()
        api_ok = resp is not None
        api_note = f"API accepted len={len(resp.raw_syntax)}"
    except (HTTPException, ValidationError, dom.KBValidationError) as exc:
        await session.rollback()
        api_ok = False
        api_note = f"API rejected: {type(exc).__name__}"
    except Exception as exc:  # noqa: BLE001
        await session.rollback()
        api_ok = False
        api_note = f"API unhandled {type(exc).__name__}"

    ok = not mem_ok and not schema_ok and not api_ok
    recorder.add(
        "V06-99", "L",
        "raw_syntax has an enforced size bound (cap 4096) at every layer",
        "1 MiB raw_syntax via in-memory, pydantic and API",
        "typed rejection in all three layers",
        f"{mem_note}; {schema_note}; {api_note} "
        "(kb_domain.MAX_RAW_SYNTAX_LEN=4096; TrainingMappingCreate max_length=4096)",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F17: one bound (4096) enforced by the shared domain validator and "
        "mirrored on the API schema, so a 1 MiB row can never bloat list "
        "responses or similarity scans",
        "",
    )
    assert ok


async def test_v06_100_sql_injection_string_returns_nothing(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "real cmd", "real",
                      universal_model_path="device.hostname", actor=str(uid))
    await session.commit()
    payload = "'; DROP TABLE semantic_mappings; --"
    try:
        got = await repo.lookup("cisco", "ios", payload)
        got_wild = await repo.lookup("cisco", "ios", "%")
        still_there = await repo.lookup("cisco", "ios", "real cmd")
        outcome = (f"payload row={got is not None}; wildcard row="
                   f"{got_wild is not None}; original row still="
                   f"{still_there is not None}")
        tables_ok = still_there is not None
    except Exception as exc:  # noqa: BLE001
        await session.rollback()
        outcome = f"{type(exc).__name__}: {str(exc)[:80]}"
        tables_ok = False
    ok = tables_ok and "payload row=False" in outcome \
        and "wildcard row=False" in outcome
    recorder.add(
        "V06-100", "L",
        "SQL injection payloads cannot extract or destroy data through lookup",
        payload, "no row, '%' is literal, table intact",
        outcome,
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F4/F13: every filter is a bound parameter compared with == on the "
        "trimmed canonical value - no string interpolation, no ilike, so '%' "
        "and '_' are literal characters (resolves the old V06-79/V06-105 "
        "wildcard residual risk)",
        "",
    )
    assert ok


async def test_v06_101_negative_list_limit_unguarded(kb_db, recorder):
    from app.ai import kb_domain as dom
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "lim", "m",
                      universal_model_path="device.hostname", actor=str(uid))
    await session.commit()

    async def _attempt(**kwargs):
        try:
            rows = await repo.list_mappings(**kwargs)
            return f"returned {len(rows)} rows"
        except dom.KBValidationError as exc:
            await session.rollback()
            return f"KBValidationError: {exc}"
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            return f"unhandled {type(exc).__name__} raised to the caller"

    negative = await _attempt(limit=-1)
    offset = await _attempt(offset=-5)
    huge = await _attempt(limit=10**9)
    unbounded = await _attempt(limit=None)
    ok = (negative.startswith("KBValidationError")
          and offset.startswith("KBValidationError")
          and huge.startswith("KBValidationError")
          and unbounded == "returned 1 rows")
    recorder.add(
        "V06-101", "L",
        "negative/absurd limit values are rejected with a typed error (or clamped) "
        "rather than passed to SQL",
        "list_mappings(limit=-1 / offset=-5 / limit=1e9 / limit=None)",
        "typed rejection for negative and absurd bounds; None means unbounded",
        f"limit=-1 -> {negative}; offset=-5 -> {offset}; limit=1e9 -> {huge}; "
        f"limit=None -> {unbounded}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F17: kb_domain.validate_limit_offset bounds both values (max 1000) "
        "in every store; the API's Query(ge=0, le=100) is a second, narrower gate",
        "",
    )
    assert ok


async def test_v06_102_vendor_over_50_unguarded_repo(kb_db, recorder):
    from app.ai import kb_domain as dom
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)

    async def _attempt(**kwargs):
        try:
            await repo.create(**kwargs)
            await session.commit()
            return "stored (no guard at all)"
        except dom.KBValidationError as exc:
            await session.rollback()
            return f"KBValidationError: {str(exc)[:70]}"
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            return f"unhandled {type(exc).__name__} raised to the caller"

    long_vendor = await _attempt(vendor="v" * 51, platform="ios", raw_syntax="cmd",
                                 semantic_meaning="m",
                                 universal_model_path="device.hostname",
                                 actor=str(uid))
    long_platform = await _attempt(vendor="cisco", platform="p" * 51,
                                   raw_syntax="cmd2", semantic_meaning="m",
                                   universal_model_path="device.hostname",
                                   actor=str(uid))
    bad_path = await _attempt(vendor="cisco", platform="ios", raw_syntax="cmd3",
                              semantic_meaning="m",
                              universal_model_path="not.a.model.path",
                              actor=str(uid))
    exact = await _attempt(vendor="v" * 50, platform="ios", raw_syntax="cmd4",
                           semantic_meaning="m",
                           universal_model_path="device.hostname",
                           actor=str(uid))
    ok = (long_vendor.startswith("KBValidationError")
          and long_platform.startswith("KBValidationError")
          and bad_path.startswith("KBValidationError")
          and exact == "stored (no guard at all)")
    recorder.add(
        "V06-102", "L",
        "the repository enforces the section 15.1 VARCHAR(50) vendor/platform bound "
        "and the model-path vocabulary with a typed error",
        "vendor/platform of 51 chars and an unknown model path via repo.create",
        "typed rejection; a 50-char vendor is accepted",
        f"vendor(51) -> {long_vendor}; platform(51) -> {long_platform}; "
        f"bad path -> {bad_path}; vendor(50) -> {exact}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F9/F17: kb_domain.validate_mapping_fields enforces VENDOR_MAX_LEN=50, "
        "PLATFORM_MAX_LEN=50 and is_valid_model_path() before any SQL, so the "
        "driver never raises DataError and the API answers 422",
        "",
    )
    assert ok


async def test_v06_103_non_string_raw_syntax_crashes(kb, recorder):
    outcomes = {}
    for label, bad in (("int", 12345), ("none", None), ("bytes", b"cmd"),
                       ("list", ["a"])):
        try:
            KnowledgeBase().create("cisco", "ios", bad, "m",
                                   universal_model_path="device.hostname",
                                   actor="t")
            outcomes[label] = "accepted"
        except TypeError as exc:
            outcomes[label] = f"TypeError: {str(exc)[:60]}"
        except Exception as exc:  # noqa: BLE001
            outcomes[label] = f"{type(exc).__name__}: {str(exc)[:60]}"
    # lookup() must be total for hostile types too (no crash, just a miss)
    try:
        miss = KnowledgeBase().lookup("cisco", "ios", 12345)
        lookup_outcome = f"miss={miss is None}"
    except Exception as exc:  # noqa: BLE001
        lookup_outcome = f"raised {type(exc).__name__}"
    ok = all(v.startswith("TypeError") for v in outcomes.values()) \
        and lookup_outcome == "miss=True"
    recorder.add(
        "V06-103", "L",
        "non-string raw_syntax is rejected with a clear typed error, and lookup "
        "stays total for hostile input",
        "raw_syntax = 12345 / None / bytes / list; lookup(12345)",
        "TypeError with a helpful message on write; None on lookup",
        f"{outcomes}; lookup -> {lookup_outcome}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F17: kb_domain.check_text raises TypeError for non-str before any "
        "attribute access (the old AttributeError from .strip()), and lookup() "
        "converts hostile input into a miss instead of an exception",
        "",
    )
    assert ok


async def test_v06_104_list_mappings_no_filters_sanitized(kb, recorder):
    kb.create("cisco", "ios", "s1", "m1",
              universal_model_path="device.hostname", actor="t")
    kb.create("juniper", "junos", "s2", "m2",
              universal_model_path="device.hostname", actor="t")
    try:
        rows_a = kb.list_mappings(vendor="cisco%")
        rows_b = kb.list_mappings(platform="nos")
        rows_c = kb.list_mappings(vendor="CISCO")
        ok = rows_a == [] and rows_b == [] and len(rows_c) == 1
        outcome = (f"vendor='cisco%' -> {len(rows_a)} rows; "
                   f"platform='nos' -> {len(rows_b)} rows; "
                   f"vendor='CISCO' -> {len(rows_c)} row(s)")
    except Exception as exc:  # noqa: BLE001
        ok = False
        outcome = f"{type(exc).__name__}: {exc}"
    recorder.add(
        "V06-104", "L",
        "list filters match literally and case-insensitively (no wildcard "
        "reinterpretation) in the in-memory store",
        "vendor='cisco%', platform='nos', vendor='CISCO'",
        "0 rows for the wildcard/miss, 1 for the case variant",
        outcome,
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F13: kb_domain.canonical_vendor filter == comparison - identical "
        "semantics to the SQL repository (see V06-105)",
        "",
    )
    assert ok


async def test_v06_105_repo_list_filter_wildcards_accepted(kb_db, recorder):
    from app.repositories.knowledge_base import KnowledgeBaseRepository

    session, uid, _ = kb_db
    repo = KnowledgeBaseRepository(session)
    await repo.create("cisco", "ios", "w1", "m1",
                      universal_model_path="device.hostname", actor=str(uid))
    await repo.create("juniper", "junos", "w2", "m2",
                      universal_model_path="device.hostname", actor=str(uid))
    await session.commit()
    rows = await repo.list_mappings(vendor="cis%")
    underscore = await repo.list_mappings(vendor="cisco_")
    exact = await repo.list_mappings(vendor="CISCO")
    count_exact = await repo.count_mappings(vendor="cisco")
    ok = (len(rows) == 0 and len(underscore) == 0 and len(exact) == 1
          and count_exact == 1)
    recorder.add(
        "V06-105", "L",
        "list filters treat '%' literally in every implementation (consistency with V06-104)",
        "repo.list_mappings(vendor='cis%' / 'cisco_' / 'CISCO')",
        "0 rows for wildcards, 1 row for the canonical case variant; count agrees",
        f"'cis%' -> {len(rows)} row(s); 'cisco_' -> {len(underscore)} row(s); "
        f"'CISCO' -> {len(exact)} row(s); count(vendor='cisco')={count_exact}",
        "PASS" if ok else "FAIL",
        "CONFIRMED BEHAVIOR" if ok else "BUG",
        "E06 F13: repository list/count share one literal canonical filter "
        "builder - the old ilike accepted wildcards and diverged from the "
        "in-memory twin",
        "",
    )
    assert ok


# <<<CHUNK-END>>>
