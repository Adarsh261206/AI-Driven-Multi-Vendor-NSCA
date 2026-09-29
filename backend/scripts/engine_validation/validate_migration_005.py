"""Execute migration 005 for real against the throwaway validation database.

The pytest suites create their schema from model metadata, which proves the
MODEL is self-consistent but says nothing about the migration. This script
executes the real Alembic chain on `engine_validation_test` only:

  1. drop everything, upgrade -> 004 (the pre-E06 state)
  2. insert LEGACY-shaped rows (case variants, trailing whitespace, NULL model
     path, FLOAT confidence, UUID actor ids, a canonical duplicate pair with
     version rows on both) and assert the pre-E06 schema really has them
  3. upgrade -> 005 and assert the reconciled data + column/constraint contract
  4. downgrade -> 004 and assert the structural reversal
  5. upgrade -> 005 again (round trip), then restore the metadata schema

Never touches the configured application database: DATABASE_URL is overridden
to TEST_DB_URL for the duration of this process only.

Writes artifacts/engine_validation/06_knowledge_base/migration_results.json
and exits 1 if any check fails.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))
OUT = BACKEND / "artifacts" / "engine_validation" / "06_knowledge_base"
OUT.mkdir(parents=True, exist_ok=True)

TEST_DB_URL = "postgresql+asyncpg://postgres:postgres@localhost:5432/engine_validation_test"
# alembic/env.py reads settings.DATABASE_URL; force the throwaway database for
# this process only (environment variables beat .env in pydantic-settings).
os.environ["DATABASE_URL"] = TEST_DB_URL

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": str(detail)[:400]})


# ---------------------------------------------------------------------------
# Alembic (synchronous: alembic's env.py runs its own asyncio.run)
# ---------------------------------------------------------------------------

def _config():
    from alembic.config import Config

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    return cfg


def alembic_upgrade(rev: str) -> None:
    from alembic import command

    command.upgrade(_config(), rev)


def alembic_downgrade(rev: str) -> None:
    from alembic import command

    command.downgrade(_config(), rev)


# ---------------------------------------------------------------------------
# Database access (async internals, sync wrappers)
# ---------------------------------------------------------------------------

async def _q(sql: str, **params):
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(TEST_DB_URL)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text(sql), params)
            return result.fetchall()
    finally:
        await engine.dispose()


async def _exec(sql: str, **params) -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(TEST_DB_URL)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params)
    finally:
        await engine.dispose()


async def _columns(table: str) -> dict[str, str]:
    """column -> exact SQL type (with length/precision) + NOT NULL marker."""
    rows = await _q(
        "SELECT a.attname, format_type(a.atttypid, a.atttypmod) || "
        "CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END "
        "FROM pg_attribute a WHERE a.attrelid = to_regclass(:t) "
        "AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum", t=table)
    return {r[0]: r[1] for r in rows}


async def _constraints(table: str) -> dict[str, str]:
    rows = await _q(
        "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = to_regclass(:t) ORDER BY conname", t=table)
    return {r[0]: r[1] for r in rows}


def q(sql: str, **params):
    return asyncio.run(_q(sql, **params))


def run_sql(sql: str, **params) -> None:
    asyncio.run(_exec(sql, **params))


def drop_everything() -> None:
    """Wipe the throwaway database INCLUDING alembic_version.

    `dbutil.drop_schema()` only drops model-metadata tables, which would
    leave a stale alembic_version behind and silently skip migrations.
    """
    run_sql("DROP SCHEMA IF EXISTS public CASCADE")
    run_sql("CREATE SCHEMA public")


def columns(table: str) -> dict[str, str]:
    return asyncio.run(_columns(table))


def constraints(table: str) -> dict[str, str]:
    return asyncio.run(_constraints(table))


# ---------------------------------------------------------------------------

def main() -> int:
    from scripts.engine_validation import dbutil

    # 1. clean slate, then the pre-E06 revision
    drop_everything()
    check("throwaway database wiped (tables + alembic_version)", True,
          "DROP SCHEMA public CASCADE / CREATE SCHEMA public")
    alembic_upgrade("004")
    check("upgrade -> 004 (pre-E06 baseline)", True, "alembic 001..004 applied")
    pre_cols = columns("semantic_mappings")
    check("004 has the legacy shape (UUID created_by_id, FLOAT confidence, "
          "nullable model path)",
          pre_cols.get("created_by_id") == "uuid NOT NULL"
          and pre_cols.get("confidence") == "double precision NOT NULL"
          and pre_cols.get("universal_model_path") == "character varying(255)",
          f"created_by_id={pre_cols.get('created_by_id')} "
          f"confidence={pre_cols.get('confidence')} "
          f"universal_model_path={pre_cols.get('universal_model_path')}")

    # 2. legacy data: the exact shapes migration 005 must reconcile
    user_id = uuid.uuid4()
    run_sql(
        "INSERT INTO users (id, email, password_hash, full_name, role, "
        "is_active, created_at, updated_at) VALUES "
        "(:id, :email, 'x', 'Legacy', 'admin', true, now(), now())",
        id=user_id, email=f"legacy-{user_id}@example.test")
    keep, drop = uuid.uuid4(), uuid.uuid4()
    for mapping_id, vendor, platform, syntax, path in (
            (keep, "Cisco", "IOS", "ntp server 1.1.1.1", "ntp.servers"),
            (drop, "cisco", "ios", "  ntp server 1.1.1.1  ", "ntp.servers")):
        run_sql(
            "INSERT INTO semantic_mappings (id, vendor, platform, raw_syntax, "
            "semantic_meaning, universal_model_path, confidence, admin_confirmed, "
            "version, created_by_id, created_at, updated_at) VALUES "
            "(:id, :vendor, :platform, :syntax, 'upstream NTP', :path, 0.900000, "
            "true, 1, :uid, now(), now())",
            id=mapping_id, vendor=vendor, platform=platform, syntax=syntax,
            path=path, uid=user_id)
        run_sql(
            "INSERT INTO mapping_versions (id, mapping_id, version, raw_syntax, "
            "semantic_meaning, universal_model_path, changed_by_id, changed_at, "
            "change_reason) VALUES (:vid, :mid, 1, :syntax, 'upstream NTP', :path, "
            ":uid, now(), 'Initial creation')",
            vid=uuid.uuid4(), mid=mapping_id, syntax=syntax, path=path, uid=user_id)
    # a legacy row that predates model-path validation
    run_sql(
        "INSERT INTO semantic_mappings (id, vendor, platform, raw_syntax, "
        "semantic_meaning, universal_model_path, confidence, admin_confirmed, "
        "version, created_by_id, created_at, updated_at) VALUES "
        "(:id, 'cisco', 'ios', 'legacy no path', 'legacy', NULL, 0.400000, "
        "false, 1, :uid, now(), now())", id=uuid.uuid4(), uid=user_id)
    legacy_rows = q("SELECT COUNT(*) FROM semantic_mappings")
    check("legacy rows inserted (case-variant pair + NULL model path)",
          legacy_rows[0][0] == 3, f"rows={legacy_rows[0][0]}")

    # 3. upgrade -> 005
    alembic_upgrade("005")
    cols = columns("semantic_mappings")
    vcols = columns("mapping_versions")
    cons = constraints("semantic_mappings")
    vcons = constraints("mapping_versions")
    check("005: universal_model_path NOT NULL (both tables)",
          cols.get("universal_model_path") == "character varying(255) NOT NULL"
          and vcols.get("universal_model_path") == "character varying(255) NOT NULL",
          f"{cols.get('universal_model_path')} / {vcols.get('universal_model_path')}")
    check("005: confidence NUMERIC(5,2) on both tables",
          cols.get("confidence") == "numeric(5,2) NOT NULL"
          and vcols.get("confidence") == "numeric(5,2)",
          f"{cols.get('confidence')} / {vcols.get('confidence')}")
    check("005: actor columns are VARCHAR(100) NOT NULL",
          cols.get("created_by") == "character varying(100) NOT NULL"
          and vcols.get("changed_by") == "character varying(100) NOT NULL",
          f"created_by={cols.get('created_by')} changed_by={vcols.get('changed_by')}")
    check("005: UNIQUE(vendor, platform, raw_syntax, version)",
          cons.get("uq_semantic_mappings_identity_version", "").lower()
          == "unique (vendor, platform, raw_syntax, version)",
          cons.get("uq_semantic_mappings_identity_version"))
    check("005: mapping_versions keeps its mapping FK (history cascades)",
          "mapping_versions_mapping_id_fkey" in vcons, sorted(vcons))
    check("005: no users FK remains on either KB table",
          not any("users" in v for v in list(cons.values()) + list(vcons.values())),
          f"{sorted(cons)} | {sorted(vcons)}")

    merged = q(
        "SELECT vendor, platform, raw_syntax, confidence, created_by, "
        "universal_model_path FROM semantic_mappings ORDER BY raw_syntax")
    identities = [(r[0], r[1], r[2]) for r in merged]
    check("005: canonical duplicates merged into one row (case + whitespace)",
          identities.count(("cisco", "ios", "ntp server 1.1.1.1")) == 1
          and not any(v == "Cisco" for v, _, _ in identities),
          f"identities={identities}")
    survivor = next(r for r in merged if r[2] == "ntp server 1.1.1.1")
    check("005: surviving row keeps a VARCHAR actor (identity survives user deletion)",
          isinstance(survivor[4], str) and survivor[4] != "",
          f"created_by={survivor[4]!r}")
    check("005: confidence converted to NUMERIC(5,2) and preserved",
          float(survivor[3]) == 0.90, f"confidence={survivor[3]}")
    legacy = next(r for r in merged if r[2] == "legacy no path")
    check("005: NULL model path backfilled to '' (visibly degraded, not valid)",
          legacy[5] == "", f"universal_model_path={legacy[5]!r}")
    versions = q(
        "SELECT mapping_id FROM mapping_versions WHERE raw_syntax LIKE '%ntp%'")
    check("005: version history preserved (no rows deleted; both v1 records "
          "reassigned to the survivor)",
          len(versions) == 2 and len({str(r[0]) for r in versions}) == 1,
          f"{[str(r[0]) for r in versions]}")

    # 4. downgrade -> 004
    alembic_downgrade("004")
    dcols = columns("semantic_mappings")
    dvcols = columns("mapping_versions")
    dcons = constraints("semantic_mappings")
    check("downgrade -> 004 restores the pre-E06 structure",
          dcols.get("created_by_id") == "uuid NOT NULL"
          and dcols.get("confidence") == "double precision NOT NULL"
          and dcols.get("universal_model_path") == "character varying(255)"
          and "confidence" not in dvcols
          and "uq_semantic_mappings_identity_version" not in dcons,
          f"created_by_id={dcols.get('created_by_id')} "
          f"confidence={dcols.get('confidence')} "
          f"universal_model_path={dcols.get('universal_model_path')} "
          f"mapping_versions.confidence={dvcols.get('confidence')}")

    # 5. round trip back to head
    alembic_upgrade("005")
    rt = constraints("semantic_mappings")
    check("round trip 005 -> 004 -> 005 re-applies the unique constraint",
          "uq_semantic_mappings_identity_version" in rt, sorted(rt))

    # restore the metadata-created schema the pytest suites expect
    asyncio.run(dbutil.create_schema())
    check("throwaway schema restored from model metadata for the pytest suites",
          True, "scripts.engine_validation.dbutil.create_schema")

    violations = [c for c in CHECKS if not c["ok"]]
    result = {
        "migration": "005_kb_contract",
        "database": "engine_validation_test (throwaway)",
        "executed": ["upgrade 001->004", "insert legacy rows", "upgrade 004->005",
                     "downgrade 005->004", "upgrade 004->005",
                     "restore metadata schema"],
        "checks": CHECKS,
        "violations_total": len(violations),
        "verdict": "PASS" if not violations else "FAIL",
    }
    (OUT / "migration_results.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    for entry in CHECKS:
        print(f"  [{'PASS' if entry['ok'] else 'FAIL'}] {entry['check']}")
        if not entry["ok"]:
            print(f"         {entry['detail']}")
    print(f"migration 005 verdict: {result['verdict']} "
          f"({result['violations_total']} violations)")
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
