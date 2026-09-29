"""Execute migration 008 for real against the throwaway validation database.

The pytest suites create their schema from model metadata, which proves the
MODEL is self-consistent but says nothing about the migration. This script
executes the real Alembic chain on `engine_validation_test` only:

  1. wipe the throwaway database (tables + alembic_version)
  2. upgrade -> 007 (the pre-E09 head)
  3. insert a finding row without risk columns populated
  4. upgrade -> 008 and assert: the four risk columns exist, the legacy
     row survives with NULL risk fields (safe defaults), and a new row
     can be written + read back with risk values
  5. downgrade -> 007 and assert the structural reversal
  6. upgrade -> 008 again (round trip), then restore the metadata schema

Never touches the configured application database: DATABASE_URL is overridden
to TEST_DB_URL for the duration of this process only.

Writes artifacts/engine_validation/09_risk/migration_results.json
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
OUT = BACKEND / "artifacts" / "engine_validation" / "09_risk"
OUT.mkdir(parents=True, exist_ok=True)

TEST_DB_URL = "postgresql+asyncpg://postgres:postgres@localhost:5432/engine_validation_test"
# alembic/env.py reads settings.DATABASE_URL; force the throwaway database for
# this process only (environment variables beat .env in pydantic-settings).
os.environ["DATABASE_URL"] = TEST_DB_URL

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": str(detail)[:400]})


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


def q(sql: str, **params):
    return asyncio.run(_q(sql, **params))


def run_sql(sql: str, **params) -> None:
    asyncio.run(_exec(sql, **params))


def drop_everything() -> None:
    run_sql("DROP SCHEMA IF EXISTS public CASCADE")
    run_sql("CREATE SCHEMA public")


def main() -> int:
    from scripts.engine_validation import dbutil

    # 1. clean slate, then the pre-E09 revision
    drop_everything()
    check("throwaway database wiped (tables + alembic_version)", True,
          "DROP SCHEMA public CASCADE / CREATE SCHEMA public")
    alembic_upgrade("007")
    check("upgrade -> 007 (pre-E09 head)", True, "alembic 001..007 applied")
    version = q("SELECT version_num FROM alembic_version")
    check("alembic head is 007 before the E09 migration",
          version and version[0][0] == "007", f"{version}")
    cols_before = {r[0] for r in q(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'findings'")}
    check("007 findings table has no risk columns",
          not ({"risk_score", "priority", "risk_method",
                "risk_model_version"} & cols_before),
          f"{sorted(cols_before)}")

    # 2. legacy row without risk data
    user_id = uuid.uuid4()
    run_sql(
        "INSERT INTO users (id, email, password_hash, full_name, role, "
        "is_active, created_at, updated_at) VALUES "
        "(:id, :email, 'x', 'Legacy', 'admin', true, now(), now())",
        id=user_id, email=f"legacy-{user_id}@example.test")
    audit_id = uuid.uuid4()
    run_sql(
        "INSERT INTO audits (id, user_id, name, status) VALUES "
        "(:id, :uid, 'legacy', 'completed')", id=audit_id, uid=user_id)
    legacy_id = uuid.uuid4()
    run_sql(
        "INSERT INTO findings (id, audit_id, title, description, severity, "
        "confidence, status, evidence) VALUES (:id, :aid, 'Legacy', 'desc', "
        "'HIGH', 0.9, 'open', '{}')", id=legacy_id, aid=audit_id)

    # 3. upgrade -> 008
    alembic_upgrade("008")
    version = q("SELECT version_num FROM alembic_version")
    check("alembic head is 008 after the E09 migration",
          version and version[0][0] == "008", f"{version}")
    cols_after = {r[0] for r in q(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'findings'")}
    check("008 adds the four risk columns",
          {"risk_score", "priority", "risk_method",
           "risk_model_version"} <= cols_after,
          f"{sorted(cols_after)}")
    legacy = q("SELECT risk_score, priority, risk_method, "
               "risk_model_version FROM findings WHERE id = :id",
               id=legacy_id)
    check("legacy row survives with NULL risk fields (safe defaults)",
          legacy and all(v is None for v in legacy[0]), f"{legacy}")

    # 4. insert/read a fully-populated risk row through the migrated schema
    scored_id = uuid.uuid4()
    run_sql(
        "INSERT INTO findings (id, audit_id, control_id, title, description, "
        "severity, confidence, status, evidence, risk_score, priority, "
        "risk_method, risk_model_version) VALUES (:id, :aid, '1.1.1', "
        "'Scored', 'desc', 'HIGH', 0.9, 'open', '{}', 48.1, 'P3', "
        "'deterministic', 'v1')", id=scored_id, aid=audit_id)
    back = q("SELECT risk_score, priority, risk_method, risk_model_version "
             "FROM findings WHERE id = :id", id=scored_id)
    check("risk row round-trips through the migrated schema",
          back and tuple(back[0]) == (48.1, "P3", "deterministic", "v1"),
          f"{back}")

    # 5. downgrade -> 007 reverses the structure
    alembic_downgrade("007")
    cols_down = {r[0] for r in q(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'findings'")}
    check("downgrade -> 007 drops the four risk columns",
          not ({"risk_score", "priority", "risk_method",
                "risk_model_version"} & cols_down),
          f"{sorted(cols_down)}")

    # 6. round trip back to head
    alembic_upgrade("008")
    rt = q("SELECT version_num FROM alembic_version")
    check("round trip 008 -> 007 -> 008 returns to head",
          rt and rt[0][0] == "008", f"{rt}")

    # restore the metadata-created schema the pytest suites expect
    asyncio.run(dbutil.create_schema())
    check("throwaway schema restored from model metadata for the pytest suites",
          True, "scripts.engine_validation.dbutil.create_schema")

    violations = [c for c in CHECKS if not c["ok"]]
    result = {
        "migration": "008_finding_risk_columns",
        "database": "engine_validation_test (throwaway)",
        "executed": ["wipe", "upgrade 001->007", "insert legacy row",
                     "upgrade 007->008", "insert/read risk row",
                     "downgrade 008->007", "upgrade 007->008",
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
    print(f"migration 008 verdict: {result['verdict']} "
          f"({result['violations_total']} violations)")
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
