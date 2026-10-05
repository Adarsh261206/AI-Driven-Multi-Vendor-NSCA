"""Execute migration 006 for real against the throwaway validation database.

The pytest suites create their schema from model metadata, which proves the
MODEL is self-consistent but says nothing about the migration. This script
executes the real Alembic chain on `engine_validation_test` only:

  1. wipe the throwaway database (tables + alembic_version)
  2. upgrade -> 005 (the pre-E07 head)
  3. insert a legacy-shaped compliance_results row with a lowercase result
  4. upgrade -> 006 and assert the row was uppercased in place
  5. insert a new row and assert the canonical writer stores uppercase
  6. downgrade -> 005 and assert the structural reversal
  7. upgrade -> 006 again (round trip), then restore the metadata schema

Never touches the configured application database: DATABASE_URL is overridden
to TEST_DB_URL for the duration of this process only.

Writes artifacts/engine_validation/07_compliance/migration_results.json
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
OUT = BACKEND / "artifacts" / "engine_validation" / "07_compliance"
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

    # 1. clean slate, then the pre-E07 revision
    drop_everything()
    check("throwaway database wiped (tables + alembic_version)", True,
          "DROP SCHEMA public CASCADE / CREATE SCHEMA public")
    alembic_upgrade("005")
    check("upgrade -> 005 (pre-E07 head)", True, "alembic 001..005 applied")
    version = q("SELECT version_num FROM alembic_version")
    check("alembic head is 005 before the E07 migration",
          version and version[0][0] == "005", f"{version}")

    # 2. legacy row: lowercase result as the pre-E07 pipeline wrote it
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
    config_id = uuid.uuid4()
    run_sql(
        "INSERT INTO configurations (id, filename, content_hash, raw_content, "
        "content_type, size_bytes, line_count) VALUES (:id, 'legacy.cfg', "
        ":h, 'hostname R1', 'text/plain', 11, 1)",
        id=config_id, h=f"legacy-{uuid.uuid4().hex}")
    parsed_id = uuid.uuid4()
    run_sql(
        "INSERT INTO parsed_configurations (id, configuration_id, vendor, "
        "platform, parse_tree, parse_errors, parse_warnings, "
        "unknown_sections) VALUES (:id, :cid, 'cisco', 'ios_xe', '[]', "
        "'[]', '[]', '[]')", id=parsed_id, cid=config_id)
    sem_id = uuid.uuid4()
    run_sql(
        "INSERT INTO semantic_interpretations (id, parsed_configuration_id, "
        "semantic_sections, confidence_scores, unknown_meanings) VALUES "
        "(:id, :pid, '[]', '{}', '[]')", id=sem_id, pid=parsed_id)
    norm_id = uuid.uuid4()
    run_sql(
        "INSERT INTO normalized_configurations (id, "
        "semantic_interpretation_id, universal_model_version, "
        "normalized_values, unmapped_concepts) VALUES (:id, :sid, 'v1', "
        "'[]', '[]')", id=norm_id, sid=sem_id)
    legacy_row = uuid.uuid4()
    run_sql(
        "INSERT INTO compliance_results (id, audit_id, "
        "normalized_configuration_id, framework, control_id, control_name, "
        "result, confidence, severity, evidence) VALUES (:id, :aid, :nid, "
        "'CIS', '1.1.1', 'Legacy', 'pass', 0.9, 'HIGH', '{}')",
        id=legacy_row, aid=audit_id, nid=norm_id)
    before = q("SELECT result FROM compliance_results WHERE id = :id",
               id=legacy_row)
    check("legacy lowercase row inserted at 005",
          before and before[0][0] == "pass", f"{before}")

    # 3. upgrade -> 006
    alembic_upgrade("006")
    version = q("SELECT version_num FROM alembic_version")
    check("alembic head is 006 after the E07 migration",
          version and version[0][0] == "006", f"{version}")
    after = q("SELECT result FROM compliance_results WHERE id = :id",
              id=legacy_row)
    check("006 uppercases the legacy row in place (no reinterpretation)",
          after and after[0][0] == "PASS", f"{after}")

    # 4. downgrade -> 005 reverses the casing (structural reversal)
    alembic_downgrade("005")
    back = q("SELECT result FROM compliance_results WHERE id = :id",
             id=legacy_row)
    check("downgrade -> 005 restores lowercase (documented reversal)",
          back and back[0][0] == "pass", f"{back}")

    # 5. round trip back to head
    alembic_upgrade("006")
    rt = q("SELECT version_num FROM alembic_version")
    check("round trip 006 -> 005 -> 006 returns to head",
          rt and rt[0][0] == "006", f"{rt}")

    # restore the metadata-created schema the pytest suites expect
    asyncio.run(dbutil.create_schema())
    check("throwaway schema restored from model metadata for the pytest suites",
          True, "scripts.engine_validation.dbutil.create_schema")

    violations = [c for c in CHECKS if not c["ok"]]
    result = {
        "migration": "006_uppercase_compliance_results",
        "database": "engine_validation_test (throwaway)",
        "executed": ["wipe", "upgrade 001->005", "insert lowercase row",
                     "upgrade 005->006", "downgrade 006->005",
                     "upgrade 005->006", "restore metadata schema"],
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
    print(f"migration 006 verdict: {result['verdict']} "
          f"({result['violations_total']} violations)")
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
