"""Execute migration 007 for real against the throwaway validation database.

The pytest suites create their schema from model metadata, which proves the
MODEL is self-consistent but says nothing about the migration. This script
executes the real Alembic chain on `engine_validation_test` only:

  1. wipe the throwaway database (tables + alembic_version)
  2. upgrade -> 006 (the pre-E08 head)
  3. insert legacy-shaped rows: lowercase severity on findings +
     compliance_results, and a finding linked to a compliance row but with
     a NULL control_id
  4. upgrade -> 007 and assert: severities uppercased in place on both
     tables, findings.control_id column exists + indexed, and the linked
     row was backfilled from its compliance_results row
  5. downgrade -> 006 and assert the structural reversal
     (control_id column dropped; severities lowercased back)
  6. upgrade -> 007 again (round trip), then restore the metadata schema

Never touches the configured application database: DATABASE_URL is overridden
to TEST_DB_URL for the duration of this process only.

Writes artifacts/engine_validation/08_findings/migration_results.json
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
OUT = BACKEND / "artifacts" / "engine_validation" / "08_findings"
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

    # 1. clean slate, then the pre-E08 revision
    drop_everything()
    check("throwaway database wiped (tables + alembic_version)", True,
          "DROP SCHEMA public CASCADE / CREATE SCHEMA public")
    alembic_upgrade("006")
    check("upgrade -> 006 (pre-E08 head)", True, "alembic 001..006 applied")
    version = q("SELECT version_num FROM alembic_version")
    check("alembic head is 006 before the E08 migration",
          version and version[0][0] == "006", f"{version}")

    # 2. legacy rows: lowercase severities + unlinked finding
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
    comp_id = uuid.uuid4()
    run_sql(
        "INSERT INTO compliance_results (id, audit_id, "
        "normalized_configuration_id, framework, control_id, control_name, "
        "result, confidence, severity, evidence) VALUES (:id, :aid, :nid, "
        "'CIS', '1.1.1', 'Legacy', 'PASS', 0.9, 'high', '{}')",
        id=comp_id, aid=audit_id, nid=norm_id)
    finding_id = uuid.uuid4()
    run_sql(
        "INSERT INTO findings (id, audit_id, compliance_result_id, title, "
        "description, severity, confidence, status, evidence) VALUES "
        "(:id, :aid, :cid, 'Legacy finding', 'desc', 'medium', 0.9, 'open', "
        "'{}')", id=finding_id, aid=audit_id, cid=comp_id)
    before = q("SELECT severity FROM findings WHERE id = :id", id=finding_id)
    check("legacy lowercase rows inserted at 006",
          before and before[0][0] == "medium", f"{before}")

    # 3. upgrade -> 007
    alembic_upgrade("007")
    version = q("SELECT version_num FROM alembic_version")
    check("alembic head is 007 after the E08 migration",
          version and version[0][0] == "007", f"{version}")
    after_f = q("SELECT severity, control_id FROM findings WHERE id = :id",
                id=finding_id)
    after_c = q("SELECT severity FROM compliance_results WHERE id = :id",
                id=comp_id)
    check("007 uppercases findings.severity in place",
          after_f and after_f[0][0] == "MEDIUM", f"{after_f}")
    check("007 uppercases compliance_results.severity in place",
          after_c and after_c[0][0] == "HIGH", f"{after_c}")
    check("007 backfills findings.control_id from the linked row",
          after_f and after_f[0][1] == "1.1.1", f"{after_f}")
    idx = q("SELECT indexname FROM pg_indexes WHERE tablename = 'findings' "
            "AND indexname = 'ix_findings_control_id'")
    check("007 creates ix_findings_control_id", bool(idx), f"{idx}")
    remaining = q("SELECT COUNT(*) FROM findings WHERE severity <> "
                  "UPPER(severity)")
    remaining += q("SELECT COUNT(*) FROM compliance_results WHERE severity "
                   "<> UPPER(severity)")
    check("no lowercase severities remain on either table",
          all(r[0] == 0 for r in remaining), f"{remaining}")

    # 4. downgrade -> 006 reverses the structure
    alembic_downgrade("006")
    cols = q("SELECT column_name FROM information_schema.columns WHERE "
             "table_name = 'findings' AND column_name = 'control_id'")
    back = q("SELECT severity FROM findings WHERE id = :id", id=finding_id)
    check("downgrade -> 006 drops findings.control_id",
          not cols, f"{cols}")
    check("downgrade -> 006 restores lowercase (documented reversal)",
          back and back[0][0] == "medium", f"{back}")

    # 5. round trip back to head
    alembic_upgrade("007")
    rt = q("SELECT version_num FROM alembic_version")
    check("round trip 007 -> 006 -> 007 returns to head",
          rt and rt[0][0] == "007", f"{rt}")

    # restore the metadata-created schema the pytest suites expect
    asyncio.run(dbutil.create_schema())
    check("throwaway schema restored from model metadata for the pytest suites",
          True, "scripts.engine_validation.dbutil.create_schema")

    violations = [c for c in CHECKS if not c["ok"]]
    result = {
        "migration": "007_finding_severity_control_link",
        "database": "engine_validation_test (throwaway)",
        "executed": ["wipe", "upgrade 001->006", "insert legacy rows",
                     "upgrade 006->007", "downgrade 007->006",
                     "upgrade 006->007", "restore metadata schema"],
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
    print(f"migration 007 verdict: {result['verdict']} "
          f"({result['violations_total']} violations)")
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
