"""Execute migration 009 for real against the throwaway validation database.

The pytest suites create their schema from model metadata, which proves the
MODEL is self-consistent but says nothing about the migration. This script
executes the real Alembic chain on `engine_validation_test` only:

  1. wipe the throwaway database (tables + alembic_version)
  2. upgrade -> 008 (the pre-chain head)
  3. insert a legacy audit-trail row (no chain columns exist yet)
  4. upgrade -> 009 and assert: seq/previous_hash/event_hash exist, the
     legacy row survives with a backfilled seq and NULL hashes (pre-chain
     era, never rewritten), and new rows written through the repository
     form a genesis-anchored chain (recomputed independently here)
  5. downgrade -> 008 and assert the structural reversal
  6. upgrade -> 009 again (round trip), then restore the metadata schema

Never touches the configured application database: DATABASE_URL is overridden
to TEST_DB_URL for the duration of this process only.

Writes artifacts/engine_validation/12_audit_trail/migration_009_results.json
and exits 1 if any check fails.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))
OUT = BACKEND / "artifacts" / "engine_validation" / "12_audit_trail"
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

    # 1. clean slate, then the pre-chain revision
    drop_everything()
    check("throwaway database wiped (tables + alembic_version)", True,
          "DROP SCHEMA public CASCADE / CREATE SCHEMA public")
    alembic_upgrade("008")
    check("upgrade -> 008 (pre-chain head)", True, "alembic 001..008 applied")
    version = q("SELECT version_num FROM alembic_version")
    check("alembic head is 008 before the ledger migration",
          version and version[0][0] == "008", f"{version}")
    cols_before = {r[0] for r in q(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'audit_trail'")}
    check("008 audit_trail has no chain columns",
          not ({"seq", "previous_hash", "event_hash"} & cols_before),
          f"{sorted(cols_before)}")

    # 2. legacy row from the pre-chain era
    user_id = uuid.uuid4()
    run_sql(
        "INSERT INTO users (id, email, password_hash, full_name, role, "
        "is_active, created_at, updated_at) VALUES "
        "(:id, :email, 'x', 'Legacy', 'admin', true, now(), now())",
        id=user_id, email=f"legacy-{user_id}@example.test")
    legacy_id = uuid.uuid4()
    run_sql(
        "INSERT INTO audit_trail (id, entity_type, action, user_id, "
        "details, created_at) VALUES (:id, 'audit', 'audit_completed', "
        ":uid, '{}', now())", id=legacy_id, uid=user_id)

    # 3. upgrade -> 009
    alembic_upgrade("009")
    version = q("SELECT version_num FROM alembic_version")
    check("alembic head is 009 after the ledger migration",
          version and version[0][0] == "009", f"{version}")
    cols_after = {r[0] for r in q(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'audit_trail'")}
    check("009 adds seq/previous_hash/event_hash",
          {"seq", "previous_hash", "event_hash"} <= cols_after,
          f"{sorted(cols_after)}")
    legacy = q("SELECT seq, previous_hash, event_hash FROM audit_trail "
               "WHERE id = :id", id=legacy_id)
    check("legacy row survives with a seq and NULL hashes (pre-chain era, "
          "never rewritten)",
          legacy and legacy[0][0] is not None
          and legacy[0][1] is None and legacy[0][2] is None,
          f"{legacy}")

    # 4. chained rows through the repository: genesis + link, recomputed
    # independently here (canonical form per the repository contract).
    async def _write_two():
        from sqlalchemy.ext.asyncio import create_async_engine

        from app.models import AuditAction
        from app.repositories.audit_trail import AuditTrailRepository

        engine = create_async_engine(TEST_DB_URL)
        try:
            from sqlalchemy.ext.asyncio import AsyncSession

            async with AsyncSession(engine) as session:
                repo = AuditTrailRepository(session)
                e1 = await repo.log(
                    action=AuditAction.AUDIT_STARTED, entity_type="audit",
                    user_id=str(user_id), details={"n": 1})
                e2 = await repo.log(
                    action=AuditAction.AUDIT_COMPLETED, entity_type="audit",
                    user_id=str(user_id), details={"n": 2})
                # Flush expires attributes; refresh while still bound,
                # read scalars (no IO while values are present), then
                # commit (which would expire them again).
                await session.refresh(e1)
                await session.refresh(e2)
                out = (
                    (e1.previous_hash, e1.event_hash, e1.seq,
                     e1.created_at),
                    (e2.previous_hash, e2.event_hash, e2.seq,
                     e2.created_at),
                )
                await session.commit()
                return out
        finally:
            await engine.dispose()

    (prev1, hash1, seq1, ts1), (prev2, hash2, seq2, ts2) = asyncio.run(
        _write_two())

    def _canon(action, entity_type, entity_id, user_id, details, created_at):
        payload = {
            "action": action,
            "entity_type": entity_type,
            "entity_id": str(entity_id) if entity_id is not None else "",
            "user_id": str(user_id) if user_id is not None else "",
            "details": details,
            "created_at": created_at.isoformat(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)

    exp1 = hashlib.sha256(
        (_canon("audit_started", "audit", "", str(user_id), {"n": 1},
                ts1) + "").encode("utf-8")).hexdigest()
    check("first post-migration row is genesis (previous_hash == '')",
          prev1 == "", f"{prev1!r}")
    check("genesis event_hash matches the independent recomputation",
          hash1 == exp1, f"{hash1}")
    exp2 = hashlib.sha256(
        (_canon("audit_completed", "audit", "", str(user_id), {"n": 2},
                ts2) + exp1).encode("utf-8")).hexdigest()
    check("second row links to genesis (previous_hash == event_hash #1)",
          prev2 == hash1,
          f"{prev2} vs {hash1}")
    check("second event_hash matches the independent recomputation",
          hash2 == exp2, f"{hash2}")
    check("seq is strictly increasing across legacy + chained rows",
          seq1 is not None and seq2 is not None and seq2 > seq1,
          f"e1.seq={seq1} e2.seq={seq2}")

    # 5. downgrade -> 008 reverses the structure
    alembic_downgrade("008")
    cols_down = {r[0] for r in q(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'audit_trail'")}
    check("downgrade -> 008 drops the three chain columns",
          not ({"seq", "previous_hash", "event_hash"} & cols_down),
          f"{sorted(cols_down)}")

    # 6. round trip back to head
    alembic_upgrade("009")
    rt = q("SELECT version_num FROM alembic_version")
    check("round trip 009 -> 008 -> 009 returns to head",
          rt and rt[0][0] == "009", f"{rt}")

    # restore the metadata-created schema the pytest suites expect
    asyncio.run(dbutil.create_schema())
    check("throwaway schema restored from model metadata for the pytest suites",
          True, "scripts.engine_validation.dbutil.create_schema")

    violations = [c for c in CHECKS if not c["ok"]]
    result = {
        "migration": "009_trail_hash_chain",
        "database": "engine_validation_test (throwaway)",
        "executed": ["wipe", "upgrade 001->008", "insert legacy row",
                     "upgrade 008->009", "genesis + linked rows via "
                     "repository", "downgrade 009->008",
                     "upgrade 008->009", "restore metadata schema"],
        "checks": CHECKS,
        "violations_total": len(violations),
        "verdict": "PASS" if not violations else "FAIL",
    }
    (OUT / "migration_009_results.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    for entry in CHECKS:
        print(f"  [{'PASS' if entry['ok'] else 'FAIL'}] {entry['check']}")
        if not entry["ok"]:
            print(f"         {entry['detail']}")
    print(f"migration 009 verdict: {result['verdict']} "
          f"({result['violations_total']} violations)")
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
