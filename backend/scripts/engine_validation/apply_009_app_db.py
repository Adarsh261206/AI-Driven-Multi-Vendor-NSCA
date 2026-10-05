"""One-off: apply migration 009's DDL to the APPLICATION database.

Why this exists: the app DB (compliance_auditor) is stamped at alembic
revision 014, but this checkout only contains migrations 001-009, so
`alembic upgrade head` cannot run there ("Can't locate revision 014").
The 014 stamp belongs to other work and is left untouched. This script
executes exactly what 009_trail_hash_chain.py::upgrade() does, as plain
idempotent SQL: sequence + seq column (+ backfill via DEFAULT) + unique
constraint + two nullable hash columns.

Additive only: no rows modified, no history rewritten. Legacy rows keep
NULL hashes (pre-chain era). Safe to re-run.
"""

import asyncio
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))

STATEMENTS = [
    "CREATE SEQUENCE IF NOT EXISTS audit_trail_seq_seq AS BIGINT",
    "ALTER TABLE audit_trail ADD COLUMN IF NOT EXISTS seq BIGINT "
    "NOT NULL DEFAULT nextval('audit_trail_seq_seq')",
    # Unique constraint has no IF NOT EXISTS: guard in Python below.
    "ALTER TABLE audit_trail ADD COLUMN IF NOT EXISTS "
    "previous_hash VARCHAR(64)",
    "ALTER TABLE audit_trail ADD COLUMN IF NOT EXISTS "
    "event_hash VARCHAR(64)",
]


async def main() -> int:
    from sqlalchemy import text

    from app.database import engine as app_engine

    async with app_engine.connect() as conn:
        for stmt in STATEMENTS:
            await conn.execute(text(stmt))
        has_uq = (await conn.execute(text(
            "SELECT 1 FROM pg_constraint WHERE conname = "
            "'uq_audit_trail_seq'"))).scalar() is not None
        if not has_uq:
            await conn.execute(text(
                "ALTER TABLE audit_trail ADD CONSTRAINT uq_audit_trail_seq "
                "UNIQUE (seq)"))
            print("added uq_audit_trail_seq")
        else:
            print("uq_audit_trail_seq already present")
        cols = (await conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'audit_trail' "
            "ORDER BY ordinal_position"))).scalars().all()
        print("audit_trail cols:", cols)
        assert {"seq", "previous_hash", "event_hash"} <= set(cols), cols
        await conn.commit()
    print("009 DDL applied to application database")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
