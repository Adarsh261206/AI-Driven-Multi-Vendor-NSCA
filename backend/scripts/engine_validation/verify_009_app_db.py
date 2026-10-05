"""Read-only check: the exact endpoint query runs on the app DB."""

import asyncio
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND))


async def main() -> int:
    from sqlalchemy import desc, func, select

    from app.database import engine as app_engine
    from app.models import AuditTrail

    async with app_engine.connect() as conn:
        total = (await conn.execute(
            select(func.count(AuditTrail.id)))).scalar()
        rows = (await conn.execute(
            select(AuditTrail.id, AuditTrail.seq,
                   AuditTrail.previous_hash, AuditTrail.event_hash)
            .order_by(desc(AuditTrail.seq)).limit(5))).all()
    print(f"audit_trail rows: {total}")
    for r in rows:
        seq = r[1]
        prev = (r[2][:8] + "...") if r[2] else r[2]
        h = (r[3][:8] + "...") if r[3] else r[3]
        print(f"  seq={seq} prev={prev} hash={h}")
    chained = sum(1 for r in rows if r[3])
    print(f"chained rows in latest 5: {chained} "
          f"(0 with NULLs = healthy pre-chain era)")
    print("ENDPOINT QUERY OK (no UndefinedColumnError)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
