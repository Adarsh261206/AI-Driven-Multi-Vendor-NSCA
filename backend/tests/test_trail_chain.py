"""Hash-chained audit ledger acceptance tests (migration 009).

Proves the ledger contract on the throwaway database:
- every new row carries a seq, previous_hash and event_hash;
- each row links to its predecessor (no fork: no two rows share a
  previous_hash);
- ~20 parallel writers still form one continuous chain (this is the
  test that specifically validates the pg_advisory_xact_lock design);
- event hashes recompute from the canonical form (deterministic).

Global genesis (previous_hash == "") is proven by
scripts/engine_validation/validate_migration_009.py on a wiped
database; the shared throwaway DB already holds chained rows, so these
tests assert continuity from the live head instead.

Cleanup: every row created here is deleted (tracked ids).
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

import scripts.engine_validation.dbutil as dbutil
from app.models import AuditAction, AuditTrail
from app.repositories.audit_trail import (
    AuditTrailRepository,
    canonical_event,
    chain_hash,
)


@pytest.fixture()
async def chain_db():
    if not await dbutil.schema_available():
        pytest.skip("throwaway database engine_validation_test not provisioned")

    from sqlalchemy import delete

    engine, factory = dbutil.make_session_factory()
    tracked: list = []
    try:
        yield factory, tracked
    finally:
        try:
            cleanup = factory()
            try:
                if tracked:
                    await cleanup.execute(
                        delete(AuditTrail).where(
                            AuditTrail.id.in_(tracked)))
                    await cleanup.commit()
            finally:
                await cleanup.close()
        finally:
            await engine.dispose()


async def _write(session_factory, tracked, action, marker, seq_no):
    async with session_factory() as session:
        repo = AuditTrailRepository(session)
        entry = await repo.log(
            action=action, entity_type="audit",
            entity_id=uuid.uuid4(), user_id=None,
            details={"chain_test": marker, "n": seq_no})
        await session.refresh(entry)
        out = (entry.id, entry.seq, entry.previous_hash, entry.event_hash,
               entry.created_at, entry.action, entry.entity_type,
               entry.entity_id, entry.user_id, entry.details)
        await session.commit()
        tracked.append(entry.id)
        return out


def _recompute(action, entity_type, entity_id, user_id, details,
               created_at, previous_hash):
    canonical = canonical_event(action, entity_type, entity_id, user_id,
                                details, created_at)
    return chain_hash(canonical, previous_hash)


async def test_chain_links_and_recompute(chain_db):
    factory, tracked = chain_db

    marker = f"link-{uuid.uuid4().hex[:8]}"
    rows = [await _write(factory, tracked, AuditAction.AUDIT_STARTED,
                         marker, i) for i in range(3)]
    seqs = [r[1] for r in rows]
    assert seqs == sorted(seqs) and len(set(seqs)) == 3
    for r in rows:
        assert isinstance(r[3], str) and len(r[3]) == 64
        assert isinstance(r[2], str) and len(r[2]) in (0, 64)
    # sequential linkage inside our segment
    assert rows[1][2] == rows[0][3]
    assert rows[2][2] == rows[1][3]
    # independent recomputation of every link
    for r in rows:
        assert r[3] == _recompute(r[5], r[6], r[7], r[8], r[9], r[4], r[2])


async def test_concurrent_writers_form_one_chain(chain_db):
    factory, tracked = chain_db
    from sqlalchemy import desc, select

    marker = f"conc-{uuid.uuid4().hex[:8]}"

    async with factory() as probe:
        head_rows = (await probe.execute(
            select(AuditTrail.event_hash)
            .order_by(desc(AuditTrail.seq)).limit(1))).scalars().all()
    head = head_rows[0] if head_rows and head_rows[0] else ""

    results = await asyncio.gather(*[
        _write(factory, tracked, AuditAction.AUDIT_STARTED, marker, i)
        for i in range(20)
    ])
    by_seq = sorted(results, key=lambda r: r[1])
    seqs = [r[1] for r in by_seq]
    prevs = [r[2] for r in by_seq]
    hashes = [r[3] for r in by_seq]

    # no duplicate positions, no duplicate links, no duplicate hashes:
    # two writers never read the same head (no fork).
    assert len(set(seqs)) == 20
    assert len(set(prevs)) == 20
    assert len(set(hashes)) == 20
    # one continuous segment: the first links the pre-existing head,
    # every other links exactly one segment peer, each exactly once.
    assert prevs[0] == head
    assert set(prevs[1:]) == set(hashes[:-1])
    # every link recomputes from the canonical form.
    for r in by_seq:
        assert r[3] == _recompute(r[5], r[6], r[7], r[8], r[9], r[4], r[2])
