"""Durable execution tests (STEP 7).

EXECUTION STATE: queued/running/completed/failed/cancel_requested/
cancelled + invalid transitions rejected.
QUEUE: enqueue single/bulk creates QUEUED rows; worker consumes via claim.
RETRY: retryable/non-retryable classification, max attempts, backoff,
manual retry rules (completed/cancelled/running rejected).
CANCEL: queued->cancelled, running->requested->cancelled, races, repeat.
RECOVERY: stale RUNNING requeued, terminal when exhausted, cancel-orphans.
IDEMPOTENCY: duplicate delivery single-claim; double HTTP submit = two audits.
SECURITY: foreign execution/audit rejected; archived device fails closed.
DATA INTEGRITY: linkage, baseline snapshot, no duplicate findings.

Async tests use service functions + API endpoints (throwaway DB).
Worker-execution tests are SYNC and drive the task via .apply()
(asyncio.run inside works only without an ambient loop).
"""

from __future__ import annotations

import asyncio
import uuid as uuidlib
from datetime import datetime, timedelta

import pytest
from sqlalchemy import delete, select

from app.models import Audit, AuditExecution
from app.services import execution as exec_svc
from tests.test_device_security import (
    _SecClient,
    _cfg_bytes,
    _make_device,
    _make_user,
)


@pytest.fixture()
async def exec_db():
    """Throwaway-DB session with a fresh engine per test.

    MUST use dbutil (engine_validation_test), never settings.DATABASE_URL:
    a past revision of this fixture pointed at the real database and
    leaked test users/audits into it. See STEP 7.6 cleanup.
    """
    import scripts.engine_validation.dbutil as dbutil

    if not await dbutil.schema_available():
        pytest.skip("throwaway database engine_validation_test not provisioned")

    db_engine, factory = dbutil.make_session_factory()
    session = factory()
    try:
        yield session
    finally:
        try:
            await session.rollback()
        except Exception:
            pass
        await session.close()
        await db_engine.dispose()


async def _mk_audit(session, user_id, name="exec audit", status="pending"):
    audit = Audit(user_id=user_id, name=name, status=status)
    session.add(audit)
    await session.flush()
    return audit


def _run(coro):
    """Drive a coroutine from sync worker tests (no ambient loop)."""
    return asyncio.run(coro)


class TestStateMachine:
    @pytest.mark.asyncio
    async def test_create_starts_queued(self, exec_db):
        user = await _make_user(exec_db, "ex-sm")
        audit = await _mk_audit(exec_db, user.id)
        execution = await exec_svc.create_execution(exec_db, audit.id)
        assert execution.status == "queued"
        assert execution.attempt == 1
        assert execution.progress == 0

    @pytest.mark.asyncio
    async def test_claim_exactly_once(self, exec_db):
        """Two claimants, one winner (duplicate delivery exits safely)."""
        user = await _make_user(exec_db, "ex-claim")
        audit = await _mk_audit(exec_db, user.id)
        execution = await exec_svc.create_execution(exec_db, audit.id)
        exec_id = execution.id
        first = await exec_svc.claim_execution(exec_db, exec_id)
        assert first is not None
        assert first.status == "running"
        assert first.started_at is not None
        assert first.lease_expires_at is not None
        second = await exec_svc.claim_execution(exec_db, exec_id)
        assert second is None
        # Winner still owns it.
        row = await exec_db.execute(
            select(AuditExecution).where(AuditExecution.id == exec_id)
        )
        assert row.scalar_one().status == "running"

    @pytest.mark.asyncio
    async def test_complete_and_fail_terminal(self, exec_db):
        user = await _make_user(exec_db, "ex-term")
        audit = await _mk_audit(exec_db, user.id)
        execution = await exec_svc.create_execution(exec_db, audit.id)
        claimed = await exec_svc.claim_execution(exec_db, execution.id)
        assert claimed is not None
        done = await exec_svc.complete_execution(exec_db, execution.id)
        assert done is not None and done.status == "completed"
        assert done.progress == 100
        # Completing twice is a no-op (row left RUNNING state).
        assert await exec_svc.complete_execution(exec_db, execution.id) is None
        # Failed rows cannot be completed either.
        execution2 = await exec_svc.create_execution(exec_db, audit.id, attempt=2)
        await exec_svc.claim_execution(exec_db, execution2.id)
        failed = await exec_svc.fail_execution(
            exec_db, execution2.id, "EXECUTION_ERROR", "boom", True
        )
        assert failed is not None and failed.status == "failed"
        assert failed.error_category == "EXECUTION_ERROR"
        assert failed.retryable is True
        assert await exec_svc.complete_execution(exec_db, execution2.id) is None

    @pytest.mark.asyncio
    async def test_cancel_flows(self, exec_db):
        user = await _make_user(exec_db, "ex-cancel")
        audit = await _mk_audit(exec_db, user.id)
        queued = await exec_svc.create_execution(exec_db, audit.id)
        # QUEUED cancels immediately.
        cancelled = await exec_svc.request_cancel_execution(exec_db, queued.id)
        assert cancelled is not None and cancelled.status == "cancelled"
        # Repeating is terminal -> None.
        assert await exec_svc.request_cancel_execution(exec_db, queued.id) is None

        running = await exec_svc.create_execution(exec_db, audit.id, attempt=2)
        await exec_svc.claim_execution(exec_db, running.id)
        requested = await exec_svc.request_cancel_execution(exec_db, running.id)
        assert requested is not None and requested.status == "cancel_requested"
        # Heartbeat observes the request and reports stop.
        assert await exec_svc.heartbeat_execution(exec_db, running.id) is False
        confirmed = await exec_svc.confirm_cancelled(exec_db, running.id)
        assert confirmed is not None and confirmed.status == "cancelled"

    def test_classify_failure(self):
        from fastapi import HTTPException

        assert exec_svc.classify_failure(HTTPException(status_code=403))[0] == "AUTHORIZATION_ERROR"
        assert exec_svc.classify_failure(HTTPException(status_code=403))[1] is False
        cat, retryable, _ = exec_svc.classify_failure(ConnectionError("down"))
        assert (cat, retryable) == ("INFRASTRUCTURE_ERROR", True)
        cat, retryable, _ = exec_svc.classify_failure(ValueError("bad input"))
        assert (cat, retryable) == ("VALIDATION_ERROR", False)
        cat, retryable, _ = exec_svc.classify_failure(RuntimeError("weird"))
        assert (cat, retryable) == ("EXECUTION_ERROR", True)
        cat, retryable, msg = exec_svc.classify_failure(RuntimeError("x" * 900))
        assert len(msg) <= 500
        assert "Traceback" not in msg

    def test_backoff_bounded(self):
        assert exec_svc.backoff_seconds(1, 30) == 30
        assert exec_svc.backoff_seconds(2, 30) == 60
        assert exec_svc.backoff_seconds(3, 30) == 90


class TestRecovery:
    @pytest.fixture(autouse=True)
    async def _clean_executions(self, exec_db):
        """Recovery is global by design (it reaps any stale row), so these
        tests start from an empty executions table for determinism."""
        from app.models import AuditExecution as _AE

        await exec_db.execute(delete(_AE))
        await exec_db.flush()
        yield
    @pytest.mark.asyncio
    async def test_stale_running_requeued(self, exec_db):
        user = await _make_user(exec_db, "ex-rec")
        audit = await _mk_audit(exec_db, user.id)
        execution = await exec_svc.create_execution(exec_db, audit.id)
        await exec_svc.claim_execution(exec_db, execution.id)
        # Simulate a dead worker: lease in the past.
        execution.lease_expires_at = datetime.utcnow() - timedelta(minutes=1)
        await exec_db.flush()
        result = await exec_svc.recover_stale_executions(exec_db)
        assert result["stale_found"] == 1
        assert result["recovered"] == 1
        assert len(result["recovered_ids"]) == 1
        assert result["terminal"] == 0
        assert result["cancelled"] == 0
        rows = await exec_db.execute(
            select(AuditExecution)
            .where(AuditExecution.audit_id == audit.id)
            .order_by(AuditExecution.attempt)
        )
        attempts = rows.scalars().all()
        assert [a.status for a in attempts] == ["failed", "queued"]
        assert attempts[0].error_category == "INFRASTRUCTURE_ERROR"
        assert attempts[1].attempt == 2

    @pytest.mark.asyncio
    async def test_stale_running_terminal_when_exhausted(self, exec_db):
        user = await _make_user(exec_db, "ex-recex")
        audit = await _mk_audit(exec_db, user.id)
        execution = await exec_svc.create_execution(
            exec_db, audit.id, attempt=3, max_attempts=3
        )
        await exec_svc.claim_execution(exec_db, execution.id)
        execution.lease_expires_at = datetime.utcnow() - timedelta(minutes=1)
        await exec_db.flush()
        result = await exec_svc.recover_stale_executions(exec_db)
        assert result["terminal"] == 1
        assert result["recovered"] == 0

    @pytest.mark.asyncio
    async def test_fresh_running_untouched(self, exec_db):
        user = await _make_user(exec_db, "ex-fresh")
        audit = await _mk_audit(exec_db, user.id)
        execution = await exec_svc.create_execution(exec_db, audit.id)
        await exec_svc.claim_execution(exec_db, execution.id)
        result = await exec_svc.recover_stale_executions(exec_db)
        assert result["stale_found"] == 0
        assert result["recovered"] == 0
        assert result["terminal"] == 0
        assert result["cancelled"] == 0
        assert result["lost_queued_ids"] == []
        assert result["recovered_ids"] == []

    @pytest.mark.asyncio
    async def test_message_lost_queued_reported_not_published(self, exec_db):
        """A QUEUED row untouched beyond the stale window (broker message
        lost) is REPORTED for republish — but per-task callers must not
        publish it (that amplifies without bound); only worker startup
        republishes, a rare event. Duplicates stay claim-safe either way."""
        user = await _make_user(exec_db, "ex-repub")
        audit = await _mk_audit(exec_db, user.id)
        execution = await exec_svc.create_execution(exec_db, audit.id)
        execution.updated_at = datetime.utcnow() - timedelta(minutes=30)
        await exec_db.flush()
        result = await exec_svc.recover_stale_executions(exec_db)
        assert result["lost_queued_ids"] == [str(execution.id)]
        assert result["recovered_ids"] == []
        # The row itself is untouched (still QUEUED, claimable once).
        row = await exec_db.get(AuditExecution, execution.id)
        assert row.status == "queued"

    @pytest.mark.asyncio
    async def test_fresh_queued_not_republished(self, exec_db):
        user = await _make_user(exec_db, "ex-repub-fresh")
        audit = await _mk_audit(exec_db, user.id)
        await exec_svc.create_execution(exec_db, audit.id)
        result = await exec_svc.recover_stale_executions(exec_db)
        assert result["lost_queued_ids"] == []
        assert result["recovered_ids"] == []

    @pytest.mark.asyncio
    async def test_orphaned_cancel_request_confirmed(self, exec_db):
        user = await _make_user(exec_db, "ex-cor")
        audit = await _mk_audit(exec_db, user.id)
        execution = await exec_svc.create_execution(exec_db, audit.id)
        await exec_svc.claim_execution(exec_db, execution.id)
        await exec_svc.request_cancel_execution(exec_db, execution.id)
        execution.updated_at = datetime.utcnow() - timedelta(minutes=30)
        await exec_db.flush()
        result = await exec_svc.recover_stale_executions(exec_db)
        assert result["cancelled"] == 1


class TestQueueApi:
    async def _seed_config(self, session, tag: str):
        user = await _make_user(session, f"exq-{tag}")
        device = await _make_device(session, user, f"exq-{tag}")
        user_id, device_id = user.id, device.id
        async with _SecClient(session, user) as client:
            up = await client.post(
                "/api/v1/configurations/upload",
                files={"file": (f"{tag}.cfg", _cfg_bytes(f"exq-{tag}"), "text/plain")},
                params={"device_id": str(device_id)},
            )
            assert up.status_code == 201, up.text
        return user, user_id, device_id, up.json()["id"]

    @pytest.mark.asyncio
    async def test_execute_creates_queued_execution(self, exec_db):
        user, _, device_id, cfg_id = await self._seed_config(exec_db, "enq")
        async with _SecClient(exec_db, user) as client:
            resp = await client.post(
                "/api/v1/audit-execution/execute",
                json={
                    "name": "queued audit",
                    "configuration_ids": [cfg_id],
                    "device_ids": [str(device_id)],
                    "framework": "CIS",
                },
            )
        assert resp.status_code == 202, resp.text
        audit_id = resp.json()["id"]
        latest = await exec_svc.latest_execution(exec_db, audit_id)
        assert latest is not None
        assert latest.status == "queued"
        assert latest.attempt == 1
        assert latest.framework == "CIS"

    @pytest.mark.asyncio
    async def test_bulk_creates_batch_and_executions(self, exec_db):
        user, _, device_id, cfg_id = await self._seed_config(exec_db, "batch")
        async with _SecClient(exec_db, user) as client:
            resp = await client.post(
                "/api/v1/audit-execution/bulk",
                json={
                    "items": [
                        {"name": "b0", "configuration_ids": [cfg_id], "device_ids": [str(device_id)]},
                        {"name": "b1", "configuration_ids": [cfg_id], "device_ids": [str(device_id)]},
                    ]
                },
            )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["total"] == 2
        assert body["batch_id"]
        from app.models import AuditBatch

        batch = await exec_db.get(AuditBatch, body["batch_id"])
        assert batch is not None
        assert len(batch.audit_ids) == 2
        # Batch endpoint resolves both items.
        async with _SecClient(exec_db, user) as client:
            got = await client.get(f"/api/v1/audit-execution/batches/{body['batch_id']}")
        assert got.status_code == 200, got.text
        assert got.json()["total"] == 2
        assert got.json()["counts"].get("queued") == 2

    @pytest.mark.asyncio
    async def test_status_carries_execution_block(self, exec_db):
        user, _, device_id, cfg_id = await self._seed_config(exec_db, "stblk")
        async with _SecClient(exec_db, user) as client:
            resp = await client.post(
                "/api/v1/audit-execution/execute",
                json={
                    "name": "status audit",
                    "configuration_ids": [cfg_id],
                    "device_ids": [str(device_id)],
                    "framework": "CIS",
                },
            )
            assert resp.status_code == 202
            status = await client.get(
                f"/api/v1/audit-execution/{resp.json()['id']}/status"
            )
        assert status.status_code == 200
        block = status.json()["execution"]
        assert block is not None
        assert block["status"] == "queued"
        assert block["attempt"] == 1

    @pytest.mark.asyncio
    async def test_retry_rules(self, exec_db):
        from app.models import AuditStatus

        user = await _make_user(exec_db, "ex-retry")
        audit = await _mk_audit(exec_db, user.id, status=AuditStatus.FAILED.value)
        user_id = user.id
        audit_id = audit.id  # capture: session state expires across contexts
        # FAILED + retryable -> new QUEUED execution.
        failed = await exec_svc.create_execution(exec_db, audit.id)
        await exec_svc.claim_execution(exec_db, failed.id)
        await exec_svc.fail_execution(
            exec_db, failed.id, "INFRASTRUCTURE_ERROR", "blip", True
        )
        async with _SecClient(exec_db, user) as client:
            resp = await client.post(f"/api/v1/audit-execution/{audit_id}/retry")
        assert resp.status_code == 202, resp.text
        assert resp.json()["execution"]["attempt"] == 2
        assert resp.json()["execution"]["status"] == "queued"
        # Second retry while QUEUED -> rejected (not FAILED).
        async with _SecClient(exec_db, user) as client:
            resp2 = await client.post(f"/api/v1/audit-execution/{audit_id}/retry")
        assert resp2.status_code == 409
        # Non-retryable failure -> retry rejected.
        audit2 = await _mk_audit(exec_db, user_id, "no-retry")
        audit2_id = audit2.id  # capture: session state expires across contexts
        bad = await exec_svc.create_execution(exec_db, audit2.id)
        await exec_svc.claim_execution(exec_db, bad.id)
        await exec_svc.fail_execution(
            exec_db, bad.id, "CONFIGURATION_ERROR", "bad input", False
        )
        async with _SecClient(exec_db, user) as client:
            resp3 = await client.post(f"/api/v1/audit-execution/{audit2_id}/retry")
        assert resp3.status_code == 409
        # Foreign audit -> 404.
        other = await _make_user(exec_db, "ex-retry-other")
        async with _SecClient(exec_db, other) as client:
            resp4 = await client.post(f"/api/v1/audit-execution/{audit_id}/retry")
        assert resp4.status_code == 404

    @pytest.mark.asyncio
    async def test_completed_retry_rejected(self, exec_db):
        from app.models import AuditStatus

        user = await _make_user(exec_db, "ex-retry-done")
        audit = await _mk_audit(exec_db, user.id, status=AuditStatus.COMPLETED.value)
        done = await exec_svc.create_execution(exec_db, audit.id)
        await exec_svc.claim_execution(exec_db, done.id)
        await exec_svc.complete_execution(exec_db, done.id)
        async with _SecClient(exec_db, user) as client:
            resp = await client.post(f"/api/v1/audit-execution/{audit.id}/retry")
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_cancel_queued_and_running(self, exec_db):
        from app.models import AuditStatus

        user = await _make_user(exec_db, "ex-cancel")
        audit = await _mk_audit(exec_db, user.id, status=AuditStatus.PENDING.value)
        queued = await exec_svc.create_execution(exec_db, audit.id)
        async with _SecClient(exec_db, user) as client:
            resp = await client.post(f"/api/v1/audits/{audit.id}/cancel")
        assert resp.status_code == 200, resp.text
        row = await exec_db.get(AuditExecution, queued.id)
        assert row.status == "cancelled"

        audit2 = await _mk_audit(exec_db, user.id, status=AuditStatus.PROCESSING.value)
        running = await exec_svc.create_execution(exec_db, audit2.id)
        await exec_svc.claim_execution(exec_db, running.id)
        async with _SecClient(exec_db, user) as client:
            resp2 = await client.post(f"/api/v1/audits/{audit2.id}/cancel")
        assert resp2.status_code == 200, resp2.text
        # RUNNING audits stay PROCESSING until the worker observes the request.
        row2 = await exec_db.get(AuditExecution, running.id)
        assert row2.status == "cancel_requested"
        refreshed = await exec_db.get(Audit, audit2.id)
        assert refreshed.status == AuditStatus.PROCESSING.value

    @pytest.mark.asyncio
    async def test_cancel_terminal_rejected(self, exec_db):
        from app.models import AuditStatus

        user = await _make_user(exec_db, "ex-cancel-term")
        audit = await _mk_audit(exec_db, user.id, status=AuditStatus.COMPLETED.value)
        done = await exec_svc.create_execution(exec_db, audit.id)
        await exec_svc.claim_execution(exec_db, done.id)
        await exec_svc.complete_execution(exec_db, done.id)
        async with _SecClient(exec_db, user) as client:
            resp = await client.post(f"/api/v1/audits/{audit.id}/cancel")
        assert resp.status_code == 400


class TestWorkerExecution:
    """Sync tests driving the real worker task (no ambient event loop).

    The worker resolves app.database.AsyncSessionLocal at call time, so
    these tests rebind it to the throwaway DB — identical semantics,
    hermetic rows. Production binding is untouched.
    """

    @pytest.fixture()
    def _patched_worker_db(self, monkeypatch):
        import scripts.engine_validation.dbutil as dbutil
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from sqlalchemy.pool import NullPool

        # NullPool: each .apply() runs under its own fresh event loop, so
        # pooled connections must never cross loops.
        engine = create_async_engine(
            dbutil.TEST_DB_URL, poolclass=NullPool, pool_pre_ping=True
        )
        factory = async_sessionmaker(engine, expire_on_commit=False)
        monkeypatch.setattr("app.database.WorkerSessionLocal", factory)
        yield factory
        _run(engine.dispose())

    def _setup(self):
        return _run(_prepare_worker_audit())

    def _read(self, audit_id, execution_id):
        import scripts.engine_validation.dbutil as dbutil

        from sqlalchemy import func as _func
        from sqlalchemy import select as _select

        async def _fetch():
            db_engine, factory = dbutil.make_session_factory()
            session = factory()
            try:
                from uuid import UUID

                from app.models import Audit, AuditExecution, ComplianceResult, Finding

                audit = await session.get(Audit, UUID(audit_id))
                execution = await session.get(AuditExecution, UUID(execution_id))
                n_results = (
                    await session.execute(
                        _select(_func.count(ComplianceResult.id)).where(
                            ComplianceResult.audit_id == UUID(audit_id)
                        )
                    )
                ).scalar()
                n_findings = (
                    await session.execute(
                        _select(_func.count(Finding.id)).where(
                            Finding.audit_id == UUID(audit_id)
                        )
                    )
                ).scalar()
                return {
                    "audit_status": audit.status if audit else None,
                    "execution_status": execution.status if execution else None,
                    "baseline_controls": (
                        list(audit.baseline_controls) if audit and audit.baseline_controls else None
                    ),
                    "results": n_results,
                    "findings": n_findings,
                }
            finally:
                await session.close()
                await db_engine.dispose()

        return _run(_fetch())

    def test_worker_completes_audit_end_to_end(self, _patched_worker_db):
        from app.tasks import execute_audit_task

        ids = self._setup()
        outcome = execute_audit_task.apply(args=[ids["execution_id"]]).get()
        assert outcome["status"] == "completed"
        state = self._read(ids["audit_id"], ids["execution_id"])
        assert state["execution_status"] == "completed"
        assert state["audit_status"] == "completed"
        assert state["results"] > 0
        assert state["findings"] >= 0

    def test_duplicate_delivery_executes_once(self, _patched_worker_db):
        from app.tasks import execute_audit_task

        ids = self._setup()
        first = execute_audit_task.apply(args=[ids["execution_id"]]).get()
        assert first["status"] == "completed"
        second = execute_audit_task.apply(args=[ids["execution_id"]]).get()
        assert second["status"] == "skipped"
        state = self._read(ids["audit_id"], ids["execution_id"])
        assert state["execution_status"] == "completed"

    def test_worker_rejects_archived_device(self, _patched_worker_db):
        from app.tasks import execute_audit_task

        async def _archive():
            import scripts.engine_validation.dbutil as dbutil

            from sqlalchemy import select as _select

            db_engine, factory = dbutil.make_session_factory()
            session = factory()
            try:
                from uuid import UUID

                from app.models import Audit, Device

                ids = await _prepare_worker_audit()
                audits = await session.execute(
                    _select(Audit).where(Audit.id == UUID(ids["audit_id"]))
                )
                audit = audits.scalar_one()
                devices = await session.execute(
                    _select(Device).where(Device.user_id == audit.user_id)
                )
                device = devices.scalars().first()
                device.is_active = False
                await session.commit()
                return ids
            finally:
                await session.close()
                await db_engine.dispose()

        ids = _run(_archive())
        outcome = execute_audit_task.apply(args=[ids["execution_id"]]).get()
        assert outcome["status"] == "failed"
        assert outcome["category"] == "CONFIGURATION_ERROR"
        state = self._read(ids["audit_id"], ids["execution_id"])
        assert state["execution_status"] == "failed"
        assert state["results"] == 0


async def _prepare_worker_audit() -> dict:
    """Seed one owner + device + config + audit + QUEUED execution."""
    import scripts.engine_validation.dbutil as dbutil

    db_engine, factory = dbutil.make_session_factory()
    session = factory()
    from app.models import Audit, AuditConfiguration, Configuration, Device, User

    tag = f"wkr-{uuidlib.uuid4().hex[:8]}"
    user = User(
        id=uuidlib.uuid4(), email=f"{tag}@test.local",
        password_hash="x", role="auditor", is_active=True,
    )
    session.add(user)
    await session.flush()
    device = Device(user_id=user.id, name=f"{tag}-dev", vendor="cisco", platform="ios_xe")
    session.add(device)
    await session.flush()
    cfg = Configuration(
        device_id=device.id, filename=f"{tag}.cfg",
        content_hash=f"wkr-{tag}",
        raw_content="hostname WKR\n!\ninterface Gi0/0\n ip address 10.9.0.1 255.255.255.0\n",
        content_type="text/plain", size_bytes=60, line_count=4,
    )
    session.add(cfg)
    await session.flush()
    audit = Audit(user_id=user.id, name=f"{tag} audit", status="pending")
    session.add(audit)
    await session.flush()
    session.add(AuditConfiguration(audit_id=audit.id, configuration_id=cfg.id))
    await session.flush()
    from app.services import execution as exec_svc

    execution = await exec_svc.create_execution(session, audit.id)
    await session.commit()
    ids = {
        "user_id": str(user.id), "audit_id": str(audit.id),
        "config_id": str(cfg.id), "execution_id": str(execution.id),
    }
    await session.close()
    await db_engine.dispose()
    return ids


class TestCompletionRace:
    """Cancel-vs-complete atomicity: exactly one outcome wins, decided by
    the end-CAS. A cancel that lands first must surface as CANCELLED even
    when the pipeline finished its work."""

    @pytest.mark.asyncio
    async def test_cancel_wins_over_late_completion(self, exec_db):
        from app.api.v1 import audit_execution as api_exec
        from app.api.v1.audit_execution import _settle_decided_execution
        from app.models import AuditStatus

        user = await _make_user(exec_db, "ex-race")
        audit = await _mk_audit(exec_db, user.id, status=AuditStatus.PROCESSING.value)
        execution = await exec_svc.create_execution(exec_db, audit.id)
        await exec_svc.claim_execution(exec_db, execution.id)
        # Worker binds audit -> execution before running the pipeline.
        api_exec.audit_live_execution[str(audit.id)] = str(execution.id)
        try:
            # Cancel lands while the pipeline still works.
            await exec_svc.request_cancel_execution(exec_db, execution.id)
            # Pipeline finishes and tries to close: CAS loses (not RUNNING).
            assert await exec_svc.complete_execution(exec_db, execution.id) is None
            # Settle honors the decided outcome: CANCELLED, never COMPLETED.
            await _settle_decided_execution(
                exec_db, audit, str(audit.id), str(user.id)
            )
            row = await exec_db.get(AuditExecution, execution.id)
            assert row.status == "cancelled"
            refreshed = await exec_db.get(Audit, audit.id)
            assert refreshed.status == AuditStatus.CANCELLED.value
        finally:
            api_exec.audit_live_execution.pop(str(audit.id), None)

    @pytest.mark.asyncio
    async def test_completion_wins_without_cancel(self, exec_db):
        from app.models import AuditStatus

        user = await _make_user(exec_db, "ex-race-ok")
        audit = await _mk_audit(exec_db, user.id, status=AuditStatus.PROCESSING.value)
        execution = await exec_svc.create_execution(exec_db, audit.id)
        await exec_svc.claim_execution(exec_db, execution.id)
        # No cancel: the end-CAS succeeds normally.
        done = await exec_svc.complete_execution(exec_db, execution.id)
        assert done is not None and done.status == "completed"
