"""Celery worker tasks for durable audit execution (STEP 7).

The worker is an ORCHESTRATION layer only: it claims executions, re-checks
authoritative state, invokes the existing run_audit_pipeline, and records
outcomes. No parsing, evaluation, scoring, or reporting logic lives here.

Stale payload protection (PART 22): before running, the worker re-reads
the audit, its configurations, and device lifecycle from the database —
a device archived (or config deleted) between enqueue and execution fails
closed as CONFIGURATION_ERROR instead of executing stale scope.
"""

from __future__ import annotations

import asyncio
from uuid import UUID

from app.celery_app import celery_app


def _run(coro):
    """Run a coroutine from sync worker context (no ambient loop here)."""
    return asyncio.run(coro)


@celery_app.task(
    bind=True,
    name="audit.execute",
    acks_late=True,
    max_retries=0,  # retries are explicit new executions, not celery redelivery loops
)
def execute_audit_task(self, execution_id: str) -> dict:
    """Execute one queued audit execution. Idempotent via atomic claim."""
    return _run(_execute_async(str(execution_id), self.request.id))


async def _execute_async(execution_id: str, celery_task_id=None) -> dict:
    from sqlalchemy import select

    from app.database import WorkerSessionLocal as AsyncSessionLocal
    from app.models import Audit, AuditConfiguration, Configuration
    from app.models import Device, User
    from app.services import execution as exec_svc

    async with AsyncSessionLocal() as db:
        # Piggyback recovery: every task execution reaps worker-lost
        # rows (no scheduler/beat required) and publishes ONLY the
        # replacements it reaped itself (bounded: one publish per reaped
        # row). Pre-existing message-lost QUEUED rows are reported but NOT
        # republished here — republishing the whole stale set per task
        # amplifies the queue without bound. Worker startup handles those.
        try:
            recovery = await exec_svc.recover_stale_executions(db)
            await db.commit()
            for replacement_id in recovery.get("recovered_ids", []):
                execute_audit_task.apply_async(args=[replacement_id])
        except Exception:
            await db.rollback()

        # Atomic claim — duplicate delivery exits here.
        execution = await exec_svc.claim_execution(db, UUID(execution_id))
        if execution is None:
            await db.rollback()
            return {"status": "skipped", "reason": "already claimed or not queued"}
        if celery_task_id:
            execution.celery_task_id = str(celery_task_id)
        await db.commit()

        # Re-validate authoritative state (PART 22): the world may have
        # changed between enqueue and execution.
        audit_row = await db.execute(select(Audit).where(Audit.id == execution.audit_id))
        audit = audit_row.scalar_one_or_none()
        if audit is None:
            await _fail_terminal(
                db, execution, "CONFIGURATION_ERROR", "Audit row missing at execution time"
            )
            return {"status": "failed", "category": "CONFIGURATION_ERROR"}

        ac_rows = await db.execute(
            select(AuditConfiguration).where(
                AuditConfiguration.audit_id == execution.audit_id
            )
        )
        associations = ac_rows.scalars().all()
        if not associations:
            await _fail_terminal(
                db, execution, "CONFIGURATION_ERROR", "Audit has no configurations"
            )
            return {"status": "failed", "category": "CONFIGURATION_ERROR"}

        config_ids = [str(ac.configuration_id) for ac in associations]
        cfg_rows = await db.execute(
            select(Configuration).where(
                Configuration.id.in_([ac.configuration_id for ac in associations])
            )
        )
        configs = {c.id: c for c in cfg_rows.scalars().all()}
        missing = [cid for cid in config_ids if UUID(cid) not in configs]
        if missing:
            await _fail_terminal(
                db,
                execution,
                "CONFIGURATION_ERROR",
                f"{len(missing)} configuration(s) deleted after queueing",
            )
            return {"status": "failed", "category": "CONFIGURATION_ERROR"}

        device_ids = {c.device_id for c in configs.values() if c.device_id is not None}
        if device_ids:
            dev_rows = await db.execute(
                select(Device).where(Device.id.in_(list(device_ids)))
            )
            for device in dev_rows.scalars().all():
                if not device.is_active:
                    await _fail_terminal(
                        db,
                        execution,
                        "CONFIGURATION_ERROR",
                        f"Device archived after queueing: {device.name}",
                    )
                    return {"status": "failed", "category": "CONFIGURATION_ERROR"}

        # Ownership still holds (user may have been deactivated).
        user_row = await db.execute(select(User).where(User.id == audit.user_id))
        user = user_row.scalar_one_or_none()
        if user is None or not user.is_active:
            await _fail_terminal(
                db, execution, "AUTHORIZATION_ERROR", "Owning user inactive or missing"
            )
            return {"status": "failed", "category": "AUTHORIZATION_ERROR"}

        # Bind execution for pipeline checkpoints + progress persistence.
        from app.api.v1 import audit_execution as api_exec

        api_exec.audit_live_execution[str(execution.audit_id)] = str(execution.id)

        from app.api.v1.audit_execution import run_audit_pipeline

        try:
            await run_audit_pipeline(
                audit_id=str(execution.audit_id),
                config_ids=config_ids,
                framework=execution.framework or "CIS",
                user_id=str(audit.user_id),
                execution_id=str(execution.id),
            )
        except exec_svc.ExecutionCancelled:
            await _mark_cancelled(db, execution, audit)
            return {"status": "cancelled"}
        except Exception as exc:  # noqa: BLE001 — classified below, never leaks
            category, retryable, message = exec_svc.classify_failure(exc)
            await _fail_attempt(db, execution, audit, category, message, retryable)
            return {"status": "failed", "category": category}
        finally:
            api_exec.audit_live_execution.pop(str(execution.audit_id), None)

        await exec_svc.complete_execution(db, execution.id)
        await db.commit()
        return {"status": "completed"}


async def _fail_terminal(db, execution, category: str, message: str) -> None:
    from app.services import execution as exec_svc

    execution.status = exec_svc.ExecutionStatus.FAILED
    execution.error_category = category
    execution.error_message = message[:500]
    execution.retryable = False
    from datetime import datetime

    execution.completed_at = datetime.utcnow()
    execution.updated_at = datetime.utcnow()
    await db.flush()

    from sqlalchemy import select

    from app.models import Audit, AuditStatus

    audit_row = await db.execute(select(Audit).where(Audit.id == execution.audit_id))
    audit = audit_row.scalar_one_or_none()
    if audit is not None:
        audit.status = AuditStatus.FAILED.value
        from datetime import datetime as _dt

        audit.completed_at = _dt.utcnow()
        await db.flush()
    await db.commit()


async def _mark_cancelled(db, execution, audit) -> None:
    # The AUDIT_CANCELLED trail event was already logged at request time
    # (single record); here only rows transition.
    from datetime import datetime

    from app.services import execution as exec_svc

    await exec_svc.confirm_cancelled(db, execution.id)
    from app.models import AuditStatus

    audit.status = AuditStatus.CANCELLED.value
    audit.completed_at = datetime.utcnow()
    await db.flush()
    await db.commit()


async def _fail_attempt(db, execution, audit, category, message, retryable) -> None:
    # Safety net only: the pipeline records outcomes itself when bound.
    # The fail-CAS decides: a loss means cancel/recovery won first, so
    # settle instead of overwriting the decided outcome.
    from app.services import execution as exec_svc

    from app.config import settings as _settings

    failed_row = await exec_svc.fail_execution(
        db, execution.id, category, message, retryable
    )
    if failed_row is None:

        from sqlalchemy import select as _select

        from app.api.v1.audit_execution import _settle_decided_execution
        from app.models import Audit as _Audit

        await db.rollback()
        audit_row = await db.execute(
            _select(_Audit).where(_Audit.id == execution.audit_id)
        )
        live_audit = audit_row.scalar_one_or_none()
        await _settle_decided_execution(
            db,
            live_audit,
            str(execution.audit_id),
            str(audit.user_id) if audit is not None else "",
        )
        return
    # Mirror terminal audit state (retry creates a NEW execution; the audit
    # row reflects the latest attempt only after it runs).
    if not retryable or execution.attempt >= execution.max_attempts:
        from app.models import AuditStatus

        audit.status = AuditStatus.FAILED.value
        from datetime import datetime

        audit.completed_at = datetime.utcnow()
        await db.flush()
    else:
        # Bounded auto-retry: fresh execution row (attempt+1) with countdown.
        new_execution = await exec_svc.create_execution(
            db,
            execution.audit_id,
            attempt=execution.attempt + 1,
            max_attempts=execution.max_attempts,
        )
        await db.flush()
        countdown = exec_svc.backoff_seconds(
            new_execution.attempt, _settings.EXECUTION_RETRY_BACKOFF_SECONDS
        )
        execute_audit_task.apply_async(args=[str(new_execution.id)], countdown=countdown)
    await db.commit()
