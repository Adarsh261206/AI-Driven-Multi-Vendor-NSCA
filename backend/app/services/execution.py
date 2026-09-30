"""Durable audit execution state machine (STEP 7).

Execution state is OPERATIONAL and lives on audit_executions rows, separate
from the compliance result on audits. One row per attempt — retries create
new rows so failure history is never overwritten.

Valid transitions (enforced by WHERE clauses, never trusted):
    QUEUED -> RUNNING        (atomic worker claim)
    QUEUED -> CANCELLED      (cancel before claim)
    RUNNING -> COMPLETED | FAILED | CANCEL_REQUESTED
    CANCEL_REQUESTED -> CANCELLED
    FAILED -> (new row) QUEUED   (retry, attempt+1; never mutates the row)

Everything else is rejected. In particular COMPLETED/CANCELLED rows are
terminal and a second claim on the same row always fails (duplicate
delivery exits safely).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditExecution


class ExecutionStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"


class ErrorCategory:
    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    PARSER_ERROR = "PARSER_ERROR"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


# Default worker lease: a RUNNING execution must heartbeat within this
# window or recovery treats its worker as lost.
LEASE_MINUTES_DEFAULT = 15


# Categories that may be retried (bounded by max_attempts). Everything
# else is terminal on first failure.
RETRYABLE_CATEGORIES = frozenset(
    {
        ErrorCategory.EXECUTION_ERROR,
        ErrorCategory.INFRASTRUCTURE_ERROR,
        ErrorCategory.UNKNOWN,
    }
)


class ExecutionCancelled(Exception):
    """Raised at worker checkpoints when cancellation was requested."""


class ExecutionSuperseded(Exception):
    """Raised when the execution row left RUNNING for a non-cancel reason
    (e.g. lease reaped by recovery). The worker stops quietly: recovery
    already owns the outcome, so no rows are touched."""



def _utcnow() -> datetime:
    return datetime.utcnow()


async def create_execution(
    db: AsyncSession,
    audit_id: UUID,
    attempt: int = 1,
    max_attempts: int = 3,
    framework: str = "CIS",
    framework_version: Optional[str] = None,
) -> AuditExecution:
    """Persist a QUEUED execution row for an audit (attempt N)."""
    execution = AuditExecution(
        audit_id=audit_id,
        attempt=attempt,
        status=ExecutionStatus.QUEUED,
        max_attempts=max_attempts,
        framework=framework or "CIS",
        framework_version=framework_version,
    )
    db.add(execution)
    await db.flush()
    await db.refresh(execution)
    return execution


async def latest_execution(
    db: AsyncSession, audit_id: UUID
) -> Optional[AuditExecution]:
    """Newest execution row for an audit (highest attempt)."""
    result = await db.execute(
        select(AuditExecution)
        .where(AuditExecution.audit_id == audit_id)
        .order_by(AuditExecution.attempt.desc(), AuditExecution.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def claim_execution(
    db: AsyncSession,
    execution_id: UUID,
    lease_minutes: int = 15,
) -> Optional[AuditExecution]:
    """Atomically claim a QUEUED execution for a worker.

    Returns the claimed row, or None when another worker won (or the row
    left QUEUED state). Exactly one claimant succeeds — duplicate queue
    delivery exits safely here.
    """
    now = _utcnow()
    result = await db.execute(
        update(AuditExecution)
        .where(
            AuditExecution.id == execution_id,
            AuditExecution.status == ExecutionStatus.QUEUED,
        )
        .values(
            status=ExecutionStatus.RUNNING,
            started_at=now,
            updated_at=now,
            lease_expires_at=now + timedelta(minutes=lease_minutes),
        )
    )
    await db.flush()
    if (result.rowcount or 0) != 1:
        # Lost race (or row left QUEUED): nothing was modified by the
        # zero-row UPDATE, so return without touching the caller's
        # transaction — never roll back here.
        return None
    row = await db.execute(
        select(AuditExecution).where(AuditExecution.id == execution_id)
    )
    return row.scalar_one()


async def heartbeat_execution(
    db: AsyncSession,
    execution_id: UUID,
    lease_minutes: int = 15,
    progress: Optional[int] = None,
    current_step: Optional[str] = None,
) -> bool:
    """Extend the worker lease; returns False when the worker must stop.

    Returns False when the row is gone, completed/failed by someone else,
    or cancellation was requested (CANCEL_REQUESTED) — the worker treats
    all three as "stop now". True otherwise (lease extended).
    """
    row = await db.execute(
        select(AuditExecution).where(AuditExecution.id == execution_id)
    )
    execution = row.scalar_one_or_none()
    if execution is None or execution.status != ExecutionStatus.RUNNING:
        return False
    execution.lease_expires_at = _utcnow() + timedelta(minutes=lease_minutes)
    if progress is not None:
        execution.progress = max(0, min(100, int(progress)))
    if current_step is not None:
        execution.current_step = current_step[:100]
    execution.updated_at = _utcnow()
    await db.flush()
    return True


async def complete_execution(
    db: AsyncSession, execution_id: UUID
) -> Optional[AuditExecution]:
    """Mark a RUNNING execution COMPLETED (progress 100)."""
    now = _utcnow()
    result = await db.execute(
        update(AuditExecution)
        .where(
            AuditExecution.id == execution_id,
            AuditExecution.status == ExecutionStatus.RUNNING,
        )
        .values(
            status=ExecutionStatus.COMPLETED,
            progress=100,
            completed_at=now,
            updated_at=now,
        )
    )
    await db.flush()
    if (result.rowcount or 0) != 1:
        return None
    row = await db.execute(
        select(AuditExecution).where(AuditExecution.id == execution_id)
    )
    return row.scalar_one()


async def fail_execution(
    db: AsyncSession,
    execution_id: UUID,
    category: str,
    message: str,
    retryable: bool,
) -> Optional[AuditExecution]:
    """Mark a RUNNING execution FAILED with a classified, safe reason."""
    now = _utcnow()
    result = await db.execute(
        update(AuditExecution)
        .where(
            AuditExecution.id == execution_id,
            AuditExecution.status == ExecutionStatus.RUNNING,
        )
        .values(
            status=ExecutionStatus.FAILED,
            error_category=category,
            error_message=(message or "")[:500],
            retryable=retryable,
            completed_at=now,
            updated_at=now,
        )
    )
    await db.flush()
    if (result.rowcount or 0) != 1:
        return None
    row = await db.execute(
        select(AuditExecution).where(AuditExecution.id == execution_id)
    )
    return row.scalar_one()


async def request_cancel_execution(
    db: AsyncSession, execution_id: UUID
) -> Optional[AuditExecution]:
    """QUEUED -> CANCELLED, or RUNNING -> CANCEL_REQUESTED (cooperative).

    Returns None for terminal rows (COMPLETED/FAILED/CANCELLED) and for
    CANCEL_REQUESTED (already requested — idempotent second call).
    """
    row = await db.execute(
        select(AuditExecution).where(AuditExecution.id == execution_id)
    )
    execution = row.scalar_one_or_none()
    if execution is None:
        return None
    now = _utcnow()
    if execution.status == ExecutionStatus.QUEUED:
        execution.status = ExecutionStatus.CANCELLED
        execution.completed_at = now
        execution.updated_at = now
        await db.flush()
        return execution
    if execution.status == ExecutionStatus.RUNNING:
        execution.status = ExecutionStatus.CANCEL_REQUESTED
        execution.updated_at = now
        await db.flush()
        return execution
    return None


async def confirm_cancelled(
    db: AsyncSession, execution_id: UUID
) -> Optional[AuditExecution]:
    """Worker-observed cancellation: CANCEL_REQUESTED -> CANCELLED."""
    now = _utcnow()
    result = await db.execute(
        update(AuditExecution)
        .where(
            AuditExecution.id == execution_id,
            AuditExecution.status == ExecutionStatus.CANCEL_REQUESTED,
        )
        .values(status=ExecutionStatus.CANCELLED, completed_at=now, updated_at=now)
    )
    await db.flush()
    if (result.rowcount or 0) != 1:
        return None
    row = await db.execute(
        select(AuditExecution).where(AuditExecution.id == execution_id)
    )
    return row.scalar_one()


def classify_failure(exc: BaseException) -> tuple[str, bool, str]:
    """Map an exception to (category, retryable, safe_message).

    Never exposes tracebacks, config contents, or secrets — only the
    exception class name plus a short sanitized message.
    """
    from fastapi import HTTPException

    safe = f"{type(exc).__name__}: {str(exc)[:200]}"
    if isinstance(exc, ExecutionCancelled):
        return ErrorCategory.CANCELLED, False, "Execution cancelled"
    if isinstance(exc, HTTPException):
        if exc.status_code in (401, 403):
            return ErrorCategory.AUTHORIZATION_ERROR, False, safe
        return ErrorCategory.CONFIGURATION_ERROR, False, safe
    name = type(exc).__name__
    module = type(exc).__module__ or ""
    # Deterministic parser failures never succeed on retry.
    if name == "ParseError" or "parsing" in module:
        return ErrorCategory.PARSER_ERROR, False, safe
    # Deterministic engine input/contract failures.
    if name in (
        "ComplianceError",
        "ComplianceInputError",
        "UnsupportedFrameworkError",
        "UnknownFrameworkVersionError",
        "UnsupportedVendorError",
        "InvalidControlError",
        "DuplicateControlError",
        "ValidationError",
        "ValueError",
        "KeyError",
        "TypeError",
    ):
        return ErrorCategory.VALIDATION_ERROR, False, safe
    # Transient infrastructure: connections, broker, timeouts.
    if name in (
        "OperationalError",
        "DBAPIError",
        "InterfaceError",
        "ConnectionError",
        "TimeoutError",
        "RedisError",
        "KombuError",
        "ChannelError",
    ) or "redis" in module or "kombu" in module or "asyncpg" in module:
        return ErrorCategory.INFRASTRUCTURE_ERROR, True, safe
    # Unknown engine/internal failures: retryable but bounded.
    return ErrorCategory.EXECUTION_ERROR, True, safe


# A QUEUED execution untouched beyond this window is treated as
# message-lost (broker drop, crash before delivery-ack) and republished.
# Duplicates are harmless by design: only one claimant can leave QUEUED.
STALE_QUEUED_MINUTES_DEFAULT = 15


async def recover_stale_executions(
    db: AsyncSession,
    now: Optional[datetime] = None,
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Recover worker-lost executions.

    Handles two cases:
    1. RUNNING rows with expired leases (dead workers): marked FAILED +
       fresh QUEUED replacements (attempt+1). Returned in `recovered_ids`
       so the CALLER publishes exactly those (bounded: one publish per
       reaped row — never a blind re-broadcast).
    2. QUEUED rows untouched beyond the stale window (lost broker
       messages): reported in `lost_queued_ids` but NOT published here.
       Only worker STARTUP publishes those (rare event); per-task callers
       must ignore that key, otherwise every task run re-broadcasts the
       whole stale set and the queue amplifies without bound.

    CANCEL_REQUESTED rows untouched beyond the lease window confirm to
    CANCELLED (their worker died before observing the request).
    """
    now = now or _utcnow()
    rows = await db.execute(
        select(AuditExecution).where(
            AuditExecution.status == ExecutionStatus.RUNNING,
            AuditExecution.lease_expires_at.is_not(None),
            AuditExecution.lease_expires_at < now,
        )
    )
    stale = rows.scalars().all()
    recovered_ids: list[str] = []
    terminal = 0
    for execution in stale:
        execution.status = ExecutionStatus.FAILED
        execution.error_category = ErrorCategory.INFRASTRUCTURE_ERROR
        execution.error_message = "Worker lost (lease expired) — recovered"
        execution.retryable = execution.attempt < max_attempts
        execution.completed_at = now
        execution.updated_at = now
        await db.flush()
        if execution.attempt < max_attempts:
            replacement = await create_execution(
                db,
                execution.audit_id,
                attempt=execution.attempt + 1,
                max_attempts=max_attempts,
            )
            recovered_ids.append(str(replacement.id))
        else:
            terminal += 1
    cancel_rows = await db.execute(
        select(AuditExecution).where(
            AuditExecution.status == ExecutionStatus.CANCEL_REQUESTED,
            AuditExecution.updated_at < now - timedelta(minutes=LEASE_MINUTES_DEFAULT),
        )
    )
    cancelled = 0
    for execution in cancel_rows.scalars().all():
        execution.status = ExecutionStatus.CANCELLED
        execution.completed_at = now
        execution.updated_at = now
        cancelled += 1
    lost_rows = await db.execute(
        select(AuditExecution).where(
            AuditExecution.status == ExecutionStatus.QUEUED,
            AuditExecution.updated_at < now - timedelta(minutes=STALE_QUEUED_MINUTES_DEFAULT),
        )
    )
    lost_queued_ids = [str(execution.id) for execution in lost_rows.scalars().all()]
    await db.flush()
    return {
        "stale_found": len(stale),
        "recovered": len(recovered_ids),
        "recovered_ids": recovered_ids,
        "terminal": terminal,
        "cancelled": cancelled,
        "lost_queued_ids": lost_queued_ids,
    }


def backoff_seconds(attempt: int, base_seconds: int = 30) -> int:
    """Bounded linear backoff for auto-retry countdowns (30s, 60s, ...)."""
    return max(0, base_seconds * max(1, int(attempt)))


def describe_execution(execution: AuditExecution) -> dict[str, Any]:
    """Safe public projection of an execution row (no secrets, no traces)."""
    return {
        "id": str(execution.id),
        "audit_id": str(execution.audit_id),
        "attempt": execution.attempt,
        "max_attempts": execution.max_attempts,
        "status": execution.status,
        "error_category": execution.error_category,
        "error_message": execution.error_message,
        "retryable": execution.retryable,
        "progress": execution.progress,
        "current_step": execution.current_step,
        "queued_at": execution.queued_at.isoformat() if execution.queued_at else None,
        "started_at": execution.started_at.isoformat() if execution.started_at else None,
        "completed_at": (
            execution.completed_at.isoformat() if execution.completed_at else None
        ),
    }
