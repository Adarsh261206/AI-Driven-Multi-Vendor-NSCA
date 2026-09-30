"""Celery application for durable audit execution (STEP 7).

Broker: Redis (REDIS_URL; tests override to memory:// via conftest).
Tasks live in app.tasks and are imported below so workers discover them.

Delivery semantics relied upon:
- acks_late=True: an unacked task is redelivered when its worker dies.
  Combined with the atomic DB claim in services.execution, redelivery
  exits safely instead of double-executing.
- prefetch_multiplier=1: fair dispatch across workers.
- visibility_timeout: broker-level backstop behind the DB lease.
"""

from celery import Celery
from celery.signals import worker_ready

from app.config import settings

broker_url = settings.CELERY_BROKER_URL or settings.REDIS_URL

celery_app = Celery(
    "configshield",
    broker=broker_url,
)

celery_app.conf.update(
    task_acks_late=True,
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    worker_prefetch_multiplier=1,
    broker_transport_options={
        "visibility_timeout": settings.EXECUTION_VISIBILITY_TIMEOUT_SECONDS,
    },
    task_default_queue="audits",
    task_create_missing_queues=True,
    worker_send_task_events=False,
)

# Task modules import celery_app (above is fully defined first), and import
# audit_execution lazily inside task bodies — no import cycles.
# autodiscover_tasks (not a mid-module import) registers app.tasks.
celery_app.autodiscover_tasks(["app"])

@worker_ready.connect
def recover_executions_on_worker_start(sender=None, **kwargs):
    """Reap worker-lost executions whenever a worker (re)starts.

    Fires in worker processes only (never in API/client processes):
    RUNNING rows with expired leases become FAILED + requeued, orphaned
    CANCEL_REQUESTED rows confirm to CANCELLED. This is what makes queued
    work survive backend restarts and worker crashes without a scheduler.
    """
    import asyncio

    async def _run():
        from app.database import WorkerSessionLocal as AsyncSessionLocal
        from app.services import execution as exec_svc

        from app.tasks import execute_audit_task

        async with AsyncSessionLocal() as db:
            result = await exec_svc.recover_stale_executions(db)
            await db.commit()
            for replacement_id in result.get("recovered_ids", []):
                execute_audit_task.apply_async(args=[replacement_id])
            for lost_id in result.get("lost_queued_ids", []):
                execute_audit_task.apply_async(args=[lost_id])
            return result

    try:
        return asyncio.run(_run())
    except Exception:
        return None
