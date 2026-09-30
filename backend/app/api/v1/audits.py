from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from uuid import UUID
from datetime import datetime

from app.database import get_db
from app.models import User, Audit, AuditConfiguration
from app.models import AuditAction
from app.repositories.audit_trail import AuditTrailRepository
from app.schemas import AuditCreate, AuditResponse, AuditStatusResponse, AuditListResponse, AuditStatus, FindingListResponse, FindingStatus, PaginationMeta
from app.security.auth import get_current_user
from app.services.scope import validate_audit_scope
from app.api.v1.findings import _to_finding_response

router = APIRouter()


@router.get("/", response_model=AuditListResponse)
async def list_audits(
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    audit_status: Optional[AuditStatus] = None,
    framework: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all audits for the current user"""
    # Build query
    query = select(Audit).where(Audit.user_id == current_user.id)
    count_query = select(func.count(Audit.id)).where(Audit.user_id == current_user.id)
    
    if audit_status:
        query = query.where(Audit.status == audit_status.value)
        count_query = count_query.where(Audit.status == audit_status.value)
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(Audit.created_at.desc())
    
    # Execute query
    result = await db.execute(query)
    audits = result.scalars().all()
    
    return AuditListResponse(
        items=[AuditResponse.from_orm(audit) for audit in audits],
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
        ),
    )


@router.post("/", response_model=AuditResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_audit(
    audit: AuditCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new audit"""
    # Ownership + optional device-scope boundary: EVERY requested
    # configuration must be inside the caller's permitted scope, and when
    # device_ids are supplied every configuration must belong to one of
    # those devices. A single violation rejects the ENTIRE request BEFORE
    # any audit row exists — no partial audits, ever.
    await validate_audit_scope(db, audit.device_ids, audit.configuration_ids, current_user)
    
    # Create audit
    new_audit = Audit(
        user_id=current_user.id,
        name=audit.name,
        description=audit.description,
        status=AuditStatus.PENDING.value,
        configuration_count=len(audit.configuration_ids),
    )
    
    db.add(new_audit)
    await db.flush()
    
    # Create audit-configuration associations
    for config_id in audit.configuration_ids:
        audit_config = AuditConfiguration(
            audit_id=new_audit.id,
            configuration_id=config_id,
        )
        db.add(audit_config)
    
    await db.flush()
    await db.refresh(new_audit)

    # E12: audit creation opens the lifecycle history.
    trail = AuditTrailRepository(db)
    await trail.log_audit_event(
        action=AuditAction.AUDIT_CREATED,
        audit_id=str(new_audit.id),
        user_id=str(current_user.id),
        details={
            "name": new_audit.name,
            "configuration_count": len(audit.configuration_ids),
        },
    )
    await db.flush()

    return AuditResponse.from_orm(new_audit)


@router.get("/{audit_id}", response_model=AuditResponse)
async def get_audit(
    audit_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get an audit by ID"""
    result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = result.scalar_one_or_none()
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    return AuditResponse.from_orm(audit)


@router.get("/{audit_id}/status", response_model=AuditStatusResponse)
async def get_audit_status(
    audit_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get audit status"""
    result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = result.scalar_one_or_none()
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # Calculate progress based on status
    progress_map = {
        AuditStatus.PENDING.value: 0,
        AuditStatus.PROCESSING.value: 50,
        AuditStatus.COMPLETED.value: 100,
        AuditStatus.FAILED.value: 100,
        AuditStatus.CANCELLED.value: 100,
    }
    
    steps_map = {
        AuditStatus.PENDING.value: [],
        AuditStatus.PROCESSING.value: ["ingestion", "detection", "parsing"],
        AuditStatus.COMPLETED.value: [
            "ingestion", "detection", "parsing", "semantic_analysis",
            "normalization", "compliance_evaluation", "finding_generation"
        ],
        AuditStatus.FAILED.value: [],
        AuditStatus.CANCELLED.value: [],
    }
    
    return AuditStatusResponse(
        status=AuditStatus(audit.status),
        progress=progress_map.get(audit.status, 0),
        current_step="processing" if audit.status == AuditStatus.PROCESSING.value else None,
        steps_completed=steps_map.get(audit.status, []),
        estimated_completion=None,
    )


@router.get("/{audit_id}/findings", response_model=FindingListResponse)
async def list_audit_findings_canonical(
    audit_id: UUID,
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    severity: Optional[str] = None,
    status: Optional[FindingStatus] = None,
    vendor: Optional[str] = None,
    platform: Optional[str] = None,
    control_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List findings for an audit (spec 20.2 canonical endpoint).

    Backed by the single FindingQueryService shared with every other
    findings list endpoint (E08 F4).
    """
    from app.repositories.findings import FindingQueryService
    from app.schemas import FindingListResponse as _FLR

    items, total = await FindingQueryService(db).list_for_audit(
        audit_id=audit_id, user_id=current_user.id, page=page,
        per_page=per_page, severity=severity, status=status, vendor=vendor,
        platform=platform, control_id=control_id,
    )
    return _FLR(
        items=[_to_finding_response(f) for f in items],
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
        ),
    )


@router.post("/{audit_id}/cancel", response_model=AuditResponse)
async def cancel_audit(
    audit_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cancel an audit"""
    result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = result.scalar_one_or_none()
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # STEP 7: queue-aware cancellation. The latest execution row decides:
    # QUEUED -> revoke + CANCELLED immediately; RUNNING -> CANCEL_REQUESTED
    # (the worker observes it at safe checkpoints); terminal rows keep the
    # legacy 400 below. Audits without execution rows use legacy behavior.
    from app.services import execution as exec_svc

    latest = await exec_svc.latest_execution(db, audit.id)
    if latest is not None and latest.status not in (
        exec_svc.ExecutionStatus.QUEUED,
        exec_svc.ExecutionStatus.RUNNING,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot cancel audit in current status"
        )

    if latest is not None:
        if latest.status == exec_svc.ExecutionStatus.QUEUED:
            try:
                from app.celery_app import celery_app

                if latest.celery_task_id:
                    celery_app.control.revoke(latest.celery_task_id, terminate=False)
            except Exception:
                pass
            latest.status = exec_svc.ExecutionStatus.CANCELLED
            latest.completed_at = datetime.utcnow()
            latest.updated_at = datetime.utcnow()
            await db.flush()
        else:
            requested = await exec_svc.request_cancel_execution(db, latest.id)
            if requested is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot cancel audit in current status"
                )

    if audit.status not in [AuditStatus.PENDING.value, AuditStatus.PROCESSING.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot cancel audit in current status"
        )

    # QUEUED executions (and legacy audits) close immediately; RUNNING
    # audits stay PROCESSING until the worker observes the request.
    if latest is None or latest.status == exec_svc.ExecutionStatus.CANCELLED:
        audit.status = AuditStatus.CANCELLED.value
        audit.completed_at = datetime.utcnow()

    await db.flush()

    # E12: cancellation closes the lifecycle history.
    trail = AuditTrailRepository(db)
    await trail.log_audit_event(
        action=AuditAction.AUDIT_CANCELLED,
        audit_id=str(audit.id),
        user_id=str(current_user.id),
        details=(
            {"execution_id": str(latest.id), "queue_state": latest.status}
            if latest is not None
            else None
        ),
    )
    await db.flush()
    await db.refresh(audit)

    return AuditResponse.from_orm(audit)
