from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from uuid import UUID
from datetime import datetime

from app.database import get_db
from app.models import User, Audit, AuditConfiguration, Configuration
from app.models import AuditAction
from app.repositories.audit_trail import AuditTrailRepository
from app.schemas import AuditCreate, AuditResponse, AuditStatusResponse, AuditListResponse, AuditStatus, FindingListResponse, FindingStatus, PaginationMeta
from app.security.auth import get_current_user
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
    # Validate configuration IDs exist
    if audit.configuration_ids:
        result = await db.execute(
            select(Configuration.id).where(Configuration.id.in_(audit.configuration_ids))
        )
        existing_ids = [row[0] for row in result.all()]
        
        missing_ids = set(audit.configuration_ids) - set(existing_ids)
        if missing_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Configuration IDs not found: {missing_ids}"
            )
    
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
    
    if audit.status not in [AuditStatus.PENDING.value, AuditStatus.PROCESSING.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot cancel audit in current status"
        )
    
    audit.status = AuditStatus.CANCELLED.value
    audit.completed_at = datetime.utcnow()

    await db.flush()

    # E12: cancellation closes the lifecycle history.
    trail = AuditTrailRepository(db)
    await trail.log_audit_event(
        action=AuditAction.AUDIT_CANCELLED,
        audit_id=str(audit.id),
        user_id=str(current_user.id),
    )
    await db.flush()
    await db.refresh(audit)

    return AuditResponse.from_orm(audit)
