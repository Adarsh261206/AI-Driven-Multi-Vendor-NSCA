from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from app.database import get_db
from app.models import User, Audit, AuditConfiguration, Configuration
from app.schemas import AuditCreate, AuditResponse, AuditStatusResponse, AuditListResponse, AuditStatus, PaginationMeta
from app.security.auth import get_current_user

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
    await db.refresh(audit)
    
    return AuditResponse.from_orm(audit)
