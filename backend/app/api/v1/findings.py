from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from uuid import UUID

from app.database import get_db
from app.models import User, Finding, Audit
from app.schemas import FindingResponse, FindingStatusUpdate, FindingListResponse, FindingStatus, PaginationMeta
from app.security.auth import get_current_user

router = APIRouter()


@router.get("/audit/{audit_id}", response_model=FindingListResponse)
async def list_audit_findings(
    audit_id: UUID,
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    severity: Optional[str] = None,
    finding_status: Optional[FindingStatus] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List findings for an audit"""
    # Verify audit exists and belongs to user
    audit_result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = audit_result.scalar_one_or_none()
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # Build query
    query = select(Finding).where(Finding.audit_id == audit_id)
    count_query = select(func.count(Finding.id)).where(Finding.audit_id == audit_id)
    
    if severity:
        query = query.where(Finding.severity == severity)
        count_query = count_query.where(Finding.severity == severity)
    
    if finding_status:
        query = query.where(Finding.status == finding_status.value)
        count_query = count_query.where(Finding.status == finding_status.value)
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(Finding.created_at.desc())
    
    # Execute query
    result = await db.execute(query)
    findings = result.scalars().all()
    
    return FindingListResponse(
        items=[_to_finding_response(finding) for finding in findings],
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
        ),
    )


def _to_finding_response(finding) -> FindingResponse:
    """Serialize a finding with normalized uppercase severity (API contract)."""
    resp = FindingResponse.from_orm(finding)
    if finding.severity:
        resp.severity = finding.severity.upper()
    return resp


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a finding by ID"""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Verify user has access to the audit
    audit_result = await db.execute(
        select(Audit).where(
            Audit.id == finding.audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = audit_result.scalar_one_or_none()
    
    if not audit:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return _to_finding_response(finding)


@router.put("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: UUID,
    update: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update finding status"""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Verify user has access to the audit
    audit_result = await db.execute(
        select(Audit).where(
            Audit.id == finding.audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = audit_result.scalar_one_or_none()
    
    if not audit:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Update status
    finding.status = update.status.value
    
    await db.flush()
    await db.refresh(finding)
    
    return _to_finding_response(finding)
