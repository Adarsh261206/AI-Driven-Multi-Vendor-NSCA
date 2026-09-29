from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
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
    vendor: Optional[str] = None,
    platform: Optional[str] = None,
    control_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List findings for an audit (canonical query service, E08 F4)."""
    from app.repositories.findings import FindingQueryService

    items, total = await FindingQueryService(db).list_for_audit(
        audit_id=audit_id, user_id=current_user.id, page=page,
        per_page=per_page, severity=severity, status=finding_status,
        vendor=vendor, platform=platform, control_id=control_id,
    )
    return FindingListResponse(
        items=[_to_finding_response(finding) for finding in items],
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
    """Update finding status (E08 F6: every accepted transition — including
    an explicit no-op — records audit history with actor, previous/new
    status, timestamp and notes; notes are never silently dropped)."""
    from app.repositories.audit_trail import AuditTrailRepository

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

    previous_status = finding.status
    new_status = update.status.value
    notes = update.notes or ""
    trail = AuditTrailRepository(db)
    if previous_status == new_status:
        # Explicit no-op (project convention): state is unchanged, but the
        # request — actor, timestamp and especially notes — is preserved in
        # history instead of vanishing.
        await trail.log_finding_update(
            finding_id=str(finding.id),
            audit_id=str(finding.audit_id),
            old_status=previous_status,
            new_status=new_status,
            user_id=str(current_user.id),
            notes=notes,
            no_op=True,
        )
    else:
        # Update status
        finding.status = new_status
        await trail.log_finding_update(
            finding_id=str(finding.id),
            audit_id=str(finding.audit_id),
            old_status=previous_status,
            new_status=new_status,
            user_id=str(current_user.id),
            notes=notes,
        )

    await db.flush()
    await db.refresh(finding)

    return _to_finding_response(finding)
