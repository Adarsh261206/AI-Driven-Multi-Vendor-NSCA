from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from uuid import UUID

from app.database import get_db
from app.models import User, Finding, Audit
from app.schemas import FindingResponse, FindingStatusUpdate, FindingListResponse, FindingStatus, PaginationMeta, RemediationApproveRequest, RemediationPlanResponse
from app.security.auth import get_current_user, require_auditor
from app.engines.remediation.models import RemediationPlanError

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


# ---------------------------------------------------------------------------
# Remediation plans (plan-first workflow; backend execution disabled)
# ---------------------------------------------------------------------------


def _plan_error(exc: RemediationPlanError) -> HTTPException:
    message = str(exc)
    if message.startswith("unknown plan") or message.startswith(
            "unknown finding"):
        return HTTPException(status_code=404, detail=message)
    return HTTPException(status_code=422, detail=message)


def _to_plan_response(row) -> RemediationPlanResponse:
    return RemediationPlanResponse(
        id=row.id,
        plan_id=row.plan_id,
        finding_id=row.finding_id,
        control_id=row.control_id,
        status=row.status,
        plan=row.plan_json or {},
        configuration_id=row.configuration_id,
        configuration_hash_before=row.configuration_hash_before,
        approved_by=row.approved_by,
        approved_at=row.approved_at,
        rejection_reason=row.rejection_reason,
        failure_info=row.failure_info,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _owned_finding(finding_id: UUID, db: AsyncSession,
                         current_user: User):
    """Fetch the finding, scoped to the caller's audits (404 otherwise)."""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    audit_result = await db.execute(
        select(Audit).where(
            Audit.id == finding.audit_id,
            Audit.user_id == current_user.id,
        )
    )
    if audit_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.post("/{finding_id}/remediation/plan",
             response_model=RemediationPlanResponse)
async def create_remediation_plan(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a dry-run remediation plan (never touches a device)."""
    from app.engines.remediation import service as plan_service

    finding = await _owned_finding(finding_id, db, current_user)
    try:
        row, _ = await plan_service.create_plan(
            db, finding, str(current_user.id))
        await db.commit()
        await db.refresh(row)
    except RemediationPlanError as exc:
        await db.rollback()
        raise _plan_error(exc) from exc
    return _to_plan_response(row)


@router.post("/{finding_id}/remediation/parameters",
             response_model=RemediationPlanResponse)
async def resolve_remediation_parameters(
    finding_id: UUID,
    body: RemediationApproveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auditor),
):
    """Parameter Resolution stage: supply placeholders, re-evaluate.

    Secrets are validated then discarded (descriptor flips to
    supplied/redacted); plain values substitute into stored commands.
    A plan that becomes safe advances to awaiting approval. Partial
    supply is allowed.
    """
    from app.engines.remediation import service as plan_service

    finding = await _owned_finding(finding_id, db, current_user)
    try:
        latest = await plan_service.latest_plan_for_finding(
            db, str(finding.id))
        if latest is None:
            raise RemediationPlanError("unknown plan for this finding")
        row, _ = await plan_service.resolve_plan_params(
            db, latest.plan_id, str(current_user.id),
            params=body.params or {})
        await db.commit()
        await db.refresh(row)
    except RemediationPlanError as exc:
        await db.rollback()
        raise _plan_error(exc) from exc
    return _to_plan_response(row)


@router.post("/{finding_id}/remediation/approve",
             response_model=RemediationPlanResponse)
async def approve_remediation_plan(
    finding_id: UUID,
    body: RemediationApproveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auditor),
):
    """Approve (confirm=true) or reject a plan awaiting approval."""
    from app.engines.remediation import service as plan_service

    finding = await _owned_finding(finding_id, db, current_user)
    try:
        latest = await plan_service.latest_plan_for_finding(
            db, str(finding.id))
        if latest is None:
            raise RemediationPlanError("unknown plan for this finding")
        row, _ = await plan_service.approve_plan(
            db, latest.plan_id, str(current_user.id),
            confirm=bool(body.confirm), params=body.params or {},
            notes=body.notes or "")
        await db.commit()
        await db.refresh(row)
    except RemediationPlanError as exc:
        await db.rollback()
        raise _plan_error(exc) from exc
    return _to_plan_response(row)


@router.post("/{finding_id}/remediation/script")
async def download_remediation_script(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auditor),
):
    """Download the generated Python script for an approved plan."""
    from fastapi.responses import Response

    from app.engines.remediation import service as plan_service

    finding = await _owned_finding(finding_id, db, current_user)
    try:
        latest = await plan_service.latest_plan_for_finding(
            db, str(finding.id))
        if latest is None:
            raise RemediationPlanError("unknown plan for this finding")
        filename, source, _ = await plan_service.generate_script_artifact(
            db, latest.plan_id, str(current_user.id))
        await db.commit()
    except RemediationPlanError as exc:
        await db.rollback()
        raise _plan_error(exc) from exc
    return Response(
        content=source,
        media_type="text/x-python",
        headers={"Content-Disposition":
                 f'attachment; filename="{filename}"'},
    )


@router.post("/{finding_id}/remediation/rollback")
async def download_rollback_script(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auditor),
):
    """Download the rollback script (only when a safe rollback exists)."""
    from fastapi.responses import Response

    from app.engines.remediation import service as plan_service

    finding = await _owned_finding(finding_id, db, current_user)
    try:
        latest = await plan_service.latest_plan_for_finding(
            db, str(finding.id))
        if latest is None:
            raise RemediationPlanError("unknown plan for this finding")
        filename, source, _ = await plan_service.generate_rollback_artifact(
            db, latest.plan_id, str(current_user.id))
        await db.commit()
    except RemediationPlanError as exc:
        await db.rollback()
        raise _plan_error(exc) from exc
    return Response(
        content=source,
        media_type="text/x-python",
        headers={"Content-Disposition":
                 f'attachment; filename="{filename}"'},
    )
