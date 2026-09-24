from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import Response
from typing import List, Optional
from uuid import UUID
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import User, Audit, Finding, ComplianceResult, AuditConfiguration, Configuration
from app.schemas import ReportResponse, ReportDownloadResponse, ReportListResponse, PaginationMeta
from app.security.auth import get_current_user
from app.engines.reporting import generate_audit_report

router = APIRouter()


@router.get("/", response_model=ReportListResponse)
async def list_reports(
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    framework: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all completed audit reports"""
    query = select(Audit).where(
        Audit.user_id == current_user.id,
        Audit.status == "completed",
    )
    count_query = select(func.count(Audit.id)).where(
        Audit.user_id == current_user.id,
        Audit.status == "completed",
    )

    if framework:
        # Filter by framework via compliance_results join
        query = query.join(ComplianceResult).where(ComplianceResult.framework == framework)
        count_query = count_query.join(ComplianceResult).where(ComplianceResult.framework == framework)

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(Audit.completed_at.desc())
    result = await db.execute(query)
    audits = result.scalars().unique().all()

    items = []
    for audit in audits:
        items.append(ReportResponse(
            id=str(audit.id),
            audit_id=audit.id,
            audit_name=audit.name,
            framework="CIS",
            overall_score=audit.overall_score or 0.0,
            generated_at=audit.completed_at or audit.updated_at,
            download_url=f"/api/v1/reports/{audit.id}/report",
        ))

    return ReportListResponse(
        items=items,
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page if per_page else 0,
        ),
    )


@router.get("/{audit_id}/report")
async def get_audit_report(
    audit_id: UUID,
    format: str = "pdf",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and return audit report as PDF"""
    # Verify audit exists and user has access
    audit_result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = audit_result.scalar_one_or_none()

    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    # Fetch findings
    findings_result = await db.execute(
        select(Finding).where(Finding.audit_id == audit_id)
    )
    findings_orm = findings_result.scalars().all()

    findings = []
    for f in findings_orm:
        findings.append({
            "id": str(f.id),
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "confidence": f.confidence,
            "status": f.status,
            "evidence": f.evidence or {},
            "remediation": f.remediation or {},
        })

    # Fetch compliance results
    compliance_result = await db.execute(
        select(ComplianceResult).where(ComplianceResult.audit_id == audit_id)
    )
    compliance_orm = compliance_result.scalars().all()

    compliance_results = []
    for cr in compliance_orm:
        compliance_results.append({
            "id": str(cr.id),
            "control_id": cr.control_id,
            "control_name": cr.control_name,
            "control_description": cr.control_description,
            "result": cr.result,
            "confidence": cr.confidence,
            "severity": cr.severity,
            "framework": cr.framework,
        })

    # Fetch configuration count + file details (vendor, device_type, platform, hostname)
    config_count_result = await db.execute(
        select(func.count(AuditConfiguration.configuration_id))
        .where(AuditConfiguration.audit_id == audit_id)
    )
    config_count = config_count_result.scalar()

    # Per-file device identification (real, from VendorIdentification + Configuration)
    file_details = []
    ac_result = await db.execute(
        select(AuditConfiguration, Configuration)
        .join(Configuration, AuditConfiguration.configuration_id == Configuration.id)
        .where(AuditConfiguration.audit_id == audit_id)
    )
    for ac, cfg in ac_result.all():
        vi = ac.vendor_identification or {}
        file_details.append({
            "filename": cfg.filename,
            "vendor": vi.get("vendor", "unknown"),
            "device_type": vi.get("device_type", "unknown"),
            "platform": vi.get("platform", "unknown"),
            "hostname": vi.get("hostname"),
            "firmware_version": vi.get("firmware_version"),
            "confidence": vi.get("confidence"),
            "detection_method": vi.get("detection_method", ""),
        })

    # Determine framework display (dual-baseline if NIST present)
    frameworks_in_audit = set(cr.framework for cr in compliance_orm)
    framework_display = "+".join(sorted(frameworks_in_audit)) if frameworks_in_audit else "CIS"

    audit_data = {
        "audit_id": str(audit.id),
        "audit_name": audit.name,
        "framework": framework_display,
        "status": audit.status,
        "overall_score": audit.overall_score or 0.0,
        "configuration_count": config_count,
        "started_at": audit.started_at.isoformat() if audit.started_at else None,
        "completed_at": audit.completed_at.isoformat() if audit.completed_at else None,
        "file_details": file_details,
    }

    if format == "json":
        return {
            "audit": audit_data,
            "findings": findings,
            "compliance_results": compliance_results,
        }

    # Generate PDF
    pdf_bytes = generate_audit_report(audit_data, findings, compliance_results)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="audit-report-{audit_id}.pdf"',
        },
    )
