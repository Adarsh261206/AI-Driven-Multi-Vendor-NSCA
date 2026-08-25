"""
Audit Execution API

Endpoints for running compliance audits and retrieving results.
"""

from fastapi import APIRouter, HTTPException, Query, status, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from uuid import UUID, uuid4
from datetime import datetime

from app.database import get_db
from app.models import (
    User, Audit, AuditConfiguration, Configuration, 
    VendorIdentification, ParsedConfiguration, SemanticInterpretation,
    NormalizedConfiguration, ComplianceResult, Finding, AuditAction,
    AuditStatus, FindingStatus, Severity,
)
from app.schemas import (
    AuditCreate, AuditResponse, AuditStatusResponse, AuditListResponse,
    FindingResponse, FindingListResponse, PaginationMeta, APIResponse,
)
from app.security.auth import get_current_user
from app.engines.compliance.executor import AuditExecutor
from app.repositories.audit_trail import AuditTrailRepository

router = APIRouter()


async def run_audit_pipeline(
    audit_id: str,
    config_ids: list[str],
    framework: str,
    user_id: str,
):
    """
    Background task to run the full audit pipeline
    
    INGEST → VALIDATE → DETECT → PARSE → NORMALIZE → EVALUATE → FINDINGS
    """
    import traceback
    from app.database import AsyncSessionLocal
    
    async with AsyncSessionLocal() as db:
        try:
            # Update audit status
            audit_result = await db.execute(
                select(Audit).where(Audit.id == UUID(audit_id))
            )
            audit = audit_result.scalar_one_or_none()
            if not audit:
                return
            
            audit.status = AuditStatus.PROCESSING.value
            audit.started_at = datetime.utcnow()
            await db.flush()
            
            executor = AuditExecutor()
            all_findings = []
            total_controls = 0
            passed = 0
            failed = 0
            review = 0
            
            for config_id in config_ids:
                # Get configuration
                config_result = await db.execute(
                    select(Configuration).where(Configuration.id == UUID(config_id))
                )
                config = config_result.scalar_one_or_none()
                if not config:
                    continue
                
                # Run audit
                result = executor.execute(
                    audit_id=audit_id,
                    config_content=config.raw_content,
                    framework=framework,
                    device_name=config.filename,
                )
                
                # Persist results
                # 1. Vendor Identification
                vendor_id = VendorIdentification(
                    configuration_id=config.id,
                    vendor=result.vendor,
                    platform=result.platform,
                    firmware_version=result.firmware_version,
                    confidence=result.detection_confidence,
                    detection_method="pattern_matching",
                    detection_evidence=[],
                )
                db.add(vendor_id)
                
                # 2. Parsed Configuration
                parse_tree = {}
                if result.parse_result:
                    parse_tree = {
                        "sections": [
                            {"key": s.key, "value": s.value, "children": len(s.children)}
                            for s in result.parse_result.parse_tree
                        ],
                        "unknown_sections": [
                            {"path": u.path, "raw_text": u.raw_text[:100]}
                            for u in result.parse_result.unknown_sections
                        ],
                    }
                
                parsed_config = ParsedConfiguration(
                    configuration_id=config.id,
                    vendor=result.vendor,
                    platform=result.platform,
                    parse_tree=parse_tree,
                    parse_errors=[],
                    parse_warnings=[],
                    unknown_sections=[
                        {"path": u.path, "raw_text": u.raw_text[:200]}
                        for u in (result.parse_result.unknown_sections if result.parse_result else [])
                    ],
                )
                db.add(parsed_config)
                await db.flush()
                
                # 3. Semantic Interpretation
                semantic_interp = SemanticInterpretation(
                    parsed_configuration_id=parsed_config.id,
                    semantic_sections=[],
                    confidence_scores={},
                    unknown_meanings=[],
                )
                db.add(semantic_interp)
                await db.flush()
                
                # 4. Normalized Configuration
                normalized_config = NormalizedConfiguration(
                    semantic_interpretation_id=semantic_interp.id,
                    universal_model_version="1.0",
                    normalized_values=[],
                    unmapped_concepts=[],
                )
                db.add(normalized_config)
                await db.flush()
                
                # 5. Compliance Results - store and build lookup
                compliance_results_by_control = {}
                if result.compliance_evaluation:
                    for eval_result in result.compliance_evaluation.evaluations:
                        compliance_result = ComplianceResult(
                            audit_id=UUID(audit_id),
                            normalized_configuration_id=normalized_config.id,
                            framework=framework,
                            control_id=eval_result.control_id,
                            control_name=eval_result.control_title,
                            control_description=eval_result.control_description,
                            result=eval_result.result.value,
                            confidence=eval_result.confidence,
                            severity=eval_result.severity.value,
                            evidence=eval_result.evidence.to_dict() if hasattr(eval_result.evidence, 'to_dict') else {},
                            remediation=eval_result.remediation if isinstance(eval_result.remediation, dict) else {},
                        )
                        db.add(compliance_result)
                        await db.flush()
                        compliance_results_by_control[eval_result.control_id] = compliance_result.id
                        
                        total_controls += 1
                        result_str = eval_result.result.value if hasattr(eval_result.result, 'value') else str(eval_result.result)
                        if result_str.upper() == "PASS":
                            passed += 1
                        elif result_str.upper() == "FAIL":
                            failed += 1
                        else:
                            review += 1
                
                # 6. Findings - linked to compliance results
                for finding in result.findings:
                    linked_result_id = compliance_results_by_control.get(finding.control_id)
                    db_finding = Finding(
                        audit_id=UUID(audit_id),
                        compliance_result_id=linked_result_id,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity.value,
                        confidence=finding.confidence,
                        status=FindingStatus.OPEN.value,
                        evidence=finding.evidence,
                        remediation=finding.remediation if isinstance(finding.remediation, dict) else {},
                        affected_device=finding.affected_device,
                        affected_vendor=finding.affected_vendor,
                        affected_platform=finding.affected_platform,
                    )
                    db.add(db_finding)
                    all_findings.append(db_finding)
                
                # Update audit-configuration association
                audit_config_result = await db.execute(
                    select(AuditConfiguration).where(
                        AuditConfiguration.audit_id == UUID(audit_id),
                        AuditConfiguration.configuration_id == config.id,
                    )
                )
                audit_config = audit_config_result.scalar_one_or_none()
                if audit_config:
                    audit_config.vendor_identification = {
                        "vendor": result.vendor,
                        "platform": result.platform,
                        "confidence": result.detection_confidence,
                    }
                    audit_config.parsed_configuration_id = parsed_config.id
            
            # Update audit summary
            audit.status = AuditStatus.COMPLETED.value
            audit.completed_at = datetime.utcnow()
            audit.overall_score = (passed / total_controls * 100) if total_controls > 0 else 0
            audit.findings_count = len(all_findings)
            audit.critical_findings = sum(1 for f in all_findings if f.severity and f.severity.upper() == "CRITICAL")
            audit.high_findings = sum(1 for f in all_findings if f.severity and f.severity.upper() == "HIGH")
            audit.medium_findings = sum(1 for f in all_findings if f.severity and f.severity.upper() == "MEDIUM")
            audit.low_findings = sum(1 for f in all_findings if f.severity and f.severity.upper() == "LOW")
            
            # Log completion
            audit_trail = AuditTrailRepository(db)
            await audit_trail.log_compliance_evaluation(
                audit_id=audit_id,
                total_controls=total_controls,
                passed=passed,
                failed=failed,
                review=review,
                overall_score=audit.overall_score,
                user_id=user_id,
            )
            
            await db.commit()
            
        except Exception as e:
            # Mark audit as failed
            import traceback
            print(f"Audit pipeline failed: {e}")
            print(traceback.format_exc())
            if audit:
                audit.status = AuditStatus.FAILED.value
                audit.completed_at = datetime.utcnow()
                await db.commit()
            
            raise


@router.post("/execute", response_model=AuditResponse, status_code=status.HTTP_202_ACCEPTED)
async def execute_audit(
    audit: AuditCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Create and execute a compliance audit
    
    Runs the full pipeline:
    INGEST → VALIDATE → DETECT → PARSE → NORMALIZE → EVALUATE → FINDINGS
    
    Returns immediately with audit ID. Results available via status endpoint.
    """
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
        id=uuid4(),
        user_id=current_user.id,
        name=audit.name,
        description=audit.description,
        status=AuditStatus.PENDING.value,
        configuration_count=len(audit.configuration_ids),
    )
    
    db.add(new_audit)
    
    # Create audit-configuration associations
    for config_id in audit.configuration_ids:
        audit_config = AuditConfiguration(
            audit_id=new_audit.id,
            configuration_id=config_id,
        )
        db.add(audit_config)
    
    await db.flush()
    await db.refresh(new_audit)
    
    # Start audit pipeline in background
    background_tasks.add_task(
        run_audit_pipeline,
        audit_id=str(new_audit.id),
        config_ids=[str(cid) for cid in audit.configuration_ids],
        framework=audit.framework or "CIS",
        user_id=str(current_user.id),
    )
    
    return AuditResponse.from_orm(new_audit)


@router.get("/{audit_id}/status")
async def get_audit_execution_status(
    audit_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get audit execution status"""
    audit_result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = audit_result.scalar_one_or_none()
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    progress = 0
    if audit.status == "completed":
        progress = 100
    elif audit.status == "processing":
        progress = 50
    
    return {
        "id": str(audit.id),
        "name": audit.name,
        "status": audit.status,
        "progress": progress,
        "overall_score": audit.overall_score,
        "findings_count": audit.findings_count,
        "critical_findings": audit.critical_findings,
        "high_findings": audit.high_findings,
        "medium_findings": audit.medium_findings,
        "low_findings": audit.low_findings,
        "started_at": audit.started_at.isoformat() if audit.started_at else None,
        "completed_at": audit.completed_at.isoformat() if audit.completed_at else None,
    }


@router.get("/{audit_id}/findings", response_model=FindingListResponse)
async def get_audit_findings(
    audit_id: UUID,
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get findings for an audit"""
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
    
    # Build query
    query = select(Finding).where(Finding.audit_id == audit_id)
    count_query = select(func.count(Finding.id)).where(Finding.audit_id == audit_id)
    
    if severity:
        query = query.where(Finding.severity == severity)
        count_query = count_query.where(Finding.severity == severity)
    
    if status_filter:
        query = query.where(Finding.status == status_filter)
        count_query = count_query.where(Finding.status == status_filter)
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(Finding.severity)
    
    # Execute query
    result = await db.execute(query)
    findings = result.scalars().all()
    
    return FindingListResponse(
        items=[_to_finding_response(f) for f in findings],
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


@router.get("/{audit_id}/summary")
async def get_audit_summary(
    audit_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get audit summary with findings breakdown"""
    # Verify audit exists
    audit_result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = audit_result.scalar_one_or_none()
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # Get findings by severity
    findings_by_severity = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.audit_id == audit_id)
        .group_by(Finding.severity)
    )
    severity_counts = {
        (row[0].upper() if row[0] else row[0]): row[1]
        for row in findings_by_severity.all()
    }
    
    # Get findings by status
    findings_by_status = await db.execute(
        select(Finding.status, func.count(Finding.id))
        .where(Finding.audit_id == audit_id)
        .group_by(Finding.status)
    )
    status_counts = {row[0]: row[1] for row in findings_by_status.all()}
    
    return {
        "audit_id": str(audit.id),
        "status": audit.status,
        "overall_score": audit.overall_score,
        "findings_count": audit.findings_count,
        "findings_by_severity": severity_counts,
        "findings_by_status": status_counts,
        "started_at": audit.started_at.isoformat() if audit.started_at else None,
        "completed_at": audit.completed_at.isoformat() if audit.completed_at else None,
    }
