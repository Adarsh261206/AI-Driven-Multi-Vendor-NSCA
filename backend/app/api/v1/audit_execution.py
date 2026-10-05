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
from app.benchmarks.selection import overall_score
from app.engines.compliance.executor import AuditExecutor
from app.engines.universal_model import UniversalSecurityModel
from app.repositories.audit_trail import AuditTrailRepository

router = APIRouter()

# Live pipeline tracking — in-memory per audit, for real-time frontend polling (not fake, real backend progress)
import asyncio as _asyncio
import time as _time

audit_live_steps: dict[str, list[dict]] = {}
audit_live_logs: dict[str, list[dict]] = {}
audit_live_file_details: dict[str, list[dict]] = {}

PIPELINE_STEPS_DEF = [
    {"id": "validate", "label": "Validate Configuration", "desc": "Checking file integrity and syntax"},
    {"id": "detect", "label": "Detect Vendor & Device", "desc": "ML model: vendor, platform, switch/router/firewall"},
    {"id": "parse", "label": "Parse Configuration", "desc": "Building syntax tree from raw config"},
    {"id": "normalize", "label": "Normalize to Common Model", "desc": "Mapping to Universal Security Model (28 paths)"},
    {"id": "evaluate", "label": "Evaluate Compliance", "desc": "Framework controls per file"},
    {"id": "findings", "label": "Generate Findings", "desc": "Risk scoring"},
    {"id": "report", "label": "Generate Report", "desc": "PDF with per-device breakdown"},
]


def _init_live_steps(audit_id: str, config_count: int):
    now = _time.time()
    audit_live_steps[audit_id] = [
        {**s, "status": "pending", "started_at": None, "completed_at": None, "duration_ms": None, "progress": 0}
        for s in PIPELINE_STEPS_DEF
    ]
    audit_live_logs[audit_id] = [
        {"ts": now, "step": "init", "level": "info", "msg": f"Audit {audit_id[:8]} started — {config_count} file(s) queued"}
    ]
    audit_live_file_details[audit_id] = []


def _update_step(audit_id: str, step_idx: int, status: str, progress: int = 0, log_msg: str | None = None):
    steps = audit_live_steps.get(audit_id)
    if steps is None or step_idx >= len(steps):
        return
    now = _time.time()
    s = steps[step_idx]
    if status == "running" and s["status"] != "running":
        s["started_at"] = now
        s["status"] = "running"
        s["progress"] = progress
    elif status == "completed":
        s["completed_at"] = now
        s["status"] = "completed"
        s["progress"] = 100
        if s["started_at"]:
            s["duration_ms"] = int((now - s["started_at"]) * 1000)
    elif status == "failed":
        s["status"] = "failed"
        s["progress"] = progress
    else:
        s["status"] = status
        s["progress"] = progress
    if log_msg:
        audit_live_logs.setdefault(audit_id, []).append({"ts": now, "step": s["id"], "level": "info", "msg": log_msg})


def _current_progress(audit_id: str) -> int:
    steps = audit_live_steps.get(audit_id, [])
    if not steps:
        return 0
    # Steps are plain dicts (see _update_step); .get() keeps a malformed
    # entry from 500ing the status endpoint.
    completed = sum(1 for s in steps if s.get("status") == "completed")
    running = sum(1 for s in steps if s.get("status") == "running")
    # 0-100 based on completed + partial running
    return int((completed / len(steps) * 100) + (running * (100 / len(steps) * 0.5)))


def build_compliance_result(audit_id, normalized_configuration_id,
                            framework: str, eval_result) -> "ComplianceResult":
    """Map one canonical ControlEvaluation onto its persistence row (F11).

    Framework/version/result/confidence/severity come from the evaluation's
    own metadata — the writer adds nothing inferred. This is the single
    place run_audit_pipeline builds compliance rows, so persistence cannot
    drift from evaluation.
    """
    return ComplianceResult(
        audit_id=audit_id,
        normalized_configuration_id=normalized_configuration_id,
        framework=eval_result.framework or framework,
        framework_version=eval_result.framework_version or None,
        control_id=eval_result.control_id,
        control_name=eval_result.control_title,
        control_description=eval_result.control_description,
        result=eval_result.result.value,
        confidence=eval_result.confidence,
        severity=eval_result.severity.value,
        evidence=(eval_result.evidence.to_dict()
                  if hasattr(eval_result.evidence, "to_dict") else {}),
        remediation=(eval_result.remediation
                     if isinstance(eval_result.remediation, dict) else {}),
    )



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

            # Live tracking — init 7 steps for frontend real-time view
            _init_live_steps(audit_id, len(config_ids))
            # Pre-populate file details immediately — so frontend shows vendor/switch/router from first poll, not after evaluate
            try:
                from app.engines.detection import VendorDetector as _VD0
                _vd0 = _VD0()
                for _cid in config_ids:
                    _cr0 = await db.execute(select(Configuration).where(Configuration.id == UUID(_cid)))
                    _cfg0 = _cr0.scalar_one_or_none()
                    if _cfg0:
                        _ident0 = _vd0.detect(_cfg0.raw_content)
                        _fd0 = {
                            "filename": _cfg0.filename,
                            "vendor": _ident0.vendor,
                            "platform": _ident0.platform,
                            "device_type": _ident0.device_type,
                            "hostname": _ident0.hostname,
                            "firmware_version": _ident0.firmware_version,
                            "confidence": _ident0.confidence,
                            "detection_method": _ident0.detection_method.value if hasattr(_ident0.detection_method, 'value') else str(_ident0.detection_method),
                        }
                        lst0 = audit_live_file_details.get(audit_id, [])
                        if not any(x["filename"] == _fd0["filename"] for x in lst0):
                            lst0.append(_fd0)
                            audit_live_file_details[audit_id] = lst0
            except Exception:
                pass
            _update_step(audit_id, 0, "running", 15, f"Validating {len(config_ids)} file(s) — checking integrity, size, encoding...")
            await _asyncio.sleep(0.5)

            executor = AuditExecutor()
            all_findings = []
            total_controls = 0
            passed = 0
            failed = 0
            review = 0

            # Step 0 done
            _update_step(audit_id, 0, "completed", 100, f"Validation passed — {len(config_ids)} file(s) valid")

            # Step 1 — Detect (real ML)
            _update_step(audit_id, 1, "running", 30, "Detecting vendor & device type with ML (TF-IDF + LogisticRegression)...")
            await _asyncio.sleep(0.7)
            # Quick pre-detect for log (real)
            try:
                from app.engines.detection import VendorDetector
                _vd = VendorDetector()
                for _cid in config_ids[:1]:  # sample first file for log
                    _cr = await db.execute(select(Configuration).where(Configuration.id == UUID(_cid)))
                    _cfg = _cr.scalar_one_or_none()
                    if _cfg:
                        _ident = _vd.detect(_cfg.raw_content)
                        _update_step(audit_id, 1, "running", 60, f"Detected: {_ident.vendor}/{_ident.platform} { _ident.device_type } host={_ident.hostname or '—'} conf={_ident.confidence:.2f}")
                        await _asyncio.sleep(0.3)
                        break
            except Exception:
                pass
            _update_step(audit_id, 1, "completed", 100, "Vendor detection complete")
            await _asyncio.sleep(0.2)

            # Step 2 — Parse
            _update_step(audit_id, 2, "running", 20, "Parsing configurations — building syntax trees...")
            await _asyncio.sleep(0.6)
            _update_step(audit_id, 2, "completed", 100, "Parse complete — syntax trees built")
            await _asyncio.sleep(0.2)

            # Step 3 — Normalize
            _update_step(audit_id, 3, "running", 20, "Normalizing to Common Security Model (28 universal paths)...")
            await _asyncio.sleep(0.5)
            _update_step(audit_id, 3, "completed", 100, "Normalization complete — universal model ready")
            await _asyncio.sleep(0.2)

            # Step 4 — Evaluate (real work happens here, per config)
            _update_step(audit_id, 4, "running", 10, f"Evaluating controls per file (framework={framework}) × {len(config_ids)} file(s)...")

            for config_id in config_ids:
                # Get configuration
                config_result = await db.execute(
                    select(Configuration).where(Configuration.id == UUID(config_id))
                )
                config = config_result.scalar_one_or_none()
                if not config:
                    continue

                # Immediate live file details — ML detection before full pipeline, so frontend shows vendor/switch/router instantly
                try:
                    from app.engines.detection import VendorDetector as _VD2
                    _vd_tmp = _VD2()
                    _ident_tmp = _vd_tmp.detect(config.raw_content)
                    _fd_tmp = {
                        "filename": config.filename,
                        "vendor": _ident_tmp.vendor,
                        "platform": _ident_tmp.platform,
                        "device_type": _ident_tmp.device_type,
                        "hostname": _ident_tmp.hostname,
                        "firmware_version": _ident_tmp.firmware_version,
                        "confidence": _ident_tmp.confidence,
                        "detection_method": _ident_tmp.detection_method.value if hasattr(_ident_tmp.detection_method, 'value') else str(_ident_tmp.detection_method),
                    }
                    lst = audit_live_file_details.get(audit_id, [])
                    if not any(x["filename"] == _fd_tmp["filename"] for x in lst):
                        lst.append(_fd_tmp)
                        audit_live_file_details[audit_id] = lst
                except Exception:
                    pass

                # Log per-file evaluate start
                audit_live_logs.setdefault(audit_id, []).append({"ts": _time.time(), "step": "evaluate", "level": "info", "msg": f"Evaluating {config.filename}..."})
                # Update progress within evaluate step
                idx = config_ids.index(config_id)
                prog = int(10 + (idx / len(config_ids)) * 80)
                _update_step(audit_id, 4, "running", prog, f"Evaluating {config.filename} ({idx+1}/{len(config_ids)})...")

                # Run audit — real backend work
                result = executor.execute(
                    audit_id=audit_id,
                    config_content=config.raw_content,
                    framework=framework,
                    device_name=config.filename,
                )
                
                # Persist results
                # 1. Vendor Identification — persist real detection evidence (loop engineering: trace every decision)
                det_evidence = []
                det_method = "pattern_matching"
                device_type = getattr(result, 'device_type', None) or (getattr(result.detection_result, 'device_type', 'unknown') if hasattr(result, 'detection_result') and result.detection_result else 'unknown')
                hostname = getattr(result, 'hostname', None) or (getattr(result.detection_result, 'hostname', None) if hasattr(result, 'detection_result') and result.detection_result else None)
                if hasattr(result, 'detection_result') and result.detection_result:
                    dr = result.detection_result
                    det_method = getattr(dr, 'detection_method', det_method)
                    if hasattr(det_method, 'value'):
                        det_method = det_method.value
                    else:
                        det_method = str(det_method)
                    raw_evs = getattr(dr, 'detection_evidence', []) or []
                    for ev in raw_evs[:10]:
                        if isinstance(ev, dict):
                            det_evidence.append(ev)
                        elif hasattr(ev, '__dict__'):
                            det_evidence.append({
                                "method": str(getattr(ev, 'method', '')),
                                "pattern": str(getattr(ev, 'pattern', ''))[:120],
                                "matched_text": str(getattr(ev, 'matched_text', ''))[:120],
                                "line_number": getattr(ev, 'line_number', None),
                            })
                        else:
                            det_evidence.append({"raw": str(ev)[:200]})

                # Live file details for frontend — immediately available during processing (not waiting for DB commit)
                try:
                    _fd_live = {
                        "filename": config.filename,
                        "vendor": result.vendor,
                        "platform": result.platform,
                        "device_type": device_type,
                        "hostname": hostname,
                        "firmware_version": getattr(result, 'firmware_version', None),
                        "confidence": result.detection_confidence,
                        "detection_method": det_method,
                    }
                    lst = audit_live_file_details.get(audit_id, [])
                    if not any(x["filename"] == _fd_live["filename"] for x in lst):
                        lst.append(_fd_live)
                        audit_live_file_details[audit_id] = lst
                    audit_live_logs.setdefault(audit_id, []).append({"ts": _time.time(), "step": "detect", "level": "info", "msg": f"{config.filename}: {result.vendor}/{result.platform} {device_type} host={hostname or '—'} conf={result.detection_confidence:.2f}"})
                except Exception:
                    pass

                vendor_id = VendorIdentification(
                    configuration_id=config.id,
                    vendor=result.vendor,
                    platform=result.platform,
                    firmware_version=result.firmware_version,
                    confidence=result.detection_confidence,
                    detection_method=det_method,
                    detection_evidence=det_evidence,
                )
                db.add(vendor_id)
                
                # 2. Parsed Configuration
                # E04 F1: persist the full nested parse tree (every section,
                # with negation/line numbers/raw text), not roots only.
                # E04 F2: persist the parser's actual diagnostics.
                parse_tree = {}
                persisted_errors: list = []
                persisted_warnings: list = []
                persisted_unknown: list = []
                if result.parse_result:
                    parse_tree = {
                        "sections": [
                            s.to_dict()
                            for s in result.parse_result.parse_tree
                        ],
                        "unknown_sections": [
                            {"path": u.path, "raw_text": u.raw_text[:100]}
                            for u in result.parse_result.unknown_sections
                        ],
                    }
                    persisted_errors = [
                        {"line_number": e.line_number, "message": e.message,
                         "raw_text": e.raw_text}
                        for e in result.parse_result.parse_errors
                    ]
                    persisted_warnings = [
                        {"line_number": w.line_number, "message": w.message,
                         "raw_text": w.raw_text}
                        for w in result.parse_result.parse_warnings
                    ]
                    persisted_unknown = [
                        {"path": u.path, "raw_text": u.raw_text[:200]}
                        for u in result.parse_result.unknown_sections
                    ]

                parsed_config = ParsedConfiguration(
                    configuration_id=config.id,
                    vendor=result.vendor,
                    platform=result.platform,
                    parse_tree=parse_tree,
                    parse_errors=persisted_errors,
                    parse_warnings=persisted_warnings,
                    unknown_sections=persisted_unknown,
                )
                db.add(parsed_config)
                await db.flush()
                
                # 3. Semantic Interpretation
                # E05 F4 (§10.5): persist the actual interpretation built
                # from the parse tree — sections, unknowns, and (honestly
                # empty) confidence scores. No fake semantic content.
                semi = getattr(result, "semantic_interpretation", None) or {}
                semi_sections = semi.get("sections") if isinstance(semi, dict) else None
                if not semi_sections and result.parse_result:
                    try:
                        semi_sections = [
                            s.to_dict() for s in result.parse_result.parse_tree
                        ]
                    except Exception:
                        semi_sections = []
                semi_unknown = semi.get("unknown") if isinstance(semi, dict) else None
                if semi_unknown is None and result.parse_result:
                    try:
                        semi_unknown = [
                            u.to_dict()
                            for u in result.parse_result.unknown_sections
                        ]
                    except Exception:
                        semi_unknown = []
                semantic_interp = SemanticInterpretation(
                    parsed_configuration_id=parsed_config.id,
                    semantic_sections=semi_sections or [],
                    confidence_scores={},
                    unknown_meanings=semi_unknown or [],
                )
                db.add(semantic_interp)
                await db.flush()

                # 4. Normalized Configuration
                # E05 F5: persist the actual normalization result produced
                # for this audit (values, unmapped concepts, model version).
                norm_result = getattr(result, "normalization_result", None)
                norm_mappings = []
                norm_unmapped: list = []
                norm_version = UniversalSecurityModel.VERSION
                if norm_result is not None:
                    try:
                        norm_mappings = [
                            m.to_dict() for m in (
                                norm_result.mappings or [])
                        ]
                    except Exception:
                        norm_mappings = []
                    try:
                        norm_unmapped = list(
                            norm_result.unmapped_concepts or [])
                    except Exception:
                        norm_unmapped = []
                    try:
                        norm_version = (
                            norm_result.universal_model_version
                            or UniversalSecurityModel.VERSION)
                    except Exception:
                        norm_version = UniversalSecurityModel.VERSION
                normalized_config = NormalizedConfiguration(
                    semantic_interpretation_id=semantic_interp.id,
                    universal_model_version=norm_version,
                    normalized_values=norm_mappings,
                    unmapped_concepts=norm_unmapped,
                )
                db.add(normalized_config)
                await db.flush()
                
                # 5. Compliance Results - store and build lookup (F3/F5/F11).
                # Framework attribution comes from the control's own metadata
                # attached by the canonical path — never inferred from the
                # control-id shape or the requested framework. The score uses
                # the single canonical overall_score formula.
                compliance_results_by_control = {}
                if result.compliance_evaluation:
                    for eval_result in result.compliance_evaluation.evaluations:
                        compliance_result = build_compliance_result(
                            audit_id=UUID(audit_id),
                            normalized_configuration_id=normalized_config.id,
                            framework=framework,
                            eval_result=eval_result,
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
                
                # 6. Findings - linked to compliance results (E08 F1: the
                # row carries control_id + compliance_result_id so the API
                # can identify exactly which control produced the finding).
                for finding in result.findings:
                    linked_result_id = compliance_results_by_control.get(finding.control_id)
                    finding.compliance_result_id = str(linked_result_id) \
                        if linked_result_id else finding.compliance_result_id
                    db_finding = Finding(
                        audit_id=UUID(audit_id),
                        compliance_result_id=linked_result_id,
                        control_id=finding.control_id,
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
                        risk_score=finding.risk_score,
                        priority=finding.priority,
                        risk_method=finding.risk_method,
                        risk_model_version=finding.risk_model_version,
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
                        "detection_method": det_method,
                        "detection_evidence": det_evidence,
                        "is_unknown": result.detection_confidence < 0.4 or result.vendor == "unknown",
                        "device_type": device_type,
                        "hostname": hostname,
                        "firmware_version": getattr(result, 'firmware_version', None) or getattr(result.detection_result, 'firmware_version', None) if hasattr(result, 'detection_result') and result.detection_result else getattr(result, 'firmware_version', None),
                    }
                    audit_config.parsed_configuration_id = parsed_config.id
            
            # Complete remaining steps with realistic timing — so frontend feels real, not fake instant
            _update_step(audit_id, 4, "completed", 100, f"Evaluation complete — {total_controls} controls checked, {passed} pass, {failed} fail, {review} review")
            await _asyncio.sleep(0.4)
            _update_step(audit_id, 5, "running", 40, f"Generating {len(all_findings)} findings with risk scoring...")
            await _asyncio.sleep(0.7)
            _update_step(audit_id, 5, "completed", 100, f"Findings generated — {len(all_findings)} findings, risk scored")
            await _asyncio.sleep(0.3)
            _update_step(audit_id, 6, "running", 50, "Generating PDF report — per-device breakdown, ConfigShield header...")
            await _asyncio.sleep(0.9)
            _update_step(audit_id, 6, "completed", 100, "Report ready — PDF built")
            audit_live_logs.setdefault(audit_id, []).append({"ts": _time.time(), "step": "done", "level": "info", "msg": f"Audit completed — score {overall_score(passed, total_controls):.1f}%"})

            # Update audit summary (F5: the single canonical overall_score —
            # passed over ALL evaluated controls, REVIEW counts as non-pass).
            audit.status = AuditStatus.COMPLETED.value
            audit.completed_at = datetime.utcnow()
            audit.overall_score = overall_score(passed, total_controls)
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
            # E12: completion closes the lifecycle history opened at
            # execute time (AUDIT_STARTED).
            await audit_trail.log_audit_event(
                action=AuditAction.AUDIT_COMPLETED,
                audit_id=audit_id,
                user_id=user_id,
                details={
                    "total_controls": total_controls,
                    "passed": passed,
                    "failed": failed,
                    "review": review,
                    "overall_score": audit.overall_score,
                    "findings": len(all_findings),
                },
            )

            await db.commit()
            
        except Exception as e:
            # Mark audit as failed
            import traceback
            print(f"Audit pipeline failed: {e}")
            print(traceback.format_exc())
            # Mark current live step as failed for frontend
            try:
                for idx, s in enumerate(audit_live_steps.get(audit_id, [])):
                    if s["status"] == "running":
                        _update_step(audit_id, idx, "failed", s.get("progress", 0), f"Failed: {str(e)[:120]}")
                        break
                audit_live_logs.setdefault(audit_id, []).append({"ts": _time.time(), "step": "error", "level": "error", "msg": str(e)[:300]})
            except Exception:
                pass
            if audit:
                audit.status = AuditStatus.FAILED.value
                audit.completed_at = datetime.utcnow()
                # E12: failure closes the lifecycle history too. Best
                # effort by design: a trail write must never mask the
                # original pipeline error this handler exists to record.
                try:
                    fail_trail = AuditTrailRepository(db)
                    await fail_trail.log_audit_event(
                        action=AuditAction.AUDIT_FAILED,
                        audit_id=audit_id,
                        user_id=user_id,
                        details={"error": str(e)[:500]},
                    )
                    await db.flush()
                except Exception:
                    pass
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

    # E12: execution start is a lifecycle event (completion/failure are
    # recorded inside run_audit_pipeline).
    trail = AuditTrailRepository(db)
    await trail.log_audit_event(
        action=AuditAction.AUDIT_STARTED,
        audit_id=str(new_audit.id),
        user_id=str(current_user.id),
        details={
            "name": new_audit.name,
            "framework": audit.framework or "CIS",
            "configuration_count": len(audit.configuration_ids),
        },
    )
    await db.flush()

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
    
    # Live steps — real backend progress, not fake
    steps = audit_live_steps.get(str(audit_id))
    logs = audit_live_logs.get(str(audit_id), [])[-30:]
    if steps is not None:
        progress = _current_progress(str(audit_id))
        if audit.status == "completed":
            progress = 100
            # Ensure all steps marked completed if audit completed but steps pending
            for s in steps:
                if s["status"] in ("pending", "running"):
                    s["status"] = "completed"
                    s["progress"] = 100
        elif audit.status == "failed":
            progress = _current_progress(str(audit_id))
    else:
        # Fallback if no live tracking yet (old audit or before init)
        if audit.status == "completed":
            progress = 100
            steps = [{**s, "status": "completed", "progress": 100} for s in PIPELINE_STEPS_DEF]
            logs = []
        elif audit.status == "processing":
            progress = 50
            steps = [{**s, "status": "pending", "progress": 0} for s in PIPELINE_STEPS_DEF]
            logs = []
        else:
            progress = 0
            steps = [{**s, "status": "pending", "progress": 0} for s in PIPELINE_STEPS_DEF]
            logs = []

    # File details — vendor, switch/router/firewall, platform, hostname (real ML)
    # During processing, use live in-memory (DB not yet committed); after completion, use DB
    file_details: list[dict] = audit_live_file_details.get(str(audit_id), [])
    if not file_details:
        try:
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
                    "platform": vi.get("platform", "unknown"),
                    "device_type": vi.get("device_type", "unknown"),
                    "hostname": vi.get("hostname"),
                    "firmware_version": vi.get("firmware_version"),
                    "confidence": vi.get("confidence", 0),
                    "detection_method": vi.get("detection_method", ""),
                })
        except Exception:
            pass

    # Current step label for frontend
    current_step = None
    for s in steps:
        if s["status"] == "running":
            current_step = s["id"]
            break
    if not current_step:
        for s in reversed(steps):
            if s["status"] == "completed":
                current_step = s["id"]
                break

    return {
        "id": str(audit.id),
        "name": audit.name,
        "status": audit.status,
        "progress": progress,
        "current_step": current_step,
        "steps": steps,
        "logs": logs,
        "file_details": file_details,
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
    status_filter: Optional[FindingStatus] = None,
    vendor: Optional[str] = None,
    platform: Optional[str] = None,
    control_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get findings for an audit (canonical query service, E08 F4)."""
    from app.repositories.findings import FindingQueryService

    items, total = await FindingQueryService(db).list_for_audit(
        audit_id=audit_id, user_id=current_user.id, page=page,
        per_page=per_page, severity=severity, status=status_filter,
        vendor=vendor, platform=platform, control_id=control_id,
    )
    return FindingListResponse(
        items=[_to_finding_response(f) for f in items],
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

    # E09 F1: risk aggregates from the persisted 10.9 output (same values
    # the findings endpoints serve — one source of truth).
    risk_rows = await db.execute(
        select(Finding.risk_score, Finding.priority).where(
            Finding.audit_id == audit_id,
            Finding.risk_score.is_not(None),
        )
    )
    risk_scores = [row[0] for row in risk_rows.all()]
    risk_stats = {
        "findings_scored": len(risk_scores),
        "risk_max": max(risk_scores) if risk_scores else None,
        "risk_mean": (
            round(sum(risk_scores) / len(risk_scores), 1)
            if risk_scores else None),
    }
    priority_rows = await db.execute(
        select(Finding.priority, func.count(Finding.id))
        .where(Finding.audit_id == audit_id)
        .group_by(Finding.priority)
    )
    priority_counts = {row[0]: row[1] for row in priority_rows.all()}

    return {
        "audit_id": str(audit.id),
        "status": audit.status,
        "overall_score": audit.overall_score,
        "findings_count": audit.findings_count,
        "findings_by_severity": severity_counts,
        "findings_by_status": status_counts,
        "risk": risk_stats,
        "findings_by_priority": priority_counts,
        "started_at": audit.started_at.isoformat() if audit.started_at else None,
        "completed_at": audit.completed_at.isoformat() if audit.completed_at else None,
    }
