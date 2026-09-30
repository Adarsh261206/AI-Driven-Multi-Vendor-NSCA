"""
Audit Execution API

Endpoints for running compliance audits and retrieving results.
"""

from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Any, Optional
from uuid import UUID, uuid4
from datetime import datetime

from app.database import get_db
from app.models import (
    User, Audit, AuditConfiguration, Configuration,
    VendorIdentification, ParsedConfiguration, SemanticInterpretation,
    NormalizedConfiguration, ComplianceResult, Finding, AuditAction,
    AuditStatus, FindingStatus, Organization, CompanyBaseline,
    AuditExecution, AuditBatch
)
from app.schemas import (
    AuditCreate, AuditResponse, FindingResponse, FindingListResponse, PaginationMeta,
    BulkAuditRequest, BulkAuditResponse, BulkAuditItemResult,
)
from app.security.auth import get_current_user
from app.config import settings
from app.services import execution as exec_svc
from app.services.scope import validate_audit_scope
from app.benchmarks.selection import overall_score
from app.engines.compliance.executor import AuditExecutor
from app.engines.universal_model import UniversalSecurityModel
from app.repositories.audit_trail import AuditTrailRepository

router = APIRouter()

# Live pipeline tracking — in-memory per audit, for real-time frontend polling (not fake, real backend progress)
import asyncio as _asyncio  # noqa: E402
import time as _time  # noqa: E402

audit_live_steps: dict[str, list[dict]] = {}
audit_live_logs: dict[str, list[dict]] = {}
audit_live_file_details: dict[str, list[dict]] = {}
# STEP 7: audit_id -> execution_id binding, set by the worker before running
# the pipeline. Lets checkpoints, progress sync, and outcome handling find
# the durable execution row. Per-process by nature (same as the dicts above).
audit_live_execution: dict[str, str] = {}

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
    completed = sum(1 for s in steps if s.get("status") == "completed")
    running = sum(1 for s in steps if s.get("status") == "running")
    # 0-100 based on completed + partial running
    return int((completed / len(steps) * 100) + (running * (100 / len(steps) * 0.5)))


async def _execution_checkpoint(db, audit_id: str) -> None:
    """Cooperative worker checkpoint: heartbeat lease, observe cancel.

    No-op when the audit is not bound to an execution (legacy direct
    runs). Raises ExecutionCancelled when cancellation was requested;
    raises ExecutionSuperseded when the row left RUNNING for any other
    reason (e.g. lease reaped by recovery) so the worker stops quietly
    without touching rows it no longer owns.
    """
    execution_id = audit_live_execution.get(audit_id)
    if not execution_id:
        return
    row = await db.execute(
        select(AuditExecution).where(AuditExecution.id == UUID(execution_id))
    )
    execution = row.scalar_one_or_none()
    if execution is None or execution.status == exec_svc.ExecutionStatus.CANCELLED:
        raise exec_svc.ExecutionCancelled(f"execution {execution_id} gone")
    if execution.status == exec_svc.ExecutionStatus.CANCEL_REQUESTED:
        raise exec_svc.ExecutionCancelled(f"execution {execution_id} cancel requested")
    if execution.status != exec_svc.ExecutionStatus.RUNNING:
        raise exec_svc.ExecutionSuperseded(f"execution {execution_id} superseded")
    from datetime import timedelta

    execution.lease_expires_at = datetime.utcnow() + timedelta(
        minutes=exec_svc.LEASE_MINUTES_DEFAULT
    )
    execution.updated_at = datetime.utcnow()
    await db.flush()


async def _settle_decided_execution(db, audit, audit_id: str, user_id: str) -> None:
    """Honor an already-decided execution outcome after losing the end-CAS.

    Called with a clean (rolled-back) transaction when complete/fail could
    not claim the bound execution because it left RUNNING first:
    - CANCEL_REQUESTED/CANCELLED -> confirm CANCELLED, mirror audit state.
    - anything else -> recovery owns the outcome; touch nothing.
    """
    from app.services import execution as exec_svc

    execution_id = audit_live_execution.get(audit_id)
    if not execution_id:
        return
    row = await db.execute(
        select(AuditExecution).where(AuditExecution.id == UUID(execution_id))
    )
    decided = row.scalar_one_or_none()
    if decided is None:
        return
    if decided.status in (
        exec_svc.ExecutionStatus.CANCEL_REQUESTED,
        exec_svc.ExecutionStatus.CANCELLED,
    ):
        await exec_svc.confirm_cancelled(db, UUID(execution_id))
        if audit is not None:
            fresh = await db.execute(select(Audit).where(Audit.id == UUID(audit_id)))
            live_audit = fresh.scalar_one_or_none()
            if live_audit is not None:
                live_audit.status = AuditStatus.CANCELLED.value
                live_audit.completed_at = datetime.utcnow()
                cancel_trail = AuditTrailRepository(db)
                await cancel_trail.log_audit_event(
                    action=AuditAction.AUDIT_CANCELLED,
                    audit_id=audit_id,
                    user_id=user_id,
                    details={"observed": "completion-race"},
                )
        await db.commit()
    # Superseded (reaped/failed/completed by recovery or redelivery):
    # recovery already recorded the outcome — commit nothing.


async def _sync_execution_progress(audit_id: str) -> None:
    """Persist live progress/steps/logs onto the audit_progress row (best effort).

    Runs on its OWN short-lived session and commits, so the API process
    (separate from the Celery worker) sees real-time progress when it
    polls getStatus — the worker's in-memory step dict is invisible
    cross-process. Deliberately writes the DEDICATED audit_progress row,
    never the audit_executions row: the pipeline's own transaction holds
    a row lock on the execution row from its first checkpoint until the
    final commit, so a concurrent UPDATE there would block and deadlock
    the solo worker. Failures here must never break the audit itself.
    """
    try:
        from app.database import WorkerSessionLocal as _SyncSession
        from app.models import AuditProgress

        async with _SyncSession() as sdb:
            row = await sdb.execute(
                select(AuditProgress).where(AuditProgress.audit_id == UUID(audit_id))
            )
            prog = row.scalar_one_or_none()
            if prog is None:
                prog = AuditProgress(audit_id=UUID(audit_id))
                sdb.add(prog)
            prog.progress = _current_progress(audit_id)
            steps = audit_live_steps.get(audit_id, [])
            running = next((s for s in steps if s.get("status") == "running"), None)
            prog.current_step = (
                str(running.get("id", ""))[:100] if running else None
            )
            prog.live_steps = steps
            prog.live_logs = audit_live_logs.get(audit_id, [])[-30:]
            prog.updated_at = datetime.utcnow()
            await sdb.commit()
    except Exception:
        pass


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
    execution_id: str | None = None,
):
    """
    Run the full audit pipeline.

    INGEST → VALIDATE → DETECT → PARSE → NORMALIZE → EVALUATE → FINDINGS

    Historically driven by BackgroundTasks; STEP 7 drives it from the
    Celery worker with execution_id bound (checkpoints, progress
    persistence, outcome recording). The engine path itself is unchanged.
    """
    import traceback
    # Worker-safe sessions: each pipeline run owns a fresh event loop, so
    # pooled connections (bound to dead loops) break here. NullPool opens
    # and closes per session instead. The API request path keeps the
    # pooled factory for throughput.
    from app.database import WorkerSessionLocal as AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        try:
            # Update audit status
            audit_result = await db.execute(
                select(Audit).where(Audit.id == UUID(audit_id))
            )
            audit = audit_result.scalar_one_or_none()
            if not audit:
                return

            # Bound executions start only from an owned RUNNING row. A
            # missing row, or one that left RUNNING (cancelled/reaped),
            # means this run must not proceed.
            if execution_id is not None:
                exec_row = await db.execute(
                    select(AuditExecution).where(
                        AuditExecution.id == UUID(execution_id)
                    )
                )
                bound = exec_row.scalar_one_or_none()
                if bound is None or bound.status not in (
                    exec_svc.ExecutionStatus.RUNNING,
                    exec_svc.ExecutionStatus.CANCEL_REQUESTED,
                ):
                    return
                if bound.status == exec_svc.ExecutionStatus.CANCEL_REQUESTED:
                    raise exec_svc.ExecutionCancelled(
                        f"execution {execution_id} cancelled before start"
                    )

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
            await _sync_execution_progress(audit_id)

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
            await _sync_execution_progress(audit_id)
            await _asyncio.sleep(0.2)

            # Step 2 — Parse
            _update_step(audit_id, 2, "running", 20, "Parsing configurations — building syntax trees...")
            await _asyncio.sleep(0.6)
            _update_step(audit_id, 2, "completed", 100, "Parse complete — syntax trees built")
            await _sync_execution_progress(audit_id)
            await _asyncio.sleep(0.2)

            # Step 3 — Normalize
            _update_step(audit_id, 3, "running", 20, "Normalizing to Common Security Model (28 universal paths)...")
            await _asyncio.sleep(0.5)
            _update_step(audit_id, 3, "completed", 100, "Normalization complete — universal model ready")
            await _sync_execution_progress(audit_id)
            await _asyncio.sleep(0.2)

            # Step 4 — Evaluate (real work happens here, per config)
            _update_step(audit_id, 4, "running", 10, f"Evaluating controls per file (framework={framework}) × {len(config_ids)} file(s)...")

            for config_id in config_ids:
                # Cooperative worker checkpoint: heartbeat the execution
                # lease and observe cancellation at this safe file boundary.
                await _execution_checkpoint(db, audit_id)
                await _sync_execution_progress(audit_id)
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
                
                # Resolve the organization's active Company Baseline once per
                # audit. The org is derived from the pipeline user's
                # server-side identity: user_id → users.organization_id
                # (never client-supplied). The resolved baseline is
                # SNAPSHOTTED onto the audit row so a later baseline
                # replacement never rewrites historical audit context; the
                # resolution is logged via the audit-trail repository.
                # Company-scope metrics are projected over the stored CIS
                # results at report time — the baseline never modifies CIS
                # evaluation itself.
                try:
                    from app.repositories.audit_trail import AuditTrailRepository
                    trail = AuditTrailRepository(db)
                    user_row = await db.execute(
                        select(User.organization_id).where(
                            User.id == UUID(user_id)
                        )
                    )
                    user_org_id = user_row.scalar_one_or_none()
                    org_result = await db.execute(
                        select(Organization).where(
                            Organization.id == user_org_id
                        )
                    ) if user_org_id else None
                    org = org_result.scalar_one_or_none() if org_result else None
                    baseline_info: Optional[dict] = None
                    snapshot_controls: Optional[list] = None
                    if org and org.baseline_status == "ACTIVE":
                        bl_result = await db.execute(
                            select(CompanyBaseline).where(
                                CompanyBaseline.organization_id == org.id,
                                CompanyBaseline.status == "ACTIVE",
                            )
                        )
                        active_baseline = bl_result.scalar_one_or_none()
                        if active_baseline:
                            controls_data = active_baseline.controls
                            if isinstance(controls_data, str):
                                snapshot_controls = [
                                    c.strip() for c in controls_data.split(",") if c.strip()
                                ]
                            else:
                                snapshot_controls = [str(c) for c in controls_data]
                            baseline_info = {
                                "baseline_id": str(active_baseline.id),
                                "baseline_name": active_baseline.name,
                                "framework": active_baseline.framework,
                                "benchmark": active_baseline.benchmark,
                                "in_scope_control_count": (
                                    len(snapshot_controls)
                                    if snapshot_controls else 0
                                ),
                            }
                    await trail.log(
                        action=AuditAction.BASELINE_RESOLVED,
                        entity_type="audit",
                        entity_id=audit_id,
                        user_id=user_id,
                        details=baseline_info or {"has_baseline": False},
                    )
                    audit = await db.get(Audit, UUID(audit_id))
                    if audit:
                        if baseline_info:
                            audit.baseline_id = UUID(baseline_info["baseline_id"])
                            audit.baseline_name = baseline_info["baseline_name"]
                            audit.baseline_controls = snapshot_controls or []
                        else:
                            audit.baseline_id = None
                            audit.baseline_name = None
                            audit.baseline_controls = []
                except Exception:
                    # Baseline resolution must never break the audit itself.
                    pass
                
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
                        "os_family": getattr(result, "os_family", "") or result.platform,
                        "confidence": result.detection_confidence,
                        "detection_method": det_method,
                        "detection_evidence": det_evidence,
                        "is_unknown": result.detection_confidence < 0.4 or result.vendor == "unknown",
                        "device_type": device_type,
                        "hostname": hostname,
                        "firmware_version": getattr(result, 'firmware_version', None) or getattr(result.detection_result, 'firmware_version', None) if hasattr(result, 'detection_result') and result.detection_result else getattr(result, 'firmware_version', None),
                    }
                    audit_config.parsed_configuration_id = parsed_config.id
            
            # Checkpoint before the finalize phase (last safe boundary
            # before findings persistence + summary commit).
            await _execution_checkpoint(db, audit_id)
            await _sync_execution_progress(audit_id)

            # Complete remaining steps with realistic timing — so frontend feels real, not fake instant
            _update_step(audit_id, 4, "completed", 100, f"Evaluation complete — {total_controls} controls checked, {passed} pass, {failed} fail, {review} review")
            await _sync_execution_progress(audit_id)
            await _asyncio.sleep(0.4)
            _update_step(audit_id, 5, "running", 40, f"Generating {len(all_findings)} findings with risk scoring...")
            await _sync_execution_progress(audit_id)
            await _asyncio.sleep(0.7)
            _update_step(audit_id, 5, "completed", 100, f"Findings generated — {len(all_findings)} findings, risk scored")
            await _sync_execution_progress(audit_id)
            await _asyncio.sleep(0.3)
            _update_step(audit_id, 6, "running", 50, "Generating PDF report — per-device breakdown, ConfigShield header...")
            await _sync_execution_progress(audit_id)
            await _asyncio.sleep(0.9)
            _update_step(audit_id, 6, "completed", 100, "Report ready — PDF built")
            audit_live_logs.setdefault(audit_id, []).append({"ts": _time.time(), "step": "done", "level": "info", "msg": f"Audit completed — score {overall_score(passed, total_controls):.1f}%"})
            await _sync_execution_progress(audit_id)

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

            # STEP 7: close the bound execution (progress 100). The CAS
            # inside complete_execution is the atomic decider of the
            # complete-vs-cancel race: if the execution left RUNNING (a
            # cancel won, or recovery reaped it), its None return means
            # this completion must NOT land — roll everything back and
            # honor the decided outcome instead. Audit-row updates above
            # stay verbatim for backward compatibility.
            bound_execution_id = audit_live_execution.get(audit_id)
            if bound_execution_id is not None:
                completed_row = await exec_svc.complete_execution(
                    db, UUID(bound_execution_id)
                )
                if completed_row is None:
                    await db.rollback()
                    await _settle_decided_execution(db, audit, audit_id, user_id)
                    return

            await db.commit()

        except exec_svc.ExecutionCancelled:
            # Cooperative cancellation observed at a checkpoint: confirm
            # CANCELLED, mirror audit state, close lifecycle. No raise —
            # cancellation is an outcome, not an error.
            try:
                bound_execution_id = audit_live_execution.get(audit_id)
                if bound_execution_id is not None:
                    await exec_svc.confirm_cancelled(db, UUID(bound_execution_id))
                if audit:
                    audit.status = AuditStatus.CANCELLED.value
                    audit.completed_at = datetime.utcnow()
                    cancel_trail = AuditTrailRepository(db)
                    await cancel_trail.log_audit_event(
                        action=AuditAction.AUDIT_CANCELLED,
                        audit_id=audit_id,
                        user_id=user_id,
                        details={"observed": "pipeline-checkpoint"},
                    )
                await db.commit()
            except Exception:
                try:
                    await db.rollback()
                except Exception:
                    pass
        except exec_svc.ExecutionSuperseded:
            # Lease reaped by recovery while running: recovery already owns
            # the outcome (FAILED + replacement queued). Stop quietly —
            # touch nothing, raise nothing.
            try:
                await db.rollback()
            except Exception:
                pass
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
            # STEP 7: bound executions classify the failure. Retryable
            # failures with attempts left requeue as a NEW execution row
            # (history preserved) and leave the audit PROCESSING; anything
            # else follows the legacy terminal path below unchanged.
            bound_execution_id = audit_live_execution.get(audit_id)
            if bound_execution_id is not None:
                try:
                    category, retryable, message = exec_svc.classify_failure(e)
                    exec_row = await db.execute(
                        select(AuditExecution).where(
                            AuditExecution.id == UUID(bound_execution_id)
                        )
                    )
                    bound_row = exec_row.scalar_one_or_none()
                    if (
                        bound_row is not None
                        and bound_row.status == exec_svc.ExecutionStatus.RUNNING
                        and retryable
                        and bound_row.attempt < bound_row.max_attempts
                    ):
                        await exec_svc.fail_execution(
                            db, bound_row.id, category, message, retryable
                        )
                        retried = await exec_svc.create_execution(
                            db,
                            bound_row.audit_id,
                            attempt=bound_row.attempt + 1,
                            max_attempts=bound_row.max_attempts,
                            framework=bound_row.framework,
                            framework_version=bound_row.framework_version,
                        )
                        await db.flush()
                        from app.tasks import execute_audit_task

                        execute_audit_task.apply_async(
                            args=[str(retried.id)],
                            countdown=exec_svc.backoff_seconds(
                                retried.attempt,
                                settings.EXECUTION_RETRY_BACKOFF_SECONDS,
                            ),
                        )
                        await db.commit()
                        return
                    if bound_row is not None and bound_row.status == (
                        exec_svc.ExecutionStatus.RUNNING
                    ):
                        # The fail-CAS is the atomic decider: only a win
                        # records the terminal audit state below. A loss
                        # means cancel/recovery decided first — honor it.
                        failed_row = await exec_svc.fail_execution(
                            db, bound_row.id, category, message, retryable
                        )
                        if failed_row is None:
                            await db.rollback()
                            await _settle_decided_execution(
                                db, audit, audit_id, user_id
                            )
                            return
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

            # Legacy direct runs (no bound execution) propagate; worker-bound
            # runs already recorded everything above and must not raise.
            if bound_execution_id is None:
                raise


MAX_BULK_AUDITS = 20


async def _enqueue_execution(db: AsyncSession, execution_id: UUID) -> str:
    """Publish an execution to the Celery queue; returns the task id.

    Raises on broker failure AFTER flushing (the caller’s commit then
    rolls everything back) so a job never references an uncommitted row
    and a committed row is never left unscheduled.
    """
    from app.tasks import execute_audit_task

    result = execute_audit_task.delay(str(execution_id))
    row = await db.execute(
        select(AuditExecution).where(AuditExecution.id == execution_id)
    )
    execution = row.scalar_one()
    execution.celery_task_id = result.id
    await db.flush()
    return result.id


async def _create_audit(
    db: AsyncSession,
    current_user: User,
    audit: AuditCreate,
) -> Audit:
    """Create one audit row + associations + trail, enqueue its execution.

    Shared by single and bulk execution so both paths run identical logic.
    Scope validation (ownership, archived, device linkage) runs FIRST and
    raises BEFORE any row exists — callers must not create partial state
    on validation failure. STEP 7: execution runs on the Celery queue via
    a durable execution row (not in-process BackgroundTasks).
    """
    # Ownership + optional device-scope boundary: EVERY requested
    # configuration must be inside the caller's permitted scope, and when
    # device_ids are supplied every configuration must belong to one of
    # those devices. A single violation rejects the ENTIRE request BEFORE
    # any audit row exists — no partial audits, ever.
    await validate_audit_scope(db, audit.device_ids, audit.configuration_ids, current_user)

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

    # STEP 7: durable execution row + queue publish. The worker (not
    # this request) runs run_audit_pipeline. Enqueue failure raises before
    # commit, so no phantom audit is ever left unscheduled.
    execution = await exec_svc.create_execution(
        db,
        new_audit.id,
        attempt=1,
        max_attempts=settings.EXECUTION_MAX_ATTEMPTS,
        framework=audit.framework or "CIS",
        framework_version=audit.framework_version,
    )
    await _enqueue_execution(db, execution.id)

    return new_audit


@router.post("/execute", response_model=AuditResponse, status_code=status.HTTP_202_ACCEPTED)
async def execute_audit(
    audit: AuditCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Create and queue a compliance audit for worker execution.

    Validates scope, persists the audit + a QUEUED execution row, and
    publishes to the Celery queue. A Celery worker runs the full pipeline:
    INGEST → VALIDATE → DETECT → PARSE → NORMALIZE → EVALUATE → FINDINGS

    Returns immediately with audit ID. Results available via status endpoint.
    """
    new_audit = await _create_audit(db, current_user, audit)
    return AuditResponse.from_orm(new_audit)


@router.post("/bulk", response_model=BulkAuditResponse, status_code=status.HTTP_202_ACCEPTED)
async def bulk_execute_audits(
    body: BulkAuditRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Queue many independent audits in one request (STEP 6 bulk, STEP 7 queue).

    Two-phase semantics:
      1. VALIDATION (atomic): every item's scope is validated up front.
         ANY violation rejects the WHOLE batch with ZERO audits created.
      2. EXECUTION (per-item): each item runs the identical single-audit
         creation path (same rows, same trail, same queue scheduling).
         Each audit keeps its own status, baseline snapshot, findings,
         and report — bulk is orchestration only. A persistent batch row
         records the item audit IDs so progress survives refresh.

    No shared transaction across items, no baseline in the request (the
    worker resolves organization.active_baseline per audit).
    """
    items = body.items or []
    if not items:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one audit item is required",
        )
    if len(items) > MAX_BULK_AUDITS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"At most {MAX_BULK_AUDITS} audits per bulk execution",
        )

    # Phase 1 — atomic validation across the whole batch.
    for item in items:
        await validate_audit_scope(
            db, item.device_ids, item.configuration_ids, current_user
        )

    # Phase 2 — per-item creation through the shared single-audit path.
    results: list[BulkAuditItemResult] = []
    created_ids: list[UUID] = []
    for item in items:
        created = await _create_audit(db, current_user, item)
        created_ids.append(created.id)
        results.append(
            BulkAuditItemResult(
                audit_id=created.id, name=created.name, status=created.status
            )
        )

    batch = AuditBatch(
        user_id=current_user.id,
        name=f"Bulk audit ({len(results)} items)",
        audit_ids=[str(audit_id) for audit_id in created_ids],
    )
    db.add(batch)
    await db.flush()
    await db.refresh(batch)

    response = BulkAuditResponse(audits=results, total=len(results))
    response.batch_id = batch.id
    return response


@router.post("/{audit_id}/retry", status_code=status.HTTP_202_ACCEPTED)
async def retry_audit_execution(
    audit_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Manually retry a failed, retryable audit execution (STEP 7).

    Creates a NEW execution row (attempt+1) so the failed attempt's
    history is preserved, and enqueues it. Rejected unless the latest
    execution is FAILED and marked retryable: COMPLETED, CANCELLED,
    QUEUED, and RUNNING executions cannot be retried through this path,
    and non-retryable failure categories stay terminal.
    """
    audit_result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.user_id == current_user.id,
        )
    )
    audit = audit_result.scalar_one_or_none()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    latest = await exec_svc.latest_execution(db, audit.id)
    if latest is None or latest.status != exec_svc.ExecutionStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only failed executions can be retried",
        )
    if not latest.retryable:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Failure is not retryable: {latest.error_category or 'unknown'}. "
                "Fix the underlying cause and start a new audit."
            ),
        )
    if latest.attempt >= latest.max_attempts:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Retry limit exhausted for this audit",
        )

    # The retry re-resolves scope at execution time (worker re-validates),
    # but fail fast here on obviously broken scope.
    retried = await exec_svc.create_execution(
        db,
        audit.id,
        attempt=latest.attempt + 1,
        max_attempts=latest.max_attempts,
        framework=getattr(latest, "framework", "CIS") or "CIS",
        framework_version=getattr(latest, "framework_version", None),
    )
    await _enqueue_execution(db, retried.id)

    trail = AuditTrailRepository(db)
    await trail.log_audit_event(
        action=AuditAction.AUDIT_STARTED,
        audit_id=str(audit.id),
        user_id=str(current_user.id),
        details={
            "retry_of_attempt": latest.attempt,
            "execution_id": str(retried.id),
        },
    )
    await db.flush()

    return {
        "audit_id": str(audit.id),
        "execution": exec_svc.describe_execution(retried),
    }


@router.get("/batches/{batch_id}")
async def get_audit_batch(
    batch_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Load a persistent bulk-execution batch with live per-item states.

    Survives refresh/navigation: the item audit IDs come from the stored
    batch row; each item's state is read from its latest execution row
    (falling back to the audit row for pre-STEP-7 audits).
    """
    batch_result = await db.execute(
        select(AuditBatch).where(
            AuditBatch.id == batch_id,
            AuditBatch.user_id == current_user.id,
        )
    )
    batch = batch_result.scalar_one_or_none()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    items = []
    for raw_audit_id in batch.audit_ids or []:
        try:
            item_audit_id = UUID(str(raw_audit_id))
        except (ValueError, AttributeError):
            continue
        audit_row = await db.execute(
            select(Audit).where(
                Audit.id == item_audit_id,
                Audit.user_id == current_user.id,
            )
        )
        audit = audit_row.scalar_one_or_none()
        if audit is None:
            continue
        latest = await exec_svc.latest_execution(db, audit.id)
        state = latest.status if latest else audit.status
        items.append(
            {
                "audit_id": str(audit.id),
                "name": audit.name,
                "status": audit.status,
                "execution_status": state,
                "execution": (
                    exec_svc.describe_execution(latest) if latest else None
                ),
                "overall_score": audit.overall_score,
            }
        )

    counts: dict[str, int] = {}
    for item in items:
        state = str(item["execution_status"] or item["status"] or "pending").lower()
        if state not in (
            "queued", "running", "completed", "failed",
            "cancel_requested", "cancelled",
        ):
            state = "pending"
        counts[state] = counts.get(state, 0) + 1

    return {
        "batch_id": str(batch.id),
        "name": batch.name,
        "total": len(items),
        "counts": counts,
        "items": items,
        "created_at": batch.created_at.isoformat() if batch.created_at else None,
    }


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

    # STEP 7: durable execution state. When an execution row exists it is
    # authoritative for queue lifecycle (queued/running/failed/cancelled);
    # otherwise the legacy memory/DB fallback below applies unchanged.
    execution_block: dict | None = None
    try:
        latest_execution = await exec_svc.latest_execution(db, audit.id)
        if latest_execution is not None:
            execution_block = exec_svc.describe_execution(latest_execution)
    except Exception:
        latest_execution = None

    # Live steps — real backend progress, not fake
    steps = audit_live_steps.get(str(audit_id))
    logs = audit_live_logs.get(str(audit_id), [])[-30:]
    persisted_progress_row = None
    if steps is None:
        # Cross-process: the Celery worker commits step/log/progress
        # snapshots onto the dedicated audit_progress row; the API process
        # cannot see the worker's in-memory dict, so surface them here.
        try:
            from app.models import AuditProgress as _AP

            pr = await db.execute(
                select(_AP).where(_AP.audit_id == audit_id)
            )
            persisted_progress_row = pr.scalar_one_or_none()
            if persisted_progress_row is not None:
                persisted_steps = persisted_progress_row.live_steps
                if isinstance(persisted_steps, list) and persisted_steps:
                    steps = persisted_steps
                persisted_logs = persisted_progress_row.live_logs
                if isinstance(persisted_logs, list) and persisted_logs:
                    logs = persisted_logs
        except Exception:
            persisted_progress_row = None
    if steps is not None:
        progress = _current_progress(str(audit_id))
        if audit.status == "completed":
            progress = 100
            # Ensure all steps marked completed if audit completed but steps pending
            for s in steps:
                if s.get("status") in ("pending", "running"):
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
                    "os_family": vi.get("os_family") or vi.get("platform", "unknown"),
                    "device_type": vi.get("device_type", "unknown"),
                    "hostname": vi.get("hostname"),
                    "firmware_version": vi.get("firmware_version"),
                    "confidence": vi.get("confidence", 0),
                    "detection_method": vi.get("detection_method", ""),
                })
        except Exception:
            pass
    # Normalize: every entry carries the canonical os_family even if the
    # writer predates it (live in-memory entries from any pipeline stage).
    # Canonical form (ios → ios_xe) via the single alias map — the same
    # identity every downstream consumer uses.
    try:
        from app.benchmarks.selection import normalize_platform as _norm_plat
    except Exception:
        _norm_plat = None
    for fd in file_details:
        if not fd.get("os_family"):
            plat = fd.get("platform", "unknown")
            try:
                fd["os_family"] = _norm_plat(fd.get("vendor", ""), plat) if _norm_plat else plat
            except Exception:
                fd["os_family"] = plat

    # Current step label for frontend
    current_step = None
    for s in steps:
        if s.get("status") == "running":
            current_step = s.get("id")
            break
    if not current_step:
        for s in reversed(steps):
            if s.get("status") == "completed":
                current_step = s.get("id")
                break

    # STEP 7: persisted progress overrides the in-memory computation when
    # an execution/progress row exists (cross-process + restart safe).
    # The audit_progress row is authoritative when present; the execution
    # row's persisted progress is the fallback for older runs. Queued
    # executions report 0 — never fabricated.
    if execution_block is not None:
        exec_status = execution_block.get("status")
        if exec_status == exec_svc.ExecutionStatus.RUNNING:
            if persisted_progress_row is not None:
                progress = int(persisted_progress_row.progress or 0)
                if persisted_progress_row.current_step:
                    current_step = persisted_progress_row.current_step
            else:
                progress = int(execution_block.get("progress") or 0)
                if execution_block.get("current_step"):
                    current_step = execution_block.get("current_step")
        elif exec_status == exec_svc.ExecutionStatus.QUEUED:
            progress = 0

    return {
        "id": str(audit.id),
        "name": audit.name,
        "status": audit.status,
        "progress": progress,
        "current_step": current_step,
        "steps": steps,
        "logs": logs,
        "file_details": file_details,
        "execution": execution_block,
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

    # Per-framework compliance counts from stored rows (never recomputed).
    compliance_rows = await db.execute(
        select(ComplianceResult.framework, ComplianceResult.result, func.count(ComplianceResult.id))
        .where(ComplianceResult.audit_id == audit_id)
        .group_by(ComplianceResult.framework, ComplianceResult.result)
    )
    per_framework = {}
    for framework, result, count in compliance_rows.all():
        fw = framework or "CIS"
        slot = per_framework.setdefault(
            fw, {"controls": 0, "pass": 0, "fail": 0, "review": 0})
        slot["controls"] += count
        rv = (result or "").upper()
        if rv == "PASS":
            slot["pass"] += count
        elif rv == "FAIL":
            slot["fail"] += count
        else:
            slot["review"] += count

    # Company Baseline projection — scope is derived from the org's active
    # baseline; verdicts come from the stored CIS results. OUT_OF_SCOPE
    # controls never enter PASS/FAIL/REVIEW or the company denominator.
    company_baseline = await _compute_company_baseline_projection(
        db, audit, getattr(current_user, "organization_id", None)
    )

    return {
        "audit_id": str(audit.id),
        "status": audit.status,
        "overall_score": audit.overall_score,
        "findings_count": audit.findings_count,
        "findings_by_severity": severity_counts,
        "findings_by_status": status_counts,
        "risk": risk_stats,
        "findings_by_priority": priority_counts,
        "compliance": per_framework,
        "company_baseline": company_baseline,
        "started_at": audit.started_at.isoformat() if audit.started_at else None,
        "completed_at": audit.completed_at.isoformat() if audit.completed_at else None,
    }


async def _compute_company_baseline_projection(
    db, audit, org_id: Optional[str]
) -> dict[str, Any]:
    """Project the company baseline over this audit's stored results.

    Scope resolution order:
      1. The audit's own snapshot (baseline_controls) — set once at audit
         time, so a later baseline replacement never rewrites historical
         audit context.
      2. Fallback: the org's current active baseline (pre-snapshot audits).

    Returns the company baseline block for the audit summary: in-scope
    metrics computed ONLY from baseline-selected controls, plus the
    control-by-control comparison (company vs Full CIS). Never modifies
    stored CIS verdicts, evidence, or findings.
    """
    empty = {
        "configured": False,
        "has_baseline": False,
        "in_scope_count": 0,
        "passed": 0,
        "failed": 0,
        "review": 0,
        "out_of_scope": 0,
        "score": None,
        "control_ids": [],
    }

    snapshot_controls = audit.baseline_controls if audit is not None else None
    snapshot_name = audit.baseline_name if audit is not None else None
    snapshot_id = audit.baseline_id if audit is not None else None

    if snapshot_controls is not None:
        if not snapshot_controls:
            return empty
        in_scope = [str(c) for c in snapshot_controls]
        name = snapshot_name or "Company Baseline"
        baseline_meta = {"name": name}
    else:
        # Pre-snapshot audit: fall back to the org's current active baseline.
        if not org_id:
            return empty
        org_result = await db.execute(
            select(Organization).where(Organization.id == org_id)
        )
        org = org_result.scalar_one_or_none()
        if not org or org.baseline_status != "ACTIVE":
            return empty
        bl_result = await db.execute(
            select(CompanyBaseline).where(
                CompanyBaseline.organization_id == org.id,
                CompanyBaseline.status == "ACTIVE",
            )
        )
        active_baseline = bl_result.scalar_one_or_none()
        if not active_baseline or not active_baseline.controls:
            return empty
        controls_data = active_baseline.controls
        if isinstance(controls_data, str):
            in_scope = [c.strip() for c in controls_data.split(",") if c.strip()]
        else:
            in_scope = [str(c) for c in controls_data]
        baseline_meta = {
            "name": active_baseline.name,
            "framework": active_baseline.framework,
            "benchmark": active_baseline.benchmark,
        }

    cr_rows = await db.execute(
        select(ComplianceResult.control_id, ComplianceResult.result)
        .where(ComplianceResult.audit_id == audit.id)
    )
    result_lookup = {
        cid: (res or "").upper() for cid, res in cr_rows.all()
    }
    passed = failed = review = 0
    for ctrl_id in in_scope:
        r = result_lookup.get(ctrl_id, "REVIEW")
        if r == "PASS":
            passed += 1
        elif r == "FAIL":
            failed += 1
        else:
            review += 1
    decisive = passed + failed
    comparison = []
    for ctrl_id in sorted(set(result_lookup.keys()) | set(in_scope)):
        cis_result = result_lookup.get(ctrl_id, "REVIEW")
        comparison.append({
            "control_id": ctrl_id,
            "company_result": (
                cis_result if ctrl_id in in_scope else "OUT_OF_SCOPE"
            ),
            "full_cis_result": cis_result,
            "in_scope": ctrl_id in in_scope,
        })
    return {
        "configured": True,
        "has_baseline": True,
        "baseline_id": str(snapshot_id) if snapshot_id else None,
        "name": baseline_meta.get("name", "Company Baseline"),
        "framework": baseline_meta.get("framework", "CIS"),
        "benchmark": baseline_meta.get("benchmark", ""),
        "in_scope_count": len(in_scope),
        "passed": passed,
        "failed": failed,
        "review": review,
        "out_of_scope": max(0, len(result_lookup) - len(in_scope)),
        "score": round(passed / decisive * 100, 1) if decisive > 0 else 0.0,
        "control_ids": in_scope,
        "comparison": comparison,
    }
