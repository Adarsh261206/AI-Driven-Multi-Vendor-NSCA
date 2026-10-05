"""Training endpoints - mapping lifecycle per SPEC section 15.

Thin HTTP boundary over the canonical Knowledge Base contract
(app.ai.kb_domain + app.repositories.knowledge_base): request validation,
administrator authorization, error translation (409/422/404, never raw
driver errors), audit logging. All business rules live in the domain.
"""

from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID

from app.ai import kb_domain as dom
from app.ai.knowledge_base import KnowledgeBase
from app.database import get_db
from app.models import User, AuditAction
from app.schemas import (
    TrainingMappingCreate, TrainingMappingUpdate, TrainingMappingResponse,
    AIHypothesisResponse, TrainingMappingListResponse, MappingVersionListResponse,
    MappingVersionResponse, PaginationMeta, AlternativeInterpretation, APIResponse,
    ReanalyzeRequest,
)
from app.security.auth import get_current_user, require_admin
from app.ai.semantic import SemanticAnalyzer
from app.ai.client import create_ai_client
from app.ai.adaptive import AdaptiveLearningEngine
from app.engines.normalization import NormalizationEngine
from app.repositories.audit_trail import AuditTrailRepository
from app.repositories.knowledge_base import KnowledgeBaseRepository

router = APIRouter()

SNAPSHOT_LIMIT = 2000


def _repo(db: AsyncSession) -> KnowledgeBaseRepository:
    return KnowledgeBaseRepository(db)


def _conflict(exc: Exception) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT, detail=str(exc))


def _unprocessable(exc: Exception) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))


def _optional_confidence(value, field: str) -> Optional[float]:
    """Validate an optional confidence query parameter.

    Plain `= None` defaults (not Query(...)) keep the endpoint callable as a
    plain coroutine in unit tests, where FastAPI's Query sentinel is never
    resolved; the 0.0-1.0 bound is enforced here and again in the domain.
    """
    if value is None:
        return None
    try:
        return dom.validate_confidence(value)
    except (TypeError, dom.KBValidationError) as exc:
        raise _unprocessable(exc) from exc


@router.get("/mappings", response_model=TrainingMappingListResponse)
async def list_mappings(
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    vendor: Optional[str] = None,
    platform: Optional[str] = None,
    confirmed: Optional[bool] = None,
    confidence_min: Optional[float] = None,
    confidence_max: Optional[float] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List training mappings (canonical order, paginated with total)."""
    repo = _repo(db)
    confidence_min = _optional_confidence(confidence_min, "confidence_min")
    confidence_max = _optional_confidence(confidence_max, "confidence_max")
    if (confidence_min is not None and confidence_max is not None
            and confidence_min > confidence_max):
        raise _unprocessable(
            dom.KBValidationError("confidence_min must be <= confidence_max"))
    try:
        total = await repo.count_mappings(
            vendor=vendor, platform=platform,
            confirmed_only=bool(confirmed),
            confidence_min=confidence_min, confidence_max=confidence_max)
        rows = await repo.list_mappings(
            vendor=vendor, platform=platform,
            confirmed_only=bool(confirmed),
            confidence_min=confidence_min, confidence_max=confidence_max,
            limit=per_page, offset=(page - 1) * per_page)
    except (TypeError, dom.KBValidationError) as exc:
        raise _unprocessable(exc)

    return TrainingMappingListResponse(
        items=[TrainingMappingResponse.model_validate(m) for m in rows],
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
        ),
    )


@router.post("/mappings", response_model=TrainingMappingResponse, status_code=status.HTTP_201_CREATED)
async def create_mapping(
    mapping: TrainingMappingCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Create a new training mapping (administrator only).

    Exact canonical duplicates are rejected with 409 (no second row, no
    silent overwrite). The initial version-1 record is written here.
    """
    repo = _repo(db)
    try:
        duplicate = await repo.lookup(
            mapping.vendor, mapping.platform, mapping.raw_syntax,
            require_confirmed=False)
    except (TypeError, dom.KBValidationError) as exc:
        raise _unprocessable(exc)
    if duplicate is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Mapping already exists for this syntax"
        )

    try:
        created = await repo.create(
            vendor=mapping.vendor,
            platform=mapping.platform,
            raw_syntax=mapping.raw_syntax,
            semantic_meaning=mapping.semantic_meaning,
            universal_model_path=mapping.universal_model_path,
            confidence=mapping.confidence,
            admin_confirmed=mapping.admin_confirmed,
            admin_notes=mapping.admin_notes,
            actor=str(current_user.id),
        )
        await db.flush()
    except dom.KBDuplicateError as exc:
        await db.rollback()
        raise _conflict(exc)
    except (TypeError, dom.KBValidationError) as exc:
        await db.rollback()
        raise _unprocessable(exc)

    # E12: creation opens the mapping's version history in the trail.
    trail = AuditTrailRepository(db)
    await trail.log_mapping_event(
        action=AuditAction.MAPPING_CREATED,
        mapping_id=str(created.id),
        user_id=str(current_user.id),
        details={"version": 1, "admin_confirmed": created.admin_confirmed},
    )
    await db.flush()

    return TrainingMappingResponse.model_validate(created)


@router.get("/mappings/{mapping_id}", response_model=TrainingMappingResponse)
async def get_mapping(
    mapping_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a training mapping"""
    repo = _repo(db)
    mapping = await repo.get_by_id(str(mapping_id))

    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")

    return TrainingMappingResponse.model_validate(mapping)


@router.put("/mappings/{mapping_id}", response_model=TrainingMappingResponse)
async def update_mapping(
    mapping_id: UUID,
    mapping_update: TrainingMappingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Edit a training mapping (administrator only).

    EDIT never confirms and never fabricates confidence. A no-op edit
    changes nothing and records nothing.
    """
    repo = _repo(db)
    before = await repo.get_by_id(str(mapping_id))
    try:
        await repo.update(
            mapping_id=str(mapping_id),
            semantic_meaning=mapping_update.semantic_meaning,
            universal_model_path=mapping_update.universal_model_path,
            admin_notes=mapping_update.admin_notes,
            change_reason=mapping_update.change_reason,
            actor=str(current_user.id),
        )
        await db.flush()
    except dom.KBNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (TypeError, dom.KBValidationError) as exc:
        await db.rollback()
        raise _unprocessable(exc)

    fresh = await repo.get_by_id(str(mapping_id))
    # E12: EDIT is a version-history event — a real change is recorded in
    # the audit trail; a no-op edit records nothing (E06 F7 convention).
    if before is not None and fresh.version != before.version:
        trail = AuditTrailRepository(db)
        await trail.log_mapping_event(
            action=AuditAction.MAPPING_UPDATED,
            mapping_id=str(mapping_id),
            user_id=str(current_user.id),
            details={
                "version": fresh.version,
                "change_reason": mapping_update.change_reason or "Edit",
            },
        )
        await db.flush()
    return TrainingMappingResponse.model_validate(fresh)


@router.get("/mappings/{mapping_id}/versions", response_model=MappingVersionListResponse)
async def get_mapping_versions(
    mapping_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get mapping version history (chronological)."""
    repo = _repo(db)
    if await repo.get_by_id(str(mapping_id)) is None:
        raise HTTPException(status_code=404, detail="Mapping not found")

    versions = await repo.get_versions(str(mapping_id))

    return MappingVersionListResponse(
        items=[
            MappingVersionResponse(
                version=v.version,
                raw_syntax=v.raw_syntax,
                semantic_meaning=v.semantic_meaning,
                universal_model_path=v.universal_model_path,
                confidence=(float(v.confidence)
                            if getattr(v, "confidence", None) is not None
                            else None),
                changed_by=str(v.changed_by) if getattr(
                    v, "changed_by", None) is not None else None,
                changed_at=v.changed_at,
                change_reason=v.change_reason,
            )
            for v in versions
        ]
    )


@router.post("/hypothesis", response_model=AIHypothesisResponse)
async def get_ai_hypothesis(
    vendor: str,
    platform: str,
    raw_syntax: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get AI hypothesis for unknown syntax

    Flow:
    1. Check Knowledge Base for existing mapping
    2. If not found, query AI for hypothesis (with KB suggestions attached)
    3. Log the interaction for audit
    4. Return hypothesis to admin
    """
    # Log the request
    audit_trail = AuditTrailRepository(db)
    kb_repo = KnowledgeBaseRepository(db)

    # Check if we already have a mapping in the knowledge base
    try:
        existing_mapping = await kb_repo.lookup(
            vendor=vendor,
            platform=platform,
            raw_syntax=raw_syntax,
            require_confirmed=True,
        )
    except (TypeError, dom.KBValidationError) as exc:
        raise _unprocessable(exc)

    if existing_mapping:
        # Log KB hit
        await audit_trail.log_ai_interaction(
            action=AuditAction.AI_HYPOTHESIS_RECEIVED,
            raw_syntax=raw_syntax,
            vendor=vendor,
            platform=platform,
            hypothesis={
                "meaning": existing_mapping.semantic_meaning,
                "confidence": existing_mapping.confidence,
                "source": "knowledge_base",
            },
            user_id=str(current_user.id),
            confidence=existing_mapping.confidence,
        )

        # Return existing mapping as "hypothesis", with relevance derived
        # from the mapping's own model path (never a constant).
        return AIHypothesisResponse(
            raw_syntax=raw_syntax,
            suggested_meaning=existing_mapping.semantic_meaning,
            confidence=existing_mapping.confidence,
            reasoning="Based on existing knowledge base mapping",
            universal_model_path=existing_mapping.universal_model_path,
            alternative_interpretations=[],
            security_relevance=dom.relevance_for_path(
                existing_mapping.universal_model_path),
            explanation=existing_mapping.admin_notes or "From knowledge base",
        )

    # Query AI for hypothesis
    ai_client = create_ai_client()
    semantic_analyzer = SemanticAnalyzer(ai_client=ai_client)
    hypothesis = await semantic_analyzer.generate_hypothesis(
        raw_syntax=raw_syntax,
        vendor=vendor,
        platform=platform,
    )

    # Attach KB suggestions (non-authoritative) as alternatives.
    alternatives = []
    try:
        suggestions = await kb_repo.lookup_suggestions(
            vendor, platform, raw_syntax, require_confirmed=True)
        for candidate, similarity in suggestions[:3]:
            alternatives.append(AlternativeInterpretation(
                meaning=candidate.semantic_meaning,
                confidence=round(similarity, 4),
                reasoning=(f"Knowledge-base suggestion "
                           f"(similarity {similarity:.2f}); requires "
                           f"administrator review before use"),
            ))
    except (TypeError, dom.KBValidationError):
        pass
    for alt in hypothesis.get("alternatives", []):
        alternatives.append(AlternativeInterpretation(
            meaning=alt.get("meaning", ""),
            confidence=alt.get("confidence", 0.0),
            reasoning=alt.get("reasoning", ""),
        ))

    # Log AI interaction
    await audit_trail.log_ai_interaction(
        action=AuditAction.AI_HYPOTHESIS_RECEIVED,
        raw_syntax=raw_syntax,
        vendor=vendor,
        platform=platform,
        hypothesis={
            "meaning": hypothesis.get("meaning", ""),
            "confidence": hypothesis.get("confidence", 0.0),
            "source": "ai",
        },
        user_id=str(current_user.id),
        confidence=hypothesis.get("confidence", 0.0),
    )

    # Build response
    return AIHypothesisResponse(
        raw_syntax=raw_syntax,
        suggested_meaning=hypothesis.get("meaning", "Unable to determine"),
        confidence=hypothesis.get("confidence", 0.0),
        reasoning=hypothesis.get("reasoning", ""),
        universal_model_path=hypothesis.get("universal_model_path"),
        alternative_interpretations=alternatives,
        security_relevance=hypothesis.get("security_relevance", "unknown"),
        explanation=hypothesis.get("explanation", ""),
    )


@router.post("/mappings/{mapping_id}/confirm", response_model=TrainingMappingResponse)
async def confirm_mapping(
    mapping_id: UUID,
    semantic_meaning: Optional[str] = None,
    universal_model_path: Optional[str] = None,
    admin_notes: Optional[str] = None,
    confidence: Optional[float] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Confirm a training mapping (administrator only).

    An explicit administrator action: always appends a version record
    (reaffirmation is an event). An explicit estimated confidence is
    preserved verbatim; otherwise the administrator's validation is the
    evidence and the stored estimate becomes 1.0 — the one place a
    hypothesis estimate is promoted, never an EDIT.
    """
    repo = _repo(db)
    confidence = _optional_confidence(confidence, "confidence")
    audit_trail = AuditTrailRepository(db)
    try:
        mapping = await repo.confirm(
            mapping_id=str(mapping_id),
            actor=str(current_user.id),
            semantic_meaning=semantic_meaning,
            universal_model_path=universal_model_path,
            admin_notes=admin_notes,
            confidence=confidence,
        )
        await db.flush()
    except dom.KBNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (TypeError, dom.KBValidationError) as exc:
        await db.rollback()
        raise _unprocessable(exc)

    # Log confirmation
    await audit_trail.log_ai_interaction(
        action=AuditAction.MAPPING_CONFIRMED,
        raw_syntax=mapping.raw_syntax,
        vendor=mapping.vendor,
        platform=mapping.platform,
        hypothesis={
            "meaning": mapping.semantic_meaning,
            "confidence": mapping.confidence,
            "universal_model_path": mapping.universal_model_path,
        },
        admin_decision="confirm",
        user_id=str(current_user.id),
        confidence=mapping.confidence,
    )

    fresh = await repo.get_by_id(str(mapping_id))
    return TrainingMappingResponse.model_validate(fresh)


@router.post("/mappings/{mapping_id}/reject", response_model=APIResponse)
async def reject_mapping(
    mapping_id: UUID,
    reason: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Reject a training mapping (administrator only).

    Marks the row unconfirmed with a REJECTED note, bumps the version and
    records history. Never deletes: audit history survives.
    """
    repo = _repo(db)
    try:
        mapping = await repo.reject(
            mapping_id=str(mapping_id),
            actor=str(current_user.id),
            reason=reason,
        )
        await db.flush()
    except dom.KBNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (TypeError, dom.KBValidationError) as exc:
        await db.rollback()
        raise _unprocessable(exc)

    # Log the rejection
    audit_trail = AuditTrailRepository(db)
    await audit_trail.log_ai_interaction(
        action=AuditAction.MAPPING_REJECTED,
        raw_syntax=mapping.raw_syntax,
        vendor=mapping.vendor,
        platform=mapping.platform,
        hypothesis={
            "meaning": mapping.semantic_meaning,
            "confidence": mapping.confidence,
        },
        admin_decision="reject",
        user_id=str(current_user.id),
        confidence=mapping.confidence,
    )

    return APIResponse(
        success=True,
        data={"message": "Mapping rejected", "mapping_id": str(mapping_id)},
    )


@router.post("/mappings/{mapping_id}/reanalyze", response_model=APIResponse)
async def reanalyze_with_mapping(
    mapping_id: UUID,
    body: ReanalyzeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    §9.2 step 5: re-run semantic analysis and normalization for a config
    with a confirmed mapping active.

    Builds a consultation snapshot of the confirmed rows for the mapping's
    vendor/platform, re-analyzes through the adaptive workflow (vendor
    parser selected per mapping), and normalizes with the snapshot
    applied. Read-only: commits nothing. Compliance re-evaluation happens
    by re-running the audit through the existing audit orchestration.
    """
    from app.ai.adaptive import AdaptiveLearningEngine

    repo = _repo(db)
    mapping = await repo.get_by_id(str(mapping_id))
    if mapping is None:
        raise HTTPException(status_code=404, detail="Mapping not found")
    if not mapping.admin_confirmed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only confirmed mappings drive re-analysis",
        )
    vendor = (body.vendor or mapping.vendor)
    platform = (body.platform or mapping.platform)

    rows = await repo.list_mappings(
        vendor=vendor, platform=platform, confirmed_only=True,
        limit=SNAPSHOT_LIMIT)
    snapshot = KnowledgeBase.from_rows(rows)
    adaptive = AdaptiveLearningEngine(knowledge_base=snapshot)
    analysis = await adaptive.reanalyze_with_mapping(
        body.config_content, vendor, platform, mapping)
    normalized = NormalizationEngine().normalize(
        {"raw_lines": body.config_content.splitlines()},
        vendor, platform, knowledge_base=snapshot)

    return APIResponse(
        success=True,
        data={
            "mapping_id": str(mapping_id),
            "semantic": analysis.to_dict(),
            "normalization": normalized.to_dict(),
        },
    )
