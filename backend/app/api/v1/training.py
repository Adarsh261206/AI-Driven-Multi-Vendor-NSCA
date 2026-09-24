from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from uuid import UUID

from app.database import get_db
from app.models import User, TrainingMapping, MappingVersion, AuditAction
from app.schemas import (
    TrainingMappingCreate, TrainingMappingUpdate, TrainingMappingResponse,
    AIHypothesisResponse, TrainingMappingListResponse, MappingVersionListResponse,
    MappingVersionResponse, PaginationMeta, AlternativeInterpretation, APIResponse,
)
from app.security.auth import get_current_user
from app.ai.semantic import SemanticAnalyzer
from app.ai.client import create_ai_client
from app.repositories.audit_trail import AuditTrailRepository
from app.repositories.knowledge_base import KnowledgeBaseRepository

router = APIRouter()


@router.get("/mappings", response_model=TrainingMappingListResponse)
async def list_mappings(
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    vendor: Optional[str] = None,
    platform: Optional[str] = None,
    confirmed: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List training mappings"""
    # Build query
    query = select(TrainingMapping)
    count_query = select(func.count(TrainingMapping.id))
    
    if vendor:
        query = query.where(TrainingMapping.vendor == vendor)
        count_query = count_query.where(TrainingMapping.vendor == vendor)
    
    if platform:
        query = query.where(TrainingMapping.platform == platform)
        count_query = count_query.where(TrainingMapping.platform == platform)
    
    if confirmed is not None:
        query = query.where(TrainingMapping.admin_confirmed == confirmed)
        count_query = count_query.where(TrainingMapping.admin_confirmed == confirmed)
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(TrainingMapping.created_at.desc())
    
    # Execute query
    result = await db.execute(query)
    mappings = result.scalars().all()
    
    return TrainingMappingListResponse(
        items=[TrainingMappingResponse.from_orm(mapping) for mapping in mappings],
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
    current_user: User = Depends(get_current_user),
):
    """Create a new training mapping"""
    # Check for existing mapping
    existing = await db.execute(
        select(TrainingMapping).where(
            TrainingMapping.vendor == mapping.vendor,
            TrainingMapping.platform == mapping.platform,
            TrainingMapping.raw_syntax == mapping.raw_syntax,
        )
    )
    existing_mapping = existing.scalar_one_or_none()
    
    if existing_mapping:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Mapping already exists for this syntax"
        )
    
    # Create mapping
    new_mapping = TrainingMapping(
        vendor=mapping.vendor,
        platform=mapping.platform,
        raw_syntax=mapping.raw_syntax,
        semantic_meaning=mapping.semantic_meaning,
        universal_model_path=mapping.universal_model_path,
        confidence=1.0,  # Admin-confirmed mappings have full confidence
        admin_confirmed=True,
        admin_notes=mapping.admin_notes,
        version=1,
        created_by_id=current_user.id,
    )
    
    db.add(new_mapping)
    await db.flush()
    await db.refresh(new_mapping)
    
    # Create initial version
    version = MappingVersion(
        mapping_id=new_mapping.id,
        version=1,
        raw_syntax=mapping.raw_syntax,
        semantic_meaning=mapping.semantic_meaning,
        universal_model_path=mapping.universal_model_path,
        changed_by_id=current_user.id,
        change_reason="Initial creation",
    )
    db.add(version)
    await db.flush()
    
    return TrainingMappingResponse.from_orm(new_mapping)


@router.get("/mappings/{mapping_id}", response_model=TrainingMappingResponse)
async def get_mapping(
    mapping_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a training mapping"""
    result = await db.execute(
        select(TrainingMapping).where(TrainingMapping.id == mapping_id)
    )
    mapping = result.scalar_one_or_none()
    
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    
    return TrainingMappingResponse.from_orm(mapping)


@router.put("/mappings/{mapping_id}", response_model=TrainingMappingResponse)
async def update_mapping(
    mapping_id: UUID,
    mapping_update: TrainingMappingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a training mapping"""
    result = await db.execute(
        select(TrainingMapping).where(TrainingMapping.id == mapping_id)
    )
    mapping = result.scalar_one_or_none()
    
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    
    # Update fields
    update_data = mapping_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        if field != "change_reason":
            setattr(mapping, field, value)
    
    # Increment version
    mapping.version += 1
    
    await db.flush()
    
    # Create version record
    version = MappingVersion(
        mapping_id=mapping.id,
        version=mapping.version,
        raw_syntax=mapping.raw_syntax,
        semantic_meaning=mapping.semantic_meaning,
        universal_model_path=mapping.universal_model_path,
        changed_by_id=current_user.id,
        change_reason=mapping_update.change_reason,
    )
    db.add(version)
    await db.flush()
    await db.refresh(mapping)
    
    return TrainingMappingResponse.from_orm(mapping)


@router.get("/mappings/{mapping_id}/versions", response_model=MappingVersionListResponse)
async def get_mapping_versions(
    mapping_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get mapping version history"""
    # Verify mapping exists
    mapping_result = await db.execute(
        select(TrainingMapping).where(TrainingMapping.id == mapping_id)
    )
    mapping = mapping_result.scalar_one_or_none()
    
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    
    # Get versions
    result = await db.execute(
        select(MappingVersion)
        .where(MappingVersion.mapping_id == mapping_id)
        .order_by(MappingVersion.version.desc())
    )
    versions = result.scalars().all()
    
    return MappingVersionListResponse(
        items=[
            MappingVersionResponse(
                version=v.version,
                raw_syntax=v.raw_syntax,
                semantic_meaning=v.semantic_meaning,
                universal_model_path=v.universal_model_path,
                changed_by=str(v.changed_by_id),
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
    2. If not found, query AI for hypothesis
    3. Log the interaction for audit
    4. Return hypothesis to admin
    """
    # Log the request
    audit_trail = AuditTrailRepository(db)
    kb_repo = KnowledgeBaseRepository(db)
    
    # Check if we already have a mapping in the knowledge base
    existing_mapping = await kb_repo.lookup(
        vendor=vendor,
        platform=platform,
        raw_syntax=raw_syntax,
        require_confirmed=True,
    )
    
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
        
        # Return existing mapping as "hypothesis"
        return AIHypothesisResponse(
            raw_syntax=raw_syntax,
            suggested_meaning=existing_mapping.semantic_meaning,
            confidence=existing_mapping.confidence,
            reasoning="Based on existing knowledge base mapping",
            universal_model_path=existing_mapping.universal_model_path,
            alternative_interpretations=[],
            security_relevance="medium",
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
    alternatives = []
    for alt in hypothesis.get("alternatives", []):
        alternatives.append(AlternativeInterpretation(
            meaning=alt.get("meaning", ""),
            confidence=alt.get("confidence", 0.0),
            reasoning=alt.get("reasoning", ""),
        ))
    
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
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Confirm or edit a training mapping
    
    Admin can:
    - Confirm AI hypothesis as-is
    - Edit the meaning before confirming
    - Add notes for future reference
    """
    result = await db.execute(
        select(TrainingMapping).where(TrainingMapping.id == mapping_id)
    )
    mapping = result.scalar_one_or_none()
    
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    
    # Log the action
    audit_trail = AuditTrailRepository(db)
    
    # Update mapping
    if semantic_meaning is not None:
        mapping.semantic_meaning = semantic_meaning
    if universal_model_path is not None:
        mapping.universal_model_path = universal_model_path
    if admin_notes is not None:
        mapping.admin_notes = admin_notes
    
    mapping.admin_confirmed = True
    mapping.confidence = 1.0
    
    # Create version record
    version = MappingVersion(
        mapping_id=mapping.id,
        version=mapping.version + 1,
        raw_syntax=mapping.raw_syntax,
        semantic_meaning=mapping.semantic_meaning,
        universal_model_path=mapping.universal_model_path,
        changed_by_id=current_user.id,
        change_reason="Admin confirmation",
    )
    db.add(version)
    
    mapping.version += 1
    
    await db.flush()
    
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
    
    await db.refresh(mapping)
    return TrainingMappingResponse.from_orm(mapping)


@router.post("/mappings/{mapping_id}/reject", response_model=APIResponse)
async def reject_mapping(
    mapping_id: UUID,
    reason: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Reject a training mapping
    
    Admin rejects the AI hypothesis as incorrect.
    """
    result = await db.execute(
        select(TrainingMapping).where(TrainingMapping.id == mapping_id)
    )
    mapping = result.scalar_one_or_none()
    
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    
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
    
    # Mark as rejected (don't delete - keep for learning)
    mapping.admin_confirmed = False
    mapping.admin_notes = f"REJECTED: {reason or 'No reason provided'}"
    
    await db.flush()
    
    return APIResponse(
        success=True,
        data={"message": "Mapping rejected", "mapping_id": str(mapping_id)},
    )
