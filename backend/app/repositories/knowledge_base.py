"""
Knowledge Base Repository

Persistent storage for semantic mappings using SQLAlchemy.
Replaces in-memory KnowledgeBase with PostgreSQL-backed storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import TrainingMapping, MappingVersion


class KnowledgeBaseRepository:
    """
    PostgreSQL-backed Knowledge Base Repository
    
    Provides persistent storage for semantic mappings with versioning.
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def lookup(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        require_confirmed: bool = True,
    ) -> Optional[TrainingMapping]:
        """
        Look up a mapping by vendor/platform/syntax
        
        Returns:
            TrainingMapping if found, None otherwise
        """
        conditions = [
            TrainingMapping.vendor.ilike(vendor),
            TrainingMapping.platform.ilike(platform),
            TrainingMapping.raw_syntax == raw_syntax.strip(),
        ]
        
        if require_confirmed:
            conditions.append(TrainingMapping.admin_confirmed == True)
        
        stmt = select(TrainingMapping).where(and_(*conditions))
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
    
    async def fuzzy_lookup(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        similarity_threshold: float = 0.8,
    ) -> Optional[TrainingMapping]:
        """
        Fuzzy lookup using syntax similarity
        
        Uses PostgreSQL similarity for fuzzy matching.
        """
        # Get all confirmed mappings for this vendor/platform
        stmt = select(TrainingMapping).where(
            and_(
                TrainingMapping.vendor.ilike(vendor),
                TrainingMapping.platform.ilike(platform),
                TrainingMapping.admin_confirmed == True,
            )
        )
        result = await self.db.execute(stmt)
        mappings = result.scalars().all()
        
        # Find best match using Jaccard similarity
        best_match = None
        best_similarity = 0.0
        
        normalized_input = self._normalize_syntax(raw_syntax)
        
        for mapping in mappings:
            normalized_mapping = self._normalize_syntax(mapping.raw_syntax)
            similarity = self._jaccard_similarity(normalized_input, normalized_mapping)
            
            if similarity > best_similarity and similarity >= similarity_threshold:
                best_similarity = similarity
                best_match = mapping
        
        return best_match
    
    async def create(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        semantic_meaning: str,
        universal_model_path: Optional[str] = None,
        admin_confirmed: bool = True,
        admin_notes: Optional[str] = None,
        created_by_id: Optional[str] = None,
    ) -> TrainingMapping:
        """
        Create a new training mapping
        
        Returns:
            Created TrainingMapping
        """
        # Check for existing mapping
        existing = await self.lookup(vendor, platform, raw_syntax, require_confirmed=False)
        
        if existing:
            # Update existing mapping (new version)
            return await self.update(
                mapping_id=str(existing.id),
                semantic_meaning=semantic_meaning,
                universal_model_path=universal_model_path,
                admin_notes=admin_notes,
                changed_by_id=created_by_id,
            )
        
        # Create new mapping
        mapping = TrainingMapping(
            id=uuid.uuid4(),
            vendor=vendor,
            platform=platform,
            raw_syntax=raw_syntax,
            semantic_meaning=semantic_meaning,
            universal_model_path=universal_model_path,
            confidence=1.0 if admin_confirmed else 0.5,
            admin_confirmed=admin_confirmed,
            admin_notes=admin_notes,
            version=1,
            created_by_id=uuid.UUID(created_by_id) if created_by_id else None,
        )
        
        self.db.add(mapping)
        await self.db.flush()
        
        return mapping
    
    async def update(
        self,
        mapping_id: str,
        semantic_meaning: Optional[str] = None,
        universal_model_path: Optional[str] = None,
        admin_notes: Optional[str] = None,
        change_reason: Optional[str] = None,
        changed_by_id: Optional[str] = None,
    ) -> TrainingMapping:
        """
        Update a mapping (creates new version)
        
        Returns:
            Updated TrainingMapping
        """
        stmt = select(TrainingMapping).where(TrainingMapping.id == uuid.UUID(mapping_id))
        result = await self.db.execute(stmt)
        mapping = result.scalar_one_or_none()
        
        if not mapping:
            raise ValueError(f"Mapping {mapping_id} not found")
        
        # Save current version to version history
        version_record = MappingVersion(
            id=uuid.uuid4(),
            mapping_id=mapping.id,
            version=mapping.version,
            raw_syntax=mapping.raw_syntax,
            semantic_meaning=mapping.semantic_meaning,
            universal_model_path=mapping.universal_model_path,
            changed_by_id=uuid.UUID(changed_by_id) if changed_by_id else None,
            change_reason=change_reason,
        )
        self.db.add(version_record)
        
        # Update mapping
        if semantic_meaning is not None:
            mapping.semantic_meaning = semantic_meaning
        if universal_model_path is not None:
            mapping.universal_model_path = universal_model_path
        if admin_notes is not None:
            mapping.admin_notes = admin_notes
        
        mapping.version += 1
        mapping.admin_confirmed = True
        mapping.confidence = 1.0
        mapping.updated_at = datetime.utcnow()
        
        await self.db.flush()
        
        return mapping
    
    async def get_versions(self, mapping_id: str) -> list[MappingVersion]:
        """Get version history of a mapping"""
        stmt = (
            select(MappingVersion)
            .where(MappingVersion.mapping_id == uuid.UUID(mapping_id))
            .order_by(MappingVersion.version.desc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())
    
    async def list_mappings(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        confirmed_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TrainingMapping]:
        """List mappings with optional filters"""
        conditions = []
        
        if vendor:
            conditions.append(TrainingMapping.vendor.ilike(vendor))
        if platform:
            conditions.append(TrainingMapping.platform.ilike(platform))
        if confirmed_only:
            conditions.append(TrainingMapping.admin_confirmed == True)
        
        stmt = select(TrainingMapping)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        stmt = stmt.order_by(TrainingMapping.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)
        
        result = await self.db.execute(stmt)
        return list(result.scalars().all())
    
    async def count_mappings(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        confirmed_only: bool = False,
    ) -> int:
        """Count mappings"""
        conditions = []
        
        if vendor:
            conditions.append(TrainingMapping.vendor.ilike(vendor))
        if platform:
            conditions.append(TrainingMapping.platform.ilike(platform))
        if confirmed_only:
            conditions.append(TrainingMapping.admin_confirmed == True)
        
        stmt = select(func.count(TrainingMapping.id))
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        result = await self.db.execute(stmt)
        return result.scalar()
    
    async def get_stats(self) -> dict:
        """Get knowledge base statistics"""
        total = await self.count_mappings()
        confirmed = await self.count_mappings(confirmed_only=True)
        
        # Get unique vendors/platforms
        vendor_stmt = select(func.distinct(TrainingMapping.vendor))
        vendor_result = await self.db.execute(vendor_stmt)
        vendors = [v for v in vendor_result.scalars().all() if v]
        
        platform_stmt = select(func.distinct(TrainingMapping.platform))
        platform_result = await self.db.execute(platform_stmt)
        platforms = [p for p in platform_result.scalars().all() if p]
        
        return {
            "total_mappings": total,
            "confirmed_mappings": confirmed,
            "pending_mappings": total - confirmed,
            "vendors": vendors,
            "platforms": platforms,
        }
    
    def _normalize_syntax(self, syntax: str) -> str:
        """Normalize syntax for comparison"""
        return " ".join(syntax.lower().split())
    
    def _jaccard_similarity(self, a: str, b: str) -> float:
        """Calculate Jaccard similarity"""
        if not a or not b:
            return 0.0
        
        set_a = set(a.split())
        set_b = set(b.split())
        
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        
        return intersection / union if union > 0 else 0.0
