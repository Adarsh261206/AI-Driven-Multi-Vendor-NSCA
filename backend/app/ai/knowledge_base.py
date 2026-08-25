"""
Knowledge Base

Persistent storage for confirmed semantic mappings.
Supports versioning, lookup, and admin confirmation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any


@dataclass
class TrainingMapping:
    """A confirmed semantic mapping"""
    id: str
    vendor: str
    platform: str
    raw_syntax: str
    semantic_meaning: str
    universal_model_path: Optional[str] = None
    confidence: float = 1.0
    admin_confirmed: bool = False
    admin_notes: Optional[str] = None
    version: int = 1
    created_by_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "platform": self.platform,
            "raw_syntax": self.raw_syntax,
            "semantic_meaning": self.semantic_meaning,
            "universal_model_path": self.universal_model_path,
            "confidence": self.confidence,
            "admin_confirmed": self.admin_confirmed,
            "admin_notes": self.admin_notes,
            "version": self.version,
            "created_by_id": self.created_by_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class MappingVersion:
    """Version history of a mapping"""
    id: str
    mapping_id: str
    version: int
    raw_syntax: str
    semantic_meaning: str
    universal_model_path: Optional[str] = None
    changed_by_id: Optional[str] = None
    changed_at: datetime = field(default_factory=datetime.utcnow)
    change_reason: Optional[str] = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mapping_id": self.mapping_id,
            "version": self.version,
            "raw_syntax": self.raw_syntax,
            "semantic_meaning": self.semantic_meaning,
            "universal_model_path": self.universal_model_path,
            "changed_by_id": self.changed_by_id,
            "changed_at": self.changed_at.isoformat(),
            "change_reason": self.change_reason,
        }


class KnowledgeBase:
    """
    Knowledge Base for semantic mappings
    
    Stores confirmed mappings from admin training.
    Supports exact and fuzzy lookup.
    """
    
    def __init__(self):
        self._mappings: dict[str, TrainingMapping] = {}
        self._versions: dict[str, list[MappingVersion]] = {}
    
    def lookup(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        require_confirmed: bool = True,
    ) -> Optional[TrainingMapping]:
        """
        Look up a mapping by vendor/platform/syntax
        
        Args:
            vendor: Device vendor
            platform: Device platform
            raw_syntax: Raw configuration syntax
            require_confirmed: Only return confirmed mappings
            
        Returns:
            TrainingMapping if found, None otherwise
        """
        # Exact match
        for mapping in self._mappings.values():
            if (mapping.vendor.lower() == vendor.lower() and
                mapping.platform.lower() == platform.lower() and
                mapping.raw_syntax.strip() == raw_syntax.strip()):
                
                if require_confirmed and not mapping.admin_confirmed:
                    continue
                
                return mapping
        
        # Fuzzy match (normalized syntax comparison)
        normalized = self._normalize_syntax(raw_syntax)
        for mapping in self._mappings.values():
            if (mapping.vendor.lower() == vendor.lower() and
                mapping.platform.lower() == platform.lower()):
                
                if require_confirmed and not mapping.admin_confirmed:
                    continue
                
                mapping_normalized = self._normalize_syntax(mapping.raw_syntax)
                if self._syntax_similarity(normalized, mapping_normalized) > 0.8:
                    return mapping
        
        return None
    
    def create(
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
        
        Args:
            vendor: Device vendor
            platform: Device platform
            raw_syntax: Raw configuration syntax
            semantic_meaning: Admin-confirmed meaning
            universal_model_path: Optional path in universal model
            admin_confirmed: Whether admin has confirmed
            admin_notes: Optional admin notes
            created_by_id: ID of the creating user
            
        Returns:
            Created TrainingMapping
        """
        # Check for existing mapping
        existing = self.lookup(vendor, platform, raw_syntax, require_confirmed=False)
        
        if existing:
            # Update existing mapping (new version)
            return self.update(
                mapping_id=existing.id,
                semantic_meaning=semantic_meaning,
                universal_model_path=universal_model_path,
                admin_notes=admin_notes,
                changed_by_id=created_by_id,
            )
        
        # Create new mapping
        mapping_id = str(uuid.uuid4())
        mapping = TrainingMapping(
            id=mapping_id,
            vendor=vendor,
            platform=platform,
            raw_syntax=raw_syntax,
            semantic_meaning=semantic_meaning,
            universal_model_path=universal_model_path,
            confidence=1.0 if admin_confirmed else 0.5,
            admin_confirmed=admin_confirmed,
            admin_notes=admin_notes,
            version=1,
            created_by_id=created_by_id,
        )
        
        self._mappings[mapping_id] = mapping
        self._versions[mapping_id] = []
        
        return mapping
    
    def update(
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
        mapping = self._mappings.get(mapping_id)
        if not mapping:
            raise ValueError(f"Mapping {mapping_id} not found")
        
        # Save current version
        version_record = MappingVersion(
            id=str(uuid.uuid4()),
            mapping_id=mapping_id,
            version=mapping.version,
            raw_syntax=mapping.raw_syntax,
            semantic_meaning=mapping.semantic_meaning,
            universal_model_path=mapping.universal_model_path,
            changed_by_id=changed_by_id,
            change_reason=change_reason,
        )
        
        if mapping_id not in self._versions:
            self._versions[mapping_id] = []
        self._versions[mapping_id].append(version_record)
        
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
        
        return mapping
    
    def get_versions(self, mapping_id: str) -> list[MappingVersion]:
        """Get version history of a mapping"""
        return self._versions.get(mapping_id, [])
    
    def list_mappings(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        confirmed_only: bool = False,
    ) -> list[TrainingMapping]:
        """List all mappings with optional filters"""
        results = list(self._mappings.values())
        
        if vendor:
            results = [m for m in results if m.vendor.lower() == vendor.lower()]
        if platform:
            results = [m for m in results if m.platform.lower() == platform.lower()]
        if confirmed_only:
            results = [m for m in results if m.admin_confirmed]
        
        return results
    
    def get_stats(self) -> dict:
        """Get knowledge base statistics"""
        mappings = list(self._mappings.values())
        confirmed = [m for m in mappings if m.admin_confirmed]
        
        return {
            "total_mappings": len(mappings),
            "confirmed_mappings": len(confirmed),
            "pending_mappings": len(mappings) - len(confirmed),
            "vendors": list(set(m.vendor for m in mappings)),
            "platforms": list(set(m.platform for m in mappings)),
        }
    
    def _normalize_syntax(self, syntax: str) -> str:
        """Normalize syntax for comparison"""
        return " ".join(syntax.lower().split())
    
    def _syntax_similarity(self, a: str, b: str) -> float:
        """Calculate syntax similarity (simple Jaccard)"""
        if not a or not b:
            return 0.0
        
        set_a = set(a.split())
        set_b = set(b.split())
        
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        
        return intersection / union if union > 0 else 0.0
