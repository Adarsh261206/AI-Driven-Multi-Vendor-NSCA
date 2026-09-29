"""
Repository Layer

Data access layer for database operations.
"""

from __future__ import annotations

from app.repositories.knowledge_base import KnowledgeBaseRepository
from app.repositories.audit_trail import AuditTrailRepository

__all__ = ["KnowledgeBaseRepository", "AuditTrailRepository"]
