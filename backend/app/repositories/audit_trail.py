"""
Audit Trail Repository

Logs all significant actions for compliance and security auditing.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditTrail, AuditAction


class AuditTrailRepository:
    """
    Audit Trail Repository
    
    Logs all significant actions for compliance and security auditing.
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def log(
        self,
        action: AuditAction,
        entity_type: str,
        entity_id: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditTrail:
        """
        Log an audit trail entry
        
        Args:
            action: Action performed
            entity_type: Type of entity affected
            entity_id: ID of entity affected
            user_id: ID of user performing action
            details: Additional details
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Created AuditTrail entry
        """
        entry = AuditTrail(
            id=uuid.uuid4(),
            action=action,
            entity_type=entity_type,
            entity_id=uuid.UUID(entity_id) if entity_id else None,
            user_id=uuid.UUID(user_id) if user_id else None,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.utcnow(),
        )
        
        self.db.add(entry)
        await self.db.flush()
        
        return entry
    
    async def log_ai_interaction(
        self,
        action: AuditAction,
        raw_syntax: str,
        vendor: str,
        platform: str,
        hypothesis: Optional[dict] = None,
        admin_decision: Optional[str] = None,
        user_id: Optional[str] = None,
        confidence: Optional[float] = None,
        ip_address: Optional[str] = None,
    ) -> AuditTrail:
        """
        Log an AI interaction for audit purposes
        
        Args:
            action: AI-related action
            raw_syntax: Raw configuration syntax
            vendor: Device vendor
            platform: Device platform
            hypothesis: AI hypothesis if available
            admin_decision: Admin decision (confirm/edit/reject)
            user_id: ID of user
            confidence: AI confidence score
            ip_address: Client IP address
        """
        details = {
            "raw_syntax": raw_syntax,
            "vendor": vendor,
            "platform": platform,
            "hypothesis": hypothesis,
            "admin_decision": admin_decision,
            "confidence": confidence,
        }
        
        return await self.log(
            action=action,
            entity_type="ai_interaction",
            user_id=user_id,
            details=details,
            ip_address=ip_address,
        )
    
    async def log_compliance_evaluation(
        self,
        audit_id: str,
        total_controls: int,
        passed: int,
        failed: int,
        review: int,
        overall_score: float,
        user_id: Optional[str] = None,
    ) -> AuditTrail:
        """Log a compliance evaluation result"""
        details = {
            "audit_id": audit_id,
            "total_controls": total_controls,
            "passed": passed,
            "failed": failed,
            "review": review,
            "overall_score": overall_score,
        }
        
        return await self.log(
            action=AuditAction.COMPLIANCE_EVALUATED,
            entity_type="audit",
            entity_id=audit_id,
            user_id=user_id,
            details=details,
        )
    
    async def log_finding_update(
        self,
        finding_id: str,
        audit_id: str,
        old_status: str,
        new_status: str,
        user_id: Optional[str] = None,
    ) -> AuditTrail:
        """Log a finding status update"""
        details = {
            "finding_id": finding_id,
            "audit_id": audit_id,
            "old_status": old_status,
            "new_status": new_status,
        }
        
        return await self.log(
            action=AuditAction.FINDING_UPDATED,
            entity_type="finding",
            entity_id=finding_id,
            user_id=user_id,
            details=details,
        )
    
    async def get_entries(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditTrail]:
        """Get audit trail entries"""
        conditions = []
        
        if entity_type:
            conditions.append(AuditTrail.entity_type == entity_type)
        if entity_id:
            conditions.append(AuditTrail.entity_id == uuid.UUID(entity_id))
        if user_id:
            conditions.append(AuditTrail.user_id == uuid.UUID(user_id))
        
        stmt = select(AuditTrail)
        if conditions:
            from sqlalchemy import and_
            stmt = stmt.where(and_(*conditions))
        
        stmt = stmt.order_by(AuditTrail.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)
        
        result = await self.db.execute(stmt)
        return list(result.scalars().all())
