"""Canonical finding query service (E08 F4).

One implementation backs every findings list endpoint:
  GET /api/v1/audits/{audit_id}/findings
  GET /api/v1/findings/audit/{audit_id}
  GET /api/v1/audit-execution/{audit_id}/findings

Shared contract:
- ownership: the audit must exist and belong to the requesting user (else
  404, never an empty list that hides an authorization failure);
- filters (all optional, conjunctive): severity (canonical uppercase;
  case-insensitive input, 422 on invalid), status (FindingStatus enum;
  FastAPI rejects invalid values with 422), vendor, platform, control_id
  (exact match against the stored canonical representation);
- deterministic ordering: created_at DESC, id ASC (documented; severity
  is never ordered lexicographically);
- pagination with total/total_pages.
"""

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import asc, desc, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Audit, Finding

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: Canonical finding statuses (§9.1 step 13 workflow).
STATUS_VALUES = ("open", "in_progress", "resolved", "accepted")


def normalize_severity(value: Any) -> str:
    """Canonical severity form for filters (F4/F7).

    Accepts any casing of the four canonical values; anything else is a
    typed 422 (never a silent zero-row match).
    """
    if not isinstance(value, str):
        raise HTTPException(
            status_code=422, detail="severity must be a string")
    canonical = value.strip().upper()
    if canonical not in SEVERITY_ORDER:
        raise HTTPException(
            status_code=422,
            detail=f"invalid severity {value!r} (expected one of "
                   f"{', '.join(SEVERITY_ORDER)})")
    return canonical


def normalize_status(value: Any) -> str:
    """Canonical status form for filters (F4).

    Accepts the FindingStatus enum or the exact canonical strings; anything
    else is a typed 422 (never a silent zero-row match). Direct Python calls
    (tests, services) get the same validation as HTTP requests.
    """
    if hasattr(value, "value"):
        value = value.value
    if not isinstance(value, str):
        raise HTTPException(
            status_code=422, detail="status must be a string")
    canonical = value.strip()
    if canonical not in STATUS_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"invalid status {value!r} (expected one of "
                   f"{', '.join(STATUS_VALUES)})")
    return canonical


class FindingQueryService:
    """One canonical findings query implementation."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def _require_audit(self, audit_id: UUID, user_id: Any) -> Any:
        audit = (await self.db.execute(
            select(Audit).where(
                Audit.id == audit_id,
                Audit.user_id == user_id,
            ))).scalar_one_or_none()
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found")
        return audit

    def _apply_filters(self, query, count_query, severity: Optional[str],
                       status: Optional[Any], vendor: Optional[str],
                       platform: Optional[str], control_id: Optional[str]):
        if severity is not None:
            canonical = normalize_severity(severity)
            query = query.where(Finding.severity == canonical)
            count_query = count_query.where(Finding.severity == canonical)
        if status is not None:
            status_value = normalize_status(status)
            query = query.where(Finding.status == status_value)
            count_query = count_query.where(Finding.status == status_value)
        if vendor is not None:
            query = query.where(Finding.affected_vendor == vendor)
            count_query = count_query.where(Finding.affected_vendor == vendor)
        if platform is not None:
            query = query.where(Finding.affected_platform == platform)
            count_query = count_query.where(
                Finding.affected_platform == platform)
        if control_id is not None:
            query = query.where(Finding.control_id == control_id)
            count_query = count_query.where(
                Finding.control_id == control_id)
        return query, count_query

    async def list_for_audit(
        self,
        audit_id: UUID,
        user_id: Any,
        page: int = 1,
        per_page: int = 20,
        severity: Optional[str] = None,
        status: Optional[Any] = None,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        control_id: Optional[str] = None,
    ) -> tuple[list[Any], int]:
        """(items, total) for one audit under the canonical contract."""
        await self._require_audit(audit_id, user_id)
        query = select(Finding).where(Finding.audit_id == audit_id)
        count_query = select(func.count(Finding.id)).where(
            Finding.audit_id == audit_id)
        query, count_query = self._apply_filters(
            query, count_query, severity, status, vendor, platform,
            control_id)
        total = (await self.db.execute(count_query)).scalar() or 0
        offset = (page - 1) * per_page
        query = (query.offset(offset).limit(per_page)
                 .order_by(desc(Finding.created_at), asc(Finding.id)))
        items = list((await self.db.execute(query)).scalars().all())
        return items, total
