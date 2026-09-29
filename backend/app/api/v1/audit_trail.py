"""Audit-trail query surface (Engine 12, spec 10.12 "Support audit queries").

Read-only: the trail is written by the pipeline and admin workflows;
this endpoint serves it back with auth, user scoping, filters and
bounded pagination. Non-admin callers see only their own entries;
admins see everything. Malformed filters are 422 (typed repository
errors), never 500.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.database import get_db
from app.models import User, UserRole
from app.repositories.audit_trail import (
    AuditTrailError,
    AuditTrailRepository,
)
from app.schemas import (
    AuditTrailListResponse,
    AuditTrailResponse,
    PaginationMeta,
)
from app.security.auth import get_current_user

router = APIRouter()

# Endpoint page cap mirrors the list endpoints (reports caps at 100).
MAX_PER_PAGE = 100


def _unprocessable(exc: Exception) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@router.get("/", response_model=AuditTrailListResponse)
async def list_trail_entries(
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=MAX_PER_PAGE),
    entity_type: Optional[str] = Query(None),
    entity_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Query audit-trail records (newest first).

    Filters: entity_type, entity_id (UUID), action (AuditAction value).
    Scoping: non-admin callers are restricted to their own user_id;
    admins see every entry.
    """
    scoped_user: Optional[str] = None
    if current_user.role != UserRole.ADMIN.value:
        scoped_user = str(current_user.id)

    repo = AuditTrailRepository(db)
    try:
        total = await repo.count_entries(
            entity_type=entity_type,
            entity_id=entity_id,
            user_id=scoped_user,
            action=action,
        )
        entries = await repo.get_entries(
            entity_type=entity_type,
            entity_id=entity_id,
            user_id=scoped_user,
            action=action,
            limit=per_page,
            offset=(page - 1) * per_page,
        )
    except AuditTrailError as exc:
        raise _unprocessable(exc) from exc

    return AuditTrailListResponse(
        items=[AuditTrailResponse.model_validate(e) for e in entries],
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page if per_page else 0,
        ),
    )
