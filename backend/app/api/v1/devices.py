from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from typing import Optional
from uuid import UUID

from app.database import get_db
from app.models import User, Device, Configuration, Audit, AuditConfiguration
from app.schemas import (
    DeviceCreate, DeviceUpdate, DeviceResponse, DeviceListResponse, PaginationMeta,
    DeviceConfigurationHistoryItem, DeviceConfigurationHistoryResponse,
    DeviceAuditHistoryItem, DeviceAuditHistoryResponse,
)
from app.security.auth import get_current_user, require_auditor
from app.services.scope import resolve_owned_device

router = APIRouter()



def _like_escape(term: str) -> str:
    """Escape LIKE wildcards so search terms match literally."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def _populate_inventory_fields(
    db: AsyncSession,
    devices: list[Device],
    current_user: User,
) -> list[DeviceResponse]:
    """Attach derived inventory fields to a page of devices.

    Constant query count regardless of page size (no N+1):
      1. config counts GROUP BY device
      2. latest config per device (ROW_NUMBER window)
      3. latest audit per device (any status)
      4. latest COMPLETED audit per device
    All derivations start from the caller's already-visible devices, and
    non-admin audit aggregates are further restricted to the caller's own
    audits so legacy cross-user associations never leak.
    """
    device_ids = [d.id for d in devices]
    if not device_ids:
        return []

    counts = {
        row[0]: row[1]
        for row in (
            await db.execute(
                select(Configuration.device_id, func.count(Configuration.id))
                .where(Configuration.device_id.in_(device_ids))
                .group_by(Configuration.device_id)
            )
        ).all()
    }

    ranked_cfg = (
        select(
            Configuration.device_id,
            Configuration.id,
            Configuration.filename,
            Configuration.uploaded_at,
            func.row_number()
            .over(
                partition_by=Configuration.device_id,
                order_by=(
                    Configuration.uploaded_at.desc(),
                    Configuration.id.desc(),
                ),
            )
            .label("rn"),
        )
        .where(Configuration.device_id.in_(device_ids))
        .subquery()
    )
    latest_cfgs = {
        row[0]: row[1:]
        for row in (
            await db.execute(select(ranked_cfg).where(ranked_cfg.c.rn == 1))
        ).all()
    }

    def _audit_window(completed_only: bool):
        q = (
            select(
                Configuration.device_id,
                Audit.id,
                Audit.status,
                Audit.created_at,
                Audit.overall_score,
                func.row_number()
                .over(
                    partition_by=Configuration.device_id,
                    order_by=(Audit.created_at.desc(), Audit.id.desc()),
                )
                .label("rn"),
            )
            .join(
                AuditConfiguration,
                AuditConfiguration.configuration_id == Configuration.id,
            )
            .join(Audit, Audit.id == AuditConfiguration.audit_id)
            .where(Configuration.device_id.in_(device_ids))
        )
        if completed_only:
            q = q.where(Audit.status == "completed")
        if current_user.role != "admin":
            q = q.where(Audit.user_id == current_user.id)
        return q.subquery()

    overall_sub = _audit_window(False)
    latest_audits = {
        row[0]: row[1:]
        for row in (
            await db.execute(select(overall_sub).where(overall_sub.c.rn == 1))
        ).all()
    }
    completed_sub = _audit_window(True)
    latest_completed = {
        row[0]: row[1:]
        for row in (
            await db.execute(select(completed_sub).where(completed_sub.c.rn == 1))
        ).all()
    }

    items = []
    for device in devices:
        latest = latest_cfgs.get(device.id)
        overall = latest_audits.get(device.id)
        done = latest_completed.get(device.id)
        payload = DeviceResponse.from_orm(device).dict()
        payload.update(
            configuration_count=counts.get(device.id, 0),
            latest_configuration_filename=latest[1] if latest else None,
            latest_configuration_at=latest[2] if latest else None,
            last_audit_id=done[0] if done else None,
            last_audit_status=overall[1] if overall else None,
            last_audit_date=done[2] if done else None,
            last_compliance_score=done[3] if done else None,
        )
        items.append(DeviceResponse(**payload))
    return items


@router.get("/", response_model=DeviceListResponse)
async def list_devices(
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    vendor: Optional[str] = None,
    platform: Optional[str] = None,
    search: Optional[str] = None,
    lifecycle: str = Query("active", pattern="^(active|archived|all)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all devices for the current user with derived inventory fields.

    `search` matches name, IP address, vendor, and platform
    case-insensitively and composes (AND) with the vendor/platform
    filters. Ownership is always enforced first: only the caller's own
    devices are ever considered.
    """
    # Build query
    query = select(Device).where(Device.user_id == current_user.id)
    count_query = select(func.count(Device.id)).where(Device.user_id == current_user.id)

    # Lifecycle filter (STEP 5): archived devices leave the default view
    # but remain fully queryable. Composes (AND) with every other filter.
    if lifecycle == "active":
        query = query.where(Device.is_active == True)  # noqa: E712
        count_query = count_query.where(Device.is_active == True)  # noqa: E712
    elif lifecycle == "archived":
        query = query.where(Device.is_active == False)  # noqa: E712
        count_query = count_query.where(Device.is_active == False)  # noqa: E712
    
    if vendor:
        query = query.where(Device.vendor == vendor)
        count_query = count_query.where(Device.vendor == vendor)

    if platform:
        query = query.where(Device.platform == platform)
        count_query = count_query.where(Device.platform == platform)

    if search:
        term = f"%{_like_escape(search.strip())}%"
        search_filter = or_(
            Device.name.ilike(term, escape="\\"),
            Device.ip_address.ilike(term, escape="\\"),
            Device.vendor.ilike(term, escape="\\"),
            Device.platform.ilike(term, escape="\\"),
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(Device.created_at.desc())

    # Execute query
    result = await db.execute(query)
    devices = result.scalars().all()

    # Derived inventory fields in bounded aggregate queries (no N+1).
    items = await _populate_inventory_fields(db, list(devices), current_user)

    return DeviceListResponse(
        items=items,
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
        ),
    )


@router.post("/", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def create_device(
    device: DeviceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new device"""
    new_device = Device(
        user_id=current_user.id,
        name=device.name,
        vendor=device.vendor,
        platform=device.platform,
        firmware_version=device.firmware_version,
        ip_address=device.ip_address,
        notes=device.notes,
    )
    
    db.add(new_device)
    await db.flush()
    await db.refresh(new_device)
    
    response = DeviceResponse.from_orm(new_device).dict()
    response["configuration_count"] = 0
    
    return DeviceResponse(**response)


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a device by ID"""
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.user_id == current_user.id,
        )
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Get configuration count
    config_count_result = await db.execute(
        select(func.count(Configuration.id)).where(Configuration.device_id == device.id)
    )
    config_count = config_count_result.scalar()
    
    response = DeviceResponse.from_orm(device).dict()
    response["configuration_count"] = config_count
    
    return DeviceResponse(**response)


@router.put("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: UUID,
    device_update: DeviceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a device"""
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.user_id == current_user.id,
        )
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Update fields
    update_data = device_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(device, field, value)
    
    await db.flush()
    await db.refresh(device)
    
    response = DeviceResponse.from_orm(device).dict()
    response["configuration_count"] = 0
    
    return DeviceResponse(**response)


@router.post("/{device_id}/archive", response_model=DeviceResponse)
async def archive_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auditor),
):
    """Archive a device: leaves the active inventory, keeps all history.

    Idempotent: archiving an archived device succeeds with no change.
    Ownership follows the devices-file convention (foreign -> 404).
    """
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.user_id == current_user.id,
        )
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.is_active = False
    await db.flush()
    await db.refresh(device)

    response = DeviceResponse.from_orm(device).dict()
    response["configuration_count"] = (
        await db.execute(
            select(func.count(Configuration.id)).where(
                Configuration.device_id == device.id
            )
        )
    ).scalar()
    return DeviceResponse(**response)


@router.post("/{device_id}/unarchive", response_model=DeviceResponse)
async def unarchive_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auditor),
):
    """Restore an archived device to the active inventory.

    Idempotent: unarchiving an active device succeeds with no change.
    Preserves all configurations, audits, findings, and reports.
    """
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.user_id == current_user.id,
        )
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.is_active = True
    await db.flush()
    await db.refresh(device)

    response = DeviceResponse.from_orm(device).dict()
    response["configuration_count"] = (
        await db.execute(
            select(func.count(Configuration.id)).where(
                Configuration.device_id == device.id
            )
        )
    ).scalar()
    return DeviceResponse(**response)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a device"""
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.user_id == current_user.id,
        )
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # STEP 5 delete policy: deleting a device cascades into configurations
    # and severs audit evidence lineage. Dependency-free devices may be
    # removed; anything with configuration or audit history is blocked
    # with counts so the caller can archive instead. No partial state:
    # the check and the delete share one transaction.
    config_count = (
        await db.execute(
            select(func.count(Configuration.id)).where(
                Configuration.device_id == device.id
            )
        )
    ).scalar()
    audit_count = (
        await db.execute(
            select(func.count(Audit.id))
            .select_from(Audit)
            .join(
                AuditConfiguration,
                AuditConfiguration.audit_id == Audit.id,
            )
            .join(
                Configuration,
                Configuration.id == AuditConfiguration.configuration_id,
            )
            .where(Configuration.device_id == device.id)
        )
    ).scalar()
    if (config_count or 0) > 0 or (audit_count or 0) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"This device has {config_count} configuration(s) and "
                f"{audit_count} audit(s) and cannot be permanently deleted. "
                "Archive it instead to preserve historical records."
            ),
        )

    await db.delete(device)
    await db.flush()

    return None


@router.get("/{device_id}/configurations", response_model=DeviceConfigurationHistoryResponse)
async def list_device_configurations(
    device_id: UUID,
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Configuration snapshot history for one device, newest-first.

    Read-only projection over immutable Configuration rows: nothing is
    created, updated, or reordered here. `latest` and `audit_count` are
    derived per request; no raw content is exposed (use the content
    endpoint). Ownership enforced via the STEP 1 scope predicate —
    foreign devices are rejected, nonexistent devices 404.
    """
    # Ownership first: fail closed before touching any configuration data.
    await resolve_owned_device(db, device_id, current_user)

    base_filter = Configuration.device_id == device_id
    ordering = (Configuration.uploaded_at.desc(), Configuration.id.desc())

    total = (
        await db.execute(select(func.count(Configuration.id)).where(base_filter))
    ).scalar()

    # Global newest id: `latest` stays correct across pages.
    latest_id = None
    if total:
        latest_id = (
            await db.execute(
                select(Configuration.id).where(base_filter).order_by(*ordering).limit(1)
            )
        ).scalar_one_or_none()

    offset = (page - 1) * per_page
    rows = (
        await db.execute(
            select(Configuration).where(base_filter).order_by(*ordering).offset(offset).limit(per_page)
        )
    ).scalars().all()
    page_ids = [c.id for c in rows]

    # Audit counts in ONE aggregate query (no N+1). Non-admin counts only
    # their own audits so foreign legacy associations never leak.
    audit_counts: dict = {}
    detection: dict = {}
    if page_ids:
        count_q = (
            select(AuditConfiguration.configuration_id, func.count(AuditConfiguration.audit_id))
            .where(AuditConfiguration.configuration_id.in_(page_ids))
        )
        det_q = (
            select(
                AuditConfiguration.configuration_id,
                AuditConfiguration.vendor_identification,
                Audit.created_at,
            )
            .join(Audit, Audit.id == AuditConfiguration.audit_id)
            .where(AuditConfiguration.configuration_id.in_(page_ids))
            .order_by(Audit.created_at.desc())
        )
        if current_user.role != "admin":
            count_q = count_q.join(Audit, Audit.id == AuditConfiguration.audit_id).where(
                Audit.user_id == current_user.id
            )
            det_q = det_q.where(Audit.user_id == current_user.id)
        for cfg_id, n in (await db.execute(count_q.group_by(AuditConfiguration.configuration_id))).all():
            audit_counts[cfg_id] = n
        for cfg_id, vi, _ in (await db.execute(det_q)).all():
            # First row per config wins (ordered newest audit first).
            if cfg_id not in detection and isinstance(vi, dict):
                detection[cfg_id] = vi

    items = []
    for config in rows:
        vi = detection.get(config.id) or {}
        item = DeviceConfigurationHistoryItem.from_orm(config).dict()
        item.update(
            device_id=config.device_id,
            content_hash=config.content_hash,
            latest=(latest_id is not None and config.id == latest_id),
            audit_count=audit_counts.get(config.id, 0),
            detected_vendor=vi.get("vendor"),
            detected_platform=vi.get("platform"),
            detected_hostname=vi.get("hostname"),
        )
        items.append(DeviceConfigurationHistoryItem(**item))

    return DeviceConfigurationHistoryResponse(
        items=items,
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page if total else 0,
        ),
    )


@router.get("/{device_id}/audits", response_model=DeviceAuditHistoryResponse)
async def list_device_audits(
    device_id: UUID,
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Audit history for one device, derived through AuditConfiguration.

    One row per (audit, configuration) association, newest audit first.
    Read-only: no Audit.device_id column, no history rewrite. Ownership
    enforced via the STEP 1 scope predicate; non-admin rows are further
    restricted to the caller's own audits.
    """
    await resolve_owned_device(db, device_id, current_user)

    base = (
        select(Audit, AuditConfiguration.configuration_id, Configuration.filename)
        .join(AuditConfiguration, AuditConfiguration.audit_id == Audit.id)
        .join(Configuration, Configuration.id == AuditConfiguration.configuration_id)
        .where(Configuration.device_id == device_id)
    )
    if current_user.role != "admin":
        base = base.where(Audit.user_id == current_user.id)
    ordering = (Audit.created_at.desc(), Audit.id.desc())

    total = (
        await db.execute(select(func.count()).select_from(base.subquery()))
    ).scalar()

    offset = (page - 1) * per_page
    rows = (
        await db.execute(base.order_by(*ordering).offset(offset).limit(per_page))
    ).all()

    items = [
        DeviceAuditHistoryItem(
            id=audit.id,
            name=audit.name,
            status=audit.status,
            overall_score=audit.overall_score,
            configuration_id=configuration_id,
            configuration_filename=filename,
            created_at=audit.created_at,
        )
        for audit, configuration_id, filename in rows
    ]

    return DeviceAuditHistoryResponse(
        items=items,
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page if total else 0,
        ),
    )
