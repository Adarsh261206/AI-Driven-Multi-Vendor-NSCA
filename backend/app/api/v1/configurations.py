from fastapi import APIRouter, HTTPException, Query, status, Depends, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from uuid import UUID

from app.database import get_db
from app.engines.ingestion import (
    DuplicateConfigurationError,
    FileTooLargeError,
    IngestionEngine,
    IngestionError,
)
from app.models import User, Configuration
from app.models import AuditAction
from app.repositories.audit_trail import AuditTrailRepository
from app.services.scope import resolve_owned_device
from app.schemas import ConfigurationResponse, ConfigurationContentResponse, ConfigurationListResponse, PaginationMeta, BulkUploadItemResult, BulkUploadSummary, BulkUploadResponse
from app.security.auth import get_current_user, require_admin, require_auditor
from app.config import settings

router = APIRouter()

# Read granularity for bounded upload reading (E01 N10).
_UPLOAD_CHUNK_BYTES = 1024 * 1024


@router.get("/", response_model=ConfigurationListResponse)
async def list_configurations(
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    device_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all configurations for the current user"""
    query = select(Configuration)
    count_query = select(func.count(Configuration.id))

    if current_user.role != "admin":
        from app.models import Device
        user_device_ids = select(Device.id).where(Device.user_id == current_user.id)
        query = query.where(
            (Configuration.device_id.in_(user_device_ids)) | (Configuration.device_id.is_(None))
        )
        count_query = count_query.where(
            (Configuration.device_id.in_(user_device_ids)) | (Configuration.device_id.is_(None))
        )

    if device_id:
        # Ownership first: a user may only link uploads to their own
        # devices. 404 when the device does not exist at all, 403 when it
        # exists but belongs to another user. Admins may link anywhere.
        await resolve_owned_device(db, device_id, current_user)
        query = query.where(Configuration.device_id == device_id)
        count_query = count_query.where(Configuration.device_id == device_id)

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(Configuration.uploaded_at.desc())
    result = await db.execute(query)
    configs = result.scalars().all()

    return ConfigurationListResponse(
        items=[ConfigurationResponse.from_orm(c) for c in configs],
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page if total else 0,
        ),
    )


@router.post("/upload", response_model=ConfigurationResponse, status_code=status.HTTP_201_CREATED)
async def upload_configuration(
    file: UploadFile = File(...),
    device_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auditor),
):
    """Upload a configuration file.

    Transport-level handling only: this route performs a bounded read
    of the uploaded part and then delegates every ingestion rule —
    extension, size, filename safety, content validation, content type,
    duplicate detection, device association, persistence — to
    IngestionEngine, the single source of truth for ingestion
    (E01 F9/N10).
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required"
        )

    max_size = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    if device_id is not None:
        # Ownership gate BEFORE ingestion: a foreign device is rejected
        # here (403). A nonexistent device falls through to the engine,
        # which owns that contract (V01-62 pins its typed 400).
        device = await resolve_owned_device(
            db, device_id, current_user, allow_missing=True
        )
        if device is not None and not device.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Device is archived and cannot accept new configurations. "
                    "Unarchive it first; existing history is preserved."
                ),
            )

    # Bounded read: stop as soon as the upload exceeds the limit so an
    # oversized body is never fully materialised in memory (N10). The
    # ASGI-level guard in app/main.py rejects oversized requests even
    # earlier — before multipart parsing begins.
    buffer = bytearray()
    while True:
        chunk = await file.read(_UPLOAD_CHUNK_BYTES)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File size exceeds maximum of {settings.MAX_UPLOAD_SIZE_MB}MB"
            )
    content = bytes(buffer)

    engine = IngestionEngine(db)
    try:
        result = await engine.ingest(
            file_content=content,
            filename=file.filename,
            content_type=file.content_type,
            device_id=device_id,
        )
    except DuplicateConfigurationError as exc:
        # Preserved API semantics: an in-scope duplicate (same bytes on
        # the same device, or any same-hash row for a device-less upload)
        # is idempotent and returns the existing row. Detection itself
        # lives in the engine — this only fetches the row the engine
        # identified. Cross-device identical content is NOT a duplicate:
        # the engine stores it as a new row for the target device, so
        # fleet-wide golden configs upload once per device.
        # E12: the idempotent replay is still an access event — logged
        # with duplicate=true so history distinguishes replays from
        # newly stored configurations.
        if exc.configuration_id is not None:
            existing = await db.get(Configuration, exc.configuration_id)
            if existing is not None:
                trail = AuditTrailRepository(db)
                await trail.log(
                    action=AuditAction.CONFIG_UPLOADED,
                    entity_type="configuration",
                    entity_id=str(existing.id),
                    user_id=str(current_user.id),
                    details={
                        "filename": file.filename,
                        "duplicate": True,
                        "configuration_id": str(existing.id),
                    },
                )
                await db.flush()
                return ConfigurationResponse.from_orm(existing)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Configuration with identical content already exists",
        )
    except FileTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        )
    except IngestionError as exc:
        # Every predictable input problem arrives here as a typed
        # engine error; raw DB/Python exceptions never do.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    config = await db.get(Configuration, result.configuration_id)
    if config is None:  # pragma: no cover - flush guarantees the row
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ingested configuration could not be loaded",
        )
    # E12: a newly stored configuration is a tracked change.
    trail = AuditTrailRepository(db)
    await trail.log(
        action=AuditAction.CONFIG_UPLOADED,
        entity_type="configuration",
        entity_id=str(config.id),
        user_id=str(current_user.id),
        details={
            "filename": file.filename,
            "content_type": file.content_type,
            "size_bytes": len(content),
            "duplicate": False,
            "configuration_id": str(config.id),
        },
    )
    await db.flush()
    return ConfigurationResponse.from_orm(config)


# Bulk batch caps: bounded per-file reads (same 10MB rule as single
# upload) plus a hard item cap so one request cannot exhaust workers.
MAX_BULK_FILES = 20


@router.post("/bulk", response_model=BulkUploadResponse)
async def bulk_upload_configurations(
    files: List[UploadFile] = File(...),
    device_map: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auditor),
):
    """Upload many configurations, each explicitly mapped to one device.

    `device_map` is a JSON array of device-id strings aligned positionally
    with `files` (files[i] belongs to device_map[i]). Two-phase semantics:
      1. ENVELOPE validation (atomic): every device mapping must resolve
         owned + active. ANY mapping failure rejects the WHOLE batch with
         zero rows persisted.
      2. INGESTION (per-file): each file runs the same IngestionEngine
         path as single upload. A bad file yields an `invalid` item; valid
         siblings still persist. Identical content replays honestly as
         `duplicate` with the existing configuration id (dedup preserved).
    """
    import json as _json

    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one file is required",
        )
    if len(files) > MAX_BULK_FILES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"At most {MAX_BULK_FILES} files per bulk upload",
        )
    try:
        parsed_map = _json.loads(device_map)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="device_map must be a JSON array of device-id strings",
        )
    if not isinstance(parsed_map, list) or len(parsed_map) != len(files):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "device_map must align positionally with files: "
                f"got {len(files)} files and "
                f"{len(parsed_map) if isinstance(parsed_map, list) else '?'} "
                "device mappings"
            ),
        )

    # Phase 1 — envelope: resolve every target device BEFORE any ingestion.
    targets: list = []
    for raw_device_id in parsed_map:
        if not raw_device_id or not str(raw_device_id).strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Every bulk item requires an explicit target device_id",
            )
        try:
            parsed_device_id = UUID(str(raw_device_id).strip())
        except (ValueError, AttributeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid device_id mapping: {raw_device_id!r}",
            )
        device = await resolve_owned_device(db, parsed_device_id, current_user)
        if not device.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Device is archived and cannot accept new configurations. "
                    "Unarchive it first; existing history is preserved."
                ),
            )
        targets.append(device)

    # Phase 2 — per-file ingestion through the single engine path.
    max_size = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    engine = IngestionEngine(db)
    items: List[BulkUploadItemResult] = []
    for upload_file, device in zip(files, targets):
        filename = upload_file.filename or "unnamed"
        try:
            buffer = bytearray()
            while True:
                chunk = await upload_file.read(_UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                buffer.extend(chunk)
                if len(buffer) > max_size:
                    raise FileTooLargeError(
                        f"File size exceeds maximum of {settings.MAX_UPLOAD_SIZE_MB}MB"
                    )
            result = await engine.ingest(
                file_content=bytes(buffer),
                filename=upload_file.filename,
                content_type=upload_file.content_type,
                device_id=device.id,
            )
            config = await db.get(Configuration, result.configuration_id)
            trail = AuditTrailRepository(db)
            await trail.log(
                action=AuditAction.CONFIG_UPLOADED,
                entity_type="configuration",
                entity_id=str(config.id),
                user_id=str(current_user.id),
                details={
                    "filename": filename,
                    "duplicate": False,
                    "configuration_id": str(config.id),
                },
            )
            await db.flush()
            items.append(
                BulkUploadItemResult(
                    filename=filename,
                    status="stored",
                    configuration_id=config.id,
                )
            )
        except DuplicateConfigurationError as exc:
            if exc.configuration_id is not None:
                existing = await db.get(Configuration, exc.configuration_id)
                if existing is not None:
                    trail = AuditTrailRepository(db)
                    await trail.log(
                        action=AuditAction.CONFIG_UPLOADED,
                        entity_type="configuration",
                        entity_id=str(existing.id),
                        user_id=str(current_user.id),
                        details={
                            "filename": filename,
                            "duplicate": True,
                            "configuration_id": str(existing.id),
                        },
                    )
                    await db.flush()
                    items.append(
                        BulkUploadItemResult(
                            filename=filename,
                            status="duplicate",
                            configuration_id=existing.id,
                        )
                    )
                    continue
            items.append(
                BulkUploadItemResult(
                    filename=filename,
                    status="invalid",
                    error="Configuration with identical content already exists",
                )
            )
        except (FileTooLargeError, IngestionError) as exc:
            items.append(
                BulkUploadItemResult(
                    filename=filename, status="invalid", error=str(exc)
                )
            )

    summary = BulkUploadSummary(
        total=len(items),
        stored=sum(1 for i in items if i.status == "stored"),
        duplicate=sum(1 for i in items if i.status == "duplicate"),
        invalid=sum(1 for i in items if i.status == "invalid"),
    )
    return BulkUploadResponse(items=items, summary=summary)


@router.get("/{config_id}", response_model=ConfigurationResponse)
async def get_configuration(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a configuration by ID"""
    result = await db.execute(
        select(Configuration).where(Configuration.id == config_id)
    )
    config = result.scalar_one_or_none()
    
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
    
    # Authorization check: admin can access all, others only their own device's configs
    if current_user.role != "admin":
        if config.device_id:
            # Check if the device belongs to the current user
            from app.models import Device
            device_result = await db.execute(
                select(Device).where(
                    Device.id == config.device_id,
                    Device.user_id == current_user.id,
                )
            )
            if not device_result.scalar_one_or_none():
                raise HTTPException(status_code=403, detail="Not authorized to access this configuration")
        else:
            raise HTTPException(status_code=403, detail="Not authorized to access this configuration")
    
    return ConfigurationResponse.from_orm(config)


@router.get("/{config_id}/content", response_model=ConfigurationContentResponse)
async def get_configuration_content(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get configuration content"""
    result = await db.execute(
        select(Configuration).where(Configuration.id == config_id)
    )
    config = result.scalar_one_or_none()
    
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
    
    # Authorization check: admin can access all, others only their own device's configs
    if current_user.role != "admin":
        if config.device_id:
            # Check if the device belongs to the current user
            from app.models import Device
            device_result = await db.execute(
                select(Device).where(
                    Device.id == config.device_id,
                    Device.user_id == current_user.id,
                )
            )
            if not device_result.scalar_one_or_none():
                raise HTTPException(status_code=403, detail="Not authorized to access this configuration")
        else:
            raise HTTPException(status_code=403, detail="Not authorized to access this configuration")
    
    return ConfigurationContentResponse(content=config.raw_content)


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_configuration(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Delete a configuration"""
    result = await db.execute(
        select(Configuration).where(Configuration.id == config_id)
    )
    config = result.scalar_one_or_none()
    
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
    
    await db.delete(config)
    await db.flush()
    
    return None
