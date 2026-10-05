from fastapi import APIRouter, HTTPException, Query, status, Depends, UploadFile, File
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
from app.schemas import ConfigurationResponse, ConfigurationContentResponse, ConfigurationListResponse, PaginationMeta
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
        # Preserved API semantics: identical content is idempotent and
        # returns the existing row. Detection itself lives in the
        # engine — this only fetches the row the engine identified.
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
