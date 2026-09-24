from fastapi import APIRouter, HTTPException, Query, status, Depends, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from uuid import UUID
import hashlib

from app.database import get_db
from app.models import User, Configuration
from app.schemas import ConfigurationResponse, ConfigurationContentResponse, ConfigurationListResponse, PaginationMeta
from app.security.auth import get_current_user, require_admin, require_auditor
from app.config import settings

router = APIRouter()


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


def calculate_content_hash(content: bytes) -> str:
    """Calculate SHA-256 hash of file content"""
    return hashlib.sha256(content).hexdigest()


@router.post("/upload", response_model=ConfigurationResponse, status_code=status.HTTP_201_CREATED)
async def upload_configuration(
    file: UploadFile = File(...),
    device_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auditor),
):
    """Upload a configuration file"""
    # Validate file extension
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required"
        )
    
    file_ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if file_ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension {file_ext} not allowed. Allowed: {settings.ALLOWED_EXTENSIONS}"
        )
    
    # Read file content
    content = await file.read()
    
    # Validate file size
    max_size = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(content) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds maximum of {settings.MAX_UPLOAD_SIZE_MB}MB"
        )
    
    # Calculate hash
    content_hash = calculate_content_hash(content)
    
    # Check for duplicate — return existing instead of erroring
    existing = await db.execute(
        select(Configuration).where(Configuration.content_hash == content_hash)
    )
    existing_config = existing.scalar_one_or_none()
    if existing_config:
        return ConfigurationResponse.from_orm(existing_config)
    
    # Decode content
    try:
        raw_content = content.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        try:
            raw_content = content.decode("latin-1")
            encoding = "latin-1"
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to decode file content"
            )
    
    # Count lines
    line_count = len(raw_content.splitlines())
    
    # Create configuration record
    config = Configuration(
        device_id=device_id,
        filename=file.filename,
        content_hash=content_hash,
        raw_content=raw_content,
        content_type=file.content_type or "text/plain",
        size_bytes=len(content),
        line_count=line_count,
        encoding=encoding,
    )
    
    db.add(config)
    await db.flush()
    await db.refresh(config)
    
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
