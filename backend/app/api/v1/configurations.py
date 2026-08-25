from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from uuid import UUID
import hashlib

from app.database import get_db
from app.models import User, Configuration
from app.schemas import ConfigurationResponse, ConfigurationContentResponse
from app.security.auth import get_current_user
from app.config import settings

router = APIRouter()


def calculate_content_hash(content: bytes) -> str:
    """Calculate SHA-256 hash of file content"""
    return hashlib.sha256(content).hexdigest()


@router.post("/upload", response_model=ConfigurationResponse, status_code=status.HTTP_201_CREATED)
async def upload_configuration(
    file: UploadFile = File(...),
    device_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
    
    # Check for duplicate
    existing = await db.execute(
        select(Configuration).where(Configuration.content_hash == content_hash)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Configuration with same content already exists"
        )
    
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
    
    return ConfigurationContentResponse(content=config.raw_content)


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_configuration(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
