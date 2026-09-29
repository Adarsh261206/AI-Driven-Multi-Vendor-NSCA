from fastapi import APIRouter, HTTPException, Query, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from uuid import UUID

from app.database import get_db
from app.models import User, Device, Configuration
from app.schemas import DeviceCreate, DeviceUpdate, DeviceResponse, DeviceListResponse, PaginationMeta
from app.security.auth import get_current_user

router = APIRouter()


@router.get("/", response_model=DeviceListResponse)
async def list_devices(
    page: int = Query(1, gt=0),
    per_page: int = Query(20, gt=0, le=100),
    vendor: Optional[str] = None,
    platform: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all devices for the current user"""
    # Build query
    query = select(Device).where(Device.user_id == current_user.id)
    count_query = select(func.count(Device.id)).where(Device.user_id == current_user.id)
    
    if vendor:
        query = query.where(Device.vendor == vendor)
        count_query = count_query.where(Device.vendor == vendor)
    
    if platform:
        query = query.where(Device.platform == platform)
        count_query = count_query.where(Device.platform == platform)
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(Device.created_at.desc())
    
    # Execute query
    result = await db.execute(query)
    devices = result.scalars().all()
    
    # Get configuration counts for each device
    items = []
    for device in devices:
        config_count_result = await db.execute(
            select(func.count(Configuration.id)).where(Configuration.device_id == device.id)
        )
        config_count = config_count_result.scalar()
        
        device_dict = DeviceResponse.from_orm(device).dict()
        device_dict["configuration_count"] = config_count
        items.append(DeviceResponse(**device_dict))
    
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
    
    await db.delete(device)
    await db.flush()
    
    return None
