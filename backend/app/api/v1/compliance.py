from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional

from app.models import User
from app.schemas import FrameworkResponse, ControlResponse, FrameworkListResponse, ControlListResponse, PaginationMeta
from app.security.auth import get_current_user

router = APIRouter()

# Framework definitions (will be loaded from database in future)
FRAMEWORKS = {
    "CIS": FrameworkResponse(
        id="CIS",
        name="CIS Benchmarks",
        description="Center for Internet Security Benchmarks",
        versions=["2024.1", "2023.1"],
        control_count=45,
        categories=["management", "ssh", "authentication", "logging", "access_control"],
    ),
    "NIST": FrameworkResponse(
        id="NIST",
        name="NIST SP 800-53",
        description="NIST Special Publication 800-53",
        versions=["5.0", "4.0"],
        control_count=30,
        categories=["access_control", "audit", "configuration_management"],
    ),
}

# Sample controls (will be loaded from database in future)
CONTROLS = [
    ControlResponse(
        id="CIS-Cisco-IOS-1.1",
        framework="CIS",
        framework_version="2024.1",
        title="Disable HTTP Server",
        description="The HTTP server feature allows web-based management of the device using HTTP. HTTP transmits data in clear text, which can expose sensitive information including credentials.",
        category="management",
        severity="HIGH",
        vendor="cisco",
        platform="ios",
    ),
    ControlResponse(
        id="CIS-Cisco-IOS-1.2",
        framework="CIS",
        framework_version="2024.1",
        title="Enable HTTPS Server",
        description="The HTTPS server provides secure web-based management of the device.",
        category="management",
        severity="HIGH",
        vendor="cisco",
        platform="ios",
    ),
    ControlResponse(
        id="CIS-Cisco-IOS-1.3",
        framework="CIS",
        framework_version="2024.1",
        title="Disable Telnet",
        description="Telnet transmits data in clear text, which can expose sensitive information including credentials.",
        category="management",
        severity="HIGH",
        vendor="cisco",
        platform="ios",
    ),
    ControlResponse(
        id="CIS-Cisco-IOS-1.4",
        framework="CIS",
        framework_version="2024.1",
        title="Enable SSH",
        description="SSH provides secure remote access to the device.",
        category="ssh",
        severity="HIGH",
        vendor="cisco",
        platform="ios",
    ),
    ControlResponse(
        id="CIS-Cisco-IOS-1.5",
        framework="CIS",
        framework_version="2024.1",
        title="Use SSH Version 2",
        description="SSH version 2 provides improved security over version 1.",
        category="ssh",
        severity="HIGH",
        vendor="cisco",
        platform="ios",
    ),
]


@router.get("/frameworks", response_model=FrameworkListResponse)
async def list_frameworks(current_user: User = Depends(get_current_user)):
    """List all compliance frameworks"""
    return FrameworkListResponse(items=list(FRAMEWORKS.values()))


@router.get("/frameworks/{framework_id}/controls", response_model=ControlListResponse)
async def list_framework_controls(
    framework_id: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
    current_user: User = Depends(get_current_user),
):
    """List controls for a framework"""
    # Filter controls
    filtered_controls = [c for c in CONTROLS if c.framework == framework_id]
    
    if category:
        filtered_controls = [c for c in filtered_controls if c.category == category]
    
    if severity:
        filtered_controls = [c for c in filtered_controls if c.severity == severity]
    
    # Apply pagination
    total = len(filtered_controls)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_controls = filtered_controls[start:end]
    
    return ControlListResponse(
        items=paginated_controls,
        meta=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
        ),
    )


@router.get("/controls/{control_id}", response_model=ControlResponse)
async def get_control(
    control_id: str,
    current_user: User = Depends(get_current_user),
):
    """Get control details"""
    for control in CONTROLS:
        if control.id == control_id:
            return control
    
    raise HTTPException(status_code=404, detail="Control not found")
