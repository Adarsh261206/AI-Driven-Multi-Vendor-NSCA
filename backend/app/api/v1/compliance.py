from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional

from app.models import User
from app.schemas import FrameworkResponse, ControlResponse, FrameworkListResponse, ControlListResponse, PaginationMeta
from app.security.auth import get_current_user
from app.benchmarks.registry import ControlRegistry
from app.benchmarks.cisco_ios_xe_controls import get_all_controls as get_cisco_controls
from app.benchmarks.juniper_junos_controls import get_all_controls as get_juniper_controls
from app.benchmarks.nist_sp800_53_controls import get_all_controls as get_nist_controls
from app.benchmarks.models import BenchmarkControl

router = APIRouter()

# Initialize registry with all benchmark controls
_control_registry = ControlRegistry()

def _initialize_registry():
    """Initialize the control registry with all benchmark controls."""
    # Register Cisco controls
    for control in get_cisco_controls():
        _control_registry.register_control(control)
    
    # Register Juniper controls
    for control in get_juniper_controls():
        _control_registry.register_control(control)

    # Register NIST controls
    for control in get_nist_controls():
        _control_registry.register_control(control)

_initialize_registry()

# Framework definitions
FRAMEWORKS = {
    "CIS": FrameworkResponse(
        id="CIS",
        name="CIS Benchmarks",
        description="Center for Internet Security Benchmarks — vendor-specific configuration controls for Cisco IOS XE and Juniper JunOS",
        versions=["2024.1", "2023.1"],
        control_count=len([c for c in get_cisco_controls()] + [c for c in get_juniper_controls()]),
        categories=sorted(set(c.category for c in list(get_cisco_controls()) + list(get_juniper_controls()))),
    ),
    "NIST": FrameworkResponse(
        id="NIST",
        name="NIST SP 800-53 Rev. 5",
        description="NIST Special Publication 800-53 Revision 5 — comprehensive security and privacy controls catalog applicable to network device configurations",
        versions=["5.0"],
        control_count=len(get_nist_controls()),
        categories=sorted(set(c.category for c in get_nist_controls())),
    ),
}


def _control_to_response(control: BenchmarkControl) -> ControlResponse:
    """Convert a BenchmarkControl to ControlResponse."""
    return ControlResponse(
        id=control.control_id,
        framework="CIS" if control.vendor in ("cisco", "juniper") else "NIST",
        framework_version=control.benchmark_version,
        title=control.title,
        description=control.description,
        category=control.category,
        severity=control.severity.value if hasattr(control.severity, 'value') else str(control.severity),
        vendor=control.vendor,
        platform=control.platform,
        references=control.references,
    )


@router.get("/frameworks", response_model=FrameworkListResponse)
async def list_frameworks(current_user: User = Depends(get_current_user)):
    """List all compliance frameworks"""
    return FrameworkListResponse(items=list(FRAMEWORKS.values()))


@router.get("/frameworks/{framework_id}/controls", response_model=ControlListResponse)
async def list_framework_controls(
    framework_id: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    platform: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
    current_user: User = Depends(get_current_user),
):
    """List controls for a framework"""
    framework_id_upper = framework_id.upper()

    if framework_id_upper == "NIST":
        # NIST controls are stored with vendor="universal" and platform="network_device"
        all_controls = [c for c in get_nist_controls()]
    else:
        # CIS controls — get from registry
        if vendor and platform:
            all_controls = _control_registry.get_controls_by_vendor_platform(vendor, platform)
        elif category:
            all_controls = _control_registry.get_controls_by_category(category)
        else:
            all_controls = list(_control_registry._controls.values())
        # Filter to only CIS framework controls (exclude NIST)
        all_controls = [c for c in all_controls if c.vendor in ("cisco", "juniper")]

    # Filter by category if specified
    if category:
        all_controls = [c for c in all_controls if c.category == category]
    
    # Filter by severity if specified
    if severity:
        all_controls = [c for c in all_controls if (c.severity.value if hasattr(c.severity, 'value') else str(c.severity)) == severity]
    
    # Convert to response format
    filtered_controls = [_control_to_response(c) for c in all_controls]
    
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
    control = _control_registry.get_control(control_id)
    if control:
        return _control_to_response(control)
    
    raise HTTPException(status_code=404, detail="Control not found")
