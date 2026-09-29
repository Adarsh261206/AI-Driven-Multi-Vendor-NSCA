from fastapi import APIRouter, HTTPException, Depends
from typing import Optional

from app.models import User
from app.schemas import FrameworkResponse, ControlResponse, FrameworkListResponse, ControlListResponse, PaginationMeta
from app.security.auth import get_current_user
from app.benchmarks.registry import ControlRegistry
from app.benchmarks.cisco_ios_xe_controls import get_registry as cisco_registry
from app.benchmarks.juniper_junos_controls import get_registry as juniper_registry
from app.benchmarks.nist_sp800_53_controls import get_registry as nist_registry
from app.benchmarks.models import BenchmarkControl
from app.benchmarks.selection import (
    ComplianceError,
    ControlSelectionService,
)

router = APIRouter()

# Initialize registry with all benchmark controls (attributed at build time).
_control_registry = ControlRegistry()
_control_registry.register_benchmark(cisco_registry())
_control_registry.register_benchmark(juniper_registry())
_control_registry.register_benchmark(nist_registry())

# The SAME selection contract as the evaluator (F2) — no independent
# filtering rules in the API layer.
_selection = ControlSelectionService(
    list(_control_registry._controls.values()))


_FRAMEWORK_DESCRIPTIONS = {
    "CIS": ("CIS Benchmarks",
            "Center for Internet Security Benchmarks — vendor-specific "
            "configuration controls for Cisco IOS XE and Juniper JunOS"),
    "NIST": ("NIST SP 800-53 Rev. 5",
             "NIST Special Publication 800-53 Revision 5 — comprehensive "
             "security and privacy controls catalog applicable to network "
             "device configurations"),
}


def _frameworks() -> dict[str, FrameworkResponse]:
    """Framework inventory derived from the loaded controls (F1/F3).

    Versions, counts and categories come from the control definitions —
    never hardcoded, never advertised beyond what the registry contains.
    """
    out: dict[str, FrameworkResponse] = {}
    meta = _selection.frameworks()
    for framework_id, info in meta.items():
        name, description = _FRAMEWORK_DESCRIPTIONS.get(
            framework_id, (framework_id, ""))
        controls = [c for c in _control_registry._controls.values()
                    if c.framework == framework_id]
        out[framework_id] = FrameworkResponse(
            id=framework_id,
            name=name,
            description=description,
            versions=info["versions"],
            control_count=len(controls),
            categories=sorted({c.category for c in controls}),
        )
    return out


def _control_to_response(control: BenchmarkControl) -> ControlResponse:
    """Convert a BenchmarkControl to ControlResponse.

    Framework attribution comes from the control's own metadata (F3).
    """
    return ControlResponse(
        id=control.control_id,
        framework=control.framework,
        framework_version=control.framework_version,
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
    return FrameworkListResponse(items=list(_frameworks().values()))


@router.get("/frameworks/{framework_id}/controls", response_model=ControlListResponse)
async def list_framework_controls(
    framework_id: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    platform: Optional[str] = None,
    framework_version: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
    current_user: User = Depends(get_current_user),
):
    """List controls for a framework.

    Filtering runs through the canonical selection service (F2): the path
    framework, vendor, platform and framework_version filters all apply
    conjunctively. Unknown framework/version values are typed 422 errors,
    never silent fallbacks or unrelated controls.
    """
    try:
        selection = _selection.select(
            vendor=vendor, platform=platform, framework=framework_id,
            framework_version=framework_version)
    except ComplianceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    all_controls = selection.controls

    # Filter by category if specified
    if category:
        all_controls = [c for c in all_controls if c.category == category]

    # Filter by severity if specified
    if severity:
        all_controls = [c for c in all_controls
                        if (c.severity.value if hasattr(c.severity, 'value')
                            else str(c.severity)) == severity]
    
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
