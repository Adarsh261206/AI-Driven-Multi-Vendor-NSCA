"""Company Baseline API.

Handles onboarding (YES/NO flow), baseline configuration, validation,
activation, and status queries. All endpoints use capability-based
authorization, not hardcoded role names.

Service helpers live in app.services.baseline (validation) and in this
module (onboarding flows, baseline resolution, comparison generation).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import CompanyBaseline, Organization, User
from app.schemas import (
    BaselineUploadRequest,
    BaselineValidationResult,
    CompanyBaselineSummary,
    SideBySideComparison,
)
from app.security.auth import get_current_user
from app.services.baseline import BaselineValidationError, BaselineValidationService

router = APIRouter()


class BaselineState:
    """Enumeration of baseline states."""

    NOT_CONFIGURED = "NOT_CONFIGURED"
    PENDING_VALIDATION = "PENDING_VALIDATION"
    ACTIVE = "ACTIVE"
    REPLACED = "REPLACED"


async def user_has_baseline_capability(user: User, capability: str) -> bool:
    """Check if a user has a specific baseline capability.

    Centralized capability check - not scattered `if role == 'auditor'`
    patterns. Current mapping: AUDITOR/ADMIN -> baseline.configure,
    AUDITOR/ADMIN -> baseline.compare, AUDITOR/ADMIN/VIEWER -> baseline.view.
    """
    if not user:
        return False

    role = user.role

    if capability == "baseline.configure":
        return role in ("auditor", "admin")

    if capability == "baseline.view":
        return role in ("auditor", "admin", "viewer")

    if capability == "baseline.compare":
        return role in ("auditor", "admin")

    # Default: deny unknown capabilities
    return False


async def check_organization_baseline(
    db, organization_id: str
) -> tuple[Optional[CompanyBaseline], str]:
    """Check if an organization has an active baseline.

    Returns (baseline, status_string).
    If no organization has a baseline, returns (None, NOT_CONFIGURED).
    """
    org_result = await db.execute(
        select(Organization).where(Organization.id == organization_id)
    )
    org = org_result.scalar_one_or_none()

    if not org:
        return None, "ORGANIZATION_NOT_FOUND"

    if org.baseline_status == BaselineState.NOT_CONFIGURED:
        return None, "NOT_CONFIGURED"

    if org.baseline_status == BaselineState.ACTIVE:
        baseline_result = await db.execute(
            select(CompanyBaseline).where(
                CompanyBaseline.organization_id == organization_id,
                CompanyBaseline.status == BaselineState.ACTIVE,
            )
        )
        baseline = baseline_result.scalar_one_or_none()
        return baseline, "ACTIVE"

    if org.baseline_status == BaselineState.PENDING_VALIDATION:
        return None, "PENDING_VALIDATION"

    return None, org.baseline_status


async def validate_baseline_controls(
    controls: list[str],
    registry: Optional[Any] = None,
) -> BaselineValidationResult:
    """Validate baseline control IDs against the CIS registry."""
    service = BaselineValidationService(registry)
    try:
        result = service.validate(controls)
        return BaselineValidationResult(
            valid_count=result["valid_count"],
            errors=result["errors"],
            invalid_controls=(
                list(result["invalid_controls"]) if result["invalid_controls"] else []
            ),
        )
    except BaselineValidationError as e:
        invalid = e.errors if e.errors else []
        return BaselineValidationResult(
            valid_count=len(controls) - len(invalid),
            errors=invalid,
            invalid_controls=(
                [err["control_id"] for err in invalid] if invalid else []
            ),
        )


async def _ensure_organization(db, user: User) -> Organization:
    """Return the user's organization, creating one if the user has none.

    Organization is derived from the authenticated user — never from an
    arbitrary client-supplied ID. When the user has no organization, a new
    one is created (company onboarding) and linked to the user.
    """
    org_id = user.organization_id
    if not org_id:
        # Org name derives from the user's unique email local-part —
        # full_name is not unique and would violate organizations.name.
        org = Organization(
            name=user.email.split("@")[0],
            baseline_status=BaselineState.NOT_CONFIGURED,
        )
        db.add(org)
        await db.flush()
        org_id = org.id
        user.organization_id = org_id
        await db.flush()

    org_result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise RuntimeError("Organization not found after creation")
    return org


async def onboarding_yes_flow(
    db,
    user: User,
    baseline_upload: BaselineUploadRequest,
) -> dict[str, Any]:
    """Process the YES flow of onboarding: upload, parse, validate, activate."""
    org = await _ensure_organization(db, user)

    # Service-layer guard: one ACTIVE baseline per org. A second onboarding
    # while a baseline is ACTIVE is a no-op (replacement has its own flow),
    # so the partial unique index never has to fire.
    existing = await get_active_baseline_for_organization(db, org.id)
    if existing is not None:
        return {
            "status": "already_active",
            "activation_blocked": True,
            "reason": "Organization already has an active baseline — use replacement.",
            "baseline": {
                "id": str(existing.id),
                "name": existing.name,
                "framework": existing.framework,
                "benchmark": existing.benchmark,
                "control_count": len(existing.controls) if existing.controls else 0,
                "status": existing.status,
            },
        }

    # Update organization status to PENDING_VALIDATION
    org.baseline_status = BaselineState.PENDING_VALIDATION
    org.updated_at = datetime.utcnow()
    await db.flush()

    # Validate the baseline controls
    validation_result = await validate_baseline_controls(baseline_upload.controls)

    if validation_result.valid_count == 0:
        # Validation failed - cannot activate
        org.baseline_status = BaselineState.NOT_CONFIGURED
        await db.flush()
        return {
            "status": "validation_failed",
            "validation_result": validation_result,
            "activation_blocked": True,
            "reason": "Baseline has no valid controls",
        }

    if validation_result.errors:
        # Some controls are invalid - store validation result but block activation
        org.baseline_status = BaselineState.PENDING_VALIDATION
        await db.flush()
        return {
            "status": "validation_with_errors",
            "validation_result": validation_result,
            "activation_blocked": True,
            "reason": "Baseline has some invalid controls",
        }

    # All controls valid - create and activate the baseline
    baseline = CompanyBaseline(
        organization_id=org.id,
        name=baseline_upload.name,
        framework=baseline_upload.framework,
        benchmark=baseline_upload.benchmark,
        status=BaselineState.ACTIVE,
        controls=baseline_upload.controls,
        created_by=user.email,
        activated_at=datetime.utcnow(),
    )
    db.add(baseline)

    # Update organization
    org.baseline_status = BaselineState.ACTIVE
    org.active_baseline_id = baseline.id
    org.updated_at = datetime.utcnow()

    await db.flush()

    return {
        "status": "activated",
        "validation_result": validation_result,
        "baseline": {
            "id": str(baseline.id),
            "name": baseline.name,
            "framework": baseline.framework,
            "benchmark": baseline.benchmark,
            "control_count": len(baseline.controls),
            "status": baseline.status,
        },
        "activation_blocked": False,
    }


async def onboarding_no_flow(
    db,
    user: User,
) -> dict[str, Any]:
    """Process the NO flow of onboarding: persist NOT_CONFIGURED state."""
    org = await _ensure_organization(db, user)

    # Persist NOT_CONFIGURED state
    org.baseline_status = BaselineState.NOT_CONFIGURED
    org.updated_at = datetime.utcnow()
    await db.flush()

    return {
        "status": "not_configured",
        "baseline_status": BaselineState.NOT_CONFIGURED,
        "evaluation_unavailable": True,
    }


async def get_active_baseline_for_organization(
    db, organization_id: str
) -> Optional[CompanyBaseline]:
    """Get the active baseline for an organization, if any."""
    result = await db.execute(
        select(CompanyBaseline).where(
            CompanyBaseline.organization_id == organization_id,
            CompanyBaseline.status == BaselineState.ACTIVE,
        )
    )
    return result.scalar_one_or_none()


async def replace_baseline(
    db,
    user: User,
    baseline_upload: BaselineUploadRequest,
) -> dict[str, Any]:
    """Atomically replace the organization's active baseline.

    Lifecycle (single transaction, caller commits):
        1. Validate the new control set — invalid input blocks immediately
           and the current baseline is untouched.
        2. Deactivate the current ACTIVE baseline (status → REPLACED).
        3. Persist the new baseline as ACTIVE.
        4. Point the organization at the new baseline.

    The DB-level partial unique index (one ACTIVE per org) plus the
    flush ordering guarantee there is never 0 or 2 active baselines:
    the old row is deactivated before the new row is inserted.
    """
    org = await _ensure_organization(db, user)

    current = await get_active_baseline_for_organization(db, org.id)
    if current is None:
        return {
            "status": "no_active_baseline",
            "activation_blocked": True,
            "reason": "No active baseline exists — use baseline onboarding instead.",
        }

    validation_result = await validate_baseline_controls(baseline_upload.controls)
    if validation_result.errors:
        return {
            "status": "validation_failed",
            "validation_result": validation_result,
            "activation_blocked": True,
            "reason": "New baseline validation failed — current baseline unchanged.",
        }

    # 2. Deactivate current (flush first so the partial unique index on
    #    ACTIVE rows never sees two ACTIVE baselines).
    current.status = BaselineState.REPLACED
    current.activated_at = None
    await db.flush()

    # 3. Persist the replacement as the new ACTIVE baseline.
    replacement = CompanyBaseline(
        organization_id=org.id,
        name=baseline_upload.name,
        framework=baseline_upload.framework,
        benchmark=baseline_upload.benchmark,
        status=BaselineState.ACTIVE,
        controls=baseline_upload.controls,
        created_by=user.email,
        activated_at=datetime.utcnow(),
    )
    db.add(replacement)
    await db.flush()

    # 4. Point the organization at the replacement.
    org.baseline_status = BaselineState.ACTIVE
    org.active_baseline_id = replacement.id
    org.updated_at = datetime.utcnow()
    await db.flush()

    return {
        "status": "replaced",
        "validation_result": validation_result,
        "replaced_baseline": {
            "id": str(current.id),
            "name": current.name,
        },
        "baseline": {
            "id": str(replacement.id),
            "name": replacement.name,
            "framework": replacement.framework,
            "benchmark": replacement.benchmark,
            "control_count": len(replacement.controls),
            "status": replacement.status,
        },
        "activation_blocked": False,
    }


async def resolve_baseline_for_audit(
    db, organization_id: str, framework: str = "CIS"
) -> dict[str, Any]:
    """Resolve the baseline for an audit execution.

    Returns dict with baseline information and scope mapping.
    This is called automatically during audit execution.
    """
    baseline = await get_active_baseline_for_organization(db, organization_id)

    if baseline is None:
        # No active baseline - baseline evaluation is unavailable
        return {
            "has_baseline": False,
            "baseline_id": None,
            "baseline_name": None,
            "in_scope_controls": [],
            "out_of_scope_controls": [],
            "baseline_status": "NOT_CONFIGURED",
        }

    # Get the control IDs in the baseline
    control_ids = baseline.controls if isinstance(baseline.controls, list) else json.loads(
        baseline.controls if isinstance(baseline.controls, str) else "[]"
    )

    return {
        "has_baseline": True,
        "baseline_id": str(baseline.id),
        "baseline_name": baseline.name,
        "framework": baseline.framework,
        "benchmark": baseline.benchmark,
        "in_scope_controls": control_ids,
        "out_of_scope_controls": [],  # Computed per-audit against full CIS
        "baseline_status": baseline.status,
    }


async def evaluate_company_baseline(
    cis_results: dict[str, dict[str, Any]],
    baseline_controls: list[str],
) -> dict[str, Any]:
    """Evaluate company baseline compliance from CIS evaluation results.

    cis_results: dict of control_id -> {result: PASS/FAIL/REVIEW, ...}
    baseline_controls: list of control IDs in the company baseline

    Returns company baseline metrics and per-control status.
    Only in-scope controls count toward the company compliance score.
    """
    in_scope_results: dict[str, dict[str, Any]] = {}
    company_passed = 0
    company_failed = 0
    company_review = 0
    out_of_scope_controls = 0

    for control_id, cis_result in cis_results.items():
        result = cis_result.get("result", "REVIEW").upper()
        in_scope = control_id in baseline_controls

        if in_scope:
            in_scope_results[control_id] = {
                "result": result,
                "in_scope": True,
            }
            if result == "PASS":
                company_passed += 1
            elif result == "FAIL":
                company_failed += 1
            elif result == "REVIEW":
                company_review += 1
        else:
            # Control is outside the company baseline
            out_of_scope_controls += 1
            in_scope_results[control_id] = {
                "result": result,
                "in_scope": False,
                "company_result": "OUT_OF_SCOPE",
            }

    total_evaluated = company_passed + company_failed + company_review
    denominator = len(baseline_controls) if baseline_controls else 1

    # Company baseline score uses only in-scope controls
    decisive = company_passed + company_failed
    score = round(company_passed / decisive * 100, 1) if decisive > 0 else 0.0

    return {
        "in_scope_results": in_scope_results,
        "company_passed": company_passed,
        "company_failed": company_failed,
        "company_review": company_review,
        "company_score": score,
        "total_evaluated": total_evaluated,
        "denominator": denominator,
        "out_of_scope_controls": out_of_scope_controls,
    }


async def generate_comparison_data(
    cis_results: dict[str, dict[str, Any]],
    baseline_controls: list[str],
    all_cis_control_ids: list[str],
) -> list[SideBySideComparison]:
    """Generate side-by-side comparison data for reports.

    Each entry has:
    - control_id
    - company_result: PASS, FAIL, REVIEW, OUT_OF_SCOPE
    - full_cis_result: PASS, FAIL, REVIEW
    - in_scope: bool
    """
    comparison: list[SideBySideComparison] = []

    for control_id in all_cis_control_ids:
        cis_result_data = cis_results.get(control_id, {})
        cis_result = cis_result_data.get("result", "REVIEW").upper()
        in_scope = control_id in baseline_controls

        if in_scope:
            company_result = cis_result
        else:
            company_result = "OUT_OF_SCOPE"

        comparison.append(
            SideBySideComparison(
                control_id=control_id,
                company_result=company_result,
                full_cis_result=cis_result,
                in_scope=in_scope,
            )
        )

    return comparison


@router.post("/onboarding", response_model=dict)
async def baseline_onboarding(
    request: BaselineUploadRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Company baseline onboarding flow.

    One-time configuration during initial company onboarding.

    Shows: 'Do you have a Company Security Baseline?'
    Options: YES / NO

    If YES: Upload baseline -> Parse -> Validate -> Confirm -> Activate
    If NO: Persist baseline_status = NOT_CONFIGURED, do not ask again
    """
    # Check capability - auditor or admin can configure baseline
    has_capability = await user_has_baseline_capability(current_user, "baseline.configure")
    if not has_capability:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient capabilities to configure baseline",
        )

    # Organization is created on demand from the authenticated user
    # (company onboarding) — never trusted from the client.
    org = await _ensure_organization(db, current_user)
    org_id = org.id

    # Check current baseline status
    baseline, current_status = await check_organization_baseline(db, org_id)

    if current_status == "ACTIVE":
        # Already has active baseline, skip onboarding
        return {
            "status": "already_active",
            "message": "Organization already has an active company baseline.",
            "baseline": {
                "id": str(baseline.id),
                "name": baseline.name,
                "framework": baseline.framework,
                "benchmark": baseline.benchmark,
                "control_count": len(baseline.controls) if baseline.controls else 0,
            },
        }

    if current_status == "NOT_CONFIGURED":
        # First time - proceed with onboarding flow
        result = await onboarding_yes_flow(db, current_user, request)
        return result

    if current_status == "PENDING_VALIDATION":
        # Already in progress - show current state
        return {
            "status": "pending_validation",
            "message": "Baseline validation in progress.",
        }

    # Some other state
    return {
        "status": current_status,
        "message": "Baseline configuration status unknown.",
    }


@router.post("/onboarding/no", response_model=dict)
async def baseline_onboarding_no(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Handle NO response in baseline onboarding.

    Persist baseline_status = NOT_CONFIGURED and do not prompt again.
    """
    has_capability = await user_has_baseline_capability(current_user, "baseline.configure")
    if not has_capability:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient capabilities to configure baseline",
        )

    result = await onboarding_no_flow(db, current_user)
    return result


@router.post("/validate", response_model=dict)
async def baseline_validate(
    request: BaselineUploadRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Validate a baseline candidate WITHOUT activating it.

    Used by the configuration workflow's validation step. The backend
    remains authoritative: activation re-validates the same payload.
    """
    has_capability = await user_has_baseline_capability(current_user, "baseline.configure")
    if not has_capability:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient capabilities to configure baseline",
        )

    validation_result = await validate_baseline_controls(request.controls)

    return {
        "status": "valid" if validation_result.valid_count == len(request.controls) else "invalid",
        "validation_result": validation_result,
        "name": request.name,
        "framework": request.framework,
        "benchmark": request.benchmark,
        "control_count": len(request.controls),
    }


@router.post("/replace", response_model=dict)
async def baseline_replace(
    request: BaselineUploadRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Atomically replace the organization's active baseline.

    The new baseline is validated first; on any validation failure the
    current active baseline remains untouched. On success the old baseline
    is deactivated (REPLACED) and the new one becomes ACTIVE in the same
    transaction — never 0, never 2 active baselines.
    """
    has_capability = await user_has_baseline_capability(current_user, "baseline.configure")
    if not has_capability:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient capabilities to replace baseline",
        )

    result = await replace_baseline(db, current_user, request)
    if result["activation_blocked"]:
        if result["status"] == "no_active_baseline":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No active baseline exists — use baseline onboarding instead.",
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=result["reason"],
        )

    await db.commit()
    return result


@router.get("/status", response_model=dict)
async def baseline_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the current baseline status for the organization."""
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        return {
            "baseline_status": BaselineState.NOT_CONFIGURED,
            "baseline_available": False,
            "evaluation_unavailable": True,
        }

    baseline, current_status = await check_organization_baseline(db, org_id)
    org_result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_result.scalar_one_or_none()
    organization_name = org.name if org else None

    if current_status == "NOT_CONFIGURED":
        return {
            "baseline_status": BaselineState.NOT_CONFIGURED,
            "baseline_available": False,
            "evaluation_unavailable": True,
            "organization_name": organization_name,
        }

    if current_status == "ACTIVE" and baseline:
        return {
            "baseline_status": BaselineState.ACTIVE,
            "baseline_available": True,
            "baseline": CompanyBaselineSummary(
                name=baseline.name,
                framework=baseline.framework,
                benchmark=baseline.benchmark,
                control_count=len(baseline.controls) if baseline.controls else 0,
                status=baseline.status,
                activated_at=baseline.activated_at,
            ),
            "organization_name": organization_name,
        }

    return {
        "baseline_status": current_status,
        "baseline_available": False,
        "evaluation_unavailable": True,
    }


@router.get("/resolve-for-audit", response_model=dict)
async def baseline_resolve_for_audit(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the baseline resolution for an audit.

    This is automatically resolved during audit execution -
    the system loads the organization's active baseline.
    """
    org_id = getattr(current_user, "organization_id", None)
    if not org_id:
        return {
            "has_baseline": False,
            "baseline_id": None,
            "baseline_name": None,
            "in_scope_controls": [],
            "out_of_scope_controls": [],
            "baseline_status": "NOT_CONFIGURED",
        }

    result = await resolve_baseline_for_audit(db, org_id)
    return result