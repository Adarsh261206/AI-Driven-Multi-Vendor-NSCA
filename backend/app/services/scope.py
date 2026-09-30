"""Ownership scope predicates — the single source of truth for "permitted scope".

Every device/configuration/audit access resolves ownership server-side from
the authenticated user. Nothing here trusts client-supplied organization_id,
user_id, or owner_id.

Established conventions reused (not reinvented):
- admin bypasses ownership checks (matches configurations/devices endpoints)
- missing row -> 404; existing-but-foreign row -> 403 (matches
  get_configuration / get_configuration_content)
- a non-admin may only audit configurations linked to their own devices
  (matches get/content, which 403 NULL-device configs for non-admins)

All three predicates raise HTTPException so routes fail closed BEFORE any
row is created, linked, or executed — the audit endpoints especially must
reject the ENTIRE request when ANY requested configuration is out of scope.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Configuration, Device, User


async def resolve_owned_device(
    db: AsyncSession,
    device_id: UUID,
    user: User,
    *,
    allow_missing: bool = False,
) -> Optional[Device]:
    """Return the device iff it is inside the user's permitted scope.

    Missing row -> 404 (or None when allow_missing=True, so the caller
    can fall through to a downstream check that owns the contract —
    e.g. the upload route, where V01-62 pins the engine's typed 400).
    Existing-but-foreign row -> 403 (non-admin). Admins resolve anything.
    """
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if device is None:
        if allow_missing:
            return None
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )
    if user.role != "admin" and device.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this device",
        )
    return device


async def resolve_auditable_configurations(
    db: AsyncSession,
    configuration_ids: list[UUID],
    user: User,
) -> list[Configuration]:
    """Return ALL requested configurations iff every one is auditable.

    Auditable means: the row exists AND (admin OR linked to a device owned
    by the user). Missing rows -> 400 (preserves the existing
    "Configuration IDs not found" contract); out-of-scope rows -> 403.
    The caller must invoke this BEFORE creating any audit row so rejection
    is atomic — no partial audit, no partial findings.
    """
    if not configuration_ids:
        return []

    result = await db.execute(
        select(Configuration).where(Configuration.id.in_(configuration_ids))
    )
    found = {c.id: c for c in result.scalars().all()}

    missing = set(configuration_ids) - set(found.keys())
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Configuration IDs not found: {missing}",
        )

    if user.role == "admin":
        return [found[cid] for cid in configuration_ids]

    # Non-admin: every configuration must be linked to an owned device.
    # NULL-device (unlinked) configurations are NOT auditable — this matches
    # get_configuration/get_content, which 403 them for non-admins.
    owned_device_ids: Optional[set] = None
    unauthorized: list[UUID] = []
    for cid in configuration_ids:
        config = found[cid]
        if config.device_id is None:
            unauthorized.append(cid)
            continue
        if owned_device_ids is None:
            dev_rows = await db.execute(
                select(Device.id).where(Device.user_id == user.id)
            )
            owned_device_ids = {row[0] for row in dev_rows.all()}
        if config.device_id not in owned_device_ids:
            unauthorized.append(cid)

    if unauthorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Not authorized to audit configurations: "
                f"{[str(c) for c in unauthorized]}"
            ),
        )
    return [found[cid] for cid in configuration_ids]


async def validate_audit_scope(
    db: AsyncSession,
    device_ids: Optional[list[UUID]],
    configuration_ids: list[UUID],
    user: User,
) -> list[Configuration]:
    """Enforce an execution-time device scope constraint on an audit request.

    - device_ids None/empty: no scope constraint; falls back to plain
      ownership validation (STEP 1 behavior, unchanged).
    - device_ids given: every device must resolve via resolve_owned_device
      (404 missing / 403 foreign, admin bypass), AND every requested
      configuration must be linked to one of those devices. Unlinked
      configurations can never satisfy a device scope. ANY violation
      rejects the ENTIRE request BEFORE any audit row exists.

    Archived devices reject new audits in BOTH paths (explicit scope and
    legacy): lifecycle state is orthogonal to ownership. Historical reads
    are unaffected — only new executions are gated.

    Returns the resolved configurations in request order. Never persists
    any device relationship — derivation stays Audit → AuditConfiguration
    → Configuration.device_id → Device.
    """
    if not device_ids:
        configs = await resolve_auditable_configurations(
            db, configuration_ids, user
        )
        await _reject_archived_devices(
            db, {c.device_id for c in configs if c.device_id is not None}
        )
        return configs

    scoped_devices: dict[UUID, Device] = {}
    for device_id in device_ids:
        device = await resolve_owned_device(db, device_id, user)
        scoped_devices[device.id] = device

    await _reject_archived_devices(db, set(scoped_devices.keys()))

    configs = await resolve_auditable_configurations(db, configuration_ids, user)

    out_of_scope: list[UUID] = []
    for config in configs:
        if config.device_id is None or config.device_id not in scoped_devices:
            out_of_scope.append(config.id)

    if out_of_scope:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Configurations do not belong to the requested audit scope: "
                f"{[str(c) for c in out_of_scope]}"
            ),
        )
    return configs


async def _reject_archived_devices(
    db: AsyncSession, device_ids: set[UUID]
) -> None:
    """409 when any of the given devices is archived.

    Applies to every caller including admins: lifecycle gates new
    operational work, never historical reads.
    """
    if not device_ids:
        return
    rows = await db.execute(
        select(Device.id, Device.name).where(
            Device.id.in_(device_ids),
            Device.is_active == False,  # noqa: E712
        )
    )
    archived = rows.all()
    if archived:
        names = ", ".join(
            f"{name} ({device_id})" for device_id, name in archived
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Archived device(s) cannot start new audits: "
                f"{names}. Unarchive first; history is preserved."
            ),
        )
