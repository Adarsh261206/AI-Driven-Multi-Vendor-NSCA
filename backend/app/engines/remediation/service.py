"""Plan lifecycle service: persistence, transitions, freshness, secrets.

Owns everything the HTTP layer must not decide: status transitions
(strict edges only, never from request bodies), configuration-hash
staleness gates, parameter resolution with secret discipline, and
audit-trail emission. Secrets pass through transiently and are never
persisted, logged, or returned.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from sqlalchemy import desc, select

from app.engines.remediation import diff as _diff
from app.engines.remediation.generator import extract_placeholders
from app.engines.remediation.models import (
    PlanChange,
    PlanStatus,
    RemediationPlan,
    RemediationPlanError,
    check_transition,
    coerce_status,
    remediation_plan_from_dict,
)
from app.engines.remediation.registry import param_type as _param_type_fn
from app.models import AuditAction


def _plain_scalar(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "value") and not isinstance(value, str):
        try:
            return value.value
        except Exception:
            return None
    return value


def finding_to_dict(finding: Any) -> dict[str, Any]:
    """Shape an ORM finding into generator input (no secrets involved)."""
    get = lambda name, default=None: getattr(finding, name, default)  # noqa: E731
    return {
        "finding_id": str(get("id") or ""),
        "control_id": str(get("control_id") or ""),
        "vendor": str(_plain_scalar(get("affected_vendor")) or ""),
        "platform": str(_plain_scalar(get("affected_platform")) or ""),
        "title": str(get("title") or ""),
        "severity": str(_plain_scalar(get("severity")) or ""),
        "confidence": get("confidence") or 0.0,
        "evidence": get("evidence") or {},
        "affected_device": str(get("affected_device") or ""),
    }


async def resolve_plan_configuration(
        session: Any,
        finding: Any) -> tuple[Optional[str], Optional[str], bool]:
    """Resolve (configuration_id, content_hash, ambiguous) for a finding.

    Single-configuration audits resolve directly; otherwise the
    affected device is matched to a filename/device. Ambiguity never
    resolves silently: (None, None, True).
    """
    from app.models import AuditConfiguration, Configuration, Device

    audit_id = getattr(finding, "audit_id", None)
    if audit_id is None:
        return None, None, True
    links = list((await session.execute(
        select(AuditConfiguration).where(
            AuditConfiguration.audit_id == audit_id)
    )).scalars().all())
    if len(links) == 1:
        cfg = await session.get(Configuration, links[0].configuration_id)
        if cfg is None:
            return None, None, True
        return str(cfg.id), cfg.content_hash, False
    device_name = str(getattr(finding, "affected_device") or "")
    candidates: list[Any] = []
    for link in links:
        cfg = await session.get(Configuration, link.configuration_id)
        if cfg is None:
            continue
        dev_name = ""
        if cfg.device_id is not None:
            dev = await session.get(Device, cfg.device_id)
            dev_name = str(getattr(dev, "name", "") or "")
        if device_name and (device_name == dev_name
                            or device_name == (cfg.filename or "")):
            candidates.append(cfg)
    if len(candidates) == 1:
        return (str(candidates[0].id), candidates[0].content_hash, False)
    return None, None, True


async def config_hash_now(session: Any,
                            configuration_id: Optional[str]) -> Optional[str]:
    if not configuration_id:
        return None
    from app.models import Configuration

    try:
        import uuid as _uuid

        cfg = await session.get(Configuration,
                                _uuid.UUID(str(configuration_id)))
    except Exception:
        return None
    return getattr(cfg, "content_hash", None) if cfg else None


async def _emit(session: Any, action: AuditAction, finding_id: str,
                plan: RemediationPlan, user_id: Optional[str],
                extra: Optional[dict] = None) -> None:
    from app.repositories.audit_trail import AuditTrailRepository

    details: dict[str, Any] = {
        "plan_id": plan.plan_id,
        "control_id": plan.control_id,
        "status": plan.status.value
        if hasattr(plan.status, "value") else str(plan.status),
        # Descriptors only (name/type/supplied) — values never logged.
        "params": [p.to_dict() for p in plan.params],
    }
    if extra:
        details.update(extra)
    await AuditTrailRepository(session).log(
        action=action, entity_type="finding", entity_id=finding_id,
        user_id=user_id, details=details)


def _set_status(row: Any, plan: RemediationPlan,
                to: PlanStatus) -> None:
    check_transition(coerce_status(plan.status), to)
    plan.status = to
    row.status = to.value
    row.plan_json = plan.to_dict()


def _validate_plain_value(name: str, value: Any) -> str:
    """Single-line safe value for a non-secret placeholder."""
    if not isinstance(value, str) or not value.strip():
        raise RemediationPlanError(
            f"parameter {name!r} requires a non-empty string value")
    cleaned = value.strip()
    if ("\n" in cleaned or "\r" in cleaned or "\x00" in cleaned
            or "|" in cleaned or ">" in cleaned or "#" in cleaned):
        raise RemediationPlanError(
            f"parameter {name!r} contains unsafe characters")
    if len(cleaned) > 256:
        raise RemediationPlanError(
            f"parameter {name!r} exceeds 256 characters")
    return cleaned


def _substitute(commands: list[str], resolved: dict[str, str]) -> list[str]:
    import re as _re

    def _fill(cmd: str) -> str:
        def _sub(match: Any) -> str:
            return resolved.get(match.group(1).strip(), match.group(0))
        return _re.sub(r"<([^<>]+)>", _sub, cmd)

    return [_fill(c) for c in commands]


def _coerce_uuid(value: Any) -> Optional[Any]:
    """UUID objects for UUID columns; None stays None (typed on misuse)."""
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    try:
        import uuid as _uuid

        return value if isinstance(value, _uuid.UUID) else _uuid.UUID(
            str(value))
    except Exception:
        raise RemediationPlanError(f"not a UUID: {value!r}")


async def create_plan(session: Any, finding: Any,
                      user_id: Optional[str]) -> tuple[Any, RemediationPlan]:
    """Generate, persist and auto-advance a plan. Returns (row, plan)."""
    from app.engines.remediation.generator import generate_plan
    from app.models import RemediationPlanRow

    payload = finding_to_dict(finding)
    config_id, config_hash, ambiguous = await resolve_plan_configuration(
        session, finding)
    plan = generate_plan(payload, config_fresh=True)
    plan.configuration_id = config_id
    plan.configuration_hash_before = config_hash
    if ambiguous:
        plan.risk_flags = sorted(set(plan.risk_flags)
                                 | {"config_ambiguous"})
        plan.safe_to_apply = False

    row = RemediationPlanRow(
        plan_id=plan.plan_id,
        finding_id=_coerce_uuid(payload["finding_id"]),
        control_id=plan.control_id or None, status=plan.status.value,
        plan_json=plan.to_dict(), configuration_id=None,
        configuration_hash_before=config_hash)
    if config_id:
        try:
            import uuid as _uuid

            row.configuration_id = _uuid.UUID(config_id)
        except Exception:
            row.configuration_id = None
    session.add(row)
    await session.flush()

    await _emit(session, AuditAction.REMEDIATION_PLAN_CREATED,
                payload["finding_id"], plan, user_id)
    if plan.status == PlanStatus.VALIDATED:
        await _emit(session, AuditAction.REMEDIATION_PLAN_VALIDATED,
                    payload["finding_id"], plan, user_id)
        if plan.safe_to_apply:
            _set_status(row, plan, PlanStatus.AWAITING_APPROVAL)
            await session.flush()
            await _emit(
                session, AuditAction.REMEDIATION_APPROVAL_REQUESTED,
                payload["finding_id"], plan, user_id)
    else:
        await session.flush()
    return row, plan


async def latest_plan_for_finding(session: Any,
                                    finding_id: str) -> Optional[Any]:
    """Newest plan row for a finding (None when the finding has none)."""
    from sqlalchemy import desc

    from app.models import RemediationPlanRow

    try:
        import uuid as _uuid

        fid = _uuid.UUID(str(finding_id))
    except Exception:
        return None
    return (await session.execute(
        select(RemediationPlanRow).where(
            RemediationPlanRow.finding_id == fid).order_by(
            desc(RemediationPlanRow.created_at)).limit(1)
    )).scalars().one_or_none()


async def _load(session: Any, plan_id: str) -> tuple[Any, RemediationPlan]:
    from app.models import RemediationPlanRow

    row = (await session.execute(
        select(RemediationPlanRow).where(
            RemediationPlanRow.plan_id == plan_id)
    )).scalars().one_or_none()
    if row is None:
        raise RemediationPlanError(f"unknown plan {plan_id!r}")
    return row, remediation_plan_from_dict(row.plan_json or {})


async def _check_fresh(session: Any, row: Any,
                       plan: RemediationPlan) -> bool:
    current = await config_hash_now(session, plan.configuration_id)
    if plan.configuration_hash_before is None or current is None:
        return False
    return current == plan.configuration_hash_before


def _refresh_safety(plan: RemediationPlan) -> None:
    """Recompute safety + safe_to_apply after parameter resolution.

    Replays the safety classifier and precondition verdict over the
    live plan object (registry metadata is static, so this is exact).
    """
    from app.engines.remediation import preconditions as _pre
    from app.engines.remediation import safety as _safety
    from app.engines.remediation.registry import get_template

    entry = get_template(plan.control_id, plan.device.vendor,
                         plan.device.platform)
    risk = entry.risk_level if entry is not None else "critical"
    safety, safety_flags = _safety.classify(
        risk, plan.changes, plan.device.vendor, plan.device.platform)
    unresolved = [p.name for p in plan.params
                  if p.required and not p.supplied]
    checks = [c for c in plan.preconditions
              if c.name not in ("params_resolved",
                                "placeholders_resolved")]
    checks.append(_pre.check_params_resolved(unresolved))
    allowed_secrets = [p.name for p in plan.params
                       if p.supplied and p.type == "secret"]
    checks.append(_pre.check_placeholders_resolved(
        [c for ch in plan.changes for c in ch.commands],
        allowed_secrets))
    pre_ok, pre_flags = _pre.evaluate(checks)
    plan.preconditions = checks
    plan.safety_class = safety
    plan.risk_flags = sorted(set(pre_flags) | set(safety_flags)
                             | {f for f in plan.risk_flags
                                if f.startswith("blocked:")
                                or f.startswith("template-precondition:")
                                or f.startswith("rollback_unavailable:")})
    plan.safe_to_apply = bool(
        pre_ok and safety != plan.safety_class.__class__.BLOCKED
        and not unresolved)


def _resolve_supplied(plan: RemediationPlan,
                      supplied: dict[str, Any],
                      require_all: bool = False) -> dict[str, str]:
    """Validate supplied placeholder values; mark descriptors.

    Secrets are validated then discarded (descriptor flips to
    supplied/redacted). Plain values are validated and returned for
    substitution. Unknown names and unsafe values raise. With
    require_all, a missing required parameter raises instead of
    waiting for a later call.
    """
    if not isinstance(supplied, dict):
        raise RemediationPlanError("params must be a mapping")
    known = {p.name for p in plan.params}
    for name in supplied:
        if name not in known:
            raise RemediationPlanError(
                f"unknown parameter {name!r} for this plan")
    resolved: dict[str, str] = {}
    for param in plan.params:
        if not param.required or param.supplied:
            continue
        if param.name not in supplied:
            if require_all:
                raise RemediationPlanError(
                    f"required parameter {param.name!r} not supplied")
            continue
        raw = supplied[param.name]
        if param.type == "secret":
            if not isinstance(raw, str) or not raw:
                raise RemediationPlanError(
                    f"secret parameter {param.name!r} requires a "
                    f"non-empty value")
            param.supplied = True
            param.redacted = True
        else:
            resolved[param.name] = _validate_plain_value(param.name, raw)
            param.supplied = True
    return resolved


async def resolve_plan_params(session: Any, plan_id: str,
                              user_id: Optional[str],
                              params: dict[str, Any]) -> tuple[Any,
                                                              RemediationPlan]:
    """Parameter Resolution stage: supply placeholders, re-evaluate,
    advance to awaiting approval when the plan becomes safe."""
    row, plan = await _load(session, plan_id)
    if plan.status not in (PlanStatus.VALIDATED,
                           PlanStatus.AWAITING_APPROVAL):
        raise RemediationPlanError(
            f"parameters cannot be resolved in status {plan.status.value}")
    resolved = _resolve_supplied(plan, params or {})
    if resolved:
        new_changes: list[PlanChange] = []
        for change in plan.changes:
            new_changes.append(PlanChange(
                context=change.context,
                commands=_substitute(change.commands, resolved)))
        plan.changes = new_changes
        plan.diff = _diff.build_diff_from_parts(
            after_blocks=_diff.render_changes(new_changes),
            add=[c for ch in new_changes for c in ch.commands],
            before_blocks=list(plan.diff.before),
            remove=list(plan.diff.remove))
    _refresh_safety(plan)
    if plan.safe_to_apply and plan.status == PlanStatus.VALIDATED:
        _set_status(row, plan, PlanStatus.AWAITING_APPROVAL)
        await session.flush()
        await _emit(session,
                    AuditAction.REMEDIATION_APPROVAL_REQUESTED,
                    plan.finding_id, plan, user_id)
    else:
        _set_status_noop(row, plan)
        await session.flush()
    return row, plan


def _set_status_noop(row: Any, plan: RemediationPlan) -> None:
    """Persist plan JSON without moving status (params recorded)."""
    row.plan_json = plan.to_dict()


async def approve_plan(session: Any, plan_id: str, user_id: str,
                       confirm: bool, params: Optional[dict[str, Any]],
                       notes: str = "") -> tuple[Any, RemediationPlan]:
    """Approve (confirm=true) or reject a plan awaiting approval."""
    row, plan = await _load(session, plan_id)
    if plan.status != PlanStatus.AWAITING_APPROVAL:
        raise RemediationPlanError(
            f"plan {plan_id!r} is {plan.status.value}, not awaiting approval")
    if not await _check_fresh(session, row, plan):
        _set_status(row, plan, PlanStatus.STALE_PLAN)
        row.failure_info = {"reason": "stale_plan",
                            "detail": "configuration changed since "
                            "plan generation; regenerate"}
        await session.flush()
        raise RemediationPlanError(
            "stale plan: configuration changed; regenerate the plan")
    if not confirm:
        _set_status(row, plan, PlanStatus.APPROVAL_REJECTED)
        row.rejection_reason = (notes or "")[:2000]
        await session.flush()
        await _emit(session, AuditAction.REMEDIATION_REJECTED,
                    plan.finding_id, plan, user_id,
                    {"notes": (notes or "")[:500]})
        return row, plan

    supplied = params or {}
    resolved = _resolve_supplied(plan, supplied, require_all=True)
    # Substitute resolved PLAIN values into stored commands (secrets
    # stay as <name> placeholders for runtime prompting) and refresh
    # the diff's addition side; the removal side is unchanged.
    if resolved:
        new_changes: list[PlanChange] = []
        for change in plan.changes:
            new_changes.append(PlanChange(
                context=change.context,
                commands=_substitute(change.commands, resolved)))
        plan.changes = new_changes
        plan.diff = _diff.build_diff_from_parts(
            after_blocks=_diff.render_changes(new_changes),
            add=[c for ch in new_changes for c in ch.commands],
            before_blocks=[],
            remove=list(plan.diff.remove))
    _set_status(row, plan, PlanStatus.APPROVED)
    from datetime import datetime as _dt

    row.approved_by = _coerce_uuid(user_id)
    row.approved_at = _dt.utcnow()
    await session.flush()
    await _emit(session, AuditAction.REMEDIATION_APPROVED,
                plan.finding_id, plan, user_id,
                {"resolved_params": sorted(resolved)})
    return row, plan


async def generate_script_artifact(
        session: Any, plan_id: str,
        user_id: Optional[str]) -> tuple[str, str, RemediationPlan]:
    """Render the downloadable script for an approved, fresh plan."""
    from app.engines.remediation.script_generator import generate_script

    row, plan = await _load(session, plan_id)
    if plan.status != PlanStatus.APPROVED:
        raise RemediationPlanError(
            f"script requires an approved plan, got {plan.status.value}")
    if not await _check_fresh(session, row, plan):
        _set_status(row, plan, PlanStatus.STALE_PLAN)
        row.failure_info = {"reason": "stale_plan"}
        await session.flush()
        raise RemediationPlanError("stale plan: regenerate before scripting")
    filename, source = generate_script(plan)
    await _emit(session, AuditAction.REMEDIATION_SCRIPT_GENERATED,
                plan.finding_id, plan, user_id, {"filename": filename})
    await session.flush()
    return filename, source, plan


async def generate_rollback_artifact(
        session: Any, plan_id: str,
        user_id: Optional[str]) -> tuple[str, str, RemediationPlan]:
    """Render the rollback script (only when a safe rollback exists)."""
    from app.engines.remediation.script_generator import generate_script

    row, plan = await _load(session, plan_id)
    if plan.status != PlanStatus.APPROVED:
        raise RemediationPlanError(
            f"rollback script requires an approved plan, got "
            f"{plan.status.value}")
    if not plan.rollback:
        raise RemediationPlanError(
            "no safe rollback exists for this plan")
    shadow = RemediationPlan(
        plan_id=plan.plan_id + "-rollback", finding_id=plan.finding_id,
        control_id=plan.control_id, device=plan.device,
        finding=plan.finding, changes=list(plan.rollback),
        verification=list(plan.verification),
        safety_class=plan.safety_class, safe_to_apply=True,
        requires_approval=True, status=PlanStatus.APPROVED)
    from app.engines.remediation import diff as _diff_mod

    shadow.diff = _diff_mod.build_diff(shadow.changes, [])
    filename, source = generate_script(shadow)
    filename = filename.replace(".py", ".rollback.py")
    await _emit(session,
                AuditAction.REMEDIATION_ROLLBACK_SCRIPT_GENERATED,
                plan.finding_id, plan, user_id, {"filename": filename})
    await session.flush()
    return filename, source, plan
