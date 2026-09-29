"""
Audit Trail Repository (Engine 12, spec 10.12).

Logs all significant actions for compliance and security auditing:
audit results, configuration changes, version history — and serves them
back through filtered queries.

Contract principles (E12):
- Typed errors: every input violation raises AuditTrailError (a
  ValueError) at the call site — never a bare ValueError/AttributeError
  from uuid, never an IntegrityError/DataError at flush time.
- The trail must never break the audited operation on payload shape:
  details are sanitized to JSONB-safe values (Decimal -> float,
  datetime -> ISO, Enum -> value, UUID -> str, sets -> sorted lists,
  NUL bytes stripped, non-finite floats stringified, unknown objects
  str()-ified at a bounded depth).
- Client-controlled metadata (ip_address, user_agent) is truncated to
  its column width; program-controlled vocabulary (action,
  entity_type) is rejected loudly when invalid.
"""

from __future__ import annotations

import datetime as _dt
import enum
import math
import uuid
from decimal import Decimal
from typing import Optional, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditTrail, AuditAction

class AuditTrailError(ValueError):
    """An audit-trail input violates the Engine 12 contract."""


#: Query page cap for get_entries (E06 pagination convention: bounded).
MAX_TRAIL_PAGE = 1000

#: Column widths (program-controlled entity_type is strict; client
#: metadata truncates — the trail never 500s on a long User-Agent).
MAX_ENTITY_TYPE_LEN = 50
MAX_IP_LEN = 45
MAX_UA_LEN = 500

#: Entity vocabulary in use. New program-controlled callers add their
#: type here and in this docstring: "audit", "finding",
#: "ai_interaction", "training_mapping", "configuration".
ENTITY_TYPES = frozenset({
    "audit", "finding", "ai_interaction", "training_mapping",
    "configuration",
})

#: Lifecycle actions emittable through log_audit_event.
AUDIT_LIFECYCLE_ACTIONS = frozenset({
    AuditAction.AUDIT_CREATED, AuditAction.AUDIT_STARTED,
    AuditAction.AUDIT_COMPLETED, AuditAction.AUDIT_FAILED,
    AuditAction.AUDIT_CANCELLED,
})

#: Mapping actions emittable through log_mapping_event.
MAPPING_ACTIONS = frozenset({
    AuditAction.MAPPING_CREATED, AuditAction.MAPPING_CONFIRMED,
    AuditAction.MAPPING_REJECTED, AuditAction.MAPPING_UPDATED,
})

_SANITIZE_MAX_DEPTH = 10


def normalize_action(action: Any) -> AuditAction:
    """Coerce to AuditAction: the enum itself, or its exact string value."""
    if isinstance(action, AuditAction):
        return action
    if isinstance(action, str):
        try:
            return AuditAction(action)
        except ValueError:
            pass
    raise AuditTrailError(
        f"action must be an AuditAction (or its value), got {action!r}")


def normalize_uuid(value: Any, name: str) -> Optional[uuid.UUID]:
    """Coerce to UUID: None stays None; UUID/str accepted; else typed error."""
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    if isinstance(value, str):
        try:
            return uuid.UUID(value)
        except (ValueError, AttributeError, TypeError):
            pass
    raise AuditTrailError(
        f"{name} must be a UUID string, got {value!r}")


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    if depth > _SANITIZE_MAX_DEPTH:
        return str(value)
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str):
            return value.replace("\x00", "")
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, Decimal):
        as_float = float(value)
        return as_float if math.isfinite(as_float) else str(value)
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat()
    if isinstance(value, enum.Enum):
        return _sanitize_value(value.value, depth + 1)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(k).replace("\x00", ""): _sanitize_value(v, depth + 1)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(v, depth + 1) for v in value]
    if isinstance(value, (set, frozenset)):
        # sorted by rendered form so sets are deterministic in history.
        return sorted((_sanitize_value(v, depth + 1) for v in value),
                      key=lambda v: str(v))
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace").replace(
            "\x00", "")
    return str(value).replace("\x00", "")


def sanitize_details(details: Any) -> dict:
    """Coerce a details payload to JSONB-safe mappings (typed on misuse)."""
    if details is None:
        return {}
    if not isinstance(details, dict):
        raise AuditTrailError(
            "details must be a mapping, got "
            f"{type(details).__name__}")
    return _sanitize_value(details)


def _check_text(name: str, value: Any, *, allow_none: bool,
                max_len: Optional[int] = None) -> Any:
    if value is None:
        if allow_none:
            return None
        raise AuditTrailError(f"{name} must be a string, got None")
    if not isinstance(value, str):
        raise AuditTrailError(
            f"{name} must be a string, got {type(value).__name__}")
    return value


def _filter_conditions(
    entity_type: Optional[str],
    entity_id: Any,
    user_id: Any,
    action: Any,
) -> list:
    """Single source of truth for trail filter semantics (list + count)."""
    conditions = []
    if entity_type:
        conditions.append(AuditTrail.entity_type == entity_type)
    if entity_id:
        conditions.append(AuditTrail.entity_id == normalize_uuid(
            entity_id, "entity_id"))
    if user_id:
        conditions.append(AuditTrail.user_id == normalize_uuid(
            user_id, "user_id"))
    if action is not None:
        conditions.append(
            AuditTrail.action == normalize_action(action).value)
    return conditions


class AuditTrailRepository:
    """
    Audit Trail Repository

    Logs all significant actions for compliance and security auditing.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        action: AuditAction,
        entity_type: str,
        entity_id: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditTrail:
        """
        Log an audit trail entry

        Args:
            action: Action performed (AuditAction or its value)
            entity_type: Type of entity affected (non-empty, <=50 chars)
            entity_id: ID of entity affected (UUID string)
            user_id: ID of user performing action (UUID string)
            details: Additional details (mapping; sanitized to JSONB-safe)
            ip_address: Client IP address (truncated to 45 chars)
            user_agent: Client user agent (truncated to 500 chars)

        Returns:
            Created AuditTrail entry

        Raises:
            AuditTrailError: on any contract violation (never a bare
                uuid/DB error).
        """
        entry = AuditTrail(
            id=uuid.uuid4(),
            action=normalize_action(action),
            entity_type=self._checked_entity_type(entity_type),
            entity_id=normalize_uuid(entity_id, "entity_id"),
            user_id=normalize_uuid(user_id, "user_id"),
            details=sanitize_details(details),
            ip_address=self._truncated_ip(ip_address),
            user_agent=self._truncated_ua(user_agent),
            created_at=_dt.datetime.utcnow(),
        )

        self.db.add(entry)
        await self.db.flush()

        return entry

    @staticmethod
    def _checked_entity_type(entity_type: Any) -> str:
        _check_text("entity_type", entity_type, allow_none=False)
        assert isinstance(entity_type, str)
        if not entity_type.strip():
            raise AuditTrailError("entity_type must not be empty")
        if len(entity_type) > MAX_ENTITY_TYPE_LEN:
            raise AuditTrailError(
                f"entity_type longer than {MAX_ENTITY_TYPE_LEN} chars")
        return entity_type

    @staticmethod
    def _truncated_ip(ip_address: Any) -> Optional[str]:
        _check_text("ip_address", ip_address, allow_none=True)
        if ip_address is None:
            return None
        assert isinstance(ip_address, str)
        return ip_address[:MAX_IP_LEN]

    @staticmethod
    def _truncated_ua(user_agent: Any) -> Optional[str]:
        _check_text("user_agent", user_agent, allow_none=True)
        if user_agent is None:
            return None
        assert isinstance(user_agent, str)
        return user_agent[:MAX_UA_LEN]

    async def log_ai_interaction(
        self,
        action: AuditAction,
        raw_syntax: str,
        vendor: str,
        platform: str,
        hypothesis: Optional[dict] = None,
        admin_decision: Optional[str] = None,
        user_id: Optional[str] = None,
        confidence: Optional[float] = None,
        ip_address: Optional[str] = None,
    ) -> AuditTrail:
        """
        Log an AI interaction for audit purposes

        Args:
            action: AI-related action
            raw_syntax: Raw configuration syntax
            vendor: Device vendor
            platform: Device platform
            hypothesis: AI hypothesis if available
            admin_decision: Admin decision (confirm/edit/reject)
            user_id: ID of user
            confidence: AI confidence score (any real number type;
                Decimal from Numeric columns is accepted)
            ip_address: Client IP address
        """
        for name, val in (("raw_syntax", raw_syntax), ("vendor", vendor),
                          ("platform", platform)):
            _check_text(name, val, allow_none=False)
        if admin_decision is not None:
            _check_text("admin_decision", admin_decision, allow_none=True)
        details = {
            "raw_syntax": raw_syntax,
            "vendor": vendor,
            "platform": platform,
            "hypothesis": hypothesis,
            "admin_decision": admin_decision,
            "confidence": confidence,
        }

        return await self.log(
            action=action,
            entity_type="ai_interaction",
            user_id=user_id,
            details=details,
            ip_address=ip_address,
        )

    async def log_compliance_evaluation(
        self,
        audit_id: str,
        total_controls: int,
        passed: int,
        failed: int,
        review: int,
        overall_score: float,
        user_id: Optional[str] = None,
    ) -> AuditTrail:
        """Log a compliance evaluation result"""
        for name, val in (("total_controls", total_controls),
                          ("passed", passed), ("failed", failed),
                          ("review", review)):
            if isinstance(val, bool) or not isinstance(val, int):
                raise AuditTrailError(f"{name} must be an int, got {val!r}")
            if val < 0:
                raise AuditTrailError(f"{name} must be >= 0, got {val!r}")
        if isinstance(overall_score, bool) or not isinstance(
                overall_score, (int, float)):
            raise AuditTrailError(
                f"overall_score must be a number, got {overall_score!r}")
        if not math.isfinite(float(overall_score)):
            raise AuditTrailError(
                f"overall_score must be finite, got {overall_score!r}")
        details = {
            "audit_id": audit_id,
            "total_controls": total_controls,
            "passed": passed,
            "failed": failed,
            "review": review,
            "overall_score": float(overall_score),
        }

        return await self.log(
            action=AuditAction.COMPLIANCE_EVALUATED,
            entity_type="audit",
            entity_id=audit_id,
            user_id=user_id,
            details=details,
        )

    async def log_finding_update(
        self,
        finding_id: str,
        audit_id: str,
        old_status: str,
        new_status: str,
        user_id: Optional[str] = None,
        notes: str = "",
        no_op: bool = False,
    ) -> AuditTrail:
        """Log a finding status update.

        The entry reconstructs the transition: finding id, actor, previous
        status, new status, notes and timestamp (created_at). Notes are part
        of history — never dropped. Explicit no-ops are recorded as such.
        """
        for name, val in (("old_status", old_status),
                          ("new_status", new_status)):
            _check_text(name, val, allow_none=False)
            assert isinstance(val, str)
            if not val.strip():
                raise AuditTrailError(f"{name} must not be empty")
        if notes is None:
            notes = ""
        _check_text("notes", notes, allow_none=False)
        if not isinstance(no_op, bool):
            raise AuditTrailError(
                f"no_op must be a bool, got {no_op!r}")
        details = {
            "finding_id": finding_id,
            "audit_id": audit_id,
            "old_status": old_status,
            "new_status": new_status,
            "notes": notes,
            "no_op": no_op,
        }

        return await self.log(
            action=AuditAction.FINDING_UPDATED,
            entity_type="finding",
            entity_id=finding_id,
            user_id=user_id,
            details=details,
        )

    async def log_audit_event(
        self,
        action: AuditAction,
        audit_id: str,
        user_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> AuditTrail:
        """Log an audit-lifecycle event (created/started/completed/failed/
        cancelled). Only AUDIT_* actions are accepted here so lifecycle
        history cannot be polluted with unrelated actions."""
        action = normalize_action(action)
        if action not in AUDIT_LIFECYCLE_ACTIONS:
            raise AuditTrailError(
                f"log_audit_event accepts audit lifecycle actions only, "
                f"got {action.value}")
        payload = {"audit_id": audit_id}
        if details:
            payload.update(sanitize_details(details))
        return await self.log(
            action=action,
            entity_type="audit",
            entity_id=audit_id,
            user_id=user_id,
            details=payload,
        )

    async def log_mapping_event(
        self,
        action: AuditAction,
        mapping_id: str,
        user_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> AuditTrail:
        """Log a knowledge-base mapping event (created/confirmed/rejected/
        updated). Only MAPPING_* actions are accepted here."""
        action = normalize_action(action)
        if action not in MAPPING_ACTIONS:
            raise AuditTrailError(
                f"log_mapping_event accepts mapping actions only, got "
                f"{action.value}")
        payload = {"mapping_id": mapping_id}
        if details:
            payload.update(sanitize_details(details))
        return await self.log(
            action=action,
            entity_type="training_mapping",
            entity_id=mapping_id,
            user_id=user_id,
            details=payload,
        )

    async def get_entries(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[Any] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditTrail]:
        """Get audit trail entries (newest first).

        Malformed UUID filters raise AuditTrailError (never ValueError);
        limit is clamped to [0, MAX_TRAIL_PAGE] and offset to >= 0 so
        hostile pagination cannot 500 or full-scan unbounded.
        """
        conditions = _filter_conditions(entity_type, entity_id, user_id,
                                        action)

        try:
            limit = int(limit)
        except (TypeError, ValueError):
            raise AuditTrailError(
                f"limit must be an int, got {limit!r}")
        try:
            offset = int(offset)
        except (TypeError, ValueError):
            raise AuditTrailError(
                f"offset must be an int, got {offset!r}")
        limit = max(0, min(limit, MAX_TRAIL_PAGE))
        offset = max(0, offset)

        stmt = select(AuditTrail)
        if conditions:
            from sqlalchemy import and_
            stmt = stmt.where(and_(*conditions))

        stmt = stmt.order_by(AuditTrail.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def count_entries(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[Any] = None,
    ) -> int:
        """Count entries for the same filter set get_entries serves."""
        from sqlalchemy import and_, func

        conditions = _filter_conditions(entity_type, entity_id, user_id,
                                        action)
        stmt = select(func.count(AuditTrail.id))
        if conditions:
            stmt = stmt.where(and_(*conditions))
        result = await self.db.execute(stmt)
        return result.scalar() or 0
