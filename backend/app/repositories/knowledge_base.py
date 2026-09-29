"""
Knowledge Base Repository

PostgreSQL-backed implementation of the canonical Knowledge Base domain
contract (spec 10.6 / 9.2 / 15.x). Persistence only: every business rule
(canonicalization, validation, versioning convention, trust, quality inputs)
lives in app.ai.kb_domain and is shared verbatim with the in-memory twin,
so both stores answer identically.

Conventions (identical to the in-memory twin):
- lookup() is EXACT canonical match, total (never raises for domain
  input); similarity is suggestion-only via lookup_suggestions()
- create() on an exact duplicate updates in place (versioned, one row)
- update() never confirms; confirm()/reject() are explicit versioned
  lifecycle actions; reject marks, never deletes
- every mutation appends a POST-change version record; no-op writes
  append nothing
- actors are required (typed errors, never driver IntegrityErrors)
- all reads are deterministically ordered; lists are uncapped by default
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select, func, and_, asc
from sqlalchemy.exc import IntegrityError

from app.ai import kb_domain as dom
from app.ai.knowledge_base import TrainingMapping as DomainMapping
from app.models import TrainingMapping as MappingRow, MappingVersion as VersionRow


def _to_domain(row: MappingRow) -> DomainMapping:
    """ORM row -> canonical domain object (Decimal confidence -> float)."""
    return DomainMapping(
        id=str(row.id),
        vendor=row.vendor,
        platform=row.platform,
        raw_syntax=row.raw_syntax,
        semantic_meaning=row.semantic_meaning,
        universal_model_path=row.universal_model_path,
        confidence=float(row.confidence) if row.confidence is not None else 0.0,
        admin_confirmed=bool(row.admin_confirmed),
        admin_notes=row.admin_notes,
        version=row.version,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _translate_integrity_error(exc: IntegrityError) -> dom.KBError:
    """Map a driver uniqueness failure to a typed domain error (F4).

    A concurrent insert that slips past the application pre-check must
    surface as KBDuplicateError (API: 409), never a raw IntegrityError.
    """
    message = str(getattr(exc, "orig", exc) or exc)
    if "uq_semantic_mappings_identity_version" in message or "unique" in message.lower():
        return dom.KBDuplicateError(
            "mapping identity already stored (concurrent insert)")
    return dom.KBError(f"database integrity error: {message[:200]}")


class KnowledgeBaseRepository:
    """
    PostgreSQL-backed Knowledge Base Repository.

    Provides persistent storage for semantic mappings with versioning.
    """

    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------
    # Reads (F2/F4/F13/F14).
    # ------------------------------------------------------------------

    def _identity_conditions(self, vendor: str, platform: str,
                             raw_syntax: str):
        """Canonical equality filters. Vendor/platform compare lowercase
        (both sides canonical); raw_syntax compares trimmed so legacy
        unstripped rows stay reachable (F12 reconciliation repairs them
        permanently). No ilike, no wildcards: '%' and '_' are literal."""
        vendor_c, platform_c, syntax_c = dom.canonical_identity(
            vendor, platform, raw_syntax)
        return [
            MappingRow.vendor == vendor_c,
            MappingRow.platform == platform_c,
            func.trim(MappingRow.raw_syntax) == syntax_c,
        ]

    async def lookup(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        require_confirmed: bool = True,
    ) -> Optional[DomainMapping]:
        """
        Look up a mapping by vendor/platform/syntax (exact canonical match).

        Total: returns the earliest stored row deterministically
        (created_at, id) instead of raising when several rows match, and
        treats hostile argument types as a miss.
        """
        try:
            conditions = self._identity_conditions(vendor, platform, raw_syntax)
        except TypeError:
            return None
        if require_confirmed:
            conditions.append(MappingRow.admin_confirmed == True)  # noqa: E712
        stmt = (select(MappingRow).where(and_(*conditions))
                .order_by(asc(MappingRow.created_at), asc(MappingRow.id))
                .limit(1))
        result = await self.db.execute(stmt)
        row = result.scalars().first()
        return _to_domain(row) if row is not None else None

    async def lookup_suggestions(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        *,
        require_confirmed: bool = True,
        threshold: float = dom.SUGGESTION_THRESHOLD,
        limit: int = 5,
    ) -> list[tuple[DomainMapping, float]]:
        """
        Suggestion-only similarity search (F5). Same ranking and
        determinism as the in-memory twin; never authoritative, never
        mutating.
        """
        vendor_c = dom.canonical_vendor(vendor)
        platform_c = dom.canonical_platform(platform)
        if not isinstance(raw_syntax, str):
            raise TypeError(
                f"raw_syntax must be str, got {type(raw_syntax).__name__}")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise dom.KBValidationError("limit must be >= 0")
        target = dom.normalize_tokens(raw_syntax)
        if not target:
            return []
        conditions = [MappingRow.vendor == vendor_c,
                      MappingRow.platform == platform_c]
        if require_confirmed:
            conditions.append(MappingRow.admin_confirmed == True)  # noqa: E712
        stmt = (select(MappingRow).where(and_(*conditions))
                .order_by(asc(MappingRow.vendor), asc(MappingRow.platform),
                          asc(MappingRow.raw_syntax), asc(MappingRow.id)))
        result = await self.db.execute(stmt)
        rows = result.scalars().all()
        query_canon = dom.canonical_syntax(raw_syntax)
        out: list[tuple[DomainMapping, float]] = []
        for row in rows:
            if dom.canonical_syntax(row.raw_syntax) == query_canon:
                continue  # exact hits are not suggestions
            sim = dom.jaccard_similarity(
                target, dom.normalize_tokens(row.raw_syntax))
            if sim >= threshold:
                out.append((_to_domain(row), sim))
        out.sort(key=lambda item: (-item[1], item[0].vendor,
                                   item[0].platform, item[0].raw_syntax,
                                   item[0].id))
        return out[:limit]

    async def get_by_id(self, mapping_id: str) -> Optional[DomainMapping]:
        """Fetch by id; None when missing (malformed ids are ValueError)."""
        stmt = select(MappingRow).where(
            MappingRow.id == uuid.UUID(dom.validate_mapping_id(mapping_id)))
        result = await self.db.execute(stmt)
        row = result.scalars().first()
        return _to_domain(row) if row is not None else None

    # ------------------------------------------------------------------
    # Writes (F2/F3/F7/F8/F9/F10/F12/F16/F17).
    # ------------------------------------------------------------------

    async def create(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        semantic_meaning: str,
        universal_model_path: Optional[str] = None,
        confidence: Optional[float] = None,
        admin_confirmed: bool = True,
        admin_notes: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> DomainMapping:
        """
        Create a new training mapping, or version-update the exact
        duplicate in place (single row per canonical identity).
        """
        actor = dom.validate_actor(actor)
        vendor_c, platform_c, syntax_c = dom.canonical_identity(
            vendor, platform, raw_syntax)
        dom.validate_mapping_fields(
            vendor=vendor, platform=platform, raw_syntax=raw_syntax,
            semantic_meaning=semantic_meaning,
            universal_model_path=universal_model_path,
            admin_notes=admin_notes)
        if confidence is None:
            confidence = (dom.DEFAULT_ADMIN_CONFIDENCE if admin_confirmed
                          else dom.DEFAULT_SUGGESTION_CONFIDENCE)
        else:
            confidence = dom.validate_confidence(confidence)

        existing = await self.lookup(vendor_c, platform_c, syntax_c,
                                     require_confirmed=False)
        if existing is not None:
            return await self.update(
                mapping_id=existing.id,
                semantic_meaning=semantic_meaning,
                universal_model_path=universal_model_path,
                admin_notes=admin_notes,
                change_reason="Duplicate create merged",
                actor=actor,
            )

        row = MappingRow(
            id=uuid.uuid4(),
            vendor=vendor_c,
            platform=platform_c,
            raw_syntax=syntax_c,
            semantic_meaning=semantic_meaning,
            universal_model_path=universal_model_path,
            confidence=confidence,
            admin_confirmed=admin_confirmed,
            admin_notes=admin_notes,
            version=1,
            created_by=actor,
        )
        self.db.add(row)
        try:
            await self.db.flush()
        except IntegrityError as exc:
            raise _translate_integrity_error(exc) from exc
        self.db.add(VersionRow(
            id=uuid.uuid4(),
            **dom.build_version_record(
                mapping_id=row.id,
                version=1,
                raw_syntax=syntax_c,
                semantic_meaning=semantic_meaning,
                universal_model_path=universal_model_path,
                confidence=confidence,
                actor=actor,
                reason="Initial creation",
            ),
        ))
        await self.db.flush()
        return _to_domain(row)

    async def _require_row(self, mapping_id: str) -> MappingRow:
        stmt = select(MappingRow).where(
            MappingRow.id == uuid.UUID(dom.validate_mapping_id(mapping_id)))
        result = await self.db.execute(stmt)
        row = result.scalars().first()
        if row is None:
            raise dom.KBNotFoundError(f"Mapping {mapping_id} not found")
        return row

    def _record(self, row: MappingRow, actor: str,
                reason: Optional[str]) -> None:
        record = dom.build_version_record(
            mapping_id=row.id,
            version=row.version,
            raw_syntax=row.raw_syntax,
            semantic_meaning=row.semantic_meaning,
            universal_model_path=row.universal_model_path,
            confidence=(float(row.confidence)
                        if row.confidence is not None else None),
            actor=actor,
            reason=reason,
        )
        self.db.add(VersionRow(id=uuid.uuid4(), **record))
        # Columns are naive TIMESTAMP (see models: default=datetime.utcnow);
        # asyncpg rejects tz-aware parameters for those, so stamp naive UTC.
        row.updated_at = datetime.utcnow()

    async def update(
        self,
        mapping_id: str,
        semantic_meaning: Optional[str] = None,
        universal_model_path: Optional[str] = None,
        admin_notes: Optional[str] = None,
        change_reason: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> DomainMapping:
        """
        Edit a mapping (creates a new version).

        EDIT never confirms and never fabricates confidence. A no-op edit
        changes nothing and records nothing (F7).
        """
        actor = dom.validate_actor(actor)
        reason = dom.validate_reason(change_reason)
        row = await self._require_row(mapping_id)
        changes: dict[str, Any] = {}
        if semantic_meaning is not None:
            if not isinstance(semantic_meaning, str):
                raise TypeError("semantic_meaning must be str")
            if not semantic_meaning.strip():
                raise dom.KBValidationError(
                    "semantic_meaning must not be empty")
            if len(semantic_meaning) > dom.MAX_MEANING_LEN:
                raise dom.KBValidationError("semantic_meaning too long")
            changes["semantic_meaning"] = semantic_meaning
        if universal_model_path is not None:
            if not isinstance(universal_model_path, str):
                raise TypeError("universal_model_path must be str")
            if not dom.is_valid_model_path(universal_model_path):
                raise dom.KBValidationError(
                    f"universal_model_path {universal_model_path!r} is not "
                    "a Universal Security Model path")
            changes["universal_model_path"] = universal_model_path
        if admin_notes is not None:
            dom.check_text("admin_notes", admin_notes, allow_empty=True,
                           max_len=dom.MAX_NOTES_LEN)
            changes["admin_notes"] = admin_notes
        current = {"semantic_meaning": row.semantic_meaning,
                   "universal_model_path": row.universal_model_path,
                   "admin_notes": row.admin_notes}
        if dom.is_noop_update(current, changes):
            return _to_domain(row)
        for key, value in changes.items():
            setattr(row, key, value)
        row.version += 1
        self._record(row, actor, reason if reason is not None else "Edit")
        await self.db.flush()
        return _to_domain(row)

    async def confirm(
        self,
        mapping_id: str,
        actor: Optional[str] = None,
        semantic_meaning: Optional[str] = None,
        universal_model_path: Optional[str] = None,
        admin_notes: Optional[str] = None,
        confidence: Optional[float] = None,
        change_reason: Optional[str] = None,
    ) -> DomainMapping:
        """
        Confirm a mapping (explicit administrator action).

        Always appends a version record (reaffirmation is an event). An
        explicit estimated confidence is preserved verbatim; otherwise the
        administrator's validation is itself the evidence and the estimate
        becomes DEFAULT_ADMIN_CONFIDENCE (1.0) - the same rule in the
        in-memory twin. A stored proposal's 0.5 hypothesis estimate is never
        silently promoted by an EDIT, only by this explicit action.
        """
        actor = dom.validate_actor(actor)
        reason = dom.validate_reason(change_reason)
        row = await self._require_row(mapping_id)
        if semantic_meaning is not None:
            if not isinstance(semantic_meaning, str) or not semantic_meaning.strip():
                raise dom.KBValidationError(
                    "semantic_meaning must not be empty")
            row.semantic_meaning = semantic_meaning
        if universal_model_path is not None:
            if not dom.is_valid_model_path(universal_model_path):
                raise dom.KBValidationError(
                    f"universal_model_path {universal_model_path!r} is not "
                    "a Universal Security Model path")
            row.universal_model_path = universal_model_path
        if admin_notes is not None:
            dom.check_text("admin_notes", admin_notes, allow_empty=True,
                           max_len=dom.MAX_NOTES_LEN)
            row.admin_notes = admin_notes
        if confidence is not None:
            row.confidence = dom.validate_confidence(confidence)
        else:
            row.confidence = dom.DEFAULT_ADMIN_CONFIDENCE
        row.admin_confirmed = True
        row.version += 1
        self._record(row, actor,
                     reason if reason is not None else "Admin confirmation")
        await self.db.flush()
        return _to_domain(row)

    async def reject(
        self,
        mapping_id: str,
        actor: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> DomainMapping:
        """
        Reject a mapping (explicit administrator action).

        Marks the row unconfirmed with a REJECTED note, bumps the version
        and records history. Never deletes: audit history survives.
        """
        actor = dom.validate_actor(actor)
        reason = dom.validate_reason(reason)
        row = await self._require_row(mapping_id)
        row.admin_confirmed = False
        row.admin_notes = (
            f"{dom.REJECTED_PREFIX} {reason or 'No reason provided'}")
        row.version += 1
        self._record(
            row, actor, f"Admin rejection: {reason or 'No reason provided'}")
        await self.db.flush()
        return _to_domain(row)

    async def update_confidence(
        self,
        mapping_id: str,
        confidence: Any,
        actor: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> DomainMapping:
        """Versioned confidence change as evidence accumulates (F10)."""
        actor = dom.validate_actor(actor)
        reason = dom.validate_reason(reason)
        row = await self._require_row(mapping_id)
        row.confidence = dom.validate_confidence(confidence)
        row.version += 1
        self._record(row, actor,
                     reason if reason is not None else "Confidence update")
        await self.db.flush()
        return _to_domain(row)

    async def get_versions(self, mapping_id: str) -> list:
        """Version history, chronological (ASC). Unknown ids yield []."""
        try:
            mid = uuid.UUID(dom.validate_mapping_id(mapping_id))
        except dom.KBError:
            return []
        stmt = (select(VersionRow)
                .where(VersionRow.mapping_id == mid)
                .order_by(asc(VersionRow.version), asc(VersionRow.id)))
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def list_mappings(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        confirmed_only: bool = False,
        confidence_min: Optional[float] = None,
        confidence_max: Optional[float] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[DomainMapping]:
        """List mappings with canonical literal filters (F13).

        Filters match literally (no wildcard reinterpretation); ordering is
        canonical (vendor, platform, raw_syntax, id) so repeated and
        multi-process runs agree (F14). limit=None means unbounded.
        """
        limit, offset = dom.validate_limit_offset(limit, offset)
        conditions = []
        if vendor is not None:
            if not isinstance(vendor, str):
                raise TypeError("vendor filter must be str")
            conditions.append(MappingRow.vendor == vendor.strip().lower())
        if platform is not None:
            if not isinstance(platform, str):
                raise TypeError("platform filter must be str")
            conditions.append(MappingRow.platform == platform.strip().lower())
        if confirmed_only:
            conditions.append(MappingRow.admin_confirmed == True)  # noqa: E712
        if confidence_min is not None:
            conditions.append(MappingRow.confidence >= float(confidence_min))
        if confidence_max is not None:
            conditions.append(MappingRow.confidence <= float(confidence_max))
        stmt = select(MappingRow)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(asc(MappingRow.vendor), asc(MappingRow.platform),
                             asc(MappingRow.raw_syntax), asc(MappingRow.id))
        if offset:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        result = await self.db.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

    async def count_mappings(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        confirmed_only: bool = False,
        confidence_min: Optional[float] = None,
        confidence_max: Optional[float] = None,
    ) -> int:
        """Count mappings under the same filters as list_mappings."""
        conditions = []
        if vendor is not None:
            if not isinstance(vendor, str):
                raise TypeError("vendor filter must be str")
            conditions.append(MappingRow.vendor == vendor.strip().lower())
        if platform is not None:
            if not isinstance(platform, str):
                raise TypeError("platform filter must be str")
            conditions.append(MappingRow.platform == platform.strip().lower())
        if confirmed_only:
            conditions.append(MappingRow.admin_confirmed == True)  # noqa: E712
        if confidence_min is not None:
            conditions.append(MappingRow.confidence >= float(confidence_min))
        if confidence_max is not None:
            conditions.append(MappingRow.confidence <= float(confidence_max))
        stmt = select(func.count(MappingRow.id))
        if conditions:
            stmt = stmt.where(and_(*conditions))
        result = await self.db.execute(stmt)
        return result.scalar()

    async def get_stats(self) -> dict:
        """Knowledge base statistics (deterministic ordering, F14)."""
        total = await self.count_mappings()
        confirmed = await self.count_mappings(confirmed_only=True)
        vendor_stmt = (select(MappingRow.vendor).distinct()
                       .order_by(asc(MappingRow.vendor)))
        vendor_result = await self.db.execute(vendor_stmt)
        vendors = sorted({v for v in vendor_result.scalars().all() if v})
        platform_stmt = (select(MappingRow.platform).distinct()
                         .order_by(asc(MappingRow.platform)))
        platform_result = await self.db.execute(platform_stmt)
        platforms = sorted({p for p in platform_result.scalars().all() if p})
        return {
            "total_mappings": total,
            "confirmed_mappings": confirmed,
            "pending_mappings": total - confirmed,
            "vendors": vendors,
            "platforms": platforms,
        }

    async def quality(self, mapping_id: str) -> dict:
        """§15.3 quality score.

        Same domain function and the same four recorded-fact axes as the
        in-memory twin, so the two stores can never disagree about a score.
        """
        row = await self._require_row(mapping_id)
        versions = await self.get_versions(mapping_id)
        candidates = (await self.db.execute(
            select(MappingRow).where(
                MappingRow.vendor == row.vendor,
                MappingRow.platform == row.platform,
                MappingRow.id != row.id))).scalars().all()
        target = dom.normalize_tokens(row.raw_syntax)
        neighbors = [
            n for n in candidates
            if dom.jaccard_similarity(
                target, dom.normalize_tokens(n.raw_syntax))
            >= dom.SUGGESTION_THRESHOLD
        ]
        agree = sum(
            1 for n in neighbors
            if n.semantic_meaning == row.semantic_meaning
            and n.universal_model_path == row.universal_model_path)
        creation_conf = (versions[0].confidence if versions
                         else row.confidence)
        rejected = (row.admin_notes or "").startswith(dom.REJECTED_PREFIX)
        return dom.quality_score(
            admin_confirmed=bool(row.admin_confirmed),
            confidence=row.confidence,
            version=row.version,
            confirm_events=dom.count_confirmations(bool(row.admin_confirmed),
                                                   versions),
            creation_confidence=creation_conf,
            agree=agree,
            disagree=len(neighbors) - agree,
            rejected=rejected,
        )
