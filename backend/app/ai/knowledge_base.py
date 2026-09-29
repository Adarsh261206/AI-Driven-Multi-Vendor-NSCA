"""
Knowledge Base

Canonical in-memory implementation of the Knowledge Base domain contract
(spec 10.6 / 9.2 / 15.x).

Every business rule lives in app.ai.kb_domain and is shared verbatim with
the SQLAlchemy repository, the REST layer and the adaptive workflow, so
"the knowledge base says X" is unambiguous:

- identity is (vendor, platform, raw_syntax) canonicalized
  (lower/strip, lower/strip, strip)
- lookup() is EXACT-only and total (never raises, never fuzzy-matches);
  similarity is suggestion-only via lookup_suggestions()
- create() on an exact duplicate updates in place (versioned, no new row)
- update() never confirms and never fabricates confidence
- confirm()/reject() are explicit versioned lifecycle actions;
  reject marks, never deletes
- every mutation appends a POST-change version record; no-op writes
  append nothing
- actors are required (typed errors, never driver IntegrityErrors)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from app.ai import kb_domain as dom


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class TrainingMapping:
    """Canonical domain mapping (spec section 12 TrainingMapping)."""
    id: str
    vendor: str
    platform: str
    raw_syntax: str
    semantic_meaning: str
    universal_model_path: str
    confidence: float = 1.0
    admin_confirmed: bool = False
    admin_notes: Optional[str] = None
    version: int = 1
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "platform": self.platform,
            "raw_syntax": self.raw_syntax,
            "semantic_meaning": self.semantic_meaning,
            "universal_model_path": self.universal_model_path,
            "confidence": self.confidence,
            "admin_confirmed": self.admin_confirmed,
            "admin_notes": self.admin_notes,
            "version": self.version,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class MappingVersion:
    """Version history of a mapping (POST-change snapshots)."""
    id: str
    mapping_id: str
    version: int
    raw_syntax: str
    semantic_meaning: str
    universal_model_path: Optional[str] = None
    confidence: Optional[float] = None
    changed_by: Optional[str] = None
    changed_at: datetime = field(default_factory=_utcnow)
    change_reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mapping_id": self.mapping_id,
            "version": self.version,
            "raw_syntax": self.raw_syntax,
            "semantic_meaning": self.semantic_meaning,
            "universal_model_path": self.universal_model_path,
            "confidence": self.confidence,
            "changed_by": self.changed_by,
            "changed_at": self.changed_at.isoformat(),
            "change_reason": self.change_reason,
        }


class KnowledgeBase:
    """
    Knowledge Base for semantic mappings (deterministic in-memory store).

    Reference implementation of the canonical contract; the SQLAlchemy
    repository mirrors its observable behavior row for row.
    """

    def __init__(self):
        self._mappings: dict[str, TrainingMapping] = {}
        # Canonical identity index: O(1) create/dedupe/lookup (F16).
        self._index: dict[tuple[str, str, str], str] = {}
        self._versions: dict[str, list[MappingVersion]] = {}

    # ------------------------------------------------------------------
    # Lookup (F2/F4/F5): exact-only, total, deterministic.
    # ------------------------------------------------------------------

    def lookup(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        require_confirmed: bool = True,
    ) -> Optional[TrainingMapping]:
        """
        Look up a mapping by vendor/platform/syntax (exact canonical match).

        Returns the mapping or None. Never raises for domain input, never
        fuzzy-matches: similarity is suggestion-only (lookup_suggestions).
        Hostile argument types are a miss, not a crash.
        """
        try:
            key = dom.canonical_identity(vendor, platform, raw_syntax)
        except TypeError:
            return None
        mapping_id = self._index.get(key)
        if mapping_id is None:
            return None
        mapping = self._mappings.get(mapping_id)
        if mapping is None:
            return None
        if require_confirmed and not mapping.admin_confirmed:
            return None
        return mapping

    def lookup_suggestions(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        *,
        require_confirmed: bool = True,
        threshold: float = dom.SUGGESTION_THRESHOLD,
        limit: int = 5,
    ) -> list[tuple[TrainingMapping, float]]:
        """
        Suggestion-only similarity search (F5).

        Returns [(mapping, similarity)] sorted by descending similarity
        then canonical identity. NON-AUTHORITATIVE: candidates require
        explicit administrator action; nothing is stored, overwritten or
        deduplicated as a side effect.
        """
        vendor_c = dom.canonical_vendor(vendor)
        platform_c = dom.canonical_platform(platform)
        if not isinstance(raw_syntax, str):
            raise TypeError(
                f"raw_syntax must be str, got {type(raw_syntax).__name__}")
        target = dom.normalize_tokens(raw_syntax)
        if not target:
            return []
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise dom.KBValidationError("limit must be >= 0")
        out: list[tuple[TrainingMapping, float]] = []
        for mapping in self._mappings.values():
            if mapping.vendor != vendor_c or mapping.platform != platform_c:
                continue
            if require_confirmed and not mapping.admin_confirmed:
                continue
            if dom.canonical_syntax(mapping.raw_syntax) == dom.canonical_syntax(
                    raw_syntax):
                continue  # exact hits are not suggestions
            sim = dom.jaccard_similarity(
                target, dom.normalize_tokens(mapping.raw_syntax))
            if sim >= threshold:
                out.append((mapping, sim))
        out.sort(key=lambda item: (-item[1], item[0].vendor,
                                   item[0].platform, item[0].raw_syntax,
                                   item[0].id))
        return out[:limit]

    # ------------------------------------------------------------------
    # Create (F2/F8/F9/F10/F12/F16/F17).
    # ------------------------------------------------------------------

    def create(
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
    ) -> TrainingMapping:
        """
        Create a new training mapping, or version-update the exact
        duplicate in place (single row per canonical identity).

        An explicit estimated confidence is preserved verbatim; when omitted
        it defaults to 1.0 for admin-asserted mappings and 0.5 for
        unconfirmed suggestions. Confirmation state of an existing row is
        preserved (create never confirms via the duplicate path either —
        pass admin_confirmed explicitly only for new rows).
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

        key = (vendor_c, platform_c, syntax_c)
        existing_id = self._index.get(key)
        if existing_id is not None and existing_id in self._mappings:
            # Exact duplicate: versioned in-place update (no second row).
            # Meaning/path/notes refresh; confirmation state and confidence
            # are preserved (edit never confirms, never fabricates).
            return self.update(
                mapping_id=existing_id,
                semantic_meaning=semantic_meaning,
                universal_model_path=universal_model_path,
                admin_notes=admin_notes,
                change_reason="Duplicate create merged",
                actor=actor,
            )

        mapping_id = str(uuid.uuid4())
        mapping = TrainingMapping(
            id=mapping_id,
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
        self._mappings[mapping_id] = mapping
        self._index[key] = mapping_id
        initial = dom.build_version_record(
            mapping_id=mapping_id,
            version=1,
            raw_syntax=syntax_c,
            semantic_meaning=semantic_meaning,
            universal_model_path=universal_model_path,
            confidence=confidence,
            actor=actor,
            reason="Initial creation",
        )
        self._versions[mapping_id] = [
            MappingVersion(id=str(uuid.uuid4()), **initial)]
        return mapping

    # ------------------------------------------------------------------
    # Update / confirm / reject / confidence (F3/F7/F10).
    # ------------------------------------------------------------------

    def _require(self, mapping_id: str) -> TrainingMapping:
        mid = dom.validate_mapping_id(mapping_id)
        mapping = self._mappings.get(mid)
        if mapping is None:
            raise dom.KBNotFoundError(f"Mapping {mapping_id} not found")
        return mapping

    def _record(self, mapping: TrainingMapping, actor: str,
                reason: Optional[str]) -> None:
        fields = dom.build_version_record(
            mapping_id=mapping.id,
            version=mapping.version,
            raw_syntax=mapping.raw_syntax,
            semantic_meaning=mapping.semantic_meaning,
            universal_model_path=mapping.universal_model_path,
            confidence=mapping.confidence,
            actor=actor,
            reason=reason,
        )
        self._versions.setdefault(mapping.id, []).append(
            MappingVersion(id=str(uuid.uuid4()), **fields))
        mapping.updated_at = _utcnow()

    def update(
        self,
        mapping_id: str,
        semantic_meaning: Optional[str] = None,
        universal_model_path: Optional[str] = None,
        admin_notes: Optional[str] = None,
        change_reason: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> TrainingMapping:
        """
        Edit a mapping (creates a new version).

        EDIT never confirms and never fabricates confidence: confirmation
        state and confidence are preserved. A no-op edit (nothing actually
        changes) bumps nothing and records nothing (F7).
        """
        actor = dom.validate_actor(actor)
        reason = dom.validate_reason(change_reason)
        mapping = self._require(mapping_id)
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
        current = {"semantic_meaning": mapping.semantic_meaning,
                   "universal_model_path": mapping.universal_model_path,
                   "admin_notes": mapping.admin_notes}
        if dom.is_noop_update(current, changes):
            return mapping
        for key, value in changes.items():
            setattr(mapping, key, value)
        mapping.version += 1
        self._record(mapping, actor, reason if reason is not None else "Edit")
        return mapping

    def confirm(
        self,
        mapping_id: str,
        actor: Optional[str] = None,
        semantic_meaning: Optional[str] = None,
        universal_model_path: Optional[str] = None,
        admin_notes: Optional[str] = None,
        confidence: Optional[float] = None,
        change_reason: Optional[str] = None,
    ) -> TrainingMapping:
        """
        Confirm a mapping (explicit administrator action).

        Always appends a version record (reaffirmation is an event). An
        explicit estimated confidence is preserved verbatim; otherwise the
        administrator's validation is itself the evidence and the estimate
        becomes DEFAULT_ADMIN_CONFIDENCE (1.0) - the same rule as the SQL
        repository. A proposal's 0.5 hypothesis estimate is never promoted
        by an EDIT, only by this explicit action.
        """
        actor = dom.validate_actor(actor)
        reason = dom.validate_reason(change_reason)
        mapping = self._require(mapping_id)
        if semantic_meaning is not None:
            if not isinstance(semantic_meaning, str) or not semantic_meaning.strip():
                raise dom.KBValidationError(
                    "semantic_meaning must not be empty")
            mapping.semantic_meaning = semantic_meaning
        if universal_model_path is not None:
            if not dom.is_valid_model_path(universal_model_path):
                raise dom.KBValidationError(
                    f"universal_model_path {universal_model_path!r} is not "
                    "a Universal Security Model path")
            mapping.universal_model_path = universal_model_path
        if admin_notes is not None:
            dom.check_text("admin_notes", admin_notes, allow_empty=True,
                           max_len=dom.MAX_NOTES_LEN)
            mapping.admin_notes = admin_notes
        if confidence is not None:
            mapping.confidence = dom.validate_confidence(confidence)
        else:
            mapping.confidence = dom.DEFAULT_ADMIN_CONFIDENCE
        mapping.admin_confirmed = True
        mapping.version += 1
        self._record(mapping, actor,
                     reason if reason is not None else "Admin confirmation")
        return mapping

    def reject(
        self,
        mapping_id: str,
        actor: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> TrainingMapping:
        """
        Reject a mapping (explicit administrator action).

        Marks the row unconfirmed with a REJECTED note, bumps the version
        and records history. Never deletes: audit history survives.
        """
        actor = dom.validate_actor(actor)
        reason = dom.validate_reason(reason)
        mapping = self._require(mapping_id)
        mapping.admin_confirmed = False
        mapping.admin_notes = (
            f"{dom.REJECTED_PREFIX} {reason or 'No reason provided'}")
        mapping.version += 1
        self._record(mapping, actor,
                     f"Admin rejection: {reason or 'No reason provided'}")
        return mapping

    def update_confidence(
        self,
        mapping_id: str,
        confidence: Any,
        actor: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> TrainingMapping:
        """Versioned confidence change as evidence accumulates (F10)."""
        actor = dom.validate_actor(actor)
        reason = dom.validate_reason(reason)
        mapping = self._require(mapping_id)
        mapping.confidence = dom.validate_confidence(confidence)
        mapping.version += 1
        self._record(mapping, actor,
                     reason if reason is not None else "Confidence update")
        return mapping

    # ------------------------------------------------------------------
    # Reads (F13/F14): canonical filters, deterministic order, guards.
    # ------------------------------------------------------------------

    def get_by_id(self, mapping_id: str) -> Optional[TrainingMapping]:
        """Fetch by id; None when missing (malformed ids are ValueError)."""
        return self._mappings.get(dom.validate_mapping_id(mapping_id))

    def get_versions(self, mapping_id: str) -> list[MappingVersion]:
        """Version history, chronological (ASC). Unknown ids yield []."""
        try:
            mid = dom.validate_mapping_id(mapping_id)
        except dom.KBError:
            return []
        return list(self._versions.get(mid, []))

    def list_mappings(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        confirmed_only: bool = False,
        confidence_min: Optional[float] = None,
        confidence_max: Optional[float] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[TrainingMapping]:
        """List mappings with canonical literal filters (F13).

        Filters match literally (no wildcard reinterpretation); ordering is
        canonical (vendor, platform, raw_syntax, id) so repeated and
        multi-process runs agree (F14). limit=None means unbounded.
        """
        limit, offset = dom.validate_limit_offset(limit, offset)
        results = list(self._mappings.values())
        if vendor is not None:
            if not isinstance(vendor, str):
                raise TypeError("vendor filter must be str")
            vendor_c = vendor.strip().lower()
            results = [m for m in results if m.vendor == vendor_c]
        if platform is not None:
            if not isinstance(platform, str):
                raise TypeError("platform filter must be str")
            platform_c = platform.strip().lower()
            results = [m for m in results if m.platform == platform_c]
        if confirmed_only:
            results = [m for m in results if m.admin_confirmed]
        if confidence_min is not None:
            results = [m for m in results
                       if m.confidence >= float(confidence_min)]
        if confidence_max is not None:
            results = [m for m in results
                       if m.confidence <= float(confidence_max)]
        results.sort(key=lambda m: (m.vendor, m.platform, m.raw_syntax, m.id))
        if offset:
            results = results[offset:]
        if limit is not None:
            results = results[:limit]
        return results

    def count_mappings(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        confirmed_only: bool = False,
        confidence_min: Optional[float] = None,
        confidence_max: Optional[float] = None,
    ) -> int:
        """Count mappings under the same filters as list_mappings."""
        return len(self.list_mappings(
            vendor=vendor, platform=platform, confirmed_only=confirmed_only,
            confidence_min=confidence_min, confidence_max=confidence_max))

    def get_stats(self) -> dict:
        """Knowledge base statistics (deterministic ordering, F14)."""
        mappings = list(self._mappings.values())
        confirmed = [m for m in mappings if m.admin_confirmed]
        return {
            "total_mappings": len(mappings),
            "confirmed_mappings": len(confirmed),
            "pending_mappings": len(mappings) - len(confirmed),
            "vendors": sorted({m.vendor for m in mappings}),
            "platforms": sorted({m.platform for m in mappings}),
        }

    def quality(
        self,
        mapping_id: str,
    ) -> dict[str, Any]:
        """§15.3 quality score, derived consistently from recorded facts."""
        mapping = self._require(mapping_id)
        versions = self.get_versions(mapping_id)
        neighbors = [
            m for m in self._mappings.values()
            if m.id != mapping.id and m.vendor == mapping.vendor
            and m.platform == mapping.platform
            and dom.jaccard_similarity(
                dom.normalize_tokens(mapping.raw_syntax),
                dom.normalize_tokens(m.raw_syntax)) >= dom.SUGGESTION_THRESHOLD
        ]
        agree = sum(1 for n in neighbors
                    if n.semantic_meaning == mapping.semantic_meaning
                    and n.universal_model_path == mapping.universal_model_path)
        creation_conf = versions[0].confidence if versions else mapping.confidence
        rejected = (mapping.admin_notes or "").startswith(dom.REJECTED_PREFIX)
        return dom.quality_score(
            admin_confirmed=mapping.admin_confirmed,
            confidence=mapping.confidence,
            version=mapping.version,
            confirm_events=dom.count_confirmations(mapping.admin_confirmed,
                                                   versions),
            creation_confidence=creation_conf,
            agree=agree,
            disagree=len(neighbors) - agree,
            rejected=rejected,
        )

    @classmethod
    def from_rows(cls, rows: list[TrainingMapping]) -> "KnowledgeBase":
        """Build a consultation snapshot from domain rows (reanalyze flow).

        Index keys are canonicalized so legacy-unclean rows stay reachable;
        first row wins a canonical collision deterministically (input order).
        Snapshots are read-only by convention — lifecycle writes belong to
        the owning store.
        """
        kb = cls()
        for row in rows:
            key = (dom.canonical_vendor(row.vendor),
                   dom.canonical_platform(row.platform),
                   dom.canonical_syntax(row.raw_syntax))
            kb._mappings[row.id] = row
            kb._index.setdefault(key, row.id)
            kb._versions.setdefault(row.id, [])
        return kb
