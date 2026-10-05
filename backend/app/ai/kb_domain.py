"""
Knowledge Base domain contract.

Single canonical home for every business rule answered by the four
Knowledge Base layers (in-memory store, SQLAlchemy repository, REST API,
adaptive workflow):

- canonical identity (vendor / platform / raw_syntax)
- field validation (types, bounds, model paths, control characters)
- version-record construction (one post-change convention)
- trust policy (which mappings automatic reuse may consume)
- quality scoring (spec section 15.3 axes, deterministic)
- model-path validation and relevance derivation (model is the source)

Stores differ ONLY in I/O mechanics (dict index vs SQL). They share every
rule here, so "the knowledge base says X" is unambiguous.
"""

from __future__ import annotations

from typing import Any, Optional


# ---------------------------------------------------------------------------
# Typed domain errors. All value problems subclass ValueError so existing
# `except ValueError` handling keeps working; type problems use TypeError.
# Repository/API layers translate these to 409/422/404 (never raw driver
# errors, never HTTP 500 for domain input).
# ---------------------------------------------------------------------------

class KBError(ValueError):
    """Base class for knowledge-base domain errors."""


class KBNotFoundError(KBError):
    """A mapping id names no stored mapping."""


class KBValidationError(KBError):
    """A field value violates the domain contract."""


class KBDuplicateError(KBError):
    """A concurrent insert collided on the identity constraint."""


# ---------------------------------------------------------------------------
# Tunables (documented DESIGN DECISIONs where the spec is silent).
# ---------------------------------------------------------------------------

#: Trust policy for automatic reuse (§14.1 threshold enforcement): a mapping
#: is auto-reusable only when confirmed AND at/above this confidence.
KB_TRUST_THRESHOLD = 0.7

#: Default confidence for an admin-asserted mapping (V06-39 contract).
DEFAULT_ADMIN_CONFIDENCE = 1.0

#: Default confidence for an unconfirmed suggestion/hypothesis.
DEFAULT_SUGGESTION_CONFIDENCE = 0.5

#: Storage bounds (F9/F17). raw_syntax TEXT is capped so a single row cannot
#: bloat list responses or similarity scans; meanings/notes capped likewise.
MAX_RAW_SYNTAX_LEN = 4096
MAX_MEANING_LEN = 2000
MAX_NOTES_LEN = 2000
MAX_REASON_LEN = 500
VENDOR_MAX_LEN = 50
PLATFORM_MAX_LEN = 50

#: Prefix marking a rejected row's notes (kept, never deleted).
REJECTED_PREFIX = "REJECTED:"

#: Fallback relevance when a mapping names no (valid) model path.
DEFAULT_RELEVANCE = "medium"

#: Jaccard threshold for suggestion candidacy (suggestion-only, never identity).
SUGGESTION_THRESHOLD = 0.8

#: Confidence range for stored estimates.
MIN_CONFIDENCE = 0.0
MAX_CONFIDENCE = 1.0

#: Upper bound for an explicit pagination limit (F17). limit=None stays
#: unbounded; a caller asking for more than this is a caller bug.
MAX_PAGE_SIZE = 5000

#: Control characters rejected in every free-text field (F17, CWE-158).
_UNSAFE_RE = None  # compiled lazily to keep import light


def _unsafe_re():
    global _UNSAFE_RE
    if _UNSAFE_RE is None:
        import re
        _UNSAFE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")
    return _UNSAFE_RE


# ---------------------------------------------------------------------------
# Canonical identity (F4/F12/F13). One representation on every path:
# create, duplicate detection, lookup, list filters, update, versioning.
# ---------------------------------------------------------------------------

def canonical_vendor(vendor: Any) -> str:
    """Lowercase + strip. Non-string input is a TypeError."""
    if not isinstance(vendor, str):
        raise TypeError(f"vendor must be str, got {type(vendor).__name__}")
    return vendor.strip().lower()


def canonical_platform(platform: Any) -> str:
    """Lowercase + strip. Non-string input is a TypeError."""
    if not isinstance(platform, str):
        raise TypeError(f"platform must be str, got {type(platform).__name__}")
    return platform.strip().lower()


def canonical_syntax(raw_syntax: Any) -> str:
    """Strip outer whitespace (incl. line endings). Case and internal
    spacing are significant: `Hostname R1` and `hostname  R1` are different
    identities. Non-string input is a TypeError."""
    if not isinstance(raw_syntax, str):
        raise TypeError(
            f"raw_syntax must be str, got {type(raw_syntax).__name__}")
    return raw_syntax.strip()


def canonical_identity(vendor: Any, platform: Any,
                       raw_syntax: Any) -> tuple[str, str, str]:
    """The (vendor, platform, raw_syntax) identity tuple used for dedupe,
    lookup, filters and the UNIQUE constraint."""
    return (canonical_vendor(vendor), canonical_platform(platform),
            canonical_syntax(raw_syntax))


def normalize_tokens(syntax: str) -> str:
    """Lowercase + whitespace-collapsed form, for suggestion similarity only
    (never for identity)."""
    return " ".join(syntax.lower().split())


def jaccard_similarity(a: str, b: str) -> float:
    """Token Jaccard similarity in [0.0, 1.0]; deterministic."""
    if not a or not b:
        return 0.0
    set_a = set(a.split())
    set_b = set(b.split())
    union = set_a | set_b
    return len(set_a & set_b) / len(union) if union else 0.0


# ---------------------------------------------------------------------------
# Validation (F9/F17). Raises TypeError (wrong Python type) or
# KBValidationError (bad value). Called at every entry point: service,
# both stores, API (via schemas + service), adaptive.
# ---------------------------------------------------------------------------

def check_text(name: str, value: Any, *, allow_empty: bool,
               max_len: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if _unsafe_re().search(value):
        raise KBValidationError(
            f"{name} contains NUL/control characters")
    if not allow_empty and not value.strip():
        raise KBValidationError(f"{name} must not be empty")
    if len(value) > max_len:
        raise KBValidationError(
            f"{name} exceeds {max_len} characters")
    return value


def validate_actor(actor: Any) -> str:
    """Every state-changing operation names its actor (spec 15.1/15.2
    NOT NULL). Missing/blank actors are a typed error, never a driver
    IntegrityError."""
    if actor is None:
        raise KBValidationError("actor is required")
    if not isinstance(actor, str):
        raise TypeError(
            f"actor must be str, got {type(actor).__name__}")
    actor = actor.strip()
    if not actor:
        raise KBValidationError("actor is required")
    if len(actor) > 100:
        raise KBValidationError("actor exceeds 100 characters")
    if _unsafe_re().search(actor):
        raise KBValidationError("actor contains NUL/control characters")
    return actor


def validate_confidence(confidence: Any) -> float:
    """Stored estimates live in [0.0, 1.0]. bool is rejected explicitly
    (True == 1 would otherwise slip through isinstance int checks)."""
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise TypeError(
            "confidence must be a number, "
            f"got {type(confidence).__name__}")
    value = float(confidence)
    if not (MIN_CONFIDENCE <= value <= MAX_CONFIDENCE):
        raise KBValidationError(
            f"confidence {value!r} outside [0.0, 1.0]")
    return value


def validate_mapping_fields(
    *,
    vendor: Any,
    platform: Any,
    raw_syntax: Any,
    semantic_meaning: Any,
    universal_model_path: Any,
    admin_notes: Any = None,
) -> tuple[str, str, str]:
    """Validate (not canonicalize) creation content. Returns nothing;
    raises on the first violation. universal_model_path is REQUIRED and
    must name a real model node (None/empty/bogus rejected)."""
    if not isinstance(vendor, str):
        raise TypeError(
            f"vendor must be str, got {type(vendor).__name__}")
    if not isinstance(platform, str):
        raise TypeError(
            f"platform must be str, got {type(platform).__name__}")
    vendor_c, platform_c, syntax_c = canonical_identity(
        vendor, platform, raw_syntax)
    if not vendor_c:
        raise KBValidationError("vendor must not be empty")
    if len(vendor_c) > VENDOR_MAX_LEN:
        raise KBValidationError(
            f"vendor exceeds {VENDOR_MAX_LEN} characters")
    if not platform_c:
        raise KBValidationError("platform must not be empty")
    if len(platform_c) > PLATFORM_MAX_LEN:
        raise KBValidationError(
            f"platform exceeds {PLATFORM_MAX_LEN} characters")
    if not syntax_c:
        raise KBValidationError("raw_syntax must not be empty")
    if len(raw_syntax) > MAX_RAW_SYNTAX_LEN:
        raise KBValidationError(
            f"raw_syntax exceeds {MAX_RAW_SYNTAX_LEN} characters")
    if _unsafe_re().search(raw_syntax):
        raise KBValidationError(
            "raw_syntax contains NUL/control characters")
    check_text("semantic_meaning", semantic_meaning, allow_empty=False,
               max_len=MAX_MEANING_LEN)
    if universal_model_path is None:
        raise KBValidationError("universal_model_path is required")
    if not isinstance(universal_model_path, str):
        raise TypeError("universal_model_path must be str, "
                        f"got {type(universal_model_path).__name__}")
    if not is_valid_model_path(universal_model_path):
        raise KBValidationError(
            f"universal_model_path {universal_model_path!r} is not a "
            "Universal Security Model path")
    if admin_notes is not None:
        check_text("admin_notes", admin_notes, allow_empty=True,
                   max_len=MAX_NOTES_LEN)
    return vendor_c, platform_c, syntax_c


def validate_reason(reason: Any) -> Optional[str]:
    if reason is None:
        return None
    if not isinstance(reason, str):
        raise TypeError(
            f"change_reason must be str, got {type(reason).__name__}")
    if _unsafe_re().search(reason):
        raise KBValidationError(
            "change_reason contains NUL/control characters")
    if len(reason) > MAX_REASON_LEN:
        raise KBValidationError(
            f"change_reason exceeds {MAX_REASON_LEN} characters")
    return reason


def validate_limit_offset(limit: Any, offset: Any) -> tuple[Optional[int], int]:
    """Negative/absurd pagination values are typed errors (F17), never raw
    driver errors. limit=None means unbounded; an explicit limit is capped
    at MAX_PAGE_SIZE so one caller cannot ask the database for an
    unbounded scan."""
    if limit is not None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError(
                f"limit must be int, got {type(limit).__name__}")
        if limit < 0:
            raise KBValidationError("limit must be >= 0")
        if limit > MAX_PAGE_SIZE:
            raise KBValidationError(
                f"limit must be <= {MAX_PAGE_SIZE} (use limit=None for all rows)")
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise TypeError(
            f"offset must be int, got {type(offset).__name__}")
    if offset < 0:
        raise KBValidationError("offset must be >= 0")
    return limit, offset


def validate_mapping_id(mapping_id: Any) -> str:
    """Malformed ids are ValueError, never driver errors (F17)."""
    if not isinstance(mapping_id, str):
        raise TypeError(
            f"mapping_id must be str, got {type(mapping_id).__name__}")
    import uuid as _uuid
    try:
        return str(_uuid.UUID(mapping_id))
    except (ValueError, AttributeError, TypeError):
        raise KBValidationError(
            f"mapping_id {mapping_id!r} is not a valid UUID")


# ---------------------------------------------------------------------------
# Model paths and relevance (F9/F15, §25). The Universal Security Model is
# the single source of truth; no second path list lives here.
# ---------------------------------------------------------------------------

def is_valid_model_path(path: Any) -> bool:
    """Reusable model-path check for training API, stores, domain
    validation and AI output validation."""
    if not isinstance(path, str) or not path:
        return False
    from app.engines.universal_model import UniversalSecurityModel
    return UniversalSecurityModel().is_valid_path(path)


def relevance_for_path(universal_model_path: Any) -> str:
    """Security relevance derived from the mapping's own model path.

    Falls back to DEFAULT_RELEVANCE only when the mapping names no
    (valid) path — a documented default, never a per-mapping override.
    """
    if isinstance(universal_model_path, str) and universal_model_path:
        from app.engines.universal_model import UniversalSecurityModel
        concept = UniversalSecurityModel().get_concept(universal_model_path)
        if concept is not None and getattr(concept, "relevance", None) is not None:
            return str(concept.relevance.value
                        if hasattr(concept.relevance, "value")
                        else concept.relevance)
    return DEFAULT_RELEVANCE


# ---------------------------------------------------------------------------
# Version records (F7). ONE convention everywhere: every mutation appends a
# POST-change snapshot labelled with the NEW version number, carrying actor,
# timestamp and reason. No-op writes append nothing and bump nothing.
# ---------------------------------------------------------------------------

def build_version_record(*, mapping_id: Any, version: int, raw_syntax: str,
                         semantic_meaning: str,
                         universal_model_path: Optional[str],
                         confidence: Optional[float], actor: str,
                         reason: Optional[str]) -> dict[str, Any]:
    """Field dict for a version row (both stores use it verbatim)."""
    from datetime import datetime
    return {
        "mapping_id": mapping_id,
        "version": version,
        "raw_syntax": raw_syntax,
        "semantic_meaning": semantic_meaning,
        "universal_model_path": universal_model_path,
        "confidence": confidence,
        "changed_by": actor,
        # Columns are naive TIMESTAMP (models use default=datetime.utcnow);
        # asyncpg rejects tz-aware parameters, so stamp naive UTC.
        "changed_at": datetime.utcnow(),
        "change_reason": reason,
    }


def is_noop_update(current: dict[str, Any], fields: dict[str, Any]) -> bool:
    """True when an edit changes nothing (phantom-version guard, F7)."""
    for key, value in fields.items():
        if value is not None and current.get(key) != value:
            return False
    return True


# ---------------------------------------------------------------------------
# Trust policy (§14.1 threshold enforcement, §14.3.2 review routing).
# ---------------------------------------------------------------------------

def is_trusted(*, admin_confirmed: bool, confidence: Any) -> bool:
    """Automatic reuse requires BOTH human confirmation and an estimated
    confidence at/above KB_TRUST_THRESHOLD. Anything else is suggestion-only
    (visible for review, never authoritative)."""
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        return False
    return bool(admin_confirmed) and conf >= KB_TRUST_THRESHOLD


# ---------------------------------------------------------------------------
# Quality scoring (§15.3). Deterministic, explainable, no wall clock:
#   score = 0.40 * confirmations + 0.25 * consistency
#         + 0.20 * history      + 0.15 * ai_confidence_at_creation
# Weights are a DESIGN DECISION (the spec fixes axes, not math).
# ---------------------------------------------------------------------------

QUALITY_WEIGHTS = {
    "confirmations": 0.40,
    "consistency": 0.25,
    "history": 0.20,
    "ai_confidence": 0.15,
}

CONFIRM_REASONS = {"Admin confirmation", "Initial creation"}


def count_confirmations(admin_confirmed: bool,
                        versions: list) -> int:
    """Confirmation events for the quality axis: explicit 'Admin
    confirmation' records, plus one when the mapping is currently confirmed
    without such a record (confirmation granted at creation)."""
    explicit = sum(1 for v in versions
                   if getattr(v, "change_reason", None) == "Admin confirmation")
    if admin_confirmed and explicit == 0:
        return 1
    return explicit


def quality_score(*, admin_confirmed: bool, confidence: Any, version: int,
                  confirm_events: int, creation_confidence: Any,
                  agree: int, disagree: int,
                  rejected: bool = False) -> dict[str, Any]:
    """Compute the §15.3 quality score from recorded facts only.

    - confirmations: min(1, confirm_events / 2) — repeated reaffirmation
      saturates; an unconfirmed mapping scores 0 here.
    - consistency: agree / (agree + disagree) over >=0.8-similar neighbours
      sharing vendor+platform; 0.5 when there are none (neutral,
      documented — not vacuous perfection).
    - history: min(1, (version - 1) / 4) — v1 scores 0, v5+ saturates.
    - ai_confidence_at_creation: the stored estimate, clamped to [0, 1].
    - rejected: a rejected mapping's confirmations/history no longer vouch
      for it (the version trail is a rejection trail); only residual
      consistency and creation confidence count.
    """
    try:
        ai_conf = max(0.0, min(1.0, float(creation_confidence)))
    except (TypeError, ValueError):
        ai_conf = 0.5
    if rejected:
        conf_axis = 0.0
        hist_axis = 0.0
    else:
        conf_axis = min(1.0, max(0, confirm_events) / 2.0) \
            if admin_confirmed else 0.0
        hist_axis = min(1.0, max(0, version - 1) / 4.0)
    total_pairs = max(0, agree) + max(0, disagree)
    cons_axis = (max(0, agree) / total_pairs) if total_pairs else 0.5
    score = (QUALITY_WEIGHTS["confirmations"] * conf_axis
             + QUALITY_WEIGHTS["consistency"] * cons_axis
             + QUALITY_WEIGHTS["history"] * hist_axis
             + QUALITY_WEIGHTS["ai_confidence"] * ai_conf)
    return {
        "score": round(score, 4),
        "axes": {
            "confirmations": round(conf_axis, 4),
            "consistency": round(cons_axis, 4),
            "history": round(hist_axis, 4),
            "ai_confidence_at_creation": round(ai_conf, 4),
        },
    }
