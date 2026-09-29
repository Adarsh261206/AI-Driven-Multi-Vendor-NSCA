"""Canonical control-selection contract for Engine 07.

One domain-level component owns every selection/evaluation rule so the
registry, the benchmark execution engine, the audit executor and the REST
API cannot drift apart:

- vendor / platform / framework / framework-version normalization
- the single supported-platform alias map (delegated to the §25 canonical
  platform identity in app.engines.normalization — never redefined here)
- the single operator vocabulary and its canonical implementation
- the single overall-score formula
- the single confidence composition (normalization x rule, <0.70 -> REVIEW)
- framework inventory metadata derived from loaded controls (never
  hardcoded, never inferred from control-id shape or the audit request)

Design decisions (also recorded in ENGINE_07_FIX_REPORT.md):

- The §13.1 dual baseline is an EXPLICIT canonical mode ("CIS+NIST"),
  selected when no framework is requested. An explicit framework=CIS
  evaluates CIS controls only; framework=NIST evaluates NIST controls
  only. There is no silent fallback.
- overall_score = passed / evaluated over ALL evaluated controls
  (REVIEW counts as non-pass). Rationale: excluding REVIEW from the
  denominator lets a 1-pass/178-REVIEW audit score 100; the conservative
  formula cannot be inflated by unevaluable controls.
- confidence composition is multiplicative: final = normalization x rule.
  It uses both inputs, is bounded [0,1], is monotonic in either input,
  and can never exceed either input (no artificial inflation).
- Raw regex evidence (explicitly regex-based controls with matched raw
  text) enters composition as RAW_MATCH_CONFIDENCE = 0.85: weaker than a
  normalized model observation (0.95 direct-exact) but stronger than a
  derived value (0.75). This is an engineering constant, labelled here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Typed errors (F1/F2/F6/F9/F13). Layers translate these; they never surface
# as raw AttributeError/TypeError text in a compliance result.
# ---------------------------------------------------------------------------

class ComplianceError(Exception):
    """Base class for typed Engine 07 errors."""


class ComplianceInputError(ComplianceError):
    """Caller input is unusable (None, non-string, NUL/control characters)."""


class UnsupportedFrameworkError(ComplianceError):
    """Requested framework is not one of the loaded MVP frameworks."""


class UnknownFrameworkVersionError(ComplianceError):
    """Requested framework version does not exist in the loaded inventory."""


class UnsupportedVendorError(ComplianceError):
    """Requested vendor cannot be evaluated (no parser/controls contract)."""


class InvalidControlError(ComplianceError):
    """A control definition violates the canonical contract."""

    def __init__(self, control_id: str, reason: str) -> None:
        super().__init__(f"control {control_id!r}: {reason}")
        self.control_id = control_id
        self.reason = reason


class DuplicateControlError(InvalidControlError):
    """Two different controls claim the same canonical control id."""


# ---------------------------------------------------------------------------
# Canonical vocabularies
# ---------------------------------------------------------------------------

#: MVP frameworks (§13.1). Future frameworks (DISA STIG, ISO 27001) are NOT
#: listed: requesting one raises UnsupportedFrameworkError instead of
#: silently evaluating something else.
SUPPORTED_FRAMEWORKS = ("CIS", "NIST")

#: Explicit canonical dual-baseline mode (§13.1 workflow).
DUAL_BASELINE = "CIS+NIST"

#: Vendors with a parser + vendor control set + normalization contract.
#: Anything else is detection-only or unsupported for evaluation.
SUPPORTED_EVALUATION_VENDORS = frozenset({"cisco", "juniper"})

#: Marker vendor/platform of vendor-agnostic (NIST) controls.
UNIVERSAL_VENDOR = "universal"
UNIVERSAL_PLATFORM = "network_device"

#: The ONE operator vocabulary (§13.3 required operators plus the *_or_equal
#: variants and the established presence/regex operators used by the loaded
#: inventory). Anything else is a control configuration error, never an
#: implicit equals.
OPERATOR_VOCABULARY = frozenset({
    "equals",
    "not_equals",
    "greater_than",
    "greater_than_or_equal",
    "less_than",
    "less_than_or_equal",
    "contains",
    "in",
    "is_set",
    "not_set",
    "regex_match",
})

#: Confidence of raw regex evidence entering composition (see module doc).
RAW_MATCH_CONFIDENCE = 0.85

#: §13.4 REVIEW threshold on final confidence.
REVIEW_THRESHOLD = 0.70


# ---------------------------------------------------------------------------
# Normalization (F1/F2). Strip + case-fold everywhere; aliases centralized.
# ---------------------------------------------------------------------------

def normalize_vendor(vendor: Any) -> str:
    """Canonical vendor form. Non-string input is a TypeError (caller bug)."""
    if not isinstance(vendor, str):
        raise TypeError(f"vendor must be str, got {type(vendor).__name__}")
    return vendor.strip().lower()


def normalize_platform(vendor: str, platform: Any) -> str:
    """Canonical platform form via the single §25 alias map.

    The alias table lives in app.engines.normalization.CANONICAL_PLATFORM;
    it is imported (not copied) so the two modules cannot disagree.
    """
    if not isinstance(platform, str):
        raise TypeError(f"platform must be str, got {type(platform).__name__}")
    from app.engines.normalization import CANONICAL_PLATFORM

    vendor_c = normalize_vendor(vendor)
    platform_c = platform.strip().lower()
    return CANONICAL_PLATFORM.get((vendor_c, platform_c), platform_c)


def normalize_framework(framework: Any) -> Optional[str]:
    """Canonical framework form.

    None means "no framework requested" (the caller selects the explicit
    dual-baseline mode). "dual"/"all"/"cis+nist" select DUAL_BASELINE
    explicitly. Anything else must be a supported framework.
    """
    if framework is None:
        return None
    if not isinstance(framework, str):
        raise TypeError(
            f"framework must be str, got {type(framework).__name__}")
    cleaned = framework.strip()
    if not cleaned:
        raise UnsupportedFrameworkError(
            "framework must name a supported framework (CIS, NIST)")
    upper = cleaned.upper()
    if upper in ("DUAL", "ALL", "CIS+NIST", "NIST+CIS"):
        return DUAL_BASELINE
    if upper not in SUPPORTED_FRAMEWORKS:
        raise UnsupportedFrameworkError(
            f"unsupported framework {framework!r} "
            f"(supported: {', '.join(SUPPORTED_FRAMEWORKS)})")
    return upper


def normalize_framework_version(version: Any) -> Optional[str]:
    """Canonical framework-version form (validated against inventory later)."""
    if version is None:
        return None
    if not isinstance(version, str):
        raise TypeError(
            f"framework_version must be str, got {type(version).__name__}")
    cleaned = version.strip()
    if not cleaned:
        raise UnknownFrameworkVersionError(
            "framework_version must name a version present in the inventory")
    return cleaned


# ---------------------------------------------------------------------------
# Canonical operator implementation (F8). One function, shared by the
# benchmark engine and the registry consultation helper.
# ---------------------------------------------------------------------------

def apply_operator(actual: Any, expected: Any, operator: str,
                   negated: bool = False) -> bool:
    """Apply a canonical operator. Unknown operators raise (never equals)."""
    if operator == "equals":
        result = actual == expected
    elif operator == "not_equals":
        result = actual != expected
    elif operator == "contains":
        if isinstance(actual, str):
            result = str(expected) in actual
        elif isinstance(actual, (list, tuple, set)):
            result = expected in actual
        else:
            result = False
    elif operator == "in":
        try:
            result = actual in expected
        except TypeError:
            result = actual == expected
    elif operator == "is_set":
        result = actual is not None and actual != ""
    elif operator == "not_set":
        result = actual is None or actual == ""
    elif operator == "greater_than":
        try:
            result = float(actual) > float(expected)
        except (TypeError, ValueError):
            result = False
    elif operator == "greater_than_or_equal":
        try:
            result = float(actual) >= float(expected)
        except (TypeError, ValueError):
            result = False
    elif operator == "less_than":
        try:
            result = float(actual) < float(expected)
        except (TypeError, ValueError):
            result = False
    elif operator == "less_than_or_equal":
        try:
            result = float(actual) <= float(expected)
        except (TypeError, ValueError):
            result = False
    elif operator == "regex_match":
        if isinstance(actual, str):
            try:
                result = bool(re.search(str(expected), actual))
            except re.error as exc:
                raise InvalidControlError(
                    "<expression>",
                    f"invalid regex {expected!r}: {exc}") from exc
        else:
            result = False
    else:
        raise InvalidControlError(
            "<expression>", f"unknown operator {operator!r} "
            f"(vocabulary: {', '.join(sorted(OPERATOR_VOCABULARY))})")
    return (not result) if negated else result


# ---------------------------------------------------------------------------
# Canonical score + confidence (F5/F7).
# ---------------------------------------------------------------------------

def overall_score(passed: int, evaluated: int) -> float:
    """THE overall score: passed / evaluated, rounded to one decimal.

    REVIEW counts as non-pass (see module docstring). Zero evaluations
    score 0.0 — never a division error, never an inflated default.
    """
    if evaluated <= 0:
        return 0.0
    return round(passed / evaluated * 100, 1)


def compose_confidence(normalization_confidence: Any,
                       rule_confidence: Any) -> Optional[float]:
    """THE confidence composition: normalization x rule (§13.3 step 4).

    Returns None when either input is missing/non-numeric — the caller must
    REVIEW, never invent a number.
    """
    try:
        norm = float(normalization_confidence)
        rule = float(rule_confidence)
    except (TypeError, ValueError):
        return None
    norm = max(0.0, min(1.0, norm))
    rule = max(0.0, min(1.0, rule))
    return round(norm * rule, 4)


def needs_review(confidence: Optional[float]) -> bool:
    """§13.4: confidence below 0.70 — or unavailable — forces REVIEW."""
    if confidence is None:
        return True
    return confidence < REVIEW_THRESHOLD


# ---------------------------------------------------------------------------
# Control metadata + validation (F3/F9). The control owns its framework,
# version and rule confidence; nothing infers them from id shape or the
# audit request.
# ---------------------------------------------------------------------------

def assign_control_metadata(control: Any, framework: str) -> Any:
    """Stamp authoritative per-control metadata at inventory build time.

    - framework: the benchmark family that DEFINES the control (CIS/NIST).
    - framework_version: the control's own benchmark_version.
    - rule_confidence: derived from the control's own evaluability —
      MANUAL controls are certain-review (1.0); mapped automated controls
      with a canonical operator evaluate against model evidence (0.95);
      explicitly regex-based unmapped controls evaluate against weaker raw
      evidence (0.85); unmapped controls with no regex cannot evaluate
      (0.5, REVIEW-only).
    """
    control.framework = framework
    control.framework_version = getattr(control, "benchmark_version", "")
    if getattr(control, "assessment_status", None) == "Manual":
        control.rule_confidence = 1.0
    elif getattr(control, "target_model_path", None):
        control.rule_confidence = 0.95
    elif getattr(control, "audit_regex", None):
        control.rule_confidence = 0.85
    else:
        control.rule_confidence = 0.5
    return control


def validate_control(control: Any, model_paths: set[str]) -> None:
    """Fail fast on control definitions that violate the contract (F9).

    Raises InvalidControlError for: unknown operator, uncompilable regex,
    non-existent model path. Duplicate ids are enforced by the registry.
    """
    control_id = getattr(control, "control_id", "?")
    operator = getattr(control, "operator", "equals")
    if operator not in OPERATOR_VOCABULARY:
        raise InvalidControlError(
            control_id, f"unknown operator {operator!r}")
    regex = getattr(control, "audit_regex", "") or ""
    if regex:
        try:
            re.compile(regex)
        except re.error as exc:
            raise InvalidControlError(
                control_id, f"invalid audit_regex {regex!r}: {exc}") from exc
    path = getattr(control, "target_model_path", None)
    if path is not None and path not in model_paths:
        raise InvalidControlError(
            control_id, f"target model path {path!r} is not defined by the "
            "Universal Security Model")


# ---------------------------------------------------------------------------
# Selection service (F1/F2). One instance over the loaded inventory, shared
# by the executor, the benchmark engine and the REST API.
# ---------------------------------------------------------------------------

@dataclass
class SelectionResult:
    """Outcome of a control selection (inventory or evaluation)."""
    controls: list[Any] = field(default_factory=list)
    vendor: str = ""
    platform: str = ""
    framework: Optional[str] = None
    framework_version: Optional[str] = None
    mode: str = ""  # "evaluation-dual" | "evaluation" | "inventory"


class ControlSelectionService:
    """Canonical selection over one loaded control inventory."""

    def __init__(self, controls: list[Any]) -> None:
        self._controls = list(controls)

    # -- inventory metadata (F1/F3: derived from controls, never hardcoded)
    def frameworks(self) -> dict[str, dict[str, Any]]:
        """{framework: {versions, control_count, vendors}} from the inventory."""
        out: dict[str, dict[str, Any]] = {}
        for control in self._controls:
            framework = getattr(control, "framework", "") or "UNKNOWN"
            entry = out.setdefault(framework, {
                "versions": set(), "control_count": 0, "vendors": set()})
            entry["versions"].add(
                getattr(control, "framework_version", "") or "unknown")
            entry["control_count"] += 1
            entry["vendors"].add(getattr(control, "vendor", ""))
        return {
            framework: {
                "versions": sorted(entry["versions"]),
                "control_count": entry["control_count"],
                "vendors": sorted(entry["vendors"]),
            }
            for framework, entry in sorted(out.items())
        }

    def versions_for_framework(self, framework: str) -> list[str]:
        """Authoritative versions actually present for a framework."""
        return self.frameworks().get(framework, {}).get("versions", [])

    def validate_framework_version(self, framework: str,
                                   version: Optional[str]) -> Optional[str]:
        """Version must exist in the loaded inventory (F1: never advertise
        a version the registry does not contain)."""
        if version is None:
            return None
        versions = self.versions_for_framework(framework)
        if version not in versions:
            raise UnknownFrameworkVersionError(
                f"framework {framework} has no version {version!r} "
                f"(available: {', '.join(versions) or 'none'})")
        return version

    # -- literal inventory selection (API filtering, F2)
    def select(self, vendor: Optional[str] = None,
               platform: Optional[str] = None,
               framework: Optional[str] = None,
               framework_version: Optional[str] = None) -> SelectionResult:
        """Conjunctive literal filtering. Every supplied filter applies.

        vendor/platform match the control's own (case-insensitive, aliased)
        values literally — universal controls match only an explicit
        universal filter or no filter. Unknown framework/version raise;
        anything else that matches nothing returns an empty selection (the
        typed empty result), never another vendor's controls.
        """
        framework_c = (normalize_framework(framework)
                       if framework is not None else None)
        if framework_c == DUAL_BASELINE:
            raise UnsupportedFrameworkError(
                "the dual baseline is an evaluation mode, not an inventory "
                "framework filter (use CIS or NIST)")
        version_c = (normalize_framework_version(framework_version)
                     if framework_version is not None else None)
        vendor_c = normalize_vendor(vendor) if vendor is not None else None
        platform_c = (normalize_platform(vendor_c or "", platform)
                      if platform is not None else None)
        if framework_c is not None and framework_c not in SUPPORTED_FRAMEWORKS:
            raise UnsupportedFrameworkError(framework_c)
        if version_c is not None:
            if framework_c is None:
                raise UnknownFrameworkVersionError(
                    "framework_version requires a framework filter")
            self.validate_framework_version(framework_c, version_c)

        selected = []
        for control in self._controls:
            if vendor_c is not None and normalize_vendor(
                    getattr(control, "vendor", "")) != vendor_c:
                continue
            if platform_c is not None and normalize_platform(
                    getattr(control, "vendor", ""),
                    getattr(control, "platform", "")) != platform_c:
                continue
            if framework_c is not None and getattr(
                    control, "framework", "") != framework_c:
                continue
            if version_c is not None and getattr(
                    control, "framework_version", "") != version_c:
                continue
            selected.append(control)
        return SelectionResult(
            controls=selected, vendor=vendor_c or "", platform=platform_c or "",
            framework=framework_c, framework_version=version_c,
            mode="inventory")

    # -- evaluation selection (executor/engine, F1/F2/F6)
    def select_for_evaluation(
            self, vendor: str, platform: str,
            framework: Optional[str] = None,
            framework_version: Optional[str] = None) -> SelectionResult:
        """Controls to evaluate for one device audit.

        - vendor must be a supported evaluation vendor (else
          UnsupportedVendorError — the engine translates this into an
          explicit unsupported status, never silent substitution).
        - framework None -> explicit dual mode (vendor CIS + universal
          NIST); "CIS" -> vendor CIS only; "NIST" -> universal NIST only.
        - version filters within the selected set (validated first).
        - deterministic order: vendor controls in inventory order, then
          universal NIST controls in inventory order, deduplicated by
          control_id (first wins; registry construction already rejects
          conflicting duplicates).
        """
        framework_c = normalize_framework(framework)
        version_c = normalize_framework_version(framework_version)
        vendor_c = normalize_vendor(vendor)
        if vendor_c not in SUPPORTED_EVALUATION_VENDORS:
            raise UnsupportedVendorError(
                f"vendor {vendor!r} has no compliance evaluation contract "
                f"(supported: {', '.join(sorted(SUPPORTED_EVALUATION_VENDORS))})")
        platform_c = normalize_platform(vendor_c, platform)

        if framework_c is None:
            framework_c = DUAL_BASELINE
        if framework_c == DUAL_BASELINE:
            wanted = ("CIS", "NIST")
        else:
            wanted = (framework_c,)
        for wanted_framework in wanted:
            if version_c is not None:
                self.validate_framework_version(wanted_framework, version_c)

        vendor_controls = [
            c for c in self._controls
            if normalize_vendor(getattr(c, "vendor", "")) == vendor_c
            and normalize_platform(getattr(c, "vendor", ""),
                                   getattr(c, "platform", "")) == platform_c
            and getattr(c, "framework", "") == "CIS"
            and (version_c is None or getattr(
                c, "framework_version", "") == version_c)
        ]
        nist_controls = [
            c for c in self._controls
            if getattr(c, "vendor", "") == UNIVERSAL_VENDOR
            and getattr(c, "framework", "") == "NIST"
            and (version_c is None or getattr(
                c, "framework_version", "") == version_c)
        ]
        if framework_c == DUAL_BASELINE:
            ordered = vendor_controls + [
                c for c in nist_controls
                if c.control_id not in {v.control_id for v in vendor_controls}
            ]
        elif framework_c == "CIS":
            ordered = vendor_controls
        else:
            ordered = nist_controls
        return SelectionResult(
            controls=ordered, vendor=vendor_c, platform=platform_c,
            framework=framework_c, framework_version=version_c,
            mode="evaluation-dual" if framework_c == DUAL_BASELINE
            else "evaluation")
