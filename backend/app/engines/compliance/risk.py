"""Canonical Risk Engine for Engine 09 (spec §10.9).

One normative scoring vocabulary, one implementation, one output contract.

Normative path (production decisions — spec §4.2 "Deterministic Engine"):
    Finding-grade inputs (severity, vendor, category, confidence)
      → input validation (typed errors, never silent coercion)
      → DeterministicRiskScorer (documented closed-form formula)
      → priority bands (verified 80/60/40)
      → RiskAssessment

Advisory path (isolated, never normative):
    the RandomForest risk model may supply an advisory_score plus model
    metadata. It never determines risk_score, priority, or any security
    decision. Its published fit metric measures formula-emulation fidelity
    on synthetic labels — never real-world risk accuracy.

Normative formula (E09 amendment §10.9.1 — the previously undocumented
implementation formula, now specified rather than changed):

    risk = base(severity) × vendor(vendor) × category(category)
           × max(confidence, 0.5) / 15.6 × 100

rounded to one decimal and clamped to [0, 100]. The 0.5 confidence floor
is preserved explicitly: below 0.5, risk stops decreasing (documented,
monotonicity-preserving). 15.6 is the maximum raw product
(10.0 × 1.2 × 1.3 × 1.0), so the normalizer maps the attainable range
onto 0–100 without inventing headroom.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Optional

from app.engines.compliance.models import Severity


# ---------------------------------------------------------------------------
# Typed errors (F7). One error type for the whole input contract; a
# subclass of ValueError so existing ValueError expectations keep working.
# ---------------------------------------------------------------------------

class RiskValidationError(ValueError):
    """A risk-engine input violates the canonical contract."""


# ---------------------------------------------------------------------------
# Normative vocabulary (F2/F5/F8). Single authoritative tables.
# ---------------------------------------------------------------------------

#: Normative scoring method + version stamped on every RiskAssessment.
SCORING_METHOD = "deterministic"
SCORING_VERSION = "v1"

#: Severity base scores (verified: CRITICAL→64.1, HIGH→48.1, MEDIUM→32.1,
#: LOW→16.0 at neutral vendor/category/confidence 1.0).
SEVERITY_BASE: dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
}

#: Severity ordinal for the shared feature builder (train + advisory).
SEVERITY_NUM: dict[str, int] = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}

#: Canonical vendor impact. Only verified supported vendors carry a
#: multiplier above neutral; everything else (unknown, unsupported,
#: empty, hostile strings) resolves to the documented neutral 1.0 —
#: never a silent Cisco substitution, never an inflated multiplier.
VENDOR_IMPACT: dict[str, float] = {
    "cisco": 1.2,
    "juniper": 1.1,
    "fortinet": 1.1,
    "paloalto": 1.2,
    "unknown": 1.0,
}
NEUTRAL_VENDOR_IMPACT = 1.0

#: Canonical category impact, keyed by NORMALIZED category (see
#: normalize_category). Merged from the serving table and the training
#: table, which agreed on every shared key except one:
#:   "access control": serving 1.1 ("access_control") vs training 1.2
#:   ("Access Control", the production vocabulary).
#: The training value (1.2) is adopted: it was built against the
#: production category names, and access-control failures belong in the
#: 1.2 tier with SSH/access-rules (documented conflict resolution).
CATEGORY_IMPACT: dict[str, float] = {
    "aaa": 1.3,
    "ssh": 1.2,
    "authentication": 1.3,
    "access control": 1.2,
    "snmp": 1.1,
    "logging": 1.0,
    "management": 1.1,
    "ntp": 1.0,
    "services": 1.1,
    "password rules": 1.2,
    "access rules": 1.2,
    "audit and accountability": 1.2,
    "configuration management": 1.1,
    "system and communications protection": 1.2,
}
NEUTRAL_CATEGORY_IMPACT = 1.0

#: Priority bands (verified, preserved exactly).
PRIORITY_THRESHOLDS: list[tuple[float, str]] = [
    (80.0, "P1"),
    (60.0, "P2"),
    (40.0, "P3"),
    (0.0, "P4"),
]

#: Confidence floor (preserved explicitly) and formula normalizer.
CONFIDENCE_FLOOR = 0.5
FORMULA_NORMALIZER = 15.6

#: Shared feature order for training and advisory serving (F6).
RISK_FEATURES: list[str] = [
    "severity_num", "vendor_mult", "category_mult", "confidence",
]

_WHITESPACE_RE = re.compile(r"\s+")
_UNSAFE_INPUT_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# ---------------------------------------------------------------------------
# Normalization + validation (F5/F7/F8). Deterministic, shared by scoring,
# validation, tests and reporting.
# ---------------------------------------------------------------------------

def normalize_severity(severity: Any) -> str:
    """Canonical severity name. Accepts the Severity enum or the exact
    canonical strings; anything else (None, "", "garbage", lowercase,
    wrong types) is a typed error — never a silent default."""
    if isinstance(severity, Severity):
        return severity.value
    if isinstance(severity, str) and severity in SEVERITY_BASE:
        return severity
    raise RiskValidationError(
        f"severity must be one of {sorted(SEVERITY_BASE)} (or the Severity "
        f"enum), got {severity!r}")


def normalize_vendor(vendor: Any) -> str:
    """Canonical vendor name. Must be a string; the value itself is never
    rejected — unknown/unsupported/empty/hostile strings resolve to the
    documented neutral multiplier (F8). Only non-strings are invalid."""
    if not isinstance(vendor, str):
        raise RiskValidationError(
            f"vendor must be str, got {type(vendor).__name__}")
    return vendor.strip().lower()


def vendor_impact(vendor: Any) -> float:
    """Impact multiplier for a (possibly unknown) vendor string."""
    return VENDOR_IMPACT.get(normalize_vendor(vendor),
                             NEUTRAL_VENDOR_IMPACT)


def normalize_category(category: Any) -> str:
    """Canonical category name: strip, lowercase, underscores to spaces,
    collapsed whitespace. Must be a string; None/non-string is a typed
    error. The empty string normalizes to unknown (documented neutral)."""
    if category is None:
        raise RiskValidationError("category must be str, got None")
    if not isinstance(category, str):
        raise RiskValidationError(
            f"category must be str, got {type(category).__name__}")
    cleaned = _WHITESPACE_RE.sub(
        " ", category.strip().lower().replace("_", " ")).strip()
    return cleaned


def category_impact(category: Any) -> float:
    """Impact multiplier for a category string; unknown categories resolve
    to the documented neutral 1.0 (F5)."""
    return CATEGORY_IMPACT.get(normalize_category(category),
                               NEUTRAL_CATEGORY_IMPACT)


def validate_confidence(confidence: Any) -> float:
    """Confidence must be a finite real number in [0.0, 1.0].

    Rejects None, bools, strings ("0.9"), NaN, ±Infinity and out-of-range
    values with a typed error — never a silent score (F7/S1).
    """
    if isinstance(confidence, bool):
        raise RiskValidationError(
            f"confidence must be a real number, got bool {confidence!r}")
    if not isinstance(confidence, (int, float)):
        raise RiskValidationError(
            f"confidence must be a real number in [0.0, 1.0], got "
            f"{type(confidence).__name__} {confidence!r}")
    value = float(confidence)
    if not math.isfinite(value):
        raise RiskValidationError(
            f"confidence must be finite, got {confidence!r}")
    if not 0.0 <= value <= 1.0:
        raise RiskValidationError(
            f"confidence must be within [0.0, 1.0], got {confidence!r}")
    return value


def build_risk_features(severity: Any, vendor: Any, category: Any,
                        confidence: Any) -> tuple[float, float, float, float]:
    """Single shared feature builder (F6): (severity_num, vendor_mult,
    category_mult, confidence). Used identically by training-data
    generation and advisory serving — same severity mapping, same vendor
    mapping, same category mapping, same confidence semantics, same
    feature order."""
    sev = normalize_severity(severity)
    conf = validate_confidence(confidence)
    norm_vendor = normalize_vendor(vendor)
    norm_category = normalize_category(category)
    return (
        float(SEVERITY_NUM[sev]),
        float(VENDOR_IMPACT.get(norm_vendor, NEUTRAL_VENDOR_IMPACT)),
        float(CATEGORY_IMPACT.get(norm_category, NEUTRAL_CATEGORY_IMPACT)),
        conf,
    )


# ---------------------------------------------------------------------------
# Normative scorer (F2/F4). Pure arithmetic, no ML, no I/O.
# ---------------------------------------------------------------------------

def deterministic_score(severity: Any, vendor: Any = "",
                        category: Any = "",
                        confidence: Any = 1.0) -> float:
    """THE normative risk score (§10.9.1)."""
    sev_num, v_mult, c_mult, conf = build_risk_features(
        severity, vendor, category, confidence)
    base = SEVERITY_BASE[normalize_severity(severity)]
    raw = base * v_mult * c_mult * max(conf, CONFIDENCE_FLOOR)
    return round(min(100.0, (raw / FORMULA_NORMALIZER) * 100.0), 1)


def priority_for(risk_score: Any) -> str:
    """Priority band for a score (verified 80/60/40 boundaries preserved).
    Non-numeric scores are a typed error; the bands always return P1–P4,
    never empty."""
    if isinstance(risk_score, bool) or not isinstance(
            risk_score, (int, float)):
        raise RiskValidationError(
            f"risk_score must be a real number, got "
            f"{type(risk_score).__name__} {risk_score!r}")
    score = float(risk_score)
    if not math.isfinite(score):
        raise RiskValidationError(
            f"risk_score must be finite, got {risk_score!r}")
    for threshold, band in PRIORITY_THRESHOLDS:
        if score >= threshold:
            return band
    return "P4"


# ---------------------------------------------------------------------------
# Advisory ML (isolated, never normative — F4/F6).
# ---------------------------------------------------------------------------

def advisory_model_info() -> dict[str, Any]:
    """Advisory-model availability/version metadata for exposure surfaces
    (reports, step text). Never used as a guard for anything except
    labeling the advisory itself."""
    try:
        from app.ml.model import get_risk_predictor
        _, available = get_risk_predictor()
    except Exception:
        available = False
    info: dict[str, Any] = {
        "available": bool(available),
        "model": None,
        "scope": "advisory-only formula emulation (never normative)",
    }
    if available:
        try:
            from pathlib import Path
            import json
            meta_path = (Path(__file__).resolve().parents[3] / "app" / "ml"
                         / "model_artifacts" / "risk_meta.json")
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            info["model"] = meta.get("model")
            info["r2_formula_emulation"] = meta.get("r2")
            info["trained_on"] = meta.get("label_source", "synthetic")
        except Exception:
            info["model"] = "RandomForestRegressor"
    return info


def advisory_score(severity: Any, vendor: Any = "",
                   category: Any = "",
                   confidence: Any = 1.0) -> Optional[float]:
    """Advisory RandomForest score, or None when the model is unavailable.

    Uses the shared build_risk_features semantics. The advisory score is
    informational only: it never determines risk_score, priority, or any
    security decision.
    """
    sev_num, v_mult, c_mult, conf = build_risk_features(
        severity, vendor, category, confidence)
    try:
        from app.ml.model import get_risk_predictor
        model, available = get_risk_predictor()
    except (ImportError, OSError, ValueError, AttributeError,
            RuntimeError):
        return None
    if not available or model is None:
        return None
    try:
        pred = model.predict([[sev_num, v_mult, c_mult, conf]])[0]
    except (ValueError, RuntimeError, AttributeError, TypeError):
        return None
    value = float(pred)
    if not math.isfinite(value):
        return None
    return round(max(0.0, min(100.0, value)), 1)


# ---------------------------------------------------------------------------
# RiskAssessment contract (F3 §19) + RiskEngine (F3/F10).
# ---------------------------------------------------------------------------

@dataclass
class RiskAssessment:
    """The §10.9 output: one risk assessment per finding.

    finding_id links the assessment to its finding; severity/confidence/
    vendor/category echo the validated inputs; scoring_method/version name
    the normative scorer; advisory_* carry the isolated ML opinion (None
    when the model is unavailable or not requested).
    """
    finding_id: str
    risk_score: float
    priority: str
    severity: str
    confidence: float
    vendor: str
    category: str
    scoring_method: str = SCORING_METHOD
    scoring_version: str = SCORING_VERSION
    advisory_score: Optional[float] = None
    advisory_model: Optional[str] = None
    advisory_model_version: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "risk_score": self.risk_score,
            "priority": self.priority,
            "severity": self.severity,
            "confidence": self.confidence,
            "vendor": self.vendor,
            "category": self.category,
            "scoring_method": self.scoring_method,
            "scoring_version": self.scoring_version,
            "advisory_score": self.advisory_score,
            "advisory_model": self.advisory_model,
            "advisory_model_version": self.advisory_model_version,
        }


class RiskEngine:
    """Canonical Risk Engine (spec §10.9).

    Owns risk assessment only: severity/vendor/category/confidence in,
    RiskAssessment out. It does NOT own the overall compliance score —
    that stays with the compliance engine (E07 single formula
    passed/evaluated); see F10 decision in the E09 report.
    """

    scoring_method = SCORING_METHOD
    scoring_version = SCORING_VERSION

    def assess(self, *, finding_id: str, severity: Any, vendor: Any = "",
               category: Any = "",
               confidence: Any = 1.0,
               include_advisory: bool = False) -> RiskAssessment:
        """Assess finding-grade inputs into a RiskAssessment.

        All inputs are validated (typed errors); the normative score and
        priority come from the deterministic scorer alone.
        """
        if not isinstance(finding_id, str) or not finding_id:
            raise RiskValidationError(
                "finding_id must be a non-empty string")
        sev = normalize_severity(severity)
        norm_vendor = normalize_vendor(vendor)
        norm_category = normalize_category(category)
        conf = validate_confidence(confidence)
        score = deterministic_score(sev, norm_vendor, norm_category, conf)
        advisory: Optional[float] = None
        advisory_model: Optional[str] = None
        if include_advisory:
            advisory = advisory_score(sev, norm_vendor, norm_category, conf)
            if advisory is not None:
                info = advisory_model_info()
                advisory_model = info.get("model")
        return RiskAssessment(
            finding_id=finding_id,
            risk_score=score,
            priority=priority_for(score),
            severity=sev,
            confidence=conf,
            vendor=norm_vendor,
            category=norm_category,
            advisory_score=advisory,
            advisory_model=advisory_model,
        )

    def attach(self, finding: Any, category: Any = "") -> RiskAssessment:
        """Assess a Finding object in place: stamps risk_score, priority,
        risk_method and risk_model_version from the assessment and returns
        the RiskAssessment. Finding-grade inputs are used verbatim
        (severity/vendor/confidence stored on the finding)."""
        assessment = self.assess(
            finding_id=getattr(finding, "id", ""),
            severity=getattr(finding, "severity", None),
            vendor=getattr(finding, "affected_vendor", "") or "",
            category=category,
            confidence=getattr(finding, "confidence", None),
        )
        finding.risk_score = assessment.risk_score
        finding.priority = assessment.priority
        finding.risk_method = assessment.scoring_method
        finding.risk_model_version = assessment.scoring_version
        return assessment

    def model_info(self) -> dict[str, Any]:
        """Advisory-model metadata for exposure surfaces."""
        return advisory_model_info()

    # Compatibility shims (single-parameter behavior preserved): existing
    # callers using SeverityCalculator-style signatures keep working; all
    # paths execute the normative scorer.
    def calculate_risk_score(self, severity: Any, vendor: Any = "",
                             category: Any = "",
                             confidence: Any = 1.0) -> float:
        return deterministic_score(severity, vendor, category, confidence)

    def calculate_priority(self, risk_score: Any) -> str:
        return priority_for(risk_score)


class SeverityCalculator:
    """Backward-compatible adapter around the canonical RiskEngine.

    Preserved (name, methods, table attributes) so existing callers keep
    working unchanged. All scoring executes the normative deterministic
    scorer; the tables below ARE the canonical objects (not copies), so
    they cannot drift. Prefer RiskEngine for new code.
    """

    SEVERITY_SCORES = {
        "CRITICAL": 10.0,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
    }

    VENDOR_IMPACT = VENDOR_IMPACT
    CATEGORY_IMPACT = CATEGORY_IMPACT
    PRIORITY_THRESHOLDS = PRIORITY_THRESHOLDS

    def __init__(self) -> None:
        self._engine = RiskEngine()

    def calculate_risk_score(
        self,
        severity: Any,
        vendor: Any = "",
        category: Any = "",
        confidence: Any = 1.0,
    ) -> float:
        """Normative deterministic risk score (validates inputs)."""
        return self._engine.calculate_risk_score(
            severity, vendor, category, confidence)

    def calculate_priority(self, risk_score: Any) -> str:
        """Priority band for a score (verified 80/60/40 boundaries)."""
        return self._engine.calculate_priority(risk_score)
