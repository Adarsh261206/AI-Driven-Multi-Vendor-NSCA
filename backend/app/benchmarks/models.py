"""Pydantic models for benchmark controls and control registry."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def _utcnow_naive() -> datetime:
    """Naive UTC now — identical values to datetime.utcnow() without the
    deprecation warning (fires per-model-validation, distorts perf tests)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AssessmentStatus(str, Enum):
    """Whether a control can be automated or requires manual review."""
    AUTOMATED = "Automated"
    MANUAL = "Manual"


class ControlSeverity(str, Enum):
    """Severity level for a control."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ProfileLevel(str, Enum):
    """CIS Benchmark profile level."""
    LEVEL_1 = "Level 1"
    LEVEL_2 = "Level 2"


class ControlScope(str, Enum):
    """Configuration scope a control applies to (§2 Cisco switch scopes).

    GLOBAL — statements at the root of the config (never inside a block).
    INTERFACE — evaluated independently per interface block; ANY violation
        fails the control; all applicable interfaces explicitly compliant
        passes; otherwise REVIEW.
    INTERFACE_RANGE — same as INTERFACE but range-aware (interface range).
    LINE_CONSOLE / LINE_AUX / LINE_VTY — evaluated only on that line family.
    VLAN / ACL / VRF / STP / DHCP_SNOOPING / DAI — future scopes.
    UNKNOWN — legacy flat evaluation (no scope decomposition).
    """
    GLOBAL = "GLOBAL"
    INTERFACE = "INTERFACE"
    INTERFACE_RANGE = "INTERFACE_RANGE"
    LINE_CONSOLE = "LINE_CONSOLE"
    LINE_AUX = "LINE_AUX"
    LINE_VTY = "LINE_VTY"
    ROUTER_PROCESS = "ROUTER_PROCESS"
    VLAN = "VLAN"
    ACL = "ACL"
    VRF = "VRF"
    STP = "STP"
    DHCP_SNOOPING = "DHCP_SNOOPING"
    DAI = "DAI"
    UNKNOWN = "UNKNOWN"


class BenchmarkControl(BaseModel):
    """A single control extracted from a CIS Benchmark."""
    benchmark_id: str = Field(..., description="Unique benchmark identifier, e.g. 'CIS-CISCO-IOS-XE-17.x-v2.2.1'")
    benchmark_name: str = Field(..., description="Human-readable benchmark name")
    benchmark_version: str = Field(..., description="Benchmark version string")

    # Authoritative framework attribution (F3): the benchmark family that
    # DEFINES this control. Assigned at inventory build time from the
    # defining module — never inferred from control-id shape, the audit
    # request, filenames or list order.
    framework: str = Field(default="", description="Authoritative framework: CIS or NIST")
    framework_version: str = Field(default="", description="Authoritative framework version from the defining benchmark")
    # Rule confidence input for §13.3 step 4 composition (F7): derived from
    # the control's own evaluability at inventory build time.
    rule_confidence: float = Field(default=1.0, ge=0.0, le=1.0,
                                   description="Rule confidence input (0.0-1.0)")
    # Explicit absence semantics (F4): when True, a non-match of the control's
    # explicit audit_regex is a verified FAIL condition defined by the control.
    # Default False: regex miss means insufficient evidence (REVIEW).
    absence_is_fail: bool = Field(default=False,
                                  description="Non-match of audit_regex is a verified FAIL")
    # Explicit violation pattern (registry-driven): when set, a match on a
    # non-negated evidence line is positive violation evidence → FAIL.
    # Checked before the compliant audit_regex match, so a config with both
    # forms still FAILs. Empty = no explicit violation form defined.
    violation_regex: str = Field(default="",
                                 description="Regex matching an explicit violation state")

    vendor: str = Field(..., description="Target vendor, e.g. 'cisco'")
    platform: str = Field(..., description="Target platform, e.g. 'ios_xe'")

    control_id: str = Field(..., description="Control identifier within the benchmark, e.g. '1.1.1'")
    title: str = Field(..., description="Short title of the control")
    category: str = Field(..., description="Control category, e.g. 'AAA', 'SSH', 'Logging'")
    description: str = Field("", description="Paraphrased description (not verbatim copyrighted text)")

    assessment_status: AssessmentStatus = Field(..., description="Automated or Manual")
    profile_level: ProfileLevel = Field(default=ProfileLevel.LEVEL_1)

    severity: ControlSeverity = Field(default=ControlSeverity.MEDIUM)

    audit_procedure_summary: str = Field("", description="Paraphrased audit procedure")
    remediation_procedure_summary: str = Field("", description="Paraphrased remediation procedure")

    references: list[str] = Field(default_factory=list)
    source_document: str = Field("", description="Source PDF filename")
    source_location: str = Field("", description="Page or section reference")

    # Mapping to universal security model
    target_model_path: Optional[str] = Field(None, description="Universal Security Model path this control maps to")
    operator: str = Field(default="equals", description="Evaluation operator: equals, not_equals, greater_than, greater_than_or_equal, less_than, less_than_or_equal, contains, in, is_set, not_set, regex_match")
    expected_value: Any = Field(None, description="Expected value for compliance")

    # Evaluation rule details
    audit_command: str = Field("", description="CLI command or regex pattern for auditing")
    audit_regex: str = Field("", description="Regex pattern to match compliant configuration")
    negated: bool = Field(default=False, description="If True, absence of the pattern means PASS")
    # Explicit scope for scope-aware evaluation (§2). UNKNOWN keeps the
    # legacy flat behavior.
    scope: ControlScope = Field(default=ControlScope.UNKNOWN,
                                description="Configuration scope this control applies to")

    # Remediation metadata
    remediation_command: str = Field("", description="CLI command for remediation")
    verification_steps: list[str] = Field(default_factory=list)
    rollback_steps: list[str] = Field(default_factory=list)

    # Metadata
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=_utcnow_naive)
    updated_at: datetime = Field(default_factory=_utcnow_naive)

    class Config:
        use_enum_values = True
        protected_namespaces = ()


class ControlMapping(BaseModel):
    """Maps a benchmark control to the Universal Security Model."""
    control_id: str
    benchmark_id: str
    model_path: str
    operator: str
    expected_value: Any
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    notes: str = ""

    class Config:
        protected_namespaces = ()


class BenchmarkRegistry(BaseModel):
    """Registry of all loaded benchmark controls."""
    benchmark_id: str
    benchmark_name: str
    benchmark_version: str
    vendor: str
    platform: str
    controls: list[BenchmarkControl] = Field(default_factory=list)
    loaded_at: datetime = Field(default_factory=_utcnow_naive)

    @property
    def total_controls(self) -> int:
        return len(self.controls)

    @property
    def automated_controls(self) -> int:
        return sum(1 for c in self.controls if c.assessment_status == AssessmentStatus.AUTOMATED.value)

    @property
    def manual_controls(self) -> int:
        return sum(1 for c in self.controls if c.assessment_status == AssessmentStatus.MANUAL.value)

    @property
    def mapped_controls(self) -> int:
        return sum(1 for c in self.controls if c.target_model_path is not None)

    @property
    def unmapped_controls(self) -> int:
        return sum(1 for c in self.controls if c.target_model_path is None)
