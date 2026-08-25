"""Pydantic models for benchmark controls and control registry."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


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


class BenchmarkControl(BaseModel):
    """A single control extracted from a CIS Benchmark."""
    benchmark_id: str = Field(..., description="Unique benchmark identifier, e.g. 'CIS-CISCO-IOS-XE-17.x-v2.2.1'")
    benchmark_name: str = Field(..., description="Human-readable benchmark name")
    benchmark_version: str = Field(..., description="Benchmark version string")

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
    operator: str = Field(default="equals", description="Evaluation operator: equals, not_equals, contains, regex_match, is_set, not_set, greater_than, less_than")
    expected_value: Any = Field(None, description="Expected value for compliance")

    # Evaluation rule details
    audit_command: str = Field("", description="CLI command or regex pattern for auditing")
    audit_regex: str = Field("", description="Regex pattern to match compliant configuration")
    negated: bool = Field(default=False, description="If True, absence of the pattern means PASS")

    # Remediation metadata
    remediation_command: str = Field("", description="CLI command for remediation")
    verification_steps: list[str] = Field(default_factory=list)
    rollback_steps: list[str] = Field(default_factory=list)

    # Metadata
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

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
    loaded_at: datetime = Field(default_factory=datetime.utcnow)

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
