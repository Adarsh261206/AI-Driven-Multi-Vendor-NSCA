"""
Control Definition Models

Defines the schema for compliance controls, rules, and evaluation logic.
Controls are loaded from Python definitions at runtime (not from database).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class Severity(str, Enum):
    """Control severity levels.

    Canonical §12 vocabulary is UPPERCASE ("CRITICAL" | "HIGH" | "MEDIUM"
    | "LOW"), shared by the control, the finding, persistence, filters,
    reports and the API. Nothing lowercases internally and uppercases at
    the edge: the stored and filtered representation IS the canonical one.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ComplianceResultType(str, Enum):
    """Result of compliance evaluation.

    Canonical §12 representation is UPPERCASE ("PASS" | "FAIL" | "REVIEW"),
    shared by the domain object, persistence, API and reports.
    """
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"


class FindingStatus(str, Enum):
    """Status of a finding"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


class RuleType(str, Enum):
    """Type of compliance rule"""
    VALUE_CHECK = "value_check"
    ABSENCE_CHECK = "absence_check"
    PRESENCE_CHECK = "presence_check"
    THRESHOLD_CHECK = "threshold_check"


class Operator(str, Enum):
    """Comparison operators for rules"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"
    NOT_IN = "not_in"
    IS_TRUE = "is_true"
    IS_FALSE = "is_false"
    IS_SET = "is_set"
    IS_NOT_SET = "is_not_set"
    REGEX_MATCH = "regex_match"


@dataclass
class RuleTarget:
    """Target of a compliance rule"""
    model_path: str  # Universal security model path, e.g. "management.ssh.version"
    vendor: Optional[str] = None
    platform: Optional[str] = None


@dataclass
class ExpectedValue:
    """Expected value for a compliance rule"""
    value: Any
    operator: Operator
    description: str = ""


@dataclass
class ControlRule:
    """Rule for evaluating a control"""
    type: RuleType
    target: RuleTarget
    expected: ExpectedValue


@dataclass
class RemediationTemplate:
    """Template for remediation instructions"""
    title: str
    description: str
    why_it_matters: str
    recommended_config: str
    verification_steps: list[str] = field(default_factory=list)
    rollback_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class Control:
    """A compliance control definition"""
    id: str  # e.g. "CIS-Cisco-IOS-1.1"
    framework: str  # "CIS" or "NIST"
    framework_version: str  # "2024.1"
    category: str  # "management", "ssh", "authentication", etc.
    title: str
    description: str
    severity: Severity
    vendor: Optional[str] = None  # null = vendor-agnostic
    platform: Optional[str] = None  # null = platform-agnostic
    rule: Optional[ControlRule] = None
    remediation: Optional[RemediationTemplate] = None
    references: list[str] = field(default_factory=list)
    enabled: bool = True
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "framework": self.framework,
            "framework_version": self.framework_version,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "vendor": self.vendor,
            "platform": self.platform,
            "references": self.references,
            "enabled": self.enabled,
        }


@dataclass
class Framework:
    """A compliance framework"""
    id: str
    name: str
    description: str
    versions: list[str]
    current_version: str
    controls: list[Control] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "versions": self.versions,
            "current_version": self.current_version,
            "control_count": len(self.controls),
        }
