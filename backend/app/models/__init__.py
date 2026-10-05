from __future__ import annotations

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, Integer, Float, Index, Numeric, UniqueConstraint, BigInteger, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, validates
from datetime import datetime
from uuid import uuid4
import enum

from app.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class AuditStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ComplianceResultType(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


class AuditAction(str, enum.Enum):
    # User sessions (observability events; best-effort at the call sites
    # so a trail hiccup can never lock users out)
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"

    # Reports
    REPORT_GENERATED = "report_generated"

    # Audit lifecycle
    AUDIT_CREATED = "audit_created"
    AUDIT_STARTED = "audit_started"
    AUDIT_COMPLETED = "audit_completed"
    AUDIT_FAILED = "audit_failed"
    AUDIT_CANCELLED = "audit_cancelled"
    
    # Configuration
    CONFIG_UPLOADED = "config_uploaded"
    CONFIG_VALIDATED = "config_validated"
    CONFIG_PARSED = "config_parsed"
    
    # Compliance
    COMPLIANCE_EVALUATED = "compliance_evaluated"
    
    # Findings
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    
    # AI interactions
    AI_HYPOTHESIS_REQUESTED = "ai_hypothesis_requested"
    AI_HYPOTHESIS_RECEIVED = "ai_hypothesis_received"
    MAPPING_CREATED = "mapping_created"
    MAPPING_CONFIRMED = "mapping_confirmed"
    MAPPING_REJECTED = "mapping_rejected"
    MAPPING_UPDATED = "mapping_updated"
    
    # Training
    TRAINING_COMPLETED = "training_completed"

    # Remediation plans (plan-first workflow; backend execution disabled)
    REMEDIATION_PLAN_CREATED = "remediation_plan_created"
    REMEDIATION_PLAN_VALIDATED = "remediation_plan_validated"
    REMEDIATION_APPROVAL_REQUESTED = "remediation_approval_requested"
    REMEDIATION_APPROVED = "remediation_approved"
    REMEDIATION_REJECTED = "remediation_rejected"
    REMEDIATION_APPLIED = "remediation_applied"
    REMEDIATION_FAILED = "remediation_failed"
    REMEDIATION_VERIFIED = "remediation_verified"
    REMEDIATION_ROLLED_BACK = "remediation_rolled_back"
    REMEDIATION_SCRIPT_GENERATED = "remediation_script_generated"
    REMEDIATION_ROLLBACK_SCRIPT_GENERATED = (
        "remediation_rollback_script_generated")


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), nullable=False, default=UserRole.AUDITOR.value)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    audits = relationship("Audit", back_populates="user", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    vendor = Column(String(50), nullable=True)
    platform = Column(String(50), nullable=True)
    firmware_version = Column(String(50), nullable=True)
    ip_address = Column(String(45), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="devices")
    configurations = relationship("Configuration", back_populates="device", cascade="all, delete-orphan")


class Configuration(Base):
    __tablename__ = "configurations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    filename = Column(String(255), nullable=False)
    content_hash = Column(String(64), nullable=False)
    raw_content = Column(Text, nullable=False)
    content_type = Column(String(50), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    line_count = Column(Integer, nullable=False)
    encoding = Column(String(50), nullable=False, default="utf-8")
    encrypted = Column(Boolean, default=False)
    uploaded_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    device = relationship("Device", back_populates="configurations")
    audit_configurations = relationship("AuditConfiguration", back_populates="configuration", cascade="all, delete-orphan")
    vendor_identifications = relationship("VendorIdentification", back_populates="configuration", cascade="all, delete-orphan")
    parsed_configurations = relationship("ParsedConfiguration", back_populates="configuration", cascade="all, delete-orphan")

    # content_hash is the canonical duplicate key: the UNIQUE index is
    # the authoritative race guard for duplicate detection (E01 N5),
    # mirrored by migration 004.
    __table_args__ = (
        Index("uq_configurations_content_hash", "content_hash", unique=True),
    )


class Audit(Base):
    __tablename__ = "audits"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default=AuditStatus.PENDING.value)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    overall_score = Column(Float, nullable=True)
    report_url = Column(String(500), nullable=True)
    configuration_count = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="audits")
    audit_configurations = relationship("AuditConfiguration", back_populates="audit", cascade="all, delete-orphan")
    compliance_results = relationship("ComplianceResult", back_populates="audit", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="audit", cascade="all, delete-orphan")


class AuditConfiguration(Base):
    __tablename__ = "audit_configurations"

    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), primary_key=True)
    configuration_id = Column(UUID(as_uuid=True), ForeignKey("configurations.id", ondelete="CASCADE"), primary_key=True)
    vendor_identification = Column(JSONB, nullable=True)
    parsed_configuration_id = Column(UUID(as_uuid=True), nullable=True)

    # Relationships
    audit = relationship("Audit", back_populates="audit_configurations")
    configuration = relationship("Configuration", back_populates="audit_configurations")


class VendorIdentification(Base):
    __tablename__ = "vendor_identifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    configuration_id = Column(UUID(as_uuid=True), ForeignKey("configurations.id", ondelete="CASCADE"), nullable=False)
    vendor = Column(String(50), nullable=False)
    platform = Column(String(50), nullable=False)
    firmware_version = Column(String(50), nullable=True)
    confidence = Column(Float, nullable=False)
    detection_method = Column(String(50), nullable=False)
    detection_evidence = Column(JSONB, nullable=False, default=[])
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    configuration = relationship("Configuration", back_populates="vendor_identifications")


class ParsedConfiguration(Base):
    __tablename__ = "parsed_configurations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    configuration_id = Column(UUID(as_uuid=True), ForeignKey("configurations.id", ondelete="CASCADE"), nullable=False)
    vendor = Column(String(50), nullable=False)
    platform = Column(String(50), nullable=False)
    parse_tree = Column(JSONB, nullable=False)
    parse_errors = Column(JSONB, nullable=False, default=[])
    parse_warnings = Column(JSONB, nullable=False, default=[])
    unknown_sections = Column(JSONB, nullable=False, default=[])
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    configuration = relationship("Configuration", back_populates="parsed_configurations")
    semantic_interpretations = relationship("SemanticInterpretation", back_populates="parsed_configuration", cascade="all, delete-orphan")


class SemanticInterpretation(Base):
    __tablename__ = "semantic_interpretations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    parsed_configuration_id = Column(UUID(as_uuid=True), ForeignKey("parsed_configurations.id", ondelete="CASCADE"), nullable=False)
    semantic_sections = Column(JSONB, nullable=False, default=[])
    confidence_scores = Column(JSONB, nullable=False, default={})
    unknown_meanings = Column(JSONB, nullable=False, default=[])
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    parsed_configuration = relationship("ParsedConfiguration", back_populates="semantic_interpretations")
    normalized_configurations = relationship("NormalizedConfiguration", back_populates="semantic_interpretation", cascade="all, delete-orphan")


class NormalizedConfiguration(Base):
    __tablename__ = "normalized_configurations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    semantic_interpretation_id = Column(UUID(as_uuid=True), ForeignKey("semantic_interpretations.id", ondelete="CASCADE"), nullable=False)
    universal_model_version = Column(String(50), nullable=False)
    normalized_values = Column(JSONB, nullable=False, default=[])
    unmapped_concepts = Column(JSONB, nullable=False, default=[])
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    semantic_interpretation = relationship("SemanticInterpretation", back_populates="normalized_configurations")
    compliance_results = relationship("ComplianceResult", back_populates="normalized_configuration", cascade="all, delete-orphan")


class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    normalized_configuration_id = Column(UUID(as_uuid=True), ForeignKey("normalized_configurations.id", ondelete="CASCADE"), nullable=False)
    framework = Column(String(50), nullable=False)
    framework_version = Column(String(50), nullable=True)
    control_id = Column(String(100), nullable=False, index=True)
    control_name = Column(String(255), nullable=False)
    control_description = Column(Text, nullable=True)
    result = Column(String(10), nullable=False)
    confidence = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False)
    evidence = Column(JSONB, nullable=False)
    remediation = Column(JSONB, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="compliance_results")
    normalized_configuration = relationship("NormalizedConfiguration", back_populates="compliance_results")
    findings = relationship("Finding", back_populates="compliance_result", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False)
    compliance_result_id = Column(UUID(as_uuid=True), ForeignKey("compliance_results.id", ondelete="CASCADE"), nullable=True)
    # E08 F1: the finding-to-control link is part of the §12 contract, so
    # it is stored on the row (indexed) — never derived per request.
    # Nullable for rows that predate the contract; always set for new rows.
    control_id = Column(String(100), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    status = Column(String(50), nullable=False, default=FindingStatus.OPEN.value)
    evidence = Column(JSONB, nullable=False)
    remediation = Column(JSONB, nullable=True)
    affected_device = Column(String(255), nullable=True)
    affected_vendor = Column(String(50), nullable=True)
    affected_platform = Column(String(50), nullable=True)
    # E09 F1: the 10.9 risk output survives on the row (nullable so
    # historical records pre-dating the contract stay valid; always set
    # for new rows by the canonical pipeline).
    risk_score = Column(Float, nullable=True)
    priority = Column(String(10), nullable=True)
    risk_method = Column(String(32), nullable=True)
    risk_model_version = Column(String(64), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="findings")
    compliance_result = relationship("ComplianceResult", back_populates="findings")
    remediation_plans = relationship("RemediationPlanRow", back_populates="finding", cascade="all, delete-orphan")

    # E08 F9: length + NUL validation before any DB write, so oversized or
    # hostile strings raise a typed ValueError instead of a raw asyncpg
    # DataError (or silently corrupting storage that rejects NUL bytes).
    _STRING_LIMITS = {
        "control_id": 100,
        "title": 255,
        "severity": 20,
        "status": 50,
        "affected_device": 255,
        "affected_vendor": 50,
        "affected_platform": 50,
    }

    @validates("control_id", "title", "severity", "status",
               "affected_device", "affected_vendor", "affected_platform")
    def _validate_text_field(self, key, value):
        if value is None:
            return value
        if not isinstance(value, str):
            raise ValueError(f"Finding.{key} must be str, "
                             f"got {type(value).__name__}")
        if "\x00" in value:
            raise ValueError(f"Finding.{key} must not contain NUL bytes")
        limit = self._STRING_LIMITS[key]
        if len(value) > limit:
            raise ValueError(
                f"Finding.{key} exceeds {limit} characters "
                f"(got {len(value)})")
        return value


class TrainingMapping(Base):
    __tablename__ = "semantic_mappings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    vendor = Column(String(50), nullable=False)
    platform = Column(String(50), nullable=False)
    raw_syntax = Column(Text, nullable=False)
    semantic_meaning = Column(Text, nullable=False)
    universal_model_path = Column(String(255), nullable=False)
    confidence = Column(Numeric(5, 2), nullable=False)
    admin_confirmed = Column(Boolean, default=False)
    admin_notes = Column(Text, nullable=True)
    version = Column(Integer, nullable=False, default=1)
    # Spec 15.1: actor identity as VARCHAR(100), not a user FK. Mappings
    # survive user deletion (audit history); no join is required to read them.
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("vendor", "platform", "raw_syntax", "version",
                         name="uq_semantic_mappings_identity_version"),
    )

    # Relationships
    versions = relationship("MappingVersion", back_populates="mapping", cascade="all, delete-orphan")


class MappingVersion(Base):
    __tablename__ = "mapping_versions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    mapping_id = Column(UUID(as_uuid=True), ForeignKey("semantic_mappings.id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, nullable=False)
    raw_syntax = Column(Text, nullable=False)
    semantic_meaning = Column(Text, nullable=False)
    universal_model_path = Column(String(255), nullable=False)
    # Confidence estimate held at this version (F11 quality axis
    # "AI confidence at creation"; NULL when unrecorded).
    confidence = Column(Numeric(5, 2), nullable=True)
    changed_by = Column(String(100), nullable=False)
    changed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    change_reason = Column(Text, nullable=True)

    # Relationships
    mapping = relationship("TrainingMapping", back_populates="versions")


class AuditTrail(Base):
    __tablename__ = "audit_trail"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    # Hash-chained ledger era (migration 009): stable ordering + chain
    # links. NULL hashes explicitly mean "pre-chain audit era" and are
    # never backfilled.
    seq = Column(BigInteger, nullable=False,
                 server_default=text("nextval('audit_trail_seq_seq')"))
    previous_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=True)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(UUID(as_uuid=True), nullable=True)
    action = Column(String(50), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    details = Column(JSONB, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("seq", name="uq_audit_trail_seq"),
    )


class RemediationPlanRow(Base):
    """Persisted remediation-plan lifecycle (plan-first workflow).

    The executable lifecycle lives here — never inside
    Finding.remediation (advisory contract, untouched) and never
    derived per request. Secrets are never stored on this row: only
    parameter descriptors (name/type/supplied) and resolved PLAIN
    values inside plan_json.commands.
    """

    __tablename__ = "remediation_plans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    plan_id = Column(String(32), nullable=False, unique=True, index=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(100), nullable=True)
    # Strict machine state; transitions enforced in service layer, never
    # accepted from API request bodies.
    status = Column(String(32), nullable=False, default="draft", index=True)
    plan_json = Column(JSONB, nullable=False)
    configuration_id = Column(UUID(as_uuid=True), nullable=True)
    configuration_hash_before = Column(String(64), nullable=True)
    approved_by = Column(UUID(as_uuid=True), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    failure_info = Column(JSONB, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    finding = relationship("Finding", back_populates="remediation_plans")
