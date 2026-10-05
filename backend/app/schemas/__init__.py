from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List, Any, Dict
from uuid import UUID
from datetime import datetime
from enum import Enum


# ============ Common Schemas ============

class APIResponse(BaseModel):
    """Standard API response wrapper"""
    success: bool = True
    data: Any = None
    error: Optional[Dict[str, Any]] = None
    meta: Optional[Dict[str, Any]] = None


class PaginationParams(BaseModel):
    """Pagination parameters"""
    page: int = 1
    per_page: int = 20


class PaginationMeta(BaseModel):
    """Pagination metadata"""
    page: int
    per_page: int
    total: int
    total_pages: int


# ============ Auth Schemas ============

class UserRole(str, Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class UserCreate(BaseModel):
    """Schema for creating a user"""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: Optional[str] = Field(None, max_length=255)


class UserLogin(BaseModel):
    """Schema for user login"""
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """Schema for user response"""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


class TokenResponse(BaseModel):
    """Schema for token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    """Schema for token refresh"""
    refresh_token: str


# ============ Device Schemas ============

class DeviceCreate(BaseModel):
    """Schema for creating a device"""
    name: str = Field(..., min_length=1, max_length=255)
    vendor: Optional[str] = Field(None, max_length=50)
    platform: Optional[str] = Field(None, max_length=50)
    firmware_version: Optional[str] = Field(None, max_length=50)
    ip_address: Optional[str] = Field(None, max_length=45)
    notes: Optional[str] = None


class DeviceUpdate(BaseModel):
    """Schema for updating a device"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    vendor: Optional[str] = Field(None, max_length=50)
    platform: Optional[str] = Field(None, max_length=50)
    firmware_version: Optional[str] = Field(None, max_length=50)
    ip_address: Optional[str] = Field(None, max_length=45)
    notes: Optional[str] = None


class DeviceResponse(BaseModel):
    """Schema for device response"""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    vendor: Optional[str]
    platform: Optional[str]
    firmware_version: Optional[str]
    ip_address: Optional[str]
    notes: Optional[str]
    configuration_count: Optional[int] = 0
    last_audit_date: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class DeviceListResponse(BaseModel):
    """Schema for device list response"""
    items: List[DeviceResponse]
    meta: PaginationMeta


# ============ Configuration Schemas ============

class ConfigurationResponse(BaseModel):
    """Schema for configuration response"""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    filename: str
    content_type: str
    size_bytes: int
    line_count: int
    uploaded_at: datetime


class ConfigurationContentResponse(BaseModel):
    """Schema for configuration content response"""
    content: str


class ConfigurationListResponse(BaseModel):
    """Schema for configuration list response"""
    items: List[ConfigurationResponse]
    meta: PaginationMeta


# ============ Audit Schemas ============

class AuditStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuditCreate(BaseModel):
    """Schema for creating an audit"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    configuration_ids: List[UUID]
    framework: str = "CIS"
    framework_version: Optional[str] = "2024.1"


class AuditResponse(BaseModel):
    """Schema for audit response"""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: Optional[str]
    status: AuditStatus
    overall_score: Optional[float]
    configuration_count: int
    findings_count: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    framework: Optional[str] = None
    framework_version: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


class AuditStatusResponse(BaseModel):
    """Schema for audit status response"""
    status: AuditStatus
    progress: int
    current_step: Optional[str]
    steps_completed: List[str]
    estimated_completion: Optional[datetime]


class AuditListResponse(BaseModel):
    """Schema for audit list response"""
    items: List[AuditResponse]
    meta: PaginationMeta


# ============ Compliance Schemas ============

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ComplianceResultType(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"


class FrameworkResponse(BaseModel):
    """Schema for framework response"""
    id: str
    name: str
    description: str
    versions: List[str]
    control_count: int
    categories: List[str]


class ControlResponse(BaseModel):
    """Schema for control response"""
    id: str
    framework: str
    framework_version: str
    title: str
    description: str
    category: str
    severity: str
    vendor: Optional[str]
    platform: Optional[str]
    rule: Optional[Dict[str, Any]] = None
    remediation_template: Optional[Dict[str, Any]] = None
    references: List[str] = []


class FrameworkListResponse(BaseModel):
    """Schema for framework list response"""
    items: List[FrameworkResponse]


class ControlListResponse(BaseModel):
    """Schema for control list response"""
    items: List[ControlResponse]
    meta: PaginationMeta


# ============ Finding Schemas ============

class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


class EvidenceChain(BaseModel):
    """Schema for evidence chain — the §12 EvidenceChain interface.

    Value fields are Optional because honest chains carry null where
    nothing was observed (e.g. no normalized value for raw-evidence
    decisions, no parsed statement for absence-based results); the KEYS
    are always present, which is what the contract guarantees.
    """
    raw_config: Optional[str] = ""
    raw_config_line_numbers: Optional[List[int]] = []
    parsed_value: Optional[Any] = None
    parsed_path: Optional[Any] = ""
    normalized_value: Optional[Any] = None
    universal_model_path: Optional[str] = ""
    normalization_confidence: Optional[float] = 0.0
    security_control: Optional[str] = ""
    control_description: Optional[str] = ""
    expected_value: Optional[Any] = None
    actual_value: Optional[Any] = None
    operator: Optional[str] = ""
    result: Optional[str] = ""
    reasoning: Optional[str] = ""
    overall_confidence: Optional[float] = 0.0
    vendor: Optional[str] = ""
    platform: Optional[str] = ""
    vendor_specific_syntax: Optional[str] = ""
    control_id: Optional[str] = ""


class Remediation(BaseModel):
    """Schema for remediation"""
    finding_id: str
    finding_title: str
    risk_description: str
    why_it_matters: str
    vendor: str
    platform: str
    recommended_config: str
    verification_steps: List[str]
    rollback_steps: List[str]
    references: List[str]
    confidence: float
    prerequisites: Optional[List[str]] = []
    side_effects: Optional[List[str]] = []
    estimated_downtime: Optional[str] = None


class FindingResponse(BaseModel):
    """Schema for finding response — the §12 Finding interface plus
    retained operational fields (audit_id, affected_platform, timestamps).

    control_id is mandatory: API consumers must identify exactly which
    control produced the finding. evidence is the typed §12 EvidenceChain,
    not an opaque dict.
    """
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    audit_id: Optional[UUID] = None
    compliance_result_id: Optional[UUID] = None
    control_id: Optional[str] = None
    title: str
    description: str
    severity: str
    confidence: float
    status: str
    evidence: Optional[EvidenceChain] = None
    remediation: Optional[dict] = None
    affected_device: Optional[str] = None
    affected_vendor: Optional[str] = None
    affected_platform: Optional[str] = None
    risk_score: Optional[float] = None
    priority: Optional[str] = None
    risk_method: Optional[str] = None
    risk_model_version: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class FindingStatusUpdate(BaseModel):
    """Schema for updating finding status"""
    status: FindingStatus
    notes: Optional[str] = None


class FindingListResponse(BaseModel):
    """Schema for finding list response"""
    items: List[FindingResponse]
    meta: PaginationMeta


# ============ Remediation Plan Schemas (plan-first workflow) ============

class RemediationApproveRequest(BaseModel):
    """Approve (confirm=true) or reject a plan awaiting approval.

    params carries operator-supplied placeholder values. Secret values
    are accepted transiently, validated, then discarded — they never
    persist. No status field exists anywhere by design.
    """
    confirm: bool
    params: Dict[str, Any] = {}
    notes: str = ""


class RemediationPlanResponse(BaseModel):
    """Schema for remediation plan response (status is server-derived)."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    plan_id: str
    finding_id: UUID
    control_id: Optional[str] = None
    status: str
    plan: Dict[str, Any] = {}
    configuration_id: Optional[UUID] = None
    configuration_hash_before: Optional[str] = None
    approved_by: Optional[UUID] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    failure_info: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime


# ============ Training Schemas ============

class TrainingMappingCreate(BaseModel):
    """Schema for creating a training mapping.

    `confidence` is an optional producer estimate (0.0-1.0); when omitted it
    defaults to 0.5 for an unconfirmed proposal and 1.0 only when the
    administrator explicitly asserts the mapping. `admin_confirmed`
    therefore defaults to False: a stored proposal enters the review queue
    (spec 14.3.2 low confidence -> REVIEW) and only an explicit
    POST /mappings/{id}/confirm makes it reusable. Trust fields
    (version/id/created_by) stay server-assigned.
    """
    vendor: str = Field(..., max_length=50)
    platform: str = Field(..., max_length=50)
    raw_syntax: str = Field(..., min_length=1, max_length=4096)
    semantic_meaning: str = Field(..., min_length=1, max_length=2000)
    universal_model_path: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    admin_confirmed: bool = False
    admin_notes: Optional[str] = Field(None, max_length=2000)


class TrainingMappingUpdate(BaseModel):
    """Schema for updating a training mapping"""
    semantic_meaning: Optional[str] = None
    universal_model_path: Optional[str] = None
    admin_notes: Optional[str] = None
    change_reason: Optional[str] = None


class TrainingMappingResponse(BaseModel):
    """Schema for training mapping response (spec section 12 interface)"""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    vendor: str
    platform: str
    raw_syntax: str
    semantic_meaning: str
    universal_model_path: Optional[str]
    confidence: float
    admin_confirmed: bool
    admin_notes: Optional[str]
    version: int
    created_by: str
    created_at: datetime
    updated_at: datetime


class MappingVersionResponse(BaseModel):
    """Schema for mapping version response"""
    version: int
    raw_syntax: str
    semantic_meaning: str
    universal_model_path: Optional[str]
    confidence: Optional[float] = None
    changed_by: Optional[str]
    changed_at: datetime
    change_reason: Optional[str]


class AlternativeInterpretation(BaseModel):
    """Schema for alternative interpretation"""
    meaning: str
    confidence: float
    reasoning: str


class AIHypothesisResponse(BaseModel):
    """Schema for AI hypothesis response"""
    raw_syntax: str
    suggested_meaning: str
    confidence: float
    reasoning: str
    universal_model_path: Optional[str]
    alternative_interpretations: List[AlternativeInterpretation]
    security_relevance: str
    explanation: str


class TrainingMappingListResponse(BaseModel):
    """Schema for training mapping list response"""
    items: List[TrainingMappingResponse]
    meta: PaginationMeta


class MappingVersionListResponse(BaseModel):
    """Schema for mapping version list response"""
    items: List[MappingVersionResponse]


class ReanalyzeRequest(BaseModel):
    """Schema for §9.2 step-5 re-analysis of a config with a mapping."""
    config_content: str = Field(..., min_length=1, max_length=200000)
    vendor: Optional[str] = Field(None, max_length=50)
    platform: Optional[str] = Field(None, max_length=50)


# ============ Report Schemas ============

class ReportResponse(BaseModel):
    """Schema for report response"""
    id: str
    audit_id: UUID
    audit_name: str
    framework: str
    overall_score: float
    generated_at: datetime
    download_url: str


class ReportDownloadResponse(BaseModel):
    """Schema for report download response"""
    download_url: str
    expires_at: datetime
    format: str
    size_bytes: int


class ReportListResponse(BaseModel):
    """Schema for report list response"""
    items: List[ReportResponse]
    meta: PaginationMeta


# ============ Audit Trail Schemas (Engine 12) ============

class AuditTrailResponse(BaseModel):
    """One audit-trail record (spec 10.12 output)"""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    action: str
    entity_type: str
    entity_id: Optional[UUID] = None
    user_id: Optional[UUID] = None
    # NULL for legacy rows predating E12 sanitization (which always
    # writes {}); served as-is, never backfilled.
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime
    # Hash-chained ledger era (migration 009). OUTPUT-ONLY: no input
    # schema carries these fields and no write route accepts them, so
    # hashes are server-generated and read-only by construction.
    # NULL explicitly means "pre-chain audit era".
    seq: Optional[int] = None
    previous_hash: Optional[str] = None
    event_hash: Optional[str] = None


class AuditTrailListResponse(BaseModel):
    """Schema for audit-trail query response"""
    items: List[AuditTrailResponse]
    meta: PaginationMeta


# ============ Health Schemas ============

class HealthResponse(BaseModel):
    """Schema for health check response"""
    status: str
    version: str
    service: str
