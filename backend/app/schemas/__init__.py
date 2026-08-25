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
    """Schema for evidence chain"""
    raw_config: str
    raw_config_line_numbers: Optional[List[int]] = []
    parsed_value: str
    parsed_path: Optional[List[str]] = []
    normalized_value: str
    universal_model_path: Optional[str]
    normalization_confidence: Optional[float]
    security_control: str
    control_description: Optional[str]
    expected_value: str
    actual_value: str
    operator: Optional[str]
    result: str
    result_reasoning: str
    overall_confidence: float
    vendor: Optional[str]
    platform: Optional[str]
    vendor_specific_syntax: Optional[str]


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
    """Schema for finding response"""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    audit_id: Optional[UUID] = None
    title: str
    description: str
    severity: str
    confidence: float
    status: str
    evidence: Optional[dict] = None
    remediation: Optional[dict] = None
    affected_device: Optional[str] = None
    affected_vendor: Optional[str] = None
    affected_platform: Optional[str] = None
    compliance_result_id: Optional[UUID] = None
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


# ============ Training Schemas ============

class TrainingMappingCreate(BaseModel):
    """Schema for creating a training mapping"""
    vendor: str = Field(..., max_length=50)
    platform: str = Field(..., max_length=50)
    raw_syntax: str
    semantic_meaning: str
    universal_model_path: Optional[str] = None
    admin_notes: Optional[str] = None


class TrainingMappingUpdate(BaseModel):
    """Schema for updating a training mapping"""
    semantic_meaning: Optional[str] = None
    universal_model_path: Optional[str] = None
    admin_notes: Optional[str] = None
    change_reason: Optional[str] = None


class TrainingMappingResponse(BaseModel):
    """Schema for training mapping response"""
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
    created_at: datetime
    updated_at: datetime


class MappingVersionResponse(BaseModel):
    """Schema for mapping version response"""
    version: int
    raw_syntax: str
    semantic_meaning: str
    universal_model_path: Optional[str]
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


# ============ Health Schemas ============

class HealthResponse(BaseModel):
    """Schema for health check response"""
    status: str
    version: str
    service: str
