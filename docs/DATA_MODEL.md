# DATA MODEL DOCUMENT

## AI-Driven Multi-Vendor Network Security Compliance Auditor

**Version:** 1.0
**Last Updated:** 2026-08-25
**Status:** Design Phase

---

## Table of Contents

1. [Data Model Overview](#1-data-model-overview)
2. [Core Entities](#2-core-entities)
3. [Configuration Entities](#3-configuration-entities)
4. [Audit Entities](#4-audit-entities)
5. [Compliance Entities](#5-compliance-entities)
6. [Training Entities](#6-training-entities)
7. [Data Contracts](#7-data-contracts)
8. [Database Schema](#8-database-schema)
9. [Data Validation](#9-data-validation)
10. [Data Encryption](#10-data-encryption)
11. [Data Retention](#11-data-retention)
12. [Data Migration](#12-data-migration)

---

## 1. Data Model Overview

### 1.1 Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Type Safety** | Pydantic schemas for validation |
| **Immutability** | Audit results are immutable |
| **Traceability** | Every finding traces to raw config |
| **Versionability** | Knowledge base is versioned |
| **Immutability** | Audit results are immutable |

### 1.2 Entity Categories

| Category | Entities | Purpose |
|----------|----------|---------|
| **User** | User, Session | Authentication, authorization |
| **Device** | Device, DeviceGroup | Device inventory |
| **Configuration** | Configuration, ConfigVersion | Configuration storage |
| **Audit** | Audit, AuditStatus | Audit management |
| **Analysis** | ParsedConfig, SemanticInterpretation, NormalizedConfig | Analysis pipeline |
| **Compliance** | ComplianceResult, Finding, Remediation | Compliance evaluation |
| **Training** | TrainingMapping, MappingVersion | Adaptive learning |
| **Reporting** | Report, ReportTemplate | Report generation |

---

## 2. Core Entities

### 2.1 User

```python
class User(Base):
    __tablename__ = "users"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    devices: Mapped[List["Device"]] = relationship(back_populates="user")
    audits: Mapped[List["Audit"]] = relationship(back_populates="user")
    training_mappings: Mapped[List["TrainingMapping"]] = relationship(back_populates="created_by")

class UserRole(Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    VIEWER = "viewer"
```

### 2.2 Session

```python
class Session(Base):
    __tablename__ = "sessions"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    user: Mapped["User"] = relationship(back_populates="sessions")
```

---

## 3. Configuration Entities

### 3.1 Device

```python
class Device(Base):
    __tablename__ = "devices"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    platform: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    firmware_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    user: Mapped["User"] = relationship(back_populates="devices")
    configurations: Mapped[List["Configuration"]] = relationship(back_populates="device")
```

### 3.2 Configuration

```python
class Configuration(Base):
    __tablename__ = "configurations"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    device_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("devices.id"), nullable=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(String(50), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Metadata
    line_count: Mapped[int] = mapped_column(Integer, nullable=False)
    encoding: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # Relationships
    device: Mapped[Optional["Device"]] = relationship(back_populates="configurations")
    audit_configurations: Mapped[List["AuditConfiguration"]] = relationship(back_populates="configuration")
    parsed_configurations: Mapped[List["ParsedConfiguration"]] = relationship(back_populates="configuration")
```

### 3.3 Configuration Metadata

```python
class ConfigurationMetadata(BaseModel):
    """Metadata for configuration files"""
    source: str  # "file_upload", "paste", "api"
    original_encoding: str
    line_count: int
    checksum: str
    file_size: int
    upload_timestamp: datetime
```

---

## 4. Audit Entities

### 4.1 Audit

```python
class Audit(Base):
    __tablename__ = "audits"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[AuditStatus] = mapped_column(Enum(AuditStatus), nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    overall_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    report_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Summary fields
    configuration_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0)
    low_findings: Mapped[int] = mapped_column(Integer, default=0)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    user: Mapped["User"] = relationship(back_populates="audits")
    audit_configurations: Mapped[List["AuditConfiguration"]] = relationship(back_populates="audit")
    compliance_results: Mapped[List["ComplianceResult"]] = relationship(back_populates="audit")
    findings: Mapped[List["Finding"]] = relationship(back_populates="audit")

class AuditStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
```

### 4.2 AuditConfiguration

```python
class AuditConfiguration(Base):
    __tablename__ = "audit_configurations"
    
    audit_id: Mapped[UUID] = mapped_column(ForeignKey("audits.id"), primary_key=True)
    configuration_id: Mapped[UUID] = mapped_column(ForeignKey("configurations.id"), primary_key=True)
    
    # Analysis results for this configuration
    vendor_identification: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    parsed_configuration_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("parsed_configurations.id"), nullable=True)
    
    # Relationships
    audit: Mapped["Audit"] = relationship(back_populates="audit_configurations")
    configuration: Mapped["Configuration"] = relationship(back_populates="audit_configurations")
```

---

## 5. Analysis Entities

### 5.1 VendorIdentification

```python
class VendorIdentification(Base):
    __tablename__ = "vendor_identifications"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    configuration_id: Mapped[UUID] = mapped_column(ForeignKey("configurations.id"), nullable=False)
    vendor: Mapped[str] = mapped_column(String(50), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    firmware_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    detection_method: Mapped[str] = mapped_column(String(50), nullable=False)
    detection_evidence: Mapped[list] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
```

### 5.2 ParsedConfiguration

```python
class ParsedConfiguration(Base):
    __tablename__ = "parsed_configurations"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    configuration_id: Mapped[UUID] = mapped_column(ForeignKey("configurations.id"), nullable=False)
    vendor: Mapped[str] = mapped_column(String(50), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    parse_tree: Mapped[dict] = mapped_column(JSON, nullable=False)
    parse_errors: Mapped[list] = mapped_column(JSON, nullable=False)
    parse_warnings: Mapped[list] = mapped_column(JSON, nullable=False)
    unknown_sections: Mapped[list] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    configuration: Mapped["Configuration"] = relationship(back_populates="parsed_configurations")
    semantic_interpretations: Mapped[List["SemanticInterpretation"]] = relationship(back_populates="parsed_configuration")
```

### 5.3 ConfigurationNode

```python
class ConfigurationNode(BaseModel):
    """Node in configuration parse tree"""
    path: List[str]
    key: str
    value: Optional[str]
    children: List["ConfigurationNode"]
    line_number: int
    raw_text: str
    
    def get_full_path(self) -> str:
        """Get full path as dot-separated string"""
        return ".".join(self.path + [self.key])
```

### 5.4 UnknownSection

```python
class UnknownSection(BaseModel):
    """Unknown configuration section"""
    path: List[str]
    raw_text: str
    line_numbers: List[int]
    ai_hypothesis: Optional["AIHypothesis"]
    knowledge_base_mapping: Optional["TrainingMapping"]
```

### 5.5 SemanticInterpretation

```python
class SemanticInterpretation(Base):
    __tablename__ = "semantic_interpretations"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    parsed_configuration_id: Mapped[UUID] = mapped_column(ForeignKey("parsed_configurations.id"), nullable=False)
    semantic_sections: Mapped[list] = mapped_column(JSON, nullable=False)
    confidence_scores: Mapped[dict] = mapped_column(JSON, nullable=False)
    unknown_meanings: Mapped[list] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    parsed_configuration: Mapped["ParsedConfiguration"] = relationship(back_populates="semantic_interpretations")
    normalized_configurations: Mapped[List["NormalizedConfiguration"]] = relationship(back_populates="semantic_interpretation")

class SemanticSection(BaseModel):
    """Semantic interpretation of a configuration section"""
    path: List[str]
    meaning: str
    security_relevance: str  # "high", "medium", "low", "none"
    confidence: float
    explanation: str
    universal_model_path: Optional[str]
```

### 5.6 NormalizedConfiguration

```python
class NormalizedConfiguration(Base):
    __tablename__ = "normalized_configurations"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    semantic_interpretation_id: Mapped[UUID] = mapped_column(ForeignKey("semantic_interpretations.id"), nullable=False)
    universal_model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    normalized_values: Mapped[list] = mapped_column(JSON, nullable=False)
    unmapped_concepts: Mapped[list] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    semantic_interpretation: Mapped["SemanticInterpretation"] = relationship(back_populates="normalized_configurations")
    compliance_results: Mapped[List["ComplianceResult"]] = relationship(back_populates="normalized_configuration")

class NormalizedValue(BaseModel):
    """Normalized security value"""
    model_path: str
    value: Any
    confidence: float
    source_path: List[str]
    vendor_specific_syntax: str
    raw_config_line: Optional[str]
```

---

## 6. Compliance Entities

### 6.1 ComplianceResult

```python
class ComplianceResult(Base):
    __tablename__ = "compliance_results"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    audit_id: Mapped[UUID] = mapped_column(ForeignKey("audits.id"), nullable=False)
    normalized_configuration_id: Mapped[UUID] = mapped_column(ForeignKey("normalized_configurations.id"), nullable=False)
    framework: Mapped[str] = mapped_column(String(50), nullable=False)
    framework_version: Mapped[str] = mapped_column(String(50), nullable=False)
    control_id: Mapped[str] = mapped_column(String(100), nullable=False)
    control_name: Mapped[str] = mapped_column(String(255), nullable=False)
    control_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    result: Mapped[ComplianceResultType] = mapped_column(Enum(ComplianceResultType), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False)
    remediation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    audit: Mapped["Audit"] = relationship(back_populates="compliance_results")
    normalized_configuration: Mapped["NormalizedConfiguration"] = relationship(back_populates="compliance_results")
    findings: Mapped[List["Finding"]] = relationship(back_populates="compliance_result")

class ComplianceResultType(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
```

### 6.2 Finding

```python
class Finding(Base):
    __tablename__ = "findings"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    audit_id: Mapped[UUID] = mapped_column(ForeignKey("audits.id"), nullable=False)
    compliance_result_id: Mapped[UUID] = mapped_column(ForeignKey("compliance_results.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False)
    remediation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    affected_device: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    affected_vendor: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    affected_platform: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    audit: Mapped["Audit"] = relationship(back_populates="findings")
    compliance_result: Mapped["ComplianceResult"] = relationship(back_populates="findings")

class FindingStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"
```

### 6.3 EvidenceChain

```python
class EvidenceChain(BaseModel):
    """Complete evidence chain for a finding"""
    raw_config: str
    parsed_value: str
    normalized_value: str
    security_control: str
    expected_value: str
    actual_value: str
    result: str
    reasoning: str
    confidence: float
    vendor_specific_syntax: Optional[str]
    universal_model_path: Optional[str]
```

### 6.4 Remediation

```python
class Remediation(BaseModel):
    """Remediation instructions for a finding"""
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
```

---

## 7. Training Entities

### 7.1 TrainingMapping

```python
class TrainingMapping(Base):
    __tablename__ = "semantic_mappings"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    vendor: Mapped[str] = mapped_column(String(50), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    raw_syntax: Mapped[str] = mapped_column(Text, nullable=False)
    semantic_meaning: Mapped[str] = mapped_column(Text, nullable=False)
    universal_model_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    admin_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    admin_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_by_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Relationships
    created_by: Mapped["User"] = relationship(back_populates="training_mappings")
    versions: Mapped[List["MappingVersion"]] = relationship(back_populates="mapping")

class MappingVersion(Base):
    __tablename__ = "mapping_versions"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    mapping_id: Mapped[UUID] = mapped_column(ForeignKey("semantic_mappings.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_syntax: Mapped[str] = mapped_column(Text, nullable=False)
    semantic_meaning: Mapped[str] = mapped_column(Text, nullable=False)
    universal_model_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    changed_by_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    change_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Relationships
    mapping: Mapped["TrainingMapping"] = relationship(back_populates="versions")
```

### 7.2 AIHypothesis

```python
class AIHypothesis(BaseModel):
    """AI-generated hypothesis for unknown syntax"""
    raw_syntax: str
    suggested_meaning: str
    confidence: float
    reasoning: str
    universal_model_path: Optional[str]
    alternative_interpretations: List["AlternativeInterpretation"]
    security_relevance: str
    explanation: str

class AlternativeInterpretation(BaseModel):
    """Alternative interpretation of unknown syntax"""
    meaning: str
    confidence: float
    reasoning: str
```

---

## 8. Data Contracts

### 8.1 Pydantic Schemas

```python
# Device Schemas
class DeviceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    vendor: Optional[str] = Field(None, max_length=50)
    platform: Optional[str] = Field(None, max_length=50)
    firmware_version: Optional[str] = Field(None, max_length=50)
    ip_address: Optional[str] = Field(None, max_length=45)
    notes: Optional[str] = None

class DeviceResponse(BaseModel):
    id: UUID
    name: str
    vendor: Optional[str]
    platform: Optional[str]
    firmware_version: Optional[str]
    ip_address: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Configuration Schemas
class ConfigurationUpload(BaseModel):
    filename: str
    content: bytes
    device_id: Optional[UUID] = None

class ConfigurationResponse(BaseModel):
    id: UUID
    filename: str
    content_type: str
    size_bytes: int
    line_count: int
    uploaded_at: datetime
    
    class Config:
        from_attributes = True

# Audit Schemas
class AuditCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    configuration_ids: List[UUID]
    framework: str = "CIS"
    framework_version: Optional[str] = "2024.1"

class AuditResponse(BaseModel):
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
    created_at: datetime
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True

# Finding Schemas
class FindingResponse(BaseModel):
    id: UUID
    title: str
    description: str
    severity: Severity
    confidence: float
    status: FindingStatus
    evidence: EvidenceChain
    remediation: Optional[Remediation]
    affected_device: Optional[str]
    affected_vendor: Optional[str]
    affected_platform: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True

# Training Schemas
class TrainingMappingCreate(BaseModel):
    vendor: str = Field(..., max_length=50)
    platform: str = Field(..., max_length=50)
    raw_syntax: str
    semantic_meaning: str
    universal_model_path: Optional[str] = None
    admin_notes: Optional[str] = None

class TrainingMappingResponse(BaseModel):
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
    
    class Config:
        from_attributes = True
```

---

## 9. Database Schema

### 9.1 Complete Schema

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'auditor', 'viewer')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Devices table
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    vendor VARCHAR(50),
    platform VARCHAR(50),
    firmware_version VARCHAR(50),
    ip_address VARCHAR(45),
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Configurations table
CREATE TABLE configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    filename VARCHAR(255) NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    raw_content TEXT NOT NULL,
    content_type VARCHAR(50) NOT NULL,
    size_bytes INTEGER NOT NULL,
    line_count INTEGER NOT NULL,
    encoding VARCHAR(50) NOT NULL,
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    encrypted BOOLEAN DEFAULT FALSE
);

-- Audits table
CREATE TABLE audits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    overall_score DECIMAL(5,2),
    report_url VARCHAR(500),
    configuration_count INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Audit configurations junction table
CREATE TABLE audit_configurations (
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    configuration_id UUID NOT NULL REFERENCES configurations(id) ON DELETE CASCADE,
    vendor_identification JSONB,
    parsed_configuration_id UUID,
    PRIMARY KEY (audit_id, configuration_id)
);

-- Vendor identifications table
CREATE TABLE vendor_identifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    configuration_id UUID NOT NULL REFERENCES configurations(id) ON DELETE CASCADE,
    vendor VARCHAR(50) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    firmware_version VARCHAR(50),
    confidence DECIMAL(5,2) NOT NULL,
    detection_method VARCHAR(50) NOT NULL,
    detection_evidence JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Parsed configurations table
CREATE TABLE parsed_configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    configuration_id UUID NOT NULL REFERENCES configurations(id) ON DELETE CASCADE,
    vendor VARCHAR(50) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    parse_tree JSONB NOT NULL,
    parse_errors JSONB NOT NULL DEFAULT '[]',
    parse_warnings JSONB NOT NULL DEFAULT '[]',
    unknown_sections JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Semantic interpretations table
CREATE TABLE semantic_interpretations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    parsed_configuration_id UUID NOT NULL REFERENCES parsed_configurations(id) ON DELETE CASCADE,
    semantic_sections JSONB NOT NULL,
    confidence_scores JSONB NOT NULL,
    unknown_meanings JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Normalized configurations table
CREATE TABLE normalized_configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    semantic_interpretation_id UUID NOT NULL REFERENCES semantic_interpretations(id) ON DELETE CASCADE,
    universal_model_version VARCHAR(50) NOT NULL,
    normalized_values JSONB NOT NULL,
    unmapped_concepts JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Compliance results table
CREATE TABLE compliance_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    normalized_configuration_id UUID NOT NULL REFERENCES normalized_configurations(id) ON DELETE CASCADE,
    framework VARCHAR(50) NOT NULL,
    framework_version VARCHAR(50),
    control_id VARCHAR(100) NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    control_description TEXT,
    result VARCHAR(10) NOT NULL CHECK (result IN ('PASS', 'FAIL', 'REVIEW')),
    confidence DECIMAL(5,2) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    evidence JSONB NOT NULL,
    remediation JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Findings table
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    compliance_result_id UUID NOT NULL REFERENCES compliance_results(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    confidence DECIMAL(5,2) NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('open', 'in_progress', 'resolved', 'accepted')),
    evidence JSONB NOT NULL,
    remediation JSONB,
    affected_device VARCHAR(255),
    affected_vendor VARCHAR(50),
    affected_platform VARCHAR(50),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Semantic mappings table (training)
CREATE TABLE semantic_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vendor VARCHAR(50) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    raw_syntax TEXT NOT NULL,
    semantic_meaning TEXT NOT NULL,
    universal_model_path VARCHAR(255),
    confidence DECIMAL(5,2) NOT NULL,
    admin_confirmed BOOLEAN DEFAULT FALSE,
    admin_notes TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_by_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vendor, platform, raw_syntax, version)
);

-- Mapping versions table
CREATE TABLE mapping_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mapping_id UUID NOT NULL REFERENCES semantic_mappings(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    raw_syntax TEXT NOT NULL,
    semantic_meaning TEXT NOT NULL,
    universal_model_path VARCHAR(255),
    changed_by_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    change_reason TEXT
);

-- Audit trail table
CREATE TABLE audit_trail (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID NOT NULL,
    action VARCHAR(50) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    details JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### 9.2 Indexes

```sql
-- Performance indexes
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE INDEX idx_devices_user ON devices(user_id);

CREATE INDEX idx_configurations_device ON configurations(device_id);
CREATE INDEX idx_configurations_hash ON configurations(content_hash);
CREATE INDEX idx_configurations_uploaded ON configurations(uploaded_at);

CREATE INDEX idx_audits_user ON audits(user_id);
CREATE INDEX idx_audits_status ON audits(status);
CREATE INDEX idx_audits_created ON audits(created_at);

CREATE INDEX idx_vendor_identifications_config ON vendor_identifications(configuration_id);

CREATE INDEX idx_parsed_configurations_config ON parsed_configurations(configuration_id);

CREATE INDEX idx_semantic_interpretations_parsed ON semantic_interpretations(parsed_configuration_id);

CREATE INDEX idx_normalized_configurations_semantic ON normalized_configurations(semantic_interpretation_id);

CREATE INDEX idx_compliance_results_audit ON compliance_results(audit_id);
CREATE INDEX idx_compliance_results_control ON compliance_results(control_id);
CREATE INDEX idx_compliance_results_framework ON compliance_results(framework);
CREATE INDEX idx_compliance_results_result ON compliance_results(result);

CREATE INDEX idx_findings_audit ON findings(audit_id);
CREATE INDEX idx_findings_compliance ON findings(compliance_result_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);

CREATE INDEX idx_semantic_mappings_vendor ON semantic_mappings(vendor, platform);
CREATE INDEX idx_semantic_mappings_confirmed ON semantic_mappings(admin_confirmed);

CREATE INDEX idx_mapping_versions_mapping ON mapping_versions(mapping_id);

CREATE INDEX idx_audit_trail_entity ON audit_trail(entity_type, entity_id);
CREATE INDEX idx_audit_trail_user ON audit_trail(user_id);
CREATE INDEX idx_audit_trail_created ON audit_trail(created_at);
```

---

## 10. Data Validation

### 10.1 Validation Rules

| Entity | Field | Validation |
|--------|-------|------------|
| User | email | Valid email format, unique |
| User | password_hash | Min 60 characters (bcrypt) |
| User | role | One of: admin, auditor, viewer |
| Device | name | 1-255 characters |
| Device | vendor | Max 50 characters |
| Device | platform | Max 50 characters |
| Device | ip_address | Valid IPv4/IPv6 format |
| Configuration | filename | Max 255 characters |
| Configuration | content_hash | 64 character hex string |
| Configuration | size_bytes | Positive integer |
| Audit | name | 1-255 characters |
| Audit | status | One of: pending, processing, completed, failed, cancelled |
| Finding | severity | One of: CRITICAL, HIGH, MEDIUM, LOW |
| Finding | status | One of: open, in_progress, resolved, accepted |
| TrainingMapping | vendor | 1-50 characters |
| TrainingMapping | platform | 1-50 characters |
| TrainingMapping | raw_syntax | Non-empty string |
| TrainingMapping | semantic_meaning | Non-empty string |
| TrainingMapping | confidence | 0.0-100.0 |

### 10.2 Validation Implementation

```python
# Pydantic validation
class DeviceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    vendor: Optional[str] = Field(None, max_length=50)
    platform: Optional[str] = Field(None, max_length=50)
    firmware_version: Optional[str] = Field(None, max_length=50)
    ip_address: Optional[str] = Field(None, max_length=45)
    notes: Optional[str] = None
    
    @validator('ip_address')
    def validate_ip_address(cls, v):
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError('Invalid IP address format')
        return v

# Database constraints
CONSTRAINTS = """
ALTER TABLE users ADD CONSTRAINT email_format 
    CHECK (email ~* '^[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+[.][A-Za-z]+$');

ALTER TABLE devices ADD CONSTRAINT valid_ip 
    CHECK (ip_address IS NULL OR ip_address ~* '^[0-9.:a-fA-F]+$');

ALTER TABLE configurations ADD CONSTRAINT positive_size 
    CHECK (size_bytes > 0);

ALTER TABLE configurations ADD CONSTRAINT positive_lines 
    CHECK (line_count > 0);
"""
```

---

## 11. Data Encryption

### 11.1 Encryption Strategy

| Data Type | Encryption Method | Key Management |
|-----------|-------------------|----------------|
| Passwords | bcrypt | Application secret |
| Config content | AES-256-GCM | Application secret |
| JWT tokens | HMAC-SHA256 | Application secret |
| Session tokens | SHA-256 hash | Database only |
| Sensitive config fields | AES-256-GCM | Application secret |

### 11.2 Implementation

```python
from cryptography.fernet import Fernet
import hashlib

class EncryptionService:
    def __init__(self, secret_key: str):
        self.key = hashlib.sha256(secret_key.encode()).digest()
        self.cipher = Fernet(base64.urlsafe_b64encode(self.key))
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    def hash_token(self, token: str) -> str:
        """Hash token for storage"""
        return hashlib.sha256(token.encode()).hexdigest()
```

---

## 12. Data Retention

### 12.1 Retention Policy

| Data Type | Retention Period | Action |
|-----------|-----------------|--------|
| User accounts | Indefinite | Manual deletion |
| Sessions | 7 days | Auto-delete |
| Configurations | Indefinite | Manual deletion |
| Audit results | 1 year | Archive |
| Findings | 1 year | Archive |
| Training mappings | Indefinite | Manual deletion |
| Audit trail | 2 years | Archive |
| Logs | 30 days | Delete |

### 12.2 Archival Strategy

```python
class DataRetentionService:
    async def archive_old_audits(self, days_old: int = 365):
        """Archive audits older than specified days"""
        cutoff_date = datetime.now() - timedelta(days=days_old)
        
        # Move to archive table
        # Compress large data
        # Update status
        pass
    
    async def delete_old_sessions(self, days_old: int = 7):
        """Delete sessions older than specified days"""
        cutoff_date = datetime.now() - timedelta(days=days_old)
        
        await self.db.execute(
            delete(Session).where(Session.created_at < cutoff_date)
        )
    
    async def delete_old_logs(self, days_old: int = 30):
        """Delete logs older than specified days"""
        # Implement based on logging solution
        pass
```

---

**END OF DATA MODEL DOCUMENT**
