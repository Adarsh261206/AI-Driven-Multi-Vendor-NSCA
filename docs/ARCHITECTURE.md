# ARCHITECTURE DOCUMENT

## AI-Driven Multi-Vendor Network Security Compliance Auditor

**Version:** 1.0
**Last Updated:** 2026-08-25
**Status:** Design Phase

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Design Principles](#2-design-principles)
3. [System Boundaries](#3-system-boundaries)
4. [Component Architecture](#4-component-architecture)
5. [Data Flow Architecture](#5-data-flow-architecture)
6. [Module Architecture](#6-module-architecture)
7. [API Architecture](#7-api-architecture)
8. [Database Architecture](#8-database-architecture)
9. [Security Architecture](#9-security-architecture)
10. [Deployment Architecture](#10-deployment-architecture)
11. [Performance Architecture](#11-performance-architecture)
12. [Scalability Architecture](#12-scalability-architecture)
13. [Integration Architecture](#13-integration-architecture)
14. [Error Handling Architecture](#14-error-handling-architecture)
15. [Logging Architecture](#15-logging-architecture)
16. [Testing Architecture](#16-testing-architecture)
17. [Monitoring Architecture](#17-monitoring-architecture)
18. [Disaster Recovery](#18-disaster-recovery)
19. [Technical Debt Strategy](#19-technical-debt-strategy)
20. [Decision Log](#20-decision-log)

---

## 1. Architecture Overview

### 1.1 Architecture Style

**Modular Monolith** with clean module boundaries.

**Rationale:**
- Faster development for 2-month timeline
- Simpler deployment and debugging
- Clear module boundaries enable future microservice extraction
- Sufficient for MVP scale

**Future Evolution:**
- Can extract modules into microservices as needed
- Module boundaries defined by interfaces, not implementation

### 1.2 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLIENTS                                    │
├─────────────────────────────────────────────────────────────────────────┤
│  Web Browser (Next.js)  │  REST API Clients  │  Future: Mobile App     │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │
                              │ HTTPS
                              │
┌─────────────────────────────┴───────────────────────────────────────────┐
│                           API GATEWAY                                    │
├─────────────────────────────────────────────────────────────────────────┤
│  Rate Limiting  │  Authentication  │  Request Validation  │  CORS      │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │
                              │
┌─────────────────────────────┴───────────────────────────────────────────┐
│                         APPLICATION LAYER                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   Device    │  │   Audit     │  │  Compliance │  │  Training   │   │
│  │   Module    │  │   Module    │  │   Module    │  │   Module    │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │  Finding    │  │  Reporting  │  │    AI       │  │  Knowledge  │   │
│  │   Module    │  │   Module    │  │   Module    │  │    Base     │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│                                                                          │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │
                              │
┌─────────────────────────────┴───────────────────────────────────────────┐
│                          ENGINE LAYER                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │  Ingestion  │  │  Detection  │  │   Parsing   │  │  Semantic   │   │
│  │   Engine    │  │   Engine    │  │   Engine    │  │   Engine    │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ Normalizer  │  │ Compliance  │  │   Finding   │  │    Risk     │   │
│  │   Engine    │  │   Engine    │  │   Engine    │  │   Engine    │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │ Remediation │  │  Reporting  │  │   Audit     │                     │
│  │   Engine    │  │   Engine    │  │   Trail     │                     │
│  └─────────────┘  └─────────────┘  └─────────────┘                     │
│                                                                          │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │
                              │
┌─────────────────────────────┴───────────────────────────────────────────┐
│                        INFRASTRUCTURE LAYER                              │
├─────────────────────────────────────────────────────────────────────────┤
│  PostgreSQL  │  Redis  │  Object Storage  │  External AI API           │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.3 Layer Responsibilities

| Layer | Responsibility |
|-------|---------------|
| **Clients** | User interface, API consumption |
| **API Gateway** | Authentication, rate limiting, validation |
| **Application** | Business logic orchestration |
| **Engine** | Core processing, domain logic |
| **Infrastructure** | Data persistence, caching, external services |

---

## 2. Design Principles

### 2.1 Core Principles

| Principle | Description | Implementation |
|-----------|-------------|----------------|
| **Modularity** | Modules are independently developable | Clear interfaces, dependency injection |
| **Testability** | Every component is testable | Unit tests, integration tests |
| **Observability** | System behavior is visible | Structured logging, metrics |
| **Security** | Security is built-in, not bolted | Input validation, encryption, auth |
| **Simplicity** | Simple solutions preferred | YAGNI, avoid over-engineering |
| **Explicitness** | No hidden magic | Clear contracts, documented decisions |

### 2.2 Architecture Principles

| Principle | Description |
|-----------|-------------|
| **Deterministic Compliance** | Compliance decisions are rule-based, not AI-based |
| **Evidence-First** | Every finding has a complete evidence chain |
| **Adaptive Learning** | System learns from human feedback |
| **Vendor-Agnostic Core** | Core logic independent of vendor specifics |
| **Fail-Safe** | Graceful degradation, never fail silently |

---

## 3. System Boundaries

### 3.1 System Context

```
┌─────────────────────────────────────────────────────────────────┐
│                        OUR SYSTEM                                │
├─────────────────────────────────────────────────────────────────┤
│  Network Security Compliance Auditor                            │
│  - Configuration ingestion and analysis                         │
│  - Compliance evaluation                                        │
│  - Adaptive learning                                            │
│  - Reporting                                                    │
└─────────────────────────────┬───────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ↓                   ↓                   ↓
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Users     │     │   Devices   │     │  External   │
│  (Auditors) │     │  (Configs)  │     │   AI API    │
└─────────────┘     └─────────────┘     └─────────────┘
```

### 3.2 External Integrations

| External System | Integration Type | Purpose |
|-----------------|------------------|---------|
| OpenAI API | REST API | Semantic analysis |
| PostgreSQL | TCP | Data persistence |
| Redis | TCP | Caching, queues |

### 3.3 System Exclusions

| System | Reason for Exclusion |
|--------|---------------------|
| Network devices | We analyze configs, not live devices |
| SIEM systems | Out of scope for MVP |
| Ticketing systems | Out of scope for MVP |
| CMDB systems | Out of scope for MVP |

---

## 4. Component Architecture

### 4.1 Frontend Components

```
frontend/
├── app/                          # Next.js App Router
│   ├── layout.tsx                # Root layout
│   ├── page.tsx                  # Redirect to dashboard
│   ├── (auth)/                   # Auth routes
│   │   ├── login/
│   │   └── register/
│   ├── (dashboard)/              # Dashboard routes
│   │   ├── layout.tsx            # Dashboard layout
│   │   ├── page.tsx              # Dashboard home
│   │   ├── devices/
│   │   ├── audit/
│   │   ├── findings/
│   │   ├── training/
│   │   ├── compliance/
│   │   ├── reports/
│   │   └── settings/
│   └── api/                      # API routes (if using BFF)
├── components/                   # Reusable components
│   ├── ui/                       # UI primitives
│   ├── layout/                   # Layout components
│   ├── dashboard/                # Dashboard-specific
│   ├── devices/                  # Device-specific
│   ├── audit/                    # Audit-specific
│   ├── findings/                 # Finding-specific
│   ├── training/                 # Training-specific
│   ├── compliance/               # Compliance-specific
│   ├── reports/                  # Report-specific
│   └── common/                   # Shared components
├── hooks/                        # Custom React hooks
├── lib/                          # Utilities
│   ├── api.ts                    # API client
│   ├── auth.ts                   # Auth utilities
│   └── utils.ts                  # General utilities
├── stores/                       # State management
└── types/                        # TypeScript types
```

### 4.2 Backend Components

```
backend/
├── app/
│   ├── main.py                   # FastAPI application
│   ├── config.py                 # Configuration
│   ├── database.py               # Database connection
│   ├── dependencies.py           # Dependency injection
│   ├── models/                   # SQLAlchemy models
│   │   ├── base.py               # Base model
│   │   ├── user.py
│   │   ├── device.py
│   │   ├── configuration.py
│   │   ├── audit.py
│   │   ├── finding.py
│   │   ├── compliance.py
│   │   └── training.py
│   ├── schemas/                  # Pydantic schemas
│   │   ├── base.py               # Base schema
│   │   ├── user.py
│   │   ├── device.py
│   │   ├── configuration.py
│   │   ├── audit.py
│   │   ├── finding.py
│   │   ├── compliance.py
│   │   └── training.py
│   ├── api/                      # API routes
│   │   ├── v1/
│   │   │   ├── router.py         # API router
│   │   │   ├── auth.py
│   │   │   ├── devices.py
│   │   │   ├── configurations.py
│   │   │   ├── audits.py
│   │   │   ├── findings.py
│   │   │   ├── compliance.py
│   │   │   ├── training.py
│   │   │   └── reports.py
│   │   └── deps.py               # API dependencies
│   ├── engines/                  # Core engines
│   │   ├── __init__.py
│   │   ├── base.py               # Base engine class
│   │   ├── ingestion.py
│   │   ├── detection.py
│   │   ├── parsing/
│   │   │   ├── __init__.py
│   │   │   ├── base.py           # Base parser
│   │   │   ├── cisco.py
│   │   │   ├── fortinet.py
│   │   │   ├── juniper.py
│   │   │   └── unknown.py
│   │   ├── semantic.py
│   │   ├── normalization.py
│   │   ├── knowledge.py
│   │   ├── compliance/
│   │   │   ├── __init__.py
│   │   │   ├── base.py           # Base compliance engine
│   │   │   ├── cis.py
│   │   │   └── nist.py
│   │   ├── findings.py
│   │   ├── risk.py
│   │   ├── remediation.py
│   │   └── reporting.py
│   ├── ai/                       # AI integration
│   │   ├── __init__.py
│   │   ├── client.py
│   │   ├── prompts.py
│   │   └── validators.py
│   ├── security/                 # Security utilities
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── credentials.py
│   │   └── encryption.py
│   └── utils/                    # Shared utilities
│       ├── __init__.py
│       ├── hashing.py
│       ├── validators.py
│       └── formatters.py
├── alembic/                      # Database migrations
│   ├── versions/
│   └── env.py
├── tests/                        # Test suite
│   ├── conftest.py
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── requirements.txt
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

---

## 5. Data Flow Architecture

### 5.1 Configuration Audit Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AUDIT WORKFLOW                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐                                                         │
│  │   Upload    │  User uploads configuration file(s)                     │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Validate   │  Check file format, size, encoding                     │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │   Store     │  Store raw config with metadata                        │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Detect     │  Identify vendor, platform, firmware                   │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │   Parse     │  Apply vendor parser, extract structure                │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Semantic   │  Interpret meaning (AI-assisted)                       │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Normalize  │  Map to Universal Security Model                       │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Evaluate   │  Apply compliance rules                                │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Findings   │  Generate findings with evidence                       │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Risk       │  Calculate risk scores                                 │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │ Remediation │  Generate fix instructions                             │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Report     │  Generate PDF report                                   │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Complete   │  Audit complete, results stored                        │
│  └─────────────┘                                                         │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Adaptive Learning Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      ADAPTIVE LEARNING WORKFLOW                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐                                                         │
│  │  Unknown    │  Parser encounters unrecognized syntax                  │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Check KB   │  Look up in knowledge base                            │
│  └──────┬──────┘                                                         │
│         │                                                                │
│    ┌────┴────┐                                                           │
│    │         │                                                           │
│    ↓         ↓                                                           │
│  Found     Not Found                                                     │
│    │         │                                                           │
│    │         ↓                                                           │
│    │    ┌─────────────┐                                                  │
│    │    │  AI Query   │  Generate hypothesis                            │
│    │    └──────┬──────┘                                                  │
│    │           │                                                         │
│    │           ↓                                                         │
│    │    ┌─────────────┐                                                  │
│    │    │  Present    │  Show to administrator                          │
│    │    └──────┬──────┘                                                  │
│    │           │                                                         │
│    │    ┌──────┴──────┐                                                  │
│    │    │      │      │                                                  │
│    │    ↓      ↓      ↓                                                  │
│    │  Confirm Edit  Reject                                              │
│    │    │      │      │                                                  │
│    │    ↓      ↓      ↓                                                  │
│    │    └──────┼──────┘                                                  │
│    │           │                                                         │
│    │           ↓                                                         │
│    │    ┌─────────────┐                                                  │
│    │    │  Store      │  Save mapping (versioned)                       │
│    │    └──────┬──────┘                                                  │
│    │           │                                                         │
│    └─────┬─────┘                                                         │
│          │                                                               │
│          ↓                                                               │
│    ┌─────────────┐                                                       │
│    │  Apply      │  Use mapping for normalization                       │
│    └──────┬──────┘                                                       │
│           │                                                              │
│           ↓                                                              │
│    ┌─────────────┐                                                       │
│    │  Re-evaluate │  Re-run compliance with new understanding           │
│    └─────────────┘                                                       │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Module Architecture

### 6.1 Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         MODULE DEPENDENCIES                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Ingestion ──→ Detection ──→ Parsing ──→ Semantic ──→ Normalization    │
│                                            │              │              │
│                                            │              ↓              │
│                                            │         Knowledge Base     │
│                                            │              │              │
│                                            ↓              ↓              │
│                                       Compliance ←────────┘              │
│                                            │                            │
│                                            ↓                            │
│                                         Findings                        │
│                                            │                            │
│                                    ┌───────┴───────┐                    │
│                                    ↓               ↓                    │
│                                   Risk        Remediation               │
│                                    │               │                    │
│                                    └───────┬───────┘                    │
│                                            ↓                            │
│                                         Reporting                       │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Module Interfaces

```python
# Base interface for all engines
class BaseEngine(ABC):
    @abstractmethod
    async def process(self, input_data: Any) -> Any:
        """Process input and return output"""
        pass
    
    @abstractmethod
    def validate_input(self, input_data: Any) -> bool:
        """Validate input data"""
        pass
    
    @abstractmethod
    def get_metrics(self) -> Dict[str, Any]:
        """Return engine metrics"""
        pass

# Specific engine interfaces
class IngestionEngine(BaseEngine):
    async def process(self, file_content: bytes, metadata: Dict) -> IngestedConfiguration:
        pass

class DetectionEngine(BaseEngine):
    async def process(self, config: IngestedConfiguration) -> VendorIdentification:
        pass

class ParsingEngine(BaseEngine):
    async def process(self, config: IngestedConfiguration, vendor: VendorIdentification) -> ParsedConfiguration:
        pass

class SemanticEngine(BaseEngine):
    async def process(self, parsed: ParsedConfiguration) -> SemanticInterpretation:
        pass

class NormalizationEngine(BaseEngine):
    async def process(self, semantic: SemanticInterpretation) -> NormalizedConfiguration:
        pass

class ComplianceEngine(BaseEngine):
    async def process(self, normalized: NormalizedConfiguration, framework: str) -> ComplianceResult:
        pass
```

### 6.3 Module Communication

Modules communicate through:
1. **Direct function calls** - For synchronous operations
2. **Event system** - For async operations (future)
3. **Shared data contracts** - For data exchange

---

## 7. API Architecture

### 7.1 API Design Principles

| Principle | Implementation |
|-----------|---------------|
| RESTful | Resource-based URLs, HTTP methods |
| Versioned | `/api/v1/`, `/api/v2/` |
| Typed | Pydantic schemas for request/response |
| Documented | OpenAPI/Swagger auto-generated |
| Secure | JWT auth, rate limiting, validation |

### 7.2 API Structure

```python
# API Router Structure
api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_router.include_router(devices_router, prefix="/devices", tags=["devices"])
api_router.include_router(configurations_router, prefix="/configurations", tags=["configurations"])
api_router.include_router(audits_router, prefix="/audits", tags=["audits"])
api_router.include_router(findings_router, prefix="/findings", tags=["findings"])
api_router.include_router(compliance_router, prefix="/compliance", tags=["compliance"])
api_router.include_router(training_router, prefix="/training", tags=["training"])
api_router.include_router(reports_router, prefix="/reports", tags=["reports"])
```

### 7.3 Request/Response Patterns

```python
# Standard response wrapper
class APIResponse(BaseModel, Generic[T]):
    success: bool
    data: Optional[T] = None
    error: Optional[APIError] = None
    meta: Optional[Meta] = None

# Pagination
class Meta(BaseModel):
    page: int
    per_page: int
    total: int
    total_pages: int

# Error response
class APIError(BaseModel):
    code: str
    message: str
    details: Optional[List[ErrorDetail]] = None
```

---

## 8. Database Architecture

### 8.1 Database Design Principles

| Principle | Implementation |
|-----------|---------------|
| Normalized | 3NF for core entities |
| Indexed | Indexes for query performance |
| Encrypted | Sensitive data encrypted |
| Audited | Audit trail for all changes |
| Migrated | Alembic for schema management |

### 8.2 Entity Relationships

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      ENTITY RELATIONSHIPS                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  User ──┬──→ Device ──→ Configuration                                   │
│         │                                                               │
│         ├──→ Audit ──→ AuditConfiguration ──→ Configuration             │
│         │         │                                                    │
│         │         └──→ ComplianceResult ──→ Finding                     │
│         │                                                               │
│         └──→ SemanticMapping                                            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 8.3 Database Schema

See [DATA_MODEL.md](./DATA_MODEL.md) for complete schema.

---

## 9. Security Architecture

### 9.1 Security Principles

| Principle | Implementation |
|-----------|---------------|
| Defense in Depth | Multiple security layers |
| Least Privilege | Minimal required permissions |
| Secure by Default | Secure configurations |
| Fail Secure | Secure failure modes |
| Complete Mediation | Every access checked |

### 9.2 Security Controls

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SECURITY CONTROLS                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │   Auth      │  │   AuthZ     │  │   Input     │                     │
│  │   (JWT)     │  │   (RBAC)    │  │  Validation │                     │
│  └─────────────┘  └─────────────┘  └─────────────┘                     │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │   Rate      │  │   CORS      │  │   HTTPS     │                     │
│  │   Limiting  │  │             │  │   Enforced  │                     │
│  └─────────────┘  └─────────────┘  └─────────────┘                     │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │   Data      │  │   Audit     │  │   Secrets   │                     │
│  │   Encryption│  │   Trail     │  │   Management│                     │
│  └─────────────┘  └─────────────┘  └─────────────┘                     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.3 Authentication Flow

```
1. User submits credentials
2. Validate credentials against database
3. Generate JWT token (15 min expiry)
4. Generate refresh token (7 days expiry)
5. Return tokens to client
6. Client includes JWT in Authorization header
7. Server validates JWT on each request
8. Token refresh when JWT expires
```

### 9.4 Authorization Model

```python
class Role(Enum):
    ADMIN = "admin"      # Full access
    AUDITOR = "auditor"  # Can run audits, view findings
    VIEWER = "viewer"    # Read-only access

class Permission(Enum):
    CREATE_DEVICE = "device:create"
    READ_DEVICE = "device:read"
    UPDATE_DEVICE = "device:update"
    DELETE_DEVICE = "device:delete"
    
    CREATE_AUDIT = "audit:create"
    READ_AUDIT = "audit:read"
    CANCEL_AUDIT = "audit:cancel"
    
    UPDATE_FINDING = "finding:update"
    TRAIN_SYSTEM = "training:create"
    
    VIEW_REPORTS = "reports:read"
    DOWNLOAD_REPORTS = "reports:download"
```

---

## 10. Deployment Architecture

### 10.1 Development Deployment

```yaml
# docker-compose.yml (development)
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: compliance_auditor
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: dev_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7
    ports:
      - "6379:6379"

  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://postgres:dev_password@db:5432/compliance_auditor
      REDIS_URL: redis://redis:6379
    depends_on:
      - db
      - redis

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      NEXT_PUBLIC_API_URL: http://localhost:8000

  celery_worker:
    build: ./backend
    command: celery -A app.celery_app worker -l info
    environment:
      DATABASE_URL: postgresql://postgres:dev_password@db:5432/compliance_auditor
      REDIS_URL: redis://redis:6379
    depends_on:
      - db
      - redis

volumes:
  postgres_data:
```

### 10.2 Production Deployment

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     PRODUCTION DEPLOYMENT                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │   Nginx     │  │   Backend   │  │   Celery    │                     │
│  │   (Reverse  │  │   (FastAPI) │  │   Workers   │                     │
│  │    Proxy)   │  │             │  │             │                     │
│  └─────────────┘  └─────────────┘  └─────────────┘                     │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │   Frontend  │  │   PostgreSQL│  │   Redis     │                     │
│  │   (Next.js) │  │   (Managed) │  │   (Managed) │                     │
│  └─────────────┘  └─────────────┘  └─────────────┘                     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.3 Environment Configuration

```python
# config.py
class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Network Security Compliance Auditor"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Security
    SECRET_KEY: str  # Required
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRATION_DAYS: int = 7
    
    # Database
    DATABASE_URL: str  # Required
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # AI
    OPENAI_API_KEY: str  # Required
    OPENAI_MODEL: str = "gpt-4"
    AI_TIMEOUT_SECONDS: int = 30
    
    # File Upload
    MAX_UPLOAD_SIZE_MB: int = 10
    ALLOWED_EXTENSIONS: List[str] = [".txt", ".cfg", ".conf", ".zip"]
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]
    
    class Config:
        env_file = ".env"
```

---

## 11. Performance Architecture

### 11.1 Performance Requirements

| Metric | Target | Measurement |
|--------|--------|-------------|
| API Response Time | < 200ms (p95) | Average endpoint |
| Audit Processing | < 5 minutes per config | End-to-end |
| Report Generation | < 30 seconds | PDF generation |
| Concurrent Users | 100+ | Simultaneous sessions |

### 11.2 Performance Strategies

| Strategy | Implementation |
|----------|---------------|
| **Async Processing** | FastAPI async, Celery for background |
| **Connection Pooling** | SQLAlchemy pool, Redis pool |
| **Caching** | Redis for frequent queries |
| **Pagination** | All list endpoints paginated |
| **Database Indexes** | Indexes for common queries |
| **Lazy Loading** | Load related data on demand |

### 11.3 Caching Strategy

```python
# Cache layers
CACHE_LAYERS = {
    "user_session": {"ttl": 900, "prefix": "session:"},
    "audit_status": {"ttl": 30, "prefix": "audit:status:"},
    "compliance_rules": {"ttl": 3600, "prefix": "rules:"},
    "knowledge_base": {"ttl": 300, "prefix": "kb:"},
}
```

---

## 12. Scalability Architecture

### 12.1 Scalability Strategy

For MVP, vertical scaling is sufficient. Horizontal scaling designed for future.

### 12.2 Future Horizontal Scaling

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     HORIZONTAL SCALING                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐                                                         │
│  │   Load      │  Nginx load balancer                                   │
│  │   Balancer  │                                                         │
│  └──────┬──────┘                                                         │
│         │                                                                │
│    ┌────┴────┐                                                           │
│    ↓         ↓                                                           │
│  Backend   Backend  (Multiple instances)                                 │
│  Node 1    Node 2                                                        │
│    │         │                                                           │
│    └────┬────┘                                                           │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │   Celery    │  Multiple worker nodes                                 │
│  │   Workers   │                                                         │
│  └─────────────┘                                                         │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 13. Integration Architecture

### 13.1 External Integrations

| System | Integration Method | Purpose |
|--------|-------------------|---------|
| OpenAI API | REST API | Semantic analysis |
| PostgreSQL | TCP | Data persistence |
| Redis | TCP | Caching, queues |

### 13.2 Future Integrations

| System | Integration Method | Purpose |
|--------|-------------------|---------|
| Network Devices | SSH/API | Live config retrieval |
| SIEM | API | Log forwarding |
| Ticketing | API | Finding creation |

---

## 14. Error Handling Architecture

### 14.1 Error Handling Strategy

```python
# Error hierarchy
class AppError(Exception):
    """Base application error"""
    pass

class ValidationError(AppError):
    """Input validation error"""
    pass

class NotFoundError(AppError):
    """Resource not found"""
    pass

class AuthenticationError(AppError):
    """Authentication failed"""
    pass

class AuthorizationError(AppError):
    """Authorization failed"""
    pass

class ExternalServiceError(AppError):
    """External service error"""
    pass

class ProcessingError(AppError):
    """Processing error"""
    pass
```

### 14.2 Error Response Format

```python
@app.exception_handler(AppError)
async def app_error_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details
            }
        }
    )
```

### 14.3 Error Recovery

| Error Type | Recovery Strategy |
|------------|-------------------|
| Validation Error | Return 400 with details |
| Not Found | Return 404 |
| Auth Error | Return 401, clear session |
| External Service | Retry with backoff, fallback |
| Processing Error | Log, return 500, alert |

---

## 15. Logging Architecture

### 15.1 Logging Strategy

```python
# Structured logging
LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json"
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "app.log",
            "formatter": "json"
        }
    },
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s"
        }
    },
    "root": {
        "level": "INFO",
        "handlers": ["console", "file"]
    }
}
```

### 15.2 Log Categories

| Category | Purpose |
|----------|---------|
| `audit.processing` | Audit workflow events |
| `engine.*` | Engine processing events |
| `api.*` | API request/response |
| `security.*` | Security events |
| `ai.*` | AI interaction events |
| `error.*` | Error events |

### 15.3 Audit Trail

```python
# Audit trail logging
class AuditTrail:
    @staticmethod
    def log(
        entity_type: str,
        entity_id: str,
        action: str,
        user_id: str,
        details: Dict
    ):
        # Store in database
        # Include timestamp, user, action, details
        pass
```

---

## 16. Testing Architecture

### 16.1 Test Strategy

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        TEST PYRAMID                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│                           ┌─────────┐                                    │
│                           │  E2E    │  Few, high-value                  │
│                          ┌┴─────────┴┐                                  │
│                          │Integration │  Module interactions            │
│                         ┌┴───────────┴┐                                 │
│                         │    Unit     │  Many, fast, isolated           │
│                         └─────────────┘                                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 16.2 Test Types

| Type | Scope | Speed | Quantity |
|------|-------|-------|----------|
| Unit | Function/method | Fast | Many |
| Integration | Module boundaries | Medium | Some |
| E2E | Complete workflow | Slow | Few |
| Performance | Load testing | Slow | Baseline |

### 16.3 Test Organization

```
tests/
├── conftest.py                 # Shared fixtures
├── unit/
│   ├── engines/
│   │   ├── test_detection.py
│   │   ├── test_parsing.py
│   │   └── test_compliance.py
│   ├── models/
│   │   └── test_models.py
│   └── schemas/
│       └── test_schemas.py
├── integration/
│   ├── api/
│   │   ├── test_devices.py
│   │   └── test_audits.py
│   └── engines/
│       └── test_audit_flow.py
└── fixtures/
    ├── cisco_ios/
    ├── fortinet/
    └── juniper/
```

---

## 17. Monitoring Architecture

### 17.1 Monitoring Strategy

For MVP, basic logging and metrics. Future: Prometheus + Grafana.

### 17.2 Key Metrics

| Metric | Description |
|--------|-------------|
| API Response Time | p50, p95, p99 latency |
| Audit Processing Time | End-to-end audit duration |
| Error Rate | Percentage of failed requests |
| Active Users | Concurrent sessions |
| Audit Success Rate | Percentage of successful audits |

### 17.3 Health Checks

```python
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "database": await check_database(),
        "redis": await check_redis()
    }
```

---

## 18. Disaster Recovery

### 18.1 Backup Strategy

| Component | Backup Method | Frequency |
|-----------|---------------|-----------|
| Database | pg_dump | Daily |
| Redis | RDB + AOF | Hourly |
| File Storage | Copy | Daily |
| Configuration | Git | Continuous |

### 18.2 Recovery Procedures

| Scenario | Recovery Time | Procedure |
|----------|---------------|-----------|
| Database failure | < 1 hour | Restore from backup |
| Redis failure | < 5 minutes | Restart, rebuild cache |
| Application failure | < 5 minutes | Restart containers |
| Full system failure | < 4 hours | Full restore |

---

## 19. Technical Debt Strategy

### 19.1 Acceptable Technical Debt (MVP)

- Limited test coverage (60%+ instead of 80%+)
- Manual deployments
- Basic monitoring
- Limited caching
- Simple error handling

### 19.2 Unacceptable Technical Debt

- No authentication
- No input validation
- No logging
- No error handling
- Hardcoded secrets
- No documentation

### 19.3 Debt Repayment Plan

| Debt | Repayment Timeline |
|------|-------------------|
| Test coverage | Post-MVP |
| CI/CD pipeline | Post-MVP |
| Advanced monitoring | Post-MVP |
| Performance optimization | Post-MVP |

---

## 20. Decision Log

### 20.1 Architecture Decisions

| Decision | Rationale | Date |
|----------|-----------|------|
| Modular monolith over microservices | Faster development, simpler deployment | 2026-08-25 |
| FastAPI over Django | Async support, type safety, speed | 2026-08-25 |
| PostgreSQL over MongoDB | ACID compliance, JSON support | 2026-08-25 |
| Celery over Dramatiq | More mature, better documentation | 2026-08-25 |
| JWT over Session | Stateless, scalable | 2026-08-25 |

### 20.2 Technology Choices

| Choice | Alternatives Considered | Rationale |
|--------|------------------------|-----------|
| Next.js | React + Vite | SSR, routing, ecosystem |
| Pydantic | Marshmallow | Type safety, performance |
| SQLAlchemy | Tortoise ORM | Maturity, features |
| ReportLab | WeasyPrint | Python-native, flexibility |

---

**END OF ARCHITECTURE DOCUMENT**
