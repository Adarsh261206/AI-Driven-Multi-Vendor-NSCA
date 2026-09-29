# PROJECT MASTER SPECIFICATION

## AI-Driven Multi-Vendor Network Security Compliance Auditor

**Problem Statement ID:** 26155
**Organization:** National Technical Research Organisation (NTRO)
**Theme:** Blockchain & Cybersecurity
**Version:** 1.0
**Last Updated:** 2026-08-25

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Problem Interpretation](#2-problem-interpretation)
3. [Target Users](#3-target-users)
4. [Product Vision](#4-product-vision)
5. [Core Value Proposition](#5-core-value-proposition)
6. [Differentiation](#6-differentiation)
7. [Competitor Analysis](#7-competitor-analysis)
8. [System Architecture](#8-system-architecture)
9. [Complete Workflow](#9-complete-workflow)
10. [Engine/Module Definitions](#10-enginemodule-definitions)
11. [Universal Security Model](#11-universal-security-model)
12. [Data Contracts](#12-data-contracts)
13. [Compliance Architecture](#13-compliance-architecture)
14. [AI Architecture](#14-ai-architecture)
15. [Adaptive Learning Architecture](#15-adaptive-learning-architecture)
16. [Security Architecture](#16-security-architecture)
17. [Frontend Information Architecture](#17-frontend-information-architecture)
18. [Backend Architecture](#18-backend-architecture)
19. [Database Architecture](#19-database-architecture)
20. [API Architecture](#20-api-architecture)
21. [Testing Strategy](#21-testing-strategy)
22. [Dataset Strategy](#22-dataset-strategy)
23. [MVP Scope](#23-mvp-scope)
24. [Future Scope](#24-future-scope)
25. [Explicit Non-Goals](#25-explicit-non-goals)
26. [SIH Demo Strategy](#26-sih-demo-strategy)
27. [Known Risks](#27-known-risks)
28. [Technical Assumptions](#28-technical-assumptions)
29. [Open Questions](#29-open-questions)
30. [Development Roadmap](#30-development-roadmap)

---

## 1. Problem Statement

### 1.1 Original Statement

Modern enterprise networks contain heterogeneous devices from many vendors (Cisco, Fortinet, Juniper, Palo Alto, Arista, Check Point, Sophos, SonicWall, Huawei, MikroTik, cloud-native networking platforms, SONiC-based systems). Each vendor uses different CLI syntax, configuration hierarchy, terminology, operating systems, firmware versions, and configuration structures.

Security standards (CIS Benchmarks, NIST SP 800-53, DISA STIGs, ISO/IEC 27001) define security requirements that must be evaluated across these heterogeneous environments.

### 1.2 Core Challenges

| Challenge | Description |
|-----------|-------------|
| Manual Auditing | Time-consuming, error-prone, doesn't scale |
| Vendor-Specific Parsers | Each vendor requires custom parsing logic |
| Vendor Lock-in | Tools often support only specific vendors |
| Poor Scalability | Adding new vendors/frameworks requires major development |
| Syntax Differences | Same security concept, different representation |
| Firmware Changes | Configuration syntax evolves across versions |
| Unknown Vendors | New/proprietary configurations break existing parsers |
| Centralized Visibility | No single view across all network devices |
| Actionable Remediation | Findings without clear fix instructions |

### 1.3 Required Capabilities

The PS explicitly asks for:
- Configuration ingestion
- Normalization
- AI-assisted interpretation
- Deviation analysis
- Multi-framework compliance
- Dynamic adaptation
- Interactive administrator training
- Actionable remediation
- Security scoring
- PDF reporting

**Most Critical Requirement:** When encountering unrecognized configuration, administrators must be able to teach the system through an interactive interface without backend code redeployment.

---

## 2. Problem Interpretation

### 2.1 What We're Actually Building

We are building an **adaptive compliance auditing platform** that:

1. **Ingests** network device configurations from multiple vendors
2. **Normalizes** vendor-specific syntax into a universal security model
3. **Evaluates** configurations against compliance frameworks
4. **Learns** from administrators when encountering unknown syntax
5. **Generates** evidence-based findings with actionable remediation
6. **Reports** compliance status with professional PDF output

### 2.2 What We're NOT Building

- A real-time network monitoring tool
- A device management platform (we don't configure devices)
- A general-purpose AI chatbot
- A replacement for commercial NAC/NAC solutions
- A full SIEM integration (out of scope)

### 2.3 Key Insight

The fundamental problem is **semantic translation** across vendor boundaries, not just syntactic parsing. A Cisco `no ip http server` and a Fortinet `set status disable` in HTTP context may both mean "disable HTTP management" but look completely different.

---

## 3. Target Users

### 3.1 Primary Users

| Role | Needs |
|------|-------|
| **Network Security Auditor** | Verify compliance across all vendors, generate evidence |
| **Security Operations Center (SOC) Analyst** | Quick visibility into network security posture |
| **Compliance Manager** | Framework-level compliance status, audit trails |
| **Network Administrator** | Understand what needs to be fixed, how to fix it |

### 3.2 Secondary Users

| Role | Needs |
|------|-------|
| **CISO** | Dashboard view, risk summary, compliance trends |
| **External Auditor** | Evidence packages, PDF reports |
| **IT Management** | Overall security posture metrics |

### 3.3 User Journey (Simplified)

```
Auditor uploads configs → System analyzes → Findings generated → 
Auditor reviews → Remediation applied → Re-audit confirms → Report generated
```

---

## 4. Product Vision

### 4.1 Vision Statement

**"An adaptive, AI-augmented platform that understands network security configurations across any vendor, provides deterministic compliance evaluation, and learns continuously from human expertise."**

### 4.2 Design Philosophy

**"AI UNDERSTANDS. DETERMINISTIC RULES DECIDE."**

| AI Handles | Deterministic Engine Handles |
|------------|------------------------------|
| Semantic interpretation | Compliance pass/fail decisions |
| Unknown syntax hypothesis | Severity classification |
| Natural language explanation | Evidence chain validation |
| Remediation explanation | Risk score calculation |
| Confidence estimation | Framework rule matching |

### 4.3 Core Principles

1. **Evidence-First:** Every finding must trace back to raw configuration
2. **Deterministic Compliance:** No black-box security decisions
3. **Adaptive Learning:** Human-in-the-loop knowledge acquisition
4. **Vendor-Agnostic Core:** Normalized model operates independently of vendor syntax
5. **Explainable Results:** Every output must be understandable by a human auditor

---

## 5. Core Value Proposition

### 5.1 For SIH Judges

| Value | Evidence |
|-------|----------|
| **Technical Depth** | Universal security model, deterministic compliance engine |
| **Innovation** | Adaptive learning loop for unknown configurations |
| **Practical Utility** | Solves real enterprise network security challenges |
| **Scalability** | Architecture supports adding new vendors/frameworks |
| **Demonstrability** | Live demo with real Cisco configs + synthetic unknown vendor |

### 5.2 For Enterprise Users

| Value | Evidence |
|-------|----------|
| **Reduced Audit Time** | Automated compliance checking across all vendors |
| **Consistent Results** | Deterministic engine eliminates human variability |
| **Knowledge Retention** | System learns and remembers vendor-specific semantics |
| **Actionable Output** | Specific remediation steps, not just findings |
| **Audit Trail** | Complete evidence chain for compliance audits |

---

## 6. Differentiation

### 6.1 Our Unique Contributions

| Feature | Why It's Different |
|---------|-------------------|
| **Adaptive Learning Loop** | Admins teach system unknown syntax without code changes |
| **Universal Security Model** | Semantic normalization across all vendors |
| **Evidence Chain** | Raw → Parsed → Normalized → Control → Expected → Actual → Result |
| **Deterministic Compliance** | AI assists, but rules decide |
| **Vendor-Agnostic Architecture** | Adding new vendors doesn't require core changes |

### 6.2 vs Existing Solutions

| Solution | Limitation | Our Advantage |
|----------|-----------|---------------|
| Tufin | Commercial, limited to supported vendors | Adaptive to unknown vendors |
| Batfish | Focus on network verification, not compliance | Security-focused compliance |
| Netmiko | Device automation, not compliance checking | Compliance-specific engine |
| NAPALM | Device management, not security auditing | Security model + AI interpretation |
| Manual Auditing | Slow, inconsistent, doesn't scale | Automated + consistent |

### 6.3 What We're NOT Claiming

- We don't claim to replace Tufin or enterprise NMS tools
- We don't claim real-time device monitoring
- We don't claim 100% accuracy on unknown configurations
- We don't claim to support every vendor from day one

---

## 7. Competitor Analysis

### 7.1 Direct Competitors

| Tool | Strength | Weakness | Our Advantage |
|------|----------|----------|---------------|
| **Batfish** | Network verification, reachability analysis | Not security-focused, no compliance | Security compliance focus |
| **Tufin** | Enterprise security policy management | Commercial, vendor-locked | Open, adaptive |
| **NAPALM** | Multi-vendor device automation | Not compliance-focused | Compliance-specific |
| **Netmiko** | Simple multi-vendor SSH | No compliance/security model | Semantic understanding |
| **Cisco NSO** | Cisco-specific network automation | Vendor-locked | Vendor-agnostic |

### 7.2 Indirect Competitors

| Tool | Relevance | Gap We Fill |
|------|-----------|-------------|
| **Nessus/Qualys** | Vulnerability scanning | Configuration compliance (not vulns) |
| **Splunk Enterprise Security** | SIEM, log analysis | Pre-config compliance (not log-based) |
| **OpenSCAP** | System compliance | Network device focus |

### 7.3 Our Honest Position

We are NOT claiming to be the first compliance tool. We ARE claiming:
1. Adaptive learning for unknown vendor syntax is novel
2. Evidence-first design with full traceability
3. Deterministic compliance with AI assistance
4. Vendor-agnostic architecture with practical MVP

---

## 8. System Architecture

### 8.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (Next.js)                       │
│  Dashboard │ Devices │ Audit │ Findings │ Training │ Reports    │
└────────────────────────────┬────────────────────────────────────┘
                             │ REST API
┌────────────────────────────┴────────────────────────────────────┐
│                      BACKEND (FastAPI)                           │
├─────────────────────────────────────────────────────────────────┤
│  API Gateway │ Auth │ Rate Limiting │ Request Validation        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │  Ingestion  │  │  Detection  │  │   Parsing   │            │
│  │   Engine    │→ │   Engine    │→ │   Engine    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          ↓                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │  Semantic   │  │ Normalizer  │  │  Knowledge  │            │
│  │   Engine    │→ │   Engine    │→ │    Base     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          ↓                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Compliance  │→ │   Finding   │→ │    Risk     │            │
│  │   Engine    │  │   Engine    │  │   Engine    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          ↓                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Remediation │  │  Reporting  │  │   Audit     │            │
│  │   Engine    │  │   Engine    │  │   Trail     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
│                                                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                    INFRASTRUCTURE                                │
├─────────────────────────────────────────────────────────────────┤
│  PostgreSQL │ Redis │ Object Storage │ AI Model API              │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Module Boundaries

Each module has:
- **Input:** Defined data contract
- **Processing:** Module-specific logic
- **Output:** Defined data contract
- **Dependencies:** Explicit module dependencies
- **Tests:** Unit and integration tests

### 8.3 Data Flow

```
1. User uploads configuration file(s)
2. Ingestion Engine validates and stores raw config
3. Detection Engine identifies vendor/platform
4. Parsing Engine extracts configuration structure
5. Semantic Engine interprets meaning (AI-assisted)
6. Normalizer maps to Universal Security Model
7. Knowledge Base provides additional context
8. Compliance Engine evaluates against frameworks
9. Finding Engine generates findings with evidence
10. Risk Engine calculates risk scores
11. Remediation Engine generates fix instructions
12. Reporting Engine creates PDF output
13. Audit Trail stores complete history
```

---

## 9. Complete Workflow

### 9.1 Primary Workflow: Configuration Audit

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. UPLOAD                                                       │
│    - User uploads config file(s)                                 │
│    - System validates file format                                │
│    - Raw config stored securely                                  │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 2. DETECTION                                                     │
│    - Identify vendor (Cisco, Fortinet, etc.)                     │
│    - Identify platform (IOS, NX-OS, etc.)                        │
│    - Identify firmware version if available                      │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 3. PARSING                                                       │
│    - Apply vendor-specific parser                                │
│    - Extract configuration tree                                  │
│    - Identify unknown/unsupported sections                       │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 4. SEMANTIC ANALYSIS                                             │
│    - Interpret meaning of configuration sections                 │
│    - Handle unknown syntax with AI assistance                    │
│    - Generate confidence scores                                  │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 5. NORMALIZATION                                                 │
│    - Map to Universal Security Model                             │
│    - Apply knowledge base mappings                               │
│    - Flag unmapped concepts                                      │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 6. COMPLIANCE EVALUATION                                         │
│    - Apply CIS/NIST rules                                        │
│    - Compare expected vs actual                                  │
│    - Generate PASS/FAIL/REVIEW results                           │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 7. FINDING GENERATION                                            │
│    - Create finding with evidence chain                          │
│    - Assign severity                                             │
│    - Calculate confidence                                        │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 8. REMEDIATION                                                   │
│    - Generate vendor-specific fix                                │
│    - Include verification steps                                  │
│    - Include rollback guidance                                   │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 9. REPORTING                                                     │
│    - Generate compliance score                                   │
│    - Create PDF report                                           │
│    - Store audit history                                         │
└──────────────────────────────────────────────────────────────────┘
```

### 9.2 Adaptive Learning Workflow

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. UNKNOWN DETECTED                                              │
│    - Parser encounters unrecognized syntax                        │
│    - System preserves original context                           │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 2. AI HYPOTHESIS                                                 │
│    - AI analyzes unknown syntax                                  │
│    - Generates semantic interpretation                          │
│    - Provides confidence score (0-100%)                          │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 3. ADMINISTRATOR REVIEW                                          │
│    - Present suggestion to administrator                         │
│    - Show original syntax + interpretation                       │
│    - Allow CONFIRM / EDIT / REJECT                               │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 4. KNOWLEDGE UPDATE                                              │
│    - Store approved mapping in knowledge base                    │
│    - Version the mapping                                         │
│    - Associate with vendor/platform                              │
└────────────────────────────┬─────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────────┐
│ 5. RE-ANALYSIS                                                   │
│    - Re-run normalization with new mapping                       │
│    - Re-run compliance evaluation                                │
│    - Show improved understanding                                 │
└──────────────────────────────────────────────────────────────────┘
```

---

## 10. Engine/Module Definitions

### 10.1 Ingestion Engine

**Purpose:** Accept configuration input from various sources

**Responsibilities:**
- File upload handling (text, zip, tar.gz)
- Input validation (encoding, size limits)
- Raw storage with integrity tracking
- Metadata extraction (filename, timestamp, size)

**Input:** Raw file bytes
**Output:** `IngestedConfiguration`

### 10.2 Detection Engine

**Purpose:** Identify vendor, platform, and firmware version

**Responsibilities:**
- Pattern matching against known vendor signatures
- Banner detection
- Configuration structure analysis
- Confidence scoring for detection

**Input:** `IngestedConfiguration`
**Output:** `VendorIdentification`

### 10.3 Parsing Engine

**Purpose:** Extract structured configuration from raw text

**Responsibilities:**
- Apply vendor-specific parser
- Handle nested configuration hierarchy
- Identify parse errors and warnings
- Flag unknown/unsupported sections

**Input:** `IngestedConfiguration` + `VendorIdentification`
**Output:** `ParsedConfiguration`

### 10.4 Semantic Engine

**Purpose:** Interpret meaning of configuration sections

**Responsibilities:**
- Map syntax to semantic meaning
- Handle unknown syntax with AI assistance
- Generate confidence scores
- Provide natural language explanations

**Input:** `ParsedConfiguration`
**Output:** `SemanticInterpretation`

### 10.5 Normalizer

**Purpose:** Map vendor-specific semantics to Universal Security Model

**Responsibilities:**
- Apply normalization rules
- Use knowledge base for mappings
- Handle semantic ambiguities
- Generate normalized security representation

**Input:** `SemanticInterpretation`
**Output:** `NormalizedConfiguration`

### 10.6 Knowledge Base

**Purpose:** Store learned mappings and semantic rules

**Responsibilities:**
- Store vendor-specific mappings
- Version control for mappings
- Provide lookup for normalization
- Support administrator updates

**Input:** Mapping queries
**Output:** Semantic mappings

### 10.7 Compliance Engine

**Purpose:** Evaluate normalized configuration against security frameworks

**Responsibilities:**
- Load framework rules (CIS, NIST)
- Apply deterministic evaluation logic
- Generate PASS/FAIL/REVIEW results
- Produce evidence chains

**Input:** `NormalizedConfiguration` + Framework Rules
**Output:** `ComplianceResults`

### 10.8 Finding Engine

**Purpose:** Generate structured findings from compliance results

**Responsibilities:**
- Create finding records
- Assign severity levels
- Calculate confidence scores
- Link evidence chains

**Input:** `ComplianceResults`
**Output:** `Findings`

### 10.9 Risk Engine

**Purpose:** Calculate risk scores for findings

**Responsibilities:**
- Apply risk calculation formula
- Consider severity, impact, confidence
- Generate priority rankings
- Calculate overall compliance score

**Input:** `Findings`
**Output:** `RiskAssessment`

#### 10.9.1 Risk Engine Contract Amendment (E09, 2026-09-28 — explicit amendment, not a silent redefinition)

The original §10.9 named the formula, vocabulary and output without
defining them. This amendment specifies them normatively; where it
narrows an ambiguity it says so.

**Normative risk formula** (deterministic production path, §4.2):

    risk = base(severity) × vendor(vendor) × category(category)
           × max(confidence, 0.5) / 15.6 × 100

rounded to one decimal, clamped to [0, 100]. The 0.5 confidence floor is
preserved explicitly (risk stops decreasing below confidence 0.5;
monotonic non-decreasing in confidence). 15.6 is the maximum raw product
(10.0 × 1.2 × 1.3 × 1.0).

**Severity base:** CRITICAL 10.0, HIGH 7.5, MEDIUM 5.0, LOW 2.5
(neutral inputs therefore score 64.1 / 48.1 / 32.1 / 16.0).

**Vendor impact** (verified supported vendors carry a multiplier;
everything else resolves to the documented neutral 1.0 — never a silent
Cisco substitution, never an inflated multiplier):
cisco 1.2, juniper 1.1, fortinet 1.1, paloalto 1.2, unknown 1.0.

**Category impact** (one canonical map keyed by normalized category —
strip, lowercase, underscores to spaces, collapsed whitespace; unknown
categories resolve to the documented neutral 1.0):
aaa 1.3, ssh 1.2, authentication 1.3, access control 1.2, snmp 1.1,
logging 1.0, management 1.1, ntp 1.0, services 1.1, password rules 1.2,
access rules 1.2, audit and accountability 1.2,
configuration management 1.1, system and communications protection 1.2.

**Priority vocabulary and bands** (preserved): P1 >= 80, P2 >= 60,
P3 >= 40, P4 below 40; every score bands to exactly one of P1, P2, P3,
P4 — never empty.

**RiskAssessment interface:** finding_id, risk_score, priority, severity,
confidence, vendor, category, scoring_method, scoring_version, plus
optional advisory_score / advisory_model / advisory_model_version.

**Deterministic-vs-ML decision:** the normative production scorer is the
deterministic formula above. The RandomForest risk model is advisory
only: it may supply an advisory_score with model metadata, and its
published fit metric measures formula-emulation fidelity on synthetic
labels — never real-world risk accuracy. It must never determine
risk_score, priority, or any security decision.

**Input contract:** the RiskEngine assesses finding-grade inputs
(severity, vendor, category, confidence for one finding) into a
RiskAssessment, which is attached to the finding before persistence.

**Overall compliance score ownership:** the overall compliance score
(passed/evaluated, single formula) stays owned by the compliance engine
(E07); the Risk Engine owns risk assessment only and computes no second
score.

**Exposure:** risk_score, priority, risk_method and risk_model_version
persist on the finding row and are served on the finding resource
(GET finding); no separate risk endpoint exists — risk travels on the
finding, and reports render the persisted values.

### 10.10 Remediation Engine

**Purpose:** Generate actionable fix instructions

**Responsibilities:**
- Generate vendor-specific remediation
- Include verification steps
- Include rollback guidance
- Reference specific findings

**Input:** `Findings` + `VendorIdentification`
**Output:** `Remediations`

### 10.11 Reporting Engine

**Purpose:** Generate compliance reports

**Responsibilities:**
- Create PDF reports
- Include executive summary
- Include detailed findings
- Include remediation guidance

**Input:** `AuditResult`
**Output:** PDF document

### 10.12 Audit Trail

**Purpose:** Maintain complete audit history

**Responsibilities:**
- Store all audit results
- Track configuration changes
- Maintain version history
- Support audit queries

**Input:** Audit events
**Output:** Audit records

---

## 11. Universal Security Model

### 11.1 Model Structure

The Universal Security Model is a hierarchical, extensible representation of security concepts.

```
universal_security_model:
  device:
    hostname
    vendor
    platform
    firmware_version
  
  management:
    http:
      enabled
      port
      secure_only
    https:
      enabled
      port
      certificate_valid
    telnet:
      enabled
    ssh:
      enabled
      version
      port
      key_size
      timeout
  
  authentication:
    password_policy:
      min_length
      complexity
      expiration
      history
    mfa_enabled
    lockout_policy:
      max_attempts
      lockout_duration
  
  aaa:
    authentication_enabled
    authorization_enabled
    accounting_enabled
    radius_configured
    tacacs_configured
  
  logging:
    enabled
    level
    remote_enabled
    remote_server
    source_interface
  
  ntp:
    configured
    authenticated
    servers
  
  access_control:
    acl_applied
    default_action
    rules_count
  
  crypto:
    ssh_key_size
    https_cert_valid
    snmp_v3_auth
  
  services:
    snmp:
      enabled
      version
      community_string_type
    dns:
      configured
    dhcp:
      enabled
  
  interfaces:
    unused_interfaces_shutdown
    management_interface_identified
```

### 11.2 Model Extensibility

New security concepts can be added by:
1. Defining the concept in the model schema
2. Creating normalization rules for each vendor
3. Adding compliance rules that reference the concept
4. Updating the knowledge base with mappings

### 11.3 Model Versioning

The model is versioned:
- **Major:** Breaking changes to existing concepts
- **Minor:** New concepts added
- **Patch:** Documentation/corrections

---

## 12. Data Contracts

### 12.1 Core Data Types

```typescript
// Configuration Ingestion
interface IngestedConfiguration {
  id: string;
  filename: string;
  content_hash: string;
  content_type: string;
  size_bytes: number;
  uploaded_at: datetime;
  raw_content: string;
  metadata: ConfigurationMetadata;
}

interface ConfigurationMetadata {
  source: "file_upload" | "paste" | "api";
  original_encoding: string;
  line_count: number;
  checksum: string;
}

// Vendor Detection
interface VendorIdentification {
  vendor: string;
  platform: string;
  firmware_version: string | null;
  confidence: number;
  detection_method: "pattern" | "banner" | "structure" | "ai";
  detection_evidence: string[];
}

// Parsing
interface ParsedConfiguration {
  id: string;
  ingested_config_id: string;
  vendor: string;
  platform: string;
  parse_tree: ConfigurationNode[];
  parse_errors: ParseError[];
  parse_warnings: ParseWarning[];
  unknown_sections: UnknownSection[];
}

interface ConfigurationNode {
  path: string[];
  key: string;
  value: string | null;
  children: ConfigurationNode[];
  line_number: number;
  raw_text: string;
}

interface UnknownSection {
  path: string[];
  raw_text: string;
  line_numbers: number[];
  ai_hypothesis: AIHypothesis | null;
}

// Semantic Analysis
interface SemanticInterpretation {
  id: string;
  parsed_config_id: string;
  semantic_sections: SemanticSection[];
  confidence_scores: ConfidenceMap;
  unknown_meanings: UnknownMeaning[];
}

interface SemanticSection {
  path: string[];
  meaning: string;
  security_relevance: "high" | "medium" | "low" | "none";
  confidence: number;
  explanation: string;
}

// Normalization
interface NormalizedConfiguration {
  id: string;
  semantic_interpretation_id: string;
  universal_model_version: string;
  normalized_values: NormalizedValue[];
  unmapped_concepts: UnmappedConcept[];
}

interface NormalizedValue {
  model_path: string;
  value: any;
  confidence: number;
  source_path: string[];
  vendor_specific_syntax: string;
}

// Compliance
interface ComplianceResult {
  id: string;
  normalized_config_id: string;
  framework: string;
  framework_version: string;
  control_results: ControlResult[];
  overall_score: number;
  total_controls: number;
  passed: number;
  failed: number;
  review: number;
}

interface ControlResult {
  control_id: string;
  control_name: string;
  description: string;
  result: "PASS" | "FAIL" | "REVIEW";
  confidence: number;
  evidence: EvidenceChain;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  remediation: Remediation | null;
}

interface EvidenceChain {
  raw_config: string;
  parsed_value: string;
  normalized_value: string;
  security_control: string;
  expected_value: string;
  actual_value: string;
  result: string;
  reasoning: string;
}

// Findings
interface Finding {
  id: string;
  compliance_result_id: string;
  control_id: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  evidence: EvidenceChain;
  affected_device: string;
  affected_vendor: string;
  remediation: Remediation | null;
  status: "open" | "in_progress" | "resolved" | "accepted";
}

// Remediation
interface Remediation {
  finding_id: string;
  finding_title: string;
  risk_description: string;
  why_it_matters: string;
  vendor: string;
  platform: string;
  recommended_config: string;
  verification_steps: string[];
  rollback_steps: string[];
  references: string[];
}

// Training/Adaptive Learning
interface TrainingMapping {
  id: string;
  vendor: string;
  platform: string;
  raw_syntax: string;
  semantic_meaning: string;
  universal_model_path: string;
  confidence: number;
  admin_confirmed: boolean;
  admin_notes: string;
  version: number;
  created_by: string;
  created_at: datetime;
}

// Audit
interface AuditResult {
  id: string;
  name: string;
  description: string;
  created_at: datetime;
  completed_at: datetime | null;
  status: "pending" | "processing" | "completed" | "failed";
  configuration_count: number;
  device_summary: DeviceSummary[];
  compliance_results: ComplianceResult[];
  overall_score: number;
  findings_summary: FindingsSummary;
  report_url: string | null;
}
```

---

## 13. Compliance Architecture

### 13.1 Framework Support

**MVP Frameworks:**
1. **CIS Benchmarks** - Primary focus
2. **NIST SP 800-53** - Selected high-impact controls

**Future Frameworks:**
3. DISA STIGs
4. ISO/IEC 27001

### 13.2 Control Structure

```yaml
control:
  id: "CIS-Cisco-IOS-1.1"
  framework: "CIS"
  version: "2024.1"
  title: "Disable HTTP Server"
  description: "The HTTP server feature allows..."
  category: "management"
  severity: "HIGH"
  
  rule:
    type: "configuration_check"
    target:
      model_path: "management.http.enabled"
      vendor: "cisco"
      platform: "ios"
    expected:
      value: false
      operator: "equals"
  
  evidence_template:
    raw_config: "ip http server"
    parsed_value: "http_server_enabled = true"
    normalized_value: "management.http.enabled = true"
    security_control: "CIS-Cisco-IOS-1.1"
    expected_value: "false"
    actual_value: "true"
    result: "FAIL"
    reasoning: "HTTP server is enabled, which violates..."
  
  remediation:
    vendor: "cisco"
    platform: "ios"
    command: "no ip http server"
    verification: "show running-config | include http"
    rollback: "ip http server"
    references:
      - "https://www.cisecurity.org/benchmark/cisco"
```

### 13.3 Evaluation Logic

```python
def evaluate_control(control, normalized_config):
    """Deterministic compliance evaluation"""
    
    # 1. Extract relevant value from normalized config
    actual_value = normalized_config.get(control.target.model_path)
    
    # 2. Apply expected operator
    if control.expected.operator == "equals":
        result = actual_value == control.expected.value
    elif control.expected.operator == "not_equals":
        result = actual_value != control.expected.value
    elif control.expected.operator == "greater_than":
        result = actual_value > control.expected.value
    elif control.expected.operator == "less_than":
        result = actual_value < control.expected.value
    elif control.expected.operator == "contains":
        result = control.expected.value in actual_value
    elif control.expected.operator == "in":
        result = actual_value in control.expected.value
    
    # 3. Generate evidence chain
    evidence = generate_evidence_chain(
        raw_config=raw_config,
        parsed_value=parsed_value,
        normalized_value=actual_value,
        expected_value=control.expected.value,
        result=result
    )
    
    # 4. Determine confidence
    confidence = calculate_confidence(
        normalization_confidence=normalized_config.confidence,
        rule_confidence=control.confidence
    )
    
    # 5. Return deterministic result
    return ComplianceResult(
        control_id=control.id,
        result="PASS" if result else "FAIL",
        confidence=confidence,
        evidence=evidence
    )
```

### 13.4 Review Result

REVIEW is returned when:
- Normalized value has low confidence (<70%)
- AI interpretation was required
- Unknown syntax was encountered
- Insufficient evidence available

---

## 14. AI Architecture

### 14.1 AI Usage Boundaries

| Task | AI Role | Deterministic Role |
|------|---------|-------------------|
| Unknown syntax interpretation | Generate hypothesis | Admin confirms/rejects |
| Natural language explanation | Generate explanation | Evidence chain validation |
| Remediation explanation | Explain why/how | Command generation |
| Confidence estimation | Estimate confidence | Threshold enforcement |
| Vendor detection assist | Suggest vendor | Pattern matching confirms |

### 14.2 AI Model Strategy

**MVP Approach:** API-based LLM (OpenAI GPT-4 or equivalent)

**Rationale:**
- No local model training required
- Rapid prototyping
- Good zero-shot performance on network configs
- Can be replaced with local model later

**Future:** Fine-tuned model on network configuration corpus

### 14.3 AI Safety Measures

1. **Never trust AI output directly** - Always validate against deterministic rules
2. **Confidence thresholds** - Low confidence triggers REVIEW, not PASS/FAIL
3. **Human-in-the-loop** - Admin must confirm AI interpretations
4. **Audit trail** - Log all AI inputs/outputs
5. **Fallback** - If AI unavailable, system still functions (with more REVIEWs)

### 14.4 AI Prompt Strategy

```python
SYSTEM_PROMPT = """You are a network security configuration analyst.

Analyze the following network device configuration and identify:
1. What security-relevant settings are configured
2. What each setting means semantically
3. Your confidence in each interpretation

Output structured JSON with:
- section: configuration section path
- meaning: semantic interpretation
- security_relevance: high/medium/low/none
- confidence: 0-100
- explanation: human-readable explanation

Be conservative. If uncertain, state uncertainty clearly."""
```

---

## 15. Adaptive Learning Architecture

### 15.1 Knowledge Base Structure

```sql
CREATE TABLE semantic_mappings (
    id UUID PRIMARY KEY,
    vendor VARCHAR(50) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    raw_syntax TEXT NOT NULL,
    semantic_meaning TEXT NOT NULL,
    universal_model_path VARCHAR(255) NOT NULL,
    confidence DECIMAL(5,2) NOT NULL,
    admin_confirmed BOOLEAN DEFAULT FALSE,
    admin_notes TEXT,
    version INTEGER NOT NULL,
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    
    UNIQUE(vendor, platform, raw_syntax, version)
);

CREATE TABLE mapping_versions (
    id UUID PRIMARY KEY,
    mapping_id UUID REFERENCES semantic_mappings(id),
    version INTEGER NOT NULL,
    raw_syntax TEXT NOT NULL,
    semantic_meaning TEXT NOT NULL,
    universal_model_path VARCHAR(255) NOT NULL,
    changed_by VARCHAR(100) NOT NULL,
    changed_at TIMESTAMP NOT NULL,
    change_reason TEXT
);
```

### 15.2 Learning Process

```
1. Parser encounters unknown syntax
2. System checks knowledge base for existing mapping
3. If not found:
   a. AI generates hypothesis
   b. Hypothesis presented to admin
   c. Admin confirms/edits/rejects
   d. Mapping stored with version
4. If found:
   a. Use existing mapping
   b. Optionally update confidence
5. Normalization uses mapping
6. Compliance re-evaluated
7. Results updated
```

### 15.3 Mapping Quality

Mappings are quality-scored based on:
- Number of admin confirmations
- Consistency across similar configs
- Age and version history
- AI confidence at creation

---

## 16. Security Architecture

### 16.1 Configuration Data Security

- Configurations may contain sensitive network information
- Store encrypted at rest
- Access controlled by user/role
- Audit trail for all access
- Optional: detect and mask credentials before storage

### 16.2 Credential Detection

Before storing configurations, scan for:
- Passwords in plaintext
- SNMP community strings
- API keys
- Certificates and private keys
- RADIUS/TACACS+ shared secrets

If detected:
- Option 1: Mask before storage (replace with ****)
- Option 2: Warn user before upload
- Option 3: Both

### 16.3 API Security

- JWT-based authentication
- Role-based access control
- Rate limiting
- Input validation
- CORS configuration
- HTTPS enforcement

### 16.4 AI Security

- No sensitive data sent to AI unless necessary
- AI prompts sanitized
- AI outputs validated before use
- AI API keys secured in environment variables
- Audit log of AI interactions

---

## 17. Frontend Information Architecture

### 17.1 Page Structure

```
/                           → Redirect to /dashboard
/login                      → Authentication
/dashboard                  → Overview metrics, recent audits
/devices                    → Device inventory list
/devices/:id                → Device details + configs
/audit/new                  → Start new audit (upload configs)
/audit/:id                  → Audit results
/audit/:id/findings         → Findings list
/audit/:id/findings/:id     → Finding detail + evidence
/audit/:id/report           → PDF report download
/training                   → Adaptive learning interface
/training/mappings          → Knowledge base mappings
/training/mapping/:id       → Mapping detail + version history
/compliance                 → Framework overview
/compliance/:framework      → Framework-specific controls
/reports                    → Historical reports
/settings                   → User settings
/settings/api-keys          → API key management
```

### 17.2 Component Architecture

```
components/
├── layout/
│   ├── Sidebar.tsx
│   ├── Header.tsx
│   └── MainLayout.tsx
├── dashboard/
│   ├── MetricsCards.tsx
│   ├── RecentAudits.tsx
│   └── ComplianceChart.tsx
├── devices/
│   ├── DeviceList.tsx
│   ├── DeviceCard.tsx
│   └── DeviceDetails.tsx
├── audit/
│   ├── UploadForm.tsx
│   ├── AuditProgress.tsx
│   ├── AuditResults.tsx
│   └── AuditHistory.tsx
├── findings/
│   ├── FindingsList.tsx
│   ├── FindingCard.tsx
│   ├── FindingDetail.tsx
│   └── EvidenceChain.tsx
├── training/
│   ├── MappingList.tsx
│   ├── MappingEditor.tsx
│   ├── AIHypothesis.tsx
│   └── VersionHistory.tsx
├── compliance/
│   ├── FrameworkSelector.tsx
│   ├── ControlList.tsx
│   └── ControlDetail.tsx
├── reports/
│   ├── ReportList.tsx
│   └── ReportPreview.tsx
└── common/
    ├── Button.tsx
    ├── Card.tsx
    ├── Modal.tsx
    ├── Table.tsx
    ├── Badge.tsx
    └── Loading.tsx
```

### 17.3 UI Design Principles

1. **Information Hierarchy** - Most important info first
2. **Evidence Visibility** - Findings always show evidence chain
3. **Professional Aesthetic** - Enterprise cybersecurity look
4. **Fast Navigation** - Minimal page loads, client-side routing
5. **Responsive** - Works on desktop and tablet
6. **Dark/Light Mode** - Support both (dark for SOC environments)

---

## 18. Backend Architecture

### 18.1 Technology Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| **Framework** | FastAPI | Async, typed, fast development |
| **Language** | Python 3.11+ | AI/ML ecosystem, rapid development |
| **Database** | PostgreSQL | JSON support, reliability |
| **Cache** | Redis | Session, rate limiting, queues |
| **Task Queue** | Celery + Redis | Background audit processing |
| **PDF Generation** | ReportLab | Python-native, flexible |
| **AI Integration** | OpenAI API | GPT-4 for semantic analysis |
| **Validation** | Pydantic | Type safety, serialization |

### 18.2 Module Structure

```
backend/
├── app/
│   ├── main.py                    # FastAPI application
│   ├── config.py                  # Configuration management
│   ├── database.py                # Database connection
│   ├── models/                    # SQLAlchemy models
│   │   ├── device.py
│   │   ├── configuration.py
│   │   ├── audit.py
│   │   ├── finding.py
│   │   └── training.py
│   ├── schemas/                   # Pydantic schemas
│   │   ├── device.py
│   │   ├── configuration.py
│   │   ├── audit.py
│   │   ├── finding.py
│   │   └── training.py
│   ├── api/                       # API routes
│   │   ├── v1/
│   │   │   ├── devices.py
│   │   │   ├── configurations.py
│   │   │   ├── audits.py
│   │   │   ├── findings.py
│   │   │   ├── training.py
│   │   │   └── reports.py
│   │   └── deps.py                # Dependencies
│   ├── engines/                   # Core business logic
│   │   ├── ingestion.py
│   │   ├── detection.py
│   │   ├── parsing/
│   │   │   ├── base.py
│   │   │   ├── cisco.py
│   │   │   ├── fortinet.py
│   │   │   ├── juniper.py
│   │   │   └── unknown.py
│   │   ├── semantic.py
│   │   ├── normalization.py
│   │   ├── knowledge.py
│   │   ├── compliance/
│   │   │   ├── base.py
│   │   │   ├── cis.py
│   │   │   └── nist.py
│   │   ├── findings.py
│   │   ├── risk.py
│   │   ├── remediation.py
│   │   └── reporting.py
│   ├── ai/                        # AI integration
│   │   ├── client.py
│   │   ├── prompts.py
│   │   └── validators.py
│   ├── security/                  # Security utilities
│   │   ├── auth.py
│   │   ├── credentials.py
│   │   └── encryption.py
│   └── utils/                     # Shared utilities
│       ├── hashing.py
│       └── validators.py
├── alembic/                       # Database migrations
├── tests/                         # Test suite
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

### 18.3 Background Processing

Audits are processed asynchronously:

```python
@celery_app.task
def process_audit(audit_id: str):
    """Process audit in background"""
    # 1. Load ingested configurations
    # 2. Run detection for each
    # 3. Run parsing for each
    # 4. Run semantic analysis
    # 5. Run normalization
    # 6. Run compliance evaluation
    # 7. Generate findings
    # 8. Calculate risk scores
    # 9. Generate remediation
    # 10. Store results
    # 11. Generate report
```

---

## 19. Database Architecture

### 19.1 Schema Design

```sql
-- Core Tables
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE devices (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    vendor VARCHAR(50),
    platform VARCHAR(50),
    firmware_version VARCHAR(50),
    ip_address VARCHAR(45),
    notes TEXT,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE configurations (
    id UUID PRIMARY KEY,
    device_id UUID REFERENCES devices(id),
    filename VARCHAR(255) NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    raw_content TEXT NOT NULL,
    content_type VARCHAR(50),
    size_bytes INTEGER,
    uploaded_at TIMESTAMP NOT NULL,
    encrypted BOOLEAN DEFAULT FALSE
);

CREATE TABLE audits (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    overall_score DECIMAL(5,2),
    report_url VARCHAR(500)
);

CREATE TABLE audit_configurations (
    audit_id UUID REFERENCES audits(id),
    configuration_id UUID REFERENCES configurations(id),
    PRIMARY KEY (audit_id, configuration_id)
);

CREATE TABLE compliance_results (
    id UUID PRIMARY KEY,
    audit_id UUID REFERENCES audits(id),
    configuration_id UUID REFERENCES configurations(id),
    framework VARCHAR(50) NOT NULL,
    framework_version VARCHAR(50),
    control_id VARCHAR(100) NOT NULL,
    control_name VARCHAR(255),
    result VARCHAR(10) NOT NULL,
    confidence DECIMAL(5,2),
    severity VARCHAR(20),
    evidence JSONB,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE findings (
    id UUID PRIMARY KEY,
    compliance_result_id UUID REFERENCES compliance_results(id),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    confidence DECIMAL(5,2),
    status VARCHAR(50) NOT NULL,
    remediation JSONB,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE semantic_mappings (
    id UUID PRIMARY KEY,
    vendor VARCHAR(50) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    raw_syntax TEXT NOT NULL,
    semantic_meaning TEXT NOT NULL,
    universal_model_path VARCHAR(255),
    confidence DECIMAL(5,2),
    admin_confirmed BOOLEAN DEFAULT FALSE,
    admin_notes TEXT,
    version INTEGER NOT NULL,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE audit_trail (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID NOT NULL,
    action VARCHAR(50) NOT NULL,
    user_id UUID REFERENCES users(id),
    details JSONB,
    created_at TIMESTAMP NOT NULL
);
```

### 19.2 Indexes

```sql
CREATE INDEX idx_configurations_device ON configurations(device_id);
CREATE INDEX idx_configurations_hash ON configurations(content_hash);
CREATE INDEX idx_audits_user ON audits(user_id);
CREATE INDEX idx_audits_status ON audits(status);
CREATE INDEX idx_compliance_results_audit ON compliance_results(audit_id);
CREATE INDEX idx_compliance_results_control ON compliance_results(control_id);
CREATE INDEX idx_findings_compliance ON findings(compliance_result_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_semantic_mappings_vendor ON semantic_mappings(vendor, platform);
CREATE INDEX idx_audit_trail_entity ON audit_trail(entity_type, entity_id);
```

---

## 20. API Architecture

### 20.1 API Design Principles

- RESTful design
- Versioned (v1, v2, etc.)
- JSON request/response
- Proper HTTP status codes
- Pagination for list endpoints
- Filtering and search support

### 20.2 Core Endpoints

```
Authentication:
POST   /api/v1/auth/login
POST   /api/v1/auth/register
POST   /api/v1/auth/refresh

Devices:
GET    /api/v1/devices
POST   /api/v1/devices
GET    /api/v1/devices/:id
PUT    /api/v1/devices/:id
DELETE /api/v1/devices/:id

Configurations:
POST   /api/v1/configurations/upload
GET    /api/v1/configurations/:id
DELETE /api/v1/configurations/:id

Audits:
POST   /api/v1/audits
GET    /api/v1/audits
GET    /api/v1/audits/:id
GET    /api/v1/audits/:id/status
POST   /api/v1/audits/:id/cancel

Findings:
GET    /api/v1/audits/:id/findings
GET    /api/v1/findings/:id
PUT    /api/v1/findings/:id/status

Training:
GET    /api/v1/training/mappings
POST   /api/v1/training/mappings
GET    /api/v1/training/mappings/:id
PUT    /api/v1/training/mappings/:id
GET    /api/v1/training/mappings/:id/versions

Reports:
GET    /api/v1/audits/:id/report
GET    /api/v1/reports

Compliance:
GET    /api/v1/compliance/frameworks
GET    /api/v1/compliance/frameworks/:id/controls
GET    /api/v1/compliance/controls/:id
```

### 20.3 API Response Format

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 100,
    "total_pages": 5
  },
  "links": {
    "self": "/api/v1/devices?page=1",
    "next": "/api/v1/devices?page=2",
    "prev": null
  }
}
```

### 20.4 Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid configuration format",
    "details": [
      {
        "field": "file",
        "message": "File must be .txt or .cfg format"
      }
    ]
  }
}
```

---

## 21. Testing Strategy

### 21.1 Test Levels

| Level | Focus | Tools | Coverage Target |
|-------|-------|-------|-----------------|
| **Unit** | Individual functions | pytest | 80%+ |
| **Integration** | Module interactions | pytest + testcontainers | 70%+ |
| **E2E** | Complete workflows | pytest + httpx | 60%+ |
| **Performance** | Load testing | locust | Baseline |
| **Security** | Vulnerability scanning | bandit, safety | No critical |

### 21.2 Test Data Strategy

**Real Configurations:**
- Cisco IOS sample configs (publicly available)
- Fortinet sample configs
- Juniper sample configs

**Synthetic Configurations:**
- Unknown vendor format (for adaptive learning demo)
- Malformed configs (error handling)
- Edge cases (empty, huge, binary)

**Test Scenarios:**
- Happy path (valid config → findings)
- Unknown vendor → AI → training
- Malformed config → graceful error
- Large batch processing
- Concurrent audit processing

### 21.3 CI/CD Pipeline

```yaml
pipeline:
  stages:
    - lint: ruff, mypy
    - test: pytest
    - security: bandit, safety
    - build: docker
    - deploy: staging
```

---

## 22. Dataset Strategy

### 22.1 Configuration Datasets

**Source:** Publicly available sample configurations

| Vendor | Source | Count |
|--------|--------|-------|
| Cisco IOS | Cisco documentation, GitHub repos | 20-30 |
| Fortinet | Fortinet documentation, forums | 15-20 |
| Juniper | Juniper documentation, GitHub | 15-20 |
| Unknown Synthetic | Manually created | 5-10 |

### 22.2 Compliance Rule Datasets

**Source:** CIS Benchmark documentation

**MVP Controls:** 30-50 high-value controls

**Categories:**
- Management access (5-8 controls)
- SSH/Telnet (3-5 controls)
- HTTP/HTTPS (2-3 controls)
- Authentication (5-8 controls)
- AAA (3-5 controls)
- Logging (3-5 controls)
- NTP (2-3 controls)
- Access control (3-5 controls)
- SNMP (2-3 controls)

### 22.3 Knowledge Base Datasets

**Initial Mappings:**
- 50-100 vendor-specific → semantic mappings
- Pre-loaded for demo purposes
- Extensible through training interface

---

## 23. MVP Scope

### 23.1 MVP Features (Must Have)

| Feature | Description | Priority |
|---------|-------------|----------|
| **File Upload** | Upload config files | P0 |
| **Cisco Parser** | Parse Cisco IOS configs | P0 |
| **Fortinet Parser** | Parse Fortinet configs | P0 |
| **Juniper Parser** | Parse Juniper configs | P0 |
| **Vendor Detection** | Auto-detect vendor | P0 |
| **Normalization** | Map to universal model | P0 |
| **Compliance Rules** | 30-50 CIS/NIST controls | P0 |
| **Findings** | Generate findings with evidence | P0 |
| **Remediation** | Generate fix instructions | P0 |
| **PDF Report** | Downloadable report | P0 |
| **Training Interface** | Teach unknown syntax | P0 |
| **Dashboard** | Overview metrics | P1 |
| **Audit History** | View past audits | P1 |
| **User Auth** | Basic login/register | P1 |

### 23.2 MVP Deferred (Nice to Have)

| Feature | Description | Defer Reason |
|---------|-------------|--------------|
| Real-time device integration | SSH/API to devices | Complexity |
| DISA STIG support | Additional framework | Time |
| ISO 27001 support | Additional framework | Time |
| Advanced analytics | Trends, forecasting | Time |
| Multi-user collaboration | Team features | Time |
| API key management | External integrations | Time |
| Webhook notifications | Event notifications | Time |

### 23.3 MVP Exclusions (Not in Scope)

| Feature | Reason |
|---------|--------|
| Device configuration (write-back) | Security risk, out of scope |
| Real-time monitoring | Different problem domain |
| Network topology discovery | Not compliance-focused |
| Vulnerability scanning | Different domain |
| SIEM integration | Complexity |
| Mobile app | Time |
| Multi-language support | Time |

---

## 24. Future Scope

### 24.1 Post-MVP Enhancements

1. **Additional Vendors:** Palo Alto, Arista, Check Point, SonicWall, MikroTik
2. **Additional Frameworks:** DISA STIG, ISO 27001, PCI-DSS, HIPAA
3. **Real-time Integration:** SSH/API device connection
4. **Scheduled Audits:** Automated periodic compliance checks
5. **Advanced AI:** Fine-tuned model on network configs
6. **Collaboration:** Multi-user, roles, approval workflows
7. **Integrations:** SIEM, ticketing systems, CMDB
8. **Custom Rules:** User-defined compliance rules
9. **REST API:** Public API for external integrations
10. **Plugin System:** Vendor-specific parser plugins

### 24.2 Scalability Considerations

- Horizontal scaling with worker nodes
- Database sharding for large audit volumes
- CDN for static assets
- Queue-based audit processing
- Caching for frequent queries

---

## 25. Explicit Non-Goals

### 25.1 What We're NOT Building

1. **Real-time Network Monitoring** - We analyze configurations, not live traffic
2. **Device Configuration Management** - We don't push configs to devices
3. **Vulnerability Scanner** - We check compliance, not vulnerabilities
4. **Network Topology Tool** - We don't discover network structure
5. **SIEM Solution** - We don't aggregate security logs
6. **Full SIEM Integration** - Not in MVP scope
7. **Mobile Application** - Web-only for MVP
8. **Multi-language UI** - English only for MVP
9. **Enterprise Deployment** - Demo/prototype only
10. **100% Vendor Support** - We support 3 vendors in MVP

### 25.2 What We're NOT Claiming

1. **"We replace Tufin/Batfish"** - We complement existing tools
2. **"We support all vendors"** - We support Cisco, Fortinet, Juniper in MVP
3. **"AI makes compliance decisions"** - AI assists, rules decide
4. **"100% accuracy"** - We have confidence scores and REVIEW results
5. **"Production-ready"** - This is a prototype/demo

---

## 26. SIH Demo Strategy

### 26.1 Demo Flow (10 minutes)

**Minute 0-2: Problem Introduction**
- Show heterogeneous network challenge
- Show manual auditing pain points

**Minute 2-4: Live Demo - Normal Audit**
- Upload Cisco IOS config
- Show vendor detection
- Show parsed configuration
- Show compliance evaluation
- Show findings with evidence
- Download PDF report

**Minute 4-6: Live Demo - Multi-Vendor**
- Upload Fortinet + Juniper configs
- Show same compliance framework across vendors
- Show unified dashboard view

**Minute 6-8: Live Demo - Adaptive Learning**
- Upload synthetic unknown vendor config
- Show AI hypothesis generation
- Show admin training interface
- Confirm mapping
- Show re-analysis with improved results

**Minute 8-9: Architecture Overview**
- Show architecture diagram
- Highlight evidence-first design
- Explain deterministic compliance

**Minute 9-10: Q&A Preparation**
- Be ready for technical questions
- Have backup slides ready

### 26.2 Demo Preparation Checklist

- [ ] Prepare 3 vendor sample configs
- [ ] Prepare synthetic unknown config
- [ ] Pre-create demo user account
- [ ] Test complete flow end-to-end
- [ ] Prepare backup slides
- [ ] Practice timing
- [ ] Prepare for technical questions

### 26.3 Technical Questions Preparation

Be ready to answer:
1. "How do you handle vendor-specific syntax?" → Universal Security Model
2. "How do you ensure compliance decisions are auditable?" → Evidence chain
3. "What happens when AI is wrong?" → Human-in-the-loop, REVIEW results
4. "How do you add new vendors?" → Parser plugin architecture
5. "How do you ensure scalability?" → Async processing, modular design

---

## 27. Known Risks

### 27.1 Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| AI hallucination | Wrong interpretations | Confidence thresholds, human review |
| Parser complexity | Time overrun | Focus on core features, defer edge cases |
| Configuration variety | Incomplete coverage | Graceful degradation, REVIEW results |
| Performance issues | Slow audits | Async processing, optimization |
| Security vulnerabilities | Data exposure | Security review, encryption |

### 27.2 Schedule Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Scope creep | Delays | Strict MVP scope, defer nice-to-haves |
| Integration issues | Delays | Early integration testing |
| Demo failures | Bad impression | Thorough testing, backup plan |
| Team bandwidth | Delays | Clear priorities, parallel work |

### 27.3 Demo Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| AI response delay | Slow demo | Pre-cache AI responses |
| Network issues | Demo failure | Offline backup |
| Data issues | Wrong results | Pre-validated demo data |

---

## 28. Technical Assumptions

### 28.1 Environment Assumptions

1. **Python 3.11+** is available
2. **Node.js 18+** is available
3. **PostgreSQL 15+** is available
4. **Redis 7+** is available
5. **Docker** is available for deployment
6. **Internet access** for AI API calls

### 28.2 Data Assumptions

1. Configuration files are **text-based** (not binary)
2. Configurations are **read-only** (we don't modify devices)
3. Users have **permission** to share configurations
4. Configurations are **not classified** (demo data only)

### 28.3 AI Assumptions

1. **OpenAI API** is available for semantic analysis
2. **API costs** are within budget
3. **Rate limits** are sufficient for demo
4. **AI responses** are not guaranteed to be accurate

### 28.4 User Assumptions

1. Users have **basic network security knowledge**
2. Users can **validate AI interpretations**
3. Users understand **compliance frameworks**
4. Users can **apply remediation** to devices

---

## 29. Open Questions

### 29.1 Architecture Decisions

| Question | Options | Recommendation |
|----------|---------|----------------|
| AI model choice | GPT-4, Claude, Local | GPT-4 for MVP |
| Database ORM | SQLAlchemy, Tortoise | SQLAlchemy |
| Task queue | Celery, Dramatiq | Celery |
| PDF library | ReportLab, WeasyPrint | ReportLab |

### 29.2 Feature Decisions

| Question | Options | Recommendation |
|----------|---------|----------------|
| Authentication | JWT, Session | JWT |
| File storage | Local, S3 | Local for MVP |
| Real-time updates | WebSocket, Polling | Polling for MVP |
| Caching strategy | Redis, In-memory | Redis |

### 29.3 Data Decisions

| Question | Options | Recommendation |
|----------|---------|----------------|
| Credential detection | Mask, Warn, Both | Both |
| Configuration versioning | Full, Hash-based | Hash-based |
| Audit retention | Indefinite, 90 days | Configurable |

---

## 30. Development Roadmap

### 30.1 Phase 1: Foundation (Week 1-2)

**Goal:** Project structure, documentation, core data models

**Deliverables:**
- [ ] Project repository structure
- [ ] Documentation suite
- [ ] Database schema
- [ ] API contracts
- [ ] Core data models
- [ ] Development environment setup

### 30.2 Phase 2: Core Engine (Week 3-4)

**Goal:** Ingestion, detection, parsing for Cisco

**Deliverables:**
- [ ] Ingestion engine
- [ ] Vendor detection
- [ ] Cisco IOS parser
- [ ] Basic normalization
- [ ] Unit tests

### 30.3 Phase 3: Compliance Engine (Week 5-6)

**Goal:** Compliance evaluation, findings, remediation

**Deliverables:**
- [ ] Compliance rule engine
- [ ] CIS controls implementation
- [ ] Finding generation
- [ ] Risk calculation
- [ ] Remediation generation
- [ ] Unit tests

### 30.4 Phase 4: Frontend Foundation (Week 7-8)

**Goal:** Dashboard, upload, results display

**Deliverables:**
- [ ] Frontend project setup
- [ ] Component library
- [ ] Dashboard page
- [ ] Upload page
- [ ] Results page
- [ ] Mock data integration

### 30.5 Phase 5: AI Integration (Week 9-10)

**Goal:** Semantic analysis, adaptive learning

**Deliverables:**
- [ ] AI client integration
- [ ] Semantic analysis engine
- [ ] Training interface
- [ ] Knowledge base
- [ ] Adaptive learning flow

### 30.6 Phase 6: Multi-Vendor (Week 11-12)

**Goal:** Fortinet, Juniper parsers

**Deliverables:**
- [ ] Fortinet parser
- [ ] Juniper parser
- [ ] Vendor-specific normalization
- [ ] Vendor-specific remediation
- [ ] Integration tests

### 30.7 Phase 7: Reporting (Week 13-14)

**Goal:** PDF reports, audit history

**Deliverables:**
- [ ] PDF generation
- [ ] Report templates
- [ ] Audit history
- [ ] Report download

### 30.8 Phase 8: Polish (Week 15-16)

**Goal:** Testing, optimization, demo prep

**Deliverables:**
- [ ] End-to-end testing
- [ ] Performance optimization
- [ ] Security review
- [ ] Demo preparation
- [ ] Documentation finalization

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| **Configuration** | The settings of a network device |
| **Compliance** | Adherence to security standards |
| **Finding** | A detected compliance issue |
| **Remediation** | Instructions to fix a finding |
| **Evidence Chain** | Complete trace from raw config to finding |
| **Universal Security Model** | Normalized representation of security concepts |
| **Knowledge Base** | Store of learned vendor-specific mappings |
| **Adaptive Learning** | System learning from administrator feedback |

---

## Appendix B: References

1. CIS Benchmarks - https://www.cisecurity.org/cis-benchmarks
2. NIST SP 800-53 - https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
3. DISA STIGs - https://public.cyber.mil/stigs/
4. ISO/IEC 27001 - https://www.iso.org/isoiec-27001-information-security.html

---

**END OF PROJECT MASTER SPECIFICATION**
