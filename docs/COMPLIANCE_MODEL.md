# COMPLIANCE MODEL DOCUMENT

## AI-Driven Multi-Vendor Network Security Compliance Auditor

**Version:** 1.0
**Last Updated:** 2026-08-25
**Status:** Design Phase

---

## Table of Contents

1. [Compliance Model Overview](#1-compliance-model-overview)
2. [Framework Structure](#2-framework-structure)
3. [Control Definition](#3-control-definition)
4. [Evaluation Logic](#4-evaluation-logic)
5. [Evidence Chain](#5-evidence-chain)
6. [Result Classification](#6-result-classification)
7. [Severity Model](#7-severity-model)
8. [Risk Model](#8-risk-model)
9. [CIS Controls](#9-cis-controls)
10. [NIST Controls](#10-nist-controls)
11. [Remediation Model](#11-remediation-model)
12. [Compliance Score](#12-compliance-score)

---

## 1. Compliance Model Overview

### 1.1 Design Principles

| Principle | Description |
|-----------|-------------|
| **Deterministic** | Compliance decisions are rule-based, not AI-based |
| **Auditable** | Every finding has a complete evidence chain |
| **Framework-Agnostic** | Core engine works with any framework |
| **Vendor-Aware** | Remediation is vendor-specific |
| **Extensible** | New controls can be added without core changes |

### 1.2 Model Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     COMPLIANCE MODEL ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │  Framework  │  │   Control   │  │    Rule     │                     │
│  │  (CIS/NIST) │  │  (1.1, 1.2) │  │  (check)    │                     │
│  └─────────────┘  └─────────────┘  └─────────────┘                     │
│         │                │                │                              │
│         └────────────────┼────────────────┘                              │
│                          ↓                                               │
│                 ┌─────────────┐                                          │
│                 │  Evaluation │                                          │
│                 │   Engine    │                                          │
│                 └─────────────┘                                          │
│                          │                                               │
│              ┌───────────┼───────────┐                                   │
│              ↓           ↓           ↓                                   │
│         ┌─────────┐ ┌─────────┐ ┌─────────┐                            │
│         │  PASS   │ │  FAIL   │ │ REVIEW  │                            │
│         └─────────┘ └─────────┘ └─────────┘                            │
│              │           │           │                                   │
│              └───────────┼───────────┘                                   │
│                          ↓                                               │
│                 ┌─────────────┐                                          │
│                 │   Finding   │                                          │
│                 │  + Evidence │                                          │
│                 └─────────────┘                                          │
│                          │                                               │
│                          ↓                                               │
│                 ┌─────────────┐                                          │
│                 │ Remediation │                                          │
│                 └─────────────┘                                          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Framework Structure

### 2.1 Framework Hierarchy

```
Framework
├── Version
│   ├── Category
│   │   ├── Control
│   │   │   ├── Rule
│   │   │   ├── Evidence Template
│   │   │   └── Remediation Template
│   │   └── Control
│   └── Category
└── Version
```

### 2.2 Framework Definition

```python
class Framework(BaseModel):
    """Compliance framework definition"""
    id: str  # "CIS", "NIST"
    name: str  # "CIS Benchmarks"
    description: str
    versions: List[FrameworkVersion]
    categories: List[Category]

class FrameworkVersion(BaseModel):
    """Framework version"""
    version: str  # "2024.1"
    release_date: date
    controls: List[Control]
    is_current: bool

class Category(BaseModel):
    """Control category"""
    id: str  # "management", "ssh", "authentication"
    name: str  # "Management Access"
    description: str
    controls: List[Control]
```

### 2.3 Framework Examples

```yaml
# CIS Framework Example
framework:
  id: "CIS"
  name: "CIS Benchmarks"
  description: "Center for Internet Security Benchmarks"
  versions:
    - version: "2024.1"
      release_date: "2024-01-15"
      is_current: true
  categories:
    - id: "management"
      name: "Management Access"
      description: "Secure device management configuration"
    - id: "ssh"
      name: "SSH Configuration"
      description: "Secure Shell configuration"
    - id: "authentication"
      name: "Authentication"
      description: "Authentication and password policies"
    - id: "logging"
      name: "Logging"
      description: "Logging and monitoring"
    - id: "access_control"
      name: "Access Control"
      description: "Access control lists and permissions"
```

---

## 3. Control Definition

### 3.1 Control Structure

```python
class Control(BaseModel):
    """Compliance control definition"""
    id: str  # "CIS-Cisco-IOS-1.1"
    framework_id: str  # "CIS"
    framework_version: str  # "2024.1"
    category_id: str  # "management"
    title: str  # "Disable HTTP Server"
    description: str
    severity: Severity
    vendor: Optional[str]  # "cisco", null for vendor-agnostic
    platform: Optional[str]  # "ios", null for platform-agnostic
    
    # Evaluation rule
    rule: ControlRule
    
    # Templates
    evidence_template: EvidenceTemplate
    remediation_template: RemediationTemplate
    
    # References
    references: List[str]
    
    # Metadata
    enabled: bool = True
    created_at: datetime
    updated_at: datetime

class ControlRule(BaseModel):
    """Rule for evaluating control"""
    type: str  # "configuration_check", "absence_check", "value_check"
    target: RuleTarget
    expected: ExpectedValue
    
class RuleTarget(BaseModel):
    """Target for rule evaluation"""
    model_path: str  # "management.http.enabled"
    vendor: Optional[str]
    platform: Optional[str]

class ExpectedValue(BaseModel):
    """Expected value for compliance"""
    value: Any
    operator: str  # "equals", "not_equals", "greater_than", "less_than", "contains", "in"
    description: str  # Human-readable description
```

### 3.2 Control Example

```yaml
# CIS-Cisco-IOS-1.1 Control Example
control:
  id: "CIS-Cisco-IOS-1.1"
  framework_id: "CIS"
  framework_version: "2024.1"
  category_id: "management"
  title: "Disable HTTP Server"
  description: |
    The HTTP server feature allows web-based management of the device
    using HTTP. HTTP transmits data in clear text, which can expose
    sensitive information including credentials. HTTPS should be used
    instead for secure management.
  severity: HIGH
  vendor: "cisco"
  platform: "ios"
  
  rule:
    type: "configuration_check"
    target:
      model_path: "management.http.enabled"
      vendor: "cisco"
      platform: "ios"
    expected:
      value: false
      operator: "equals"
      description: "HTTP server should be disabled"
  
  evidence_template:
    raw_config: "ip http server"
    parsed_value: "http_server_enabled = true"
    normalized_value: "management.http.enabled = true"
    security_control: "CIS-Cisco-IOS-1.1"
    expected_value: "false"
    actual_value: "true"
    result: "FAIL"
    reasoning: "HTTP server is enabled, violating CIS benchmark requirement"
  
  remediation_template:
    finding_title: "HTTP Server Enabled"
    risk_description: "Enabling HTTP server exposes management interface to unencrypted traffic"
    why_it_matters: "Unencrypted HTTP traffic can be intercepted, allowing credentials to be captured"
    vendor: "cisco"
    platform: "ios"
    recommended_config: "no ip http server"
    verification_steps:
      - "show running-config | include http"
    rollback_steps:
      - "ip http server"
    references:
      - "https://www.cisecurity.org/benchmark/cisco"
  
  references:
    - "https://www.cisecurity.org/benchmark/cisco"
```

---

## 4. Evaluation Logic

### 4.1 Evaluation Process

```python
class ComplianceEvaluator:
    """Deterministic compliance evaluation engine"""
    
    async def evaluate_control(
        self,
        control: Control,
        normalized_config: NormalizedConfiguration,
        raw_config: str,
        parsed_config: ParsedConfiguration
    ) -> ComplianceResult:
        """Evaluate a single control against normalized configuration"""
        
        # 1. Extract actual value from normalized config
        actual_value = self._extract_value(
            normalized_config,
            control.rule.target.model_path
        )
        
        # 2. Get confidence from normalization
        confidence = self._get_confidence(
            normalized_config,
            control.rule.target.model_path
        )
        
        # 3. Apply evaluation operator
        result = self._evaluate_operator(
            actual_value,
            control.rule.expected.value,
            control.rule.expected.operator
        )
        
        # 4. Generate evidence chain
        evidence = self._generate_evidence(
            raw_config=raw_config,
            parsed_config=parsed_config,
            normalized_config=normalized_config,
            control=control,
            actual_value=actual_value,
            result=result
        )
        
        # 5. Determine final result with confidence
        final_result = self._determine_result(result, confidence)
        
        # 6. Generate remediation if needed
        remediation = None
        if final_result == ComplianceResultType.FAIL:
            remediation = self._generate_remediation(
                control=control,
                actual_value=actual_value,
                evidence=evidence
            )
        
        return ComplianceResult(
            control_id=control.id,
            control_name=control.title,
            result=final_result,
            confidence=confidence,
            severity=control.severity,
            evidence=evidence,
            remediation=remediation
        )
    
    def _evaluate_operator(
        self,
        actual: Any,
        expected: Any,
        operator: str
    ) -> bool:
        """Apply evaluation operator"""
        if operator == "equals":
            return actual == expected
        elif operator == "not_equals":
            return actual != expected
        elif operator == "greater_than":
            return actual > expected
        elif operator == "less_than":
            return actual < expected
        elif operator == "contains":
            return expected in actual
        elif operator == "in":
            return actual in expected
        else:
            raise ValueError(f"Unknown operator: {operator}")
    
    def _determine_result(
        self,
        result: bool,
        confidence: float
    ) -> ComplianceResultType:
        """Determine final result with confidence threshold"""
        if confidence < 0.7:
            # Low confidence - require review
            return ComplianceResultType.REVIEW
        elif result:
            return ComplianceResultType.PASS
        else:
            return ComplianceResultType.FAIL
```

### 4.2 Evaluation Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match | `actual == expected` |
| `not_equals` | Not equal | `actual != expected` |
| `greater_than` | Greater than | `actual > expected` |
| `less_than` | Less than | `actual < expected` |
| `contains` | Contains value | `expected in actual` |
| `in` | Value in list | `actual in expected` |
| `regex_match` | Regex match | `re.match(expected, actual)` |
| `is_true` | Boolean true | `actual is True` |
| `is_false` | Boolean false | `actual is False` |
| `is_set` | Value is set | `actual is not None` |
| `is_not_set` | Value not set | `actual is None` |

### 4.3 Confidence Thresholds

| Confidence Level | Range | Action |
|-----------------|-------|--------|
| **High** | 0.9 - 1.0 | PASS/FAIL with high confidence |
| **Medium** | 0.7 - 0.9 | PASS/FAIL with medium confidence |
| **Low** | 0.5 - 0.7 | REVIEW recommended |
| **Very Low** | 0.0 - 0.5 | REVIEW required |

---

## 5. Evidence Chain

### 5.1 Evidence Structure

```python
class EvidenceChain(BaseModel):
    """Complete evidence chain for a finding"""
    
    # Raw configuration
    raw_config: str  # Original configuration line(s)
    raw_config_line_numbers: List[int]  # Line numbers in original
    
    # Parsed value
    parsed_value: str  # Extracted value after parsing
    parsed_path: List[str]  # Path in parse tree
    
    # Normalized value
    normalized_value: str  # Value in universal security model
    universal_model_path: str  # Path in universal model
    normalization_confidence: float  # Confidence in normalization
    
    # Security control
    security_control: str  # Control ID (e.g., "CIS-Cisco-IOS-1.1")
    control_description: str  # Control description
    
    # Expected vs Actual
    expected_value: str  # What the control expects
    actual_value: str  # What was found
    operator: str  # Comparison operator used
    
    # Result
    result: str  # "PASS", "FAIL", "REVIEW"
    result_reasoning: str  # Human-readable explanation
    
    # Confidence
    overall_confidence: float  # Overall confidence in finding
    
    # Vendor context
    vendor: str
    platform: str
    vendor_specific_syntax: str  # Original vendor syntax
```

### 5.2 Evidence Generation

```python
class EvidenceGenerator:
    """Generate evidence chain for findings"""
    
    def generate(
        self,
        raw_config: str,
        parsed_config: ParsedConfiguration,
        normalized_config: NormalizedConfiguration,
        control: Control,
        actual_value: Any,
        result: bool
    ) -> EvidenceChain:
        """Generate complete evidence chain"""
        
        # Find the raw config line(s)
        raw_lines = self._find_raw_lines(
            raw_config,
            parsed_config,
            control.rule.target.model_path
        )
        
        # Get parsed value
        parsed_value = self._get_parsed_value(
            parsed_config,
            control.rule.target.model_path
        )
        
        # Get normalized value
        normalized_value = self._get_normalized_value(
            normalized_config,
            control.rule.target.model_path
        )
        
        # Generate reasoning
        reasoning = self._generate_reasoning(
            control=control,
            actual_value=actual_value,
            expected_value=control.rule.expected.value,
            result=result
        )
        
        return EvidenceChain(
            raw_config="\n".join(raw_lines),
            raw_config_line_numbers=self._get_line_numbers(raw_lines),
            parsed_value=str(parsed_value),
            parsed_path=self._get_parsed_path(parsed_config, control.rule.target.model_path),
            normalized_value=str(normalized_value),
            universal_model_path=control.rule.target.model_path,
            normalization_confidence=self._get_confidence(normalized_config, control.rule.target.model_path),
            security_control=control.id,
            control_description=control.description,
            expected_value=str(control.rule.expected.value),
            actual_value=str(actual_value),
            operator=control.rule.expected.operator,
            result="PASS" if result else "FAIL",
            result_reasoning=reasoning,
            overall_confidence=self._calculate_overall_confidence(normalized_config, control),
            vendor=parsed_config.vendor,
            platform=parsed_config.platform,
            vendor_specific_syntax=self._get_vendor_syntax(parsed_config, control.rule.target.model_path)
        )
    
    def _generate_reasoning(
        self,
        control: Control,
        actual_value: Any,
        expected_value: Any,
        result: bool
    ) -> str:
        """Generate human-readable reasoning"""
        if result:
            return f"Configuration complies with {control.id}. {control.title}"
        else:
            return (
                f"Configuration violates {control.id}. "
                f"{control.description}. "
                f"Expected: {expected_value}, Actual: {actual_value}"
            )
```

### 5.3 Evidence Traceability

Every finding must be traceable through:

```
Raw Configuration Line
    ↓
Parsed Configuration Node
    ↓
Normalized Security Value
    ↓
Security Control Reference
    ↓
Expected Value
    ↓
Actual Value
    ↓
Comparison Result
    ↓
Finding with Evidence
```

---

## 6. Result Classification

### 6.1 Result Types

| Result | Description | When to Use |
|--------|-------------|-------------|
| **PASS** | Control is satisfied | Actual value matches expected value with high confidence |
| **FAIL** | Control is violated | Actual value does not match expected value with high confidence |
| **REVIEW** | Requires human review | Low confidence, unknown syntax, or insufficient evidence |

### 6.2 Result Determination

```python
class ResultDeterminator:
    """Determine compliance result"""
    
    def determine(
        self,
        evaluation_result: bool,
        confidence: float,
        has_unknown: bool,
        ai_interpreted: bool
    ) -> ComplianceResultType:
        """Determine final compliance result"""
        
        # Rule 1: If confidence is too low, require review
        if confidence < 0.7:
            return ComplianceResultType.REVIEW
        
        # Rule 2: If unknown syntax was encountered, require review
        if has_unknown:
            return ComplianceResultType.REVIEW
        
        # Rule 3: If AI interpretation was required, add uncertainty
        if ai_interpreted and confidence < 0.85:
            return ComplianceResultType.REVIEW
        
        # Rule 4: Otherwise, use evaluation result
        if evaluation_result:
            return ComplianceResultType.PASS
        else:
            return ComplianceResultType.FAIL
```

### 6.3 REVIEW Handling

When a REVIEW result is generated:
1. Finding is created with REVIEW status
2. Administrator is notified
3. Administrator can:
   - Manually classify as PASS or FAIL
   - Provide additional context
   - Update knowledge base
4. Classification is recorded for audit trail

---

## 7. Severity Model

### 7.1 Severity Levels

| Severity | Description | CVSS Equivalent | Response Time |
|----------|-------------|-----------------|---------------|
| **CRITICAL** | Immediate risk, exploitable | 9.0 - 10.0 | Immediate |
| **HIGH** | Significant risk, should be addressed | 7.0 - 8.9 | 24 hours |
| **MEDIUM** | Moderate risk, should be planned | 4.0 - 6.9 | 7 days |
| **LOW** | Minimal risk, best practice | 0.1 - 3.9 | 30 days |

### 7.2 Severity Assignment

```python
class SeverityAssignor:
    """Assign severity to findings"""
    
    def assign(
        self,
        control: Control,
        context: FindingContext
    ) -> Severity:
        """Assign severity based on control and context"""
        
        # Base severity from control
        base_severity = control.severity
        
        # Adjust based on context
        adjusted_severity = self._adjust_severity(
            base_severity,
            context
        )
        
        return adjusted_severity
    
    def _adjust_severity(
        self,
        base: Severity,
        context: FindingContext
    ) -> Severity:
        """Adjust severity based on context"""
        
        # Factors that increase severity
        if context.is_internet_facing:
            base = self._increase_severity(base)
        
        if context.is_production_environment:
            base = self._increase_severity(base)
        
        if context.has_sensitive_data:
            base = self._increase_severity(base)
        
        # Factors that decrease severity
        if context.is_test_environment:
            base = self._decrease_severity(base)
        
        if context.has_mitigating_controls:
            base = self._decrease_severity(base)
        
        return base
```

### 7.3 Severity Factors

| Factor | Impact | Rationale |
|--------|--------|-----------|
| Internet-facing | +1 level | Higher exposure risk |
| Production environment | +1 level | Business impact |
| Sensitive data | +1 level | Data breach risk |
| Test environment | -1 level | Lower risk |
| Mitigating controls | -1 level | Reduced impact |

---

## 8. Risk Model

### 8.1 Risk Calculation

```python
class RiskCalculator:
    """Calculate risk scores for findings"""
    
    def calculate_risk_score(
        self,
        finding: Finding
    ) -> RiskScore:
        """Calculate overall risk score"""
        
        # Severity score (0-10)
        severity_score = self._severity_to_score(finding.severity)
        
        # Impact score (0-10)
        impact_score = self._calculate_impact(finding)
        
        # Confidence factor (0-1)
        confidence_factor = finding.confidence
        
        # Risk score = severity * impact * confidence
        risk_score = severity_score * impact_score * confidence_factor
        
        # Normalize to 0-100
        normalized_score = (risk_score / 100) * 100
        
        return RiskScore(
            score=normalized_score,
            severity=severity_score,
            impact=impact_score,
            confidence=confidence_factor,
            priority=self._calculate_priority(normalized_score)
        )
    
    def _severity_to_score(self, severity: Severity) -> float:
        """Convert severity to numeric score"""
        mapping = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5
        }
        return mapping[severity]
    
    def _calculate_impact(self, finding: Finding) -> float:
        """Calculate impact score"""
        impact = 5.0  # Base impact
        
        # Adjust based on finding characteristics
        if finding.affected_vendor in ["cisco", "paloalto"]:
            impact += 1.0  # Critical infrastructure vendors
        
        if "management" in finding.control_id.lower():
            impact += 1.0  # Management access findings
        
        if "authentication" in finding.control_id.lower():
            impact += 1.0  # Authentication findings
        
        return min(impact, 10.0)
    
    def _calculate_priority(self, risk_score: float) -> str:
        """Calculate priority from risk score"""
        if risk_score >= 80:
            return "P1"
        elif risk_score >= 60:
            return "P2"
        elif risk_score >= 40:
            return "P3"
        else:
            return "P4"
```

### 8.2 Risk Score Components

| Component | Range | Weight | Description |
|-----------|-------|--------|-------------|
| Severity | 0-10 | 1.0 | Control severity level |
| Impact | 0-10 | 1.0 | Business impact assessment |
| Confidence | 0-1 | 1.0 | Confidence in finding |
| **Risk Score** | **0-100** | - | **Combined risk score** |

### 8.3 Priority Levels

| Priority | Score Range | Response Time | Description |
|----------|-------------|---------------|-------------|
| **P1** | 80-100 | Immediate | Critical risk, immediate action |
| **P2** | 60-79 | 24 hours | High risk, action required |
| **P3** | 40-59 | 7 days | Medium risk, planned action |
| **P4** | 0-39 | 30 days | Low risk, best practice |

---

## 9. CIS Controls

### 9.1 MVP CIS Controls

**Target:** 30-50 high-value controls

**Categories:**

1. **Management Access** (5-8 controls)
   - Disable HTTP server
   - Enable HTTPS
   - Disable Telnet
   - Enable SSH
   - Configure SSH version
   - Configure SSH timeout

2. **Authentication** (5-8 controls)
   - Password minimum length
   - Password complexity
   - Password expiration
   - Account lockout
   - Enable AAA

3. **Logging** (3-5 controls)
   - Enable logging
   - Configure log level
   - Configure remote logging
   - Synchronize time (NTP)

4. **Access Control** (3-5 controls)
   - Configure ACLs
   - Restrict management access
   - Disable unnecessary services

5. **SNMP** (2-3 controls)
   - Disable SNMP v1/v2
   - Use SNMP v3
   - Change community strings

### 9.2 Control Example: Cisco IOS

```yaml
# CIS-Cisco-IOS-1.1: Disable HTTP Server
- id: "CIS-Cisco-IOS-1.1"
  title: "Disable HTTP Server"
  severity: HIGH
  rule:
    model_path: "management.http.enabled"
    expected: false
  
# CIS-Cisco-IOS-1.2: Enable HTTPS
- id: "CIS-Cisco-IOS-1.2"
  title: "Enable HTTPS Server"
  severity: HIGH
  rule:
    model_path: "management.https.enabled"
    expected: true
  
# CIS-Cisco-IOS-1.3: Disable Telnet
- id: "CIS-Cisco-IOS-1.3"
  title: "Disable Telnet"
  severity: HIGH
  rule:
    model_path: "management.telnet.enabled"
    expected: false
  
# CIS-Cisco-IOS-1.4: Enable SSH
- id: "CIS-Cisco-IOS-1.4"
  title: "Enable SSH"
  severity: HIGH
  rule:
    model_path: "management.ssh.enabled"
    expected: true
  
# CIS-Cisco-IOS-1.5: SSH Version 2
- id: "CIS-Cisco-IOS-1.5"
  title: "Use SSH Version 2"
  severity: HIGH
  rule:
    model_path: "management.ssh.version"
    expected: 2
    operator: "equals"
  
# CIS-Cisco-IOS-2.1: Password Minimum Length
- id: "CIS-Cisco-IOS-2.1"
  title: "Password Minimum Length"
  severity: MEDIUM
  rule:
    model_path: "authentication.password_policy.min_length"
    expected: 10
    operator: "greater_than_or_equal"
  
# CIS-Cisco-IOS-2.2: Password Complexity
- id: "CIS-Cisco-IOS-2.2"
  title: "Password Complexity"
  severity: MEDIUM
  rule:
    model_path: "authentication.password_policy.complexity"
    expected: true
  
# CIS-Cisco-IOS-3.1: Enable AAA
- id: "CIS-Cisco-IOS-3.1"
  title: "Enable AAA"
  severity: HIGH
  rule:
    model_path: "aaa.authentication_enabled"
    expected: true
```

---

## 10. NIST Controls

### 10.1 MVP NIST Controls

**Target:** 20-30 high-impact controls from NIST SP 800-53

**Categories:**

1. **Access Control (AC)**
   - AC-2: Account Management
   - AC-3: Access Enforcement
   - AC-6: Least Privilege
   - AC-7: Unsuccessful Login Attempts

2. **Audit and Accountability (AU)**
   - AU-2: Audit Events
   - AU-3: Content of Audit Records
   - AU-6: Audit Review, Analysis, and Reporting

3. **Configuration Management (CM)**
   - CM-2: Baseline Configuration
   - CM-3: Configuration Change Control
   - CM-6: Configuration Settings

4. **Identification and Authentication (IA)**
   - IA-2: Identification and Authentication
   - IA-5: Authenticator Management
   - IA-8: Identification and Authentication (Non-Organizational Users)

5. **System and Communications Protection (SC)**
   - SC-7: Boundary Protection
   - SC-8: Transmission Confidentiality and Integrity
   - SC-12: Cryptographic Key Management

### 10.2 Control Example: NIST

```yaml
# NIST SP 800-53 AC-17: Remote Access
- id: "NIST-AC-17"
  title: "Remote Access"
  severity: HIGH
  description: "Employ cryptographic mechanisms to protect the confidentiality and integrity of remote access sessions"
  rule:
    model_path: "management.ssh.enabled"
    expected: true
  
# NIST SP 800-53 SC-8: Transmission Confidentiality
- id: "NIST-SC-8"
  title: "Transmission Confidentiality and Integrity"
  severity: HIGH
  description: "Protect the confidentiality and integrity of transmitted information"
  rule:
    model_path: "management.ssh.version"
    expected: 2
    operator: "greater_than_or_equal"
  
# NIST SP 800-53 AU-3: Content of Audit Records
- id: "NIST-AU-3"
  title: "Content of Audit Records"
  severity: MEDIUM
  description: "Audit records contain information that establishes what type of event occurred"
  rule:
    model_path: "logging.enabled"
    expected: true
```

---

## 11. Remediation Model

### 11.1 Remediation Structure

```python
class Remediation(BaseModel):
    """Remediation instructions for a finding"""
    
    # Finding reference
    finding_id: str
    finding_title: str
    
    # Risk information
    risk_description: str
    why_it_matters: str
    
    # Vendor-specific remediation
    vendor: str
    platform: str
    recommended_config: str
    
    # Verification
    verification_steps: List[str]
    
    # Rollback
    rollback_steps: List[str]
    
    # References
    references: List[str]
    
    # Confidence
    confidence: float
    
    # Additional context
    prerequisites: List[str]
    side_effects: List[str]
    estimated_downtime: Optional[str]
```

### 11.2 Remediation Generation

```python
class RemediationGenerator:
    """Generate remediation instructions"""
    
    def generate(
        self,
        finding: Finding,
        control: Control,
        actual_value: Any
    ) -> Remediation:
        """Generate remediation for a finding"""
        
        # Get vendor-specific remediation
        vendor_remediation = self._get_vendor_remediation(
            vendor=finding.affected_vendor,
            platform=finding.affected_platform,
            control=control,
            actual_value=actual_value
        )
        
        # Generate verification steps
        verification_steps = self._generate_verification(
            vendor=finding.affected_vendor,
            platform=finding.affected_platform,
            control=control
        )
        
        # Generate rollback steps
        rollback_steps = self._generate_rollback(
            vendor=finding.affected_vendor,
            platform=finding.affected_platform,
            control=control
        )
        
        return Remediation(
            finding_id=finding.id,
            finding_title=finding.title,
            risk_description=control.description,
            why_it_matters=self._explain_why_it_matters(control),
            vendor=finding.affected_vendor,
            platform=finding.affected_platform,
            recommended_config=vendor_remediation,
            verification_steps=verification_steps,
            rollback_steps=rollback_steps,
            references=control.references,
            confidence=finding.confidence,
            prerequisites=self._get_prerequisites(control),
            side_effects=self._get_side_effects(control),
            estimated_downtime=self._estimate_downtime(control)
        )
    
    def _get_vendor_remediation(
        self,
        vendor: str,
        platform: str,
        control: Control,
        actual_value: Any
    ) -> str:
        """Get vendor-specific remediation command"""
        
        # Cisco IOS remediations
        if vendor == "cisco" and platform == "ios":
            return self._cisco_ios_remediation(control, actual_value)
        
        # Fortinet remediations
        elif vendor == "fortinet" and platform == "fortios":
            return self._fortinet_remediation(control, actual_value)
        
        # Juniper remediations
        elif vendor == "juniper" and platform == "junos":
            return self._juniper_remediation(control, actual_value)
        
        # Generic remediation
        else:
            return self._generic_remediation(control, actual_value)
```

### 11.3 Vendor-Specific Remediation

**Cisco IOS:**
```
# To disable HTTP server:
no ip http server

# To enable HTTPS:
ip http secure-server

# To disable Telnet:
line vty 0 15
 transport input ssh

# To enable SSH:
ip ssh version 2
```

**Fortinet FortiOS:**
```
# To disable HTTP server:
config system global
    set admin-protocol https
    unset admin-http
end

# To enable SSH:
config system ssh-server
    set status enable
end
```

**Juniper Junos:**
```
# To disable HTTP server:
delete system services web-management http

# To enable SSH:
set system services ssh
```

---

## 12. Compliance Score

### 12.1 Score Calculation

```python
class ComplianceScoreCalculator:
    """Calculate overall compliance score"""
    
    def calculate(
        self,
        results: List[ComplianceResult]
    ) -> ComplianceScore:
        """Calculate overall compliance score"""
        
        # Count results by type
        total = len(results)
        passed = sum(1 for r in results if r.result == ComplianceResultType.PASS)
        failed = sum(1 for r in results if r.result == ComplianceResultType.FAIL)
        review = sum(1 for r in results if r.result == ComplianceResultType.REVIEW)
        
        # Calculate score (PASS / (PASS + FAIL) * 100)
        # REVIEW results are not counted in score
        applicable = passed + failed
        if applicable > 0:
            score = (passed / applicable) * 100
        else:
            score = 100.0  # No applicable controls
        
        # Calculate weighted score (considering severity)
        weighted_score = self._calculate_weighted_score(results)
        
        return ComplianceScore(
            score=score,
            weighted_score=weighted_score,
            total_controls=total,
            passed=passed,
            failed=failed,
            review=review,
            grade=self._score_to_grade(score)
        )
    
    def _calculate_weighted_score(
        self,
        results: List[ComplianceResult]
    ) -> float:
        """Calculate severity-weighted score"""
        
        severity_weights = {
            Severity.CRITICAL: 4.0,
            Severity.HIGH: 3.0,
            Severity.MEDIUM: 2.0,
            Severity.LOW: 1.0
        }
        
        total_weight = 0
        passed_weight = 0
        
        for result in results:
            weight = severity_weights[result.severity]
            total_weight += weight
            
            if result.result == ComplianceResultType.PASS:
                passed_weight += weight
        
        if total_weight > 0:
            return (passed_weight / total_weight) * 100
        else:
            return 100.0
    
    def _score_to_grade(self, score: float) -> str:
        """Convert score to grade"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
```

### 12.2 Score Components

| Component | Weight | Description |
|-----------|--------|-------------|
| **Raw Score** | 1.0 | PASS / (PASS + FAIL) * 100 |
| **Weighted Score** | 1.0 | Severity-weighted score |
| **Grade** | - | A-F grade based on score |

### 12.3 Score Interpretation

| Score | Grade | Interpretation |
|-------|-------|----------------|
| 90-100 | A | Excellent compliance posture |
| 80-89 | B | Good compliance posture |
| 70-79 | C | Fair compliance posture |
| 60-69 | D | Poor compliance posture |
| 0-59 | F | Critical compliance gaps |

---

**END OF COMPLIANCE MODEL DOCUMENT**
