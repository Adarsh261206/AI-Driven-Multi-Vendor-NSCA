# API CONTRACTS DOCUMENT

## AI-Driven Multi-Vendor Network Security Compliance Auditor

**Version:** 1.0
**Last Updated:** 2026-08-25
**Status:** Design Phase

---

## Table of Contents

1. [API Overview](#1-api-overview)
2. [Authentication API](#2-authentication-api)
3. [Devices API](#3-devices-api)
4. [Configurations API](#4-configurations-api)
5. [Audits API](#5-audits-api)
6. [Findings API](#6-findings-api)
7. [Compliance API](#7-compliance-api)
8. [Training API](#8-training-api)
9. [Reports API](#9-reports-api)
10. [Error Handling](#10-error-handling)
11. [Rate Limiting](#11-rate-limiting)
12. [Versioning](#12-versioning)

---

## 1. API Overview

### 1.1 Base URL

```
Development: http://localhost:8000/api/v1
Production: https://api.compliance-auditor.example.com/api/v1
```

### 1.2 API Standards

| Standard | Implementation |
|----------|---------------|
| Protocol | HTTPS only |
| Format | JSON request/response |
| Encoding | UTF-8 |
| Authentication | JWT Bearer token |
| Versioning | URL path (`/api/v1/`) |
| Pagination | Query parameters (`page`, `per_page`) |
| Filtering | Query parameters |
| Sorting | Query parameters (`sort_by`, `sort_order`) |

### 1.3 Response Format

```json
{
  "success": true,
  "data": {},
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 100,
    "total_pages": 5
  }
}
```

### 1.4 Error Format

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input",
    "details": []
  }
}
```

---

## 2. Authentication API

### 2.1 Register User

```
POST /api/v1/auth/register
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "full_name": "John Doe"
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "full_name": "John Doe",
    "role": "auditor",
    "created_at": "2026-08-25T10:00:00Z"
  }
}
```

**Errors:**
- `400` - Validation error
- `409` - Email already exists

### 2.2 Login

```
POST /api/v1/auth/login
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...",
    "token_type": "bearer",
    "expires_in": 900
  }
}
```

**Errors:**
- `401` - Invalid credentials
- `400` - Validation error

### 2.3 Refresh Token

```
POST /api/v1/auth/refresh
```

**Request Body:**
```json
{
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4..."
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 900
  }
}
```

**Errors:**
- `401` - Invalid refresh token
- `401` - Refresh token expired

### 2.4 Get Current User

```
GET /api/v1/auth/me
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "full_name": "John Doe",
    "role": "auditor",
    "is_active": true,
    "created_at": "2026-08-25T10:00:00Z"
  }
}
```

---

## 3. Devices API

### 3.1 List Devices

```
GET /api/v1/devices
```

**Query Parameters:**
- `page` (int, default: 1)
- `per_page` (int, default: 20, max: 100)
- `vendor` (string, optional)
- `platform` (string, optional)
- `search` (string, optional - searches name, vendor, platform)

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Core Router 01",
      "vendor": "cisco",
      "platform": "ios",
      "firmware_version": "15.7",
      "ip_address": "192.168.1.1",
      "configuration_count": 3,
      "last_audit_date": "2026-08-20T15:30:00Z",
      "created_at": "2026-08-01T10:00:00Z"
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

### 3.2 Create Device

```
POST /api/v1/devices
```

**Request Body:**
```json
{
  "name": "Core Router 01",
  "vendor": "cisco",
  "platform": "ios",
  "firmware_version": "15.7",
  "ip_address": "192.168.1.1",
  "notes": "Main core router"
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Core Router 01",
    "vendor": "cisco",
    "platform": "ios",
    "firmware_version": "15.7",
    "ip_address": "192.168.1.1",
    "notes": "Main core router",
    "created_at": "2026-08-25T10:00:00Z"
  }
}
```

### 3.3 Get Device

```
GET /api/v1/devices/{device_id}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Core Router 01",
    "vendor": "cisco",
    "platform": "ios",
    "firmware_version": "15.7",
    "ip_address": "192.168.1.1",
    "notes": "Main core router",
    "configurations": [
      {
        "id": "660e8400-e29b-41d4-a716-446655440001",
        "filename": "running-config.txt",
        "uploaded_at": "2026-08-20T15:30:00Z"
      }
    ],
    "created_at": "2026-08-01T10:00:00Z",
    "updated_at": "2026-08-25T10:00:00Z"
  }
}
```

### 3.4 Update Device

```
PUT /api/v1/devices/{device_id}
```

**Request Body:**
```json
{
  "name": "Core Router 01 - Updated",
  "notes": "Updated notes"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Core Router 01 - Updated",
    "vendor": "cisco",
    "platform": "ios",
    "firmware_version": "15.7",
    "ip_address": "192.168.1.1",
    "notes": "Updated notes",
    "updated_at": "2026-08-25T10:00:00Z"
  }
}
```

### 3.5 Delete Device

```
DELETE /api/v1/devices/{device_id}
```

**Response (204):** No content

---

## 4. Configurations API

### 4.1 Upload Configuration

```
POST /api/v1/configurations/upload
```

**Request Body (multipart/form-data):**
```
file: <configuration_file>
device_id: <optional_device_id>
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "filename": "running-config.txt",
    "content_type": "text/plain",
    "size_bytes": 12345,
    "line_count": 256,
    "uploaded_at": "2026-08-25T10:00:00Z"
  }
}
```

### 4.2 Get Configuration

```
GET /api/v1/configurations/{config_id}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "filename": "running-config.txt",
    "content_type": "text/plain",
    "size_bytes": 12345,
    "line_count": 256,
    "uploaded_at": "2026-08-25T10:00:00Z"
  }
}
```

### 4.3 Get Configuration Content

```
GET /api/v1/configurations/{config_id}/content
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "content": "hostname CoreRouter01\n!\nip ssh version 2\n..."
  }
}
```

### 4.4 Delete Configuration

```
DELETE /api/v1/configurations/{config_id}
```

**Response (204):** No content

---

## 5. Audits API

### 5.1 List Audits

```
GET /api/v1/audits
```

**Query Parameters:**
- `page` (int, default: 1)
- `per_page` (int, default: 20, max: 100)
- `status` (string, optional - pending, processing, completed, failed)
- `framework` (string, optional)
- `sort_by` (string, optional - created_at, completed_at, overall_score)
- `sort_order` (string, optional - asc, desc)

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "770e8400-e29b-41d4-a716-446655440002",
      "name": "August Compliance Audit",
      "description": "Monthly compliance check",
      "status": "completed",
      "overall_score": 75.5,
      "configuration_count": 5,
      "findings_count": 12,
      "critical_findings": 1,
      "high_findings": 3,
      "medium_findings": 5,
      "low_findings": 3,
      "created_at": "2026-08-25T10:00:00Z",
      "completed_at": "2026-08-25T10:05:00Z"
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

### 5.2 Create Audit

```
POST /api/v1/audits
```

**Request Body:**
```json
{
  "name": "August Compliance Audit",
  "description": "Monthly compliance check",
  "configuration_ids": [
    "660e8400-e29b-41d4-a716-446655440001",
    "660e8400-e29b-41d4-a716-446655440002"
  ],
  "framework": "CIS",
  "framework_version": "2024.1"
}
```

**Response (202):**
```json
{
  "success": true,
  "data": {
    "id": "770e8400-e29b-41d4-a716-446655440002",
    "name": "August Compliance Audit",
    "description": "Monthly compliance check",
    "status": "pending",
    "configuration_count": 2,
    "created_at": "2026-08-25T10:00:00Z"
  }
}
```

### 5.3 Get Audit

```
GET /api/v1/audits/{audit_id}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "770e8400-e29b-41d4-a716-446655440002",
    "name": "August Compliance Audit",
    "description": "Monthly compliance check",
    "status": "completed",
    "overall_score": 75.5,
    "configuration_count": 5,
    "findings_count": 12,
    "critical_findings": 1,
    "high_findings": 3,
    "medium_findings": 5,
    "low_findings": 3,
    "framework": "CIS",
    "framework_version": "2024.1",
    "created_at": "2026-08-25T10:00:00Z",
    "started_at": "2026-08-25T10:00:00Z",
    "completed_at": "2026-08-25T10:05:00Z"
  }
}
```

### 5.4 Get Audit Status

```
GET /api/v1/audits/{audit_id}/status
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "status": "processing",
    "progress": 65,
    "current_step": "compliance_evaluation",
    "steps_completed": [
      "ingestion",
      "detection",
      "parsing",
      "semantic_analysis",
      "normalization"
    ],
    "estimated_completion": "2026-08-25T10:05:00Z"
  }
}
```

### 5.5 Cancel Audit

```
POST /api/v1/audits/{audit_id}/cancel
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "770e8400-e29b-41d4-a716-446655440002",
    "status": "cancelled",
    "cancelled_at": "2026-08-25T10:02:00Z"
  }
}
```

---

## 6. Findings API

### 6.1 List Audit Findings

```
GET /api/v1/audits/{audit_id}/findings
```

**Query Parameters:**
- `page` (int, default: 1)
- `per_page` (int, default: 20, max: 100)
- `severity` (string, optional - CRITICAL, HIGH, MEDIUM, LOW)
- `status` (string, optional - open, in_progress, resolved, accepted)
- `sort_by` (string, optional - severity, confidence, created_at)
- `sort_order` (string, optional - asc, desc)

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "880e8400-e29b-41d4-a716-446655440003",
      "title": "HTTP Server Enabled",
      "description": "HTTP server is enabled, which may expose management interface to unencrypted traffic",
      "severity": "HIGH",
      "confidence": 0.95,
      "status": "open",
      "affected_device": "Core Router 01",
      "affected_vendor": "cisco",
      "affected_platform": "ios",
      "control_id": "CIS-Cisco-IOS-1.1",
      "created_at": "2026-08-25T10:05:00Z"
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 12,
    "total_pages": 1
  }
}
```

### 6.2 Get Finding

```
GET /api/v1/findings/{finding_id}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "880e8400-e29b-41d4-a716-446655440003",
    "title": "HTTP Server Enabled",
    "description": "HTTP server is enabled, which may expose management interface to unencrypted traffic",
    "severity": "HIGH",
    "confidence": 0.95,
    "status": "open",
    "evidence": {
      "raw_config": "ip http server",
      "parsed_value": "http_server_enabled = true",
      "normalized_value": "management.http.enabled = true",
      "security_control": "CIS-Cisco-IOS-1.1",
      "expected_value": "false",
      "actual_value": "true",
      "result": "FAIL",
      "reasoning": "HTTP server is enabled, violating CIS benchmark requirement"
    },
    "remediation": {
      "finding_id": "880e8400-e29b-41d4-a716-446655440003",
      "finding_title": "HTTP Server Enabled",
      "risk_description": "Enabling HTTP server exposes management interface to unencrypted traffic",
      "why_it_matters": "Unencrypted HTTP traffic can be intercepted, allowing credentials to be captured",
      "vendor": "cisco",
      "platform": "ios",
      "recommended_config": "no ip http server",
      "verification_steps": [
        "show running-config | include http"
      ],
      "rollback_steps": [
        "ip http server"
      ],
      "references": [
        "https://www.cisecurity.org/benchmark/cisco"
      ],
      "confidence": 0.95
    },
    "affected_device": "Core Router 01",
    "affected_vendor": "cisco",
    "affected_platform": "ios",
    "control_id": "CIS-Cisco-IOS-1.1",
    "created_at": "2026-08-25T10:05:00Z",
    "updated_at": "2026-08-25T10:05:00Z"
  }
}
```

### 6.3 Update Finding Status

```
PUT /api/v1/findings/{finding_id}/status
```

**Request Body:**
```json
{
  "status": "in_progress",
  "notes": "Started remediation"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "880e8400-e29b-41d4-a716-446655440003",
    "status": "in_progress",
    "updated_at": "2026-08-25T10:10:00Z"
  }
}
```

---

## 7. Compliance API

### 7.1 List Frameworks

```
GET /api/v1/compliance/frameworks
```

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "CIS",
      "name": "CIS Benchmarks",
      "description": "Center for Internet Security Benchmarks",
      "versions": ["2024.1", "2023.1"],
      "control_count": 45,
      "categories": [
        "management",
        "ssh",
        "authentication",
        "logging",
        "access_control"
      ]
    },
    {
      "id": "NIST",
      "name": "NIST SP 800-53",
      "description": "NIST Special Publication 800-53",
      "versions": ["5.0", "4.0"],
      "control_count": 30,
      "categories": [
        "access_control",
        "audit",
        "configuration_management"
      ]
    }
  ]
}
```

### 7.2 List Framework Controls

```
GET /api/v1/compliance/frameworks/{framework_id}/controls
```

**Query Parameters:**
- `category` (string, optional)
- `severity` (string, optional)

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "CIS-Cisco-IOS-1.1",
      "framework": "CIS",
      "framework_version": "2024.1",
      "title": "Disable HTTP Server",
      "description": "The HTTP server feature allows web-based management...",
      "category": "management",
      "severity": "HIGH",
      "vendor": "cisco",
      "platform": "ios"
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 45,
    "total_pages": 3
  }
}
```

### 7.3 Get Control Details

```
GET /api/v1/compliance/controls/{control_id}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "CIS-Cisco-IOS-1.1",
    "framework": "CIS",
    "framework_version": "2024.1",
    "title": "Disable HTTP Server",
    "description": "The HTTP server feature allows web-based management of the device using HTTP. HTTP transmits data in clear text, which can expose sensitive information including credentials.",
    "category": "management",
    "severity": "HIGH",
    "vendor": "cisco",
    "platform": "ios",
    "rule": {
      "type": "configuration_check",
      "target": {
        "model_path": "management.http.enabled",
        "vendor": "cisco",
        "platform": "ios"
      },
      "expected": {
        "value": false,
        "operator": "equals"
      }
    },
    "remediation_template": {
      "command": "no ip http server",
      "verification": "show running-config | include http",
      "rollback": "ip http server"
    },
    "references": [
      "https://www.cisecurity.org/benchmark/cisco"
    ]
  }
}
```

---

## 8. Training API

### 8.1 List Training Mappings

```
GET /api/v1/training/mappings
```

**Query Parameters:**
- `page` (int, default: 1)
- `per_page` (int, default: 20, max: 100)
- `vendor` (string, optional)
- `platform` (string, optional)
- `confirmed` (boolean, optional)

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "990e8400-e29b-41d4-a716-446655440004",
      "vendor": "custom",
      "platform": "unknown",
      "raw_syntax": "set system services ssh",
      "semantic_meaning": "Enable SSH service on the device",
      "universal_model_path": "management.ssh.enabled",
      "confidence": 0.90,
      "admin_confirmed": true,
      "admin_notes": "This enables SSH service",
      "version": 1,
      "created_at": "2026-08-25T10:00:00Z"
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

### 8.2 Create Training Mapping

```
POST /api/v1/training/mappings
```

**Request Body:**
```json
{
  "vendor": "custom",
  "platform": "unknown",
  "raw_syntax": "set system services ssh",
  "semantic_meaning": "Enable SSH service on the device",
  "universal_model_path": "management.ssh.enabled",
  "admin_notes": "This enables SSH service"
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "id": "990e8400-e29b-41d4-a716-446655440004",
    "vendor": "custom",
    "platform": "unknown",
    "raw_syntax": "set system services ssh",
    "semantic_meaning": "Enable SSH service on the device",
    "universal_model_path": "management.ssh.enabled",
    "confidence": 0.90,
    "admin_confirmed": true,
    "admin_notes": "This enables SSH service",
    "version": 1,
    "created_at": "2026-08-25T10:00:00Z"
  }
}
```

### 8.3 Get Training Mapping

```
GET /api/v1/training/mappings/{mapping_id}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "990e8400-e29b-41d4-a716-446655440004",
    "vendor": "custom",
    "platform": "unknown",
    "raw_syntax": "set system services ssh",
    "semantic_meaning": "Enable SSH service on the device",
    "universal_model_path": "management.ssh.enabled",
    "confidence": 0.90,
    "admin_confirmed": true,
    "admin_notes": "This enables SSH service",
    "version": 1,
    "created_at": "2026-08-25T10:00:00Z",
    "updated_at": "2026-08-25T10:00:00Z"
  }
}
```

### 8.4 Update Training Mapping

```
PUT /api/v1/training/mappings/{mapping_id}
```

**Request Body:**
```json
{
  "semantic_meaning": "Enable SSH service on the device (updated)",
  "universal_model_path": "management.ssh.enabled",
  "admin_notes": "Updated interpretation",
  "change_reason": "Corrected semantic meaning"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "990e8400-e29b-41d4-a716-446655440004",
    "version": 2,
    "semantic_meaning": "Enable SSH service on the device (updated)",
    "updated_at": "2026-08-25T10:10:00Z"
  }
}
```

### 8.5 Get Mapping Versions

```
GET /api/v1/training/mappings/{mapping_id}/versions
```

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "version": 2,
      "raw_syntax": "set system services ssh",
      "semantic_meaning": "Enable SSH service on the device (updated)",
      "universal_model_path": "management.ssh.enabled",
      "changed_by": "user@example.com",
      "changed_at": "2026-08-25T10:10:00Z",
      "change_reason": "Corrected semantic meaning"
    },
    {
      "version": 1,
      "raw_syntax": "set system services ssh",
      "semantic_meaning": "Enable SSH service on the device",
      "universal_model_path": "management.ssh.enabled",
      "changed_by": "user@example.com",
      "changed_at": "2026-08-25T10:00:00Z",
      "change_reason": null
    }
  ]
}
```

### 8.6 Get AI Hypothesis

```
POST /api/v1/training/hypothesis
```

**Request Body:**
```json
{
  "vendor": "custom",
  "platform": "unknown",
  "raw_syntax": "set system services ssh"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "raw_syntax": "set system services ssh",
    "suggested_meaning": "Enable SSH service on the device",
    "confidence": 0.85,
    "reasoning": "The 'set system services ssh' syntax is similar to Juniper-style configuration, suggesting SSH service enablement",
    "universal_model_path": "management.ssh.enabled",
    "alternative_interpretations": [
      {
        "meaning": "Configure SSH service parameters",
        "confidence": 0.10,
        "reasoning": "Could be configuring SSH settings rather than just enabling"
      }
    ],
    "security_relevance": "high",
    "explanation": "SSH is a secure remote management protocol. Enabling it is generally recommended for secure device management."
  }
}
```

---

## 9. Reports API

### 9.1 Get Audit Report

```
GET /api/v1/audits/{audit_id}/report
```

**Query Parameters:**
- `format` (string, default: pdf - pdf, json)

**Response (200):**
```json
{
  "success": true,
  "data": {
    "download_url": "https://api.compliance-auditor.example.com/reports/audit-770e8400.pdf",
    "expires_at": "2026-08-25T22:00:00Z",
    "format": "pdf",
    "size_bytes": 123456
  }
}
```

### 9.2 List Reports

```
GET /api/v1/reports
```

**Query Parameters:**
- `page` (int, default: 1)
- `per_page` (int, default: 20, max: 100)
- `framework` (string, optional)

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "report-001",
      "audit_id": "770e8400-e29b-41d4-a716-446655440002",
      "audit_name": "August Compliance Audit",
      "framework": "CIS",
      "overall_score": 75.5,
      "generated_at": "2026-08-25T10:05:00Z",
      "download_url": "https://api.compliance-auditor.example.com/reports/audit-770e8400.pdf"
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

---

## 10. Error Handling

### 10.1 Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Input validation failed |
| `AUTHENTICATION_ERROR` | 401 | Authentication required |
| `AUTHORIZATION_ERROR` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |
| `EXTERNAL_SERVICE_ERROR` | 502 | External service unavailable |
| `PROCESSING_ERROR` | 500 | Audit processing failed |

### 10.2 Error Response Examples

```json
// Validation Error
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format"
      }
    ]
  }
}

// Authentication Error
{
  "success": false,
  "error": {
    "code": "AUTHENTICATION_ERROR",
    "message": "Invalid or expired token"
  }
}

// Not Found Error
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "Device not found"
  }
}
```

---

## 11. Rate Limiting

### 11.1 Rate Limits

| Endpoint Category | Rate Limit | Window |
|-------------------|------------|--------|
| Authentication | 10 requests | 1 minute |
| Read Operations | 100 requests | 1 minute |
| Write Operations | 30 requests | 1 minute |
| File Upload | 5 requests | 1 minute |
| Audit Processing | 2 requests | 1 minute |

### 11.2 Rate Limit Headers

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1692950400
```

### 11.3 Rate Limit Exceeded Response

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "retry_after": 60
  }
}
```

---

## 12. Versioning

### 12.1 Versioning Strategy

- API version in URL path: `/api/v1/`, `/api/v2/`
- Breaking changes require new version
- Non-breaking changes (new fields, new endpoints) allowed in current version

### 12.2 Version Lifecycle

| Version | Status | Sunset Date |
|---------|--------|-------------|
| v1 | Active | N/A |
| v2 | Planned | N/A |

### 12.3 Breaking Changes

Examples of breaking changes:
- Removing fields from response
- Changing field types
- Changing endpoint URLs
- Changing authentication method

### 12.4 Non-Breaking Changes

Examples of non-breaking changes:
- Adding new optional fields to response
- Adding new endpoints
- Adding new query parameters
- Adding new enum values

---

**END OF API CONTRACTS DOCUMENT**
