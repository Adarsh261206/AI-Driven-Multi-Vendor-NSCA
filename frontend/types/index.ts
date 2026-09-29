/**
 * Type definitions mirroring the REAL backend API responses
 * (verified against backend/app/api/v1 and schemas).
 */

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

export interface PaginationMeta {
  page: number;
  per_page: number;
  total: number;
  total_pages: number;
}

export interface ListResponse<T> {
  items: T[];
  meta: PaginationMeta;
}

export interface ItemsResponse<T> {
  items: T[];
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: 'admin' | 'auditor' | 'viewer';
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

export interface Device {
  id: string;
  name: string;
  vendor: string | null;
  platform: string | null;
  firmware_version: string | null;
  ip_address: string | null;
  notes: string | null;
  configuration_count: number;
  last_audit_date: string | null;
  created_at: string;
  updated_at: string;
}

export interface DeviceCreate {
  name: string;
  vendor?: string;
  platform?: string;
  firmware_version?: string;
  ip_address?: string;
  notes?: string;
}

// ---------------------------------------------------------------------------
// Configurations
// ---------------------------------------------------------------------------

export interface Configuration {
  id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  line_count: number;
  uploaded_at: string;
}

// ---------------------------------------------------------------------------
// Audits
// ---------------------------------------------------------------------------

export type AuditStatusValue = 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';

export interface Audit {
  id: string;
  name: string;
  description: string | null;
  status: AuditStatusValue;
  overall_score: number | null;
  configuration_count: number;
  findings_count: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  framework: string | null;
  framework_version: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface AuditCreate {
  name: string;
  description?: string;
  configuration_ids: string[];
  framework: string;
  framework_version?: string;
}

export interface AuditStatusResponse {
  status: AuditStatusValue;
  progress: number;
  current_step: string | null;
  steps_completed: string[];
  estimated_completion: string | null;
}

// audit-execution status (raw dict, different shape)
export interface AuditExecutionStatus {
  id: string;
  name: string;
  status: AuditStatusValue;
  progress: number;
  overall_score: number | null;
  findings_count: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  started_at: string | null;
  completed_at: string | null;
}

export interface AuditExecutionSummary {
  audit_id: string;
  status: AuditStatusValue;
  overall_score: number | null;
  findings_count: number;
  findings_by_severity: Partial<Record<SeverityValue, number>>;
  findings_by_status: Partial<Record<FindingStatusValue, number>>;
  started_at: string | null;
  completed_at: string | null;
  compliance?: Partial<Record<string, PerFrameworkCompliance>>;
  company_baseline?: CompanyBaselineProjection;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type SeverityValue = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type FindingStatusValue = 'open' | 'in_progress' | 'resolved' | 'accepted';

export interface EvidenceChain {
  raw_config: string;
  raw_config_line_numbers: number[];
  parsed_value: unknown | null;
  parsed_path: string;
  normalized_value: unknown | null;
  universal_model_path: string;
  normalization_confidence: number;
  control_id: string;
  control_description: string;
  expected_value: unknown | null;
  actual_value: unknown | null;
  operator: string;
  result: string; // lowercase: pass | fail | review
  result_reasoning: string;
  overall_confidence: number;
  vendor: string;
  platform: string;
  vendor_specific_syntax: string;
}

export interface Remediation {
  title?: string;
  description?: string;
  why_it_matters?: string;
  recommended_config?: string;
  verification_steps?: string[];
  rollback_steps?: string[];
  references?: string[];
  confidence?: number;
  vendor?: string;
  platform?: string;
  [key: string]: unknown;
}

export interface Finding {
  id: string;
  audit_id: string | null;
  title: string;
  description: string;
  severity: SeverityValue;
  confidence: number;
  status: FindingStatusValue;
  evidence: EvidenceChain | null;
  remediation: Remediation | null;
  affected_device: string | null;
  affected_vendor: string | null;
  affected_platform: string | null;
  compliance_result_id: string | null;
  created_at: string | null;
  updated_at: string | null;
}

// ---------------------------------------------------------------------------
// Compliance frameworks
// ---------------------------------------------------------------------------

export interface Framework {
  id: string;
  name: string;
  description: string;
  versions: string[];
  control_count: number;
  categories: string[];
}

export interface Control {
  id: string;
  framework: string;
  framework_version: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  vendor: string | null;
  platform: string | null;
  rule: Record<string, unknown> | null;
  remediation_template: Record<string, unknown> | null;
  references: string[];
}

// ---------------------------------------------------------------------------
// Training / AI
// ---------------------------------------------------------------------------

export interface TrainingMapping {
  id: string;
  vendor: string;
  platform: string;
  raw_syntax: string;
  semantic_meaning: string;
  universal_model_path: string | null;
  confidence: number;
  admin_confirmed: boolean;
  admin_notes: string | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface MappingVersion {
  version: number;
  raw_syntax: string;
  semantic_meaning: string;
  universal_model_path: string | null;
  changed_by: string;
  changed_at: string;
  change_reason: string | null;
}

export interface AIHypothesis {
  raw_syntax: string;
  suggested_meaning: string;
  confidence: number;
  reasoning: string;
  universal_model_path: string | null;
  alternative_interpretations: {
    meaning: string;
    confidence: number;
    reasoning: string;
  }[];
  security_relevance: 'high' | 'medium' | 'low' | 'none' | 'unknown';
  explanation: string;
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

export interface Report {
  id: string;
  audit_id: string;
  audit_name: string;
  framework: string;
  overall_score: number;
  generated_at: string;
  download_url: string;
}

export interface ReportJSON {
  audit: {
    audit_id: string;
    audit_name: string;
    framework: string;
    status: string;
    overall_score: number;
    configuration_count: number;
    started_at: string | null;
    completed_at: string | null;
  };
  findings: Finding[];
  compliance_results: {
    id: string;
    control_id: string;
    control_name: string;
    control_description: string;
    result: 'PASS' | 'FAIL' | 'REVIEW';
    confidence: number;
    severity: string;
    framework: string;
  }[];
}

// ---------------------------------------------------------------------------
// Company Baseline
// ---------------------------------------------------------------------------

export type BaselineStateValue = 'NOT_CONFIGURED' | 'PENDING_VALIDATION' | 'ACTIVE';

export type ComplianceResultValue = 'PASS' | 'FAIL' | 'REVIEW' | 'OUT_OF_SCOPE';

export interface CompanyBaselineSummary {
  name: string;
  framework: string;
  benchmark: string;
  control_count: number;
  status: string;
  activated_at: string | null;
}

export interface BaselineStatusResponse {
  baseline_status: BaselineStateValue;
  baseline_available: boolean;
  evaluation_unavailable: boolean;
  organization_name?: string | null;
  baseline?: CompanyBaselineSummary | null;
}

export interface BaselineValidationErrorItem {
  control_id: string;
  reason: 'duplicate' | 'unknown' | 'malformed';
}

export interface BaselineValidationResult {
  valid_count: number;
  errors: BaselineValidationErrorItem[];
  invalid_controls: string[];
}

export interface BaselineValidateResponse {
  status: 'valid' | 'invalid';
  validation_result: BaselineValidationResult;
  name: string;
  framework: string;
  benchmark: string;
  control_count: number;
}

export interface BaselineUploadPayload {
  name: string;
  framework: string;
  benchmark: string;
  controls: string[];
}

export interface BaselineOnboardingResponse {
  status: string;
  validation_result?: BaselineValidationResult;
  baseline?: {
    id: string;
    name: string;
    framework: string;
    benchmark: string;
    control_count: number;
    status: string;
  };
  activation_blocked?: boolean;
  reason?: string;
  message?: string;
}

export interface BaselineResolveResponse {
  has_baseline: boolean;
  baseline_id: string | null;
  baseline_name: string | null;
  framework?: string;
  benchmark?: string;
  in_scope_controls: string[];
  out_of_scope_controls: string[];
  baseline_status: string;
}

export interface PerFrameworkCompliance {
  controls: number;
  pass: number;
  fail: number;
  review: number;
}

export interface CompanyBaselineProjection {
  configured: boolean;
  has_baseline: boolean;
  name?: string;
  framework?: string;
  benchmark?: string;
  in_scope_count: number;
  passed: number;
  failed: number;
  review: number;
  out_of_scope: number;
  score: number | null;
  control_ids: string[];
  comparison?: Array<{
    control_id: string;
    company_result: ComplianceResultValue;
    full_cis_result: 'PASS' | 'FAIL' | 'REVIEW';
    in_scope: boolean;
  }>;
}
