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
  /** STEP 5 device lifecycle: true = active inventory, false = archived.
   * Archive preserves all history; never edited via generic update. */
  is_active: boolean;
  /** STEP 4 derived inventory fields — computed server-side per request,
   * never stored. Null means absent data (render "Not configured" /
   * "Never" / "Not audited", never fabricate). */
  latest_configuration_filename?: string | null;
  latest_configuration_at?: string | null;
  last_audit_id?: string | null;
  last_audit_status?: string | null;
  last_compliance_score?: number | null;
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
  /** Optional execution-time device scope constraint. Never persisted as
   * Audit.device_id — device identity stays derivable via associations. */
  device_ids?: string[];
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
  execution?: ExecutionInfo | null;
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
  reasoning: string;
  overall_confidence: number;
  vendor: string;
  platform: string;
  vendor_specific_syntax: string;
  hostname?: string | null;
  device_type?: string | null;
  review_code?: string | null;
  evaluation_method?: string | null;
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
// NOTE (STEP 7.5 audit): backend FindingResponse carries additional
// control-identity and scoring fields that stay untyped here because
// frozen V09-87 pins no such surface in frontend sources. No component
// reads them today; type them in the milestone that renders them.

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
  confidence: number | null;
  changed_by: string | null;
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

// ---------------------------------------------------------------------------
// Device configuration history
// ---------------------------------------------------------------------------

export interface DeviceConfigurationHistoryItem {
  id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  line_count: number;
  uploaded_at: string;
  device_id: string;
  content_hash: string;
  latest: boolean;
  audit_count: number;
  detected_vendor: string | null;
  detected_platform: string | null;
  detected_hostname: string | null;
}

export interface DeviceConfigurationHistoryResponse {
  items: DeviceConfigurationHistoryItem[];
  meta: PaginationMeta;
}

export interface DeviceAuditHistoryItem {
  id: string;
  name: string;
  status: string;
  overall_score: number | null;
  configuration_id: string;
  configuration_filename: string;
  created_at: string;
}

export interface DeviceAuditHistoryResponse {
  items: DeviceAuditHistoryItem[];
  meta: PaginationMeta;
}

// ---------------------------------------------------------------------------
// Bulk operations (STEP 6)
// ---------------------------------------------------------------------------

export type BulkUploadItemStatus = 'stored' | 'duplicate' | 'invalid';

export interface BulkUploadItemResult {
  filename: string;
  status: BulkUploadItemStatus;
  configuration_id: string | null;
  error: string | null;
}

export interface BulkUploadSummary {
  total: number;
  stored: number;
  duplicate: number;
  invalid: number;
}

export interface BulkUploadResponse {
  items: BulkUploadItemResult[];
  summary: BulkUploadSummary;
}

export interface BulkAuditItemInput {
  name: string;
  description?: string;
  configuration_ids: string[];
  device_ids?: string[];
  framework?: string;
  framework_version?: string;
}

export interface BulkAuditItemResult {
  audit_id: string;
  name: string;
  status: string;
}

export interface BulkAuditResponse {
  audits: BulkAuditItemResult[];
  total: number;
  batch_id?: string | null;
}

// ---------------------------------------------------------------------------
// Durable execution (STEP 7)
// ---------------------------------------------------------------------------

export type ExecutionStatusValue =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancel_requested'
  | 'cancelled';

export interface ExecutionInfo {
  id: string;
  audit_id: string;
  attempt: number;
  max_attempts: number;
  status: ExecutionStatusValue;
  error_category: string | null;
  error_message: string | null;
  retryable: boolean;
  progress: number;
  current_step: string | null;
  queued_at: string | null;
  started_at: string | null;
  completed_at: string | null;
}

export interface RetryExecutionResponse {
  audit_id: string;
  execution: ExecutionInfo;
}

export interface BatchAuditItem {
  audit_id: string;
  name: string;
  status: string;
  execution_status: string;
  execution: ExecutionInfo | null;
  overall_score: number | null;
}

export interface AuditBatchResponse {
  batch_id: string;
  name: string;
  total: number;
  counts: Partial<Record<string, number>>;
  items: BatchAuditItem[];
  created_at: string | null;
}

// ---------------------------------------------------------------------------
// Audit ledger (read-only; mirrors backend AuditTrailResponse)
// ---------------------------------------------------------------------------

export interface AuditTrailEntry {
  id: string;
  action: string;
  entity_type: string;
  entity_id: string | null;
  user_id: string | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
  // Hash-chained ledger era. NULL explicitly means "pre-chain audit era".
  seq: number | null;
  previous_hash: string | null;
  event_hash: string | null;
}

// ---------------------------------------------------------------------------
// Remediation plans (plan-first workflow; mirrors backend plan to_dict)
// ---------------------------------------------------------------------------

export interface PlanChange {
  context: string;
  commands: string[];
}

export interface PlanPrecondition {
  name: string;
  passed: boolean;
  severity: string;
  message: string;
}

export interface PlanParam {
  name: string;
  type: string;
  required: boolean;
  supplied: boolean;
  redacted: boolean;
}

export interface RemediationPlan {
  plan_id: string;
  finding_id: string;
  control_id: string;
  device: {
    name: string;
    vendor: string;
    platform: string;
    model: string | null;
    version: string | null;
  };
  finding: { title: string; severity: string; confidence: number };
  preconditions: PlanPrecondition[];
  changes: { add: string[]; remove: string[]; contexts: PlanChange[] };
  diff: { before: string[]; after: string[]; add: string[]; remove: string[] };
  rollback: PlanChange[];
  verification: string[];
  risk_flags: string[];
  params: PlanParam[];
  safety_class: string;
  safe_to_apply: boolean;
  requires_approval: boolean;
  status: string;
  configuration_id: string | null;
  configuration_hash_before: string | null;
}

export interface RemediationPlanRecord {
  id: string;
  plan_id: string;
  finding_id: string;
  control_id: string | null;
  status: string;
  plan: RemediationPlan;
  configuration_id: string | null;
  configuration_hash_before: string | null;
  approved_by: string | null;
  approved_at: string | null;
  rejection_reason: string | null;
  failure_info: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}
