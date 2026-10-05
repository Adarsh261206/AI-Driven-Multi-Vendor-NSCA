import axios, { type AxiosInstance, type AxiosResponse } from 'axios';
import type {
  AIHypothesis,
  Audit,
  AuditCreate,
  AuditExecutionStatus,
  AuditExecutionSummary,
  AuditTrailEntry,
  Configuration,
  Control,
  Device,
  DeviceCreate,
  Finding,
  Framework,
  ItemsResponse,
  ListResponse,
  MappingVersion,
  RemediationPlanRecord,
  Report,
  TokenResponse,
  TrainingMapping,
  User,
} from '@/types';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

/**
 * Shared axios instance. All API paths in this module are relative to
 * the versioned backend prefix (/api/v1).
 */
const api: AxiosInstance = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  timeout: 60000,
});

api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = window.localStorage.getItem('access_token');
    if (token) config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

type QueryParams = Record<string, string | number | boolean | undefined>;

interface ApiErrorBody {
  detail?: unknown;
  message?: string;
}

/** Extracts a human-readable message from any error thrown by the API. */
export function getApiError(err: unknown, fallback: string): string {
  if (axios.isAxiosError(err)) {
    const body = (err.response?.data ?? undefined) as ApiErrorBody | undefined;
    const detail = body?.detail;

    if (typeof detail === 'string' && detail) return detail;
    if (Array.isArray(detail)) {
      const messages = detail.map((item) => {
        if (item && typeof item === 'object' && 'msg' in item) {
          return String((item as { msg: unknown }).msg);
        }
        return String(item);
      });
      if (messages.length > 0) return messages.join(' ');
    }
    if (typeof body?.message === 'string' && body.message) return body.message;

    if (err.response?.status === 401) return 'Your session has expired. Please sign in again.';
    if (err.response?.status === 403) return 'You do not have permission to perform this action.';
    if (
      err.code === 'ERR_NETWORK' ||
      err.code === 'ECONNABORTED' ||
      err.message === 'Network Error'
    ) {
      return 'Cannot reach the API server. Is the backend running?';
    }
    if (err.message) return err.message;
  }

  if (err instanceof Error && err.message) return err.message;
  return fallback;
}

/**
 * Runs an API call and unwraps its payload, throwing an Error with a
 * user-friendly message on failure.
 */
export async function request<T>(
  fn: () => Promise<AxiosResponse<T>>,
  fallback: string
): Promise<T> {
  try {
    const res = await fn();
    return res.data;
  } catch (err) {
    throw new Error(getApiError(err, fallback));
  }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const authAPI = {
  login: (email: string, password: string) =>
    api.post<TokenResponse>('/auth/login', { email, password }),

  register: (email: string, password: string, fullName?: string) =>
    api.post<User>('/auth/register', {
      email,
      password,
      full_name: fullName || null,
    }),

  getMe: () => api.get<User>('/auth/me'),

  refresh: (refreshToken: string) =>
    api.post<TokenResponse>('/auth/refresh', { refresh_token: refreshToken }),

  /** Observability only: records USER_LOGOUT server-side. Never throws. */
  logout: async (): Promise<void> => {
    try {
      await api.post('/auth/logout');
    } catch {
      // Best-effort: sign-out always proceeds client-side regardless.
    }
  },
};

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

export const devicesAPI = {
  list: (params?: QueryParams) =>
    api.get<ListResponse<Device>>('/devices', { params }),

  get: (id: string) => api.get<Device>(`/devices/${id}`),

  create: (data: DeviceCreate) => api.post<Device>('/devices', data),

  update: (id: string, data: Partial<DeviceCreate>) =>
    api.put<Device>(`/devices/${id}`, data),

  delete: (id: string) => api.delete<void>(`/devices/${id}`),
};

// ---------------------------------------------------------------------------
// Configurations
// ---------------------------------------------------------------------------

export const configurationsAPI = {
  list: (params?: QueryParams) =>
    api.get<ListResponse<Configuration>>('/configurations', { params }),

  upload: (file: File, deviceId?: string) => {
    const form = new FormData();
    form.append('file', file);
    if (deviceId) form.append('device_id', deviceId);
    return api.post<Configuration>('/configurations/upload', form);
  },

  get: (id: string) => api.get<Configuration>(`/configurations/${id}`),

  content: (id: string) =>
    api.get<{ content: string }>(`/configurations/${id}/content`),

  delete: (id: string) => api.delete<void>(`/configurations/${id}`),
};

// ---------------------------------------------------------------------------
// Audits
// ---------------------------------------------------------------------------

export const auditsAPI = {
  list: (params?: QueryParams) => {
    const { status, ...rest } = params ?? {};
    return api.get<ListResponse<Audit>>('/audits', {
      params: status === undefined ? rest : { ...rest, audit_status: status },
    });
  },

  get: (id: string) => api.get<Audit>(`/audits/${id}`),

  create: (data: AuditCreate) => api.post<Audit>('/audits', data),

  status: (id: string) =>
    api.get<{ status: string; progress: number; current_step: string | null }>(
      `/audits/${id}/status`
    ),

  cancel: (id: string) => api.post<Audit>(`/audits/${id}/cancel`),
};

// ---------------------------------------------------------------------------
// Audit execution (runs the pipeline)
// ---------------------------------------------------------------------------

export const auditExecutionAPI = {
  execute: (data: AuditCreate) =>
    api.post<Audit>('/audit-execution/execute', data),

  getStatus: (id: string) =>
    api.get<AuditExecutionStatus>(`/audit-execution/${id}/status`),

  getSummary: (id: string) =>
    api.get<AuditExecutionSummary>(`/audit-execution/${id}/summary`),

  getFindings: (id: string, params?: QueryParams) =>
    api.get<ListResponse<Finding>>(`/audit-execution/${id}/findings`, {
      params,
    }),
};

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export const findingsAPI = {
  listByAudit: (auditId: string, params?: QueryParams) =>
    api.get<ListResponse<Finding>>(`/findings/audit/${auditId}`, { params }),

  get: (id: string) => api.get<Finding>(`/findings/${id}`),

  updateStatus: (id: string, status: string) =>
    api.put<Finding>(`/findings/${id}/status`, { status }),
};

// ---------------------------------------------------------------------------
// Remediation plans (plan-first workflow; backend never executes)
// ---------------------------------------------------------------------------

export const remediationAPI = {
  plan: (findingId: string) =>
    api.post<RemediationPlanRecord>(`/findings/${findingId}/remediation/plan`),

  saveParams: (findingId: string, params?: Record<string, string>) =>
    api.post<RemediationPlanRecord>(`/findings/${findingId}/remediation/parameters`, {
      confirm: false,
      params: params ?? {},
      notes: '',
    }),

  approve: (findingId: string, confirm: boolean, params?: Record<string, string>, notes?: string) =>
    api.post<RemediationPlanRecord>(`/findings/${findingId}/remediation/approve`, {
      confirm,
      params: params ?? {},
      notes: notes ?? '',
    }),

  scriptBlob: (findingId: string) =>
    api.post<Blob>(`/findings/${findingId}/remediation/script`, {}, { responseType: 'blob' }),

  rollbackBlob: (findingId: string) =>
    api.post<Blob>(`/findings/${findingId}/remediation/rollback`, {}, { responseType: 'blob' }),
};

// ---------------------------------------------------------------------------
// Compliance frameworks
// ---------------------------------------------------------------------------

export const complianceAPI = {
  listFrameworks: () => api.get<ItemsResponse<Framework>>('/compliance/frameworks'),

  listControls: (frameworkId: string, params?: QueryParams) =>
    api.get<ItemsResponse<Control>>(
      `/compliance/frameworks/${frameworkId}/controls`,
      { params }
    ),

  getControl: (controlId: string) =>
    api.get<Control>(`/compliance/controls/${controlId}`),
};

// ---------------------------------------------------------------------------
// Training / adaptive learning
// ---------------------------------------------------------------------------

export interface TrainingMappingCreateInput {
  vendor: string;
  platform: string;
  raw_syntax: string;
  semantic_meaning: string;
  universal_model_path?: string;
  admin_notes?: string;
}

export const trainingAPI = {
  listMappings: (params?: QueryParams) =>
    api.get<ListResponse<TrainingMapping>>('/training/mappings', { params }),

  createMapping: (data: TrainingMappingCreateInput) =>
    api.post<TrainingMapping>('/training/mappings', data),

  getVersions: (mappingId: string) =>
    api.get<ItemsResponse<MappingVersion>>(
      `/training/mappings/${mappingId}/versions`
    ),

  /** POST body is empty — vendor/platform/raw_syntax travel as query params. */
  getHypothesis: (vendor: string, platform: string, rawSyntax: string) =>
    api.post<AIHypothesis>('/training/hypothesis', null, {
      params: { vendor, platform, raw_syntax: rawSyntax },
    }),

  confirmMapping: (mappingId: string, reason?: string) =>
    api.post<TrainingMapping>(`/training/mappings/${mappingId}/confirm`, null, {
      params: reason ? { admin_notes: reason } : undefined,
    }),

  rejectMapping: (mappingId: string, reason?: string) =>
    api.post(`/training/mappings/${mappingId}/reject`, null, {
      params: reason ? { reason } : undefined,
    }),
};

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

export const reportsAPI = {
  list: (params?: QueryParams) =>
    api.get<ListResponse<Report>>('/reports', { params }),

  download: (auditId: string, format = 'pdf') =>
    api.get<Blob>(`/reports/${auditId}/report`, {
      params: { format },
      responseType: 'blob',
    }),
};

// ---------------------------------------------------------------------------
// Audit ledger (read-only — no create/edit/delete surface exists)
// ---------------------------------------------------------------------------

export const auditTrailAPI = {
  // Trailing slash is deliberate: the route is registered as "/" and a
  // bare "/audit-trail" hits FastAPI's 307 redirect, whose response
  // carries no CORS headers (browser blocks the call).
  list: (params?: QueryParams) =>
    api.get<ListResponse<AuditTrailEntry>>('/audit-trail/', { params }),
};

export default api;
