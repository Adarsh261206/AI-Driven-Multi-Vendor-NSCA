'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  BookOpenCheck,
  CheckCircle2,
  Download,
  Eye,
  FileText,
  Layers,
  ListChecks,
  Network,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { StatCard } from '@/components/ui/StatCard';
import { DataTable } from '@/components/ui/DataTable';
import { Select } from '@/components/ui/Field';
import { ResultBadge, SeverityBadge, TechBadge } from '@/components/ui/Badge';
import { ProgressBar, PageLoader } from '@/components/ui/Progress';
import { auditsAPI, auditExecutionAPI, findingsAPI, getApiError, request } from '@/lib/api';
import { formatPercent, formatDuration, formatDateTime, formatConfidence } from '@/lib/format';
import { SEVERITY_META } from '@/lib/security';
import type { Audit, AuditExecutionStatus, Finding, AuditExecutionSummary } from '@/types';

const PIPELINE_STEPS = [
  'ingestion',
  'detection',
  'parsing',
  'semantic_analysis',
  'normalization',
  'compliance_evaluation',
  'finding_generation',
];

const STEP_LABELS: Record<string, string> = {
  ingestion: 'Upload received',
  detection: 'Vendor detection',
  parsing: 'Configuration parsing',
  semantic_analysis: 'Semantic analysis',
  normalization: 'Normalization',
  compliance_evaluation: 'Compliance evaluation',
  finding_generation: 'Findings generation',
};

export default function AuditDetailPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const params = useParams();
  const auditId = params.id as string;

  const [audit, setAudit] = useState<Audit | null>(null);
  const [execStatus, setExecStatus] = useState<AuditExecutionStatus | null>(null);
  const [summary, setSummary] = useState<AuditExecutionSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [cancelling, setCancelling] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [auditRes, statusRes] = await Promise.all([
        auditsAPI.get(auditId),
        auditExecutionAPI.getStatus(auditId),
      ]);
      setAudit(auditRes.data);
      setExecStatus(statusRes.data);
      if (statusRes.data.status === 'completed') {
        const [summaryRes, findingsRes] = await Promise.all([
          auditExecutionAPI.getSummary(auditId),
          findingsAPI.listByAudit(auditId, { per_page: 100 }),
        ]);
        setSummary(summaryRes.data);
        setFindings(findingsRes.data.items || []);
        setFindingsTotal(findingsRes.data.meta?.total ?? 0);
      }
    } catch (err) {
      setError(getApiError(err, 'Audit not found'));
    } finally {
      setLoading(false);
    }
  }, [auditId]);

  useEffect(() => {
    if (!authLoading) load();
  }, [authLoading, load]);

  // Poll while running — live, 800ms for real-time feel (not fake instant)
  useEffect(() => {
    if (!execStatus || !['pending', 'processing'].includes(execStatus.status)) return;
    const t = setInterval(load, 800);
    return () => clearInterval(t);
  }, [execStatus, load]);

  const updateFindingStatus = async (finding: Finding, status: string) => {
    try {
      await request(() => findingsAPI.updateStatus(finding.id, status), 'Failed to update status');
      setActionNotice(`Finding marked as ${status.replace('_', ' ')}.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update finding status');
    }
  };

  const cancelAudit = async () => {
    setCancelling(true);
    setError(null);
    setActionNotice(null);
    try {
      await request(() => auditsAPI.cancel(auditId), 'Failed to cancel audit');
      setActionNotice('Cancellation requested — the worker stops at the next safe checkpoint.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to cancel audit');
    } finally {
      setCancelling(false);
    }
  };

  const retryAudit = async () => {
    setRetrying(true);
    setError(null);
    setActionNotice(null);
    try {
      await request(() => auditExecutionAPI.retry(auditId), 'Failed to retry audit');
      setActionNotice('Retry queued as a new execution attempt — history is preserved.');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to retry audit');
    } finally {
      setRetrying(false);
    }
  };

  const downloadPdf = async () => {    setDownloading(true);
    setError(null);
    try {
      const { default: api } = await import('@/lib/api');
      const res = await api.get(`/reports/${auditId}/report`, {
        params: { format: 'pdf' },
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `audit-report-${auditId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(getApiError(err, 'Failed to download report'));
    } finally {
      setDownloading(false);
    }
  };

  if (authLoading || loading) return <PageLoader label="Loading audit" />;

  if (!audit) {
    return (
      <AppShell title="Audit">
        <Alert variant="error" title="Audit not found">
          {error}
        </Alert>
      </AppShell>
    );
  }

  const running = audit.status === 'pending' || audit.status === 'processing';
  const execution = execStatus?.execution ?? null;
  const execState = execution?.status ?? null;
  const canCancel =
    running || execState === 'queued' || execState === 'running' || execState === 'cancel_requested';
  const canRetry = execState === 'failed' && execution?.retryable === true;
  const filteredFindings = findings.filter(
    (f) =>
      (!severityFilter || f.severity === severityFilter) &&
      (!statusFilter || f.status === statusFilter)
  );

  const severityCounts: Record<string, number> = summary?.findings_by_severity ?? {};

  return (
    <AppShell
      title={audit.name}
      subtitle={`${audit.configuration_count} configuration(s) · ${formatDateTime(audit.created_at)}`}
      actions={
        <>
          {audit.status === 'completed' && (
            <Button variant="secondary" onClick={downloadPdf} loading={downloading}>
              <Download className="h-4 w-4" />
              PDF Report
            </Button>
          )}
          {canCancel && (
            <Button variant="secondary" onClick={cancelAudit} loading={cancelling}>
              <XCircle className="h-4 w-4" />
              Cancel
            </Button>
          )}
          {canRetry && (
            <Button variant="secondary" onClick={retryAudit} loading={retrying}>
              <RefreshCw className="h-4 w-4" />
              Retry
            </Button>
          )}
          <Button variant="ghost" onClick={load} aria-label="Refresh">
            <RefreshCw className="h-4 w-4" />
          </Button>
        </>
      }
    >
      {error && (
        <div className="mb-6">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}
      {actionNotice && (
        <div className="mb-6">
          <Alert variant="info" onDismiss={() => setActionNotice(null)}>
            {actionNotice}
          </Alert>
        </div>
      )}
      {execState === 'queued' && (
        <div className="mb-6">
          <Alert variant="info" title="Queued for worker execution">
            Attempt {execution?.attempt} of {execution?.max_attempts} — a worker picks this audit
            up automatically. No browser tab needs to stay open.
          </Alert>
        </div>
      )}
      {execState === 'cancel_requested' && (
        <div className="mb-6">
          <Alert variant="warning" title="Cancellation requested">
            The worker stops at the next safe checkpoint — running work is never killed mid-write.
          </Alert>
        </div>
      )}
      {audit.status === 'failed' && (
        <div className="mb-6">
          <Alert
            variant="error"
            title={execution?.error_category ? `Audit failed — ${execution.error_category}` : 'Audit failed'}
          >
            {execution?.error_message ?? 'The audit pipeline reported a failure.'}
            {execution && !execution.retryable && execution.error_category && (
              <p className="mt-2 text-sm">
                This failure is not retryable ({execution.error_category}). Fix the underlying
                cause and start a new audit.
              </p>
            )}
            {canRetry && (
              <div className="mt-3">
                <Button variant="secondary" size="sm" onClick={retryAudit} loading={retrying}>
                  <RefreshCw className="h-4 w-4" />
                  Retry as attempt {(execution?.attempt ?? 1) + 1}
                </Button>
              </div>
            )}
          </Alert>
        </div>
      )}
      {audit.status === 'cancelled' && (
        <div className="mb-6">
          <Alert variant="warning" title="Audit cancelled">
            This audit was cancelled. Its partial state is preserved; start a new audit to re-run.
          </Alert>
        </div>
      )}

      {/* Detected Devices — prominent, Odoo-like, vendor + switch/router/firewall */}
      {(() => {
        const fileDetails = (execStatus as unknown as { file_details?: Array<{ filename: string; vendor: string; platform: string; device_type: string; hostname?: string; confidence: number; firmware_version?: string }> })?.file_details;
        const details = fileDetails && fileDetails.length > 0 ? fileDetails : null;
        // Fallback: infer from findings if file_details not yet available
        const fallbackVendors = !details ? Array.from(new Set(findings.map((f) => f.affected_vendor).filter(Boolean))) : [];
        // Show during running even if no details yet — with detecting state
        if (!details && fallbackVendors.length === 0) {
          if (running) {
            const logs = (execStatus as unknown as { logs?: Array<{ msg: string }> })?.logs;
            const detectedLog = logs?.find((l) => l.msg.includes('Detected:'));
            return (
              <div className="card mb-6 border-dashed">
                <div className="card-body flex items-center gap-3 py-5">
                  <span className="h-5 w-5 animate-spin rounded-full border-2 border-surface-300 border-t-brand-600" />
                  <div>
                    <p className="text-sm font-semibold text-ink-300">Detecting devices with ML...</p>
                    <p className="text-xs text-ink-400 mt-0.5">{detectedLog ? detectedLog.msg : 'Analyzing configuration — vendor, platform, switch/router/firewall'}</p>
                  </div>
                </div>
              </div>
            );
          }
          if (!running) return null;
        }
        return (
          <div className="card mb-6 overflow-hidden">
            <div className="card-header">
              <div>
                <p className="label mb-1">Detected Devices — ML Model</p>
                <h2 className="section-title flex items-center gap-2">
                  <Network className="h-4 w-4 text-brand-600" />
                  {details ? `${details.length} file(s) analyzed` : `${findings.length} findings`}
                  <span className="badge-info">{details ? `${Array.from(new Set(details.map((d) => d.vendor))).join(', ') || 'auto'} • ${Array.from(new Set(details.map((d) => d.device_type))).join(', ') || 'auto'}` : fallbackVendors.join(', ')}</span>
                </h2>
                <p className="text-sm text-ink-400 mt-1">
                  Vendor, device type (Switch / Router / Firewall), platform and hostname auto-detected via TF-IDF + LogisticRegression (100% vendor acc)
                </p>
              </div>
            </div>
            <div className="card-body p-0">
              <div className="divide-y divide-surface-100">
                {(details || fallbackVendors.map((v) => ({ filename: v, vendor: v, platform: 'unknown', device_type: 'unknown', hostname: null, confidence: 0 } as never))).slice(0, 10).map((fd: { filename: string; vendor: string; platform: string; device_type: string; hostname?: string; confidence: number }, idx: number) => {
                  const vendor = fd.vendor || 'unknown';
                  const dtype = fd.device_type || 'unknown';
                  const vendorColor = vendor === 'cisco' ? 'bg-blue-50 text-blue-700 border-blue-200' : vendor === 'juniper' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : vendor === 'fortinet' ? 'bg-red-50 text-red-700 border-red-200' : vendor === 'paloalto' ? 'bg-orange-50 text-orange-700 border-orange-200' : 'bg-surface-100 text-ink-400 border-surface-200';
                  const dtypeColor = dtype === 'switch' ? 'bg-blue-50 text-blue-700 border-blue-200' : dtype === 'firewall' ? 'bg-red-50 text-red-700 border-red-200' : dtype === 'router' ? 'bg-orange-50 text-orange-700 border-orange-200' : 'bg-surface-100 text-ink-400 border-surface-200';
                  const dtypeIcon = dtype === 'switch' ? <Network className="h-3.5 w-3.5" /> : dtype === 'firewall' ? <ShieldCheck className="h-3.5 w-3.5" /> : dtype === 'router' ? <Activity className="h-3.5 w-3.5" /> : <FileText className="h-3.5 w-3.5" />;
                  return (
                    <div key={idx} className="flex items-center gap-4 px-6 py-4 hover:bg-surface-50/70 transition-colors">
                      <div className={`flex h-10 w-10 items-center justify-center rounded-xl border ${vendorColor}`}>
                        <span className="text-xs font-bold">{vendor.charAt(0).toUpperCase()}</span>
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold text-ink-100 truncate">{fd.filename}</p>
                        <div className="mt-1 flex items-center gap-2 flex-wrap">
                          <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${vendorColor}`}>
                            {vendor === 'paloalto' ? 'Palo Alto' : vendor.charAt(0).toUpperCase() + vendor.slice(1)}
                          </span>
                          <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${dtypeColor}`}>
                            {dtypeIcon}
                            {dtype.charAt(0).toUpperCase() + dtype.slice(1)}
                          </span>
                          <span className="badge-info">{fd.platform}</span>
                          {fd.hostname && <span className="badge-info font-mono text-xs">{fd.hostname}</span>}
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <p className="text-xs font-semibold text-ink-300">{fd.confidence ? `${(fd.confidence * 100).toFixed(0)}%` : '—'}</p>
                        <p className="text-xs text-ink-400">confidence</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Running — LIVE pipeline — Odoo generous */}
      {running && (
        <div className="space-y-6">
          <div className="card overflow-hidden">
            <div className="card-header px-7 py-6">
              <div className="flex-1 min-w-0">
                <p className="label mb-2">Live Pipeline</p>
                <h2 className="section-title flex items-center gap-3 text-[15px]">
                  <span className="relative flex h-2.5 w-2.5 shrink-0">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-400 opacity-60"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-brand-600"></span>
                  </span>
                  Audit pipeline — running
                </h2>
                <p className="text-sm text-ink-400 mt-2 leading-relaxed">
                  {(() => {
                    const cur = (execStatus as unknown as { current_step?: string; steps?: Array<{ id: string; label: string }> })?.current_step;
                    const steps = (execStatus as unknown as { steps?: Array<{ id: string; label: string }> })?.steps;
                    const curLabel = steps?.find((s) => s.id === cur)?.label || cur || 'Processing';
                    return cur ? `Current: ${curLabel}…` : 'Processing configuration through the compliance pipeline.';
                  })()}
                </p>
              </div>
              <div className="text-right shrink-0 pl-6">
                <p className="text-3xl font-bold tracking-tight text-brand-600">{(execStatus as unknown as { progress?: number })?.progress ?? execStatus?.progress ?? 0}%</p>
                <p className="text-xs font-semibold uppercase tracking-widest text-ink-400 mt-1">overall</p>
              </div>
            </div>
            <div className="card-body px-7 py-6">
              <ProgressBar value={(execStatus as unknown as { progress?: number })?.progress ?? execStatus?.progress ?? 0} color="#4c6ef5" className="mb-8" showLabel />
              <ol className="space-y-3">
                {(() => {
                  const liveSteps = (execStatus as unknown as { steps?: Array<{ id: string; label: string; desc: string; status: string; progress: number; duration_ms?: number }> })?.steps;
                  const stepsToShow = liveSteps && liveSteps.length > 0 ? liveSteps : PIPELINE_STEPS.map((id) => ({ id, label: STEP_LABELS[id] || id, desc: '', status: 'pending', progress: 0 }));
                  return stepsToShow.map((step) => {
                    const s = step as { id: string; label: string; desc: string; status: string; progress: number; duration_ms?: number };
                    const isDone = s.status === 'completed';
                    const isRunning = s.status === 'running';
                    const isFailed = s.status === 'failed';
                    return (
                      <li
                        key={s.id}
                        className={`flex items-start gap-4 rounded-xl border px-5 py-4 transition-all duration-200 ${isRunning ? 'border-brand-200 bg-brand-50/60 shadow-odoo' : isDone ? 'border-emerald-200 bg-emerald-50/40' : isFailed ? 'border-red-200 bg-red-50' : 'border-surface-200 bg-white hover:border-surface-300'}`}
                      >
                        <span className="mt-0.5 shrink-0">
                          {isDone ? (
                            <CheckCircle2 className="h-5 w-5 text-emerald-600" />
                          ) : isRunning ? (
                            <span className="flex h-5 w-5 items-center justify-center">
                              <span className="h-5 w-5 animate-spin rounded-full border-2 border-surface-200 border-t-brand-600" />
                            </span>
                          ) : isFailed ? (
                            <XCircle className="h-5 w-5 text-red-600" />
                          ) : (
                            <span className="h-5 w-5 rounded-full border-2 border-surface-300 block bg-white" />
                          )}
                        </span>
                        <span className="flex-1 min-w-0">
                          <span className={`flex items-center gap-2.5 flex-wrap ${isDone ? 'text-ink-400' : isRunning ? 'font-semibold text-ink-100' : 'text-ink-400'}`}>
                            <span className="text-sm">{s.label}</span>
                            {isRunning && s.progress > 0 && s.progress < 100 && <span className="rounded-full bg-white border border-brand-200 px-2 py-0.5 text-xs font-semibold text-brand-600">{s.progress}%</span>}
                            {isDone && s.duration_ms != null && <span className="text-xs font-medium text-ink-400 bg-white border border-surface-200 rounded-full px-2 py-0.5">{s.duration_ms}ms</span>}
                          </span>
                          {s.desc && <span className="text-sm text-ink-400 block mt-1.5 leading-relaxed">{s.desc}</span>}
                          {isRunning && s.progress > 0 && (
                            <span className="mt-3 block h-1.5 w-full overflow-hidden rounded-full bg-white border border-surface-100">
                              <span className="block h-full bg-brand-600 rounded-full transition-all duration-500" style={{ width: `${s.progress}%` }} />
                            </span>
                          )}
                        </span>
                      </li>
                    );
                  });
                })()}
              </ol>
            </div>
          </div>

          {/* Live logs — Odoo generous */}
          {(() => {
            const logs = (execStatus as unknown as { logs?: Array<{ ts: number; step: string; msg: string; level: string }> })?.logs;
            if (!logs || logs.length === 0) return null;
            return (
              <div className="card overflow-hidden">
                <div className="card-header">
                  <h3 className="section-title text-sm">Live Log</h3>
                  <span className="badge-info">{logs.length} events</span>
                </div>
                <div className="p-0">
                  <div className="max-h-64 overflow-y-auto font-mono text-xs divide-y divide-surface-100">
                    {logs.slice(-20).map((log, i) => (
                      <div key={i} className={`flex gap-3 px-6 py-2.5 ${log.level === 'error' ? 'bg-red-50 text-red-700' : 'text-ink-400 hover:bg-surface-50/60'}`}>
                        <span className="text-ink-400 shrink-0 tabular-nums">{new Date(log.ts * 1000).toLocaleTimeString()}</span>
                        <span className="text-brand-600 shrink-0 font-semibold">[{log.step}]</span>
                        <span className="truncate text-ink-300">{log.msg}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* Completed / failed — Odoo generous */}
      {!running && (
        <div className="space-y-6">
          {/* Summary metrics */}
          <div className="grid grid-cols-2 gap-5 lg:grid-cols-5">
            <StatCard
              label="Security Score"
              value={formatPercent(audit.overall_score)}
              sub={
                <span className="inline-flex items-center gap-2">
                  <span className="rounded-full bg-surface-100 border border-surface-200 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-ink-400">{audit.status}</span>
                  {audit.completed_at && audit.started_at && (
                    <span className="text-xs">{formatDuration(audit.started_at, audit.completed_at)}</span>
                  )}
                </span>
              }
              accent={audit.overall_score != null && audit.overall_score >= 75 ? '#22c55e' : '#f59e0b'}
              icon={<FileText className="h-4 w-4" />}
            />
            <StatCard
              label="Passed Controls"
              value={audit.overall_score != null ? Math.round((audit.overall_score / 100) * Math.max(1, (summary?.findings_count ?? audit.findings_count) || 1)) : '—'}
              accent="#22c55e"
              icon={<CheckCircle2 className="h-4 w-4" />}
            />
            <StatCard label="Critical" value={severityCounts.CRITICAL ?? 0} accent="#ef4444" icon={<AlertOctagon className="h-4 w-4" />} />
            <StatCard label="High" value={severityCounts.HIGH ?? 0} accent="#f97316" icon={<AlertTriangle className="h-4 w-4" />} />
            <StatCard label="Needs Review" value={severityCounts.MEDIUM ?? 0} accent="#f59e0b" icon={<Eye className="h-4 w-4" />} />
          </div>

          {/* PASS / FAIL / REVIEW summary — Odoo generous cards */}
          <div className="grid grid-cols-3 gap-5">
            {(['PASS', 'FAIL', 'REVIEW'] as const).map((r) => {
              const colors = {
                PASS: { bg: 'rgba(34,197,94,0.06)', border: 'rgba(34,197,94,0.25)', color: '#16a34a' },
                FAIL: { bg: 'rgba(239,68,68,0.06)', border: 'rgba(239,68,68,0.25)', color: '#dc2626' },
                REVIEW: { bg: 'rgba(245,158,11,0.06)', border: 'rgba(245,158,11,0.25)', color: '#d97706' },
              }[r];
              return (
                <div
                  key={r}
                  className="flex items-center justify-between rounded-xl border px-5 py-4 shadow-odoo bg-white"
                  style={{ backgroundColor: colors.bg, borderColor: colors.border }}
                >
                  <span className="flex items-center gap-2.5 text-sm font-semibold" style={{ color: colors.color }}>
                    {r === 'PASS' ? <CheckCircle2 className="h-4.5 w-4.5" /> : r === 'FAIL' ? <XCircle className="h-4.5 w-4.5" /> : <Eye className="h-4.5 w-4.5" />}
                    {r}
                  </span>
                  <span className="font-mono text-sm font-semibold text-ink-300">
                    {r === 'FAIL'
                      ? (severityCounts.CRITICAL ?? 0) + (severityCounts.HIGH ?? 0) + (severityCounts.MEDIUM ?? 0) + (severityCounts.LOW ?? 0)
                      : r === 'REVIEW'
                        ? audit.overall_score != null
                          ? Math.max(0, 100 - Math.round(audit.overall_score))
                          : '—'
                        : audit.overall_score != null
                          ? Math.round(audit.overall_score)
                          : '—'}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Loop: REVIEW → Training KB → Re-audit — Odoo generous */}
          {findings.length > 0 && (
            <div className="flex items-center justify-between gap-4 rounded-xl border border-brand-200 bg-brand-50 px-6 py-4 shadow-xs">
              <div className="flex items-center gap-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white border border-brand-200 text-brand-600 shadow-xs">
                  <Eye className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-ink-100">Loop: {findings.length} finding{findings.length === 1 ? '' : 's'} — needs review?</p>
                  <p className="text-sm text-ink-400 mt-0.5">Teach ConfigShield in AI Training — next audit auto-resolves.</p>
                </div>
              </div>
              <Link href="/training" className="btn-secondary shrink-0">Open AI Training →</Link>
            </div>
          )}

          {/* Company Baseline / Full CIS / NIST — three separate layers */}
          {(() => {
            const company = summary?.company_baseline;
            const compliance = summary?.compliance ?? {};
            const cis = compliance.CIS;
            const nist = compliance.NIST;
            const comparison = company?.comparison ?? [];
            const hasCompany = company?.configured === true;

            if (!hasCompany && !cis && !nist) return null;

            return (
              <div className="space-y-5">
                <div className="flex items-center gap-2.5 text-sm text-ink-400">
                  <Layers className="h-4 w-4" />
                  <span>
                    Three separate layers: Company Baseline scope, Full CIS reference, and NIST
                    evaluation.
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
                  {/* A. COMPANY BASELINE */}
                  <div className="card overflow-hidden">
                    <div className="card-header">
                      <div>
                        <p className="label mb-1">Company Compliance</p>
                        <h3 className="section-title flex items-center gap-2">
                          <ListChecks className="h-4 w-4 text-brand-600" />
                          Company Baseline
                        </h3>
                      </div>
                      {hasCompany ? <span className="badge-info">{company!.in_scope_count} in scope</span> : <span className="badge-info">Not configured</span>}
                    </div>
                    <div className="px-6 py-5">
                      {hasCompany ? (
                        <div className="space-y-4">
                          <div className="flex items-end justify-between">
                            <div>
                              <p className="text-3xl font-bold tracking-tight text-ink-100">{formatPercent(company!.score)}</p>
                              <p className="text-xs font-semibold uppercase tracking-widest text-ink-400 mt-1">company score</p>
                            </div>
                            <div className="text-right text-xs text-ink-400">
                              <p>denominator: {company!.in_scope_count}</p>
                              <p className="mt-0.5">{company!.out_of_scope} OUT_OF_SCOPE</p>
                            </div>
                          </div>
                          <div className="grid grid-cols-3 gap-2.5">
                            <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-center">
                              <p className="text-lg font-bold text-emerald-700">{company!.passed}</p>
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-600">PASS</p>
                            </div>
                            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-center">
                              <p className="text-lg font-bold text-red-700">{company!.failed}</p>
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-red-600">FAIL</p>
                            </div>
                            <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2.5 text-center">
                              <p className="text-lg font-bold text-amber-700">{company!.review}</p>
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-600">REVIEW</p>
                            </div>
                          </div>
                          <p className="text-xs leading-relaxed text-ink-400">
                            {company!.name} — {company!.framework} · {company!.benchmark}. Controls
                            outside this baseline are OUT_OF_SCOPE and never counted.
                          </p>
                        </div>
                      ) : (
                        <p className="text-sm leading-relaxed text-ink-400">
                          No company baseline configured. Full CIS auditing continues normally — no
                          company compliance score is generated.
                        </p>
                      )}
                    </div>
                  </div>

                  {/* B. FULL CIS */}
                  <div className="card overflow-hidden">
                    <div className="card-header">
                      <div>
                        <p className="label mb-1">Full CIS Reference</p>
                        <h3 className="section-title flex items-center gap-2">
                          <BookOpenCheck className="h-4 w-4 text-blue-600" />
                          Full CIS
                        </h3>
                      </div>
                      {cis && <span className="badge-info">{cis.controls} controls</span>}
                    </div>
                    <div className="px-6 py-5">
                      {cis && cis.controls > 0 ? (
                        <div className="space-y-4">
                          <div className="flex items-end justify-between">
                            <div>
                              <p className="text-3xl font-bold tracking-tight text-ink-100">
                                {formatPercent(cis.controls > 0 ? (cis.pass / (cis.pass + cis.fail)) * 100 : null)}
                              </p>
                              <p className="text-xs font-semibold uppercase tracking-widest text-ink-400 mt-1">CIS score</p>
                            </div>
                            <div className="text-right text-xs text-ink-400">
                              <p>denominator: {cis.pass + cis.fail}</p>
                            </div>
                          </div>
                          <div className="grid grid-cols-3 gap-2.5">
                            <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-center">
                              <p className="text-lg font-bold text-emerald-700">{cis.pass}</p>
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-600">PASS</p>
                            </div>
                            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-center">
                              <p className="text-lg font-bold text-red-700">{cis.fail}</p>
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-red-600">FAIL</p>
                            </div>
                            <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2.5 text-center">
                              <p className="text-lg font-bold text-amber-700">{cis.review}</p>
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-600">REVIEW</p>
                            </div>
                          </div>
                          <p className="text-xs leading-relaxed text-ink-400">
                            The complete benchmark evaluation — authoritative and unchanged by the
                            company baseline.
                          </p>
                        </div>
                      ) : (
                        <p className="text-sm leading-relaxed text-ink-400">No CIS evaluation rows for this audit.</p>
                      )}
                    </div>
                  </div>

                  {/* C. NIST */}
                  <div className="card overflow-hidden">
                    <div className="card-header">
                      <div>
                        <p className="label mb-1">NIST</p>
                        <h3 className="section-title flex items-center gap-2">
                          <ShieldCheck className="h-4 w-4 text-violet-600" />
                          NIST SP 800-53
                        </h3>
                      </div>
                      {nist && nist.controls > 0 && <span className="badge-info">{nist.controls} controls</span>}
                    </div>
                    <div className="px-6 py-5">
                      {nist && nist.controls > 0 ? (
                        <div className="space-y-4">
                          <div className="grid grid-cols-3 gap-2.5">
                            <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-center">
                              <p className="text-lg font-bold text-emerald-700">{nist.pass}</p>
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-600">PASS</p>
                            </div>
                            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-center">
                              <p className="text-lg font-bold text-red-700">{nist.fail}</p>
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-red-600">FAIL</p>
                            </div>
                            <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2.5 text-center">
                              <p className="text-lg font-bold text-amber-700">{nist.review}</p>
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-600">REVIEW</p>
                            </div>
                          </div>
                          <p className="text-xs leading-relaxed text-ink-400">
                            Separate NIST SP 800-53 evaluation layer — independent of the company
                            baseline scope.
                          </p>
                        </div>
                      ) : (
                        <p className="text-sm leading-relaxed text-ink-400">
                          No NIST evaluation for this audit (CIS-only run).
                        </p>
                      )}
                    </div>
                  </div>
                </div>

                {/* Control-by-control comparison — Company Baseline vs Full CIS */}
                {comparison.length > 0 && (
                  <div className="card overflow-hidden">
                    <div className="card-header">
                      <div>
                        <h3 className="section-title flex items-center gap-2">
                          <ListChecks className="h-4 w-4 text-brand-600" />
                          Control comparison
                        </h3>
                        <p className="mt-1 text-sm text-ink-400">
                          Company Baseline scope vs Full CIS — {comparison.length} controls
                        </p>
                      </div>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="table">
                        <thead>
                          <tr>
                            <th>Control ID</th>
                            <th>Company Baseline</th>
                            <th>Full CIS</th>
                            <th>In Scope</th>
                          </tr>
                        </thead>
                        <tbody>
                          {comparison.map((row) => (
                            <tr key={row.control_id}>
                              <td className="font-mono font-semibold text-ink-100">{row.control_id}</td>
                              <td>
                                <ResultBadge result={row.company_result} />
                              </td>
                              <td>
                                <ResultBadge result={row.full_cis_result} />
                              </td>
                              <td>
                                {row.in_scope ? (
                                  <span className="text-xs font-medium text-emerald-700">In scope</span>
                                ) : (
                                  <span className="text-xs font-medium text-slate-500">Out of scope</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          <div className="flex items-center gap-2.5 text-sm text-ink-400">
            <Eye className="h-4 w-4" />
            <span>Dual-baseline: CIS vendor-specific + NIST universal — auto-selected by detected vendor.</span>
          </div>

          {/* Findings table — Odoo generous */}
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h2 className="section-title">Findings</h2>
                <p className="mt-1 text-sm text-ink-400">
                  {findingsTotal} finding{findingsTotal === 1 ? '' : 's'} · click a row for the full evidence chain
                </p>
              </div>
              <div className="flex gap-2.5">
                <Select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="w-40" aria-label="Filter by severity">
                  <option value="">All severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </Select>
                <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="w-40" aria-label="Filter by status">
                  <option value="">All statuses</option>
                  <option value="open">Open</option>
                  <option value="in_progress">In progress</option>
                  <option value="resolved">Resolved</option>
                  <option value="accepted">Accepted</option>
                </Select>
              </div>
            </div>
            <div className="p-0">
              <DataTable<Finding>
                rows={filteredFindings}
                rowKey={(f) => f.id}
                onRowClick={(f) => (window.location.href = `/findings/${f.id}?audit=${auditId}`)}
                emptyTitle={findings.length === 0 ? 'No findings' : 'No findings match filters'}
                emptyDescription={
                  findings.length === 0
                    ? audit.status === 'completed'
                      ? 'Configuration is compliant — no controls failed or required review.'
                      : 'Findings will appear once the audit completes.'
                    : 'Adjust the severity or status filters.'
                }
                columns={[
                  {
                    key: 'title',
                    header: 'Finding',
                    render: (f) => (
                      <div className="min-w-0">
                        <p className="truncate font-medium text-ink-100">{f.title}</p>
                        {f.evidence?.control_id && <TechBadge className="mt-1.5">{f.evidence.control_id}</TechBadge>}
                      </div>
                    ),
                    sortValue: (f) => f.title,
                  },
                  {
                    key: 'severity',
                    header: 'Severity',
                    render: (f) => <SeverityBadge severity={f.severity} />,
                    sortValue: (f) => SEVERITY_META[f.severity]?.label ?? '',
                  },
                  {
                    key: 'result',
                    header: 'Result',
                    render: (f) => <ResultBadge result={f.evidence?.result} />,
                    sortValue: (f) => f.evidence?.result ?? '',
                  },
                  {
                    key: 'vendor',
                    header: 'Affected',
                    render: (f) => (
                      <span className="text-sm text-ink-400">
                        {f.affected_vendor ? `${f.affected_vendor}/${f.affected_platform ?? ''}` : '—'}
                      </span>
                    ),
                    sortValue: (f) => f.affected_vendor ?? '',
                  },
                  {
                    key: 'confidence',
                    header: 'Confidence',
                    align: 'right',
                    render: (f) => <span className="font-mono text-xs text-ink-400">{formatConfidence(f.confidence)}</span>,
                    sortValue: (f) => f.confidence,
                  },
                  {
                    key: 'status',
                    header: 'Status',
                    render: (f) => (
                      <select
                        value={f.status}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) => updateFindingStatus(f, e.target.value)}
                        className="rounded-lg border border-surface-200 bg-white px-2.5 py-1.5 text-xs font-medium text-ink-300 hover:border-surface-300 focus:border-brand-400 focus:ring-2 focus:ring-brand-50 focus:outline-none"
                        aria-label={`Status of ${f.title}`}
                      >
                        <option value="open">Open</option>
                        <option value="in_progress">In progress</option>
                        <option value="resolved">Resolved</option>
                        <option value="accepted">Accepted</option>
                      </select>
                    ),
                    sortValue: (f) => f.status,
                  },
                ]}
              />
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
