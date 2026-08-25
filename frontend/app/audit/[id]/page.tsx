'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Download,
  Eye,
  FileText,
  RefreshCw,
  XCircle,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { StatCard } from '@/components/ui/StatCard';
import { DataTable } from '@/components/ui/DataTable';
import { Select } from '@/components/ui/Field';
import { ResultBadge, SeverityBadge, FindingStatusBadge, TechBadge, AuditStatusBadge } from '@/components/ui/Badge';
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

  // Poll while running
  useEffect(() => {
    if (!execStatus || !['pending', 'processing'].includes(execStatus.status)) return;
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [execStatus, load]);

  const updateFindingStatus = async (finding: Finding, status: string) => {
    try {
      await request(() => findingsAPI.updateStatus(finding.id, status), 'Failed to update status');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update finding status');
    }
  };

  const downloadPdf = async () => {
    setDownloading(true);
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
          <Button variant="ghost" onClick={load} aria-label="Refresh">
            <RefreshCw className="h-4 w-4" />
          </Button>
        </>
      }
    >
      {error && (
        <div className="mb-5">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      {/* Running progress view */}
      {running && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                <AuditStatusBadge status={audit.status} />
                Audit pipeline
              </h2>
              <p className="mt-0.5 text-xs text-slate-500">
                {audit.status === 'pending'
                  ? 'Queued — the pipeline will begin shortly.'
                  : 'Processing configuration through the compliance pipeline.'}
              </p>
            </div>
            <div className="text-right">
              <p className="font-mono text-lg font-semibold text-accent-300">{execStatus?.progress ?? 0}%</p>
            </div>
          </div>
          <div className="panel-body">
            <ProgressBar value={execStatus?.progress ?? 0} color="#22d3ee" className="mb-6" showLabel />
            <ol className="space-y-0.5">
              {PIPELINE_STEPS.map((step, i) => {
                const idx = i < 3 ? (audit.status === 'processing' ? 2 : 0) : i;
                const isDone = audit.status === 'processing' ? i < 3 : i < idx;
                const isCurrent = audit.status === 'processing' ? i === 2 : false;
                return (
                  <li
                    key={step}
                    className="flex items-center gap-3 rounded-md px-2.5 py-1.5 text-sm"
                    aria-current={isCurrent ? 'step' : undefined}
                  >
                    {isDone ? (
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                    ) : isCurrent ? (
                      <div className="h-4 w-4 animate-spin rounded-full border-2 border-base-600 border-t-accent-500" />
                    ) : (
                      <span className="h-4 w-4 rounded-full border border-base-600" />
                    )}
                    <span className={isDone ? 'text-slate-400' : isCurrent ? 'font-medium text-slate-100' : 'text-slate-600'}>
                      {STEP_LABELS[step]}
                    </span>
                  </li>
                );
              })}
            </ol>
          </div>
        </div>
      )}

      {/* Completed / failed result view */}
      {!running && (
        <>
          {/* Summary metrics */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            <StatCard
              label="Security Score"
              value={formatPercent(audit.overall_score)}
              sub={
                <span className="inline-flex items-center gap-1.5">
                  <span className="rounded bg-base-800 px-1.5 py-0.5 text-[10px] uppercase">{audit.status}</span>
                  {audit.completed_at && audit.started_at && (
                    <span>{formatDuration(audit.started_at, audit.completed_at)}</span>
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

          {/* PASS / FAIL / REVIEW summary */}
          <div className="mt-5 grid grid-cols-3 gap-4">
            {(['PASS', 'FAIL', 'REVIEW'] as const).map((r) => {
              const colors = {
                PASS: { bg: 'rgba(34,197,94,0.08)', border: 'rgba(34,197,94,0.3)', color: '#22c55e' },
                FAIL: { bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.3)', color: '#ef4444' },
                REVIEW: { bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.3)', color: '#f59e0b' },
              }[r];
              return (
                <div
                  key={r}
                  className="flex items-center justify-between rounded-lg border px-4 py-3"
                  style={{ backgroundColor: colors.bg, borderColor: colors.border }}
                >
                  <span className="flex items-center gap-2 text-sm font-semibold" style={{ color: colors.color }}>
                    {r === 'PASS' ? <CheckCircle2 className="h-4 w-4" /> : r === 'FAIL' ? <XCircle className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    {r}
                  </span>
                  <span className="font-mono text-sm text-slate-300">
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

          {/* Findings table */}
          <div className="mt-5 panel">
            <div className="panel-header">
              <div>
                <h2 className="text-sm font-semibold text-slate-200">Findings</h2>
                <p className="mt-0.5 text-xs text-slate-500">
                  {findingsTotal} finding{findingsTotal === 1 ? '' : 's'} · click a row for the full evidence chain
                </p>
              </div>
              <div className="flex gap-2">
                <Select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="w-36" aria-label="Filter by severity">
                  <option value="">All severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </Select>
                <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="w-36" aria-label="Filter by status">
                  <option value="">All statuses</option>
                  <option value="open">Open</option>
                  <option value="in_progress">In progress</option>
                  <option value="resolved">Resolved</option>
                  <option value="accepted">Accepted</option>
                </Select>
              </div>
            </div>
            <div className="panel-body p-0">
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
                        <p className="truncate font-medium text-slate-200">{f.title}</p>
                        {f.evidence?.control_id && <TechBadge className="mt-1">{f.evidence.control_id}</TechBadge>}
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
                      <span className="text-xs text-slate-400">
                        {f.affected_vendor ? `${f.affected_vendor}/${f.affected_platform ?? ''}` : '—'}
                      </span>
                    ),
                    sortValue: (f) => f.affected_vendor ?? '',
                  },
                  {
                    key: 'confidence',
                    header: 'Confidence',
                    align: 'right',
                    render: (f) => <span className="font-mono text-xs text-slate-400">{formatConfidence(f.confidence)}</span>,
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
                        className="field !w-auto !py-1 text-xs"
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
        </>
      )}
    </AppShell>
  );
}
