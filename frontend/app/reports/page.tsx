'use client';

import { useCallback, useEffect, useState } from 'react';
import { Download, FileText, RefreshCw } from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { DataTable } from '@/components/ui/DataTable';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { TechBadge } from '@/components/ui/Badge';
import { PageLoader } from '@/components/ui/Progress';
import { reportsAPI, getApiError } from '@/lib/api';
import { formatDate, formatPercent } from '@/lib/format';
import type { Report } from '@/types';

export default function ReportsPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const [reports, setReports] = useState<Report[]>([]);
  const [meta, setMeta] = useState<{ total: number; total_pages: number; page: number } | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await reportsAPI.list({ page, per_page: 20 });
      setReports(res.data.items || []);
      setMeta(res.data.meta ?? null);
    } catch (err) {
      setError(getApiError(err, 'Failed to load reports'));
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    if (!authLoading) load();
  }, [authLoading, load]);

  const download = async (report: Report) => {
    setDownloading(report.id);
    setError(null);
    try {
      const { default: api } = await import('@/lib/api');
      const res = await api.get(`/reports/${report.audit_id}/report`, {
        params: { format: 'pdf' },
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `audit-report-${report.audit_id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(getApiError(err, 'Failed to download report'));
    } finally {
      setDownloading(null);
    }
  };

  if (authLoading) return <PageLoader label="Loading reports" />;

  return (
    <AppShell
      title="Reports"
      subtitle="Generated compliance report artifacts — PDF exports from completed audits"
      actions={
        <button className="btn-secondary" onClick={load} aria-label="Refresh reports">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-6">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
            <div className="mt-3">
              <button className="btn-secondary text-xs px-3.5 py-2" onClick={load}>
                Retry
              </button>
            </div>
          </Alert>
        </div>
      )}

      {/* Summary strip — Odoo airy */}
      <div className="mb-6 flex items-center gap-3 text-xs text-ink-400">
        <span className="inline-flex items-center gap-2 rounded-full bg-white px-3 py-1.5 ring-1 ring-surface-200 shadow-xs">
          <FileText className="h-3.5 w-3.5" />
          {meta?.total != null ? `${meta.total} reports` : 'Reports'}
        </span>
        <span className="hidden sm:inline">Each completed audit automatically produces a PDF report</span>
      </div>

      <div className="card overflow-hidden">
        <div className="card-body p-0">
          <DataTable<Report>
            loading={loading}
            rows={reports}
            rowKey={(r) => r.id}
            page={page}
            totalPages={meta?.total_pages}
            total={meta?.total}
            onPageChange={setPage}
            emptyTitle="No reports yet"
            emptyDescription="Completed audits automatically produce a PDF report."
            columns={[
              {
                key: 'audit_name',
                header: 'Audit',
                render: (r) => (
                  <div className="flex items-center gap-3.5">
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-surface-50 text-ink-400 ring-1 ring-surface-200">
                      <FileText className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <a href={`/audit/${r.audit_id}`} className="truncate text-sm font-semibold text-ink-100 transition-colors duration-150 hover:text-brand-600">
                        {r.audit_name}
                      </a>
                      <p className="font-mono text-xs text-ink-400">{r.id}</p>
                    </div>
                  </div>
                ),
                sortValue: (r) => r.audit_name,
              },
              {
                key: 'framework',
                header: 'Framework',
                render: () => <span className="badge-info">CIS</span>,
              },
              {
                key: 'overall_score',
                header: 'Score',
                align: 'right',
                render: (r) => (
                  <span className="font-mono text-sm font-semibold text-ink-300">{formatPercent(r.overall_score)}</span>
                ),
                sortValue: (r) => r.overall_score,
              },
              {
                key: 'generated_at',
                header: 'Generated',
                render: (r) => <span className="text-xs text-ink-400">{formatDate(r.generated_at)}</span>,
                sortValue: (r) => r.generated_at,
              },
              {
                key: 'actions',
                header: 'Actions',
                align: 'right',
                render: (r) => (
                  <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                    <a
                      href={`/audit/${r.audit_id}`}
                      className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-surface-100 hover:text-ink-300"
                      aria-label={`View audit ${r.audit_name}`}
                    >
                      <FileText className="h-4 w-4" />
                    </a>
                    <button
                      onClick={() => download(r)}
                      disabled={downloading === r.id}
                      className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-brand-50 hover:text-brand-600 disabled:opacity-50"
                      aria-label={`Download PDF for ${r.audit_name}`}
                    >
                      <Download className="h-4 w-4" />
                    </button>
                  </div>
                ),
              },
            ]}
          />
        </div>
      </div>
    </AppShell>
  );
}
