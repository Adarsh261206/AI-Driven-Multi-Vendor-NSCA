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
      subtitle="Generated compliance report artifacts"
      actions={
        <Button variant="secondary" onClick={load} aria-label="Refresh reports">
          <RefreshCw className="h-4 w-4" />
        </Button>
      }
    >
      {error && (
        <div className="mb-5">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      <div className="panel">
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
                <div className="flex items-center gap-2.5">
                  <div className="flex h-7 w-7 items-center justify-center rounded-md border border-base-700 bg-base-900 text-slate-400">
                    <FileText className="h-3.5 w-3.5" />
                  </div>
                  <div className="min-w-0">
                    <a href={`/audit/${r.audit_id}`} className="truncate font-medium text-slate-200 hover:text-accent-300">
                      {r.audit_name}
                    </a>
                    <p className="text-[11px] text-slate-500">{r.id}</p>
                  </div>
                </div>
              ),
              sortValue: (r) => r.audit_name,
            },
            {
              key: 'framework',
              header: 'Framework',
              render: () => <TechBadge>CIS</TechBadge>,
            },
            {
              key: 'overall_score',
              header: 'Score',
              align: 'right',
              render: (r) => (
                <span className="font-mono text-slate-200">{formatPercent(r.overall_score)}</span>
              ),
              sortValue: (r) => r.overall_score,
            },
            {
              key: 'generated_at',
              header: 'Generated',
              render: (r) => <span className="text-xs text-slate-500">{formatDate(r.generated_at)}</span>,
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
                    className="rounded p-1.5 text-slate-500 hover:bg-base-800 hover:text-slate-300"
                    aria-label={`View audit ${r.audit_name}`}
                  >
                    <FileText className="h-3.5 w-3.5" />
                  </a>
                  <button
                    onClick={() => download(r)}
                    disabled={downloading === r.id}
                    className="rounded p-1.5 text-slate-500 hover:bg-base-800 hover:text-accent-300 disabled:opacity-50"
                    aria-label={`Download PDF for ${r.audit_name}`}
                  >
                    <Download className="h-3.5 w-3.5" />
                  </button>
                </div>
              ),
            },
          ]}
        />
      </div>
    </AppShell>
  );
}
