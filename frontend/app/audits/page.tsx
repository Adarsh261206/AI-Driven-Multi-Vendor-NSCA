'use client';

import { useCallback, useEffect, useState } from 'react';
import { Activity, RefreshCw } from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { DataTable } from '@/components/ui/DataTable';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Select } from '@/components/ui/Field';
import { AuditStatusBadge, TechBadge } from '@/components/ui/Badge';
import { PageLoader } from '@/components/ui/Progress';
import { auditsAPI, getApiError } from '@/lib/api';
import { formatDateTime, formatPercent } from '@/lib/format';
import type { Audit, PaginationMeta } from '@/types';

export default function AuditHistoryPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const [audits, setAudits] = useState<Audit[]>([]);
  const [meta, setMeta] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { page, per_page: 20 };
      if (statusFilter) params.status = statusFilter;
      const res = await auditsAPI.list(params);
      setAudits(res.data.items);
      setMeta(res.data.meta);
    } catch (err) {
      setError(getApiError(err, 'Failed to load audits'));
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter]);

  useEffect(() => {
    if (!authLoading) load();
  }, [authLoading, load]);

  if (authLoading) return <PageLoader label="Loading" />;

  return (
    <AppShell
      title="Audit History"
      subtitle="All compliance evaluations"
      actions={
        <button className="btn-secondary" onClick={load} aria-label="Refresh audits">
          <RefreshCw className="h-4 w-4" />
        </button>
      }
    >
      {error && (
        <div className="mb-6">
          <Alert variant="error" onDismiss={() => setError(null)}>{error}
            <div className="mt-3">
              <button className="btn-secondary text-xs px-3.5 py-2" onClick={load}>
                Retry
              </button>
            </div></Alert>
        </div>
      )}

      <div className="mb-6 flex items-center gap-3">
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          className="select w-48"
          aria-label="Filter by status"
        >
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="processing">Processing</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
      </div>

      <div className="card">
        <div className="card-body p-0">
          <DataTable<Audit>
            loading={loading}
            rows={audits}
            rowKey={(a) => a.id}
            onRowClick={(a) => (window.location.href = `/audit/${a.id}`)}
            page={page}
            totalPages={meta?.total_pages}
            total={meta?.total}
            onPageChange={setPage}
            emptyTitle="No audits yet"
            emptyDescription="Run your first audit from the New Audit flow."
            columns={[
              {
                key: 'name',
                header: 'Audit',
                render: (a) => (
                  <div className="flex items-center gap-3">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-surface-100 text-ink-400">
                      <Activity className="h-4 w-4" strokeWidth={1.75} />
                    </div>
                    <div className="min-w-0">
                      <p className="truncate font-semibold text-sm text-ink-100">{a.name}</p>
                      {a.description && <p className="mt-0.5 truncate text-xs text-ink-400">{a.description}</p>}
                    </div>
                  </div>
                ),
                sortValue: (a) => a.name,
              },
              {
                key: 'status',
                header: 'Status',
                render: (a) => <AuditStatusBadge status={a.status} />,
                sortValue: (a) => a.status,
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
                render: (a) => (
                  <span className="font-mono font-semibold text-sm text-ink-300">
                    {a.overall_score != null ? formatPercent(a.overall_score) : '—'}
                  </span>
                ),
                sortValue: (a) => a.overall_score ?? -1,
              },
              {
                key: 'findings_count',
                header: 'Findings',
                align: 'right',
                render: (a) => (
                  <span className="font-mono text-sm">
                    {a.findings_count}
                    {a.critical_findings > 0 && (
                      <span className="ml-1 text-red-600 font-semibold">({a.critical_findings} crit)</span>
                    )}
                  </span>
                ),
                sortValue: (a) => a.findings_count,
              },
              {
                key: 'configuration_count',
                header: 'Configs',
                align: 'right',
                render: (a) => <span className="font-mono text-sm text-ink-400">{a.configuration_count}</span>,
                sortValue: (a) => a.configuration_count,
              },
              {
                key: 'created_at',
                header: 'Run',
                render: (a) => <span className="text-xs text-ink-400">{formatDateTime(a.created_at)}</span>,
                sortValue: (a) => a.created_at,
              },
            ]}
          />
        </div>
      </div>
    </AppShell>
  );
}
