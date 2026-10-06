'use client';

import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, ScrollText } from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { DataTable } from '@/components/ui/DataTable';
import { Alert } from '@/components/ui/Alert';
import { PageLoader } from '@/components/ui/Progress';
import { auditTrailAPI, getApiError } from '@/lib/api';
import { formatDateTime } from '@/lib/format';
import type { AuditTrailEntry } from '@/types';

const ENTITY_TYPES = ['', 'audit', 'finding', 'ai_interaction', 'training_mapping', 'configuration'];

// Closed action vocabulary — mirrors backend AuditAction exactly. If the
// backend enum gains a value, add it here. A dropdown (never free text)
// guarantees only valid actions reach the API, so the 422 contract for
// malformed filters can never trigger from this UI.
const ACTIONS = [
  '',
  'user_login',
  'user_logout',
  'report_generated',
  'audit_created',
  'audit_started',
  'audit_completed',
  'audit_failed',
  'audit_cancelled',
  'config_uploaded',
  'config_validated',
  'config_parsed',
  'compliance_evaluated',
  'finding_created',
  'finding_updated',
  'ai_hypothesis_requested',
  'ai_hypothesis_received',
  'mapping_created',
  'mapping_confirmed',
  'mapping_rejected',
  'mapping_updated',
  'training_completed',
];

function shortId(value: string | null): string {
  if (!value) return '—';
  return value.length > 8 ? `${value.slice(0, 8)}…` : value;
}

function hashCell(value: string | null) {
  if (!value) {
    return (
      <span className="rounded-full bg-surface-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-ink-500" title="Recorded before the hash-chained ledger era; never backfilled">
        pre-chain
      </span>
    );
  }
  return (
    <span className="font-mono text-xs text-ink-300" title={value}>
      {value.length > 12 ? `${value.slice(0, 12)}…` : value}
    </span>
  );
}

export default function AuditLogPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const [entries, setEntries] = useState<AuditTrailEntry[]>([]);
  const [meta, setMeta] = useState<{ total: number; total_pages: number; page: number } | null>(null);
  const [page, setPage] = useState(1);
  const [entityType, setEntityType] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  // Entity filter is set ONLY by clicking an entity ID in the table
  // (cleared via the chip) — never typed. UUIDs are not human-typable,
  // so no textbox exists for this filter and no invalid value can ever
  // be sent.
  const [entityIdFilter, setEntityIdFilter] = useState('');
  // Date range: raw picker values stay local; only committed (blur/Enter
  // with a complete date) values reach the API. Native date inputs only
  // produce "" or full YYYY-MM-DD, so partial typing can never leak a
  // malformed filter — no debounce machinery needed.
  const [fromInput, setFromInput] = useState('');
  const [toInput, setToInput] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Day boundaries in UTC: from-day 00:00 inclusive, to-day+1 00:00
  // exclusive — selecting Oct 4 covers the whole of Oct 4.
  const toExclusive = (day: string): string => {
    const d = new Date(`${day}T00:00:00Z`);
    d.setUTCDate(d.getUTCDate() + 1);
    return d.toISOString().slice(0, 19);
  };

  // A date pair applies only when valid (empty side = unbounded).
  // Invalid pairs keep the previous filter while the hint shows.
  const applyDates = (f: string, t: string) => {
    if (f && t && f > t) return;
    setFromDate(f);
    setToDate(t);
    setPage(1);
  };

  const commitDates = () => applyDates(fromInput.trim(), toInput.trim());

  // Calendar-picker selections always yield complete YYYY-MM-DD values,
  // so they apply instantly; manually typed partials ("" until complete)
  // wait for blur/Enter instead of firing per keystroke.
  const FULL_DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
  const onFromChange = (v: string) => {
    setFromInput(v);
    if (v === '' || FULL_DAY_RE.test(v)) applyDates(v.trim(), toInput.trim());
  };
  const onToChange = (v: string) => {
    setToInput(v);
    if (v === '' || FULL_DAY_RE.test(v)) applyDates(fromInput.trim(), v.trim());
  };

  const rangeInvalid = Boolean(
    fromInput.trim() && toInput.trim() && fromInput.trim() > toInput.trim()
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { page, per_page: 20 };
      if (entityType) params.entity_type = entityType;
      if (actionFilter) params.action = actionFilter;
      if (entityIdFilter) params.entity_id = entityIdFilter;
      if (fromDate) params.from_date = `${fromDate}T00:00:00`;
      if (toDate) params.to_date = toExclusive(toDate);
      const res = await auditTrailAPI.list(params);
      setEntries(res.data.items || []);
      setMeta(res.data.meta ?? null);
    } catch (err) {
      setError(getApiError(err, 'Failed to load audit ledger'));
    } finally {
      setLoading(false);
    }
  }, [page, entityType, actionFilter, entityIdFilter, fromDate, toDate]);

  useEffect(() => {
    if (!authLoading) load();
  }, [authLoading, load]);

  if (authLoading) return <PageLoader label="Loading audit ledger" />;

  return (
    <AppShell
      title="Audit Ledger"
      subtitle="Append-only security history — every record is server-generated and hash-chained"
      actions={
        <button className="btn-secondary" onClick={load} aria-label="Refresh audit ledger">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-6">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      {/* Summary strip */}
      <div className="mb-6 flex items-center gap-3 text-xs text-ink-400">
        <span className="inline-flex items-center gap-2 rounded-full bg-white px-3 py-1.5 ring-1 ring-surface-200 shadow-xs">
          <ScrollText className="h-3.5 w-3.5" />
          {meta?.total != null ? `${meta.total} events` : 'Ledger'}
        </span>
        <span className="hidden sm:inline">Read-only — records cannot be created, edited, or deleted from here</span>
      </div>

      {/* Filters — constrained controls only. Every control produces
          valid values by construction, so no request from this UI can
          ever trip the backend's 422 malformed-filter contract. */}
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <select
          value={entityType}
          onChange={(e) => { setEntityType(e.target.value); setPage(1); }}
          className="select w-48"
          aria-label="Filter by entity type"
        >
          <option value="">All entity types</option>
          {ENTITY_TYPES.filter(Boolean).map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
          className="select w-56"
          aria-label="Filter by action"
        >
          <option value="">All actions</option>
          {ACTIONS.filter(Boolean).map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        {entityIdFilter && (
          <button
            onClick={() => { setEntityIdFilter(''); setPage(1); }}
            className="inline-flex items-center gap-2 rounded-full bg-brand-50 px-3 py-1.5 text-xs font-semibold text-brand-700 ring-1 ring-brand-200"
            aria-label="Clear entity filter"
            title={entityIdFilter}
          >
            <span className="font-mono">entity: {shortId(entityIdFilter)}</span>
            <span aria-hidden="true">✕</span>
          </button>
        )}
        <label className="flex items-center gap-2 text-xs text-ink-400">
          From
          <input
            type="date"
            value={fromInput}
            onChange={(e) => onFromChange(e.target.value)}
            onBlur={commitDates}
            onKeyDown={(e) => { if (e.key === 'Enter') commitDates(); }}
            className="input w-40"
            aria-label="Filter from date"
          />
        </label>
        <label className="flex items-center gap-2 text-xs text-ink-400">
          To
          <input
            type="date"
            value={toInput}
            onChange={(e) => onToChange(e.target.value)}
            onBlur={commitDates}
            onKeyDown={(e) => { if (e.key === 'Enter') commitDates(); }}
            className="input w-40"
            aria-label="Filter to date"
          />
        </label>
        {(fromInput || toInput) && (
          <button
            onClick={() => {
              setFromInput(''); setToInput('');
              setFromDate(''); setToDate(''); setPage(1);
            }}
            className="inline-flex items-center gap-2 rounded-full bg-surface-100 px-3 py-1.5 text-xs font-semibold text-ink-400 ring-1 ring-surface-200"
            aria-label="Clear date range"
          >
            <span>dates{(fromDate || toDate) ? `: ${fromDate || '…'} → ${toDate || '…'}` : ''}</span>
            <span aria-hidden="true">✕</span>
          </button>
        )}
      </div>
      {rangeInvalid && (
        <p className="mb-6 text-xs font-medium text-red-600">
          From date must be on or before To date — date filter not applied.
        </p>
      )}

      <div className="card overflow-hidden">
        <div className="card-body p-0">
          <DataTable<AuditTrailEntry>
            loading={loading}
            rows={entries}
            rowKey={(r) => r.id}
            page={page}
            totalPages={meta?.total_pages}
            total={meta?.total}
            onPageChange={setPage}
            emptyTitle="No ledger events yet"
            emptyDescription="Security-relevant actions will appear here as they happen."
            columns={[
              {
                key: 'created_at',
                header: 'Timestamp',
                render: (r) => <span className="whitespace-nowrap text-xs text-ink-400">{formatDateTime(r.created_at)}</span>,
                sortValue: (r) => r.created_at,
              },
              {
                key: 'action',
                header: 'Action',
                render: (r) => <span className="font-mono text-xs font-semibold text-ink-100">{r.action}</span>,
              },
              {
                key: 'actor',
                header: 'Actor',
                render: (r) => (
                  <span className="font-mono text-xs text-ink-400" title={r.user_id ?? 'system'}>
                    {shortId(r.user_id)}
                  </span>
                ),
              },
              {
                key: 'entity',
                header: 'Entity',
                render: (r) => (
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-ink-300">{r.entity_type}</p>
                    {r.entity_id ? (
                      <button
                        onClick={() => { setEntityIdFilter(r.entity_id as string); setPage(1); }}
                        className="font-mono text-xs text-brand-600 hover:text-brand-700 hover:underline"
                        title={`Filter ledger to entity ${r.entity_id}`}
                        aria-label={`Filter by entity ${r.entity_id}`}
                      >
                        {shortId(r.entity_id)}
                      </button>
                    ) : (
                      <p className="font-mono text-xs text-ink-500">—</p>
                    )}
                  </div>
                ),
              },
              {
                key: 'seq',
                header: 'Seq',
                align: 'right',
                render: (r) => (
                  <span className="font-mono text-sm font-semibold text-ink-300">
                    {r.seq != null ? r.seq : '—'}
                  </span>
                ),
                sortValue: (r) => r.seq ?? -1,
              },
              {
                key: 'previous_hash',
                header: 'Previous Hash',
                render: (r) => hashCell(r.previous_hash),
              },
              {
                key: 'event_hash',
                header: 'Event Hash',
                render: (r) => hashCell(r.event_hash),
              },
            ]}
          />
        </div>
      </div>
    </AppShell>
  );
}
