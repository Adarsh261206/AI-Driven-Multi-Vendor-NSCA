'use client';

import { Suspense, useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ArrowLeft,
  CheckCircle2,
  PlayCircle,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { PageLoader } from '@/components/ui/Progress';
import { cn } from '@/lib/utils';
import {
  auditExecutionAPI,
  baselinesAPI,
  bulkAPI,
  devicesAPI,
  getApiError,
  request,
} from '@/lib/api';
import { formatDateTime } from '@/lib/format';
import type {
  AuditBatchResponse,
  BaselineStatusResponse,
  BulkAuditItemResult,
  Device,
} from '@/types';

interface BulkTarget {
  device: Device;
  configId: string | null;
  configFilename: string | null;
  resolveError: string | null;
}

type ItemState = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

function auditState(status: string): ItemState {
  const s = (status || '').toLowerCase();
  if (s === 'completed') return 'completed';
  if (s === 'failed') return 'failed';
  if (s === 'cancelled' || s === 'cancel_requested') return 'cancelled';
  if (s === 'processing' || s === 'running') return 'running';
  if (s === 'queued') return 'queued';
  return 'pending';
}

function stateBadge(state: ItemState) {
  if (state === 'completed') {
    return (
      <span className="badge-pass inline-flex items-center gap-1.5">
        <CheckCircle2 className="h-3.5 w-3.5" />
        Completed
      </span>
    );
  }
  if (state === 'failed') {
    return (
      <span className="badge-critical inline-flex items-center gap-1.5">
        <XCircle className="h-3.5 w-3.5" />
        Failed
      </span>
    );
  }
  if (state === 'cancelled') {
    return (
      <span className="badge-info inline-flex items-center gap-1.5">
        <XCircle className="h-3.5 w-3.5" />
        Cancelled
      </span>
    );
  }
  if (state === 'running') {
    return (
      <span className="badge-info inline-flex items-center gap-1.5">
        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-surface-200 border-t-brand-600" />
        Running
      </span>
    );
  }
  if (state === 'queued') {
    return <span className="badge-info">Queued</span>;
  }
  return <span className="badge-info">Pending</span>;
}

export default function BulkAuditPage() {
  return (
    <Suspense fallback={<PageLoader label="Loading bulk audit" />}>
      <BulkAuditFlow />
    </Suspense>
  );
}

function BulkAuditFlow() {
  const { isLoading: authLoading } = useRequireAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const batchParam = searchParams.get('batch');

  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [loadingDevices, setLoadingDevices] = useState(true);
  const [devicesError, setDevicesError] = useState<string | null>(null);
  const [baseline, setBaseline] = useState<BaselineStatusResponse | null>(null);

  const [resolving, setResolving] = useState(false);
  const [targets, setTargets] = useState<BulkTarget[] | null>(null);
  const [resolveError, setResolveError] = useState<string | null>(null);

  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [executions, setExecutions] = useState<BulkAuditItemResult[] | null>(null);
  const [batch, setBatch] = useState<AuditBatchResponse | null>(null);
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [states, setStates] = useState<Record<string, ItemState>>({});
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadDevices = useCallback(async () => {
    setLoadingDevices(true);
    setDevicesError(null);
    try {
      const [devRes, baseRes] = await Promise.all([
        request(() => devicesAPI.list({ per_page: 100 }), 'Unable to load devices.'),
        request(() => baselinesAPI.status(), 'Unable to load Company Baseline.'),
      ]);
      setDevices(devRes.items || []);
      setBaseline(baseRes);
    } catch (err) {
      setDevicesError(err instanceof Error ? err.message : 'Unable to load devices.');
    } finally {
      setLoadingDevices(false);
    }
  }, []);

  useEffect(() => {
    if (!authLoading) loadDevices();
  }, [authLoading, loadDevices]);

  useEffect(() => () => {
    if (pollRef.current) clearInterval(pollRef.current);
  }, []);

  const loadBatch = useCallback(async (id: string) => {
    setBatchLoading(true);
    setBatchError(null);
    try {
      const res = await request(() => bulkAPI.getBatch(id), 'Unable to load batch.');
      setBatch(res);
      const initial: Record<string, ItemState> = {};
      (res.items || []).forEach((it) => {
        initial[it.audit_id] = auditState(it.execution_status || it.status);
      });
      setStates(initial);
    } catch (err) {
      setBatchError(err instanceof Error ? err.message : 'Unable to load batch.');
    } finally {
      setBatchLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!authLoading && batchParam && !batch && !batchLoading) void loadBatch(batchParam);
  }, [authLoading, batchParam, batch, batchLoading, loadBatch]);

  const toggle = (id: string) => {
    setSelected((prev) => (prev.includes(id) ? prev.filter((d) => d !== id) : [...prev, id]));
    setTargets(null);
  };

  const resolveTargets = async () => {
    if (selected.length === 0 || resolving) return;
    setResolving(true);
    setResolveError(null);
    setTargets(null);
    try {
      const byId = new Map(devices.map((d) => [d.id, d]));
      const rows: BulkTarget[] = await Promise.all(
        selected.map(async (deviceId) => {
          const device = byId.get(deviceId);
          if (!device) {
            return {
              device: { id: deviceId, name: deviceId } as Device,
              configId: null,
              configFilename: null,
              resolveError: 'Device no longer listed.',
            };
          }
          try {
            const res = await request(
              () => devicesAPI.listConfigurations(deviceId, { per_page: 5 }),
              `Unable to resolve configuration for ${device.name}.`
            );
            const latest = (res.items || []).find((c) => c.latest) ?? (res.items || [])[0] ?? null;
            if (!latest) {
              return { device, configId: null, configFilename: null, resolveError: 'No configuration snapshots — upload one first.' };
            }
            return { device, configId: latest.id, configFilename: latest.filename, resolveError: null };
          } catch (err) {
            return {
              device,
              configId: null,
              configFilename: null,
              resolveError: err instanceof Error ? err.message : 'Resolution failed.',
            };
          }
        })
      );
      setTargets(rows);
    } finally {
      setResolving(false);
    }
  };

  const validTargets = (targets ?? []).filter((t) => t.configId && !t.resolveError);
  const canStart = validTargets.length > 0 && !starting && !executions;

  const start = async () => {
    if (!canStart) return;
    setStarting(true);
    setStartError(null);
    try {
      const stamp = new Date().toISOString().slice(0, 16).replace('T', ' ');
      const res = await request(
        () =>
          bulkAPI.executeAudits(
            validTargets.map((t) => ({
              name: `${t.device.name} — bulk audit ${stamp}`,
              configuration_ids: [t.configId as string],
              device_ids: [t.device.id],
              framework: 'CIS',
              framework_version: '2024.1',
            }))
          ),
        'Bulk audit failed to start'
      );
      if (res.batch_id) {
        router.push(`/audit/bulk?batch=${res.batch_id}`);
        return;
      }
      // Fallback (batch persistence unavailable): local-only tracking.
      const initial: Record<string, ItemState> = {};
      res.audits.forEach((a) => {
        initial[a.audit_id] = 'pending';
      });
      setStates(initial);
      setExecutions(res.audits);
    } catch (err) {
      setStartError(err instanceof Error ? err.message : 'Bulk audit failed to start');
    } finally {
      setStarting(false);
    }
  };

  // One interval polls every unresolved audit via the existing status
  // endpoint. States come from the backend — never timers, never faked.
  // Tracked IDs come from the persistent batch (refresh-safe) or from the
  // just-started local response as fallback.
  const trackedIds: string[] =
    batch != null
      ? (batch.items || []).map((it) => it.audit_id)
      : (executions ?? []).map((ex) => ex.audit_id);
  useEffect(() => {
    if (trackedIds.length === 0) return;
    const tick = async () => {
      let changed = false;
      const next: Record<string, ItemState> = {};
      await Promise.all(
        trackedIds.map(async (auditId) => {
          try {
            const res = await auditExecutionAPI.getStatus(auditId);
            const exec = (res.data as { execution?: { status?: string } | null }).execution;
            next[auditId] = auditState(exec?.status ?? res.data.status);
          } catch {
            next[auditId] = states[auditId] ?? 'pending';
          }
          if (next[auditId] !== states[auditId]) changed = true;
        })
      );
      if (changed) setStates(next);
      if (
        Object.values(next).every(
          (s) => s === 'completed' || s === 'failed' || s === 'cancelled'
        )
      ) {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    };
    void tick();
    pollRef.current = setInterval(() => void tick(), 800);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batch, executions]);

  if (authLoading || loadingDevices) return <PageLoader label="Loading bulk audit" />;

  const inProgressView = batch != null || executions != null;
  const progressRows: { audit_id: string; name: string }[] =
    batch != null
      ? (batch.items || []).map((it) => ({ audit_id: it.audit_id, name: it.name }))
      : (executions ?? []).map((ex) => ({ audit_id: ex.audit_id, name: ex.name }));
  const isTerminal = (s: ItemState) => s === 'completed' || s === 'failed' || s === 'cancelled';
  const resolved = inProgressView
    ? progressRows.filter((r) => isTerminal(states[r.audit_id] ?? 'pending')).length
    : 0;
  const completedCount = inProgressView
    ? progressRows.filter((r) => (states[r.audit_id] ?? 'pending') === 'completed').length
    : 0;
  const failedCount = inProgressView
    ? progressRows.filter((r) => (states[r.audit_id] ?? 'pending') === 'failed').length
    : 0;
  const cancelledCount = inProgressView
    ? progressRows.filter((r) => (states[r.audit_id] ?? 'pending') === 'cancelled').length
    : 0;

  return (
    <AppShell
      title="Bulk Audit"
      subtitle="Audit many devices at once — each device gets its own independent audit of its latest snapshot"
      actions={
        <Link href="/devices">
          <button className="btn-secondary">
            <ArrowLeft className="h-4 w-4" />
            Devices
          </button>
        </Link>
      }
    >
      {devicesError && (
        <div className="mb-6">
          <Alert variant="error" title="Unable to load devices" onDismiss={() => setDevicesError(null)}>
            {devicesError}
          </Alert>
        </div>
      )}
      {startError && (
        <div className="mb-6">
          <Alert variant="error" title="Bulk audit failed to start" onDismiss={() => setStartError(null)}>
            {startError}
          </Alert>
        </div>
      )}

      <div className="max-w-4xl space-y-6">
        {batchLoading ? (
          <PageLoader label="Loading batch" />
        ) : batchError ? (
          <Alert variant="error" title="Unable to load batch" onDismiss={() => setBatchError(null)}>
            {batchError}
          </Alert>
        ) : !inProgressView ? (
          <>
            {/* Device selection */}
            <div className="card overflow-hidden">
              <div className="card-header">
                <div>
                  <h3 className="section-title">Select devices</h3>
                  <p className="mt-1 text-sm text-ink-400">
                    {selected.length} selected · only active devices with snapshots can run
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    className="btn-secondary text-xs px-3.5 py-2"
                    onClick={() =>
                      setSelected(devices.filter((d) => (d.configuration_count ?? 0) > 0).map((d) => d.id))
                    }
                  >
                    Select all ready
                  </button>
                  <button className="btn-secondary text-xs px-3.5 py-2" onClick={() => { setSelected([]); setTargets(null); }}>
                    Clear
                  </button>
                </div>
              </div>
              <div className="divide-y divide-surface-100">
                {devices.map((d) => {
                  const ready = (d.configuration_count ?? 0) > 0;
                  return (
                    <label
                      key={d.id}
                      className={cn(
                        'flex items-center gap-4 px-6 py-4 transition-colors',
                        ready ? 'cursor-pointer hover:bg-surface-50/70' : 'opacity-60'
                      )}
                    >
                      <input
                        type="checkbox"
                        checked={selected.includes(d.id)}
                        disabled={!ready}
                        onChange={() => toggle(d.id)}
                        className="h-4 w-4 shrink-0 rounded border-surface-300 accent-brand-600"
                        aria-label={`Select ${d.name} for bulk audit`}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-semibold text-ink-100">{d.name}</p>
                        <p className="mt-0.5 text-xs text-ink-400">
                          {[d.vendor, d.platform].filter(Boolean).join(' · ') || 'Unknown vendor'}
                          {' · '}
                          {ready
                            ? `${d.configuration_count} snapshot${(d.configuration_count ?? 0) === 1 ? '' : 's'}`
                            : 'No snapshots — upload first'}
                        </p>
                      </div>
                      {!ready && <span className="badge-info shrink-0">No config</span>}
                    </label>
                  );
                })}
                {devices.length === 0 && (
                  <p className="px-6 py-8 text-center text-sm text-ink-400">
                    No active devices. Register devices and upload configurations first.
                  </p>
                )}
              </div>
              <div className="flex items-center justify-end gap-3 border-t border-surface-100 px-6 py-4">
                <Button onClick={resolveTargets} loading={resolving} disabled={selected.length === 0}>
                  Review selection
                </Button>
              </div>
            </div>

            {/* Review */}
            {resolveError && (
              <Alert variant="error" title="Resolution failed" onDismiss={() => setResolveError(null)}>
                {resolveError}
              </Alert>
            )}
            {targets && (
              <div className="card overflow-hidden">
                <div className="card-header">
                  <div>
                    <h3 className="section-title">Review</h3>
                    <p className="mt-1 text-sm text-ink-400">
                      Each device audits its latest snapshot · baseline resolves server-side per audit
                    </p>
                  </div>
                </div>
                <div className="divide-y divide-surface-100">
                  {targets.map((t) => (
                    <div key={t.device.id} className="flex items-center gap-4 px-6 py-4">
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-semibold text-ink-100">{t.device.name}</p>
                        {t.resolveError || !t.configId ? (
                          <p className="mt-0.5 text-xs text-red-600">
                            {t.resolveError ?? 'No snapshot available.'}
                          </p>
                        ) : (
                          <p className="mt-0.5 truncate font-mono text-xs text-ink-400" title={t.configFilename ?? ''}>
                            {t.configFilename}
                          </p>
                        )}
                      </div>
                      {t.configId && !t.resolveError ? (
                        <span className="badge-pass shrink-0">Ready</span>
                      ) : (
                        <span className="badge-critical shrink-0">Excluded</span>
                      )}
                    </div>
                  ))}
                </div>
                <div className="border-t border-surface-100 px-6 py-4">
                  <div className="mb-4 flex items-start gap-3 rounded-xl border border-surface-200 bg-surface-50 px-4 py-3">
                    <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-brand-600" />
                    <p className="text-xs leading-relaxed text-ink-400">
                      {baseline?.baseline_status === 'ACTIVE' && baseline.baseline ? (
                        <>
                          Company Baseline <span className="font-semibold text-ink-200">{baseline.baseline.name}</span>{' '}
                          ({baseline.baseline.control_count} controls) applies automatically to every audit.
                        </>
                      ) : (
                        <>No Company Baseline configured — audits run Full CIS. Resolved server-side; nothing to select.</>
                      )}
                    </p>
                  </div>
                  <div className="flex items-center justify-end">
                    <Button onClick={start} loading={starting} disabled={!canStart}>
                      <PlayCircle className="h-4 w-4" />
                      Start {validTargets.length} audit{validTargets.length === 1 ? '' : 's'}
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </>
        ) : (
          /* Progress — aggregated from real per-audit states, never timers.
             Loaded from the persistent batch, so refresh/navigation is safe. */
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h3 className="section-title">Bulk audit — {progressRows.length} devices</h3>
                <p className="mt-1 text-sm text-ink-400">
                  {completedCount} completed · {failedCount} failed
                  {cancelledCount > 0 && ` · ${cancelledCount} cancelled`} · {resolved}/{progressRows.length} resolved
                  {resolved < progressRows.length && ' · live from persisted state — safe to refresh'}
                </p>
              </div>
              <Link href="/audits" className="btn-secondary text-xs px-3.5 py-2 shrink-0">
                Audit History
              </Link>
            </div>
            <div className="divide-y divide-surface-100">
              {progressRows.map((row) => {
                const st = states[row.audit_id] ?? 'pending';
                return (
                  <div key={row.audit_id} className="flex items-center gap-4 px-6 py-4">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-semibold text-ink-100">{row.name}</p>
                      <p className="mt-0.5 font-mono text-xs text-ink-400">{row.audit_id}</p>
                    </div>
                    {stateBadge(st)}
                    {isTerminal(st) && (
                      <Link
                        href={`/audit/${row.audit_id}`}
                        className="btn-secondary shrink-0 text-xs px-3.5 py-2"
                      >
                        {st === 'completed' ? 'Open Report' : 'Open Audit'}
                      </Link>
                    )}
                  </div>
                );
              })}
            </div>
            {resolved === progressRows.length && progressRows.length > 0 && (
              <div className="border-t border-surface-100 px-6 py-4">
                <Alert
                  variant={failedCount === 0 && cancelledCount === 0 ? 'success' : 'warning'}
                  title={
                    failedCount === 0 && cancelledCount === 0
                      ? 'All audits completed'
                      : 'Batch finished'
                  }
                >
                  {completedCount} completed, {failedCount} failed
                  {cancelledCount > 0 && `, ${cancelledCount} cancelled`}. Each audit keeps its
                  own findings and report — failed items never alter completed ones.
                </Alert>
              </div>
            )}
          </div>
        )}
      </div>
    </AppShell>
  );
}
