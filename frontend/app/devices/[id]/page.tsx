'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  AlertTriangle,
  Archive,
  ArchiveRestore,
  ArrowLeft,
  CheckCircle2,
  Eye,
  FileText,
  History,
  ListChecks,
  Network,
  PlayCircle,
  Server,
  Trash2,
  UploadCloud,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Modal } from '@/components/ui/Modal';
import { TechBadge, AuditStatusBadge } from '@/components/ui/Badge';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { EmptyState } from '@/components/ui/EmptyState';
import { PageLoader, Skeleton } from '@/components/ui/Progress';
import {
  configurationsAPI,
  devicesAPI,
  getApiError,
  request,
} from '@/lib/api';
import { formatBytes, formatDate, formatDateTime, formatPercent } from '@/lib/format';
import type {
  Device,
  DeviceAuditHistoryItem,
  DeviceConfigurationHistoryItem,
} from '@/types';

const ACCEPTED = '.txt,.cfg,.conf';

export default function DeviceDetailPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const params = useParams();
  const deviceId = params.id as string;

  const [device, setDevice] = useState<Device | null>(null);
  const [configs, setConfigs] = useState<DeviceConfigurationHistoryItem[]>([]);
  const [configTotal, setConfigTotal] = useState(0);
  const [audits, setAudits] = useState<DeviceAuditHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [auditsLoading, setAuditsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [auditsError, setAuditsError] = useState<string | null>(null);

  // Upload modal state (single snapshot; reuses the existing upload endpoint)
  const [uploadOpen, setUploadOpen] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadDone, setUploadDone] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Viewer modal state (read-only; existing content endpoint)
  const [viewerItem, setViewerItem] = useState<DeviceConfigurationHistoryItem | null>(null);
  const [viewerContent, setViewerContent] = useState<string | null>(null);
  const [viewerLoading, setViewerLoading] = useState(false);
  const [viewerError, setViewerError] = useState<string | null>(null);

  const [unarchiving, setUnarchiving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  // Archive flow (same as inventory: confirm → archive → refresh; history preserved).
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const [archiving, setArchiving] = useState(false);

  // Delete flow (same backend policy as inventory: pristine → 204,
  // history-bearing → 409 with archive guidance).
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const router = useRouter();

  const confirmDelete = async () => {
    setDeleting(true);
    setDeleteError(null);
    try {
      await request(() => devicesAPI.delete(deviceId), 'Failed to delete device');
      setDeleteOpen(false);
      router.push('/devices');
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Failed to delete device');
    } finally {
      setDeleting(false);
    }
  };

  const confirmArchive = async () => {
    setArchiving(true);
    setArchiveError(null);
    try {
      await request(() => devicesAPI.archive(deviceId), 'Failed to archive device');
      setArchiveOpen(false);
      setNotice('Device archived. History preserved.');
      await refreshAll();
    } catch (err) {
      setArchiveError(err instanceof Error ? err.message : 'Failed to archive device');
    } finally {
      setArchiving(false);
    }
  };

  const unarchive = async () => {
    setUnarchiving(true);
    setError(null);
    try {
      await request(() => devicesAPI.unarchive(deviceId), 'Failed to unarchive device');
      setNotice('Device restored to active inventory. History preserved.');
      await refreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unarchive device');
    } finally {
      setUnarchiving(false);
    }
  };

  const loadDevice = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await devicesAPI.get(deviceId);
      setDevice(res.data);
    } catch (err) {
      setError(getApiError(err, 'Device not found'));
    } finally {
      setLoading(false);
    }
  }, [deviceId]);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const res = await request(
        () => devicesAPI.listConfigurations(deviceId, { per_page: 50 }),
        'Unable to load configuration history.'
      );
      setConfigs(res.items || []);
      setConfigTotal(res.meta?.total ?? 0);
    } catch (err) {
      setHistoryError(err instanceof Error ? err.message : 'Unable to load configuration history.');
    } finally {
      setHistoryLoading(false);
    }
  }, [deviceId]);

  const loadAudits = useCallback(async () => {
    setAuditsLoading(true);
    setAuditsError(null);
    try {
      const res = await request(
        () => devicesAPI.listAudits(deviceId, { per_page: 20 }),
        'Unable to load audit history.'
      );
      setAudits(res.items || []);
    } catch (err) {
      setAuditsError(err instanceof Error ? err.message : 'Unable to load audit history.');
    } finally {
      setAuditsLoading(false);
    }
  }, [deviceId]);

  useEffect(() => {
    if (!authLoading) {
      loadDevice();
      loadHistory();
      loadAudits();
    }
  }, [authLoading, loadDevice, loadHistory, loadAudits]);

  const refreshAll = useCallback(async () => {
    await Promise.all([loadDevice(), loadHistory(), loadAudits()]);
  }, [loadDevice, loadHistory, loadAudits]);

  const handleUploadFile = async (file: File | undefined) => {
    if (!file || uploading) return;
    setUploadError(null);
    setUploadDone(null);
    setUploading(true);
    try {
      await request(
        () => configurationsAPI.upload(file, deviceId),
        'Configuration upload failed'
      );
      setUploadDone(`Snapshot "${file.name}" stored. Uploading a new file never overwrites history.`);
      await refreshAll();
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Configuration upload failed');
    } finally {
      setUploading(false);
    }
  };

  const openViewer = async (item?: DeviceConfigurationHistoryItem) => {
    const target = item ?? viewerItem;
    if (!target) return;
    setViewerItem(target);
    setViewerContent(null);
    setViewerError(null);
    setViewerLoading(true);
    try {
      const res = await request(
        () => configurationsAPI.content(target.id),
        'Unable to load configuration content.'
      );
      setViewerContent(res.content);
    } catch (err) {
      setViewerError(err instanceof Error ? err.message : 'Unable to load configuration content.');
    } finally {
      setViewerLoading(false);
    }
  };

  if (authLoading || loading) return <PageLoader label="Loading device" />;

  if (!device) {
    return (
      <AppShell title="Device">
        <Alert variant="error" title="Device not found">
          {error}
        </Alert>
      </AppShell>
    );
  }

  const latest = configs.find((c) => c.latest) ?? configs[0] ?? null;
  const completedAudits = audits.filter((a) => a.status === 'completed');
  const deviceStatus = configs.length === 0
    ? { label: 'Needs Configuration', cls: 'badge-medium' }
    : completedAudits.length === 0
      ? { label: 'Ready to Audit', cls: 'badge-info' }
      : { label: 'Audited', cls: 'badge-pass' };

  return (
    <AppShell
      title={device.name}
      subtitle={`${device.vendor ?? 'Unknown vendor'} · ${device.platform ?? 'unknown platform'}`}
      actions={
        <>
          {!device.is_active && <span className="badge-medium">Archived</span>}
          <span className={deviceStatus.cls}>{deviceStatus.label}</span>
          <Link href="/devices">
            <button className="btn-secondary">
              <ArrowLeft className="h-4 w-4" />
              Devices
            </button>
          </Link>
          {device.is_active ? (
            <>
              <Button variant="secondary" size="sm" onClick={() => setUploadOpen(true)}>
                <UploadCloud className="h-4 w-4" />
                Upload Configuration
              </Button>
              <Link href={`/audit/new?device=${device.id}`}>
                <button className="btn-primary">
                  <PlayCircle className="h-4 w-4" />
                  Run Audit
                </button>
              </Link>
            </>
          ) : (
            <Button variant="secondary" size="sm" onClick={unarchive} loading={unarchiving}>
              <ArchiveRestore className="h-4 w-4" />
              Unarchive
            </Button>
          )}
          <button
            onClick={() => {
              setArchiveError(null);
              setArchiveOpen(true);
            }}
            className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-amber-50 hover:text-amber-600"
            aria-label={`Archive ${device.name}`}
            title={`Archive ${device.name}`}
          >
            <Archive className="h-4 w-4" />
          </button>
          <button
            onClick={() => {
              setDeleteError(null);
              setDeleteOpen(true);
            }}
            className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-red-50 hover:text-red-600"
            aria-label={`Delete ${device.name}`}
            title={`Delete ${device.name}`}
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </>
      }
    >
      {!device.is_active && (
        <div className="mb-6">
          <Alert variant="warning" title="This device is archived">
            Archived devices keep their full configuration and audit history, but cannot accept
            new configurations or audits. Unarchive to resume operations.
          </Alert>
        </div>
      )}
      {error && (
        <div className="mb-6">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}
      {notice && (
        <div className="mb-6">
          <Alert variant="success" onDismiss={() => setNotice(null)}>
            {notice}
          </Alert>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3 stagger-children">
        {/* Identity Card — unchanged */}
        <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
          <div className="card-header">
            <h3 className="section-title flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                <Server className="h-4 w-4" />
              </span>
              Identity
            </h3>
          </div>
          <div className="px-6 py-5">
            <dl className="space-y-4 text-sm">
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Vendor</dt>
                <dd>{device.vendor ? <span className="badge-info">{device.vendor}</span> : <span className="text-ink-400 text-sm">—</span>}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Platform</dt>
                <dd>{device.platform ? <span className="badge-info">{device.platform}</span> : <span className="text-ink-400 text-sm">—</span>}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Firmware</dt>
                <dd className="font-mono text-xs font-medium text-ink-300">{device.firmware_version ?? '—'}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">IP address</dt>
                <dd className="font-mono text-xs font-medium text-ink-300">{device.ip_address ?? '—'}</dd>
              </div>
              <div className="flex items-center justify-between gap-4 border-t border-surface-100 pt-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Registered</dt>
                <dd className="text-xs text-ink-400">{formatDate(device.created_at)}</dd>
              </div>
            </dl>
          </div>
        </div>

        {/* Latest Configuration Card — real data */}
        <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
          <div className="card-header">
            <h3 className="section-title flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-50 text-sky-600 ring-1 ring-sky-100">
                <FileText className="h-4 w-4" />
              </span>
              Latest Configuration
            </h3>
            {latest && <span className="badge-pass">LATEST</span>}
          </div>
          <div className="px-6 py-5">
            {historyLoading ? (
              <div className="space-y-3">
                <Skeleton className="h-5 w-3/4" />
                <Skeleton className="h-4 w-1/2" />
                <Skeleton className="h-9 w-full" />
              </div>
            ) : historyError ? (
              <Alert variant="error" title="Unable to load configuration history">
                {historyError}
                <div className="mt-3">
                  <Button variant="secondary" size="sm" onClick={loadHistory}>
                    Retry
                  </Button>
                </div>
              </Alert>
            ) : !latest ? (
              <div className="text-center">
                <p className="text-sm font-semibold text-ink-100">No configuration uploaded</p>
                <p className="mt-1.5 text-xs leading-relaxed text-ink-400">
                  Upload a configuration snapshot to make this device ready for auditing.
                </p>
                {device.is_active && (
                  <Button size="sm" onClick={() => setUploadOpen(true)} className="mt-4">
                    <UploadCloud className="h-4 w-4" />
                    Upload Configuration
                  </Button>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <p className="truncate font-mono text-sm font-semibold text-ink-100" title={latest.filename}>
                    {latest.filename}
                  </p>
                  <p className="mt-1 text-xs text-ink-400">
                    {formatDateTime(latest.uploaded_at)} · {formatBytes(latest.size_bytes)} · {latest.line_count} lines
                  </p>
                </div>
                <dl className="space-y-2.5 text-sm">
                  <div className="flex items-center justify-between gap-4">
                    <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Checksum</dt>
                    <dd className="font-mono text-xs text-ink-300" title={latest.content_hash}>
                      {latest.content_hash.slice(0, 12)}…
                    </dd>
                  </div>
                  {(latest.detected_vendor || latest.detected_platform) && (
                    <div className="flex items-center justify-between gap-4">
                      <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Detected</dt>
                      <dd className="flex gap-1.5">
                        {latest.detected_vendor && <TechBadge>{latest.detected_vendor}</TechBadge>}
                        {latest.detected_platform && <TechBadge>{latest.detected_platform}</TechBadge>}
                      </dd>
                    </div>
                  )}
                  <div className="flex items-center justify-between gap-4">
                    <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Audits</dt>
                    <dd className="text-sm font-medium text-ink-100">
                      {latest.audit_count === 0 ? 'Never audited' : `${latest.audit_count} audit${latest.audit_count === 1 ? '' : 's'}`}
                    </dd>
                  </div>
                </dl>
                <div className="flex gap-2.5">
                  <Button variant="secondary" size="sm" onClick={() => openViewer(latest)} className="flex-1">
                    <Eye className="h-4 w-4" />
                    View Configuration
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Notes Card — unchanged */}
        <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
          <div className="card-header">
            <h3 className="section-title flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-50 text-amber-600 ring-1 ring-amber-100">
                <Network className="h-4 w-4" />
              </span>
              Notes
            </h3>
          </div>
          <div className="px-6 py-6">
            {device.notes ? (
              <p className="text-sm leading-relaxed text-ink-300">{device.notes}</p>
            ) : (
              <p className="text-sm text-ink-400">No notes recorded.</p>
            )}
            <div className="mt-6 flex items-center justify-between border-t border-surface-100 pt-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-ink-400">Last updated</span>
              <span className="text-xs text-ink-400">{formatDateTime(device.updated_at)}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration History */}
      <div className="card mt-6 overflow-hidden" id="configuration-history">
        <div className="card-header">
          <div>
            <h2 className="section-title flex items-center gap-2">
              <History className="h-4 w-4 text-brand-600" />
              Configuration History
            </h2>
            <p className="mt-1 text-sm text-ink-400">
              Immutable snapshots, newest first — uploading never overwrites history.
            </p>
          </div>
          <div className="flex items-center gap-2.5">
            <span className="badge-info">{configTotal} snapshot{configTotal === 1 ? '' : 's'}</span>
            {device.is_active && (
              <Button variant="secondary" size="sm" onClick={() => setUploadOpen(true)}>
                <UploadCloud className="h-4 w-4" />
                Upload
              </Button>
            )}
          </div>
        </div>
        <div className="card-body p-0">
          {historyLoading ? (
            <div className="space-y-3 px-6 py-5">
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-2/3" />
            </div>
          ) : historyError ? (
            <div className="px-6 py-5">
              <Alert variant="error" title="Unable to load configuration history">
                {historyError}
                <div className="mt-3">
                  <Button variant="secondary" size="sm" onClick={loadHistory}>
                    Retry
                  </Button>
                </div>
              </Alert>
            </div>
          ) : configs.length === 0 ? (
            <div className="px-6 py-8">
              <EmptyState
                title="No configuration snapshots yet"
                description="Upload the running configuration to create the first immutable snapshot for this device."
                action={
                  device.is_active ? (
                    <Button size="sm" onClick={() => setUploadOpen(true)}>
                      <UploadCloud className="h-4 w-4" />
                      Upload Configuration
                    </Button>
                  ) : undefined
                }
              />
            </div>
          ) : (
            <div className="divide-y divide-surface-100">
              {configs.map((cfg) => (
                <div key={cfg.id} className="flex items-center gap-4 px-6 py-4 transition-colors hover:bg-surface-50/70">
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-surface-200 bg-surface-50 text-ink-400">
                    <FileText className="h-4 w-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="flex items-center gap-2 truncate text-sm font-semibold text-ink-100">
                      <span className="truncate font-mono" title={cfg.filename}>{cfg.filename}</span>
                      {cfg.latest && <span className="badge-pass shrink-0">LATEST</span>}
                    </p>
                    <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-ink-400">
                      <span>{formatDateTime(cfg.uploaded_at)}</span>
                      <span>{formatBytes(cfg.size_bytes)}</span>
                      <span className="font-mono" title={cfg.content_hash}>{cfg.content_hash.slice(0, 12)}…</span>
                      {cfg.detected_hostname && (
                        <span className="font-mono">{cfg.detected_hostname}</span>
                      )}
                    </p>
                  </div>
                  <div className="shrink-0 text-right">
                    <p className="text-sm font-semibold text-ink-100">
                      {cfg.audit_count === 0 ? '—' : `${cfg.audit_count} audit${cfg.audit_count === 1 ? '' : 's'}`}
                    </p>
                    <p className="text-xs text-ink-400">audits</p>
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => openViewer(cfg)} aria-label={`View ${cfg.filename}`}>
                    <Eye className="h-4 w-4" />
                    View
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Audit History */}
      <div className="card mt-6 overflow-hidden">
        <div className="card-header">
          <div>
            <h2 className="section-title flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-brand-600" />
              Audit History
            </h2>
            <p className="mt-1 text-sm text-ink-400">
              Audits run against this device&apos;s configurations — opening one shows its original report.
            </p>
          </div>
        </div>
        <div className="card-body p-0">
          {auditsLoading ? (
            <div className="space-y-3 px-6 py-5">
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-2/3" />
            </div>
          ) : auditsError ? (
            <div className="px-6 py-5">
              <Alert variant="error" title="Unable to load audit history">
                {auditsError}
                <div className="mt-3">
                  <Button variant="secondary" size="sm" onClick={loadAudits}>
                    Retry
                  </Button>
                </div>
              </Alert>
            </div>
          ) : audits.length === 0 ? (
            <div className="px-6 py-8">
              <EmptyState
                title="No audits yet"
                description="Run an audit against one of this device's configuration snapshots."
                action={
                  <Link href={`/audit/new?device=${device.id}`} className="btn-secondary">
                    <PlayCircle className="h-4 w-4" />
                    Run Audit
                  </Link>
                }
              />
            </div>
          ) : (
            <div className="divide-y divide-surface-100">
              {audits.map((a) => (
                <Link key={`${a.id}-${a.configuration_id}`} href={`/audit/${a.id}`} className="flex items-center gap-4 px-6 py-4 transition-colors hover:bg-surface-50/70">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-semibold text-ink-100">{a.name}</p>
                    <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-ink-400">
                      <span>{formatDateTime(a.created_at)}</span>
                      <span className="truncate font-mono" title={a.configuration_filename}>{a.configuration_filename}</span>
                    </p>
                  </div>
                  <div className="shrink-0 text-right">
                    <p className="text-sm font-semibold text-ink-100">
                      {a.overall_score != null ? formatPercent(a.overall_score) : '—'}
                    </p>
                    <p className="text-xs text-ink-400">score</p>
                  </div>
                  <AuditStatusBadge status={a.status} />
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Upload modal — single snapshot via the existing upload endpoint */}
      <Modal
        open={uploadOpen}
        onClose={() => {
          if (!uploading) {
            setUploadOpen(false);
            setUploadError(null);
            setUploadDone(null);
          }
        }}
        title="Upload Configuration"
        description={`New immutable snapshot for ${device.name} — history is never overwritten`}
        size="md"
      >
        <div className="space-y-4">
          {uploadDone && (
            <Alert variant="success" title="Snapshot stored" onDismiss={() => setUploadDone(null)}>
              {uploadDone}
            </Alert>
          )}
          {uploadError && (
            <Alert variant="error" title="Upload failed" onDismiss={() => setUploadError(null)}>
              {uploadError}
            </Alert>
          )}
          <div
            role="button"
            tabIndex={0}
            aria-label="Upload configuration file"
            onClick={() => fileInputRef.current?.click()}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
            }}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              handleUploadFile(e.dataTransfer.files?.[0]);
            }}
            className="flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed border-brand-200 bg-brand-50/50 px-6 py-10 text-center transition-all duration-150 hover:border-brand-400 hover:bg-brand-50"
          >
            {uploading ? (
              <>
                <span className="mx-auto block h-10 w-10 animate-spin rounded-full border-4 border-surface-200 border-t-brand-600" />
                <p className="text-sm font-semibold text-ink-100">Uploading and validating…</p>
              </>
            ) : (
              <>
                <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white text-brand-600 shadow-odoo ring-1 ring-brand-100">
                  <UploadCloud className="h-6 w-6" />
                </span>
                <div>
                  <p className="text-sm font-semibold text-ink-100">Drop a configuration file, or click to browse</p>
                  <p className="mt-1 text-xs text-ink-400">.txt, .cfg, .conf · max 10 MB · duplicate content returns the existing snapshot</p>
                </div>
              </>
            )}
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept={ACCEPTED}
            className="hidden"
            onChange={(e) => {
              handleUploadFile(e.target.files?.[0]);
              e.target.value = '';
            }}
          />
          <div className="flex items-center justify-end gap-3 border-t border-surface-100 pt-5">
            {uploadDone ? (
              <>
                <Button variant="ghost" size="sm" onClick={() => setUploadOpen(false)}>
                  Done
                </Button>
                <Link href={`/audit/new?device=${device.id}`} className="btn-primary">
                  <PlayCircle className="h-4 w-4" />
                  Run Audit
                </Link>
              </>
            ) : (
              <Button variant="ghost" size="sm" onClick={() => setUploadOpen(false)} disabled={uploading}>
                Cancel
              </Button>
            )}
          </div>
        </div>
      </Modal>

      {/* Viewer modal — read-only, existing content endpoint */}
      <Modal
        open={viewerItem !== null}
        onClose={() => {
          setViewerItem(null);
          setViewerContent(null);
          setViewerError(null);
        }}
        title={viewerItem ? `Configuration — ${viewerItem.filename}` : 'Configuration'}
        description={
          viewerItem
            ? `Snapshot ${viewerItem.uploaded_at ? formatDateTime(viewerItem.uploaded_at) : ''} · read-only`
            : undefined
        }
        size="xl"
      >
        <div className="space-y-4">
          <Alert variant="warning" title="Sensitive configuration data">
            Network configuration may contain credentials, secrets, keys, or other sensitive
            information. Handle according to your organization&apos;s security policy.
          </Alert>
          {viewerLoading && (
            <div className="space-y-3 py-4">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-2/3" />
            </div>
          )}
          {viewerError && (
            <Alert variant="error" title="Unable to load content">
              {viewerError}
              <div className="mt-3">
                <Button variant="secondary" size="sm" onClick={() => openViewer()}>
                  Retry
                </Button>
              </div>
            </Alert>
          )}
          {viewerContent !== null && !viewerLoading && (
            <CodeBlock code={viewerContent} language="config" lineNumbers maxHeight={480} />
          )}
          {viewerItem && (
            <div className="flex items-center gap-2 text-xs text-ink-400">
              <AlertTriangle className="h-3.5 w-3.5" />
              <span className="font-mono" title={viewerItem.content_hash}>
                SHA-256 {viewerItem.content_hash.slice(0, 16)}…
              </span>
              <span>·</span>
              <span>{viewerItem.audit_count} audit{viewerItem.audit_count === 1 ? '' : 's'}</span>
              {viewerItem.latest && (
                <span className="badge-pass">LATEST</span>
              )}
              {viewerItem.audit_count > 0 && (
                <span className="inline-flex items-center gap-1.5 text-emerald-700">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Referenced by audits — preserved as evidence
                </span>
              )}
            </div>
          )}
        </div>
      </Modal>

      {/* Archive confirmation — same copy as inventory list */}
      <Modal
        open={archiveOpen}
        onClose={() => {
          if (!archiving) setArchiveOpen(false);
        }}
        title="Archive this device?"
        size="md"
        footer={
          <>
            <Button variant="ghost" onClick={() => setArchiveOpen(false)} disabled={archiving}>
              Cancel
            </Button>
            <Button onClick={confirmArchive} loading={archiving}>
              <Archive className="h-4 w-4" />
              Archive Device
            </Button>
          </>
        }
      >
        <div className="space-y-4 text-sm leading-relaxed text-ink-300">
          {archiveError && (
            <Alert variant="error" title="Archive failed" onDismiss={() => setArchiveError(null)}>
              {archiveError}
            </Alert>
          )}
          <p>
            <span className="font-semibold text-ink-100">{device.name}</span> will be removed
            from the active inventory and will no longer accept new configurations or audits.
          </p>
          <p className="text-ink-400">
            Existing configuration history, audits, findings, and reports are preserved and
            remain accessible. You can unarchive the device at any time.
          </p>
        </div>
      </Modal>

      {/* Delete confirmation — real backend policy (pristine → delete,
          history-bearing → 409 with archive guidance) */}
      <Modal
        open={deleteOpen}
        onClose={() => {
          if (!deleting) setDeleteOpen(false);
        }}
        title="Delete this device?"
        size="md"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeleteOpen(false)} disabled={deleting}>
              Cancel
            </Button>
            <Button variant="danger" onClick={confirmDelete} loading={deleting}>
              <Trash2 className="h-4 w-4" />
              Delete Permanently
            </Button>
          </>
        }
      >
        <div className="space-y-4 text-sm leading-relaxed text-ink-300">
          {deleteError ? (
            <Alert variant="error" title="Cannot delete device">
              {deleteError}
            </Alert>
          ) : (
            <p>
              <span className="font-semibold text-ink-100">{device.name}</span> will be
              permanently removed. Devices with configuration or audit history cannot be
              deleted — archive them instead to preserve historical records.
            </p>
          )}
        </div>
      </Modal>
    </AppShell>
  );
}
