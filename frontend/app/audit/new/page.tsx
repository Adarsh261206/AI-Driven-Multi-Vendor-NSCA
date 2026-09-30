'use client';

import { Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ArrowRight,
  Check,
  ChevronLeft,
  ChevronRight,
  FileText,
  ListChecks,
  PlayCircle,
  Server,
  ShieldCheck,
  UploadCloud,
  X,
  Zap,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { PageLoader } from '@/components/ui/Progress';
import { Button } from '@/components/ui/Button';
import { Skeleton } from '@/components/ui/Progress';
import { configurationsAPI, auditExecutionAPI, baselinesAPI, devicesAPI, request } from '@/lib/api';
import { cn } from '@/lib/utils';
import { formatBytes, formatDateTime } from '@/lib/format';
import type {
  BaselineStatusResponse,
  Configuration,
  Device,
  DeviceConfigurationHistoryItem,
} from '@/types';

const STEPS = [
  { id: 'upload', label: 'Upload', icon: UploadCloud },
  { id: 'review', label: 'Review', icon: ListChecks },
  { id: 'run', label: 'Run', icon: PlayCircle },
];

const MAX_UPLOAD_MB = 10;
const ACCEPTED = '.txt,.cfg,.conf,.zip';
// Bumped after the fleet-rule change: v1 pending items may reference
// device-less (unlinked) configurations, which auditors can no longer
// audit. v2 starts clean; new freestyle uploads bind to an owned device.
const SESSION_KEY = 'guardian_pending_configs_v2';

export default function NewAuditPage() {
  return (
    <Suspense fallback={<PageLoader label="Loading audit workspace" />}>
      <NewAuditWizard />
    </Suspense>
  );
}

function NewAuditWizard() {
  const { isLoading: authLoading, user } = useRequireAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const deviceParam = searchParams.get('device');

  const [step, setStep] = useState(0);
  const [configs, setConfigs] = useState<Configuration[]>([]);
  const [selectedConfigs, setSelectedConfigs] = useState<string[]>([]);
  const [auditName, setAuditName] = useState('');
  const [auditDescription, setAuditDescription] = useState('');

  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadNotice, setUploadNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [executing, setExecuting] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  // Device-aware mode (STEP 3): ?device=<id> selects exactly one device
  // and exactly one of its configuration snapshots. Generic multi-file
  // flow below is untouched when no device param is present.
  const [device, setDevice] = useState<Device | null>(null);
  const [deviceConfigs, setDeviceConfigs] = useState<DeviceConfigurationHistoryItem[]>([]);
  const [selectedDeviceConfig, setSelectedDeviceConfig] = useState<string | null>(null);
  const [deviceLoading, setDeviceLoading] = useState(false);
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const [baseline, setBaseline] = useState<BaselineStatusResponse | null>(null);

  const deviceMode = deviceParam !== null && deviceParam !== '';
  // Ownership rule (server-enforced, mirrored here): a non-admin can only
  // audit configurations linked to a device they own. Freestyle uploads
  // must therefore bind to one of the user's devices so the audit can
  // access them; admins may audit device-less configs.
  const isAdmin = user?.role === 'admin';
  const needsBind = !deviceMode && !isAdmin;
  const [userDevices, setUserDevices] = useState<Device[]>([]);
  const [bindDevice, setBindDevice] = useState<Device | null>(null);

  useEffect(() => {
    if (authLoading || deviceMode || isAdmin) return;
    let cancelled = false;
    devicesAPI
      .list({ per_page: 100 })
      .then((res) => {
        if (cancelled) return;
        const active = (res.data.items || []).filter((d) => d.is_active !== false);
        setUserDevices(active);
        setBindDevice((prev) => prev ?? active[0] ?? null);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [authLoading, deviceMode, isAdmin]);

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (raw) setConfigs(JSON.parse(raw) as Configuration[]);
    } catch {}
  }, []);

  const loadDeviceContext = useCallback(async () => {
    if (!deviceParam) return;
    setDeviceLoading(true);
    setDeviceError(null);
    try {
      const [deviceRes, configsRes, baselineRes] = await Promise.all([
        request(() => devicesAPI.get(deviceParam), 'Device not found'),
        request(
          () => devicesAPI.listConfigurations(deviceParam, { per_page: 50 }),
          'Unable to load device configurations.'
        ),
        request(() => baselinesAPI.status(), 'Unable to load Company Baseline.'),
      ]);
      setDevice(deviceRes);
      const items = configsRes.items || [];
      setDeviceConfigs(items);
      // Default: latest snapshot. An explicit user choice afterwards wins.
      const latest = items.find((c) => c.latest) ?? items[0] ?? null;
      setSelectedDeviceConfig(latest ? latest.id : null);
      setBaseline(baselineRes);
    } catch (err) {
      setDeviceError(err instanceof Error ? err.message : 'Unable to load device context.');
      setDevice(null);
      setDeviceConfigs([]);
      setSelectedDeviceConfig(null);
    } finally {
      setDeviceLoading(false);
    }
  }, [deviceParam]);

  useEffect(() => {
    if (!authLoading && deviceParam) loadDeviceContext();
  }, [authLoading, deviceParam, loadDeviceContext]);

  const persistConfigs = useCallback((next: Configuration[]) => {
    setConfigs(next);
    try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(next)); } catch {}
  }, []);

  const uploadedBytes = useMemo(
    () => configs.filter((c) => selectedConfigs.includes(c.id)).reduce((s, c) => s + c.size_bytes, 0),
    [configs, selectedConfigs]
  );

  const uploadFiles = async (files: File[]) => {
    if (files.length === 0) return;
    setUploading(true);
    setUploadError(null);
    setUploadNotice(null);
    // Device mode: uploads bind to the selected device server-side.
    // Freestyle: non-admins must bind to an owned device (backend 403s
    // device-less configs for non-admin audit requests).
    const bindDeviceId = deviceMode
      ? device?.id
      : needsBind
        ? bindDevice?.id
        : undefined;
    if (needsBind && !bindDeviceId) {
      setUploading(false);
      setUploadError('Select a device to bind this upload to — audits require configurations linked to your devices.');
      return;
    }
    let added: Configuration[] = [];
    for (const file of files) {
      if (!ACCEPTED.split(',').some((ext) => file.name.toLowerCase().endsWith(ext.trim()))) {
        setUploadError(`"${file.name}" rejected — accepted types: .txt, .cfg, .conf, .zip`);
        continue;
      }
      if (file.size > MAX_UPLOAD_MB * 1024 * 1024) {
        setUploadError(`"${file.name}" exceeds the ${MAX_UPLOAD_MB} MB limit.`);
        continue;
      }
      try {
        const res = await request(() => configurationsAPI.upload(file, bindDeviceId), `Upload of ${file.name} failed`);
        added.push(res as unknown as Configuration);
      } catch (err) {
        setUploadError(err instanceof Error ? err.message : `Upload of ${file.name} failed`);
      }
    }
    if (added.length > 0) {
      if (deviceMode) {
        // Refresh device snapshots, then select the resulting snapshot.
        // Dedup may return a pre-existing snapshot honestly — select it.
        await loadDeviceContext();
        const lastAdded = added[added.length - 1];
        setSelectedDeviceConfig(lastAdded.id);
        setUploadNotice(
          `"${lastAdded.filename}" ready — selected for this audit. History is never overwritten.`
        );
      } else {
        const seen = new Set(configs.map((c) => c.id));
        const merged = [...configs, ...added.filter((c) => !seen.has(c.id))];
        persistConfigs(merged);
        setSelectedConfigs((prev) => [...prev, ...added.map((c) => c.id)]);
      }
    }
    setUploading(false);
  };

  const onFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    e.target.value = '';
    void uploadFiles(files);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    void uploadFiles(Array.from(e.dataTransfer.files));
  };

  const removeConfig = (id: string) => {
    persistConfigs(configs.filter((c) => c.id !== id));
    setSelectedConfigs((prev) => prev.filter((c) => c !== id));
  };

  const canContinue = (): boolean => {
    if (step === 0) {
      // Device mode: exactly one device snapshot must be selected, and
      // archived devices cannot start audits (server enforces this too).
      if (deviceMode) {
        return (
          selectedDeviceConfig !== null && device !== null && device.is_active !== false
        );
      }
      return selectedConfigs.length > 0;
    }
    if (step === 1) return auditName.trim().length > 0;
    return true;
  };

  const execute = async () => {
    setExecuting(true);
    setError(null);
    try {
      const payload = deviceMode && device && selectedDeviceConfig
        ? {
            name: auditName.trim(),
            description: auditDescription.trim() || undefined,
            configuration_ids: [selectedDeviceConfig],
            framework: 'CIS',
            framework_version: '2024.1',
            device_ids: [device.id],
          }
        : {
            name: auditName.trim(),
            description: auditDescription.trim() || undefined,
            configuration_ids: selectedConfigs,
            framework: 'CIS',
            framework_version: '2024.1',
          };
      const audit = await request(
        () => auditExecutionAPI.execute(payload),
        'Failed to start audit'
      );
      sessionStorage.removeItem(SESSION_KEY);
      router.push(`/audit/${audit.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start audit');
      setExecuting(false);
    }
  };

  if (authLoading) return <PageLoader label="Loading" />;

  return (
    <AppShell
      title="New Audit — ConfigShield"
      subtitle="Drop a config file. Vendor, framework and compliance are detected automatically."
    >
      {error && (
        <div className="mb-6">
          <Alert variant="error" title="Audit creation failed" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      {/* ── STEPPER ── Odoo-like generous */}
      <div className="mb-10">
        <nav aria-label="Audit creation steps">
          <ol className="flex items-center">
            {STEPS.map((s, i) => {
              const active = i === step;
              const done = i < step;
              const Icon = s.icon;
              return (
                <li key={s.id} className="flex items-center flex-1 last:flex-none">
                  <div className="flex items-center gap-4">
                    <button
                      onClick={() => i < step && setStep(i)}
                      disabled={i > step}
                      className={cn(
                        'relative flex h-11 w-11 shrink-0 items-center justify-center rounded-full text-sm font-semibold transition-all duration-200',
                        done && 'bg-brand-600 text-white shadow-odoo',
                        active && 'bg-brand-600 text-white shadow-odoo-md ring-[5px] ring-brand-50',
                        !done && !active && 'bg-white text-ink-400 border-2 border-surface-200 shadow-xs'
                      )}
                      aria-current={active ? 'step' : undefined}
                    >
                      {done ? <Check className="h-5 w-5" strokeWidth={2.5} /> : <Icon className="h-5 w-5" strokeWidth={active ? 2 : 1.75} />}
                    </button>
                    <div className={cn('min-w-0 pr-2 transition-colors duration-200', (active || done) ? 'text-ink-100' : 'text-ink-400')}>
                      <p className="text-[11px] font-semibold uppercase tracking-widest leading-none text-ink-400">
                        Step {i + 1}
                      </p>
                      <p className={cn('text-sm font-semibold mt-1 leading-none', active ? 'text-brand-700' : done ? 'text-ink-100' : 'text-ink-400')}>
                        {s.label}
                      </p>
                    </div>
                  </div>
                  {i < STEPS.length - 1 && (
                    <div className={cn('h-[2px] flex-1 mx-6 rounded-full transition-colors duration-300', i < step ? 'bg-brand-600' : 'bg-surface-200')} />
                  )}
                </li>
              );
            })}
          </ol>
        </nav>
      </div>

      {/* ── AUTO PIPELINE BANNER ── Odoo generous */}
      <div className="mb-8 flex items-center gap-3 rounded-xl border border-brand-200 bg-brand-50 px-5 py-3.5 shadow-xs">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-white border border-brand-200 text-brand-600 shadow-xs">
          <Zap className="h-4 w-4" />
        </span>
        <p className="text-sm leading-relaxed text-brand-700">
          <span className="font-semibold">Auto pipeline:</span> Upload → Understand (AI) → Normalize → Compliance (CIS + NIST) → Secure (Risk + Report). No manual vendor/framework selection.
        </p>
      </div>

      {/* ── STEP CONTENT ── */}
      <div className="max-w-3xl">
        {/* STEP 0 — Upload (generic) or Select snapshot (device mode) */}
        {step === 0 && deviceMode && (
          <div className="space-y-6">
            <div>
              <h2 className="page-title">Audit device</h2>
              <p className="page-subtitle mt-2 max-w-2xl">
                Select exactly one configuration snapshot for this device — or upload a new one.
              </p>
            </div>

            {device && !device.is_active && (
              <Alert variant="warning" title="This device is archived">
                Archived devices cannot start new audits. Unarchive the device from its detail
                page to resume operations — history is preserved.
              </Alert>
            )}

            {deviceLoading ? (
              <div className="card px-6 py-5">
                <div className="flex items-center gap-4">
                  <Skeleton className="h-10 w-10 rounded-xl" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-5 w-1/3" />
                    <Skeleton className="h-4 w-1/2" />
                  </div>
                </div>
              </div>
            ) : deviceError || !device ? (
              <Alert variant="error" title="Unable to load device context">
                {deviceError ?? 'This device could not be loaded. It may not exist or you may not have access to it.'}
                <div className="mt-3">
                  <Button variant="secondary" size="sm" onClick={loadDeviceContext}>
                    Retry
                  </Button>
                </div>
              </Alert>
            ) : (
              <>
                {/* Device context card */}
                <div className="card overflow-hidden">
                  <div className="card-header">
                    <div className="flex items-center gap-3">
                      <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                        <Server className="h-5 w-5" />
                      </span>
                      <div>
                        <p className="label">AUDIT DEVICE</p>
                        <h3 className="section-title">{device.name}</h3>
                      </div>
                    </div>
                    <span className="badge-info">
                      {[device.vendor, device.platform].filter(Boolean).join(' · ') || 'Unknown vendor'}
                    </span>
                  </div>
                  <div className="px-6 py-4 text-sm text-ink-400">
                    {deviceConfigs.length === 0
                      ? 'No configuration snapshots on record for this device yet.'
                      : `${deviceConfigs.length} snapshot${deviceConfigs.length === 1 ? '' : 's'} on record — select exactly one to audit.`}
                  </div>
                </div>

                {device.is_active !== false && (
                  <>
                {/* Snapshot radio list */}
                {deviceConfigs.length > 0 && (
                  <div className="card overflow-hidden">
                    <div className="card-header">
                      <h3 className="section-title">Configuration snapshot</h3>
                      <span className="badge-info">one snapshot</span>
                    </div>
                    <div className="space-y-3 bg-surface-50/30 p-4">
                      {deviceConfigs.map((cfg) => (
                        <label
                          key={cfg.id}
                          className={cn('select-card cursor-pointer', selectedDeviceConfig === cfg.id ? '!border-brand-300 !bg-brand-50/60 shadow-odoo' : '')}
                        >
                          <input
                            type="radio"
                            name="device-snapshot"
                            checked={selectedDeviceConfig === cfg.id}
                            onChange={() => setSelectedDeviceConfig(cfg.id)}
                            className="sr-only peer"
                          />
                          <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 border-surface-300 bg-white transition-all peer-checked:border-brand-600 peer-checked:bg-brand-600 [&>span]:opacity-0 peer-checked:[&>span]:opacity-100">
                            <span className="h-2 w-2 rounded-full bg-white transition-opacity" />
                          </span>
                          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-surface-200 bg-surface-100 text-ink-400">
                            <FileText className="h-4.5 w-4.5" />
                          </span>
                          <div className="min-w-0 flex-1">
                            <p className="flex items-center gap-2 truncate text-sm font-semibold text-ink-100">
                              <span className="truncate font-mono" title={cfg.filename}>{cfg.filename}</span>
                              {cfg.latest && <span className="badge-pass shrink-0">LATEST</span>}
                            </p>
                            <p className="mt-1 text-xs text-ink-400">
                              {formatDateTime(cfg.uploaded_at)} · {formatBytes(cfg.size_bytes)}
                              {cfg.audit_count > 0 && ` · ${cfg.audit_count} audit${cfg.audit_count === 1 ? '' : 's'}`}
                            </p>
                          </div>
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {uploadNotice && (
                  <Alert variant="success" onDismiss={() => setUploadNotice(null)}>
                    {uploadNotice}
                  </Alert>
                )}
                {uploadError && (
                  <Alert variant="warning" title="Upload issues" onDismiss={() => setUploadError(null)}>
                    {uploadError}
                  </Alert>
                )}

                {/* Upload-new affordance (bound to this device server-side) */}
                <div
                  role="button"
                  tabIndex={0}
                  aria-label="Upload a new configuration for this device"
                  onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                  onDragLeave={() => setDragOver(false)}
                  onDrop={onDrop}
                  onClick={() => document.getElementById('config-file-input')?.click()}
                  onKeyDown={(e) => e.key === 'Enter' && document.getElementById('config-file-input')?.click()}
                  className={cn(
                    'card cursor-pointer border-2 border-dashed p-8 text-center transition-all duration-200',
                    dragOver ? 'border-brand-400 bg-brand-50 shadow-odoo' : 'border-surface-300 bg-surface-50/40 hover:border-brand-300 hover:bg-brand-50/30 hover:shadow-odoo'
                  )}
                >
                  <input id="config-file-input" type="file" multiple accept={ACCEPTED} onChange={onFileInput} className="hidden" disabled={uploading} />
                  <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-white border border-surface-200 text-brand-600 shadow-odoo">
                    <UploadCloud className="h-6 w-6" strokeWidth={1.6} />
                  </div>
                  <p className="text-sm font-semibold text-ink-100">
                    {uploading ? 'Uploading…' : 'Upload new configuration for this device'}
                  </p>
                  <p className="mt-1 text-xs text-ink-400">
                    Bound to {device.name} server-side · history is never overwritten
                  </p>
                </div>

                {deviceConfigs.length === 0 && !uploading && (
                  <Alert variant="info" title="No configurations yet">
                    Upload a configuration snapshot before running this device audit.
                  </Alert>
                )}
                  </>
                )}
              </>
            )}
          </div>
        )}
        {step === 0 && !deviceMode && (
          <div className="space-y-6">
            <div>
              <h2 className="page-title">Upload configuration</h2>
              <p className="page-subtitle mt-2 max-w-2xl">
                Drop your network device config — Cisco, Juniper, Fortinet, Palo Alto, or any CLI. Vendor and framework are auto-detected.
              </p>
            </div>

            {needsBind && (
              <div className="card overflow-hidden">
                <div className="card-header">
                  <div>
                    <h3 className="section-title">Bind uploads to a device</h3>
                    <p className="text-sm text-ink-400 mt-1">
                      Audits can only run configurations linked to your devices. Uploads below bind to the selected device — same content on another device is stored separately.
                    </p>
                  </div>
                  <span className="badge-info">required for auditors</span>
                </div>
                <div className="card-body">
                  {userDevices.length === 0 ? (
                    <Alert variant="warning" title="No devices available">
                      You have no active devices. Create a device first, or run the audit from a device detail page.
                    </Alert>
                  ) : (
                    <div className="flex flex-wrap items-center gap-2">
                      {userDevices.map((d) => (
                        <button
                          key={d.id}
                          onClick={() => setBindDevice(d)}
                          className={cn(
                            'rounded-lg border px-3 py-2 text-sm font-medium transition-all',
                            bindDevice?.id === d.id
                              ? 'border-brand-300 bg-brand-50 text-brand-700 shadow-odoo'
                              : 'border-surface-200 bg-white text-ink-400 hover:border-brand-200'
                          )}
                        >
                          {d.name}
                          {d.vendor ? ` · ${d.vendor}` : ''}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            <div
              role="button"
              tabIndex={0}
              aria-label="Upload configuration files"
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDrop}
              onClick={() => document.getElementById('config-file-input')?.click()}
              onKeyDown={(e) => e.key === 'Enter' && document.getElementById('config-file-input')?.click()}
              className={cn(
                'card cursor-pointer border-2 border-dashed p-12 text-center transition-all duration-200',
                dragOver ? 'border-brand-400 bg-brand-50 shadow-odoo' : 'border-surface-300 bg-surface-50/40 hover:border-brand-300 hover:bg-brand-50/30 hover:shadow-odoo'
              )}
            >
              <input id="config-file-input" type="file" multiple accept={ACCEPTED} onChange={onFileInput} className="hidden" disabled={uploading} />
              <div className="mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-2xl bg-white border border-surface-200 text-brand-600 shadow-odoo">
                <UploadCloud className="h-7 w-7" strokeWidth={1.6} />
              </div>
              <p className="text-[15px] font-semibold text-ink-100">
                {uploading ? 'Uploading...' : 'Drop config files here or click to browse'}
              </p>
              <p className="mt-1.5 text-sm text-ink-400">Accepted: {ACCEPTED} · Max {MAX_UPLOAD_MB} MB · Any vendor</p>
              <div className="mt-4 inline-flex items-center gap-2 rounded-full bg-white border border-surface-200 px-4 py-1.5 text-xs font-medium text-ink-400 shadow-xs">
                <ShieldCheck className="h-3.5 w-3.5 text-brand-500" />
                {needsBind
                  ? bindDevice
                    ? `Uploads bind to ${bindDevice.name}`
                    : 'Select a device to bind uploads'
                  : 'Vendor + framework auto-detected on next step'}
              </div>
            </div>

            {uploadError && (
              <Alert variant="warning" title="Upload issues" onDismiss={() => setUploadError(null)}>
                {uploadError}
              </Alert>
            )}

            {configs.length > 0 && (
              <div className="card overflow-hidden">
                <div className="card-header">
                  <div>
                    <h3 className="section-title">Configurations</h3>
                    <p className="text-sm text-ink-400 mt-1">
                      {selectedConfigs.length} of {configs.length} selected · {formatBytes(uploadedBytes)}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <button className="btn-secondary text-xs px-3.5 py-2" onClick={() => setSelectedConfigs(configs.map((c) => c.id))}>Select all</button>
                    <button className="btn-secondary text-xs px-3.5 py-2" onClick={() => setSelectedConfigs([])}>Clear</button>
                  </div>
                </div>
                <div className="p-4 space-y-3 bg-surface-50/30">
                  {configs.map((cfg) => (
                    <label
                      key={cfg.id}
                      className={cn('select-card', selectedConfigs.includes(cfg.id) ? '!border-brand-300 !bg-brand-50/60 shadow-odoo' : '')}
                    >
                      <input
                        type="checkbox"
                        checked={selectedConfigs.includes(cfg.id)}
                        onChange={() => setSelectedConfigs((prev) => (prev.includes(cfg.id) ? prev.filter((c) => c !== cfg.id) : [...prev, cfg.id]))}
                        className="sr-only peer"
                      />
                      <span className="h-5 w-5 shrink-0 rounded-md border-2 border-surface-300 bg-white transition-all peer-checked:border-brand-600 peer-checked:bg-brand-600 flex items-center justify-center [&>svg]:opacity-0 peer-checked:[&>svg]:opacity-100 mt-0.5">
                        <svg className="h-3 w-3 text-white transition-opacity" viewBox="0 0 12 12" fill="none"><path d="M2 6l3 3 5-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
                      </span>
                      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-surface-100 border border-surface-200 text-ink-400">
                        <FileText className="h-4.5 w-4.5" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold text-ink-100 truncate">{cfg.filename}</p>
                        <p className="text-xs text-ink-400 mt-1">
                          {formatBytes(cfg.size_bytes)} · {cfg.line_count.toLocaleString()} lines
                        </p>
                      </div>
                      <span className="badge-info shrink-0">auto</span>
                      <button
                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); removeConfig(cfg.id); }}
                        aria-label={`Remove ${cfg.filename}`}
                        className="rounded-lg p-1.5 text-ink-400 transition-colors duration-150 hover:bg-red-50 hover:text-red-600 shrink-0"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {configs.length === 0 && !uploading && (
              <p className="text-center text-sm text-ink-400 py-2">No files yet — drop a config to start. Any vendor, any format.</p>
            )}
          </div>
        )}

        {/* STEP 1 — Review */}
        {step === 1 && (
          <div className="space-y-6">
            <div>
              <h2 className="page-title">Review & launch</h2>
              <p className="page-subtitle mt-2">Name your audit. Everything else is automatic.</p>
            </div>

            {deviceMode && device && (() => {
              const selected = deviceConfigs.find((c) => c.id === selectedDeviceConfig) ?? null;
              return (
                <div className="card overflow-hidden">
                  <div className="card-header">
                    <h3 className="section-title">Audit scope</h3>
                    <span className="badge-info">device-aware</span>
                  </div>
                  <div className="card-body">
                    <dl className="grid grid-cols-2 gap-x-6 gap-y-4 text-sm">
                      <div>
                        <dt className="label mb-1">Device</dt>
                        <dd className="font-semibold text-ink-100">{device.name}</dd>
                        <dd className="mt-0.5 text-xs text-ink-400">
                          {[device.vendor, device.platform].filter(Boolean).join(' · ') || 'Unknown vendor'}
                          {device.firmware_version ? ` · ${device.firmware_version}` : ''}
                        </dd>
                      </div>
                      <div>
                        <dt className="label mb-1">Configuration</dt>
                        <dd className="truncate font-mono font-semibold text-ink-100" title={selected?.filename ?? ''}>
                          {selected?.filename ?? '—'}
                        </dd>
                        <dd className="mt-0.5 text-xs text-ink-400">
                          {selected ? `Snapshot ${formatDateTime(selected.uploaded_at)}` : 'No snapshot selected'}
                          {selected?.latest ? ' · LATEST' : ''}
                        </dd>
                      </div>
                      <div>
                        <dt className="label mb-1">Framework</dt>
                        <dd className="font-semibold text-ink-100">CIS</dd>
                        <dd className="mt-0.5 text-xs text-ink-400">CIS Cisco IOS XE 17.x Benchmark</dd>
                      </div>
                      <div>
                        <dt className="label mb-1">Company Baseline</dt>
                        {baseline?.baseline_status === 'ACTIVE' && baseline.baseline ? (
                          <>
                            <dd className="font-semibold text-ink-100">{baseline.baseline.name}</dd>
                            <dd className="mt-0.5 text-xs text-ink-400">
                              {baseline.baseline.control_count} controls in scope · Applied automatically
                            </dd>
                          </>
                        ) : (
                          <>
                            <dd className="font-semibold text-ink-100">Not configured</dd>
                            <dd className="mt-0.5 text-xs text-ink-400">Full CIS auditing — resolved server-side</dd>
                          </>
                        )}
                      </div>
                    </dl>
                  </div>
                </div>
              );
            })()}

            <div className="space-y-6">
              <div className="card overflow-hidden">
                <div className="card-header">
                  <h3 className="section-title">Audit details</h3>
                  <span className="text-xs text-ink-400">Step 2 of 3</span>
                </div>
                <div className="card-body space-y-5">
                  <div>
                    <label className="label">Audit name <span className="text-red-500">*</span></label>
                    <input
                      type="text"
                      value={auditName}
                      onChange={(e) => setAuditName(e.target.value)}
                      placeholder="e.g., Q1 edge-router sweep — auto-detected"
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="label">Description</label>
                    <textarea
                      value={auditDescription}
                      onChange={(e) => setAuditDescription(e.target.value)}
                      placeholder="Optional notes — purpose, scope, owner…"
                      className="input min-h-[96px] resize-y"
                    />
                  </div>
                </div>
              </div>

              <div className="card overflow-hidden">
                <div className="card-header">
                  <h3 className="section-title">What will run — auto</h3>
                  <span className="badge-info">No configuration needed</span>
                </div>
                <div className="card-body">
                  <div className="grid grid-cols-3 gap-6">
                    <div className="rounded-xl bg-surface-50 border border-surface-200 p-4">
                      <p className="label mb-1.5">Vendor</p>
                      <p className="text-sm font-semibold text-ink-100">Auto-detected</p>
                      <p className="text-xs text-ink-400 mt-1">per file on launch</p>
                    </div>
                    <div className="rounded-xl bg-surface-50 border border-surface-200 p-4">
                      <p className="label mb-1.5">Frameworks</p>
                      <p className="text-sm font-semibold text-ink-100">CIS + NIST</p>
                      <p className="text-xs text-ink-400 mt-1">vendor-scoped, dual-baseline</p>
                    </div>
                    <div className="rounded-xl bg-surface-50 border border-surface-200 p-4">
                      <p className="label mb-1.5">Files</p>
                      <p className="text-sm font-semibold text-ink-100">
                        {deviceMode ? '1 file' : `${selectedConfigs.length} file(s)`}
                      </p>
                      <p className="text-xs text-ink-400 mt-1">
                        {deviceMode
                          ? 'device snapshot'
                          : formatBytes(uploadedBytes)}
                      </p>
                    </div>
                  </div>
                  {selectedConfigs.length > 0 && (
                    <div className="mt-6 border-t border-surface-100 pt-5">
                      <p className="label">Selected files</p>
                      <ul className="mt-3 space-y-2">
                        {configs.filter((c) => selectedConfigs.includes(c.id)).map((c) => (
                          <li key={c.id} className="flex items-center justify-between rounded-lg bg-surface-50 border border-surface-100 px-4 py-2.5">
                            <span className="truncate text-sm font-medium text-ink-300">{c.filename}</span>
                            <span className="ml-4 font-mono text-xs text-ink-400 shrink-0">{formatBytes(c.size_bytes)}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="mt-5 rounded-xl bg-brand-50 border border-brand-100 px-4 py-3 text-xs leading-relaxed text-brand-700">
                    <span className="font-semibold">Pipeline:</span> Validate → Detect vendor → Parse → Normalize (Common Security Model) → Compliance (CIS 70 + NIST 126, vendor-scoped) → Findings → Report
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* STEP 2 — Run */}
        {step === 2 && (
          <div>
            <div className="card flex flex-col items-center px-8 py-16 text-center">
              <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-50 border border-brand-100 text-brand-600 shadow-odoo">
                <PlayCircle className="h-8 w-8" strokeWidth={1.5} />
              </div>
              <p className="label mb-2">Ready — fully automatic</p>
              <h2 className="page-title">Start audit</h2>
              <p className="mt-3 max-w-xl text-sm leading-relaxed text-ink-400">
                Drop done. On start, ConfigShield will auto-detect vendor per file, normalize to the Common Security Model, and evaluate{' '}
                <span className="font-semibold text-ink-200">{selectedConfigs.length} file(s)</span> against{' '}
                <span className="font-semibold text-ink-200">CIS + NIST</span> in one go. Every unknown maps to Human-in-the-Loop training for the next loop.
              </p>
              <div className="mt-10 flex gap-3">
                <button className="btn-secondary px-6" onClick={() => setStep(1)}>
                  <ChevronLeft className="h-4 w-4" />
                  Back
                </button>
                <button className="btn-primary px-7" onClick={execute} disabled={executing}>
                  {executing ? 'Starting...' : 'Start Audit'}
                  {!executing && <ArrowRight className="h-4 w-4" />}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Footer nav ── Odoo generous */}
      <div className="mt-10 flex items-center justify-between max-w-3xl border-t border-surface-200 pt-6">
        <button className="btn-ghost" onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0}>
          <ChevronLeft className="h-4 w-4" />
          Back
        </button>
        {step < 2 ? (
          <button className="btn-primary px-6" onClick={() => canContinue() && setStep(step + 1)} disabled={!canContinue()}>
            Continue
            <ChevronRight className="h-4 w-4" />
          </button>
        ) : (
          <span />
        )}
      </div>
    </AppShell>
  );
}
