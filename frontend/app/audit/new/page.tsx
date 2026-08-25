'use client';

import { Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  Check,
  ChevronLeft,
  ChevronRight,
  FileText,
  HardDrive,
  ListChecks,
  PlayCircle,
  Server,
  ShieldCheck,
  UploadCloud,
  X,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Field, Input, Select, Textarea } from '@/components/ui/Field';
import { TechBadge } from '@/components/ui/Badge';
import { PageLoader } from '@/components/ui/Progress';
import { configurationsAPI, devicesAPI, auditExecutionAPI, getApiError, request } from '@/lib/api';
import { cn } from '@/lib/utils';
import { formatBytes } from '@/lib/format';
import type { Configuration, Device } from '@/types';

const STEPS = [
  { id: 'device', label: 'Device', icon: <Server className="h-4 w-4" /> },
  { id: 'upload', label: 'Configuration', icon: <UploadCloud className="h-4 w-4" /> },
  { id: 'framework', label: 'Framework', icon: <ShieldCheck className="h-4 w-4" /> },
  { id: 'review', label: 'Review', icon: <ListChecks className="h-4 w-4" /> },
  { id: 'run', label: 'Run', icon: <PlayCircle className="h-4 w-4" /> },
];

const MAX_UPLOAD_MB = 10;
const ACCEPTED = '.txt,.cfg,.conf,.zip';

const SESSION_KEY = 'guardian_pending_configs';

export default function NewAuditPage() {
  return (
    <Suspense fallback={<PageLoader label="Loading audit wizard" />}>
      <NewAuditWizard />
    </Suspense>
  );
}

function NewAuditWizard() {
  const { isLoading: authLoading } = useRequireAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const deviceParam = searchParams.get('device');

  const [step, setStep] = useState(0);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string | null>(deviceParam);
  const [configs, setConfigs] = useState<Configuration[]>([]);
  const [selectedConfigs, setSelectedConfigs] = useState<string[]>([]);
  const [framework, setFramework] = useState('CIS');
  const [auditName, setAuditName] = useState('');
  const [auditDescription, setAuditDescription] = useState('');

  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [executing, setExecuting] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  // Load devices
  useEffect(() => {
    devicesAPI
      .list({ per_page: 100 })
      .then((res) => {
        setDevices(res.data.items || []);
        if (!deviceParam && res.data.items?.length === 1) {
          setSelectedDevice(res.data.items[0].id);
        }
      })
      .catch(() => setDevices([]));
  }, [deviceParam]);

  // Restore session-uploaded configs (there is no backend list endpoint)
  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (raw) {
        const stored = JSON.parse(raw) as Configuration[];
        setConfigs(stored);
      }
    } catch {
      // ignore corrupt session data
    }
  }, []);

  const persistConfigs = useCallback((next: Configuration[]) => {
    setConfigs(next);
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(next));
    } catch {
      // storage full or unavailable
    }
  }, []);

  const selectedDeviceObj = devices.find((d) => d.id === selectedDevice) ?? null;
  const uploadedBytes = useMemo(
    () => configs.filter((c) => selectedConfigs.includes(c.id)).reduce((s, c) => s + c.size_bytes, 0),
    [configs, selectedConfigs]
  );

  // ------------------------------------------------------------------
  // Upload
  // ------------------------------------------------------------------

  const uploadFiles = async (files: File[]) => {
    if (files.length === 0) return;
    setUploading(true);
    setUploadError(null);
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
        const res = await request(
          () => configurationsAPI.upload(file, selectedDevice ?? undefined),
          `Upload of ${file.name} failed`
        );
        const cfg = res as unknown as Configuration;
        added.push(cfg);
      } catch (err) {
        const msg = err instanceof Error ? err.message : `Upload of ${file.name} failed`;
        setUploadError(msg);
      }
    }
    if (added.length > 0) {
      const seen = new Set(configs.map((c) => c.id));
      const merged = [...configs, ...added.filter((c) => !seen.has(c.id))];
      persistConfigs(merged);
      setSelectedConfigs((prev) => [...prev, ...added.map((c) => c.id)]);
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

  // ------------------------------------------------------------------
  // Execute
  // ------------------------------------------------------------------

  const canContinue = (): boolean => {
    if (step === 1) return selectedConfigs.length > 0;
    if (step === 3) return auditName.trim().length > 0;
    return true;
  };

  const execute = async () => {
    setExecuting(true);
    setError(null);
    try {
      const audit = await request(
        () =>
          auditExecutionAPI.execute({
            name: auditName.trim(),
            description: auditDescription.trim() || undefined,
            configuration_ids: selectedConfigs,
            framework,
            framework_version: '2024.1',
          }),
        'Failed to start audit'
      );
      // Clear session configs on successful run
      sessionStorage.removeItem(SESSION_KEY);
      router.push(`/audit/${audit.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start audit');
      setExecuting(false);
    }
  };

  if (authLoading) return <PageLoader label="Loading" />;

  return (
    <AppShell title="Run New Audit" subtitle="Upload a configuration and evaluate it against a security framework">
      {/* Step indicator */}
      <ol aria-label="Audit creation steps" className="mb-7 flex items-center gap-1">
        {STEPS.map((s, i) => {
          const active = i === step;
          const done = i < step;
          return (
            <li key={s.id} className="flex flex-1 items-center gap-1">
              <button
                onClick={() => i < step && setStep(i)}
                disabled={i > step}
                className={cn(
                  'flex w-full items-center gap-2 rounded-md border px-3 py-2 text-left transition-colors',
                  active && 'border-accent-500/50 bg-accent-500/5',
                  done && 'border-green-500/30 bg-green-500/5',
                  !active && !done && 'border-base-700 bg-base-850',
                  i < step && 'cursor-pointer hover:border-base-500'
                )}
                aria-current={active ? 'step' : undefined}
              >
                <span
                  className={cn(
                    'flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full text-[11px] font-semibold',
                    done ? 'bg-green-500/20 text-green-400' : active ? 'bg-accent-500/20 text-accent-300' : 'bg-base-800 text-slate-500'
                  )}
                >
                  {done ? <Check className="h-3.5 w-3.5" /> : i + 1}
                </span>
                <span className="hidden items-center gap-1.5 text-xs font-medium text-slate-300 sm:flex">
                  {s.icon}
                  {s.label}
                </span>
              </button>
              {i < STEPS.length - 1 && <span className="h-px flex-1 bg-base-700" aria-hidden />}
            </li>
          );
        })}
      </ol>

      {error && (
        <div className="mb-5">
          <Alert variant="error" title="Audit creation failed" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      {/* STEP 1 — Device */}
      {step === 0 && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2 className="text-sm font-semibold text-slate-200">Select or create a device</h2>
              <p className="mt-0.5 text-xs text-slate-500">
                The device provides context for the configuration. You can also audit an uploaded
                configuration without a registered device.
              </p>
            </div>
          </div>
          <div className="panel-body">
            <div className="space-y-2">
              <label className="flex cursor-pointer items-center gap-3 rounded-md border border-base-700 bg-base-900 px-3.5 py-3 hover:border-base-500">
                <input
                  type="radio"
                  name="device"
                  checked={selectedDevice == null}
                  onChange={() => setSelectedDevice(null)}
                  className="h-4 w-4 accent-accent-500"
                />
                <div>
                  <p className="text-sm font-medium text-slate-200">No registered device</p>
                  <p className="text-xs text-slate-500">Audit the configuration standalone</p>
                </div>
              </label>
              {devices.map((d) => (
                <label
                  key={d.id}
                  className="flex cursor-pointer items-center gap-3 rounded-md border border-base-700 bg-base-900 px-3.5 py-3 hover:border-base-500"
                >
                  <input
                    type="radio"
                    name="device"
                    checked={selectedDevice === d.id}
                    onChange={() => setSelectedDevice(d.id)}
                    className="h-4 w-4 accent-accent-500"
                  />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-slate-200">{d.name}</p>
                    <p className="truncate text-xs text-slate-500">
                      {d.vendor ?? 'unknown'} / {d.platform ?? 'unknown'} {d.firmware_version ? `· ${d.firmware_version}` : ''}
                    </p>
                  </div>
                  <TechBadge>{d.configuration_count} cfg</TechBadge>
                </label>
              ))}
              {devices.length === 0 && (
                <p className="rounded-md border border-dashed border-base-600 px-3 py-2.5 text-xs text-slate-500">
                  No devices registered yet — you can audit a configuration directly, or{' '}
                  <Link href="/devices" className="text-accent-400 hover:text-accent-300">
                    register a device
                  </Link>
                  .
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* STEP 2 — Upload */}
      {step === 1 && (
        <div className="space-y-5">
          <div
            role="button"
            tabIndex={0}
            aria-label="Upload configuration files"
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={onDrop}
            onClick={() => document.getElementById('config-file-input')?.click()}
            onKeyDown={(e) => e.key === 'Enter' && document.getElementById('config-file-input')?.click()}
            className={cn(
              'cursor-pointer rounded-lg border-2 border-dashed p-8 text-center transition-colors',
              dragOver ? 'border-accent-500 bg-accent-500/5' : 'border-base-600 hover:border-base-500'
            )}
          >
            <input
              id="config-file-input"
              type="file"
              multiple
              accept={ACCEPTED}
              onChange={onFileInput}
              className="hidden"
              disabled={uploading}
            />
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-lg border border-base-700 bg-base-900 text-accent-400">
              <UploadCloud className="h-5 w-5" />
            </div>
            <p className="text-sm font-medium text-slate-200">
              {uploading ? 'Uploading...' : 'Drop configuration files here or click to browse'}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Accepted: {ACCEPTED} · Max {MAX_UPLOAD_MB} MB per file
            </p>
            <p className="mt-3 inline-flex items-center gap-1.5 rounded border border-amber-500/25 bg-amber-500/5 px-2.5 py-1 text-[11px] text-amber-400">
              <HardDrive className="h-3 w-3" />
              Configurations contain sensitive device data. Files are stored encrypted and used only
              for compliance evaluation.
            </p>
          </div>

          {uploadError && (
            <Alert variant="warning" title="Upload issues" onDismiss={() => setUploadError(null)}>
              {uploadError}
            </Alert>
          )}

          {configs.length > 0 && (
            <div className="panel">
              <div className="panel-header">
                <div>
                  <h2 className="text-sm font-semibold text-slate-200">Configurations</h2>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {selectedConfigs.length} of {configs.length} selected · {formatBytes(uploadedBytes)}
                  </p>
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => setSelectedConfigs(configs.map((c) => c.id))}
                  >
                    Select all
                  </Button>
                  <Button size="sm" variant="secondary" onClick={() => setSelectedConfigs([])}>
                    Clear
                  </Button>
                </div>
              </div>
              <div className="panel-body space-y-2">
                {configs.map((cfg) => (
                  <div
                    key={cfg.id}
                    className={cn(
                      'flex items-center gap-3 rounded-md border px-3.5 py-2.5',
                      selectedConfigs.includes(cfg.id)
                        ? 'border-accent-500/40 bg-accent-500/5'
                        : 'border-base-700 bg-base-900'
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={selectedConfigs.includes(cfg.id)}
                      onChange={() =>
                        setSelectedConfigs((prev) =>
                          prev.includes(cfg.id)
                            ? prev.filter((c) => c !== cfg.id)
                            : [...prev, cfg.id]
                        )
                      }
                      className="h-4 w-4 rounded accent-accent-500"
                      aria-label={`Select ${cfg.filename}`}
                    />
                    <FileText className="h-4 w-4 flex-shrink-0 text-slate-500" />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-slate-200">{cfg.filename}</p>
                      <p className="text-xs text-slate-500">
                        {formatBytes(cfg.size_bytes)} · {cfg.line_count.toLocaleString()} lines
                      </p>
                    </div>
                    <TechBadge>{cfg.content_type || 'text'}</TechBadge>
                    <button
                      onClick={() => removeConfig(cfg.id)}
                      aria-label={`Remove ${cfg.filename}`}
                      className="rounded p-1 text-slate-500 hover:bg-red-500/10 hover:text-red-400"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {configs.length === 0 && !uploading && (
            <p className="text-center text-xs text-slate-600">
              No files uploaded this session. Uploaded configurations are tracked locally until the
              audit is started.
            </p>
          )}
        </div>
      )}

      {/* STEP 3 — Framework */}
      {step === 2 && (
        <div className="space-y-3">
          {[
            {
              id: 'CIS',
              name: 'CIS Benchmarks',
              desc: 'CIS Cisco IOS XE 17.x v2.2.1 (53 controls) and CIS Juniper OS v2.1.0 (17 controls)',
              active: true,
            },
            {
              id: 'NIST',
              name: 'NIST SP 800-53',
              desc: 'Framework architecture available — controls not yet configured',
              active: false,
            },
            {
              id: 'STIG',
              name: 'DISA STIG',
              desc: 'RTR / NDM STIG mappings available — rules are manual-status',
              active: false,
            },
          ].map((f) => (
            <label
              key={f.id}
              className={cn(
                'flex cursor-pointer items-start gap-3 rounded-md border px-4 py-3.5 transition-colors',
                framework === f.id
                  ? 'border-accent-500/50 bg-accent-500/5'
                  : 'border-base-700 bg-base-900',
                !f.active && 'opacity-60'
              )}
            >
              <input
                type="radio"
                name="framework"
                value={f.id}
                checked={framework === f.id}
                onChange={() => f.active && setFramework(f.id)}
                disabled={!f.active}
                className="mt-0.5 h-4 w-4 accent-accent-500"
              />
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-medium text-slate-200">{f.name}</p>
                  {f.active ? (
                    <span className="rounded bg-green-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-green-400">
                      Active
                    </span>
                  ) : (
                    <span className="rounded bg-base-800 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-slate-500">
                      Pending
                    </span>
                  )}
                </div>
                <p className="mt-0.5 text-xs text-slate-500">{f.desc}</p>
              </div>
            </label>
          ))}
        </div>
      )}

      {/* STEP 4 — Review */}
      {step === 3 && (
        <div className="space-y-5">
          <div className="panel">
            <div className="panel-header">
              <h2 className="text-sm font-semibold text-slate-200">Audit metadata</h2>
            </div>
            <div className="panel-body space-y-4">
              <Field label="Audit name" hint="Required">
                <Input
                  value={auditName}
                  onChange={(e) => setAuditName(e.target.value)}
                  placeholder="e.g., Q1 edge-router compliance sweep"
                />
              </Field>
              <Field label="Description">
                <Textarea
                  value={auditDescription}
                  onChange={(e) => setAuditDescription(e.target.value)}
                  placeholder="Optional notes about this audit"
                />
              </Field>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h2 className="text-sm font-semibold text-slate-200">Configuration summary</h2>
            </div>
            <div className="panel-body grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Device</p>
                <p className="mt-1 text-sm text-slate-200">
                  {selectedDeviceObj ? selectedDeviceObj.name : 'Standalone configuration'}
                </p>
                {selectedDeviceObj && (
                  <p className="text-xs text-slate-500">
                    {selectedDeviceObj.vendor ?? 'unknown'} / {selectedDeviceObj.platform ?? 'unknown'}
                  </p>
                )}
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Framework</p>
                <p className="mt-1 text-sm text-slate-200">{framework === 'CIS' ? 'CIS Benchmarks' : framework}</p>
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Files</p>
                <p className="mt-1 text-sm text-slate-200">{selectedConfigs.length} configuration(s)</p>
                <p className="text-xs text-slate-500">{formatBytes(uploadedBytes)} total</p>
              </div>
            </div>
            {selectedConfigs.length > 0 && (
              <div className="border-t border-base-700 px-5 py-3">
                <ul className="space-y-1">
                  {configs
                    .filter((c) => selectedConfigs.includes(c.id))
                    .map((c) => (
                      <li key={c.id} className="flex items-center justify-between text-xs text-slate-400">
                        <span className="truncate">{c.filename}</span>
                        <span className="ml-3 font-mono text-slate-500">{formatBytes(c.size_bytes)}</span>
                      </li>
                    ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* STEP 5 — Run */}
      {step === 4 && (
        <div className="panel flex flex-col items-center py-12 text-center">
          <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-accent-500/40 bg-accent-500/10 text-accent-400">
            <PlayCircle className="h-6 w-6" />
          </div>
          <h2 className="text-base font-semibold text-slate-100">Ready to evaluate</h2>
          <p className="mt-1 max-w-md text-xs text-slate-500">
            The audit pipeline will validate, detect vendor, parse, normalize, and evaluate{' '}
            {selectedConfigs.length} configuration file(s) against the {framework === 'CIS' ? 'CIS' : framework}{' '}
            framework. You will be redirected to live progress.
          </p>
          <div className="mt-5 flex gap-2">
            <Button variant="secondary" onClick={() => setStep(3)}>
              <ChevronLeft className="h-4 w-4" />
              Back
            </Button>
            <Button onClick={execute} loading={executing} size="lg">
              {executing ? 'Starting audit...' : 'Start Audit'}
            </Button>
          </div>
        </div>
      )}

      {/* Footer nav */}
      <div className="mt-7 flex items-center justify-between">
        <Button variant="ghost" onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0}>
          <ChevronLeft className="h-4 w-4" />
          Back
        </Button>
        {step < 4 ? (
          <Button onClick={() => canContinue() && setStep(step + 1)} disabled={!canContinue()}>
            Continue
            <ChevronRight className="h-4 w-4" />
          </Button>
        ) : (
          <span />
        )}
      </div>
    </AppShell>
  );
}
