'use client';

import { Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  ArrowRight,
  Check,
  ChevronLeft,
  ChevronRight,
  FileText,
  ListChecks,
  PlayCircle,
  ShieldCheck,
  UploadCloud,
  X,
  Zap,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { PageLoader } from '@/components/ui/Progress';
import { configurationsAPI, auditExecutionAPI, request } from '@/lib/api';
import { cn } from '@/lib/utils';
import { formatBytes } from '@/lib/format';
import type { Configuration } from '@/types';

const STEPS = [
  { id: 'upload', label: 'Upload', icon: UploadCloud },
  { id: 'review', label: 'Review', icon: ListChecks },
  { id: 'run', label: 'Run', icon: PlayCircle },
];

const MAX_UPLOAD_MB = 10;
const ACCEPTED = '.txt,.cfg,.conf,.zip';
const SESSION_KEY = 'guardian_pending_configs';

export default function NewAuditPage() {
  return (
    <Suspense fallback={<PageLoader label="Loading audit workspace" />}>
      <NewAuditWizard />
    </Suspense>
  );
}

function NewAuditWizard() {
  const { isLoading: authLoading } = useRequireAuth();
  const router = useRouter();

  const [step, setStep] = useState(0);
  const [configs, setConfigs] = useState<Configuration[]>([]);
  const [selectedConfigs, setSelectedConfigs] = useState<string[]>([]);
  const [auditName, setAuditName] = useState('');
  const [auditDescription, setAuditDescription] = useState('');

  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [executing, setExecuting] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (raw) setConfigs(JSON.parse(raw) as Configuration[]);
    } catch {}
  }, []);

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
        const res = await request(() => configurationsAPI.upload(file), `Upload of ${file.name} failed`);
        added.push(res as unknown as Configuration);
      } catch (err) {
        setUploadError(err instanceof Error ? err.message : `Upload of ${file.name} failed`);
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

  const canContinue = (): boolean => {
    if (step === 0) return selectedConfigs.length > 0;
    if (step === 1) return auditName.trim().length > 0;
    return true;
  };

  const execute = async () => {
    setExecuting(true);
    setError(null);
    try {
      const audit = await request(
        () => auditExecutionAPI.execute({
          name: auditName.trim(),
          description: auditDescription.trim() || undefined,
          configuration_ids: selectedConfigs,
          framework: 'CIS',
          framework_version: '2024.1',
        }),
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
        {/* STEP 0 — Upload */}
        {step === 0 && (
          <div className="space-y-6">
            <div>
              <h2 className="page-title">Upload configuration</h2>
              <p className="page-subtitle mt-2 max-w-2xl">
                Drop your network device config — Cisco, Juniper, Fortinet, Palo Alto, or any CLI. Vendor and framework are auto-detected.
              </p>
            </div>

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
                Vendor + framework auto-detected on next step
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
                      <p className="text-sm font-semibold text-ink-100">{selectedConfigs.length} file(s)</p>
                      <p className="text-xs text-ink-400 mt-1">{formatBytes(uploadedBytes)}</p>
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
