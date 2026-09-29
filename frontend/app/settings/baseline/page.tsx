'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  CheckCircle2,
  ChevronLeft,
  FileJson,
  Layers,
  ListChecks,
  ShieldCheck,
  UploadCloud,
  XCircle,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/Modal';
import { Field, Input, Textarea } from '@/components/ui/Field';
import { PageLoader } from '@/components/ui/Progress';
import { baselinesAPI, getApiError, request } from '@/lib/api';
import { formatDate } from '@/lib/format';
import type {
  BaselineStatusResponse,
  BaselineUploadPayload,
  BaselineValidateResponse,
} from '@/types';

const DEFAULT_FRAMEWORK = 'CIS';
const DEFAULT_BENCHMARK = 'CIS Cisco IOS XE 17.x';

type ConfigStep = 'source' | 'validating' | 'review' | 'activating';

interface ParsedBaselineFile {
  name?: unknown;
  framework?: unknown;
  benchmark?: unknown;
  controls?: unknown;
}

function parseControlsInput(value: string): string[] {
  return value
    .split(/[\n,;]+/)
    .map((c) => c.trim())
    .filter((c) => c.length > 0);
}

export default function CompanyBaselinePage() {
  const { user, isLoading: authLoading } = useRequireAuth();

  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [status, setStatus] = useState<BaselineStatusResponse | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [declining, setDeclining] = useState(false);

  // Configuration flow state
  const [configOpen, setConfigOpen] = useState(false);
  const [step, setStep] = useState<ConfigStep>('source');
  const [name, setName] = useState('Company Security Baseline');
  const [framework, setFramework] = useState(DEFAULT_FRAMEWORK);
  const [benchmark, setBenchmark] = useState(DEFAULT_BENCHMARK);
  const [controlsText, setControlsText] = useState('');
  const [fileError, setFileError] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [validation, setValidation] = useState<BaselineValidateResponse | null>(null);
  const [showControls, setShowControls] = useState(false);
  const [inScopeControls, setInScopeControls] = useState<string[] | null>(null);
  const [controlsLoading, setControlsLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadStatus = useCallback(async () => {
    try {
      const res = await request(
        () => baselinesAPI.status(),
        'Could not load Company Baseline'
      );
      setStatus(res);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Could not load Company Baseline');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!authLoading) loadStatus();
  }, [authLoading, loadStatus]);

  const openConfig = () => {
    setActionError(null);
    setStep('source');
    setValidation(null);
    setFileError(null);
    setFileName(null);
    setControlsText('');
    setName('Company Security Baseline');
    setFramework(DEFAULT_FRAMEWORK);
    setBenchmark(DEFAULT_BENCHMARK);
    setConfigOpen(true);
  };

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    setFileError(null);
    setFileName(file.name);
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as ParsedBaselineFile;
      if (!Array.isArray(parsed.controls) || parsed.controls.length === 0) {
        throw new Error('File must contain a non-empty "controls" array.');
      }
      if (typeof parsed.name !== 'string' || !parsed.name.trim()) {
        throw new Error('File must contain a "name" string.');
      }
      setName(parsed.name.trim());
      if (typeof parsed.framework === 'string' && parsed.framework.trim()) {
        setFramework(parsed.framework.trim());
      }
      if (typeof parsed.benchmark === 'string' && parsed.benchmark.trim()) {
        setBenchmark(parsed.benchmark.trim());
      }
      setControlsText(
        parsed.controls
          .map((c) => String(c).trim())
          .filter((c) => c.length > 0)
          .join('\n')
      );
    } catch (err) {
      setFileError(
        err instanceof Error
          ? err.message
          : 'Invalid baseline file. Expected JSON: { "name", "framework", "benchmark", "controls": ["1.1.1", ...] }'
      );
      setFileName(null);
    }
  };

  const runValidation = async () => {
    const controls = parseControlsInput(controlsText);
    if (controls.length === 0) {
      setActionError('Add at least one CIS control ID (e.g. 1.1.1, one per line).');
      return;
    }
    const payload: BaselineUploadPayload = { name, framework, benchmark, controls };
    setActionError(null);
    setStep('validating');
    try {
      const res = await request(
        () => baselinesAPI.validate(payload),
        'Baseline validation failed'
      );
      setValidation(res);
      setStep('review');
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Baseline validation failed');
      setStep('source');
    }
  };

  const activate = async () => {
    const controls = parseControlsInput(controlsText);
    const payload: BaselineUploadPayload = { name, framework, benchmark, controls };
    setActionError(null);
    setStep('activating');
    try {
      const res = await request(
        () => baselinesAPI.onboarding(payload),
        'Baseline activation failed'
      );
      if (res.activation_blocked) {
        setActionError(
          res.reason || 'Baseline could not be activated. Review the validation errors.'
        );
        setStep('review');
        return;
      }
      setConfigOpen(false);
      await loadStatus();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Baseline activation failed');
      setStep('review');
    }
  };

  const toggleControls = async () => {
    const next = !showControls;
    setShowControls(next);
    if (next && inScopeControls === null) {
      setControlsLoading(true);
      try {
        const res = await request(
          () => baselinesAPI.resolveForAudit(),
          'Could not load baseline controls'
        );
        setInScopeControls(res.in_scope_controls ?? []);
      } catch (err) {
        setActionError(err instanceof Error ? err.message : 'Could not load baseline controls');
      } finally {
        setControlsLoading(false);
      }
    }
  };

  const declineBaseline = async () => {
    setDeclining(true);
    setActionError(null);
    try {
      await request(
        () => baselinesAPI.onboardingNo(),
        'Could not update baseline status'
      );
      await loadStatus();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Could not update baseline status');
    } finally {
      setDeclining(false);
    }
  };

  if (authLoading || loading) return <PageLoader label="Loading Company Baseline" />;

  const configured = status?.baseline_status === 'ACTIVE' && status.baseline;
  const canConfigure = ['admin', 'auditor'].includes(user?.role ?? 'auditor');

  return (
    <AppShell
      title="Company Baseline"
      subtitle="Organization-level compliance scope — configured once, applied to every device audit"
    >
      {loadError && (
        <div className="mb-6">
          <Alert variant="error" title="Could not load Company Baseline" onDismiss={() => setLoadError(null)}>
            {loadError}
          </Alert>
        </div>
      )}

      {actionError && (
        <div className="mb-6">
          <Alert variant="error" title="Action failed" onDismiss={() => setActionError(null)}>
            {actionError}
          </Alert>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3 stagger-children">
        {/* Main status card — Odoo generous */}
        <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md lg:col-span-2">
          <div className="card-header">
            <h3 className="section-title flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                <ShieldCheck className="h-4 w-4" />
              </span>
              Company Security Baseline
            </h3>
            {configured ? (
              <span className="badge-success">ACTIVE</span>
            ) : (
              <span className="badge-info">NOT CONFIGURED</span>
            )}
          </div>
          <div className="px-6 py-6">
            {configured ? (
              <div className="space-y-5">
                <div className="flex items-start gap-4 rounded-xl border border-emerald-200 bg-emerald-50 px-5 py-4">
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-white text-emerald-600 ring-1 ring-emerald-200">
                    <CheckCircle2 className="h-5 w-5" />
                  </span>
                  <div>
                    <p className="text-sm font-semibold text-emerald-900">
                      {status.baseline!.name} — active
                    </p>
                    <p className="mt-1 text-sm leading-relaxed text-emerald-800">
                      {status.baseline!.control_count} CIS control
                      {status.baseline!.control_count === 1 ? '' : 's'} in scope · configured{' '}
                      {formatDate(status.baseline!.activated_at)}
                    </p>
                  </div>
                </div>
                <dl className="space-y-4 text-sm">
                  <div className="flex items-center justify-between gap-4">
                    <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Framework</dt>
                    <dd className="font-medium text-ink-100">{status.baseline!.framework}</dd>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Benchmark</dt>
                    <dd className="font-medium text-ink-100">{status.baseline!.benchmark}</dd>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Controls in scope</dt>
                    <dd className="font-medium text-ink-100">{status.baseline!.control_count}</dd>
                  </div>
                </dl>
                <div className="flex items-start gap-3 rounded-xl border border-surface-200 bg-surface-50 px-5 py-4">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-white text-brand-600 ring-1 ring-brand-100">
                    <Layers className="h-4 w-4" />
                  </span>
                  <p className="text-xs leading-relaxed text-ink-400">
                    Applied automatically to future device audits. Full CIS results remain available
                    separately in every audit report. An organization can have one active Company
                    Baseline in the current MVP.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={toggleControls}
                    loading={controlsLoading}
                  >
                    <ListChecks className="h-4 w-4" />
                    {showControls ? 'Hide Controls' : 'View Controls'}
                  </Button>
                </div>
                {showControls && (
                  <div className="rounded-xl border border-surface-200 bg-surface-50 p-5">
                    <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-ink-400">
                      In-scope controls ({inScopeControls?.length ?? status.baseline?.control_count ?? 0})
                    </p>
                    {inScopeControls === null ? (
                      <p className="text-sm text-ink-400">Loading controls...</p>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {inScopeControls.map((c) => (
                          <span key={c} className="rounded-md border border-surface-200 bg-white px-2 py-1 font-mono text-xs font-medium text-ink-300">
                            {c}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-5">
                <p className="text-sm leading-relaxed text-ink-300">
                  Company Baseline defines which CIS controls are included in your organization&apos;s
                  compliance scope. It is configured <strong>once</strong> at the organization level
                  and automatically applies to future device audits — you never upload it again.
                </p>
                <ul className="space-y-2.5 text-sm text-ink-400">
                  <li className="flex items-start gap-2.5">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                    Controls outside the baseline are OUT_OF_SCOPE for company compliance — Full CIS
                    results remain unchanged and separately visible.
                  </li>
                  <li className="flex items-start gap-2.5">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                    Without a baseline, normal Full CIS auditing continues — no company compliance
                    score is generated.
                  </li>
                  <li className="flex items-start gap-2.5">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                    The baseline is a scope projection over CIS evaluation — it never modifies the
                    underlying CIS benchmark.
                  </li>
                </ul>
                <div className="flex flex-wrap items-center gap-3 pt-1">
                  <Button onClick={openConfig} disabled={!canConfigure}>
                    <UploadCloud className="h-4 w-4" />
                    Configure Company Baseline
                  </Button>
                  {!canConfigure && (
                    <span className="text-xs text-ink-400">
                      Only auditor/admin roles can configure the baseline.
                    </span>
                  )}
                  <Button variant="ghost" size="sm" onClick={declineBaseline} loading={declining}>
                    No baseline — continue with Full CIS
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Side panel — scope explanation — Odoo generous */}
        <div className="space-y-6">
          <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
            <div className="card-header">
              <h3 className="section-title flex items-center gap-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-50 text-amber-600 ring-1 ring-amber-100">
                  <Layers className="h-4 w-4" />
                </span>
                How scope works
              </h3>
            </div>
            <div className="px-6 py-6 space-y-4 text-xs leading-relaxed text-ink-400">
              <div className="rounded-xl border border-surface-200 bg-surface-50 px-4 py-3.5">
                <p className="text-sm font-semibold text-ink-100">Company Baseline</p>
                <p className="mt-1">The CIS controls your organization commits to — PASS / FAIL / REVIEW only for in-scope controls.</p>
              </div>
              <div className="rounded-xl border border-surface-200 bg-surface-50 px-4 py-3.5">
                <p className="text-sm font-semibold text-ink-100">Full CIS</p>
                <p className="mt-1">The complete benchmark evaluation — always authoritative, always visible separately.</p>
              </div>
              <div className="rounded-xl border border-surface-200 bg-surface-50 px-4 py-3.5">
                <p className="text-sm font-semibold text-ink-100">OUT_OF_SCOPE</p>
                <p className="mt-1">Controls not selected in the baseline — never counted as PASS, FAIL or REVIEW for the company score.</p>
              </div>
            </div>
          </div>

          <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
            <div className="card-header">
              <h3 className="section-title flex items-center gap-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600 ring-1 ring-emerald-100">
                  <FileJson className="h-4 w-4" />
                </span>
                Baseline file format
              </h3>
            </div>
            <div className="px-6 py-6">
              <pre className="overflow-x-auto rounded-xl border border-surface-200 bg-ink-1000 p-4 font-mono text-xs leading-relaxed text-emerald-300">
{`{
  "name": "CIS Baseline",
  "framework": "CIS",
  "benchmark": "CIS Cisco IOS XE 17.x",
  "controls": ["1.1.1", "1.1.5", "1.5.2"]
}`}
              </pre>
              <p className="mt-3 text-xs leading-relaxed text-ink-400">
                JSON array of CIS control IDs. You can also paste control IDs directly.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration modal — multi-step flow */}
      <Modal
        open={configOpen}
        onClose={() => setConfigOpen(false)}
        title="Configure Company Baseline"
        description="Define the CIS controls in your organization's compliance scope"
        size="lg"
      >
        <div className="space-y-5">
          {/* Step indicator */}
          <div className="flex items-center gap-2 text-xs font-semibold">
            {(['source', 'review'] as const).map((s, i) => (
              <span key={s} className="flex items-center gap-2">
                <span
                  className={`flex h-6 w-6 items-center justify-center rounded-full text-[11px] ${
                    step === s || step === 'validating' || step === 'activating'
                      ? 'bg-brand-600 text-white'
                      : 'bg-surface-100 text-ink-400'
                  }`}
                >
                  {i + 1}
                </span>
                <span className={step === s || step === 'validating' || step === 'activating' ? 'text-ink-100' : 'text-ink-400'}>
                  {s === 'source' ? 'Upload / Enter' : 'Review & Activate'}
                </span>
                {i === 0 && <span className="h-px w-6 bg-surface-200" />}
              </span>
            ))}
            {(step === 'validating' || step === 'activating') && (
              <span className="flex items-center gap-2 text-brand-600">
                <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-surface-200 border-t-brand-600" />
                {step === 'validating' ? 'Validating...' : 'Activating...'}
              </span>
            )}
          </div>

          {step === 'validating' && (
            <div className="flex items-center justify-center py-10">
              <div className="text-center">
                <span className="mx-auto mb-4 block h-10 w-10 animate-spin rounded-full border-4 border-surface-200 border-t-brand-600" />
                <p className="text-sm font-semibold text-ink-100">Validating baseline against the CIS registry...</p>
                <p className="mt-1 text-xs text-ink-400">Checking control IDs, duplicates and benchmark compatibility</p>
              </div>
            </div>
          )}

          {step === 'activating' && (
            <div className="flex items-center justify-center py-10">
              <div className="text-center">
                <span className="mx-auto mb-4 block h-10 w-10 animate-spin rounded-full border-4 border-surface-200 border-t-brand-600" />
                <p className="text-sm font-semibold text-ink-100">Activating Company Baseline...</p>
                <p className="mt-1 text-xs text-ink-400">This updates the organization-wide compliance scope</p>
              </div>
            </div>
          )}

          {step === 'source' && (
            <>
              {/* Upload zone — matches audit/new drag-drop pattern */}
              <div
                role="button"
                tabIndex={0}
                aria-label="Upload baseline JSON file"
                onClick={() => fileInputRef.current?.click()}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
                }}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  handleFile(e.dataTransfer.files?.[0]);
                }}
                className="flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed border-brand-200 bg-brand-50/50 px-6 py-10 text-center transition-all duration-150 hover:border-brand-400 hover:bg-brand-50"
              >
                <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white text-brand-600 shadow-odoo ring-1 ring-brand-100">
                  <UploadCloud className="h-6 w-6" />
                </span>
                <div>
                  <p className="text-sm font-semibold text-ink-100">
                    {fileName ? fileName : 'Upload baseline JSON'}
                  </p>
                  <p className="mt-1 text-xs text-ink-400">
                    Drag & drop, or click to browse · .json — {'{'} name, framework, benchmark, controls {'}'}
                  </p>
                </div>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,application/json"
                className="hidden"
                onChange={(e) => handleFile(e.target.files?.[0])}
              />
              {fileError && (
                <Alert variant="error" title="Invalid baseline file" onDismiss={() => setFileError(null)}>
                  {fileError}
                </Alert>
              )}

              <div className="flex items-center gap-3 py-1">
                <span className="h-px flex-1 bg-surface-200" />
                <span className="text-xs font-medium text-ink-400">or enter manually</span>
                <span className="h-px flex-1 bg-surface-200" />
              </div>

              <div className="space-y-4">
                <Field label="Baseline name" hint="Display name for the organization baseline">
                  <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Company Security Baseline" />
                </Field>
                <div className="grid grid-cols-2 gap-4">
                  <Field label="Framework">
                    <Input value={framework} onChange={(e) => setFramework(e.target.value)} placeholder="CIS" />
                  </Field>
                  <Field label="Benchmark">
                    <Input value={benchmark} onChange={(e) => setBenchmark(e.target.value)} placeholder="CIS Cisco IOS XE 17.x" />
                  </Field>
                </div>
                <Field
                  label="CIS control IDs"
                  hint="One control ID per line — e.g. 1.1.1, 1.1.5, 1.5.2"
                  error={controlsText.trim() === '' ? undefined : undefined}
                >
                  <Textarea
                    value={controlsText}
                    onChange={(e) => setControlsText(e.target.value)}
                    placeholder={'1.1.1\n1.1.5\n1.5.2\n1.2.8'}
                    className="min-h-[140px] font-mono text-sm"
                  />
                </Field>
                {parseControlsInput(controlsText).length > 0 && (
                  <div className="flex items-center gap-2 text-xs font-medium text-ink-400">
                    <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                    {parseControlsInput(controlsText).length} control
                    {parseControlsInput(controlsText).length === 1 ? '' : 's'} parsed
                  </div>
                )}
              </div>
            </>
          )}

          {step === 'review' && validation && (
            <div className="space-y-5">
              {validation.status === 'valid' ? (
                <div className="flex items-start gap-4 rounded-xl border border-emerald-200 bg-emerald-50 px-5 py-4">
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-white text-emerald-600 ring-1 ring-emerald-200">
                    <CheckCircle2 className="h-5 w-5" />
                  </span>
                  <div>
                    <p className="text-sm font-semibold text-emerald-900">Baseline valid</p>
                    <p className="mt-1 text-sm text-emerald-800">
                      {validation.validation_result.valid_count} CIS control
                      {validation.validation_result.valid_count === 1 ? '' : 's'} selected
                    </p>
                  </div>
                </div>
              ) : (
                <Alert variant="error" title="Baseline validation failed">
                  <p className="mb-3">
                    {validation.validation_result.invalid_controls.length} invalid control
                    {validation.validation_result.invalid_controls.length === 1 ? '' : 's'} — fix them
                    and validate again. Invalid controls are never silently removed.
                  </p>
                  <ul className="space-y-2">
                    {validation.validation_result.errors.map((err) => (
                      <li key={`${err.control_id}-${err.reason}`} className="flex items-center gap-2.5 text-sm">
                        <XCircle className="h-4 w-4 shrink-0 text-red-600" />
                        <span className="font-mono font-semibold text-ink-100">{err.control_id}</span>
                        <span className="rounded-full bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-700">
                          {err.reason}
                        </span>
                      </li>
                    ))}
                  </ul>
                </Alert>
              )}

              <div className="rounded-xl border border-surface-200 bg-surface-50 p-5">
                <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-ink-400">Review</p>
                <dl className="space-y-3 text-sm">
                  <div className="flex items-center justify-between gap-4">
                    <dt className="text-ink-400">Framework</dt>
                    <dd className="font-medium text-ink-100">{validation.framework}</dd>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <dt className="text-ink-400">Benchmark</dt>
                    <dd className="font-medium text-ink-100">{validation.benchmark}</dd>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <dt className="text-ink-400">Selected controls</dt>
                    <dd className="font-medium text-ink-100">{validation.control_count}</dd>
                  </div>
                </dl>
                <div className="mt-4 flex flex-wrap gap-1.5">
                  {parseControlsInput(controlsText).map((c) => (
                    <span key={c} className="rounded-md border border-surface-200 bg-white px-2 py-1 font-mono text-xs font-medium text-ink-300">
                      {c}
                    </span>
                  ))}
                </div>
              </div>

              <p className="text-xs leading-relaxed text-ink-400">
                Activating this baseline changes the organization&apos;s CIS compliance scope for future
                audits. The underlying CIS benchmark is not modified — Full CIS results remain
                available in every audit report.
              </p>
            </div>
          )}

          {/* Footer actions */}
          <div className="flex items-center justify-between border-t border-surface-100 pt-5">
            <div>
              {step === 'review' && (
                <Button variant="ghost" size="sm" onClick={() => setStep('source')}>
                  <ChevronLeft className="h-4 w-4" />
                  Back
                </Button>
              )}
            </div>
            <div className="flex items-center gap-3">
              {step === 'source' && (
                <Button onClick={runValidation}>Validate Baseline</Button>
              )}
              {step === 'review' && validation?.status === 'valid' && (
                <Button variant="success" onClick={activate} disabled={!canConfigure}>
                  Activate Baseline
                </Button>
              )}
              {step === 'review' && validation?.status !== 'valid' && (
                <Button variant="secondary" onClick={() => setStep('source')}>
                  Fix Controls
                </Button>
              )}
            </div>
          </div>
        </div>
      </Modal>
    </AppShell>
  );
}