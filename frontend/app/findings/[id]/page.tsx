'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useSearchParams } from 'next/navigation';
import {
  ArrowRight,
  BookOpen,
  ChevronRight,
  ClipboardCheck,
  FileWarning,
  ShieldAlert,
  Target,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { TechBadge, SeverityBadge, ResultBadge, FindingStatusBadge } from '@/components/ui/Badge';
import { Select } from '@/components/ui/Field';
import { PageLoader } from '@/components/ui/Progress';
import { findingsAPI, getApiError, request } from '@/lib/api';
import { formatDateTime, formatConfidence } from '@/lib/format';
import { SEVERITY_META } from '@/lib/security';
import type { Finding } from '@/types';

function valueToString(v: unknown): string {
  if (v == null) return '—';
  if (typeof v === 'boolean') return String(v);
  if (typeof v === 'object') {
    try {
      return JSON.stringify(v, null, 2);
    } catch {
      return String(v);
    }
  }
  return String(v);
}

export default function FindingDetailPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const params = useParams();
  const searchParams = useSearchParams();
  const findingId = params.id as string;
  const auditId = searchParams.get('audit');

  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await findingsAPI.get(findingId);
      setFinding(res.data);
    } catch (err) {
      setError(getApiError(err, 'Finding not found'));
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  useEffect(() => {
    if (!authLoading) load();
  }, [authLoading, load]);

  const changeStatus = async (status: string) => {
    if (!finding) return;
    setUpdating(true);
    setError(null);
    try {
      await request(() => findingsAPI.updateStatus(finding.id, status), 'Failed to update status');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update status');
    } finally {
      setUpdating(false);
    }
  };

  if (authLoading || loading) return <PageLoader label="Loading finding" />;

  if (!finding) {
    return (
      <AppShell title="Finding">
        <Alert variant="error" title="Finding not found">
          {error}
        </Alert>
      </AppShell>
    );
  }

  const e = finding.evidence;
  const rem = finding.remediation;

  const evidenceSteps = e
    ? [
        {
          label: 'Raw Configuration',
          icon: <FileWarning className="h-4 w-4" />,
          body: e.raw_config ? (
            <CodeBlock
              code={e.raw_config}
              language={e.vendor || 'config'}
              lineNumbers
              maxHeight={180}
            />
          ) : (
            <p className="text-xs leading-relaxed text-ink-400">No raw evidence captured for this finding.</p>
          ),
          detail: e.raw_config_line_numbers?.length
            ? `Source lines: ${e.raw_config_line_numbers.join(', ')}`
            : null,
        },
        {
          label: 'Parsed Representation',
          icon: <ChevronRight className="h-4 w-4" />,
          body: (
            <p className="font-mono text-xs leading-relaxed text-ink-300">
              {e.parsed_value != null ? valueToString(e.parsed_value) : 'Not captured (benchmark evaluation path)'}
            </p>
          ),
          detail: e.parsed_path ? `Path: ${e.parsed_path}` : null,
        },
        {
          label: 'Normalized Model',
          icon: <Target className="h-4 w-4" />,
          body: (
            <div className="space-y-2">
              <span className="badge-info font-mono text-xs">{e.universal_model_path || '—'}</span>
              <p className="font-mono text-xs leading-relaxed text-ink-300">
                {e.normalized_value != null ? valueToString(e.normalized_value) : '—'}
              </p>
            </div>
          ),
          detail:
            e.normalization_confidence != null
              ? `Normalization confidence: ${formatConfidence(e.normalization_confidence)}`
              : null,
        },
        {
          label: 'Security Control',
          icon: <ShieldAlert className="h-4 w-4" />,
          body: (
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="badge-info">{e.control_id || '—'}</span>
                <span className="text-sm font-medium leading-relaxed text-ink-300">
                  {e.control_description || finding.title}
                </span>
              </div>
            </div>
          ),
          detail: e.vendor ? `${e.vendor} / ${e.platform ?? ''}` : null,
        },
        {
          label: 'Expected vs Actual',
          icon: <ArrowRight className="h-4 w-4" />,
          body: (
            <div className="grid grid-cols-2 gap-5">
              <div className="rounded-xl bg-surface-50 border border-surface-200 px-4 py-3.5">
                <p className="label mb-1">Expected</p>
                <p className="font-mono text-xs leading-relaxed text-ink-300">{valueToString(e.expected_value)}</p>
              </div>
              <div className="rounded-xl bg-surface-50 border border-surface-200 px-4 py-3.5">
                <p className="label mb-1">Actual</p>
                <p className="font-mono text-xs leading-relaxed text-ink-300">{valueToString(e.actual_value)}</p>
              </div>
            </div>
          ),
          detail: `Operator: ${e.operator || '—'}`,
        },
        {
          label: 'Evaluation Result',
          icon: <ClipboardCheck className="h-4 w-4" />,
          body: (
            <div className="space-y-2.5">
              <ResultBadge result={e.result} />
              {e.result_reasoning && (
                <p className="text-xs leading-relaxed text-ink-400 italic">{e.result_reasoning}</p>
              )}
            </div>
          ),
          detail: `Overall confidence: ${formatConfidence(e.overall_confidence ?? finding.confidence)}`,
        },
      ]
    : [];

  return (
    <AppShell
      title={finding.title}
      subtitle={finding.description}
      actions={
        auditId ? (
          <Link href={`/audit/${auditId}`}>
            <button className="btn-secondary">Back to Audit</button>
          </Link>
        ) : undefined
      }
    >
      {error && (
        <div className="mb-6">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      <div className="mb-6 flex flex-wrap items-center gap-2.5">
        <SeverityBadge severity={finding.severity} />
        <FindingStatusBadge status={finding.status} />
        <span className="badge-info">
          {finding.affected_vendor ? `${finding.affected_vendor}/${finding.affected_platform ?? '?'}` : 'vendor unknown'}
        </span>
        {finding.affected_device && <span className="badge-info">{finding.affected_device}</span>}
        <span className="rounded-full bg-white px-3 py-1 text-xs font-medium text-ink-400 ring-1 ring-surface-200">Confidence {formatConfidence(finding.confidence)}</span>
        <span className="text-xs text-ink-400">Created {formatDateTime(finding.created_at)}</span>
        <div className="ml-auto flex items-center gap-2">
          <select
            value={finding.status}
            onChange={(e) => changeStatus(e.target.value)}
            disabled={updating}
            className="select !w-44 !py-2 text-xs font-medium"
            aria-label="Change finding status"
          >
            <option value="open">Open</option>
            <option value="in_progress">In progress</option>
            <option value="resolved">Resolved</option>
            <option value="accepted">Accepted risk</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Evidence Chain — Odoo generous */}
        <div className="xl:col-span-2">
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <p className="label mb-1.5">Audit Trail</p>
                <h2 className="section-title">Evidence Chain</h2>
                <p className="mt-1.5 text-sm leading-relaxed text-ink-400">
                  Every stage traces from the raw configuration to the evaluation result
                </p>
              </div>
            </div>
            <div className="px-6 py-6">
              <div className="relative">
                {evidenceSteps.map((step, i) => (
                  <div key={step.label} className="relative pb-7 pl-12 last:pb-0">
                    {i < evidenceSteps.length - 1 && (
                      <span className="absolute left-[16px] top-9 bottom-0 w-px bg-surface-200" aria-hidden />
                    )}
                    <span
                      className="absolute left-0 top-0 flex h-8 w-8 items-center justify-center rounded-xl border border-surface-200 bg-white text-ink-400 shadow-xs"
                      aria-hidden
                    >
                      {step.icon}
                    </span>
                    <div>
                      <div className="flex flex-wrap items-center gap-2.5">
                        <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-300">{step.label}</h3>
                        {step.detail && <span className="rounded-full bg-surface-50 px-2.5 py-0.5 text-xs text-ink-400 ring-1 ring-surface-200">{step.detail}</span>}
                      </div>
                      <div className="mt-3">{step.body}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Remediation sidebar — Odoo generous */}
        <div className="space-y-6">
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <p className="label mb-1.5">Action Plan</p>
                <h2 className="section-title">Remediation</h2>
                <p className="mt-1.5 text-sm text-ink-400">Recommended configuration change</p>
              </div>
            </div>
            <div className="px-6 py-6 space-y-5">
              {rem && rem.recommended_config ? (
                <>
                  <div>
                    <p className="label">Why it matters</p>
                    <p className="mt-1.5 text-sm leading-relaxed text-ink-400">
                      {rem.why_it_matters || rem.description || 'This control is required by the benchmark.'}
                    </p>
                  </div>
                  <div>
                    <p className="label mb-2.5">Recommended configuration</p>
                    <CodeBlock code={rem.recommended_config} language={rem.vendor || 'config'} />
                  </div>
                  {rem.vendor && rem.platform && (
                    <div className="flex gap-2">
                      <span className="badge-info">{rem.vendor}</span>
                      <span className="badge-info">{rem.platform}</span>
                    </div>
                  )}
                  {rem.references && rem.references.length > 0 && (
                    <div>
                      <p className="label mb-2.5">Benchmark reference</p>
                      <ul className="space-y-2">
                        {rem.references.map((ref, i) => (
                          <li key={i} className="flex items-start gap-2.5 rounded-lg bg-surface-50 border border-surface-200 px-3 py-2.5 text-xs leading-relaxed text-ink-400">
                            <BookOpen className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-brand-600" />
                            <span className="break-all">{ref}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {rem.confidence != null && (
                    <p className="text-xs text-ink-400">
                      Remediation confidence: {formatConfidence(rem.confidence)}
                    </p>
                  )}
                </>
              ) : (
                <div className="rounded-xl border border-surface-200 bg-surface-50 px-5 py-4">
                  <p className="text-xs leading-relaxed text-ink-400">
                    No automated remediation metadata is available for this finding.
                  </p>
                </div>
              )}
              <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3.5">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-white text-amber-600 ring-1 ring-amber-200">
                  <ShieldAlert className="h-4 w-4" />
                </span>
                <p className="text-xs leading-relaxed text-amber-800">
                  Commands are never executed automatically. Apply changes manually after validating
                  against your change-management process.
                </p>
              </div>
            </div>
          </div>

          {rem && (rem.verification_steps?.length || rem.rollback_steps?.length) && (
            <div className="card overflow-hidden">
              <div className="card-header">
                <h2 className="section-title">Verification & Rollback</h2>
              </div>
              <div className="px-6 py-6 space-y-5">
                {rem.verification_steps && rem.verification_steps.length > 0 && (
                  <div>
                    <p className="label mb-2.5">Verification</p>
                    <ol className="list-decimal space-y-2 pl-4 text-xs leading-relaxed text-ink-400">
                      {rem.verification_steps.map((s, i) => (
                        <li key={i} className="pl-1">{s}</li>
                      ))}
                    </ol>
                  </div>
                )}
                {rem.rollback_steps && rem.rollback_steps.length > 0 && (
                  <div>
                    <p className="label mb-2.5">Rollback</p>
                    <ol className="list-decimal space-y-2 pl-4 text-xs leading-relaxed text-ink-400">
                      {rem.rollback_steps.map((s, i) => (
                        <li key={i} className="pl-1">{s}</li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}
