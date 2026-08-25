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
  const severityMeta = SEVERITY_META[finding.severity];

  const evidenceSteps = e
    ? [
        {
          label: 'Raw Configuration',
          icon: <FileWarning className="h-3.5 w-3.5" />,
          body: e.raw_config ? (
            <CodeBlock
              code={e.raw_config}
              language={e.vendor || 'config'}
              lineNumbers
              maxHeight={160}
            />
          ) : (
            <p className="text-xs text-slate-500">No raw evidence captured for this finding.</p>
          ),
          detail: e.raw_config_line_numbers?.length
            ? `Source lines: ${e.raw_config_line_numbers.join(', ')}`
            : null,
        },
        {
          label: 'Parsed Representation',
          icon: <ChevronRight className="h-3.5 w-3.5" />,
          body: (
            <p className="font-mono text-xs text-slate-300">
              {e.parsed_value != null ? valueToString(e.parsed_value) : 'Not captured (benchmark evaluation path)'}
            </p>
          ),
          detail: e.parsed_path ? `Path: ${e.parsed_path}` : null,
        },
        {
          label: 'Normalized Model',
          icon: <Target className="h-3.5 w-3.5" />,
          body: (
            <div className="space-y-1.5">
              <TechBadge>{e.universal_model_path || '—'}</TechBadge>
              <p className="font-mono text-xs text-slate-300">
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
          icon: <ShieldAlert className="h-3.5 w-3.5" />,
          body: (
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <TechBadge>{e.control_id || '—'}</TechBadge>
                <span className="text-sm font-medium text-slate-200">
                  {e.control_description || finding.title}
                </span>
              </div>
            </div>
          ),
          detail: e.vendor ? `${e.vendor} / ${e.platform ?? ''}` : null,
        },
        {
          label: 'Expected vs Actual',
          icon: <ArrowRight className="h-3.5 w-3.5" />,
          body: (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Expected</p>
                <p className="mt-1 font-mono text-xs text-slate-300">{valueToString(e.expected_value)}</p>
              </div>
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Actual</p>
                <p className="mt-1 font-mono text-xs text-slate-300">{valueToString(e.actual_value)}</p>
              </div>
            </div>
          ),
          detail: `Operator: ${e.operator || '—'}`,
        },
        {
          label: 'Evaluation Result',
          icon: <ClipboardCheck className="h-3.5 w-3.5" />,
          body: (
            <div className="space-y-2">
              <ResultBadge result={e.result} />
              {e.result_reasoning && (
                <p className="text-xs text-slate-400 italic">{e.result_reasoning}</p>
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
            <Button variant="secondary">Back to Audit</Button>
          </Link>
        ) : undefined
      }
    >
      {error && (
        <div className="mb-5">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      {/* Header row */}
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SeverityBadge severity={finding.severity} />
        <FindingStatusBadge status={finding.status} />
        <TechBadge>
          {finding.affected_vendor ? `${finding.affected_vendor}/${finding.affected_platform ?? '?'}` : 'vendor unknown'}
        </TechBadge>
        {finding.affected_device && <TechBadge>{finding.affected_device}</TechBadge>}
        <span className="text-xs text-slate-500">Confidence {formatConfidence(finding.confidence)}</span>
        <span className="text-xs text-slate-500">Created {formatDateTime(finding.created_at)}</span>
        <div className="ml-auto flex items-center gap-2">
          <Select
            value={finding.status}
            onChange={(e) => changeStatus(e.target.value)}
            disabled={updating}
            className="!w-40"
            aria-label="Change finding status"
          >
            <option value="open">Open</option>
            <option value="in_progress">In progress</option>
            <option value="resolved">Resolved</option>
            <option value="accepted">Accepted risk</option>
          </Select>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        {/* Evidence chain */}
        <div className="xl:col-span-2">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h2 className="text-sm font-semibold text-slate-200">Evidence Chain</h2>
                <p className="mt-0.5 text-xs text-slate-500">
                  Every stage traces from the raw configuration to the evaluation result
                </p>
              </div>
            </div>
            <div className="panel-body space-y-0">
              {evidenceSteps.map((step, i) => (
                <div key={step.label} className="relative pb-6 pl-9 last:pb-0">
                  {/* Connector line */}
                  {i < evidenceSteps.length - 1 && (
                    <span className="absolute left-[15px] top-8 bottom-0 w-px bg-base-700" aria-hidden />
                  )}
                  <span
                    className="absolute left-0 top-0 flex h-8 w-8 items-center justify-center rounded-full border border-base-600 bg-base-900 text-slate-400"
                    aria-hidden
                  >
                    {step.icon}
                  </span>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">
                        {step.label}
                      </h3>
                      {step.detail && <span className="text-[11px] text-slate-600">{step.detail}</span>}
                    </div>
                    <div className="mt-2">{step.body}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Remediation */}
        <div className="space-y-5">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h2 className="text-sm font-semibold text-slate-200">Remediation</h2>
                <p className="mt-0.5 text-xs text-slate-500">Recommended configuration change</p>
              </div>
            </div>
            <div className="panel-body space-y-4">
              {rem && rem.recommended_config ? (
                <>
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                      Why it matters
                    </p>
                    <p className="mt-1 text-xs text-slate-400">
                      {rem.why_it_matters || rem.description || 'This control is required by the benchmark.'}
                    </p>
                  </div>
                  <div>
                    <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                      Recommended configuration
                    </p>
                    <CodeBlock code={rem.recommended_config} language={rem.vendor || 'config'} />
                  </div>
                  {rem.vendor && rem.platform && (
                    <div className="flex gap-2">
                      <TechBadge>{rem.vendor}</TechBadge>
                      <TechBadge>{rem.platform}</TechBadge>
                    </div>
                  )}
                  {rem.references && rem.references.length > 0 && (
                    <div>
                      <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                        Benchmark reference
                      </p>
                      <ul className="space-y-1">
                        {rem.references.map((ref, i) => (
                          <li key={i} className="flex items-start gap-1.5 text-xs text-slate-400">
                            <BookOpen className="mt-0.5 h-3 w-3 flex-shrink-0 text-accent-400" />
                            <span className="break-all">{ref}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {rem.confidence != null && (
                    <p className="text-xs text-slate-500">
                      Remediation confidence: {formatConfidence(rem.confidence)}
                    </p>
                  )}
                </>
              ) : (
                <div className="rounded-md border border-base-700 bg-base-900 px-3.5 py-3">
                  <p className="text-xs text-slate-400">
                    No automated remediation metadata is available for this finding.
                  </p>
                </div>
              )}
              <p className="flex items-start gap-1.5 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-400">
                <ShieldAlert className="mt-0.5 h-3 w-3 flex-shrink-0" />
                Commands are never executed automatically. Apply changes manually after validating
                against your change-management process.
              </p>
            </div>
          </div>

          {/* Verification / rollback */}
          {rem && (rem.verification_steps?.length || rem.rollback_steps?.length) && (
            <div className="panel">
              <div className="panel-header">
                <h2 className="text-sm font-semibold text-slate-200">Verification & Rollback</h2>
              </div>
              <div className="panel-body space-y-4">
                {rem.verification_steps && rem.verification_steps.length > 0 && (
                  <div>
                    <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                      Verification
                    </p>
                    <ol className="list-decimal space-y-1 pl-4 text-xs text-slate-400">
                      {rem.verification_steps.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ol>
                  </div>
                )}
                {rem.rollback_steps && rem.rollback_steps.length > 0 && (
                  <div>
                    <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                      Rollback
                    </p>
                    <ol className="list-decimal space-y-1 pl-4 text-xs text-slate-400">
                      {rem.rollback_steps.map((s, i) => (
                        <li key={i}>{s}</li>
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
