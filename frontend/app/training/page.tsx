'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  BrainCircuit,
  Check,
  CheckCircle2,
  ChevronDown,
  GitBranch,
  History,
  Lightbulb,
  Pencil,
  PlayCircle,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  X,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Field, Input, Select, Textarea } from '@/components/ui/Field';
import { TechBadge } from '@/components/ui/Badge';
import { Modal } from '@/components/ui/Modal';
import { DataTable } from '@/components/ui/DataTable';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { PageLoader, ProgressBar } from '@/components/ui/Progress';
import {
  trainingAPI,
  configurationsAPI,
  auditExecutionAPI,
  findingsAPI,
  getApiError,
  request,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import { formatDate, formatConfidence } from '@/lib/format';
import type { AIHypothesis, TrainingMapping, Audit } from '@/types';

const RELEVANCE_COLORS: Record<string, string> = {
  high: '#dc2626',
  medium: '#ca8a04',
  low: '#2563eb',
  none: '#6b7280',
  unknown: '#6b7280',
};

export default function TrainingPage() {
  const { isLoading: authLoading } = useRequireAuth();

  const [vendor, setVendor] = useState('cisco');
  const [platform, setPlatform] = useState('ios_xe');
  const [rawSyntax, setRawSyntax] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [hypothesis, setHypothesis] = useState<AIHypothesis | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [editMeaning, setEditMeaning] = useState('');
  const [editPath, setEditPath] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [savedMapping, setSavedMapping] = useState<TrainingMapping | null>(null);


  const [reanalyzeFile, setReanalyzeFile] = useState<File | null>(null);
  const [analyzing2, setAnalyzing2] = useState(false);
  const [beforeReviews, setBeforeReviews] = useState<number | null>(null);


  const [mappings, setMappings] = useState<TrainingMapping[]>([]);
  const [mappingsLoading, setMappingsLoading] = useState(true);
  const [versionsFor, setVersionsFor] = useState<TrainingMapping | null>(null);
  const [versions, setVersions] = useState<Awaited<ReturnType<typeof trainingAPI.getVersions>>['data']['items']>([]);
  const [versionsLoading, setVersionsLoading] = useState(false);

  const loadMappings = useCallback(async () => {
    setMappingsLoading(true);
    try {
      const res = await trainingAPI.listMappings({ per_page: 50 });
      setMappings(res.data.items || []);
    } catch {
      setMappings([]);
    } finally {
      setMappingsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!authLoading) loadMappings();
  }, [authLoading, loadMappings]);

  const analyze = async () => {
    if (!rawSyntax.trim()) {
      setError('Enter the unknown configuration syntax first.');
      return;
    }
    setAnalyzing(true);
    setError(null);
    setSavedMapping(null);
    setHypothesis(null);
    try {
      const res = await request(
        () => trainingAPI.getHypothesis(vendor, platform, rawSyntax.trim()),
        'Hypothesis request failed'
      );
      setHypothesis(res as unknown as AIHypothesis);
      setEditMeaning((res as unknown as AIHypothesis).suggested_meaning);
      setEditPath((res as unknown as AIHypothesis).universal_model_path ?? '');
      setEditNotes('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Hypothesis request failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const saveMapping = async (confirmed: boolean) => {
    setSaving(true);
    setError(null);
    try {
      const res = await request(
        () =>
          trainingAPI.createMapping({
            vendor,
            platform,
            raw_syntax: rawSyntax.trim(),
            semantic_meaning: editMeaning,
            universal_model_path: editPath || undefined,
            admin_notes: editNotes || undefined,
          }),
        'Failed to save mapping'
      );
      setSavedMapping(res as unknown as TrainingMapping);
      setConfirmOpen(false);
      await loadMappings();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save mapping');
    } finally {
      setSaving(false);
    }
  };

  const reject = () => {
    // A hypothesis is pre-persistence (no mapping ID exists yet), so
    // "reject" dismisses the suggestion locally. The previous code fired
    // rejectMapping('none', ...) — a fabricated ID the backend rejects.
    if (!hypothesis) return;
    setHypothesis(null);
    setRawSyntax('');
  };

  const openVersions = async (mapping: TrainingMapping) => {
    setVersionsFor(mapping);
    setVersionsLoading(true);
    setVersions([]);
    try {
      const res = await trainingAPI.getVersions(mapping.id);
      setVersions(res.data.items || []);
    } catch {
      setVersions([]);
    } finally {
      setVersionsLoading(false);
    }
  };

  const runReanalyze = async (): Promise<number> => {
    if (!reanalyzeFile) return 0;
    setAnalyzing2(true);
    setError(null);
    try {
      const cfg = await request(
        () => configurationsAPI.upload(reanalyzeFile),
        'Upload failed'
      );
      const audit = await request(
        () =>
          auditExecutionAPI.execute({
            name: `Re-analysis ${new Date().toLocaleTimeString()}`,
            configuration_ids: [(cfg as unknown as { id: string }).id],
            framework: 'CIS',
            framework_version: '2024.1',
          }),
        'Failed to start audit'
      );
      let reviews = 0;
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 4000));
        const status = await auditExecutionAPI.getStatus(audit.id);
        if (status.data.status === 'completed') {
          const findings = await findingsAPI.listByAudit(audit.id, { per_page: 100 });
          const reviewFindings = (findings.data.items || []).filter(
            (f) => f.evidence?.result?.toLowerCase() === 'review'
          );
          reviews = reviewFindings.length;
          break;
        }
        if (status.data.status === 'failed') break;
      }
      return reviews;
    } finally {
      setAnalyzing2(false);
    }
  };


  if (authLoading) return <PageLoader label="Loading" />;

  const relevanceColor = hypothesis ? RELEVANCE_COLORS[hypothesis.security_relevance] ?? '#6b7280' : '#6b7280';

  return (
    <AppShell
      title="AI Training"
      subtitle="Teach the system to understand unknown configuration syntax — Human-in-the-Loop"
      actions={
        <button className="btn-secondary" onClick={loadMappings}>
          <RefreshCw className="h-4 w-4" />
          Refresh Mappings
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

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
        <div className="xl:col-span-3">
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h2 className="section-title flex items-center gap-2.5">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                    <BrainCircuit className="h-4 w-4" />
                  </span>
                  Unknown Configuration Interpretation
                </h2>
                <p className="mt-2 text-sm leading-relaxed text-ink-400">
                  Submit syntax the deterministic engine could not map. AI proposes a hypothesis — you decide.
                </p>
              </div>
            </div>
            <div className="px-6 py-6 space-y-5">
              <div className="grid grid-cols-2 gap-5">
                <div>
                  <label className="label">Vendor</label>
                  <select value={vendor} onChange={(e) => setVendor(e.target.value)} className="select">
                    <option value="cisco">Cisco</option>
                    <option value="juniper">Juniper</option>
                    <option value="fortinet">Fortinet</option>
                  </select>
                </div>
                <div>
                  <label className="label">Platform</label>
                  <select value={platform} onChange={(e) => setPlatform(e.target.value)} className="select">
                    <option value="ios_xe">IOS XE</option>
                    <option value="junos">JUNOS</option>
                    <option value="fortios">FortiOS</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="label">Raw syntax <span className="font-normal normal-case tracking-normal text-ink-400">— Paste a configuration line the engine reported as unknown (REVIEW).</span></label>
                <textarea
                  value={rawSyntax}
                  onChange={(e) => setRawSyntax(e.target.value)}
                  placeholder={'e.g., set system services ssh protocol-version v2'}
                  className="input font-mono text-xs min-h-[96px] resize-y"
                  rows={3}
                />
              </div>
              <button className="btn-primary" onClick={analyze} disabled={analyzing}>
                <Sparkles className="h-4 w-4" />
                {analyzing ? 'Generating…' : 'Generate AI Hypothesis'}
              </button>

              {hypothesis && (
                <div className="space-y-5 rounded-xl border border-brand-200 bg-brand-50/40 p-6">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <p className="label mb-1">AI Hypothesis</p>
                      <p className="text-sm font-semibold leading-relaxed text-ink-100">
                        {hypothesis.suggested_meaning}
                      </p>
                    </div>
                    <span
                      className={cn(
                        'badge text-xs shrink-0',
                        hypothesis.confidence >= 0.7
                          ? 'badge-pass'
                          : hypothesis.confidence >= 0.4
                            ? 'badge-medium'
                            : 'badge-critical'
                      )}
                    >
                      {formatConfidence(hypothesis.confidence)}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-5 text-sm">
                    <div className="rounded-xl bg-white border border-brand-100 px-4 py-3.5">
                      <p className="label mb-1">Security relevance</p>
                      <p className="font-semibold capitalize" style={{ color: relevanceColor }}>
                        {hypothesis.security_relevance}
                      </p>
                    </div>
                    <div className="rounded-xl bg-white border border-brand-100 px-4 py-3.5">
                      <p className="label mb-1">Suggested universal path</p>
                      <p className="font-mono text-xs text-ink-300">
                        {hypothesis.universal_model_path || 'none suggested'}
                      </p>
                    </div>
                  </div>

                  {hypothesis.reasoning && (
                    <div>
                      <p className="label">Why</p>
                      <p className="mt-1 text-xs leading-relaxed text-ink-400">{hypothesis.reasoning}</p>
                    </div>
                  )}

                  {hypothesis.alternative_interpretations?.length > 0 && (
                    <div>
                      <p className="label mb-2.5">Alternative interpretations</p>
                      <ul className="space-y-2.5">
                        {hypothesis.alternative_interpretations.map((alt, i) => (
                          <li key={i} className="rounded-xl border border-surface-200 bg-white px-4 py-3.5">
                            <div className="flex items-center justify-between gap-2">
                              <p className="text-xs font-medium leading-relaxed text-ink-300">{alt.meaning}</p>
                              <span className="font-mono text-xs font-medium text-ink-400">
                                {formatConfidence(alt.confidence)}
                              </span>
                            </div>
                            {alt.reasoning && <p className="mt-1.5 text-xs leading-relaxed text-ink-400">{alt.reasoning}</p>}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="flex flex-wrap gap-2.5 border-t border-brand-200 pt-5">
                    <button
                      className="btn-primary"
                      onClick={() => {
                        setEditMeaning(hypothesis.suggested_meaning);
                        setEditPath(hypothesis.universal_model_path ?? '');
                        setEditNotes('');
                        setConfirmOpen(true);
                      }}
                    >
                      <Check className="h-4 w-4" />
                      Confirm
                    </button>
                    <button
                      className="btn-secondary"
                      onClick={() => {
                        setEditMeaning(hypothesis.suggested_meaning);
                        setEditPath(hypothesis.universal_model_path ?? '');
                        setEditNotes('');
                        setConfirmOpen(true);
                      }}
                    >
                      <Pencil className="h-4 w-4" />
                      Edit & Confirm
                    </button>
                    <button className="btn-danger" onClick={reject} disabled={saving}>
                      <X className="h-4 w-4" />
                      {saving ? 'Rejecting…' : 'Reject'}
                    </button>
                  </div>
                </div>
              )}

              {savedMapping && (
                <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-6">
                  <div className="flex items-center gap-2.5">
                    <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-white text-emerald-600 ring-1 ring-emerald-200">
                      <CheckCircle2 className="h-4 w-4" />
                    </span>
                    <p className="text-sm font-semibold text-emerald-800">Mapping saved</p>
                    <span className="badge-info">v{savedMapping.version}</span>
                  </div>
                  <p className="mt-3 text-sm leading-relaxed text-ink-400">
                    <span className="font-mono text-ink-300">{savedMapping.raw_syntax}</span> →{' '}
                    <span className="text-ink-300">{savedMapping.semantic_meaning}</span>
                    {savedMapping.universal_model_path && (
                      <>
                        {' '}· <span className="font-mono text-brand-600">{savedMapping.universal_model_path}</span>
                      </>
                    )}
                  </p>
                  <p className="mt-2 text-xs leading-relaxed text-ink-400">
                    Stored in the knowledge base with admin confirmation. The normalization engine
                    consults the knowledge base for subsequent audits.
                  </p>
                </div>
              )}

              <div className="rounded-xl border border-surface-200 bg-surface-50 px-6 py-5">
                <p className="flex items-center gap-2.5 text-sm font-semibold text-ink-100">
                  <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-white text-brand-600 ring-1 ring-surface-200 shadow-xs">
                    <RefreshCw className="h-3.5 w-3.5" />
                  </span>
                  Re-analyze a configuration
                </p>
                <p className="mt-2 text-xs leading-relaxed text-ink-400">
                  Run a real audit against a config and count REVIEW findings.
                </p>
                <div className="mt-4 flex flex-wrap items-center gap-3">
                  <input
                    type="file"
                    accept=".txt,.cfg,.conf,.zip"
                    onChange={(e) => setReanalyzeFile(e.target.files?.[0] ?? null)}
                    className="text-xs text-ink-400 file:mr-3 file:rounded-lg file:border file:border-surface-200 file:bg-white file:px-4 file:py-2 file:text-xs file:font-medium file:text-ink-300 hover:file:bg-surface-50 file:shadow-xs"
                    aria-label="Choose configuration to re-analyze"
                  />
                  <button
                    className="btn-secondary text-xs px-4 py-2"
                    disabled={!reanalyzeFile}
                    onClick={async () => {
                      setAnalyzing2(true);
                      setError(null);
                      try {
                        const count = await runReanalyze();
                        setBeforeReviews(count);
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'Re-analysis failed');
                      } finally {
                        setAnalyzing2(false);
                      }
                    }}
                  >
                    <PlayCircle className="h-3.5 w-3.5" />
                    {analyzing2 ? 'Running audit…' : 'Run Analysis'}
                  </button>
                </div>
                {beforeReviews != null && (
                  <div className="mt-5 rounded-xl border border-surface-200 bg-white px-5 py-4">
                    <p className="label mb-1">Review findings in fresh audit</p>
                    <p className="font-mono text-lg font-bold text-amber-600">{beforeReviews} REVIEW</p>
                    <p className="mt-1 text-xs text-ink-400">
                      Confirm a mapping above, then re-run to compare.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="xl:col-span-2">
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h2 className="section-title flex items-center gap-2.5">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-50 text-amber-600 ring-1 ring-amber-100">
                    <Lightbulb className="h-4 w-4" />
                  </span>
                  Knowledge Base Mappings
                </h2>
                <p className="mt-2 text-sm leading-relaxed text-ink-400">
                  Admin-confirmed syntax → security meaning translations
                </p>
              </div>
              <span className="rounded-full bg-surface-50 px-3 py-1 text-xs font-semibold text-ink-400 ring-1 ring-surface-200">{mappings.length}</span>
            </div>
            <div className="p-0">
              <DataTable<TrainingMapping>
                loading={mappingsLoading}
                rows={mappings}
                rowKey={(m) => m.id}
                onRowClick={openVersions}
                emptyTitle="No mappings yet"
                emptyDescription="Run a hypothesis analysis and confirm a mapping to build the knowledge base."
                dense
                columns={[
                  {
                    key: 'raw_syntax',
                    header: 'Syntax',
                    render: (m) => (
                      <div className="min-w-0">
                        <p className="truncate font-mono text-xs font-medium text-ink-300">{m.raw_syntax}</p>
                        <p className="mt-1 truncate text-xs text-ink-400">{m.semantic_meaning}</p>
                      </div>
                    ),
                    sortValue: (m) => m.raw_syntax,
                  },
                  {
                    key: 'vendor',
                    header: 'Vendor',
                    render: (m) => <span className="badge-info">{m.vendor}</span>,
                    sortValue: (m) => m.vendor,
                  },
                  {
                    key: 'version',
                    header: 'V',
                    align: 'center',
                    render: (m) => <span className="font-mono text-xs font-medium text-ink-400">v{m.version}</span>,
                    sortValue: (m) => m.version,
                  },
                  {
                    key: 'created_at',
                    header: 'Added',
                    render: (m) => <span className="text-xs text-ink-400">{formatDate(m.created_at)}</span>,
                    sortValue: (m) => m.created_at,
                  },
                ]}
              />
            </div>
          </div>
        </div>
      </div>

      <Modal
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="Confirm Mapping"
        description="The confirmed mapping is stored in the knowledge base and used for subsequent audits."
        footer={
          <>
            <button className="btn-secondary" onClick={() => setConfirmOpen(false)}>
              Cancel
            </button>
            <button className="btn-primary" onClick={() => saveMapping(true)} disabled={saving}>
              <CheckCircle2 className="h-4 w-4" />
              {saving ? 'Saving…' : 'Save Mapping'}
            </button>
          </>
        }
      >
        <div className="space-y-5">
          <div className="rounded-xl border border-surface-200 bg-surface-50 px-5 py-4">
            <p className="label mb-1">Raw syntax</p>
            <p className="font-mono text-xs font-medium text-ink-300">{rawSyntax}</p>
          </div>
          <div>
            <label className="label">Semantic meaning</label>
            <input value={editMeaning} onChange={(e) => setEditMeaning(e.target.value)} className="input" />
          </div>
          <div>
            <label className="label">Universal model path <span className="font-normal normal-case tracking-normal text-ink-400">— Use dotted notation, e.g. management.ssh.version</span></label>
            <input
              value={editPath}
              onChange={(e) => setEditPath(e.target.value)}
              placeholder="management.ssh.version"
              className="input font-mono text-xs"
            />
          </div>
          <div>
            <label className="label">Admin notes</label>
            <textarea
              value={editNotes}
              onChange={(e) => setEditNotes(e.target.value)}
              placeholder="Context for other auditors"
              className="input min-h-[72px] resize-y"
              rows={2}
            />
          </div>
        </div>
      </Modal>

      <Modal
        open={versionsFor != null}
        onClose={() => setVersionsFor(null)}
        title="Mapping Version History"
        description={versionsFor ? `${versionsFor.vendor}/${versionsFor.platform} · ${versionsFor.raw_syntax}` : ''}
        size="lg"
      >
        {versionsLoading ? (
          <div className="py-10 text-center text-sm text-ink-400">Loading versions…</div>
        ) : versions.length === 0 ? (
          <div className="flex flex-col items-center py-10 text-center">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-surface-50 text-ink-400 ring-1 ring-surface-200">
              <History className="h-5 w-5" />
            </div>
            <p className="mt-3 text-sm text-ink-400">No version history.</p>
          </div>
        ) : (
          <ol className="space-y-3">
            {versions.map((v) => (
              <li key={v.version} className="rounded-xl border border-surface-200 bg-surface-50 px-5 py-4">
                <div className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2.5 text-sm font-semibold text-ink-100">
                    <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-white text-brand-600 ring-1 ring-surface-200">
                      <GitBranch className="h-4 w-4" />
                    </span>
                    Version {v.version}
                  </span>
                  <span className="text-xs text-ink-400">{formatDate(v.changed_at)}</span>
                </div>
                <p className="mt-2.5 text-sm leading-relaxed text-ink-400">{v.semantic_meaning}</p>
                {v.universal_model_path && (
                  <span className="badge-info mt-2.5">{v.universal_model_path}</span>
                )}
                {v.change_reason && (
                  <p className="mt-2 text-xs italic leading-relaxed text-ink-400">Reason: {v.change_reason}</p>
                )}
              </li>
            ))}
          </ol>
        )}
      </Modal>
    </AppShell>
  );
}
