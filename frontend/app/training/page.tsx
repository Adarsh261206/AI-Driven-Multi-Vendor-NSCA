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
  high: '#ef4444',
  medium: '#f59e0b',
  low: '#38bdf8',
  none: '#94a3b8',
  unknown: '#94a3b8',
};

export default function TrainingPage() {
  const { isLoading: authLoading } = useRequireAuth();

  // Analysis state
  const [vendor, setVendor] = useState('cisco');
  const [platform, setPlatform] = useState('ios_xe');
  const [rawSyntax, setRawSyntax] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [hypothesis, setHypothesis] = useState<AIHypothesis | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Confirm/Edit state
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [editMeaning, setEditMeaning] = useState('');
  const [editPath, setEditPath] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [savedMapping, setSavedMapping] = useState<TrainingMapping | null>(null);

  // Re-analyze state
  const [reanalyzeOpen, setReanalyzeOpen] = useState(false);
  const [reanalyzeFile, setReanalyzeFile] = useState<File | null>(null);
  const [analyzing2, setAnalyzing2] = useState(false);
  const [beforeReviews, setBeforeReviews] = useState<number | null>(null);
  const [afterReviews, setAfterReviews] = useState<number | null>(null);
  const [reanalyzeAudit, setReanalyzeAudit] = useState<Audit | null>(null);

  // Mapping list
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
      if (confirmed) {
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
      } else {
        // Edit flow: create with edited fields (mappings API creates confirmed at v1)
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
      }
      setConfirmOpen(false);
      await loadMappings();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save mapping');
    } finally {
      setSaving(false);
    }
  };

  const reject = async () => {
    if (!hypothesis) return;
    setSaving(true);
    setError(null);
    try {
      await request(
        () => trainingAPI.rejectMapping('none', 'Rejected by administrator'),
        'Failed to reject'
      );
      // No mapping existed for a fresh hypothesis; record rejection locally
      setHypothesis(null);
      setRawSyntax('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reject');
    } finally {
      setSaving(false);
    }
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

  // ------------------------------------------------------------------
  // Re-analyze: run a real audit, count REVIEWs before/after
  // ------------------------------------------------------------------

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
      // Poll until complete
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

  const startReanalyze = async () => {
    setError(null);
    setReanalyzeOpen(true);
  };

  if (authLoading) return <PageLoader label="Loading" />;

  const relevanceColor = hypothesis ? RELEVANCE_COLORS[hypothesis.security_relevance] ?? '#94a3b8' : '#94a3b8';

  return (
    <AppShell
      title="AI Training"
      subtitle="Teach the system to understand unknown configuration syntax"
      actions={
        <Button variant="secondary" onClick={loadMappings}>
          <RefreshCw className="h-4 w-4" />
          Refresh Mappings
        </Button>
      }
    >
      {error && (
        <div className="mb-5">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-5">
        {/* Analysis panel */}
        <div className="xl:col-span-3">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                  <BrainCircuit className="h-4 w-4 text-accent-400" />
                  Unknown Configuration Interpretation
                </h2>
                <p className="mt-0.5 text-xs text-slate-500">
                  Submit syntax the deterministic engine could not map. AI proposes a hypothesis —
                  you decide.
                </p>
              </div>
            </div>
            <div className="panel-body space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <Field label="Vendor">
                  <Select value={vendor} onChange={(e) => setVendor(e.target.value)}>
                    <option value="cisco">Cisco</option>
                    <option value="juniper">Juniper</option>
                    <option value="fortinet">Fortinet</option>
                  </Select>
                </Field>
                <Field label="Platform">
                  <Select value={platform} onChange={(e) => setPlatform(e.target.value)}>
                    <option value="ios_xe">IOS XE</option>
                    <option value="junos">JUNOS</option>
                    <option value="fortios">FortiOS</option>
                  </Select>
                </Field>
              </div>
              <Field
                label="Raw syntax"
                hint="Paste a configuration line the engine reported as unknown (REVIEW)."
              >
                <Textarea
                  value={rawSyntax}
                  onChange={(e) => setRawSyntax(e.target.value)}
                  placeholder={'e.g., set system services ssh protocol-version v2'}
                  className="font-mono text-xs"
                  rows={3}
                />
              </Field>
              <Button onClick={analyze} loading={analyzing}>
                <Sparkles className="h-4 w-4" />
                Generate AI Hypothesis
              </Button>

              {/* Hypothesis result */}
              {hypothesis && (
                <div className="mt-2 space-y-4 rounded-lg border border-accent-500/25 bg-accent-500/5 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                        AI Hypothesis
                      </p>
                      <p className="mt-1 text-sm font-medium text-slate-100">
                        {hypothesis.suggested_meaning}
                      </p>
                    </div>
                    <TechBadge
                      className={cn(
                        '!text-[11px]',
                        hypothesis.confidence >= 0.7
                          ? '!text-green-400'
                          : hypothesis.confidence >= 0.4
                            ? '!text-amber-400'
                            : '!text-red-400'
                      )}
                    >
                      {formatConfidence(hypothesis.confidence)}
                    </TechBadge>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                        Security relevance
                      </p>
                      <p className="mt-0.5 font-medium" style={{ color: relevanceColor }}>
                        {hypothesis.security_relevance}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                        Suggested universal path
                      </p>
                      <p className="mt-0.5 font-mono text-slate-300">
                        {hypothesis.universal_model_path || 'none suggested'}
                      </p>
                    </div>
                  </div>

                  {hypothesis.reasoning && (
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Why</p>
                      <p className="mt-0.5 text-xs text-slate-400">{hypothesis.reasoning}</p>
                    </div>
                  )}

                  {hypothesis.alternative_interpretations?.length > 0 && (
                    <div>
                      <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                        Alternative interpretations
                      </p>
                      <ul className="space-y-1.5">
                        {hypothesis.alternative_interpretations.map((alt, i) => (
                          <li key={i} className="rounded-md border border-base-700 bg-base-900 px-3 py-2">
                            <div className="flex items-center justify-between gap-2">
                              <p className="text-xs text-slate-300">{alt.meaning}</p>
                              <span className="font-mono text-[11px] text-slate-500">
                                {formatConfidence(alt.confidence)}
                              </span>
                            </div>
                            {alt.reasoning && <p className="mt-0.5 text-[11px] text-slate-500">{alt.reasoning}</p>}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="flex flex-wrap gap-2 border-t border-base-700 pt-3">
                    <Button
                      variant="success"
                      onClick={() => {
                        setEditMeaning(hypothesis.suggested_meaning);
                        setEditPath(hypothesis.universal_model_path ?? '');
                        setEditNotes('');
                        setConfirmOpen(true);
                      }}
                    >
                      <Check className="h-4 w-4" />
                      Confirm
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setEditMeaning(hypothesis.suggested_meaning);
                        setEditPath(hypothesis.universal_model_path ?? '');
                        setEditNotes('');
                        setConfirmOpen(true);
                      }}
                    >
                      <Pencil className="h-4 w-4" />
                      Edit & Confirm
                    </Button>
                    <Button variant="danger" onClick={reject} loading={saving}>
                      <X className="h-4 w-4" />
                      Reject
                    </Button>
                  </div>
                </div>
              )}

              {/* Saved mapping state */}
              {savedMapping && (
                <div className="rounded-lg border border-green-500/25 bg-green-500/5 p-4">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-400" />
                    <p className="text-sm font-medium text-green-300">Mapping saved</p>
                    <TechBadge>v{savedMapping.version}</TechBadge>
                  </div>
                  <p className="mt-1.5 text-xs text-slate-400">
                    <span className="font-mono">{savedMapping.raw_syntax}</span> →{' '}
                    <span className="text-slate-300">{savedMapping.semantic_meaning}</span>
                    {savedMapping.universal_model_path && (
                      <>
                        {' '}· <span className="font-mono text-accent-400">{savedMapping.universal_model_path}</span>
                      </>
                    )}
                  </p>
                  <p className="mt-1 text-[11px] text-slate-500">
                    Stored in the knowledge base with admin confirmation. The normalization engine
                    consults the knowledge base for subsequent audits.
                  </p>
                </div>
              )}

              {/* Re-analyze */}
              <div className="rounded-lg border border-base-700 bg-base-900 p-4">
                <p className="flex items-center gap-2 text-xs font-medium text-slate-300">
                  <RefreshCw className="h-3.5 w-3.5 text-accent-400" />
                  Re-analyze a configuration
                </p>
                <p className="mt-1 text-[11px] text-slate-500">
                  Run a real audit against a config and compare REVIEW counts before/after teaching.
                </p>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <input
                    type="file"
                    accept=".txt,.cfg,.conf,.zip"
                    onChange={(e) => setReanalyzeFile(e.target.files?.[0] ?? null)}
                    className="text-xs text-slate-400 file:mr-2 file:rounded file:border-0 file:bg-base-800 file:px-2.5 file:py-1 file:text-xs file:text-slate-300"
                    aria-label="Choose configuration to re-analyze"
                  />
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={!reanalyzeFile}
                    onClick={async () => {
                      setAnalyzing2(true);
                      setError(null);
                      try {
                        const count = await runReanalyze();
                        setBeforeReviews(count);
                        setAfterReviews(null);
                        setReanalyzeAudit(null);
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'Re-analysis failed');
                      } finally {
                        setAnalyzing2(false);
                      }
                    }}
                  >
                    <PlayCircle className="h-3.5 w-3.5" />
                    {analyzing2 ? 'Running audit...' : 'Run Analysis'}
                  </Button>
                </div>
                {beforeReviews != null && (
                  <div className="mt-3 grid grid-cols-2 gap-3">
                    <div className="rounded-md border border-base-700 px-3 py-2.5">
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                        Before training
                      </p>
                      <p className="font-mono text-xl font-semibold text-amber-400">{beforeReviews} REVIEW</p>
                    </div>
                    <div className="rounded-md border border-base-700 px-3 py-2.5">
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                        After confirmation
                      </p>
                      <p className="font-mono text-xl font-semibold text-slate-200">
                        {afterReviews ?? '—'} REVIEW
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Mapping list */}
        <div className="xl:col-span-2">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                  <Lightbulb className="h-4 w-4 text-accent-400" />
                  Knowledge Base Mappings
                </h2>
                <p className="mt-0.5 text-xs text-slate-500">
                  Admin-confirmed syntax → security meaning translations
                </p>
              </div>
              <TechBadge>{mappings.length}</TechBadge>
            </div>
            <div className="panel-body p-0">
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
                        <p className="truncate font-mono text-xs text-slate-300">{m.raw_syntax}</p>
                        <p className="mt-0.5 truncate text-[11px] text-slate-500">{m.semantic_meaning}</p>
                      </div>
                    ),
                    sortValue: (m) => m.raw_syntax,
                  },
                  {
                    key: 'vendor',
                    header: 'Vendor',
                    render: (m) => <TechBadge>{m.vendor}</TechBadge>,
                    sortValue: (m) => m.vendor,
                  },
                  {
                    key: 'version',
                    header: 'V',
                    align: 'center',
                    render: (m) => <span className="font-mono text-xs text-slate-400">v{m.version}</span>,
                    sortValue: (m) => m.version,
                  },
                  {
                    key: 'created_at',
                    header: 'Added',
                    render: (m) => <span className="text-[11px] text-slate-500">{formatDate(m.created_at)}</span>,
                    sortValue: (m) => m.created_at,
                  },
                ]}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Confirm / edit modal */}
      <Modal
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="Confirm Mapping"
        description="The confirmed mapping is stored in the knowledge base and used for subsequent audits."
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => saveMapping(true)} loading={saving}>
              <CheckCircle2 className="h-4 w-4" />
              Save Mapping
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="rounded-md border border-base-700 bg-base-900 px-3 py-2.5">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Raw syntax</p>
            <p className="mt-0.5 font-mono text-xs text-slate-300">{rawSyntax}</p>
          </div>
          <Field label="Semantic meaning">
            <Input value={editMeaning} onChange={(e) => setEditMeaning(e.target.value)} />
          </Field>
          <Field label="Universal model path" hint="Use dotted notation, e.g. management.ssh.version">
            <Input
              value={editPath}
              onChange={(e) => setEditPath(e.target.value)}
              placeholder="management.ssh.version"
              className="font-mono text-xs"
            />
          </Field>
          <Field label="Admin notes">
            <Textarea
              value={editNotes}
              onChange={(e) => setEditNotes(e.target.value)}
              placeholder="Context for other auditors"
              rows={2}
            />
          </Field>
        </div>
      </Modal>

      {/* Version history modal */}
      <Modal
        open={versionsFor != null}
        onClose={() => setVersionsFor(null)}
        title="Mapping Version History"
        description={versionsFor ? `${versionsFor.vendor}/${versionsFor.platform} · ${versionsFor.raw_syntax}` : ''}
        size="lg"
      >
        {versionsLoading ? (
          <div className="py-6 text-center text-xs text-slate-500">Loading versions...</div>
        ) : versions.length === 0 ? (
          <div className="py-6 text-center text-xs text-slate-500">No version history.</div>
        ) : (
          <ol className="space-y-3">
            {versions.map((v) => (
              <li key={v.version} className="rounded-md border border-base-700 bg-base-900 px-3.5 py-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2 text-xs font-semibold text-slate-200">
                    <GitBranch className="h-3.5 w-3.5 text-accent-400" />
                    Version {v.version}
                  </span>
                  <span className="text-[11px] text-slate-500">{formatDate(v.changed_at)}</span>
                </div>
                <p className="mt-1.5 text-xs text-slate-400">{v.semantic_meaning}</p>
                {v.universal_model_path && (
                  <TechBadge className="mt-1">{v.universal_model_path}</TechBadge>
                )}
                {v.change_reason && (
                  <p className="mt-1 text-[11px] italic text-slate-500">Reason: {v.change_reason}</p>
                )}
              </li>
            ))}
          </ol>
        )}
      </Modal>
    </AppShell>
  );
}
