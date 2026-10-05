'use client';

import { useState } from 'react';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { Modal } from '@/components/ui/Modal';
import { remediationAPI, getApiError } from '@/lib/api';
import type { RemediationPlan, RemediationPlanRecord } from '@/types';

const SAFETY_STYLES: Record<string, string> = {
  safe: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  controlled: 'bg-amber-50 text-amber-700 ring-amber-200',
  high_risk: 'bg-orange-50 text-orange-700 ring-orange-200',
  blocked: 'bg-red-50 text-red-700 ring-red-200',
};

function downloadBlob(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export function PlanSection({ findingId }: { findingId: string }) {
  const [record, setRecord] = useState<RemediationPlanRecord | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [paramValues, setParamValues] = useState<Record<string, string>>({});
  const [approveOpen, setApproveOpen] = useState(false);
  const [notes, setNotes] = useState('');

  const plan: RemediationPlan | null = record?.plan ?? null;

  const generate = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await remediationAPI.plan(findingId);
      setRecord(res.data);
      setParamValues({});
    } catch (err) {
      setError(getApiError(err, 'Failed to generate remediation plan'));
    } finally {
      setBusy(false);
    }
  };

  const approve = async (confirm: boolean) => {    if (!record) return;
    setBusy(true);
    setError(null);
    try {
      const res = await remediationAPI.approve(
        findingId, confirm, paramValues, notes);
      setRecord(res.data);
      setApproveOpen(false);
      setNotes('');
    } catch (err) {
      setError(getApiError(err, 'Failed to record approval decision'));
    } finally {
      setBusy(false);
    }
  };

  const saveParameters = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await remediationAPI.saveParams(findingId, paramValues);
      setRecord(res.data);
    } catch (err) {
      setError(getApiError(err, 'Failed to save parameters'));
    } finally {
      setBusy(false);
    }
  };

  const download = async (kind: 'script' | 'rollback') => {
    setBusy(true);
    setError(null);
    try {
      const res = kind === 'script'
        ? await remediationAPI.scriptBlob(findingId)
        : await remediationAPI.rollbackBlob(findingId);
      const disp = res.headers?.['content-disposition'] as string | undefined;
      const name = disp?.match(/filename="([^"]+)"/)?.[1]
        ?? `nsca_remediation_${record?.plan_id ?? 'plan'}.py`;
      downloadBlob(res.data, name);
    } catch (err) {
      setError(getApiError(err, 'Failed to download script'));
    } finally {
      setBusy(false);
    }
  };

  const copyCommands = async () => {
    if (!plan) return;
    const text = plan.diff.after.join('\n');
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      setError('Copy failed — select the diff text manually.');
    }
  };

  const unresolved = (plan?.params ?? []).filter(
    (p) => p.required && !p.supplied);
  const canApprove = plan != null
    && (record?.status === 'awaiting_approval' || record?.status === 'validated')
    && plan.safe_to_apply;
  const canScript = plan != null && record?.status === 'approved' && plan.safe_to_apply;

  return (
    <div className="card overflow-hidden">
      <div className="card-header">
        <div>
          <p className="label mb-1.5">Structured Plan</p>
          <h2 className="section-title">Remediation Plan</h2>
          <p className="mt-1.5 text-sm text-ink-400">
            Dry-run planning only — NSCA never executes anything on your devices.
          </p>
        </div>
      </div>
      <div className="px-6 py-6 space-y-5">
        {error && (
          <Alert variant="error" onDismiss={() => setError(null)}>{error}</Alert>
        )}

        {!plan && (
          <Button onClick={generate} disabled={busy}>
            {busy ? 'Generating…' : 'Generate Remediation Plan'}
          </Button>
        )}

        {plan && record && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-surface-100 px-2.5 py-0.5 font-mono text-xs text-ink-300">
                {record.status}
              </span>
              <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ${SAFETY_STYLES[plan.safety_class] ?? SAFETY_STYLES.blocked}`}>
                {plan.safety_class.replace('_', ' ').toUpperCase()}
              </span>
              <span className="text-xs text-ink-400">
                Safe to apply: {plan.safe_to_apply ? 'YES' : 'NO'} · Approval required: YES
              </span>
            </div>

            <div>
              <p className="label mb-2.5">Preconditions</p>
              <ul className="space-y-1.5">
                {plan.preconditions.map((p, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-ink-400">
                    <span aria-hidden="true">
                      {!p.passed ? '❌' : p.severity === 'warning' ? '⚠️' : '✅'}
                    </span>
                    <span>
                      <span className="font-mono font-semibold">{p.name}</span>
                      {p.message ? ` — ${p.message}` : ''}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <p className="label mb-2.5">Configuration diff</p>
              <div className="space-y-1 font-mono text-xs">
                {plan.diff.remove.map((l, i) => (
                  <p key={`r${i}`} className="rounded bg-red-50 px-2.5 py-1 text-red-700">− {l}</p>
                ))}
                {plan.diff.add.map((l, i) => (
                  <p key={`a${i}`} className="rounded bg-emerald-50 px-2.5 py-1 text-emerald-700">+ {l}</p>
                ))}
                {plan.diff.add.length === 0 && plan.diff.remove.length === 0 && (
                  <p className="text-ink-400">No command changes in this plan.</p>
                )}
              </div>
              {plan.changes.contexts.filter((c) => c.context).length > 0 && (
                <p className="mt-2 text-xs text-ink-400">
                  Contexts: {plan.changes.contexts.filter((c) => c.context).map((c) => c.context).join(', ')}
                </p>
              )}
            </div>

            {plan.params.length > 0 && (
              <div>
                <p className="label mb-2.5">Parameters</p>
                <div className="space-y-2.5">
                  {plan.params.map((p) => (
                    <div key={p.name} className="flex items-center gap-3">
                      <span className="font-mono text-xs text-ink-300">
                        &lt;{p.name}&gt;
                        <span className="ml-2 text-[10px] uppercase tracking-widest text-ink-500">
                          {p.type}{p.supplied ? ' · supplied' : ' · required'}
                        </span>
                      </span>
                      {!p.supplied && (
                        <input
                          type={p.type === 'secret' ? 'password' : 'text'}
                          value={paramValues[p.name] ?? ''}
                          onChange={(e) => setParamValues((v) => ({ ...v, [p.name]: e.target.value }))}
                          className="input w-56"
                          placeholder={p.type === 'secret' ? '••••••••••' : `Enter ${p.name}…`}
                          aria-label={`Parameter ${p.name}`}
                        />
                      )}
                    </div>
                  ))}
                  <p className="text-[11px] leading-relaxed text-ink-500">
                    Secrets are used once for approval and never stored, logged, or returned.
                  </p>
                  {unresolved.length > 0 && (
                    <Button onClick={saveParameters} disabled={busy} variant="secondary">
                      Save Parameters
                    </Button>
                  )}
                </div>
              </div>
            )}

            {plan.rollback.length > 0 ? (
              <div>
                <p className="label mb-2.5">Rollback (safe inverse available)</p>
                <CodeBlock
                  code={plan.rollback.map((c) => (c.context ? `${c.context}\n` : '') + c.commands.map((x) => ` ${x}`).join('\n')).join('\n')}
                  language="config"
                />
              </div>
            ) : (
              <p className="text-xs text-ink-400">No safe rollback available — this change is one-way unless manually reverted.</p>
            )}

            {plan.verification.length > 0 && (
              <div>
                <p className="label mb-2.5">Verification</p>
                <ol className="list-decimal space-y-2 pl-4 text-xs leading-relaxed text-ink-400">
                  {plan.verification.map((s, i) => (
                    <li key={i} className="pl-1 font-mono">{s}</li>
                  ))}
                </ol>
              </div>
            )}

            {plan.risk_flags.length > 0 && (
              <div>
                <p className="label mb-2.5">Risk flags</p>
                <ul className="space-y-1 text-xs text-ink-400">
                  {plan.risk_flags.map((f, i) => (
                    <li key={i} className="font-mono">{f}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="flex flex-wrap gap-2.5">
              <Button onClick={generate} disabled={busy} variant="secondary">
                Regenerate Plan
              </Button>
              <Button onClick={copyCommands} disabled={busy} variant="secondary">
                Copy Commands
              </Button>
              {canApprove && (
                <Button onClick={() => setApproveOpen(true)} disabled={busy}>
                  Review & Approve
                </Button>
              )}
              {canScript && (
                <>
                  <Button onClick={() => download('script')} disabled={busy}>
                    Download .py
                  </Button>
                  {plan.rollback.length > 0 && (
                    <Button onClick={() => download('rollback')} disabled={busy} variant="secondary">
                      Download Rollback
                    </Button>
                  )}
                </>
              )}
            </div>
            <p className="text-[11px] leading-relaxed text-ink-500">
              Review the generated script before executing it. NSCA does not execute this script on your device.
            </p>
          </>
        )}
      </div>

      <Modal
        open={approveOpen}
        onClose={() => setApproveOpen(false)}
        title="Approve remediation plan"
        description="You are approving this remediation plan."
        size="lg"
        footer={
          <>
            <Button onClick={() => approve(false)} disabled={busy} variant="secondary">
              Reject
            </Button>
            <Button onClick={() => approve(true)} disabled={busy || !plan?.safe_to_apply}>
              Approve (confirm = true)
            </Button>
          </>
        }
      >
        {plan && (
          <div className="space-y-3 text-xs leading-relaxed text-ink-400">
            <p><span className="font-semibold text-ink-100">Safety:</span> {plan.safety_class} · <span className="font-semibold text-ink-100">Safe to apply:</span> {plan.safe_to_apply ? 'YES' : 'NO'}</p>
            <p><span className="font-semibold text-ink-100">Changes:</span></p>
            <CodeBlock code={plan.diff.after.join('\n') || '(no changes)'} language="config" />
            {unresolved.length > 0 && (
              <p className="font-semibold text-red-600">
                Unresolved parameters block approval: {unresolved.map((p) => p.name).join(', ')}. Supply them above first.
              </p>
            )}
            <label className="block">
              <span className="label mb-1.5 block">Notes (optional)</span>
              <input value={notes} onChange={(e) => setNotes(e.target.value)} className="input w-full" placeholder="Change ticket, reason…" />
            </label>
          </div>
        )}
      </Modal>
    </div>
  );
}
