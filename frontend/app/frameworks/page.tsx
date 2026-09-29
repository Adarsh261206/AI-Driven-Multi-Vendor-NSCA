'use client';

import { useEffect, useState } from 'react';
import { BookOpenCheck, ChevronRight, Database, ShieldCheck } from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { TechBadge } from '@/components/ui/Badge';
import { PageLoader } from '@/components/ui/Progress';
import { complianceAPI, getApiError } from '@/lib/api';
import type { Control, Framework } from '@/types';

export default function FrameworksPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [controls, setControls] = useState<Record<string, Control[]>>({});
  const [selected, setSelected] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (authLoading) return;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await complianceAPI.listFrameworks();
        const list = res.data.items || [];
        setFrameworks(list);
        if (list.length > 0 && !selected) {
          setSelected(list[0].id);
        }
        const map: Record<string, Control[]> = {};
        await Promise.all(
          list.map(async (f) => {
            try {
              const cres = await complianceAPI.listControls(f.id, { per_page: 500 });
              map[f.id] = cres.data.items || [];
            } catch {
              map[f.id] = [];
            }
          })
        );
        setControls(map);
      } catch (err) {
        setError(getApiError(err, 'Failed to load frameworks'));
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [authLoading, selected]);

  if (authLoading || loading) return <PageLoader label="Loading frameworks" />;

  const selectedFramework = frameworks.find((f) => f.id === selected);
  const selectedControls = selected ? (controls[selected] ?? []) : [];

  return (
    <AppShell title="Compliance Frameworks" subtitle="Security evaluation frameworks and their controls — explore benchmarks across vendors">
      {error && (
        <div className="mb-6">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left sidebar — framework list — Odoo generous */}
        <div className="space-y-3">
          <p className="label px-1">Frameworks</p>
          {frameworks.map((f) => {
            const active = selected === f.id;
            const isCis = f.id === 'CIS';
            const isNist = f.id === 'NIST';
            return (
              <button
                key={f.id}
                onClick={() => setSelected(f.id)}
                className={`w-full rounded-xl border p-5 text-left transition-all duration-200 ${
                  active ? 'border-brand-300 bg-brand-50 shadow-odoo ring-1 ring-brand-500/10' : 'border-surface-200 bg-white shadow-odoo hover:border-surface-300 hover:shadow-odoo-md'
                }`}
              >
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div
                      className={`flex h-10 w-10 items-center justify-center rounded-xl ring-1 ${
                        isCis ? 'bg-emerald-50 text-emerald-600 ring-emerald-100' : isNist ? 'bg-blue-50 text-blue-600 ring-blue-100' : 'bg-surface-50 text-ink-400 ring-surface-200'
                      }`}
                    >
                      <ShieldCheck className="h-5 w-5" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-ink-100">{f.name}</p>
                      <p className="mt-0.5 text-xs text-ink-400">
                        {f.versions.join(', ')} · {f.control_count} registered controls
                      </p>
                    </div>
                  </div>
                  <ChevronRight className={`h-4 w-4 shrink-0 transition-colors ${active ? 'text-brand-600' : 'text-ink-400'}`} />
                </div>
              </button>
            );
          })}
        </div>

        {/* Right panel — controls — Odoo card generous */}
        <div className="lg:col-span-2">
          <div className="card overflow-hidden">
            <div className="card-header">
              <div className="min-w-0 flex-1">
                <p className="label mb-1.5">Framework Details</p>
                <h2 className="section-title flex flex-wrap items-center gap-2.5">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                    <BookOpenCheck className="h-4 w-4" />
                  </span>
                  {selectedFramework?.name ?? 'Framework'}
                  <span className="badge-info">{selectedFramework?.id}</span>
                </h2>
                <p className="mt-2 text-sm text-ink-400">
                  Controls exposed by the compliance API — the engine evaluates the full benchmark set during audits
                </p>
              </div>
              <span className="shrink-0 rounded-full bg-surface-50 px-3 py-1 text-xs font-semibold text-ink-400 ring-1 ring-surface-200">{selectedControls.length} controls</span>
            </div>
            <div className="px-6 py-6">
              {selectedControls.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-14 text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-surface-50 text-ink-400 ring-1 ring-surface-200">
                    <Database className="h-6 w-6" />
                  </div>
                  <p className="mt-4 text-sm font-semibold text-ink-300">
                    {selected === 'CIS'
                      ? 'Control list limited by the compliance API'
                      : 'No controls registered for this framework'}
                  </p>
                  <p className="mx-auto mt-2 max-w-md text-xs leading-relaxed text-ink-400">
                    {selected === 'CIS'
                      ? 'The compliance API exposes a subset. The benchmark engine evaluates the full 53 Cisco IOS XE + 17 Juniper OS control sets during audits.'
                      : 'Framework architecture is ready. Controls are loaded from the benchmark engine as they are registered.'}
                  </p>
                </div>
              ) : (
                <ul className="space-y-3">
                  {selectedControls.map((c) => (
                    <li key={c.id} className="rounded-xl border border-surface-200 bg-surface-50/50 px-5 py-4 transition-all duration-150 hover:border-surface-300 hover:bg-white hover:shadow-odoo">
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-semibold leading-tight text-ink-100">{c.title}</p>
                          <p className="mt-1 text-xs leading-relaxed text-ink-400">{c.description}</p>
                        </div>
                        <div className="flex flex-shrink-0 gap-1.5">
                          <span className="badge-info">{c.id}</span>
                          <span className="badge-info">{c.severity}</span>
                        </div>
                      </div>
                      {(c.vendor || c.category) && (
                        <div className="mt-3 flex gap-1.5">
                          {c.vendor && <span className="badge-info">{c.vendor}</span>}
                          {c.category && <span className="badge-info">{c.category}</span>}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
