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
        // Load controls for each framework
        const map: Record<string, Control[]> = {};
        await Promise.all(
          list.map(async (f) => {
            try {
              const cres = await complianceAPI.listControls(f.id, { per_page: 100 });
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authLoading]);

  if (authLoading || loading) return <PageLoader label="Loading frameworks" />;

  const selectedFramework = frameworks.find((f) => f.id === selected);
  const selectedControls = selected ? (controls[selected] ?? []) : [];

  return (
    <AppShell title="Compliance Frameworks" subtitle="Security evaluation frameworks and their controls">
      {error && (
        <div className="mb-5">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Framework list */}
        <div className="space-y-3">
          {frameworks.map((f) => {
            const active = selected === f.id;
            const isCis = f.id === 'CIS';
            return (
              <button
                key={f.id}
                onClick={() => setSelected(f.id)}
                className={`w-full rounded-lg border p-4 text-left transition-colors ${
                  active ? 'border-accent-500/50 bg-accent-500/5' : 'border-base-700 bg-base-850 hover:border-base-500'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div
                      className={`flex h-8 w-8 items-center justify-center rounded-md border ${
                        isCis ? 'border-green-500/30 bg-green-500/10 text-green-400' : 'border-base-700 bg-base-900 text-slate-500'
                      }`}
                    >
                      <ShieldCheck className="h-4 w-4" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-slate-200">{f.name}</p>
                      <p className="text-[11px] text-slate-500">
                        {f.versions.join(', ')} · {f.control_count} registered controls
                      </p>
                    </div>
                  </div>
                  <ChevronRight className={`h-4 w-4 ${active ? 'text-accent-400' : 'text-slate-600'}`} />
                </div>
              </button>
            );
          })}
        </div>

        {/* Controls for selected framework */}
        <div className="lg:col-span-2">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                  <BookOpenCheck className="h-4 w-4 text-accent-400" />
                  {selectedFramework?.name ?? 'Framework'}
                  <TechBadge>{selectedFramework?.id}</TechBadge>
                </h2>
                <p className="mt-0.5 text-xs text-slate-500">
                  Controls exposed by the compliance API
                </p>
              </div>
              <TechBadge>{selectedControls.length} controls</TechBadge>
            </div>
            <div className="panel-body">
              {selectedControls.length === 0 ? (
                <div className="py-10 text-center">
                  <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-lg border border-base-700 bg-base-900 text-slate-500">
                    <Database className="h-4 w-4" />
                  </div>
                  <p className="text-sm font-medium text-slate-300">
                    {selected === 'CIS'
                      ? 'Control list limited by the compliance API'
                      : 'No controls registered for this framework'}
                  </p>
                  <p className="mx-auto mt-1 max-w-sm text-xs text-slate-500">
                    {selected === 'CIS'
                      ? 'The live compliance API exposes a small reference set. The benchmark engine evaluates the full 53 Cisco IOS XE + 17 Juniper OS control sets during audits.'
                      : 'Framework architecture is ready. Controls are loaded from the benchmark engine as they are registered.'}
                  </p>
                </div>
              ) : (
                <ul className="space-y-2">
                  {selectedControls.map((c) => (
                    <li key={c.id} className="rounded-md border border-base-700 bg-base-900 px-3.5 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-slate-200">{c.title}</p>
                          <p className="mt-0.5 text-xs text-slate-500">{c.description}</p>
                        </div>
                        <div className="flex flex-shrink-0 gap-1.5">
                          <TechBadge>{c.id}</TechBadge>
                          <TechBadge>{c.severity}</TechBadge>
                        </div>
                      </div>
                      {(c.vendor || c.category) && (
                        <div className="mt-2 flex gap-1.5">
                          {c.vendor && <TechBadge>{c.vendor}</TechBadge>}
                          {c.category && <TechBadge>{c.category}</TechBadge>}
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
