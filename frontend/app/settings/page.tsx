'use client';

import { KeyRound, ShieldCheck, User } from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { TechBadge } from '@/components/ui/Badge';
import { PageLoader } from '@/components/ui/Progress';
import { formatDateTime } from '@/lib/format';

export default function SettingsPage() {
  const { user, isLoading: authLoading } = useRequireAuth();

  if (authLoading || !user) return <PageLoader label="Loading" />;

  return (
    <AppShell title="Settings" subtitle="Workspace configuration — account, security and data handling">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2 stagger-children">
        {/* Account Card — Odoo generous */}
        <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
          <div className="card-header">
            <h3 className="section-title flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                <User className="h-4 w-4" />
              </span>
              Account
            </h3>
            <span className="badge-info">{user.role}</span>
          </div>
          <div className="px-6 py-6">
            <dl className="space-y-5 text-sm">
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Name</dt>
                <dd className="font-medium text-ink-100">{user.full_name ?? '—'}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Email</dt>
                <dd className="font-medium text-ink-100">{user.email}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Role</dt>
                <dd>
                  <span className="badge-info capitalize">{user.role}</span>
                </dd>
              </div>
              <div className="flex items-center justify-between gap-4 border-t border-surface-100 pt-5">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Member since</dt>
                <dd className="text-xs text-ink-400">{formatDateTime(user.created_at)}</dd>
              </div>
            </dl>
          </div>
        </div>

        {/* Security Card — Odoo generous */}
        <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
          <div className="card-header">
            <h3 className="section-title flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-50 text-amber-600 ring-1 ring-amber-100">
                <KeyRound className="h-4 w-4" />
              </span>
              Security
            </h3>
          </div>
          <div className="px-6 py-6 space-y-4">
            <div className="rounded-xl border border-surface-200 bg-surface-50 px-5 py-4">
              <p className="text-sm font-semibold text-ink-100">Session tokens</p>
              <p className="mt-1.5 text-xs leading-relaxed text-ink-400">
                Access tokens are stored in browser storage and automatically refreshed. Sign out
                from the sidebar to clear the session.
              </p>
            </div>
            <div className="rounded-xl border border-surface-200 bg-surface-50 px-5 py-4">
              <p className="text-sm font-semibold text-ink-100">Data handling</p>
              <p className="mt-1.5 text-xs leading-relaxed text-ink-400">
                Device configurations are encrypted at rest. Evidence shown in findings is limited to
                matched configuration lines. Secrets are never displayed.
              </p>
            </div>
            <div className="flex items-start gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3.5">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-white text-emerald-600 ring-1 ring-emerald-200">
                <ShieldCheck className="h-4 w-4" />
              </span>
              <p className="text-xs leading-relaxed text-emerald-800">
                API keys and external AI provider configuration are managed server-side.
              </p>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
