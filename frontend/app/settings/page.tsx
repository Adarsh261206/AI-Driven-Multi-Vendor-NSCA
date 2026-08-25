'use client';

import { KeyRound, ShieldCheck, User } from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { TechBadge } from '@/components/ui/Badge';
import { PageLoader } from '@/components/ui/Progress';
import { formatDateTime } from '@/lib/format';

export default function SettingsPage() {
  const { user, isLoading: authLoading } = useRequireAuth();

  if (authLoading || !user) return <PageLoader label="Loading" />;

  return (
    <AppShell title="Settings" subtitle="Workspace configuration">
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <User className="h-4 w-4 text-accent-400" />
              Account
            </CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-3 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Name</dt>
                <dd className="text-slate-200">{user.full_name ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Email</dt>
                <dd className="text-slate-200">{user.email}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Role</dt>
                <dd>
                  <TechBadge>{user.role}</TechBadge>
                </dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Member since</dt>
                <dd className="text-xs text-slate-400">{formatDateTime(user.created_at)}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-accent-400" />
              Security
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="rounded-md border border-base-700 bg-base-900 px-3.5 py-3">
              <p className="text-xs font-medium text-slate-300">Session tokens</p>
              <p className="mt-1 text-[11px] text-slate-500">
                Access tokens are stored in browser storage and automatically refreshed. Sign out
                from the sidebar to clear the session.
              </p>
            </div>
            <div className="rounded-md border border-base-700 bg-base-900 px-3.5 py-3">
              <p className="text-xs font-medium text-slate-300">Data handling</p>
              <p className="mt-1 text-[11px] text-slate-500">
                Device configurations are encrypted at rest. Evidence shown in findings is limited to
                matched configuration lines. Secrets are never displayed.
              </p>
            </div>
            <div className="flex items-center gap-2 rounded-md border border-green-500/20 bg-green-500/5 px-3.5 py-3">
              <ShieldCheck className="h-4 w-4 text-green-400" />
              <p className="text-xs text-slate-400">
                API keys and external AI provider configuration are managed server-side.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
