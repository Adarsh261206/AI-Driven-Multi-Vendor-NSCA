'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, FileText, Network, PlayCircle, Server } from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { TechBadge } from '@/components/ui/Badge';
import { PageLoader } from '@/components/ui/Progress';
import { devicesAPI, getApiError } from '@/lib/api';
import { formatDate, formatDateTime } from '@/lib/format';
import type { Device } from '@/types';

export default function DeviceDetailPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const params = useParams();
  const deviceId = params.id as string;

  const [device, setDevice] = useState<Device | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await devicesAPI.get(deviceId);
      setDevice(res.data);
    } catch (err) {
      setError(getApiError(err, 'Device not found'));
    } finally {
      setLoading(false);
    }
  }, [deviceId]);

  useEffect(() => {
    if (!authLoading) load();
  }, [authLoading, load]);

  if (authLoading || loading) return <PageLoader label="Loading device" />;

  if (!device) {
    return (
      <AppShell title="Device">
        <Alert variant="error" title="Device not found">
          {error}
        </Alert>
      </AppShell>
    );
  }

  return (
    <AppShell
      title={device.name}
      subtitle={`${device.vendor ?? 'Unknown vendor'} · ${device.platform ?? 'unknown platform'}`}
      actions={
        <>
          <Link href="/devices">
            <button className="btn-secondary">
              <ArrowLeft className="h-4 w-4" />
              Devices
            </button>
          </Link>
          <Link href={`/audit/new?device=${device.id}`}>
            <button className="btn-primary">
              <PlayCircle className="h-4 w-4" />
              Run Audit
            </button>
          </Link>
        </>
      }
    >
      {error && (
        <div className="mb-6">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3 stagger-children">
        {/* Identity Card — Odoo generous */}
        <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
          <div className="card-header">
            <h3 className="section-title flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                <Server className="h-4 w-4" />
              </span>
              Identity
            </h3>
          </div>
          <div className="px-6 py-5">
            <dl className="space-y-4 text-sm">
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Vendor</dt>
                <dd>{device.vendor ? <span className="badge-info">{device.vendor}</span> : <span className="text-ink-400 text-sm">—</span>}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Platform</dt>
                <dd>{device.platform ? <span className="badge-info">{device.platform}</span> : <span className="text-ink-400 text-sm">—</span>}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Firmware</dt>
                <dd className="font-mono text-xs font-medium text-ink-300">{device.firmware_version ?? '—'}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">IP address</dt>
                <dd className="font-mono text-xs font-medium text-ink-300">{device.ip_address ?? '—'}</dd>
              </div>
              <div className="flex items-center justify-between gap-4 border-t border-surface-100 pt-4">
                <dt className="text-xs font-semibold uppercase tracking-wider text-ink-400">Registered</dt>
                <dd className="text-xs text-ink-400">{formatDate(device.created_at)}</dd>
              </div>
            </dl>
          </div>
        </div>

        {/* Configuration Activity Card */}
        <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
          <div className="card-header">
            <h3 className="section-title flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-50 text-sky-600 ring-1 ring-sky-100">
                <FileText className="h-4 w-4" />
              </span>
              Configuration Activity
            </h3>
          </div>
          <div className="px-6 py-6">
            <p className="metric-value">{device.configuration_count}</p>
            <p className="metric-label mt-1.5">configurations on record</p>
            <div className="mt-5 rounded-xl border border-surface-200 bg-surface-50 px-4 py-3.5">
              <p className="text-xs leading-relaxed text-ink-400">
                Configurations are uploaded as part of audit runs and are not exposed as a separate
                list by the API. Upload a configuration and run an audit to associate it with this
                device.
              </p>
            </div>
            <Link href={`/audit/new?device=${device.id}`} className="mt-5 block">
              <button className="btn-secondary w-full">
                <PlayCircle className="h-4 w-4" />
                Audit this device
              </button>
            </Link>
          </div>
        </div>

        {/* Notes Card */}
        <div className="card overflow-hidden transition-all duration-200 hover:shadow-odoo-md">
          <div className="card-header">
            <h3 className="section-title flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-50 text-amber-600 ring-1 ring-amber-100">
                <Network className="h-4 w-4" />
              </span>
              Notes
            </h3>
          </div>
          <div className="px-6 py-6">
            {device.notes ? (
              <p className="text-sm leading-relaxed text-ink-300">{device.notes}</p>
            ) : (
              <p className="text-sm text-ink-400">No notes recorded.</p>
            )}
            <div className="mt-6 flex items-center justify-between border-t border-surface-100 pt-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-ink-400">Last updated</span>
              <span className="text-xs text-ink-400">{formatDateTime(device.updated_at)}</span>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
