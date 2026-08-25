'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, FileText, Network, PlayCircle, Server } from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
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
            <Button variant="secondary">
              <ArrowLeft className="h-4 w-4" />
              Devices
            </Button>
          </Link>
          <Link href={`/audit/new?device=${device.id}`}>
            <Button>
              <PlayCircle className="h-4 w-4" />
              Run Audit
            </Button>
          </Link>
        </>
      }
    >
      {error && (
        <div className="mb-5">
          <Alert variant="error" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Identity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-4 w-4 text-accent-400" />
              Identity
            </CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-3 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Vendor</dt>
                <dd>{device.vendor ? <TechBadge>{device.vendor}</TechBadge> : '—'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Platform</dt>
                <dd>{device.platform ? <TechBadge>{device.platform}</TechBadge> : '—'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Firmware</dt>
                <dd className="font-mono text-xs text-slate-300">{device.firmware_version ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">IP address</dt>
                <dd className="font-mono text-xs text-slate-300">{device.ip_address ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Registered</dt>
                <dd className="text-xs text-slate-400">{formatDate(device.created_at)}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        {/* Activity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-accent-400" />
              Configuration Activity
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-mono text-3xl font-semibold text-slate-100">{device.configuration_count}</p>
            <p className="mt-1 text-xs text-slate-500">configurations on record</p>
            <div className="mt-4 rounded-md border border-base-700 bg-base-900 px-3 py-2.5">
              <p className="text-xs text-slate-500">
                Configurations are uploaded as part of audit runs and are not exposed as a separate
                list by the API. Upload a configuration and run an audit to associate it with this
                device.
              </p>
            </div>
            <Link href={`/audit/new?device=${device.id}`} className="mt-4 block">
              <Button className="w-full" variant="secondary">
                <PlayCircle className="h-4 w-4" />
                Audit this device
              </Button>
            </Link>
          </CardContent>
        </Card>

        {/* Notes */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Network className="h-4 w-4 text-accent-400" />
              Notes
            </CardTitle>
          </CardHeader>
          <CardContent>
            {device.notes ? (
              <p className="text-sm text-slate-400">{device.notes}</p>
            ) : (
              <p className="text-xs text-slate-600">No notes recorded.</p>
            )}
            <div className="mt-4 border-t border-base-700 pt-3 text-xs text-slate-500">
              Last updated: {formatDateTime(device.updated_at)}
            </div>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
