'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Network, Plus, Search, Trash2, RefreshCw } from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { DataTable } from '@/components/ui/DataTable';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Modal } from '@/components/ui/Modal';
import { Field, Input, Select } from '@/components/ui/Field';
import { TechBadge } from '@/components/ui/Badge';
import { PageLoader } from '@/components/ui/Progress';
import { devicesAPI, getApiError, request } from '@/lib/api';
import { formatDate, formatPercent } from '@/lib/format';
import type { Device, PaginationMeta } from '@/types';

const VENDORS = ['cisco', 'juniper', 'fortinet', 'paloalto'];

export default function DevicesPage() {
  const { isLoading: authLoading } = useRequireAuth();

  const [devices, setDevices] = useState<Device[]>([]);
  const [meta, setMeta] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [vendorFilter, setVendorFilter] = useState('');
  const [platformFilter, setPlatformFilter] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { page, per_page: 20 };
      if (vendorFilter) params.vendor = vendorFilter;
      if (platformFilter) params.platform = platformFilter;
      const res = await devicesAPI.list(params);
      setDevices(res.data.items);
      setMeta(res.data.meta);
    } catch (err) {
      setError(getApiError(err, 'Failed to load devices'));
    } finally {
      setLoading(false);
    }
  }, [page, vendorFilter, platformFilter]);

  useEffect(() => {
    if (!authLoading) load();
  }, [authLoading, load]);

  const createDevice = async (data: {
    name: string;
    vendor?: string;
    platform?: string;
    firmware_version?: string;
    ip_address?: string;
    notes?: string;
  }) => {
    setCreating(true);
    setCreateError(null);
    try {
      await request(() => devicesAPI.create(data), 'Failed to create device');
      setCreateOpen(false);
      setPage(1);
      await load();
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create device');
    } finally {
      setCreating(false);
    }
  };

  const deleteDevice = async (device: Device) => {
    if (!window.confirm(`Delete device "${device.name}"? This cannot be undone.`)) return;
    try {
      await request(() => devicesAPI.delete(device.id), 'Failed to delete device');
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete device');
    }
  };

  if (authLoading) return <PageLoader label="Loading" />;

  return (
    <AppShell
      title="Devices"
      subtitle="Network device inventory"
      actions={
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4" />
          Add Device
        </Button>
      }
    >
      {error && (
        <div className="mb-5">
          <Alert variant="error" title="Devices" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      {/* Filters */}
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <div className="relative min-w-[240px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by name (client-side)..."
            className="pl-8"
            aria-label="Filter devices"
          />
        </div>
        <Select
          value={vendorFilter}
          onChange={(e) => {
            setVendorFilter(e.target.value);
            setPage(1);
          }}
          className="w-40"
          aria-label="Filter by vendor"
        >
          <option value="">All vendors</option>
          {VENDORS.map((v) => (
            <option key={v} value={v}>
              {v.charAt(0).toUpperCase() + v.slice(1)}
            </option>
          ))}
        </Select>
        <Select
          value={platformFilter}
          onChange={(e) => {
            setPlatformFilter(e.target.value);
            setPage(1);
          }}
          className="w-40"
          aria-label="Filter by platform"
        >
          <option value="">All platforms</option>
          <option value="ios_xe">IOS XE</option>
          <option value="junos">JUNOS</option>
          <option value="fortios">FortiOS</option>
        </Select>
        <Button variant="secondary" onClick={load} aria-label="Refresh devices">
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
      </div>

      <div className="panel">
        <DataTable<Device>
          loading={loading}
          rows={search ? devices.filter((d) => d.name.toLowerCase().includes(search.toLowerCase())) : devices}
          rowKey={(d) => d.id}
          onRowClick={(d) => (window.location.href = `/devices/${d.id}`)}
          page={page}
          totalPages={meta?.total_pages}
          total={meta?.total}
          onPageChange={setPage}
          emptyTitle="No devices found"
          emptyDescription="Register a device or run an audit against an uploaded configuration."
          columns={[
            {
              key: 'name',
              header: 'Device',
              render: (d) => (
                <div className="flex items-center gap-2.5">
                  <div className="flex h-7 w-7 items-center justify-center rounded-md border border-base-700 bg-base-900 text-slate-400">
                    <Network className="h-3.5 w-3.5" />
                  </div>
                  <div className="min-w-0">
                    <p className="truncate font-medium text-slate-200">{d.name}</p>
                    {d.ip_address && <p className="font-mono text-[11px] text-slate-500">{d.ip_address}</p>}
                  </div>
                </div>
              ),
              sortValue: (d) => d.name,
            },
            {
              key: 'vendor',
              header: 'Vendor',
              render: (d) =>
                d.vendor ? <TechBadge>{d.vendor}</TechBadge> : <span className="text-slate-600">—</span>,
              sortValue: (d) => d.vendor ?? '',
            },
            {
              key: 'platform',
              header: 'Platform',
              render: (d) =>
                d.platform ? <TechBadge>{d.platform}</TechBadge> : <span className="text-slate-600">—</span>,
              sortValue: (d) => d.platform ?? '',
            },
            {
              key: 'firmware_version',
              header: 'Version',
              render: (d) => (
                <span className="font-mono text-xs text-slate-400">{d.firmware_version ?? '—'}</span>
              ),
              sortValue: (d) => d.firmware_version ?? '',
            },
            {
              key: 'configuration_count',
              header: 'Configs',
              align: 'right',
              render: (d) => <span className="font-mono">{d.configuration_count}</span>,
              sortValue: (d) => d.configuration_count,
            },
            {
              key: 'last_audit_date',
              header: 'Last Audit',
              render: (d) => <span className="text-xs text-slate-500">{formatDate(d.last_audit_date)}</span>,
              sortValue: (d) => d.last_audit_date ?? '',
            },
            {
              key: 'created_at',
              header: 'Added',
              render: (d) => <span className="text-xs text-slate-500">{formatDate(d.created_at)}</span>,
              sortValue: (d) => d.created_at,
            },
            {
              key: 'actions',
              header: '',
              align: 'right',
              render: (d) => (
                <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                  <Link
                    href={`/devices/${d.id}`}
                    className="rounded p-1.5 text-slate-500 hover:bg-base-800 hover:text-slate-300"
                    aria-label={`View ${d.name}`}
                  >
                    <Network className="h-3.5 w-3.5" />
                  </Link>
                  <button
                    onClick={() => deleteDevice(d)}
                    className="rounded p-1.5 text-slate-500 hover:bg-red-500/10 hover:text-red-400"
                    aria-label={`Delete ${d.name}`}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ),
            },
          ]}
        />
      </div>

      {/* Create device modal */}
      <CreateDeviceModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onSubmit={createDevice}
        error={createError}
        creating={creating}
      />
    </AppShell>
  );
}

function CreateDeviceModal({
  open,
  onClose,
  onSubmit,
  error,
  creating,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: {
    name: string;
    vendor?: string;
    platform?: string;
    firmware_version?: string;
    ip_address?: string;
    notes?: string;
  }) => void;
  error: string | null;
  creating: boolean;
}) {
  const [name, setName] = useState('');
  const [vendor, setVendor] = useState('cisco');
  const [platform, setPlatform] = useState('ios_xe');
  const [firmwareVersion, setFirmwareVersion] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [notes, setNotes] = useState('');

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      name,
      vendor,
      platform,
      firmware_version: firmwareVersion || undefined,
      ip_address: ipAddress || undefined,
      notes: notes || undefined,
    });
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Register Device"
      description="Add a network device to the inventory"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="create-device-form" loading={creating}>
            Create Device
          </Button>
        </>
      }
    >
      <form id="create-device-form" onSubmit={submit} className="space-y-4">
        {error && <Alert variant="error">{error}</Alert>}
        <Field label="Device name" hint="Required">
          <Input
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="edge-router-01"
            autoFocus
          />
        </Field>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Vendor">
            <Select value={vendor} onChange={(e) => setVendor(e.target.value)}>
              {VENDORS.map((v) => (
                <option key={v} value={v}>
                  {v.charAt(0).toUpperCase() + v.slice(1)}
                </option>
              ))}
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
        <div className="grid grid-cols-2 gap-4">
          <Field label="Firmware version">
            <Input
              value={firmwareVersion}
              onChange={(e) => setFirmwareVersion(e.target.value)}
              placeholder="17.9.4"
            />
          </Field>
          <Field label="IP address">
            <Input
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              placeholder="10.0.0.1"
            />
          </Field>
        </div>
        <Field label="Notes">
          <Input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Optional notes" />
        </Field>
      </form>
    </Modal>
  );
}
