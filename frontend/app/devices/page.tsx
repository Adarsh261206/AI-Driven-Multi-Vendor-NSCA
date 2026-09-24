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
      subtitle="Network device inventory — register, filter and manage your infrastructure"
      actions={
        <button className="btn-primary" onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4" />
          Add Device
        </button>
      }
    >
      {error && (
        <div className="mb-6">
          <Alert variant="error" title="Devices" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      {/* Filters — Odoo: white card, generous padding, airy */}
      <div className="card mb-6">
        <div className="flex flex-wrap items-center gap-4 p-5">
          <div className="relative min-w-[280px] flex-1">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by name (client-side)…"
              className="input pl-10"
              aria-label="Filter devices"
            />
          </div>
          <select
            value={vendorFilter}
            onChange={(e) => {
              setVendorFilter(e.target.value);
              setPage(1);
            }}
            className="select w-44"
            aria-label="Filter by vendor"
          >
            <option value="">All vendors</option>
            {VENDORS.map((v) => (
              <option key={v} value={v}>
                {v.charAt(0).toUpperCase() + v.slice(1)}
              </option>
            ))}
          </select>
          <select
            value={platformFilter}
            onChange={(e) => {
              setPlatformFilter(e.target.value);
              setPage(1);
            }}
            className="select w-44"
            aria-label="Filter by platform"
          >
            <option value="">All platforms</option>
            <option value="ios_xe">IOS XE</option>
            <option value="junos">JUNOS</option>
            <option value="fortios">FortiOS</option>
          </select>
          <button className="btn-secondary" onClick={load} aria-label="Refresh devices">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="card-body p-0">
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
                  <div className="flex items-center gap-3.5">
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-surface-50 text-ink-400 ring-1 ring-surface-200">
                      <Network className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-ink-100">{d.name}</p>
                      {d.ip_address && <p className="font-mono text-xs text-ink-400">{d.ip_address}</p>}
                    </div>
                  </div>
                ),
                sortValue: (d) => d.name,
              },
              {
                key: 'vendor',
                header: 'Vendor',
                render: (d) =>
                  d.vendor ? <span className="badge-info">{d.vendor}</span> : <span className="text-ink-400">—</span>,
                sortValue: (d) => d.vendor ?? '',
              },
              {
                key: 'platform',
                header: 'Platform',
                render: (d) =>
                  d.platform ? <span className="badge-info">{d.platform}</span> : <span className="text-ink-400">—</span>,
                sortValue: (d) => d.platform ?? '',
              },
              {
                key: 'firmware_version',
                header: 'Version',
                render: (d) => (
                  <span className="font-mono text-xs text-ink-400">{d.firmware_version ?? '—'}</span>
                ),
                sortValue: (d) => d.firmware_version ?? '',
              },
              {
                key: 'configuration_count',
                header: 'Configs',
                align: 'right',
                render: (d) => <span className="font-mono text-sm font-medium">{d.configuration_count}</span>,
                sortValue: (d) => d.configuration_count,
              },
              {
                key: 'last_audit_date',
                header: 'Last Audit',
                render: (d) => <span className="text-xs text-ink-400">{formatDate(d.last_audit_date)}</span>,
                sortValue: (d) => d.last_audit_date ?? '',
              },
              {
                key: 'created_at',
                header: 'Added',
                render: (d) => <span className="text-xs text-ink-400">{formatDate(d.created_at)}</span>,
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
                      className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-surface-100 hover:text-ink-300"
                      aria-label={`View ${d.name}`}
                    >
                      <Network className="h-4 w-4" />
                    </Link>
                    <button
                      onClick={() => deleteDevice(d)}
                      className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-red-50 hover:text-red-600"
                      aria-label={`Delete ${d.name}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                ),
              },
            ]}
          />
        </div>
      </div>

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
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="create-device-form" className="btn-primary" disabled={creating}>
            {creating ? 'Creating…' : 'Create Device'}
          </button>
        </>
      }
    >
      <form id="create-device-form" onSubmit={submit} className="space-y-5">
        {error && <Alert variant="error">{error}</Alert>}
        <div>
          <label className="label">Device name <span className="text-red-500">*</span></label>
          <input
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="edge-router-01"
            autoFocus
            className="input"
          />
        </div>
        <div className="grid grid-cols-2 gap-5">
          <div>
            <label className="label">Vendor</label>
            <select value={vendor} onChange={(e) => setVendor(e.target.value)} className="select">
              {VENDORS.map((v) => (
                <option key={v} value={v}>
                  {v.charAt(0).toUpperCase() + v.slice(1)}
                </option>
              ))}
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
        <div className="grid grid-cols-2 gap-5">
          <div>
            <label className="label">Firmware version</label>
            <input
              value={firmwareVersion}
              onChange={(e) => setFirmwareVersion(e.target.value)}
              placeholder="17.9.4"
              className="input"
            />
          </div>
          <div>
            <label className="label">IP address</label>
            <input
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              placeholder="10.0.0.1"
              className="input"
            />
          </div>
        </div>
        <div>
          <label className="label">Notes</label>
          <input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Optional notes" className="input" />
        </div>
      </form>
    </Modal>
  );
}
