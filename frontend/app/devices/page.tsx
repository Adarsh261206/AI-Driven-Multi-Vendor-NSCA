'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Archive,
  ArchiveRestore,
  Eye,
  FileText,
  Network,
  Pencil,
  PlayCircle,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  UploadCloud,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { DataTable } from '@/components/ui/DataTable';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Modal } from '@/components/ui/Modal';
import { PageLoader } from '@/components/ui/Progress';
import { devicesAPI, getApiError, getApiStatus, request } from '@/lib/api';
import { formatDate, formatPercent } from '@/lib/format';
import type { Device, PaginationMeta } from '@/types';

const VENDORS = ['cisco', 'juniper', 'fortinet', 'paloalto'];
const SEARCH_DEBOUNCE_MS = 350;

type LifecycleFilter = 'active' | 'archived' | 'all';

/** Operational state derived from real inventory fields — text-first,
 * never color-only. Lifecycle (archived) is separate and shown as its
 * own badge next to the device name. */
function deviceStatus(d: Device): { label: string; cls: string } {
  if ((d.configuration_count ?? 0) === 0 && !d.latest_configuration_at) {
    return { label: 'Configuration Required', cls: 'badge-medium' };
  }
  const s = (d.last_audit_status ?? '').toLowerCase();
  if (s === 'processing' || s === 'pending') {
    return { label: 'Running…', cls: 'badge-info' };
  }
  if (s === 'failed') {
    return { label: 'Audit Failed', cls: 'badge-critical' };
  }
  if (s === 'completed') {
    return { label: 'Audited', cls: 'badge-pass' };
  }
  return { label: 'Ready to Audit', cls: 'badge-info' };
}

export default function DevicesPage() {
  const { isLoading: authLoading } = useRequireAuth();

  const [devices, setDevices] = useState<Device[]>([]);
  const [meta, setMeta] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [vendorFilter, setVendorFilter] = useState('');
  const [platformFilter, setPlatformFilter] = useState('');
  const [lifecycleFilter, setLifecycleFilter] = useState<LifecycleFilter>('active');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [editingDevice, setEditingDevice] = useState<Device | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const [savingEdit, setSavingEdit] = useState(false);

  const [archivingDevice, setArchivingDevice] = useState<Device | null>(null);
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const [archiving, setArchiving] = useState(false);

  const [deletingDevice, setDeletingDevice] = useState<Device | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleteConflict, setDeleteConflict] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const [actingId, setActingId] = useState<string | null>(null);

  // Debounced server-side search: typing resets to page 1.
  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(searchInput.trim());
      setPage(1);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [searchInput]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { page, per_page: 20 };
      if (vendorFilter) params.vendor = vendorFilter;
      if (platformFilter) params.platform = platformFilter;
      if (search) params.search = search;
      if (lifecycleFilter !== 'active') params.lifecycle = lifecycleFilter;
      const res = await devicesAPI.list(params);
      setDevices(res.data.items);
      setMeta(res.data.meta);
    } catch (err) {
      setError(getApiError(err, 'Failed to load devices'));
    } finally {
      setLoading(false);
    }
  }, [page, vendorFilter, platformFilter, search, lifecycleFilter]);

  useEffect(() => {
    if (!authLoading) load();
  }, [authLoading, load]);

  const hasActiveFilters =
    vendorFilter !== '' || platformFilter !== '' || search !== '' || lifecycleFilter !== 'active';

  const clearFilters = () => {
    setVendorFilter('');
    setPlatformFilter('');
    setLifecycleFilter('active');
    setSearchInput('');
    setSearch('');
    setPage(1);
  };

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
      setNotice(`Device "${data.name}" registered.`);
      await load();
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create device');
    } finally {
      setCreating(false);
    }
  };

  const saveEdit = async (data: {
    name: string;
    vendor?: string;
    platform?: string;
    firmware_version?: string;
    ip_address?: string;
    notes?: string;
  }) => {
    if (!editingDevice) return;
    setSavingEdit(true);
    setEditError(null);
    try {
      await request(() => devicesAPI.update(editingDevice.id, data), 'Failed to update device');
      setEditingDevice(null);
      setNotice(`Device "${data.name}" updated. History untouched.`);
      await load();
    } catch (err) {
      setEditError(err instanceof Error ? err.message : 'Failed to update device');
    } finally {
      setSavingEdit(false);
    }
  };

  const confirmArchive = async () => {
    if (!archivingDevice) return;
    setArchiving(true);
    setArchiveError(null);
    try {
      const archName = archivingDevice.name;
      await request(() => devicesAPI.archive(archivingDevice.id), 'Failed to archive device');
      setArchivingDevice(null);
      setNotice(`Device "${archName}" archived. History preserved.`);
      await load();
    } catch (err) {
      setArchiveError(err instanceof Error ? err.message : 'Failed to archive device');
    } finally {
      setArchiving(false);
    }
  };

  const unarchiveDevice = async (device: Device) => {
    setActingId(device.id);
    setError(null);
    try {
      await request(() => devicesAPI.unarchive(device.id), 'Failed to unarchive device');
      setNotice(`Device "${device.name}" restored to active inventory.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unarchive device');
    } finally {
      setActingId(null);
    }
  };

  const confirmDelete = async () => {
    if (!deletingDevice) return;
    setDeleting(true);
    setDeleteError(null);
    setDeleteConflict(false);
    try {
      const delName = deletingDevice.name;
      await request(() => devicesAPI.delete(deletingDevice.id), 'Failed to delete device');
      setDeletingDevice(null);
      setNotice(`Device "${delName}" permanently deleted.`);
      await load();
    } catch (err) {
      // 409 = history-bearing device (backend policy with counts);
      // anything else is a generic failure without the archive escape hatch.
      setDeleteConflict(getApiStatus(err) === 409);
      setDeleteError(err instanceof Error ? err.message : 'Failed to delete device');
    } finally {
      setDeleting(false);
    }
  };

  if (authLoading) return <PageLoader label="Loading" />;

  return (
    <AppShell
      title="Devices"
      subtitle="Network device inventory — configurations, audits and compliance at a glance"
      actions={
        <>
          <Link href="/devices/bulk-upload">
            <button className="btn-secondary">
              <UploadCloud className="h-4 w-4" />
              Bulk Upload
            </button>
          </Link>
          <Link href="/audit/bulk">
            <button className="btn-secondary">
              <PlayCircle className="h-4 w-4" />
              Bulk Audit
            </button>
          </Link>
          <button className="btn-primary" onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4" />
            Add Device
          </button>
        </>
      }
    >
      {error && (
        <div className="mb-6">
          <Alert variant="error" title="Unable to load devices" onDismiss={() => setError(null)}>
            {error}
            <div className="mt-3">
              <button className="btn-secondary text-xs px-3.5 py-2" onClick={load}>
                Retry
              </button>
            </div>
          </Alert>
        </div>
      )}
      {notice && (
        <div className="mb-6">
          <Alert variant="success" onDismiss={() => setNotice(null)}>
            {notice}
          </Alert>
        </div>
      )}

      {/* Filters — Odoo: white card, generous padding, airy */}
      <div className="card mb-6">
        <div className="flex flex-wrap items-center gap-4 p-5">
          <div className="relative min-w-[280px] flex-1">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-400" />
            <input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search name, IP, vendor, platform…"
              className="input pl-10"
              aria-label="Search devices"
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
          <select
            value={lifecycleFilter}
            onChange={(e) => {
              setLifecycleFilter(e.target.value as LifecycleFilter);
              setPage(1);
            }}
            className="select w-44"
            aria-label="Filter by lifecycle"
          >
            <option value="active">Active</option>
            <option value="archived">Archived</option>
            <option value="all">All</option>
          </select>
          {hasActiveFilters && (
            <button className="btn-ghost text-xs px-3.5 py-2" onClick={clearFilters}>
              Clear filters
            </button>
          )}
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
            rows={devices}
            rowKey={(d) => d.id}
            onRowClick={(d) => (window.location.href = `/devices/${d.id}`)}
            page={page}
            totalPages={meta?.total_pages}
            total={meta?.total}
            onPageChange={setPage}
            emptyTitle={
              lifecycleFilter === 'archived' && !hasActiveFilters
                ? 'No archived devices'
                : hasActiveFilters
                  ? 'No matching devices'
                  : 'No devices registered'
            }
            emptyDescription={
              lifecycleFilter === 'archived' && !hasActiveFilters
                ? 'Archived devices are preserved here with their full history.'
                : hasActiveFilters
                  ? 'Try another name, IP, vendor, platform, or search term.'
                  : 'Register your network devices to build your infrastructure inventory.'
            }
            emptyAction={
              hasActiveFilters ? (
                <button className="btn-secondary text-xs px-3.5 py-2" onClick={clearFilters}>
                  Clear Filters
                </button>
              ) : (
                <button className="btn-primary text-xs px-3.5 py-2" onClick={() => setCreateOpen(true)}>
                  <Plus className="h-4 w-4" />
                  Add Device
                </button>
              )
            }
            columns={[
              {
                key: 'name',
                header: 'Device',
                render: (d) => (
                  <div className="flex items-center gap-3.5">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-surface-50 text-ink-400 ring-1 ring-surface-200">
                      <Network className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="flex items-center gap-2 truncate text-sm font-semibold text-ink-100">
                        <span className="truncate">{d.name}</span>
                        {!d.is_active && <span className="badge-medium shrink-0">Archived</span>}
                      </p>
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
                className: 'hidden md:table-cell',
                render: (d) =>
                  d.platform ? <span className="badge-info">{d.platform}</span> : <span className="text-ink-400">—</span>,
                sortValue: (d) => d.platform ?? '',
              },
              {
                key: 'firmware_version',
                header: 'Version',
                className: 'hidden xl:table-cell',
                render: (d) => (
                  <span className="font-mono text-xs text-ink-400">{d.firmware_version ?? '—'}</span>
                ),
                sortValue: (d) => d.firmware_version ?? '',
              },
              {
                key: 'configuration',
                header: 'Configuration',
                render: (d) =>
                  d.latest_configuration_filename ? (
                    <div className="min-w-0">
                      <p className="truncate font-mono text-xs font-medium text-ink-300" title={d.latest_configuration_filename}>
                        {d.latest_configuration_filename}
                      </p>
                      <p className="text-xs text-ink-400">
                        {d.latest_configuration_at ? formatDate(d.latest_configuration_at) : ''}
                      </p>
                    </div>
                  ) : (
                    <span className="text-xs text-ink-400">Not configured</span>
                  ),
                sortValue: (d) => d.latest_configuration_at ?? '',
              },
              {
                key: 'last_audit',
                header: 'Last Audit',
                render: (d) => {
                  const running = (d.last_audit_status ?? '').toLowerCase();
                  if (d.last_audit_date && d.last_audit_id) {
                    return (
                      <Link
                        href={`/audit/${d.last_audit_id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-xs font-medium text-brand-600 hover:underline"
                      >
                        {formatDate(d.last_audit_date)}
                      </Link>
                    );
                  }
                  if (running === 'processing' || running === 'pending') {
                    return <span className="text-xs font-medium text-brand-600">Running…</span>;
                  }
                  return <span className="text-xs text-ink-400">Never</span>;
                },
                sortValue: (d) => d.last_audit_date ?? '',
              },
              {
                key: 'compliance',
                header: 'Compliance',
                align: 'right',
                render: (d) =>
                  d.last_compliance_score != null ? (
                    <span className="font-mono text-sm font-semibold text-ink-100">
                      {formatPercent(d.last_compliance_score)}
                    </span>
                  ) : (
                    <span className="text-xs text-ink-400">Not audited</span>
                  ),
                sortValue: (d) => d.last_compliance_score ?? -1,
              },
              {
                key: 'status',
                header: 'Status',
                render: (d) => {
                  const s = deviceStatus(d);
                  return <span className={s.cls}>{s.label}</span>;
                },
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
                      title={`View ${d.name}`}
                    >
                      <Eye className="h-4 w-4" />
                    </Link>
                    <Link
                      href={`/devices/${d.id}#configuration-history`}
                      className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-surface-100 hover:text-ink-300"
                      aria-label={`Configuration history of ${d.name}`}
                      title="Configuration history"
                    >
                      <FileText className="h-4 w-4" />
                    </Link>
                    {d.is_active ? (
                      <>
                        <Link
                          href={`/audit/new?device=${d.id}`}
                          className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-brand-50 hover:text-brand-600"
                          aria-label={`Audit ${d.name}`}
                          title={`Audit ${d.name}`}
                        >
                          <PlayCircle className="h-4 w-4" />
                        </Link>
                        <button
                          onClick={() => {
                            setEditError(null);
                            setEditingDevice(d);
                          }}
                          className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-surface-100 hover:text-ink-300"
                          aria-label={`Edit ${d.name}`}
                          title={`Edit ${d.name}`}
                        >
                          <Pencil className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => {
                            setArchiveError(null);
                            setArchivingDevice(d);
                          }}
                          className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-amber-50 hover:text-amber-600"
                          aria-label={`Archive ${d.name}`}
                          title={`Archive ${d.name}`}
                        >
                          <Archive className="h-4 w-4" />
                        </button>
                      </>
                    ) : (
                      <button
                        onClick={() => unarchiveDevice(d)}
                        disabled={actingId === d.id}
                        className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-emerald-50 hover:text-emerald-600 disabled:opacity-50"
                        aria-label={`Unarchive ${d.name}`}
                        title={`Unarchive ${d.name}`}
                      >
                        <ArchiveRestore className="h-4 w-4" />
                      </button>
                    )}
                    <button
                      onClick={() => {
                        setDeleteError(null);
                        setDeletingDevice(d);
                      }}
                      className="rounded-lg p-2 text-ink-400 transition-colors duration-150 hover:bg-red-50 hover:text-red-600"
                      aria-label={`Delete ${d.name}`}
                      title={`Delete ${d.name}`}
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

      {/* Edit modal — reuses the registration form, pre-populated */}
      <DeviceFormModal
        key={editingDevice ? `edit-${editingDevice.id}` : 'edit-closed'}
        open={editingDevice !== null}
        onClose={() => setEditingDevice(null)}
        onSubmit={saveEdit}
        error={editError}
        saving={savingEdit}
        title="Edit Device"
        description={editingDevice ? `Update identity metadata for ${editingDevice.name}` : undefined}
        submitLabel={savingEdit ? 'Saving…' : 'Save Changes'}
        initial={
          editingDevice
            ? {
                name: editingDevice.name,
                vendor: editingDevice.vendor ?? 'cisco',
                platform: editingDevice.platform ?? 'ios_xe',
                firmware_version: editingDevice.firmware_version ?? '',
                ip_address: editingDevice.ip_address ?? '',
                notes: editingDevice.notes ?? '',
              }
            : undefined
        }
      />

      {/* Archive confirmation */}
      <Modal
        open={archivingDevice !== null}
        onClose={() => {
          if (!archiving) setArchivingDevice(null);
        }}
        title="Archive this device?"
        size="md"
        footer={
          <>
            <Button variant="ghost" onClick={() => setArchivingDevice(null)} disabled={archiving}>
              Cancel
            </Button>
            <Button onClick={confirmArchive} loading={archiving}>
              <Archive className="h-4 w-4" />
              Archive Device
            </Button>
          </>
        }
      >
        <div className="space-y-4 text-sm leading-relaxed text-ink-300">
          {archiveError && (
            <Alert variant="error" title="Archive failed" onDismiss={() => setArchiveError(null)}>
              {archiveError}
            </Alert>
          )}
          <p>
            <span className="font-semibold text-ink-100">{archivingDevice?.name}</span> will be
            removed from the active inventory and will no longer accept new configurations or
            audits.
          </p>
          <p className="text-ink-400">
            Existing configuration history, audits, findings, and reports are preserved and remain
            accessible. You can unarchive the device at any time.
          </p>
        </div>
      </Modal>

      {/* Delete confirmation — describes the REAL backend policy */}
      <Modal
        open={deletingDevice !== null}
        onClose={() => {
          if (!deleting) setDeletingDevice(null);
        }}
        title="Delete this device?"
        size="md"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeletingDevice(null)} disabled={deleting}>
              Cancel
            </Button>
            <Button variant="danger" onClick={confirmDelete} loading={deleting}>
              <Trash2 className="h-4 w-4" />
              Delete Permanently
            </Button>
          </>
        }
      >
        <div className="space-y-4 text-sm leading-relaxed text-ink-300">
          {deleteError ? (
            <Alert variant="error" title="Cannot delete device">
              {deleteError}
              {deleteConflict && (
              <div className="mt-3">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    if (deletingDevice) {
                      setDeletingDevice(null);
                      setArchiveError(null);
                      setArchivingDevice(deletingDevice);
                    }
                  }}
                >
                  <Archive className="h-4 w-4" />
                  Archive Instead
                </Button>
              </div>
              )}
            </Alert>
          ) : (
            <p>
              <span className="font-semibold text-ink-100">{deletingDevice?.name}</span> will be
              permanently removed. Devices with configuration or audit history cannot be deleted —
              archive them instead to preserve historical records.
            </p>
          )}
        </div>
      </Modal>
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
  return (
    <DeviceFormModal
      open={open}
      onClose={onClose}
      onSubmit={onSubmit}
      error={error}
      saving={creating}
      title="Register Device"
      description="Add a network device to the inventory"
      submitLabel={creating ? 'Creating…' : 'Create Device'}
    />
  );
}

function DeviceFormModal({
  open,
  onClose,
  onSubmit,
  error,
  saving,
  title,
  description,
  submitLabel,
  initial,
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
  saving: boolean;
  title: string;
  description?: string;
  submitLabel: string;
  initial?: {
    name: string;
    vendor: string;
    platform: string;
    firmware_version: string;
    ip_address: string;
    notes: string;
  };
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [vendor, setVendor] = useState(initial?.vendor ?? 'cisco');
  const [platform, setPlatform] = useState(initial?.platform ?? 'ios_xe');
  const [firmwareVersion, setFirmwareVersion] = useState(initial?.firmware_version ?? '');
  const [ipAddress, setIpAddress] = useState(initial?.ip_address ?? '');
  const [notes, setNotes] = useState(initial?.notes ?? '');

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
      title={title}
      description={description}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="device-form" className="btn-primary" disabled={saving}>
            {submitLabel}
          </button>
        </>
      }
    >
      <form id="device-form" onSubmit={submit} className="space-y-5">
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
        {initial && (
          <p className="text-xs leading-relaxed text-ink-400">
            Editing identity metadata never rewrites configuration history, audits, findings, or reports.
          </p>
        )}
      </form>
    </Modal>
  );
}
