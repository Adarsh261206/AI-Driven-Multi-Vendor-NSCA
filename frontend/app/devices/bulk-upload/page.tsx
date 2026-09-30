'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ArrowLeft,
  CheckCircle2,
  Copy,
  FileText,
  UploadCloud,
  X,
  XCircle,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { PageLoader } from '@/components/ui/Progress';
import { bulkAPI, devicesAPI, getApiError, request } from '@/lib/api';
import { cn } from '@/lib/utils';
import { formatBytes } from '@/lib/format';
import type { BulkUploadResponse, Device } from '@/types';

const ACCEPTED = '.txt,.cfg,.conf';
const MAX_FILES = 20;

interface PendingFile {
  key: string;
  file: File;
  deviceId: string;
}

function statusBadge(status: string) {
  if (status === 'stored') {
    return (
      <span className="badge-pass inline-flex items-center gap-1.5">
        <CheckCircle2 className="h-3.5 w-3.5" />
        Stored
      </span>
    );
  }
  if (status === 'duplicate') {
    return (
      <span className="badge-info inline-flex items-center gap-1.5">
        <Copy className="h-3.5 w-3.5" />
        Duplicate
      </span>
    );
  }
  return (
    <span className="badge-critical inline-flex items-center gap-1.5">
      <XCircle className="h-3.5 w-3.5" />
      Invalid
    </span>
  );
}

export default function BulkUploadPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const router = useRouter();

  const [pending, setPending] = useState<PendingFile[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesError, setDevicesError] = useState<string | null>(null);
  const [applyAll, setApplyAll] = useState('');
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [result, setResult] = useState<BulkUploadResponse | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const keySeq = useRef(0);

  const loadDevices = useCallback(async () => {
    try {
      const res = await request(
        () => devicesAPI.list({ per_page: 100 }),
        'Unable to load devices for mapping.'
      );
      // Only active devices accept new configurations (server enforces too).
      setDevices((res.items || []).filter((d) => d.is_active !== false));
      setDevicesError(null);
    } catch (err) {
      setDevicesError(err instanceof Error ? err.message : 'Unable to load devices.');
    }
  }, []);

  useEffect(() => {
    if (!authLoading) loadDevices();
  }, [authLoading, loadDevices]);

  const addFiles = (files: File[]) => {
    const next: PendingFile[] = [];
    for (const file of files) {
      if (next.length + pending.length >= MAX_FILES) {
        setUploadError(`At most ${MAX_FILES} files per bulk upload.`);
        break;
      }
      keySeq.current += 1;
      next.push({ key: `${Date.now()}-${keySeq.current}`, file, deviceId: '' });
    }
    if (next.length > 0) {
      setPending((prev) => [...prev, ...next]);
      setResult(null);
    }
  };

  const setDeviceFor = (key: string, deviceId: string) => {
    setPending((prev) => prev.map((p) => (p.key === key ? { ...p, deviceId } : p)));
  };

  const applyAllDevices = () => {
    if (!applyAll) return;
    setPending((prev) => prev.map((p) => ({ ...p, deviceId: applyAll })));
  };

  const removeFile = (key: string) => {
    setPending((prev) => prev.filter((p) => p.key !== key));
    setResult(null);
  };

  const allMapped = pending.length > 0 && pending.every((p) => p.deviceId !== '');

  const upload = async () => {
    if (!allMapped || uploading) return;
    setUploading(true);
    setUploadError(null);
    setResult(null);
    try {
      const res = await request(
        () =>
          bulkAPI.uploadConfigurations(
            pending.map((p) => p.file),
            pending.map((p) => p.deviceId)
          ),
        'Bulk upload failed'
      );
      setResult(res);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Bulk upload failed');
    } finally {
      setUploading(false);
    }
  };

  const deviceName = (id: string) => devices.find((d) => d.id === id)?.name ?? id;

  if (authLoading) return <PageLoader label="Loading bulk upload" />;

  const summary = result?.summary;

  return (
    <AppShell
      title="Bulk Upload"
      subtitle="Upload many configurations at once — each file is mapped explicitly to one active device"
      actions={
        <Link href="/devices">
          <button className="btn-secondary">
            <ArrowLeft className="h-4 w-4" />
            Devices
          </button>
        </Link>
      }
    >
      {devicesError && (
        <div className="mb-6">
          <Alert variant="error" title="Unable to load devices" onDismiss={() => setDevicesError(null)}>
            {devicesError}
          </Alert>
        </div>
      )}
      {uploadError && (
        <div className="mb-6">
          <Alert variant="error" title="Bulk upload failed" onDismiss={() => setUploadError(null)}>
            {uploadError}
          </Alert>
        </div>
      )}

      <div className="max-w-4xl space-y-6">
        {/* File picker */}
        <div
          role="button"
          tabIndex={0}
          aria-label="Select configuration files for bulk upload"
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
          }}
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            addFiles(Array.from(e.dataTransfer.files));
          }}
          className="card cursor-pointer border-2 border-dashed p-10 text-center transition-all duration-150 hover:border-brand-300 hover:bg-brand-50/30"
        >
          <input
            ref={fileInputRef}
            type="file"
            multiple
            accept={ACCEPTED}
            className="hidden"
            onChange={(e) => {
              addFiles(Array.from(e.target.files ?? []));
              e.target.value = '';
            }}
          />
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-white text-brand-600 shadow-odoo ring-1 ring-brand-100">
            <UploadCloud className="h-6 w-6" />
          </div>
          <p className="text-sm font-semibold text-ink-100">Drop configuration files, or click to browse</p>
          <p className="mt-1 text-xs text-ink-400">
            {ACCEPTED} · max 10 MB each · at most {MAX_FILES} files · never guessed — you map every file
          </p>
        </div>

        {/* Mapping table */}
        {pending.length > 0 && !result && (
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h3 className="section-title">Map files to devices</h3>
                <p className="mt-1 text-sm text-ink-400">
                  {pending.length} file{pending.length === 1 ? '' : 's'} · every file needs an explicit target device
                </p>
              </div>
              <div className="flex items-center gap-2">
                <select
                  value={applyAll}
                  onChange={(e) => setApplyAll(e.target.value)}
                  className="select w-48"
                  aria-label="Set all files to one device"
                >
                  <option value="">Set all to…</option>
                  {devices.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name}
                    </option>
                  ))}
                </select>
                <Button variant="secondary" size="sm" onClick={applyAllDevices} disabled={!applyAll}>
                  Apply
                </Button>
              </div>
            </div>
            <div className="divide-y divide-surface-100">
              {pending.map((p) => (
                <div key={p.key} className="flex items-center gap-4 px-6 py-4">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-surface-200 bg-surface-100 text-ink-400">
                    <FileText className="h-4 w-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-sm font-medium text-ink-100" title={p.file.name}>
                      {p.file.name}
                    </p>
                    <p className="text-xs text-ink-400">{formatBytes(p.file.size)}</p>
                  </div>
                  <select
                    value={p.deviceId}
                    onChange={(e) => setDeviceFor(p.key, e.target.value)}
                    className="select w-56"
                    aria-label={`Target device for ${p.file.name}`}
                  >
                    <option value="">Select device…</option>
                    {devices.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={() => removeFile(p.key)}
                    className="rounded-lg p-2 text-ink-400 transition-colors hover:bg-red-50 hover:text-red-600"
                    aria-label={`Remove ${p.file.name}`}
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
            <div className="flex items-center justify-end gap-3 border-t border-surface-100 px-6 py-4">
              <span className="mr-auto text-xs text-ink-400">
                {allMapped
                  ? 'All files mapped — envelope validation runs server-side before anything is stored.'
                  : 'Map every file to continue.'}
              </span>
              <Button onClick={upload} loading={uploading} disabled={!allMapped}>
                <UploadCloud className="h-4 w-4" />
                Upload {pending.length} file{pending.length === 1 ? '' : 's'}
              </Button>
            </div>
          </div>
        )}

        {/* Per-item results */}
        {result && (
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h3 className="section-title">Upload results</h3>
                <p className="mt-1 text-sm text-ink-400">
                  {summary?.stored ?? 0} stored · {summary?.duplicate ?? 0} duplicate ·{' '}
                  {summary?.invalid ?? 0} invalid · {summary?.total ?? 0} total
                </p>
              </div>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setPending([]);
                  setResult(null);
                  router.push('/devices');
                }}
              >
                Done
              </Button>
            </div>
            <div className="divide-y divide-surface-100">
              {result.items.map((item, i) => (
                <div key={`${item.filename}-${i}`} className="flex items-center gap-4 px-6 py-4">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-surface-200 bg-surface-100 text-ink-400">
                    <FileText className="h-4 w-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-sm font-medium text-ink-100" title={item.filename}>
                      {item.filename}
                    </p>
                    {item.status === 'invalid' && item.error ? (
                      <p className="mt-0.5 text-xs text-red-600">{item.error}</p>
                    ) : (
                      <p className="mt-0.5 text-xs text-ink-400">
                        {item.status === 'duplicate'
                          ? 'Identical content already stored — existing snapshot reused.'
                          : `Snapshot stored${pending[i] ? ` for ${deviceName(pending[i].deviceId)}` : ''}.`}
                      </p>
                    )}
                  </div>
                  {statusBadge(item.status)}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
