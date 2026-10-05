type DateInput = string | number | Date | null | undefined;

function toDate(value: DateInput): Date | null {
  if (value == null || value === '') return null;
  const d = value instanceof Date ? value : new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

const EMPTY = '—';

export function formatDate(value: DateInput): string {
  const d = toDate(value);
  if (!d) return EMPTY;
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

export function formatDateTime(value: DateInput): string {
  const d = toDate(value);
  if (!d) return EMPTY;
  const date = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  return `${date}, ${time}`;
}

/** Formats a 0–100 score as a percentage, e.g. 87.5 → "88%". */
export function formatPercent(value: number | null | undefined): string {
  if (value == null || isNaN(value)) return EMPTY;
  return `${Math.round(value)}%`;
}

/** Formats a 0–1 confidence value as a percentage, e.g. 0.92 → "92%". */
export function formatConfidence(value: number | null | undefined): string {
  if (value == null || isNaN(value)) return EMPTY;
  const pct = value > 1 ? value : value * 100;
  return `${Math.round(pct)}%`;
}

/** "just now" / "5m ago" / "3h ago" / "12d ago" / "04 Mar 2026" */
export function formatRelative(value: DateInput): string {
  const d = toDate(value);
  if (!d) return EMPTY;

  const diffMs = Date.now() - d.getTime();
  if (diffMs < 0) return formatDateTime(d);

  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return 'just now';

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;

  return formatDate(d);
}

/** Elapsed time between two timestamps ("2m 14s"). Falls back to now when end is missing. */
export function formatDuration(start: DateInput, end: DateInput): string {
  const s = toDate(start);
  if (!s) return EMPTY;
  const e = toDate(end) ?? new Date();

  let total = Math.floor((e.getTime() - s.getTime()) / 1000);
  if (!isFinite(total) || total < 0) total = 0;

  const hours = Math.floor(total / 3600);
  total %= 3600;
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;

  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

/** Human-readable byte size, e.g. 1536 → "1.50 KB". */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || isNaN(bytes)) return EMPTY;
  if (bytes < 1024) return `${bytes} B`;

  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let i = -1;
  do {
    value /= 1024;
    i += 1;
  } while (value >= 1024 && i < units.length - 1);

  const digits = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[i]}`;
}
