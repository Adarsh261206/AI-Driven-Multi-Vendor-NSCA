import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

type BadgeVariant = 'default' | 'severity' | 'result' | 'status' | 'tech' | 'navy' | 'success' | 'warning' | 'danger';

export function Badge({
  children,
  variant = 'default',
  className,
}: {
  children: ReactNode;
  variant?: BadgeVariant;
  className?: string;
}) {
  const variants: Record<BadgeVariant, string> = {
    default: 'badge-info',
    severity: 'badge-critical',
    result: 'badge-pass',
    status: 'badge-info',
    tech: 'badge-info font-mono',
    navy: 'badge-info bg-brand-600 text-white border-brand-700',
    success: 'badge-pass',
    warning: 'badge-medium',
    danger: 'badge-critical',
  };

  return (
    <span className={cn('inline-flex items-center', variants[variant], className)}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    CRITICAL: { label: 'Critical', cls: 'badge-critical' },
    HIGH: { label: 'High', cls: 'badge-high' },
    MEDIUM: { label: 'Medium', cls: 'badge-medium' },
    LOW: { label: 'Low', cls: 'badge-low' },
  };
  const m = map[severity] ?? { label: severity, cls: 'badge-info' };
  return (
    <span className={cn('inline-flex items-center', m.cls, className)}>
      {m.label}
    </span>
  );
}

export function ResultBadge({ result, className }: { result?: string | null; className?: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    PASS: { label: 'Pass', cls: 'badge-pass' },
    FAIL: { label: 'Fail', cls: 'badge-fail' },
    REVIEW: { label: 'Review', cls: 'badge-review' },
    OUT_OF_SCOPE: { label: 'Out of Scope', cls: 'badge-out-of-scope' },
    NOT_APPLICABLE: { label: 'Not Applicable', cls: 'badge-out-of-scope' },
  };
  const key = (result ?? '').toUpperCase();
  const m = map[key] ?? { label: result ?? '—', cls: 'badge-info' };
  return (
    <span className={cn('inline-flex items-center', m.cls, className)}>
      {m.label}
    </span>
  );
}

export function AuditStatusBadge({ status, className }: { status: string; className?: string }) {
  const map: Record<string, { label: string; cls: string; dot: string }> = {
    pending: { label: 'Pending', cls: 'badge-info', dot: 'bg-ink-400' },
    processing: { label: 'Processing', cls: 'badge-info', dot: 'bg-brand-600 animate-pulse-soft' },
    completed: { label: 'Completed', cls: 'badge-pass', dot: 'bg-emerald-500' },
    failed: { label: 'Failed', cls: 'badge-critical', dot: 'bg-red-500' },
    cancelled: { label: 'Cancelled', cls: 'badge-info', dot: 'bg-ink-400' },
  };
  const m = map[status] ?? map.pending;
  return (
    <span className={cn('inline-flex items-center gap-1.5', m.cls, className)}>
      <span className={cn('h-1.5 w-1.5 rounded-full', m.dot)} />
      {m.label}
    </span>
  );
}

export function FindingStatusBadge({ status, className }: { status: string; className?: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    open: { label: 'Open', cls: 'badge-critical' },
    in_progress: { label: 'In Progress', cls: 'badge-info' },
    resolved: { label: 'Resolved', cls: 'badge-pass' },
    accepted: { label: 'Accepted', cls: 'badge-low' },
  };
  const m = map[status] ?? map.open;
  return (
    <span className={cn('inline-flex items-center', m.cls, className)}>
      {m.label}
    </span>
  );
}

export function TechBadge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn('inline-flex items-center font-mono badge-info', className)}>
      {children}
    </span>
  );
}
