import { cn } from '@/lib/utils';
import {
  SEVERITY_META,
  RESULT_META,
  AUDIT_STATUS_META,
  FINDING_STATUS_META,
  type Severity,
  type ComplianceResult,
  type AuditStatus,
  type FindingStatus,
} from '@/lib/security';

export interface BadgeProps {
  label?: string;
  color?: string;
  bg?: string;
  dot?: boolean;
  className?: string;
  title?: string;
}

export function Badge({ label, color, bg, dot, className, title }: BadgeProps) {
  if (!label) return null;
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide whitespace-nowrap',
        className
      )}
      style={bg ? { backgroundColor: bg, color } : undefined}
    >
      {dot && <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />}
      {label}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: string | null | undefined; className?: string }) {
  const meta = severity && severity in SEVERITY_META ? SEVERITY_META[severity as Severity] : undefined;
  return (
    <Badge
      label={meta?.label ?? 'Unknown'}
      color={meta?.color ?? '#94a3b8'}
      bg={meta?.bg ?? 'rgba(148,163,184,0.12)'}
      dot
      className={className}
    />
  );
}

export function ResultBadge({ result, className }: { result: string | null | undefined; className?: string }) {
  const normalized = result?.toUpperCase() as ComplianceResult | undefined;
  const meta = normalized && normalized in RESULT_META ? RESULT_META[normalized] : undefined;
  return (
    <Badge
      label={meta?.label ?? 'Unknown'}
      color={meta?.color ?? '#94a3b8'}
      bg={meta?.bg ?? 'rgba(148,163,184,0.12)'}
      dot
      className={className}
      title={meta?.description}
    />
  );
}

export function AuditStatusBadge({ status, className }: { status: string | null | undefined; className?: string }) {
  const meta = status && status in AUDIT_STATUS_META ? AUDIT_STATUS_META[status as AuditStatus] : undefined;
  return (
    <Badge
      label={meta?.label ?? status ?? 'Unknown'}
      color={meta?.color ?? '#94a3b8'}
      bg={meta?.bg ?? 'rgba(148,163,184,0.12)'}
      dot
      className={className}
    />
  );
}

export function FindingStatusBadge({ status, className }: { status: string | null | undefined; className?: string }) {
  const meta = status && status in FINDING_STATUS_META ? FINDING_STATUS_META[status as FindingStatus] : undefined;
  return (
    <Badge
      label={meta?.label ?? status ?? 'Unknown'}
      color={meta?.color ?? '#94a3b8'}
      bg={meta?.bg ?? 'rgba(148,163,184,0.12)'}
      className={className}
    />
  );
}

/** Neutral technical badge (vendor, category, control id, etc.) */
export function TechBadge({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded px-2 py-0.5 text-[11px] font-mono font-medium text-slate-400 bg-base-800 border border-base-600 whitespace-nowrap',
        className
      )}
    >
      {children}
    </span>
  );
}
