import { cn } from '@/lib/utils';

export function Spinner({ className, label = 'Loading' }: { className?: string; label?: string }) {
  return (
    <div className={cn('flex items-center justify-center gap-2 text-slate-500', className)}>
      <div
        role="status"
        aria-label={label}
        className="h-5 w-5 animate-spin rounded-full border-2 border-base-600 border-t-accent-500"
      />
      <span className="text-xs">{label}...</span>
    </div>
  );
}

export function PageLoader({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex min-h-[50vh] items-center justify-center">
      <Spinner label={label} />
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded bg-base-800', className)} aria-hidden />;
}

export function ProgressBar({
  value,
  max = 100,
  color = '#22d3ee',
  className,
  showLabel = false,
}: {
  value: number;
  max?: number;
  color?: string;
  className?: string;
  showLabel?: boolean;
}) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <div
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        className="h-1.5 flex-1 overflow-hidden rounded-full bg-base-800"
      >
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      {showLabel && <span className="text-xs font-mono text-slate-400">{Math.round(pct)}%</span>}
    </div>
  );
}
