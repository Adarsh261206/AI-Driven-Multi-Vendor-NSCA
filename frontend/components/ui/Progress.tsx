import { cn } from '@/lib/utils';

export function Spinner({ className, label = 'Loading' }: { className?: string; label?: string }) {
  return (
    <div className={cn('flex items-center justify-center gap-2.5 text-ink-400', className)}>
      <div
        role="status"
        aria-label={label}
        className="h-4 w-4 animate-spin rounded-full border-[2.5px] border-surface-200 border-t-brand-600"
      />
      <span className="text-sm font-medium">{label}...</span>
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
  return (
    <div
      className={cn('animate-pulse rounded-lg bg-surface-200', className)}
      aria-hidden
    />
  );
}

export function ProgressBar({
  value,
  max = 100,
  color = '#2d4373',
  className,
  showLabel = false,
  size = 'md',
}: {
  value: number;
  max?: number;
  color?: string;
  className?: string;
  showLabel?: boolean;
  size?: 'sm' | 'md' | 'lg';
}) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  const heights = { sm: 'h-1.5', md: 'h-2', lg: 'h-3' };
  return (
    <div className={cn('flex items-center gap-2.5', className)}>
      <div
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        className={cn('flex-1 overflow-hidden rounded-full bg-surface-200', heights[size])}
      >
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      {showLabel && (
        <span className="text-sm font-semibold text-ink-500 min-w-[3ch] text-right">
          {Math.round(pct)}%
        </span>
      )}
    </div>
  );
}
