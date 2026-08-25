import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export function StatCard({
  label,
  value,
  sub,
  icon,
  accent,
  className,
  onClick,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: ReactNode;
  accent?: string;
  className?: string;
  onClick?: () => void;
}) {
  const inner = (
    <>
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="truncate text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
          <p
            className="mt-1.5 font-mono text-2xl font-semibold leading-none tracking-tight text-slate-100"
            style={accent ? { color: accent } : undefined}
          >
            {value}
          </p>
          {sub && <div className="mt-1.5 text-xs text-slate-500">{sub}</div>}
        </div>
        {icon && (
          <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-md border border-base-700 bg-base-900 text-slate-400">
            {icon}
          </div>
        )}
      </div>
    </>
  );

  if (onClick) {
    return (
      <button
        onClick={onClick}
        className={cn(
          'panel w-full text-left transition-colors hover:border-base-500 cursor-pointer',
          className
        )}
      >
        {inner}
      </button>
    );
  }

  return <div className={cn('panel', className)}>{inner}</div>;
}
