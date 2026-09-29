import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { TrendingUp, TrendingDown } from 'lucide-react';

export function StatCard({
  label,
  value,
  sub,
  icon,
  accent,
  className,
  onClick,
  size = 'md',
  trend,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: ReactNode;
  accent?: string;
  className?: string;
  onClick?: () => void;
  size?: 'sm' | 'md' | 'lg';
  trend?: { value: number; direction: 'up' | 'down' };
}) {
  const inner = (
    <>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <p className="metric-label">{label}</p>
          <p
            className={cn(
              'font-extrabold tracking-tight',
              size === 'lg' ? 'text-3xl mt-2.5' : size === 'sm' ? 'text-xl mt-1.5' : 'text-2xl mt-2',
              'metric-value'
            )}
            style={{ color: accent ?? undefined }}
          >
            {value}
          </p>
          {trend && (
            <div className={cn('flex items-center gap-1 mt-2 text-sm font-medium', trend.direction === 'up' ? 'text-emerald-600' : 'text-red-600')}>
              {trend.direction === 'up' ? <TrendingUp className="h-3.5 w-3.5" /> : <TrendingDown className="h-3.5 w-3.5" />}
              <span>{Math.abs(trend.value)}%</span>
            </div>
          )}
          {sub && <div className="mt-2.5 text-sm text-ink-400">{sub}</div>}
        </div>
        {icon && (
          <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-brand-50 text-brand-600">
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
          'card p-5 w-full text-left transition-all duration-200 hover:shadow-md cursor-pointer group',
          className
        )}
      >
        {inner}
      </button>
    );
  }

  return <div className={cn('card p-5', className)}>{inner}</div>;
}
