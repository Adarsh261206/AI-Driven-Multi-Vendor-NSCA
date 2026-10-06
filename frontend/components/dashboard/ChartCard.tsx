'use client';

import type { ReactNode } from 'react';
import { EmptyState } from '@/components/ui/EmptyState';
import { Skeleton } from '@/components/ui/Progress';

export function ChartCard({
  title,
  subtitle,
  children,
  loading,
  empty,
  actions,
  className,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  loading?: boolean;
  empty?: boolean;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-lg border border-surface-200 bg-white ${className ?? ''}`}>
      <div className="flex items-center justify-between border-b border-surface-200 px-5 py-3.5">
        <div>
          <h3 className="text-sm font-semibold text-ink-100">{title}</h3>
          {subtitle && <p className="mt-0.5 text-xs text-ink-400">{subtitle}</p>}
        </div>
        {actions}
      </div>
      <div className="px-5 py-4">
        {loading ? (
          <div className="space-y-3" aria-busy="true">
            <Skeleton className="h-48 w-full rounded-md bg-surface-200" />
          </div>
        ) : empty ? (
          <EmptyState
            title="No data yet"
            description="Run an audit to populate this view."
          />
        ) : (
          children
        )}
      </div>
    </div>
  );
}
