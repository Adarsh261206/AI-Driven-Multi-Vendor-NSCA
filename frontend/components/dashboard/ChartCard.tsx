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
    <div className={`panel ${className ?? ''}`}>
      <div className="panel-header">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
          {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
        </div>
        {actions}
      </div>
      <div className="panel-body">
        {loading ? (
          <div className="space-y-2" aria-busy="true">
            <Skeleton className="h-40 w-full" />
          </div>
        ) : empty ? (
          <EmptyState title="No data yet" description="Run an audit to populate this view." />
        ) : (
          children
        )}
      </div>
    </div>
  );
}
