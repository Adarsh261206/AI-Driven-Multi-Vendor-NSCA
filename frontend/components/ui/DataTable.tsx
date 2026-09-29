'use client';

import { useMemo, useState, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ChevronsUpDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import { EmptyState } from '@/components/ui/EmptyState';
import { Skeleton } from '@/components/ui/Progress';

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number | null;
  className?: string;
  align?: 'left' | 'right' | 'center';
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  loading?: boolean;
  onRowClick?: (row: T) => void;
  emptyTitle?: string;
  emptyDescription?: string;
  emptyAction?: ReactNode;
  sortable?: boolean;
  page?: number;
  totalPages?: number;
  total?: number;
  onPageChange?: (page: number) => void;
  className?: string;
  dense?: boolean;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  onRowClick,
  emptyTitle = 'No data',
  emptyDescription,
  emptyAction,
  sortable = true,
  page,
  totalPages,
  total,
  onPageChange,
  className,
  dense,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  const sortedRows = useMemo(() => {
    if (!sortable || !sortKey) return rows;
    const col = columns.find((c) => c.key === sortKey);
    if (!col?.sortValue) return rows;
    const dir = sortDir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = col.sortValue!(a);
      const vb = col.sortValue!(b);
      if (va == null && vb == null) return 0;
      if (va == null) return 1;
      if (vb == null) return -1;
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
      return String(va).localeCompare(String(vb)) * dir;
    });
  }, [rows, sortKey, sortDir, columns, sortable]);

  const toggleSort = (key: string) => {
    if (!sortable) return;
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  if (loading) {
    return (
      <div className={cn('space-y-2.5 p-5', className)} aria-busy="true">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <EmptyState
        title={emptyTitle}
        description={emptyDescription}
        action={emptyAction}
        className={className}
      />
    );
  }

  return (
    <div className={cn('table-wrapper', className)}>
      <table className="table">
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                className={cn(
                  col.align === 'right' && 'text-right',
                  col.align === 'center' && 'text-center',
                  col.className
                )}
              >
                {sortable && col.sortValue ? (
                  <button
                    onClick={() => toggleSort(col.key)}
                    className="inline-flex items-center gap-1.5 transition-colors duration-150 hover:text-ink-600"
                  >
                    {col.header}
                    {sortKey === col.key ? (
                      sortDir === 'asc' ? (
                        <ArrowUp className="h-3 w-3" />
                      ) : (
                        <ArrowDown className="h-3 w-3" />
                      )
                    ) : (
                      <ChevronsUpDown className="h-3 w-3 opacity-30" />
                    )}
                  </button>
                ) : (
                  col.header
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedRows.map((row) => (
            <tr
              key={rowKey(row)}
              className={cn(onRowClick && 'cursor-pointer hover:bg-surface-50 transition-colors')}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
            >
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={cn(
                    col.align === 'right' && 'text-right',
                    col.align === 'center' && 'text-center',
                    dense && 'py-3',
                    col.className
                  )}
                >
                  {col.render ? col.render(row) : String((row as Record<string, unknown>)[col.key] ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>

      {(page != null || total != null) && (
        <div className="flex items-center justify-between border-t border-surface-200 px-4 py-3">
          <span className="text-sm text-ink-400">
            {total != null ? `${total.toLocaleString()} total` : `Page ${page ?? 1}`}
          </span>
          {totalPages != null && totalPages > 1 && (
            <div className="flex items-center gap-1">
              <button
                aria-label="Previous page"
                disabled={!page || page <= 1}
                onClick={() => onPageChange?.(Math.max(1, (page ?? 1) - 1))}
                className="rounded-md p-1.5 text-ink-400 transition-colors duration-150 hover:bg-surface-100 hover:text-ink-600 disabled:opacity-30"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <span className="px-2 font-mono text-sm text-ink-500">
                {page ?? 1} / {totalPages}
              </span>
              <button
                aria-label="Next page"
                disabled={!page || (totalPages != null && page >= totalPages)}
                onClick={() => onPageChange?.((page ?? 1) + 1)}
                className="rounded-md p-1.5 text-ink-400 transition-colors duration-150 hover:bg-surface-100 hover:text-ink-600 disabled:opacity-30"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
