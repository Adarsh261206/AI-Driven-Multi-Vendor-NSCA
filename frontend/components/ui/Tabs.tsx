'use client';

import { useState, type ReactNode } from 'react';
import { cn } from '@/lib/utils';

export interface TabItem {
  id: string;
  label: string;
  count?: number;
  content: ReactNode;
}

export function Tabs({
  tabs,
  defaultId,
  onChange,
  className,
}: {
  tabs: TabItem[];
  defaultId?: string;
  onChange?: (id: string) => void;
  className?: string;
}) {
  const [active, setActive] = useState(defaultId ?? tabs[0]?.id);
  const activeTab = tabs.find((t) => t.id === active) ?? tabs[0];

  return (
    <div className={className}>
      <div role="tablist" aria-label="Sections" className="flex gap-1 border-b border-base-700">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={tab.id === active}
            onClick={() => {
              setActive(tab.id);
              onChange?.(tab.id);
            }}
            className={cn(
              'flex items-center gap-2 border-b-2 px-3.5 py-2.5 text-sm font-medium transition-colors',
              tab.id === active
                ? 'border-accent-500 text-slate-100'
                : 'border-transparent text-slate-500 hover:text-slate-300'
            )}
          >
            {tab.label}
            {tab.count != null && (
              <span className="rounded bg-base-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-400">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>
      <div className="pt-4">{activeTab?.content}</div>
    </div>
  );
}
