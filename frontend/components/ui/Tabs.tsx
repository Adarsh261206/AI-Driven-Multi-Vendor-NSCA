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
      <div role="tablist" aria-label="Sections" className="flex gap-0 border-b border-surface-200">
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
              'relative flex items-center gap-1.5 px-4 py-3 text-sm font-semibold transition-colors duration-200',
              tab.id === active
                ? 'text-brand-600'
                : 'text-ink-400 hover:text-ink-600'
            )}
          >
            {tab.label}
            {tab.count != null && (
              <span
                className={cn(
                  'rounded-full px-2 py-0.5 text-xs font-mono',
                  tab.id === active
                    ? 'bg-brand-100 text-brand-700'
                    : 'bg-surface-100 text-ink-400'
                )}
              >
                {tab.count}
              </span>
            )}
            {tab.id === active && (
              <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-brand-600" />
            )}
          </button>
        ))}
      </div>
      <div className="pt-5">{activeTab?.content}</div>
    </div>
  );
}
