'use client';

import type { ReactNode } from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { TopBar } from '@/components/layout/TopBar';

export function AppShell({
  children,
  title,
  subtitle,
  actions,
}: {
  children: ReactNode;
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-base-950">
      <Sidebar />
      <div className="pl-60">
        <TopBar title={title} subtitle={subtitle} actions={actions} />
        <main className="mx-auto max-w-[1400px] px-6 py-6">{children}</main>
      </div>
    </div>
  );
}
