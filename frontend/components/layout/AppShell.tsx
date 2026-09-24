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
    <div className="min-h-screen bg-[#fafafb]">
      <Sidebar />
      <div className="ml-[260px]">
        <TopBar title={title} subtitle={subtitle} actions={actions} />
        <main className="px-8 py-6">{children}</main>
      </div>
    </div>
  );
}
