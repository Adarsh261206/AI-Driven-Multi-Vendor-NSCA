'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Activity,
  BookOpenCheck,
  FileText,
  LayoutDashboard,
  Network,
  PlayCircle,
  Settings,
  ShieldCheck,
  LogOut,
  BrainCircuit,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuthStore } from '@/stores/authStore';

const NAV_SECTIONS: { label: string; items: { href: string; label: string; icon: React.ReactNode }[] }[] = [
  {
    label: 'Operations',
    items: [
      { href: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard className="h-4 w-4" strokeWidth={1.75} /> },
      { href: '/devices', label: 'Devices', icon: <Network className="h-4 w-4" strokeWidth={1.75} /> },
      { href: '/audit/new', label: 'Run Audit', icon: <PlayCircle className="h-4 w-4" strokeWidth={1.75} /> },
      { href: '/audits', label: 'Audit History', icon: <Activity className="h-4 w-4" strokeWidth={1.75} /> },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { href: '/frameworks', label: 'Frameworks', icon: <BookOpenCheck className="h-4 w-4" strokeWidth={1.75} /> },
      { href: '/reports', label: 'Reports', icon: <FileText className="h-4 w-4" strokeWidth={1.75} /> },
      { href: '/training', label: 'AI Training', icon: <BrainCircuit className="h-4 w-4" strokeWidth={1.75} /> },
    ],
  },
  {
    label: 'System',
    items: [{ href: '/settings', label: 'Settings', icon: <Settings className="h-4 w-4" strokeWidth={1.75} /> }],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { user, logout } = useAuthStore();

  const isActive = (href: string) => {
    if (href === '/devices') return pathname.startsWith('/devices');
    if (href === '/audit/new') return pathname.startsWith('/audit/new');
    if (href === '/audits') return pathname.startsWith('/audits');
    if (href.startsWith('/audit/')) return pathname.startsWith('/audit/');
    return pathname === href || pathname.startsWith(href + '/');
  };

  const handleLogout = () => {
    logout();
    router.replace('/login');
  };

  return (
    <aside className="fixed inset-y-0 left-0 z-40 flex w-[260px] flex-col border-r border-surface-200 bg-white">
      {/* Brand — Odoo-like: clean, generous, well-spaced */}
      <div className="flex h-16 items-center gap-3 border-b border-surface-100 px-6">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-600 shadow-sm">
          <ShieldCheck className="h-4 w-4 text-white" strokeWidth={2} />
        </div>
        <span className="text-sm font-bold tracking-tight text-ink-100">ConfigShield</span>
        <span className="ml-auto rounded-full bg-brand-50 px-2 py-0.5 text-xs font-medium text-brand-700">SIH 2026</span>
      </div>

      {/* Navigation — Odoo-like: generous, clean, well-spaced */}
      <nav className="flex-1 overflow-y-auto px-4 py-6" aria-label="Main navigation">
        {NAV_SECTIONS.map((section, sIdx) => (
          <div key={section.label} className={cn(sIdx < NAV_SECTIONS.length - 1 && 'mb-6')}>
            <p className="mb-3 px-3 text-xs font-semibold uppercase tracking-wider text-ink-500">
              {section.label}
            </p>
            <ul className="space-y-1">
              {section.items.map((item) => {
                const active = isActive(item.href);
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      aria-current={active ? 'page' : undefined}
                      className={cn(
                        'group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-all duration-150',
                        active
                          ? 'bg-brand-50 font-medium text-brand-700 shadow-sm'
                          : 'text-ink-400 hover:bg-surface-50 hover:text-ink-300'
                      )}
                    >
                      <span
                        className={cn(
                          'transition-colors duration-150',
                          active ? 'text-brand-600' : 'text-ink-500 group-hover:text-ink-400'
                        )}
                      >
                        {item.icon}
                      </span>
                      <span className="flex-1">{item.label}</span>
                      {active && <span className="h-1.5 w-1.5 rounded-full bg-brand-600" />}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Bottom — Odoo-like: clean, well-spaced, subtle */}
      <div className="border-t border-surface-100 px-4 py-4">
        {/* Engine status — subtle, Odoo-like */}
        <div className="mb-3 flex items-center gap-2.5 rounded-lg bg-surface-50 px-3 py-2">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-30" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
          <span className="text-xs font-medium text-ink-400">Engine Online</span>
          <span className="ml-auto text-xs text-ink-500">ML Ready</span>
        </div>

        {/* User — Odoo-like: clean, generous */}
        <div className="flex items-center gap-3 rounded-xl bg-surface-50 px-3 py-3">
          <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-full bg-brand-100 text-sm font-bold text-brand-700 ring-2 ring-white shadow-sm">
            {(user?.full_name || user?.email || '?').charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-ink-100">
              {user?.full_name || user?.email || 'User'}
            </p>
            <p className="truncate text-xs text-ink-400">
              {user?.role ?? 'auditor'} • ConfigShield
            </p>
          </div>
          <button
            onClick={handleLogout}
            aria-label="Sign out"
            title="Sign out"
            className="rounded-lg p-2 text-ink-500 transition-all duration-150 hover:bg-white hover:text-red-600 hover:shadow-sm"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
