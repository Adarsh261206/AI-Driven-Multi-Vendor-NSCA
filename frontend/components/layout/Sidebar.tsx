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
      { href: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard className="h-4 w-4" /> },
      { href: '/devices', label: 'Devices', icon: <Network className="h-4 w-4" /> },
      { href: '/audit/new', label: 'Run Audit', icon: <PlayCircle className="h-4 w-4" /> },
      { href: '/audits', label: 'Audit History', icon: <Activity className="h-4 w-4" /> },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { href: '/frameworks', label: 'Frameworks', icon: <BookOpenCheck className="h-4 w-4" /> },
      { href: '/reports', label: 'Reports', icon: <FileText className="h-4 w-4" /> },
      { href: '/training', label: 'AI Training', icon: <BrainCircuit className="h-4 w-4" /> },
    ],
  },
  {
    label: 'System',
    items: [{ href: '/settings', label: 'Settings', icon: <Settings className="h-4 w-4" /> }],
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
    <aside className="fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-base-700 bg-base-900">
      {/* Product identity */}
      <div className="flex h-14 items-center gap-2.5 border-b border-base-700 px-4">
        <div className="flex h-8 w-8 items-center justify-center rounded-md border border-accent-500/40 bg-accent-500/10">
          <ShieldCheck className="h-4.5 w-4.5 text-accent-400" aria-hidden />
        </div>
        <div className="leading-tight">
          <p className="text-[13px] font-semibold tracking-wide text-slate-100">GuardianAudit</p>
          <p className="text-[10px] font-medium uppercase tracking-widest text-slate-500">
            Compliance Console
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4" aria-label="Main navigation">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label} className="mb-5">
            <p className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
              {section.label}
            </p>
            <ul className="space-y-0.5">
              {section.items.map((item) => {
                const active = isActive(item.href);
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      aria-current={active ? 'page' : undefined}
                      className={cn(
                        'flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] font-medium transition-colors',
                        active
                          ? 'bg-accent-500/10 text-accent-300'
                          : 'text-slate-400 hover:bg-base-800 hover:text-slate-200'
                      )}
                    >
                      {item.icon}
                      {item.label}
                      {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-accent-400" aria-hidden />}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* User + environment */}
      <div className="border-t border-base-700 p-3">
        <div className="mb-2.5 flex items-center gap-2 rounded-md border border-base-700 bg-base-850 px-2.5 py-1.5">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-40" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-green-500" />
          </span>
          <span className="text-[11px] font-medium text-slate-400">Engine Online</span>
          <span className="ml-auto font-mono text-[10px] text-slate-600">v1.0</span>
        </div>
        <div className="flex items-center gap-2.5 rounded-md px-2 py-1.5">
          <div className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full bg-base-700 text-[11px] font-semibold text-slate-300">
            {(user?.full_name || user?.email || '?').charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1 leading-tight">
            <p className="truncate text-xs font-medium text-slate-300">
              {user?.full_name || user?.email || 'User'}
            </p>
            <p className="truncate text-[10px] uppercase tracking-wide text-slate-500">
              {user?.role ?? 'auditor'}
            </p>
          </div>
          <button
            onClick={handleLogout}
            aria-label="Sign out"
            title="Sign out"
            className="rounded p-1.5 text-slate-500 hover:bg-base-800 hover:text-red-400"
          >
            <LogOut className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </aside>
  );
}
