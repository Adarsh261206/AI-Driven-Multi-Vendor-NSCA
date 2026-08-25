'use client';

import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';

function pathToBreadcrumb(pathname: string): { label: string; href?: string }[] {
  const parts = pathname.split('/').filter(Boolean);
  const crumbs: { label: string; href?: string }[] = [{ label: 'Console', href: '/dashboard' }];
  let acc = '';
  for (const part of parts) {
    acc += `/${part}`;
    const label = part
      .split('-')
      .map((w) => (w === 'id' ? 'Detail' : w.charAt(0).toUpperCase() + w.slice(1)))
      .join(' ');
    crumbs.push({ label, href: acc });
  }
  return crumbs;
}

export function TopBar({ title, subtitle, actions }: { title?: string; subtitle?: string; actions?: React.ReactNode }) {
  const pathname = usePathname();
  const crumbs = pathToBreadcrumb(pathname);

  return (
    <header className="flex h-14 items-center justify-between gap-4 border-b border-base-700 bg-base-900/80 px-6 backdrop-blur">
      <div className="min-w-0">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-[11px] text-slate-500">
          {crumbs.map((crumb, i) => (
            <span key={i} className="flex items-center gap-1.5">
              {i > 0 && <span aria-hidden>/</span>}
              {crumb.href && i < crumbs.length - 1 ? (
                <a href={crumb.href} className="hover:text-slate-300">
                  {crumb.label}
                </a>
              ) : (
                <span className={cn(i === crumbs.length - 1 && 'text-slate-300')}>{crumb.label}</span>
              )}
            </span>
          ))}
        </nav>
        <h1 className="mt-0.5 truncate text-[15px] font-semibold text-slate-100">
          {title ?? crumbs[crumbs.length - 1].label}
        </h1>
        {subtitle && <p className="truncate text-xs text-slate-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-shrink-0 items-center gap-2">{actions}</div>}
    </header>
  );
}
