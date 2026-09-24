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
    <header className="flex items-center justify-between border-b border-surface-100 bg-white px-8 py-4">
      <div className="min-w-0 flex-1">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs text-ink-400 mb-1">
          {crumbs.map((crumb, i) => (
            <span key={i} className="flex items-center gap-1.5">
              {i > 0 && <span aria-hidden className="text-ink-500 font-light">/</span>}
              {crumb.href && i < crumbs.length - 1 ? (
                <a href={crumb.href} className="transition-colors duration-150 hover:text-brand-600 font-medium">
                  {crumb.label}
                </a>
              ) : (
                <span className={cn(i === crumbs.length - 1 && 'font-semibold text-ink-300')}>{crumb.label}</span>
              )}
            </span>
          ))}
        </nav>
        {title && (
          <h1 className="truncate text-xl font-bold tracking-tight text-ink-100">
            {title}
          </h1>
        )}
        {subtitle && <p className="mt-1 truncate text-sm text-ink-400 leading-relaxed">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-shrink-0 items-center gap-2.5 ml-6">{actions}</div>}
    </header>
  );
}
