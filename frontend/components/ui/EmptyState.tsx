import type { ReactNode } from 'react';
import { Inbox } from 'lucide-react';

export function EmptyState({
  title,
  description,
  action,
  icon,
  className,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`flex flex-col items-center justify-center py-16 px-6 text-center ${className ?? ''}`}>
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-brand-50 text-brand-500">
        {icon ?? <Inbox className="h-7 w-7" aria-hidden />}
      </div>
      <h3 className="text-lg font-bold text-ink-700">{title}</h3>
      {description && (
        <p className="mt-1.5 max-w-md text-sm text-ink-400 leading-relaxed">{description}</p>
      )}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}
