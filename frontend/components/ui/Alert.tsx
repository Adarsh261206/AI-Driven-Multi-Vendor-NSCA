import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, Info, XCircle, X } from 'lucide-react';
import { cn } from '@/lib/utils';

type AlertVariant = 'error' | 'warning' | 'success' | 'info';

const VARIANTS: Record<AlertVariant, { icon: ReactNode; border: string; bg: string; iconColor: string }> = {
  error: {
    icon: <XCircle className="h-4 w-4" aria-hidden />,
    border: 'border-l-red-500',
    bg: 'bg-red-50',
    iconColor: 'text-red-500',
  },
  warning: {
    icon: <AlertTriangle className="h-4 w-4" aria-hidden />,
    border: 'border-l-amber-500',
    bg: 'bg-amber-50',
    iconColor: 'text-amber-500',
  },
  success: {
    icon: <CheckCircle2 className="h-4 w-4" aria-hidden />,
    border: 'border-l-emerald-500',
    bg: 'bg-emerald-50',
    iconColor: 'text-emerald-500',
  },
  info: {
    icon: <Info className="h-4 w-4" aria-hidden />,
    border: 'border-l-brand-600',
    bg: 'bg-brand-50',
    iconColor: 'text-brand-600',
  },
};

export function Alert({
  variant = 'info',
  title,
  children,
  onDismiss,
  className,
}: {
  variant?: AlertVariant;
  title?: string;
  children?: ReactNode;
  onDismiss?: () => void;
  className?: string;
}) {
  const v = VARIANTS[variant];
  return (
    <div
      role={variant === 'error' ? 'alert' : 'status'}
      className={cn(
        'flex items-start gap-3 rounded-lg border-l-4 px-4 py-3 text-sm',
        v.border,
        v.bg,
        className
      )}
    >
      <span className={cn('mt-0.5 flex-shrink-0', v.iconColor)}>{v.icon}</span>
      <div className="flex-1 min-w-0">
        {title && <p className="font-semibold text-ink-800">{title}</p>}
        {children && <div className={cn('text-ink-600', title && 'mt-1')}>{children}</div>}
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          aria-label="Dismiss"
          className="flex-shrink-0 rounded-md p-1 text-ink-400 transition-colors duration-150 hover:bg-white/50 hover:text-ink-600"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  );
}
