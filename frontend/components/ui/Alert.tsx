import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, Info, XCircle, X } from 'lucide-react';
import { cn } from '@/lib/utils';

type AlertVariant = 'error' | 'warning' | 'success' | 'info';

const VARIANTS: Record<AlertVariant, { icon: ReactNode; classes: string; iconColor: string }> = {
  error: {
    icon: <XCircle className="h-4 w-4" aria-hidden />,
    classes: 'bg-red-500/10 border-red-500/30 text-red-300',
    iconColor: 'text-red-400',
  },
  warning: {
    icon: <AlertTriangle className="h-4 w-4" aria-hidden />,
    classes: 'bg-amber-500/10 border-amber-500/30 text-amber-300',
    iconColor: 'text-amber-400',
  },
  success: {
    icon: <CheckCircle2 className="h-4 w-4" aria-hidden />,
    classes: 'bg-green-500/10 border-green-500/30 text-green-300',
    iconColor: 'text-green-400',
  },
  info: {
    icon: <Info className="h-4 w-4" aria-hidden />,
    classes: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300',
    iconColor: 'text-cyan-400',
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
      className={cn('flex items-start gap-2.5 rounded-lg border px-3.5 py-3 text-sm', v.classes, className)}
    >
      <span className={cn('mt-0.5 flex-shrink-0', v.iconColor)}>{v.icon}</span>
      <div className="flex-1 min-w-0">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className={cn('text-xs opacity-90', title && 'mt-0.5')}>{children}</div>}
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          aria-label="Dismiss"
          className="flex-shrink-0 rounded p-0.5 opacity-70 hover:opacity-100"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  );
}
