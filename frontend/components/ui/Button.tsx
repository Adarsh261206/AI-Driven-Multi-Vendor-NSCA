import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'success';
type Size = 'sm' | 'md' | 'lg';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

const variantClasses: Record<Variant, string> = {
  primary:
    'bg-accent-600 text-white hover:bg-accent-500 active:bg-accent-700 border border-transparent disabled:bg-base-600 disabled:text-slate-400',
  secondary:
    'bg-base-800 text-slate-200 hover:bg-base-700 border border-base-600 disabled:opacity-50',
  ghost:
    'bg-transparent text-slate-300 hover:bg-base-800 hover:text-slate-100 border border-transparent disabled:opacity-50',
  danger:
    'bg-red-600/15 text-red-400 hover:bg-red-600/25 border border-red-500/30 disabled:opacity-50',
  success:
    'bg-green-600/15 text-green-400 hover:bg-green-600/25 border border-green-500/30 disabled:opacity-50',
};

const sizeClasses: Record<Size, string> = {
  sm: 'h-7 px-2.5 text-xs gap-1.5',
  md: 'h-9 px-3.5 text-sm gap-2',
  lg: 'h-11 px-5 text-sm gap-2',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, disabled, children, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        'inline-flex items-center justify-center rounded font-medium transition-colors',
        'focus-visible:outline-2 focus-visible:outline-accent-400',
        'disabled:cursor-not-allowed',
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  )
);

Button.displayName = 'Button';
