import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'success' | 'navy';
type Size = 'sm' | 'md' | 'lg' | 'xl';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

const variantClasses: Record<Variant, string> = {
  primary: 'btn-primary',
  navy: 'btn-primary',
  secondary: 'btn-secondary',
  ghost: 'btn-ghost',
  danger: 'btn-danger',
  success: 'bg-emerald-600 text-white hover:bg-emerald-700 active:bg-emerald-800 shadow-sm disabled:opacity-50 disabled:bg-surface-300 disabled:text-ink-700 disabled:shadow-none',
};

const sizeClasses: Record<Size, string> = {
  sm: 'h-8 px-3 text-sm gap-1.5 rounded-lg font-medium',
  md: 'h-10 px-4 text-sm gap-2 rounded-lg font-semibold',
  lg: 'h-12 px-5 text-base gap-2 rounded-xl font-semibold',
  xl: 'h-14 px-7 text-base gap-2.5 rounded-xl font-bold tracking-wide',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, disabled, children, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        'inline-flex items-center justify-center transition-all duration-200',
        'focus-visible:outline-2 focus-visible:outline-brand-600 focus-visible:outline-offset-2',
        'disabled:cursor-not-allowed',
        'active:scale-[0.98]',
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
      {children}
    </button>
  )
);

Button.displayName = 'Button';
