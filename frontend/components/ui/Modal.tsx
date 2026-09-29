'use client';

import { useEffect, type ReactNode } from 'react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    };
  }, [open, onClose]);

  if (!open) return null;

  const sizes = {
    sm: 'max-w-sm',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 pt-[12vh]"
      style={{ background: 'rgba(0, 0, 0, 0.5)', backdropFilter: 'blur(4px)' }}
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn('card w-full animate-in fade-in zoom-in-95 duration-200', sizes[size])}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-header flex items-start justify-between">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-ink-800">{title}</h2>
            {description && <p className="mt-1.5 text-sm text-ink-400">{description}</p>}
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-lg p-1.5 text-ink-400 transition-colors duration-150 hover:bg-surface-100 hover:text-ink-600 -mr-1 -mt-1"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="card-body">{children}</div>
        {footer && (
          <div className="flex justify-end gap-2.5 border-t border-surface-200 px-5 py-4">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
