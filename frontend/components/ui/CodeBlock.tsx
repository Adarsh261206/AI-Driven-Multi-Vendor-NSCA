'use client';

import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { cn } from '@/lib/utils';

export function CodeBlock({
  code,
  language,
  maxHeight,
  lineNumbers,
  className,
}: {
  code: string;
  language?: string;
  maxHeight?: number;
  lineNumbers?: boolean;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {}
  };

  const lines = code.split('\n');

  return (
    <div className={cn('overflow-hidden rounded-lg border border-surface-200 bg-ink-100', className)}>
      <div className="flex items-center justify-between border-b border-surface-200 bg-surface-50 px-4 py-2">
        <span className="font-mono text-xs uppercase tracking-wider text-ink-400">
          {language ?? 'config'}
        </span>
        <button
          onClick={copy}
          aria-label="Copy to clipboard"
          className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium text-ink-400 transition-colors duration-150 hover:bg-surface-200 hover:text-ink-600"
        >
          {copied ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <div
        className="overflow-auto p-4 font-mono text-sm leading-relaxed text-ink-700"
        style={maxHeight ? { maxHeight } : undefined}
      >
        {lineNumbers ? (
          <table className="w-full border-collapse">
            <tbody>
              {lines.map((line, i) => (
                <tr key={i}>
                  <td className="w-12 select-none pr-4 text-right align-top text-xs text-ink-300">
                    {i + 1}
                  </td>
                  <td className="align-top">{line || ' '}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <pre className="whitespace-pre-wrap">{code}</pre>
        )}
      </div>
    </div>
  );
}
