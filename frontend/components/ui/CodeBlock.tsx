'use client';

import { useState } from 'react';
import { Check, Copy } from 'lucide-react';

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
    } catch {
      // clipboard unavailable
    }
  };

  const lines = code.split('\n');

  return (
    <div className={`overflow-hidden rounded-lg border border-base-700 bg-base-950 ${className ?? ''}`}>
      <div className="flex items-center justify-between border-b border-base-800 px-3 py-1.5">
        <span className="font-mono text-[11px] uppercase tracking-wider text-slate-500">
          {language ?? 'config'}
        </span>
        <button
          onClick={copy}
          aria-label="Copy to clipboard"
          className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-slate-400 hover:bg-base-800 hover:text-slate-200"
        >
          {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <div className="code-block overflow-auto p-3 text-slate-300" style={maxHeight ? { maxHeight } : undefined}>
        {lineNumbers ? (
          <table className="w-full border-collapse">
            <tbody>
              {lines.map((line, i) => (
                <tr key={i}>
                  <td className="w-10 select-none pr-3 text-right align-top font-mono text-[11px] leading-relaxed text-slate-600">
                    {i + 1}
                  </td>
                  <td className="align-top">{line || ' '}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          code
        )}
      </div>
    </div>
  );
}
