import type { SeverityValue } from '@/types';

export interface SeverityMeta {
  label: string;
  color: string;
  /** Tailwind badge class matching components/ui/Badge.tsx */
  cls: string;
}

/** Display metadata for each finding severity. Keyed by uppercase severity value. */
export const SEVERITY_META: Record<string, SeverityMeta> = {
  CRITICAL: { label: 'Critical', color: '#ef4444', cls: 'badge-critical' },
  HIGH: { label: 'High', color: '#f97316', cls: 'badge-high' },
  MEDIUM: { label: 'Medium', color: '#f59e0b', cls: 'badge-medium' },
  LOW: { label: 'Low', color: '#38bdf8', cls: 'badge-low' },
};

export interface RiskLevel {
  label: string;
  color: string;
  /** Tailwind text utility for the label */
  cls: string;
}

/**
 * Maps a 0–100 compliance score to a human-readable risk level.
 * Returns null when the score is unknown.
 */
export function scoreRisk(score: number | null | undefined): RiskLevel | null {
  if (score == null || isNaN(score)) return null;

  if (score >= 90) return { label: 'Excellent', color: '#10b981', cls: 'text-emerald-600' };
  if (score >= 75) return { label: 'Good', color: '#22c55e', cls: 'text-green-600' };
  if (score >= 50) return { label: 'Needs attention', color: '#f59e0b', cls: 'text-amber-500' };
  if (score >= 25) return { label: 'Poor', color: '#f97316', cls: 'text-orange-500' };
  return { label: 'Critical', color: '#ef4444', cls: 'text-red-500' };
}

/** Lookup helper that tolerates unknown/legacy severity strings. */
export function severityMeta(severity: SeverityValue | string): SeverityMeta | undefined {
  return SEVERITY_META[severity?.toUpperCase?.() ?? ''];
}
