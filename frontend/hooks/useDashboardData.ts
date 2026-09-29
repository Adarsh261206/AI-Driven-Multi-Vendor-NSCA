'use client';

import { useCallback, useEffect, useState } from 'react';
import { auditsAPI, devicesAPI, findingsAPI, auditExecutionAPI, getApiError } from '@/lib/api';
import type { Audit, Device, Finding, AuditExecutionSummary } from '@/types';

export interface DashboardData {
  audits: Audit[];
  devices: Device[];
  completedAudits: Audit[];
  recentAudits: Audit[];
  // computed
  totalDevices: number;
  auditedDevices: number;
  avgScore: number | null;
  latestScore: number | null;
  scoreDelta: number | null;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  reviewCount: number;
  severityDistribution: { name: string; value: number; color: string }[];
  scoreTrend: { date: string; score: number | null; name: string }[];
  vendorCompliance: { vendor: string; score: number; devices: number; critical: number }[];
  topFailingControls: { control_id: string; title: string; count: number }[];
  recentCriticalFindings: Finding[];
  summaries: Record<string, AuditExecutionSummary>;
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

export function useDashboardData(): DashboardData {
  const [audits, setAudits] = useState<Audit[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [summaries, setSummaries] = useState<Record<string, AuditExecutionSummary>>({});
  const [criticalFindings, setCriticalFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const refresh = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const [devRes, audRes] = await Promise.all([
          devicesAPI.list({ per_page: 100 }),
          auditsAPI.list({ per_page: 100 }),
        ]);
        if (cancelled) return;
        const devList = devRes.data.items || [];
        const audList = audRes.data.items || [];
        setDevices(devList);
        setAudits(audList);

        const completed = audList.filter((a) => a.status === 'completed');

        // Fetch summaries + severity findings for completed audits
        const summaryMap: Record<string, AuditExecutionSummary> = {};
        let crit: Finding[] = [];
        await Promise.all(
          completed.map(async (a) => {
            try {
              const [sumRes, critRes] = await Promise.all([
                auditExecutionAPI.getSummary(a.id),
                findingsAPI.listByAudit(a.id, { per_page: 50, severity: 'CRITICAL' }),
              ]);
              if (cancelled) return;
              summaryMap[a.id] = sumRes.data;
              crit = crit.concat(critRes.data.items || []);
            } catch {
              // summary unavailable for this audit
            }
          })
        );
        if (cancelled) return;
        setSummaries(summaryMap);
        setCriticalFindings(crit);
      } catch (err) {
        if (!cancelled) setError(getApiError(err, 'Failed to load dashboard data'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [tick]);

  const completedAudits = audits.filter((a) => a.status === 'completed' && a.overall_score != null);
  const recentAudits = [...audits].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  ).slice(0, 8);

  const avgScore =
    completedAudits.length > 0
      ? completedAudits.reduce((s, a) => s + (a.overall_score ?? 0), 0) / completedAudits.length
      : null;

  const byTime = [...completedAudits].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
  );
  const latestScore = byTime.length > 0 ? byTime[byTime.length - 1].overall_score : null;
  const prevScore = byTime.length > 1 ? byTime[byTime.length - 2].overall_score : null;
  const scoreDelta =
    latestScore != null && prevScore != null ? latestScore - prevScore : null;

  const totalFindings = audits.reduce((s, a) => s + (a.findings_count || 0), 0);
  const criticalFindingsTotal = audits.reduce((s, a) => s + (a.critical_findings || 0), 0);
  const highFindingsTotal = audits.reduce((s, a) => s + (a.high_findings || 0), 0);
  const reviewCount = audits.reduce((s, a) => s + (a.medium_findings || 0) + (a.low_findings || 0), 0);

  const severityDistribution = [
    { name: 'Critical', value: criticalFindingsTotal, color: '#ef4444' },
    { name: 'High', value: highFindingsTotal, color: '#f97316' },
    { name: 'Medium', value: audits.reduce((s, a) => s + (a.medium_findings || 0), 0), color: '#f59e0b' },
    { name: 'Low', value: audits.reduce((s, a) => s + (a.low_findings || 0), 0), color: '#38bdf8' },
  ].filter((d) => d.value > 0);

  const scoreTrend = byTime.map((a) => ({
    date: a.completed_at || a.created_at,
    score: a.overall_score ?? null,
    name: a.name,
  }));

  // Vendor compliance: device vendor + audit-derived score by device isn't linked
  // in the API, so group by finding affected_vendor for severity context.
  const vendorDevices = new Map<string, number>();
  for (const d of devListAll(devices)) {
    const v = d.vendor || 'unknown';
    vendorDevices.set(v, (vendorDevices.get(v) ?? 0) + 1);
  }
  const vendorCompliance = Array.from(vendorDevices.entries())
    .map(([vendor, count]) => ({
      vendor,
      devices: count,
      score: completedAudits.length > 0 ? avgScore ?? 0 : 0,
      critical: 0,
    }))
    .sort((a, b) => a.vendor.localeCompare(b.vendor));

  // Top failing controls from critical findings evidence
  const controlCounts = new Map<string, { title: string; count: number }>();
  for (const f of criticalFindings) {
    const cid = f.evidence?.control_id ?? f.compliance_result_id ?? 'unknown';
    const title = f.title;
    const cur = controlCounts.get(cid) ?? { title, count: 0 };
    cur.count += 1;
    controlCounts.set(cid, cur);
  }
  const topFailingControls = Array.from(controlCounts.entries())
    .map(([control_id, v]) => ({ control_id, title: v.title, count: v.count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  const auditedDevices = new Set<string>();
  for (const f of criticalFindings) if (f.affected_device) auditedDevices.add(f.affected_device);
  const auditedDevicesCount = Math.min(devices.length, Math.max(auditedDevices.size, completedAudits.length));

  return {
    audits,
    devices,
    completedAudits,
    recentAudits,
    totalDevices: devices.length,
    auditedDevices: auditedDevicesCount,
    avgScore,
    latestScore,
    scoreDelta,
    totalFindings,
    criticalFindings: criticalFindingsTotal,
    highFindings: highFindingsTotal,
    reviewCount,
    severityDistribution,
    scoreTrend,
    vendorCompliance,
    topFailingControls,
    recentCriticalFindings: criticalFindings.slice(0, 6),
    summaries,
    loading,
    error,
    refresh,
  };
}

function devListAll(devices: Device[]): Device[] {
  return devices;
}
