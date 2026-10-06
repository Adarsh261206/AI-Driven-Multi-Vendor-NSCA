'use client';

import Link from 'next/link';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Eye,
  Network,
  PlayCircle,
  ShieldCheck,
  Server,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';
import { useRequireAuth } from '@/hooks/useAuth';
import { useDashboardData } from '@/hooks/useDashboardData';
import { AppShell } from '@/components/layout/AppShell';
import { Alert } from '@/components/ui/Alert';
import { PageLoader } from '@/components/ui/Progress';
import { DataTable } from '@/components/ui/DataTable';
import { AuditStatusBadge, SeverityBadge } from '@/components/ui/Badge';
import { scoreRisk } from '@/lib/security';
import { formatPercent, formatRelative } from '@/lib/format';
import type { Audit } from '@/types';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

const AXIS = { stroke: '#a8a89f', fontSize: 11 };
const GRID = { stroke: '#f0eff0' };

export default function DashboardPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const data = useDashboardData();

  if (authLoading || data.loading) return <PageLoader label="Loading dashboard" />;

  const risk = scoreRisk(data.latestScore ?? data.avgScore);

  const trendData = data.scoreTrend.map((t) => ({ ...t, score: t.score ?? null }));
  const severityChartData = data.severityDistribution.map((s) => ({
    name: s.name,
    value: s.value,
    color: s.color,
  }));

  const hasData = data.audits.length > 0;

  return (
    <AppShell
      title="Dashboard"
      subtitle="Security posture overview • Track compliance, findings and audit activity at a glance"
      actions={
        hasData ? (
          <div className="flex items-center gap-3">
            <Link href="/devices" className="btn-secondary">
              <Server className="h-4 w-4" />
              Devices
            </Link>
            <Link href="/audit/new" className="btn-primary">
              <PlayCircle className="h-4 w-4" />
              New Audit
            </Link>
          </div>
        ) : null
      }
    >
      {data.error && (
        <div className="mb-8">
          <Alert variant="error" title="Dashboard data unavailable" onDismiss={data.refresh}>
            {data.error}
          </Alert>
        </div>
      )}

      {/* ── Stat cards — Odoo: generous p-6, soft icon wells, airy spacing ── */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {/* Security Score */}
        <div className="card group transition-all duration-200 hover:shadow-odoo-md">
          <div className="p-6">
            <div className="flex items-start justify-between">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-brand-50 text-brand-600 ring-1 ring-brand-100">
                <ShieldCheck className="h-5 w-5" strokeWidth={1.75} />
              </div>
              {data.scoreDelta != null && (
                <span
                  className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ${
                    data.scoreDelta >= 0
                      ? 'bg-emerald-50 text-emerald-700 ring-emerald-200'
                      : 'bg-red-50 text-red-700 ring-red-200'
                  }`}
                >
                  {data.scoreDelta >= 0 ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
                  {data.scoreDelta >= 0 ? '+' : ''}
                  {data.scoreDelta.toFixed(1)}
                </span>
              )}
            </div>
            <p className="metric-label mt-5">Security Score</p>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="metric-value">
                {data.latestScore != null ? `${Math.round(data.latestScore)}%` : '—'}
              </span>
              {risk?.label && data.latestScore != null && (
                <span className="rounded-full bg-surface-50 px-2 py-0.5 text-xs font-medium text-ink-400 ring-1 ring-surface-200">
                  {risk.label}
                </span>
              )}
            </div>
            <p className="mt-3 text-xs leading-relaxed text-ink-400">
              {data.avgScore != null ? `Avg ${Math.round(data.avgScore)}% across ${data.completedAudits.length} audits` : 'No completed audits yet'}
            </p>
          </div>
        </div>

        {/* Total Devices */}
        <div className="card group transition-all duration-200 hover:shadow-odoo-md">
          <div className="p-6">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-sky-50 text-sky-600 ring-1 ring-sky-100">
              <Server className="h-5 w-5" strokeWidth={1.75} />
            </div>
            <p className="metric-label mt-5">Total Devices</p>
            <p className="metric-value mt-2">{data.totalDevices}</p>
            <p className="mt-3 flex items-center gap-1.5 text-xs text-ink-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              {data.auditedDevices} audited · {data.totalDevices > 0 ? Math.round((data.auditedDevices / Math.max(1, data.totalDevices)) * 100) : 0}% coverage
            </p>
          </div>
        </div>

        {/* Critical Findings */}
        <div className="card group transition-all duration-200 hover:shadow-odoo-md">
          <div className="p-6">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-red-50 text-sev-critical ring-1 ring-red-100">
              <AlertOctagon className="h-5 w-5" strokeWidth={1.75} />
            </div>
            <p className="metric-label mt-5">Critical Findings</p>
            <p className="metric-value mt-2 text-sev-critical">{data.criticalFindings}</p>
            <p className="mt-3 text-xs leading-relaxed text-ink-400">
              {data.criticalFindings > 0 ? 'Requires immediate attention' : 'No critical issues — good standing'}
            </p>
          </div>
        </div>

        {/* High Findings */}
        <div className="card group transition-all duration-200 hover:shadow-odoo-md">
          <div className="p-6">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-orange-50 text-sev-high ring-1 ring-orange-100">
              <AlertTriangle className="h-5 w-5" strokeWidth={1.75} />
            </div>
            <p className="metric-label mt-5">High Findings</p>
            <p className="metric-value mt-2 text-sev-high">{data.highFindings}</p>
            <p className="mt-3 text-xs leading-relaxed text-ink-400">
              {data.highFindings > 0 ? 'Review recommended this week' : 'No high severity open'}
            </p>
          </div>
        </div>
      </div>

      {/* ── Analytics — Odoo cards with generous header/body padding ── */}
      <div className="mt-8">
        <div className="mb-5 flex items-end justify-between">
          <div>
            <h2 className="section-title">Analytics</h2>
            <p className="mt-1 text-xs text-ink-400">Compliance trends and finding breakdown</p>
          </div>
          <span className="hidden text-xs text-ink-400 sm:block">{trendData.length} audits · {severityChartData.length} severities</span>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Compliance Trend */}
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h3 className="text-sm font-semibold text-ink-100">Compliance Trend</h3>
                <p className="mt-0.5 text-xs text-ink-400">Score over completed audits</p>
              </div>
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-surface-50 text-ink-400 ring-1 ring-surface-200">
                <BarChart3 className="h-4 w-4" />
              </div>
            </div>
            <div className="card-body">
              {trendData.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-surface-50 text-ink-400 ring-1 ring-surface-200">
                    <BarChart3 className="h-6 w-6" />
                  </div>
                  <p className="mt-4 text-sm font-medium text-ink-300">No trend data yet</p>
                  <p className="mt-1 text-xs text-ink-400">Run an audit to populate this view</p>
                </div>
              ) : (
                <div className="h-[280px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={trendData} margin={{ top: 12, right: 20, bottom: 8, left: -12 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={GRID.stroke} vertical={false} />
                      <XAxis
                        dataKey="date"
                        tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                        stroke={AXIS.stroke}
                        fontSize={AXIS.fontSize}
                        tickLine={false}
                        axisLine={false}
                        dy={8}
                      />
                      <YAxis domain={[0, 100]} stroke={AXIS.stroke} fontSize={AXIS.fontSize} unit="%" tickLine={false} axisLine={false} dx={-4} />
                      <Tooltip
                        cursor={{ stroke: '#e9e7e4', strokeDasharray: '4 4' }}
                        contentStyle={{
                          backgroundColor: '#ffffff',
                          border: '1px solid #ececec',
                          borderRadius: 12,
                          fontSize: 13,
                          boxShadow: '0 4px 12px rgba(0,0,0,0.06), 0 1px 3px rgba(0,0,0,0.04)',
                          padding: '10px 14px',
                        }}
                        labelFormatter={(_, payload) => (payload?.[0]?.payload?.name as string) ?? ''}
                        formatter={(value) => [`${Number(value).toFixed(1)}%`, 'Score']}
                      />
                      <Line
                        type="monotone"
                        dataKey="score"
                        stroke="#4c6ef5"
                        strokeWidth={2.5}
                        dot={{ r: 4, fill: '#4c6ef5', strokeWidth: 2, stroke: '#ffffff' }}
                        activeDot={{ r: 6, fill: '#4c6ef5', stroke: '#ffffff', strokeWidth: 2 }}
                        connectNulls
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </div>

          {/* Severity Distribution */}
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h3 className="text-sm font-semibold text-ink-100">Severity Distribution</h3>
                <p className="mt-0.5 text-xs text-ink-400">Findings across completed audits</p>
              </div>
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-surface-50 text-ink-400 ring-1 ring-surface-200">
                <AlertOctagon className="h-4 w-4" />
              </div>
            </div>
            <div className="card-body">
              {severityChartData.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-surface-50 text-ink-400 ring-1 ring-surface-200">
                    <Activity className="h-6 w-6" />
                  </div>
                  <p className="mt-4 text-sm font-medium text-ink-300">No findings yet</p>
                  <p className="mt-1 text-xs text-ink-400">Completed audits will populate the distribution</p>
                </div>
              ) : (
                <>
                  <div className="h-[260px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={severityChartData}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={64}
                          outerRadius={92}
                          paddingAngle={3}
                          strokeWidth={0}
                        >
                          {severityChartData.map((entry) => (
                            <Cell key={entry.name} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#ffffff',
                            border: '1px solid #ececec',
                            borderRadius: 12,
                            fontSize: 13,
                            boxShadow: '0 4px 12px rgba(0,0,0,0.06), 0 1px 3px rgba(0,0,0,0.04)',
                            padding: '10px 14px',
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-2 flex flex-wrap justify-center gap-2.5">
                    {data.severityDistribution.map((s) => (
                      <span
                        key={s.name}
                        className="inline-flex items-center gap-2 rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-medium text-ink-400"
                      >
                        <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: s.color }} />
                        {s.name}
                        <span className="font-mono text-ink-300">{s.value}</span>
                      </span>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Activity — Top failing controls + Recent audits ── */}
      <div className="mt-8">
        <div className="mb-5">
          <h2 className="section-title">Operational Overview</h2>
          <p className="mt-1 text-xs text-ink-400">Controls that fail most often and latest audit runs</p>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Top Failing Controls */}
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h3 className="text-sm font-semibold text-ink-100">Top Failing Controls</h3>
                <p className="mt-0.5 text-xs text-ink-400">Most frequently failed controls</p>
              </div>
              <span className="rounded-full bg-surface-50 px-2.5 py-1 text-xs font-medium text-ink-400 ring-1 ring-surface-200">
                {data.topFailingControls.length} controls
              </span>
            </div>

            <div className="px-6 py-6">
              {data.topFailingControls.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-50 text-emerald-600 ring-1 ring-emerald-100">
                    <ShieldCheck className="h-6 w-6" />
                  </div>
                  <p className="mt-4 text-sm font-medium text-ink-300">No failing controls yet</p>
                  <p className="mt-1 max-w-[22rem] text-xs leading-relaxed text-ink-400">All controls are passing or no critical findings have been collected.</p>
                </div>
              ) : (
                <div className="space-y-5">
                  {data.topFailingControls.map((c, i) => (
                    <div key={c.control_id} className="group flex items-center gap-4">
                      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-50 font-mono text-xs font-semibold text-ink-400 ring-1 ring-surface-200 group-hover:bg-white group-hover:shadow-xs">
                        {String(i + 1).padStart(2, '0')}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-start justify-between gap-3">
                          <p className="truncate text-sm font-medium leading-tight text-ink-100">{c.title}</p>
                          <span className="shrink-0 font-mono text-xs font-semibold text-ink-500">{c.count}×</span>
                        </div>
                        <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-surface-100">
                          <div
                            className="h-full rounded-full bg-sev-critical transition-all duration-700"
                            style={{ width: `${Math.min(100, (c.count / Math.max(1, data.topFailingControls[0].count)) * 100)}%` }}
                          />
                        </div>
                      </div>
                      <span className="hidden shrink-0 rounded-lg bg-surface-50 px-2.5 py-1 font-mono text-xs font-medium text-ink-400 ring-1 ring-surface-200 sm:inline-flex">
                        {c.control_id}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Recent Audits */}
          <div className="card overflow-hidden">
            <div className="card-header">
              <div>
                <h3 className="text-sm font-semibold text-ink-100">Recent Audits</h3>
                <p className="mt-0.5 text-xs text-ink-400">Latest audit activity</p>
              </div>
              <Link
                href="/audits"
                className="inline-flex items-center gap-1 rounded-full bg-brand-50 px-3 py-1 text-xs font-semibold text-brand-600 ring-1 ring-brand-100 transition-colors hover:bg-brand-100"
              >
                View all
                <ArrowRight className="h-3 w-3" />
              </Link>
            </div>

            <div className="p-0">
              {data.recentAudits.length === 0 ? (
                <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-surface-50 text-ink-400 ring-1 ring-surface-200">
                    <Network className="h-6 w-6" />
                  </div>
                  <p className="mt-4 text-sm font-medium text-ink-300">No audits yet</p>
                  <p className="mt-1 text-xs text-ink-400">Audits will appear here once created</p>
                </div>
              ) : (
                <DataTable<Audit>
                  rows={data.recentAudits}
                  rowKey={(a) => a.id}
                  onRowClick={(a) => (window.location.href = `/audit/${a.id}`)}
                  className="border-0 shadow-none rounded-none"
                  columns={[
                    {
                      key: 'name',
                      header: 'Audit',
                      render: (a) => <span className="font-semibold text-ink-100">{a.name}</span>,
                      sortValue: (a) => a.name,
                    },
                    {
                      key: 'status',
                      header: 'Status',
                      render: (a) => <AuditStatusBadge status={a.status} />,
                      sortValue: (a) => a.status,
                    },
                    {
                      key: 'overall_score',
                      header: 'Score',
                      align: 'right',
                      render: (a) => (
                        <span className="font-mono text-sm font-semibold text-ink-100">
                          {a.overall_score != null ? formatPercent(a.overall_score) : '—'}
                        </span>
                      ),
                      sortValue: (a) => a.overall_score ?? -1,
                    },
                    {
                      key: 'findings_count',
                      header: 'Findings',
                      align: 'right',
                      render: (a) => <span className="font-mono text-xs text-ink-500">{a.findings_count}</span>,
                      sortValue: (a) => a.findings_count,
                    },
                    {
                      key: 'created_at',
                      header: 'Run',
                      render: (a) => <span className="whitespace-nowrap text-xs text-ink-400">{formatRelative(a.created_at)}</span>,
                      sortValue: (a) => a.created_at,
                    },
                  ]}
                />
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Critical Findings — full-width Odoo card ── */}
      {data.recentCriticalFindings.length > 0 && (
        <div className="mt-8">
          <div className="card overflow-hidden">
            <div className="card-header">
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-50 text-sev-critical ring-1 ring-red-100">
                  <AlertOctagon className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-ink-100">Critical Findings</h3>
                  <p className="text-xs text-ink-400">{data.recentCriticalFindings.length} critical issues requiring attention</p>
                </div>
              </div>
              {/* No /findings index route exists — per-finding links below are the navigation. */}
            </div>

            <div className="px-6 py-6">
              <ul className="space-y-3">
                {data.recentCriticalFindings.map((f) => (
                  <li key={f.id}>
                    <a
                      href={`/findings/${f.id}`}
                      className="group flex items-center justify-between gap-4 rounded-xl border border-surface-200 bg-white px-5 py-4 transition-all duration-150 hover:border-surface-300 hover:bg-surface-50/70 hover:shadow-odoo"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-semibold leading-tight text-ink-100 group-hover:text-brand-700">{f.title}</p>
                        <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-ink-400">
                          {f.affected_vendor && (
                            <span className="inline-flex rounded-md bg-surface-50 px-2 py-0.5 font-mono text-xs font-medium text-ink-500 ring-1 ring-surface-200">
                              {f.affected_vendor}
                            </span>
                          )}
                          <span className="inline-flex items-center gap-1">
                            <span className="hidden sm:inline">{f.affected_device ?? '—'}</span>
                            <span className="text-surface-300">·</span>
                            {formatRelative(f.created_at)}
                          </span>
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-3">
                        <SeverityBadge severity={f.severity} />
                        <ArrowRight className="hidden h-4 w-4 text-ink-400 transition-transform duration-150 group-hover:translate-x-0.5 group-hover:text-ink-600 sm:block" />
                      </div>
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* ── Empty state — Odoo generous whitespace, centered ── */}
      {!hasData && (
        <div className="card mt-8 flex flex-col items-center px-8 py-16 text-center sm:py-20">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-50 text-brand-600 ring-1 ring-brand-100">
            <Activity className="h-7 w-7" strokeWidth={1.5} />
          </div>
          <h3 className="mt-6 text-lg font-bold tracking-tight text-ink-100">No data yet</h3>
          <p className="mt-2 max-w-sm text-sm leading-relaxed text-ink-400">
            Upload a device configuration to run your first CIS benchmark audit and see your security posture come to life.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link href="/audit/new" className="btn-primary">
              <PlayCircle className="h-4 w-4" />
              Run First Audit
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/devices" className="btn-secondary">
              <Server className="h-4 w-4" />
              Manage Devices
            </Link>
          </div>
        </div>
      )}
    </AppShell>
  );
}
