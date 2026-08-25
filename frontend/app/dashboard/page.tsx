'use client';

import Link from 'next/link';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
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
import { StatCard } from '@/components/ui/StatCard';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { PageLoader } from '@/components/ui/Progress';
import { ChartCard } from '@/components/dashboard/ChartCard';
import { DataTable } from '@/components/ui/DataTable';
import { AuditStatusBadge, SeverityBadge, TechBadge } from '@/components/ui/Badge';
import { scoreRisk } from '@/lib/security';
import { formatPercent, formatRelative } from '@/lib/format';
import type { Audit, Finding } from '@/types';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
  Cell,
  PieChart,
  Pie,
} from 'recharts';

const AXIS = { stroke: '#4a5876', fontSize: 11 };
const GRID = { stroke: '#1c2638' };

export default function DashboardPage() {
  const { isLoading: authLoading } = useRequireAuth();
  const data = useDashboardData();

  if (authLoading || data.loading) return <PageLoader label="Loading dashboard" />;

  const risk = scoreRisk(data.latestScore ?? data.avgScore);

  const trendData = data.scoreTrend.map((t) => ({ ...t, score: t.score ?? null }));
  const vendorData = data.vendorCompliance.map((v) => ({
    name: v.vendor,
    Devices: v.devices,
    Score: Math.round(v.score),
  }));

  const severityChartData = data.severityDistribution.map((s) => ({
    name: s.name,
    value: s.value,
    color: s.color,
  }));

  return (
    <AppShell title="Dashboard" subtitle="Network security posture overview">
      {data.error && (
        <div className="mb-5">
          <Alert variant="error" title="Dashboard data unavailable" onDismiss={data.refresh}>
            {data.error}
          </Alert>
        </div>
      )}

      {/* Run audit CTA */}
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-base-700 bg-base-850 p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-md border border-accent-500/40 bg-accent-500/10 text-accent-400">
            <PlayCircle className="h-4.5 w-4.5" />
          </div>
          <div>
            <p className="text-sm font-medium text-slate-200">Evaluate a device configuration</p>
            <p className="text-xs text-slate-500">
              Upload a Cisco IOS XE or Juniper JUNOS configuration and run a CIS benchmark audit.
            </p>
          </div>
        </div>
        <Link href="/audit/new">
          <Button>Run New Audit</Button>
        </Link>
      </div>

      {/* Summary metrics */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard
          label="Security Score"
          value={formatPercent(data.latestScore ?? data.avgScore)}
          sub={
            data.scoreDelta != null ? (
              <span className={`inline-flex items-center gap-1 font-medium ${data.scoreDelta >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                {data.scoreDelta >= 0 ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
                {data.scoreDelta >= 0 ? '+' : ''}
                {data.scoreDelta.toFixed(1)} pts vs previous
              </span>
            ) : (
              'No completed audits'
            )
          }
          accent={risk.color}
          icon={<ShieldCheck className="h-4 w-4" />}
          onClick={() => data.recentAudits.length > 0 && (window.location.href = `/audit/${data.recentAudits[0].id}`)}
        />
        <StatCard
          label="Devices"
          value={data.totalDevices}
          sub={`${data.auditedDevices} audited`}
          icon={<Server className="h-4 w-4" />}
          onClick={() => (window.location.href = '/devices')}
        />
        <StatCard
          label="Critical Findings"
          value={data.criticalFindings}
          accent="#ef4444"
          icon={<AlertOctagon className="h-4 w-4" />}
        />
        <StatCard
          label="High Findings"
          value={data.highFindings}
          accent="#f97316"
          icon={<AlertTriangle className="h-4 w-4" />}
        />
        <StatCard
          label="Needs Review"
          value={data.reviewCount}
          accent="#f59e0b"
          icon={<Eye className="h-4 w-4" />}
        />
      </div>

      {/* Main trend chart */}
      <div className="mt-5">
        <ChartCard
          title="Compliance Score Trend"
          subtitle="Overall score of completed audits over time"
          loading={data.loading}
          empty={trendData.length === 0}
        >
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData} margin={{ top: 8, right: 16, bottom: 4, left: -16 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={GRID.stroke} />
                <XAxis
                  dataKey="date"
                  tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                  stroke={AXIS.stroke}
                  fontSize={AXIS.fontSize}
                />
                <YAxis domain={[0, 100]} stroke={AXIS.stroke} fontSize={AXIS.fontSize} unit="%" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#151d2d',
                    border: '1px solid #243046',
                    borderRadius: 6,
                    fontSize: 12,
                  }}
                  labelFormatter={(_, payload) => (payload?.[0]?.payload?.name as string) ?? ''}
                  formatter={(value) => [`${Number(value).toFixed(1)}%`, 'Score']}
                />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="#22d3ee"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#22d3ee', strokeWidth: 0 }}
                  activeDot={{ r: 5 }}
                  connectNulls
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </div>

      {/* Second row: vendor + framework */}
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <ChartCard
          title="Compliance by Vendor"
          subtitle="Devices and average score per vendor"
          loading={data.loading}
          empty={vendorData.length === 0}
        >
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={vendorData} margin={{ top: 8, right: 16, bottom: 4, left: -16 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={GRID.stroke} />
                <XAxis dataKey="name" stroke={AXIS.stroke} fontSize={AXIS.fontSize} />
                <YAxis yAxisId="devices" orientation="left" stroke={AXIS.stroke} fontSize={AXIS.fontSize} allowDecimals={false} />
                <YAxis yAxisId="score" orientation="right" domain={[0, 100]} stroke={AXIS.stroke} fontSize={AXIS.fontSize} unit="%" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#151d2d', border: '1px solid #243046', borderRadius: 6, fontSize: 12 }}
                />
                <Bar yAxisId="devices" dataKey="Devices" fill="#243046" radius={[3, 3, 0, 0]} />
                <Bar yAxisId="score" dataKey="Score" fill="#22d3ee" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>

        <ChartCard
          title="Framework Status"
          subtitle="Active evaluation frameworks"
          loading={data.loading}
          empty={false}
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between rounded-md border border-green-500/25 bg-green-500/5 px-3.5 py-3">
              <div className="flex items-center gap-3">
                <TechBadge>CIS</TechBadge>
                <div>
                  <p className="text-sm font-medium text-slate-200">CIS Benchmarks</p>
                  <p className="text-xs text-slate-500">
                    53 Cisco IOS XE + 17 Juniper OS controls · {data.completedAudits.length} completed audit{data.completedAudits.length === 1 ? '' : 's'}
                  </p>
                </div>
              </div>
              <span className="rounded bg-green-500/15 px-2 py-0.5 text-[11px] font-semibold uppercase text-green-400">
                Active
              </span>
            </div>
            {(['NIST SP 800-53', 'DISA STIG'] as const).map((f) => (
              <div key={f} className="flex items-center justify-between rounded-md border border-base-700 px-3.5 py-3 opacity-60">
                <div className="flex items-center gap-3">
                  <TechBadge>{f.startsWith('NIST') ? 'NIST' : 'STIG'}</TechBadge>
                  <div>
                    <p className="text-sm font-medium text-slate-300">{f}</p>
                    <p className="text-xs text-slate-500">Architecture ready · controls not yet configured</p>
                  </div>
                </div>
                <span className="rounded bg-base-800 px-2 py-0.5 text-[11px] font-semibold uppercase text-slate-500">
                  Pending
                </span>
              </div>
            ))}
          </div>
        </ChartCard>
      </div>

      {/* Third row: severity + top failing controls */}
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <ChartCard
          title="Severity Distribution"
          subtitle="Findings across completed audits"
          loading={data.loading}
          empty={severityChartData.length === 0}
        >
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityChartData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={52}
                  outerRadius={80}
                  paddingAngle={2}
                  strokeWidth={0}
                >
                  {severityChartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#151d2d', border: '1px solid #243046', borderRadius: 6, fontSize: 12 }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 flex flex-wrap justify-center gap-3">
            {data.severityDistribution.map((s) => (
              <span key={s.name} className="flex items-center gap-1.5 text-xs text-slate-400">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: s.color }} />
                {s.name} · {s.value}
              </span>
            ))}
          </div>
        </ChartCard>

        <ChartCard
          title="Top Failing Controls"
          subtitle="Most frequently failed controls (from critical findings)"
          loading={data.loading}
          empty={data.topFailingControls.length === 0}
        >
          <div className="space-y-2.5">
            {data.topFailingControls.map((c, i) => (
              <div key={c.control_id} className="flex items-center gap-3">
                <span className="w-5 text-right font-mono text-[11px] text-slate-600">{i + 1}</span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <p className="truncate text-xs font-medium text-slate-300">{c.title}</p>
                    <span className="font-mono text-[11px] text-slate-500">{c.count}x</span>
                  </div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-base-800">
                    <div
                      className="h-full rounded-full bg-red-500/70"
                      style={{ width: `${Math.min(100, (c.count / Math.max(1, data.topFailingControls[0].count)) * 100)}%` }}
                    />
                  </div>
                </div>
                <TechBadge>{c.control_id}</TechBadge>
              </div>
            ))}
          </div>
        </ChartCard>
      </div>

      {/* Recent audits + critical findings */}
      <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Recent Audits</h3>
                <p className="mt-0.5 text-xs text-slate-500">Latest audit activity</p>
              </div>
              <Link href="/audits" className="text-xs font-medium text-accent-400 hover:text-accent-300">
                View all
              </Link>
            </div>
            <div className="panel-body p-0">
              <DataTable<Audit>
                dense
                rows={data.recentAudits}
                rowKey={(a) => a.id}
                onRowClick={(a) => (window.location.href = `/audit/${a.id}`)}
                columns={[
                  {
                    key: 'name',
                    header: 'Audit',
                    render: (a) => <span className="font-medium text-slate-200">{a.name}</span>,
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
                      <span className="font-mono text-slate-300">
                        {a.overall_score != null ? formatPercent(a.overall_score) : '—'}
                      </span>
                    ),
                    sortValue: (a) => a.overall_score ?? -1,
                  },
                  {
                    key: 'findings_count',
                    header: 'Findings',
                    align: 'right',
                    render: (a) => <span className="font-mono">{a.findings_count}</span>,
                    sortValue: (a) => a.findings_count,
                  },
                  {
                    key: 'created_at',
                    header: 'Run',
                    render: (a) => <span className="text-slate-500">{formatRelative(a.created_at)}</span>,
                    sortValue: (a) => a.created_at,
                  },
                ]}
              />
            </div>
          </div>
        </div>

        <div>
          <div className="panel h-full">
            <div className="panel-header">
              <div>
                <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                  <AlertOctagon className="h-3.5 w-3.5 text-red-400" />
                  Critical Findings
                </h3>
                <p className="mt-0.5 text-xs text-slate-500">Most recent critical issues</p>
              </div>
            </div>
            <div className="panel-body">
              {data.recentCriticalFindings.length === 0 ? (
                <div className="py-8 text-center">
                  <p className="text-xs text-slate-500">No critical findings yet.</p>
                </div>
              ) : (
                <ul className="space-y-3">
                  {data.recentCriticalFindings.map((f) => (
                    <li key={f.id}>
                      <a
                        href={`/findings/${f.id}`}
                        className="block rounded-md border border-base-700 bg-base-900 px-3 py-2.5 transition-colors hover:border-red-500/30"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <p className="text-xs font-medium text-slate-200">{f.title}</p>
                          <SeverityBadge severity={f.severity} />
                        </div>
                        <div className="mt-1.5 flex items-center gap-2">
                          {f.affected_vendor && <TechBadge>{f.affected_vendor}</TechBadge>}
                          <span className="text-[11px] text-slate-500">
                            {f.affected_device ?? '—'} · {formatRelative(f.created_at)}
                          </span>
                        </div>
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Empty state when nothing exists */}
      {data.audits.length === 0 && (
        <div className="mt-5">
          <div className="panel flex flex-col items-center py-14 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-lg border border-base-700 bg-base-900 text-accent-400">
              <Activity className="h-5 w-5" />
            </div>
            <h3 className="text-sm font-semibold text-slate-200">No audits yet</h3>
            <p className="mt-1 max-w-md text-xs text-slate-500">
              Upload a device configuration to run your first CIS benchmark audit. Every result includes
              evidence-backed findings and remediation guidance.
            </p>
            <div className="mt-5 flex gap-2">
              <Link href="/audit/new">
                <Button>Run First Audit</Button>
              </Link>
              <Link href="/devices">
                <Button variant="secondary">
                  <Network className="h-3.5 w-3.5" />
                  Manage Devices
                </Button>
              </Link>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
