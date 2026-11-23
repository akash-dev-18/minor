import { ArrowRight, ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'

import { Badge } from '../components/ui/badge'
import type { BadgeTone } from '../lib/tones'
import { riskTone } from '../lib/tones'
import { Button } from '../components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { useHealth, useModules, useRecentAnalyses, useStats } from '../hooks/queries'
import type { Classification, RiskLevel } from '../types/api'

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Card>
      <CardContent className="py-5">
        <p className="text-xs uppercase tracking-wider text-ink-faint">{label}</p>
        <p className="mt-2 text-2xl font-semibold tabular-nums text-ink">{value}</p>
        {hint ? <p className="mt-1 text-xs text-ink-muted">{hint}</p> : null}
      </CardContent>
    </Card>
  )
}

const CLASSIFICATION_TONES: Record<Classification, BadgeTone> = {
  LEGITIMATE: 'ok',
  SPAM: 'warn',
  PHISHING: 'critical',
}

const RISK_ORDER: RiskLevel[] = ['LOW', 'GUARDED', 'MEDIUM', 'HIGH', 'CRITICAL']

function Distribution({
  title,
  description,
  rows,
}: {
  title: string
  description: string
  rows: Array<{ label: string; count: number; tone: BadgeTone }>
}) {
  const total = rows.reduce((sum, row) => sum + row.count, 0)
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="space-y-2.5">
        {rows.map((row) => {
          const share = total > 0 ? Math.round((row.count / total) * 100) : 0
          return (
            <div key={row.label}>
              <div className="flex items-center justify-between text-xs">
                <span className="text-ink-muted">{row.label}</span>
                <span className="tabular-nums text-ink-faint">
                  {row.count} · {share}%
                </span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-line">
                <div
                  className={`h-full rounded-full ${
                    row.tone === 'critical'
                      ? 'bg-critical'
                      : row.tone === 'warn'
                        ? 'bg-warn'
                        : row.tone === 'ok'
                          ? 'bg-ok'
                          : row.tone === 'accent'
                            ? 'bg-accent'
                            : 'bg-ink-faint'
                  }`}
                  style={{ width: `${share}%` }}
                />
              </div>
            </div>
          )
        })}
        {total === 0 ? <p className="text-xs text-ink-faint">No completed analyses yet.</p> : null}
      </CardContent>
    </Card>
  )
}

export function DashboardPage() {
  const health = useHealth()
  const modules = useModules()
  const recent = useRecentAnalyses(5)
  const stats = useStats()

  const availableModules = modules.data?.filter((m) => m.available).length ?? 0
  const totalModules = modules.data?.length ?? 0

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-ink">Security Overview</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Analysis activity, module readiness and system health.
          </p>
        </div>
        <Link to="/analyze">
          <Button>
            Analyze an email
            <ArrowRight className="h-4 w-4" />
          </Button>
        </Link>
      </header>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Analyses"
          value={stats.data ? String(stats.data.total) : '—'}
          hint="Total stored reports"
        />
        <Stat
          label="Phishing detected"
          value={stats.data ? String(stats.data.threats) : '—'}
          hint={
            stats.data?.average_risk_score != null
              ? `Average score ${stats.data.average_risk_score}`
              : 'No scored analyses yet'
          }
        />
        <Stat
          label="Last 24 hours"
          value={stats.data ? String(stats.data.last_24_hours) : '—'}
          hint="Submitted analyses"
        />
        <Stat
          label="Modules ready"
          value={totalModules ? `${availableModules}/${totalModules}` : '—'}
          hint={
            health.data
              ? `API v${health.data.version} · database ${health.data.database}`
              : 'Checking service health'
          }
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Distribution
          title="Classification"
          description="All stored analyses by final verdict."
          rows={(Object.keys(CLASSIFICATION_TONES) as Classification[]).map((label) => ({
            label,
            count: stats.data?.by_classification[label] ?? 0,
            tone: CLASSIFICATION_TONES[label],
          }))}
        />
        <Distribution
          title="Risk levels"
          description="Distribution of aggregated risk scores."
          rows={RISK_ORDER.map((label) => ({
            label,
            count: stats.data?.by_risk_level[label] ?? 0,
            tone: riskTone(label),
          }))}
        />

        <Card>
          <CardHeader>
            <div>
              <CardTitle>System health</CardTitle>
              <CardDescription>Live dependency status.</CardDescription>
            </div>
            <Badge tone={health.data?.status === 'ok' ? 'ok' : health.isError ? 'critical' : 'neutral'}>
              {health.data?.status === 'ok' ? 'online' : health.isError ? 'offline' : 'checking'}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-ink-muted">API</span>
              <Badge tone={health.data ? 'ok' : health.isError ? 'critical' : 'neutral'}>
                {health.data?.status ?? (health.isError ? 'unreachable' : '—')}
              </Badge>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-ink-muted">Database</span>
              <Badge tone={health.data?.database === 'ok' ? 'ok' : 'neutral'}>
                {health.data?.database ?? '—'}
              </Badge>
            </div>
            <p className="pt-1 text-[11px] leading-relaxed text-ink-faint">
              SQLite with WAL journaling. Unavailable modules are reported as unknown, never as
              safe.
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader>
            <div>
              <CardTitle>Recent activity</CardTitle>
              <CardDescription>Latest submitted analyses, newest first.</CardDescription>
            </div>
            <Link to="/history" className="text-xs text-accent hover:underline">
              View all
            </Link>
          </CardHeader>
          <CardContent className="p-0">
            {recent.isLoading ? (
              <p className="px-5 py-8 text-sm text-ink-muted">Loading analyses…</p>
            ) : recent.isError ? (
              <p className="px-5 py-8 text-sm text-critical">Could not load analyses.</p>
            ) : recent.data && recent.data.items.length > 0 ? (
              <ul className="divide-y divide-line">
                {recent.data.items.map((analysis) => (
                  <li key={analysis.id}>
                    <Link
                      to={`/analyses/${analysis.id}`}
                      className="flex items-center justify-between gap-4 px-5 py-3 hover:bg-raised/60"
                    >
                      <div className="min-w-0">
                        <p className="truncate text-sm text-ink">
                          {analysis.subject || '(no subject)'}
                        </p>
                        <p className="truncate text-xs text-ink-muted">
                          {analysis.sender || 'unknown sender'}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <Badge tone={riskTone(analysis.risk_level)}>
                          {analysis.risk_level ?? analysis.status}
                        </Badge>
                        <span className="text-xs tabular-nums text-ink-faint">
                          {analysis.risk_score ?? '—'}
                        </span>
                      </div>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="px-5 py-10 text-center">
                <ShieldCheck className="mx-auto h-6 w-6 text-ink-faint" />
                <p className="mt-3 text-sm text-ink">No analyses yet</p>
                <p className="mt-1 text-xs text-ink-muted">
                  Submitted emails will appear here with their risk assessment.
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <div>
              <CardTitle>Module status</CardTitle>
              <CardDescription>Detection modules and current availability.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-3 p-4">
            {modules.isLoading ? (
              <p className="text-xs text-ink-muted">Loading modules…</p>
            ) : modules.isError ? (
              <p className="text-xs text-critical">Could not load modules.</p>
            ) : (
              modules.data?.map((module) => (
                <div key={module.name} className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-medium text-ink">{module.title}</p>
                    {!module.available && module.reason ? (
                      <p className="mt-0.5 text-[11px] text-ink-faint">{module.reason}</p>
                    ) : null}
                  </div>
                  <Badge tone={module.available ? 'ok' : 'neutral'}>
                    {module.available ? 'ready' : 'unavailable'}
                  </Badge>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
