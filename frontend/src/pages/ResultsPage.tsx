import { AlertTriangle, ArrowLeft, CheckCircle2, Clock, Loader2, ShieldAlert, ShieldCheck } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'

import { Badge } from '../components/ui/badge'
import type { BadgeTone } from '../lib/tones'
import { riskTone, severityTone } from '../lib/tones'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { useAnalysis } from '../hooks/queries'
import { ApiError } from '../lib/api'
import type { AnalysisDetail, AnalysisStatus } from '../types/api'

const MODULE_TITLES: Record<string, string> = {
  email_parser: 'Email parser',
  url_analysis: 'URL analysis',
  domain_reputation: 'Domain reputation',
  header_analysis: 'Header analysis',
  content_analysis: 'Content analysis',
  attachment_analysis: 'Attachment analysis',
  ml_classification: 'ML classification',
}

function statusTone(status: AnalysisStatus): BadgeTone {
  switch (status) {
    case 'COMPLETED':
      return 'ok'
    case 'FAILED':
      return 'critical'
    case 'RUNNING':
    case 'PENDING':
      return 'accent'
    default:
      return 'neutral'
  }
}

function authTone(status: string): BadgeTone {
  if (status === 'pass') return 'ok'
  if (status === 'fail') return 'critical'
  if (status === 'neutral' || status === 'none') return 'warn'
  return 'neutral'
}

function BackLink() {
  return (
    <Link to="/history" className="inline-flex items-center gap-2 text-xs text-ink-muted hover:text-ink">
      <ArrowLeft className="h-3.5 w-3.5" />
      Back to history
    </Link>
  )
}

function Progress({ data }: { data: AnalysisDetail }) {
  return (
    <Card>
      <CardContent className="py-14 text-center">
        <Loader2 className="mx-auto h-7 w-7 animate-spin text-accent" />
        <p className="mt-4 text-sm font-medium text-ink">Analysis {data.status.toLowerCase()}</p>
        <p className="mt-1 text-xs text-ink-muted">
          Parsing the message, then running detection modules concurrently. This page refreshes
          automatically.
        </p>
      </CardContent>
    </Card>
  )
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-md border border-line bg-raised/60 px-4 py-3">
      <p className="text-[10px] uppercase tracking-wider text-ink-faint">{label}</p>
      <p className="mt-1 text-lg font-semibold tabular-nums text-ink">{value}</p>
      {hint ? <p className="mt-1 text-[11px] text-ink-muted">{hint}</p> : null}
    </div>
  )
}

function Report({ data }: { data: AnalysisDetail }) {
  const completed = data.modules.filter((m) => m.execution_status === 'COMPLETED').length
  const total = Math.max(1, data.modules.length)

  return (
    <>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <Card className="lg:col-span-2">
          <CardHeader>
            <div>
              <CardTitle>Overall assessment</CardTitle>
              <CardDescription>Independent of the ML classifier.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-end gap-4">
              <p className="text-4xl font-semibold tabular-nums text-ink">
                {data.risk_score ?? '—'}
                <span className="ml-1 text-sm font-normal text-ink-faint">/ 100</span>
              </p>
              <Badge tone={riskTone(data.risk_level)}>{data.risk_level ?? data.status}</Badge>
              <Badge tone="accent">{data.classification ?? 'unclassified'}</Badge>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <Stat
                label="Confidence"
                value={
                  data.assessment_confidence != null
                    ? `${Math.round(data.assessment_confidence * 100)}%`
                    : '—'
                }
                hint="Modules completed"
              />
              <Stat label="Findings" value={String(data.findings.length)} />
              <Stat label="Modules" value={`${completed}/${total}`} />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>ML prediction</CardTitle>
              <CardDescription>Independent classifier signal.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {data.ml_prediction ? (
              <>
                <p className="text-lg font-semibold text-ink">{data.ml_prediction.label}</p>
                <p className="mt-1 text-sm text-ink-muted">
                  {Math.round(data.ml_prediction.confidence * 100)}% confidence
                </p>
                <p className="mt-2 font-mono text-xs text-ink-faint">
                  {data.ml_prediction.model_version ?? 'unknown version'}
                </p>
              </>
            ) : (
              <>
                <p className="text-lg font-semibold text-ink">Unavailable</p>
                <p className="mt-1 text-xs text-ink-muted">
                  No trained model artifact is deployed. The deterministic score does not depend on
                  it, and the missing prediction is not treated as safe.
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Authentication</CardTitle>
              <CardDescription>Header claims, not verified.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            {(['spf', 'dkim', 'dmarc'] as const).map((key) => {
              const value = data.authentication?.[key] ?? 'not_verified'
              return (
                <div key={key} className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] uppercase text-ink-faint">{key}</span>
                  <Badge tone={authTone(value)}>{value}</Badge>
                </div>
              )
            })}
          </CardContent>
        </Card>
      </div>

      {data.explanation ? (
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Explanation</CardTitle>
              <CardDescription>Why this email received its score.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-relaxed text-ink-muted">{data.explanation}</p>
          </CardContent>
        </Card>
      ) : null}

      {data.contributions.length > 0 ? (
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Score contributions</CardTitle>
              <CardDescription>
                Duplicate causes are grouped; diminishing weights prevent inflation.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <ul className="divide-y divide-line">
              {data.contributions.map((contribution) => (
                <li key={contribution.category} className="px-5 py-3.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2">
                      <Badge tone={severityTone(contribution.severity)}>
                        {contribution.severity}
                      </Badge>
                      <span className="truncate text-sm text-ink">{contribution.title}</span>
                    </div>
                    <span className="font-mono text-sm tabular-nums text-ink">
                      +{contribution.contribution}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] text-ink-faint">
                    {MODULE_TITLES[contribution.module] ?? contribution.module}
                    {contribution.suppressed_duplicates > 0
                      ? ` · ${contribution.suppressed_duplicates} duplicate finding(s) merged`
                      : ''}
                  </p>
                  {contribution.evidence ? (
                    <p className="mt-2 truncate rounded border border-line bg-canvas px-3 py-1.5 font-mono text-[11px] text-ink-muted">
                      {contribution.evidence}
                    </p>
                  ) : null}
                </li>
              ))}
              {data.ml_prediction ? (
                <li className="flex items-center justify-between px-5 py-3.5">
                  <div>
                    <p className="text-sm text-ink">
                      ML prediction · {data.ml_prediction.label}
                    </p>
                    <p className="mt-1 text-[11px] text-ink-faint">
                      Weighted by {Math.round(data.ml_prediction.confidence * 100)}% confidence
                    </p>
                  </div>
                  <span className="font-mono text-sm tabular-nums text-ink">
                    {data.ml_prediction.contribution >= 0 ? '+' : ''}
                    {data.ml_prediction.contribution}
                  </span>
                </li>
              ) : null}
            </ul>
          </CardContent>
        </Card>
      ) : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Positive checks</CardTitle>
              <CardDescription>Checks that completed without findings.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {data.positives.length === 0 ? (
              <p className="text-sm text-ink-muted">No positive checks were recorded.</p>
            ) : (
              <ul className="space-y-2">
                {data.positives.map((item) => (
                  <li key={item} className="flex items-start gap-2 text-sm text-ink-muted">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" />
                    {item}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Unknown or unavailable checks</CardTitle>
              <CardDescription>Missing data is never interpreted as safe.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            {data.unknowns.length === 0 ? (
              <p className="flex items-center gap-2 text-sm text-ok">
                <ShieldCheck className="h-4 w-4" />
                All expected checks produced a result.
              </p>
            ) : (
              <ul className="space-y-2">
                {data.unknowns.map((item) => (
                  <li key={item.module} className="flex items-start gap-2 text-sm text-ink-muted">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
                    <span>
                      <span className="text-ink">{MODULE_TITLES[item.module] ?? item.module}</span>{' '}
                      <Badge tone={statusTone(item.status)}>{item.status}</Badge>
                      <span className="mt-0.5 block text-[11px] text-ink-faint">{item.reason}</span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Module results</CardTitle>
            <CardDescription>Execution status and duration per analysis module.</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <ul className="divide-y divide-line">
            {data.modules.map((module) => (
              <li key={module.id} className="flex flex-wrap items-center justify-between gap-2 px-5 py-3">
                <div className="min-w-0">
                  <p className="text-sm text-ink">{MODULE_TITLES[module.module_name] ?? module.module_name}</p>
                  {module.error_message ? (
                    <p className="mt-0.5 text-[11px] text-ink-faint">{module.error_message}</p>
                  ) : null}
                </div>
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1 text-[11px] tabular-nums text-ink-faint">
                    <Clock className="h-3 w-3" />
                    {module.execution_duration != null ? `${module.execution_duration} ms` : '—'}
                  </span>
                  <Badge tone={statusTone(module.execution_status)}>
                    {module.execution_status}
                  </Badge>
                </div>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Security findings</CardTitle>
            <CardDescription>Every finding includes evidence and a recommendation.</CardDescription>
          </div>
          <Badge tone={data.findings.length > 0 ? 'warn' : 'ok'}>
            {data.findings.length} finding{data.findings.length === 1 ? '' : 's'}
          </Badge>
        </CardHeader>
        <CardContent className="p-0">
          {data.findings.length === 0 ? (
            <div className="px-5 py-10 text-center">
              <ShieldCheck className="mx-auto h-6 w-6 text-ok" />
              <p className="mt-3 text-sm text-ink">No findings recorded</p>
              <p className="mt-1 text-xs text-ink-muted">
                Completed modules did not raise any security indicators.
              </p>
            </div>
          ) : (
            <ul className="divide-y divide-line">
              {data.findings.map((finding, index) => (
                <li key={`${finding.type}-${index}`} className="px-5 py-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge>
                      <p className="text-sm font-medium text-ink">{finding.title}</p>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-[11px] text-ink-faint">
                      <span>{MODULE_TITLES[finding.source_module] ?? finding.source_module}</span>
                      {finding.risk_contribution != null ? (
                        <span className="text-ink-muted">+{finding.risk_contribution}</span>
                      ) : null}
                    </div>
                  </div>
                  <p className="mt-1.5 text-xs text-ink-muted">{finding.description}</p>
                  {finding.evidence ? (
                    <p className="mt-2 break-words rounded border border-line bg-canvas px-3 py-2 font-mono text-[11px] text-ink-muted">
                      {finding.evidence}
                    </p>
                  ) : null}
                  {finding.recommendation ? (
                    <p className="mt-2 text-xs text-ink-faint">Action: {finding.recommendation}</p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Recommended actions</CardTitle>
            <CardDescription>Derived from the highest-impact findings.</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <ol className="list-decimal space-y-1.5 pl-5 text-sm text-ink-muted">
            {data.recommendations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ol>
        </CardContent>
      </Card>
    </>
  )
}

export function ResultsPage() {
  const { id } = useParams<{ id: string }>()
  const analysis = useAnalysis(id)

  if (analysis.isLoading) {
    return <p className="text-sm text-ink-muted">Loading analysis…</p>
  }

  if (analysis.isError) {
    const notFound = analysis.error instanceof ApiError && analysis.error.status === 404
    return (
      <div className="space-y-4">
        <BackLink />
        <Card>
          <CardContent className="py-10 text-center">
            <ShieldAlert className={`mx-auto h-6 w-6 ${notFound ? 'text-ink-faint' : 'text-critical'}`} />
            <p className="mt-3 text-sm text-ink">
              {notFound ? 'Analysis not found' : 'Analysis could not be loaded'}
            </p>
            <p className="mt-1 text-xs text-ink-muted">
              {analysis.error instanceof ApiError ? analysis.error.message : 'Unexpected error'}
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  const data = analysis.data
  if (!data) {
    return null
  }

  return (
    <div className="space-y-6">
      <div>
        <BackLink />
        <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h1 className="truncate text-xl font-semibold text-ink">
              {data.subject || '(no subject)'}
            </h1>
            <p className="mt-1 break-words text-sm text-ink-muted">
              {data.sender || 'unknown sender'} · {data.original_filename}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge tone={riskTone(data.risk_level)}>{data.risk_level ?? data.status}</Badge>
            <Badge tone="accent">{data.classification ?? 'unclassified'}</Badge>
          </div>
        </div>
      </div>

      {data.status === 'PENDING' || data.status === 'RUNNING' ? <Progress data={data} /> : null}

      {data.status === 'FAILED' ? (
        <Card>
          <CardContent className="py-10 text-center">
            <AlertTriangle className="mx-auto h-6 w-6 text-critical" />
            <p className="mt-3 text-sm text-ink">Analysis failed</p>
            <p className="mt-1 text-xs text-ink-muted">
              {data.error_message ?? 'The analysis could not be completed.'}
            </p>
          </CardContent>
        </Card>
      ) : null}

      {data.status === 'COMPLETED' ? <Report data={data} /> : null}
    </div>
  )
}
