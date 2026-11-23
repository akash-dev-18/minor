import { Loader2, Search, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent } from '../components/ui/card'
import { useAnalyses, useDeleteAnalysis } from '../hooks/queries'
import { riskTone } from '../lib/tones'
import type { AnalysisFilters, Classification, RiskLevel } from '../types/api'

const CLASSIFICATIONS: Array<Classification | ''> = ['', 'LEGITIMATE', 'SPAM', 'PHISHING']
const RISK_LEVELS: Array<RiskLevel | ''> = ['', 'LOW', 'GUARDED', 'MEDIUM', 'HIGH', 'CRITICAL']

function classificationTone(classification: Classification | null) {
  if (classification === 'PHISHING') return 'critical' as const
  if (classification === 'SPAM') return 'warn' as const
  if (classification === 'LEGITIMATE') return 'ok' as const
  return 'neutral' as const
}

export function HistoryPage() {
  const [query, setQuery] = useState('')
  const [filters, setFilters] = useState<AnalysisFilters>({
    page: 1,
    pageSize: 20,
    sort: 'created_at',
    order: 'desc',
  })
  const analyses = useAnalyses(filters)
  const remove = useDeleteAnalysis()

  function update(patch: Partial<AnalysisFilters>) {
    setFilters((current) => ({ ...current, ...patch, page: patch.page ?? 1 }))
  }

  async function onDelete(id: string) {
    if (!window.confirm('Delete this analysis and its stored email?')) return
    await remove.mutateAsync(id)
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-ink">Analysis History</h1>
        <p className="mt-1 text-sm text-ink-muted">Stored analyses with their final assessment.</p>
      </header>

      <Card>
        <CardContent className="space-y-3 py-4">
          <form
            className="flex flex-wrap items-center gap-2"
            onSubmit={(event) => {
              event.preventDefault()
              update({ q: query.trim() || undefined })
            }}
          >
            <div className="relative min-w-[220px] flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search sender or subject"
                aria-label="Search analyses"
                className="h-9 w-full rounded-md border border-line bg-canvas pl-9 pr-3 text-sm text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
              />
            </div>

            <select
              value={filters.classification ?? ''}
              onChange={(event) =>
                update({ classification: (event.target.value as Classification | '') || '' })
              }
              aria-label="Filter by classification"
              className="h-9 rounded-md border border-line bg-canvas px-3 text-sm text-ink focus:border-accent focus:outline-none"
            >
              {CLASSIFICATIONS.map((value) => (
                <option key={value || 'all'} value={value}>
                  {value || 'All classifications'}
                </option>
              ))}
            </select>

            <select
              value={filters.riskLevel ?? ''}
              onChange={(event) => update({ riskLevel: (event.target.value as RiskLevel | '') || '' })}
              aria-label="Filter by risk level"
              className="h-9 rounded-md border border-line bg-canvas px-3 text-sm text-ink focus:border-accent focus:outline-none"
            >
              {RISK_LEVELS.map((value) => (
                <option key={value || 'all'} value={value}>
                  {value || 'All risk levels'}
                </option>
              ))}
            </select>

            <select
              value={`${filters.sort}:${filters.order}`}
              onChange={(event) => {
                const [sort, order] = event.target.value.split(':') as [
                  AnalysisFilters['sort'],
                  AnalysisFilters['order'],
                ]
                update({ sort, order })
              }}
              aria-label="Sort analyses"
              className="h-9 rounded-md border border-line bg-canvas px-3 text-sm text-ink focus:border-accent focus:outline-none"
            >
              <option value="created_at:desc">Newest first</option>
              <option value="created_at:asc">Oldest first</option>
              <option value="risk_score:desc">Highest risk</option>
              <option value="risk_score:asc">Lowest risk</option>
            </select>

            <Button type="submit" variant="secondary" size="sm">
              Search
            </Button>
          </form>

          {remove.isError ? (
            <p role="alert" className="text-xs text-critical">
              Could not delete the analysis.
            </p>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {analyses.isLoading ? (
            <div className="flex items-center justify-center gap-2 px-5 py-10 text-sm text-ink-muted">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading history…
            </div>
          ) : analyses.isError ? (
            <p className="px-5 py-10 text-sm text-critical">Could not load analysis history.</p>
          ) : analyses.data && analyses.data.items.length > 0 ? (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-line text-xs uppercase tracking-wider text-ink-faint">
                    <tr>
                      <th className="px-5 py-3 font-medium">Subject</th>
                      <th className="px-5 py-3 font-medium">Sender</th>
                      <th className="px-5 py-3 font-medium">Classification</th>
                      <th className="px-5 py-3 font-medium">Risk</th>
                      <th className="px-5 py-3 text-right font-medium">Score</th>
                      <th className="px-5 py-3 font-medium">Created</th>
                      <th className="px-5 py-3" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {analyses.data.items.map((analysis) => (
                      <tr key={analysis.id} className="hover:bg-raised/50">
                        <td className="max-w-[280px] truncate px-5 py-3">
                          <Link className="text-ink hover:text-accent" to={`/analyses/${analysis.id}`}>
                            {analysis.subject || '(no subject)'}
                          </Link>
                        </td>
                        <td className="max-w-[220px] truncate px-5 py-3 text-ink-muted">
                          {analysis.sender || '—'}
                        </td>
                        <td className="px-5 py-3">
                          <Badge tone={classificationTone(analysis.classification)}>
                            {analysis.classification ?? analysis.status}
                          </Badge>
                        </td>
                        <td className="px-5 py-3">
                          <Badge tone={riskTone(analysis.risk_level)}>
                            {analysis.risk_level ?? '—'}
                          </Badge>
                        </td>
                        <td className="px-5 py-3 text-right tabular-nums text-ink-muted">
                          {analysis.risk_score ?? '—'}
                        </td>
                        <td className="whitespace-nowrap px-5 py-3 text-xs text-ink-faint">
                          {new Date(analysis.created_at).toLocaleString()}
                        </td>
                        <td className="px-5 py-3 text-right">
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={`Delete analysis ${analysis.subject ?? analysis.id}`}
                            disabled={remove.isPending}
                            onClick={() => void onDelete(analysis.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="flex items-center justify-between border-t border-line px-5 py-3 text-xs text-ink-muted">
                <span>
                  Page {analyses.data.page} of {analyses.data.pages} · {analyses.data.total} total
                </span>
                <div className="flex gap-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    disabled={analyses.data.page <= 1}
                    onClick={() => update({ page: analyses.data.page - 1 })}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="secondary"
                    size="sm"
                    disabled={analyses.data.page >= analyses.data.pages}
                    onClick={() => update({ page: analyses.data.page + 1 })}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </>
          ) : (
            <div className="px-5 py-12 text-center">
              <p className="text-sm text-ink">No stored analyses</p>
              <p className="mt-1 text-xs text-ink-muted">
                Completed analyses will be listed here.
              </p>
              <Link to="/analyze" className="mt-4 inline-block text-sm text-accent hover:underline">
                Analyze an email
              </Link>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
