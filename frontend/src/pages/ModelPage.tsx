import { BrainCircuit } from 'lucide-react'

import { Badge } from '../components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { useMlMetrics, useMlStatus } from '../hooks/queries'
import type { Classification, MlEvaluation } from '../types/api'

const LABELS: Classification[] = ['LEGITIMATE', 'SPAM', 'PHISHING']

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-line bg-raised/60 px-4 py-3">
      <p className="text-[10px] uppercase tracking-wider text-ink-faint">{label}</p>
      <p className="mt-1 text-lg font-semibold tabular-nums text-ink">{value}</p>
    </div>
  )
}

function percent(value: number | undefined): string {
  return value == null ? '—' : `${(value * 100).toFixed(1)}%`
}

function EvaluationSummary({ evaluation, title }: { evaluation: MlEvaluation; title: string }) {
  return (
    <div className="space-y-3">
      <p className="text-xs uppercase tracking-wider text-ink-faint">{title}</p>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Metric label="Accuracy" value={percent(evaluation.accuracy)} />
        <Metric label="Phishing precision" value={percent(evaluation.phishing_precision ?? evaluation.per_class?.PHISHING.precision)} />
        <Metric label="Phishing recall" value={percent(evaluation.phishing_recall ?? evaluation.per_class?.PHISHING.recall)} />
        <Metric label="Phishing F1" value={percent(evaluation.phishing_f1 ?? evaluation.per_class?.PHISHING.f1)} />
      </div>
    </div>
  )
}

export function ModelPage() {
  const status = useMlStatus()
  const metrics = useMlMetrics()

  const data = metrics.data
  const test = data?.test

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-ink">Model Information</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Active classifier, training metadata and real evaluation metrics.
        </p>
      </header>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Classifier status</CardTitle>
            <CardDescription>Only real, evaluated models are reported here.</CardDescription>
          </div>
          <Badge tone={status.data?.available ? 'ok' : 'neutral'}>
            {status.data?.available ? 'active' : 'unavailable'}
          </Badge>
        </CardHeader>
        <CardContent>
          {status.isLoading ? (
            <p className="text-sm text-ink-muted">Checking model status…</p>
          ) : status.isError ? (
            <p className="text-sm text-critical">Could not read model status.</p>
          ) : status.data?.available ? (
            <dl className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-xs text-ink-faint">Model</dt>
                <dd className="mt-1 text-ink">{status.data.model_name ?? '—'}</dd>
              </div>
              <div>
                <dt className="text-xs text-ink-faint">Version</dt>
                <dd className="mt-1 font-mono text-ink">{status.data.model_version ?? '—'}</dd>
              </div>
              <div>
                <dt className="text-xs text-ink-faint">Algorithm</dt>
                <dd className="mt-1 text-ink">{status.data.algorithm ?? '—'}</dd>
              </div>
              <div>
                <dt className="text-xs text-ink-faint">Trained</dt>
                <dd className="mt-1 text-ink">
                  {status.data.trained_at ? new Date(status.data.trained_at).toLocaleString() : '—'}
                </dd>
              </div>
            </dl>
          ) : (
            <div className="py-8 text-center">
              <BrainCircuit className="mx-auto h-6 w-6 text-ink-faint" />
              <p className="mt-3 text-sm text-ink">No trained model available</p>
              <p className="mx-auto mt-1 max-w-md text-xs text-ink-muted">
                {status.data?.reason ??
                  'Train and version a model to enable ML classification. No placeholder metrics are shown.'}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {status.data?.available && test ? (
        <>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Held-out test performance</CardTitle>
                <CardDescription>
                  Evaluated once after selecting the model on validation data.
                </CardDescription>
              </div>
              {data?.selection ? (
                <Badge tone="accent">selected {data.selection.selected}</Badge>
              ) : null}
            </CardHeader>
            <CardContent className="space-y-5">
              <EvaluationSummary evaluation={test} title="Overall" />

              {test.per_class ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-line text-xs uppercase tracking-wider text-ink-faint">
                      <tr>
                        <th className="py-2 pr-4 font-medium">Class</th>
                        <th className="py-2 pr-4 font-medium">Precision</th>
                        <th className="py-2 pr-4 font-medium">Recall</th>
                        <th className="py-2 pr-4 font-medium">F1</th>
                        <th className="py-2 text-right font-medium">Support</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {LABELS.map((label) => (
                        <tr key={label}>
                          <td className="py-2 pr-4 text-ink">{label}</td>
                          <td className="py-2 pr-4 tabular-nums text-ink-muted">{percent(test.per_class?.[label].precision)}</td>
                          <td className="py-2 pr-4 tabular-nums text-ink-muted">{percent(test.per_class?.[label].recall)}</td>
                          <td className="py-2 pr-4 tabular-nums text-ink-muted">{percent(test.per_class?.[label].f1)}</td>
                          <td className="py-2 text-right tabular-nums text-ink-muted">{test.per_class?.[label].support ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}

              {test.confusion_matrix && test.labels ? (
                <div>
                  <p className="text-xs uppercase tracking-wider text-ink-faint">Confusion matrix</p>
                  <div className="mt-2 inline-block overflow-hidden rounded border border-line">
                    <table className="text-center text-xs">
                      <thead className="bg-raised text-ink-faint">
                        <tr>
                          <th className="px-3 py-2" />
                          {test.labels.map((label) => (
                            <th key={label} className="px-3 py-2 font-medium">
                              {label}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {test.confusion_matrix.map((row, rowIndex) => (
                          <tr key={test.labels?.[rowIndex]} className="border-t border-line">
                            <th className="bg-raised px-3 py-2 text-left font-medium text-ink-faint">
                              {test.labels?.[rowIndex]}
                            </th>
                            {row.map((value, columnIndex) => (
                              <td key={columnIndex} className="px-3 py-2 tabular-nums text-ink-muted">
                                {value}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <p className="mt-2 text-[11px] text-ink-faint">Rows: actual · columns: predicted</p>
                </div>
              ) : null}
            </CardContent>
          </Card>

          {data?.diagnostics?.calibration ? (
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Calibration and data sources</CardTitle>
                  <CardDescription>Confidence quality and per-source behaviour.</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                  <Metric
                    label="Expected calibration error"
                    value={data.diagnostics.calibration.expected_calibration_error.toFixed(4)}
                  />
                  <Metric
                    label="Mean confidence"
                    value={percent(data.diagnostics.calibration.mean_confidence)}
                  />
                  <Metric
                    label="Test accuracy"
                    value={percent(data.diagnostics.calibration.accuracy)}
                  />
                </div>

                {data.diagnostics.by_source ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead className="border-b border-line text-xs uppercase tracking-wider text-ink-faint">
                        <tr>
                          <th className="py-2 pr-4 font-medium">Source</th>
                          <th className="py-2 pr-4 font-medium">Records</th>
                          <th className="py-2 pr-4 font-medium">Accuracy</th>
                          <th className="py-2 font-medium">Phishing recall</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-line">
                        {Object.entries(data.diagnostics.by_source).map(([source, entry]) => (
                          <tr key={source}>
                            <td className="py-2 pr-4 font-mono text-xs text-ink-muted">{source}</td>
                            <td className="py-2 pr-4 tabular-nums text-ink-muted">{entry.records}</td>
                            <td className="py-2 pr-4 tabular-nums text-ink-muted">{percent(entry.accuracy)}</td>
                            <td className="py-2 tabular-nums text-ink-muted">
                              {entry.phishing_recall != null ? percent(Number(entry.phishing_recall)) : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}

                {data.diagnostics.notes?.length ? (
                  <ul className="space-y-1 text-[11px] leading-relaxed text-ink-faint">
                    {data.diagnostics.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                ) : null}
              </CardContent>
            </Card>
          ) : null}

          {data?.cross_validation ? (
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Model comparison</CardTitle>
                  <CardDescription>
                    {data.cross_validation.folds}-fold cross-validation on the training split.
                  </CardDescription>
                </div>
              </CardHeader>
              <CardContent className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-line text-xs uppercase tracking-wider text-ink-faint">
                    <tr>
                      <th className="py-2 pr-4 font-medium">Model</th>
                      <th className="py-2 pr-4 font-medium">Accuracy</th>
                      <th className="py-2 pr-4 font-medium">Macro F1</th>
                      <th className="py-2 pr-4 font-medium">Phishing precision</th>
                      <th className="py-2 font-medium">Phishing recall</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {Object.entries(data.cross_validation.results).map(([name, result]) => (
                      <tr key={name}>
                        <td className="py-2 pr-4 text-ink">{name}</td>
                        <td className="py-2 pr-4 tabular-nums text-ink-muted">{percent(result.accuracy)}</td>
                        <td className="py-2 pr-4 tabular-nums text-ink-muted">{percent(result.macro_f1)}</td>
                        <td className="py-2 pr-4 tabular-nums text-ink-muted">{percent(result.phishing_precision)}</td>
                        <td className="py-2 tabular-nums text-ink-muted">{percent(result.phishing_recall)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          ) : null}
        </>
      ) : null}
    </div>
  )
}
