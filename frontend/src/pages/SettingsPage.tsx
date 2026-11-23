import { Badge } from '../components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { useConfig, useHealth, useModules, useReadiness } from '../hooks/queries'

function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

const INTEGRATION_LABELS: Record<string, string> = {
  url_fetch: 'URL fetching (SSRF-guarded)',
  dns_lookups: 'DNS lookups',
  rdap: 'RDAP domain age',
  virustotal: 'VirusTotal',
  safe_browsing: 'Google Safe Browsing',
  abuseipdb: 'AbuseIPDB',
  clamav: 'ClamAV',
}

export function SettingsPage() {
  const health = useHealth()
  const readiness = useReadiness()
  const modules = useModules()
  const config = useConfig()

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-ink">Settings</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Runtime configuration and integration availability. Secrets are never sent to the
          browser.
        </p>
      </header>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Application</CardTitle>
            <CardDescription>Build and service information.</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <p className="text-xs text-ink-faint">Version</p>
            <p className="mt-1 font-mono text-ink">
              {config.data?.version ?? health.data?.version ?? '—'}
            </p>
          </div>
          <div>
            <p className="text-xs text-ink-faint">Environment</p>
            <p className="mt-1 font-mono text-ink">{config.data?.app_env ?? '—'}</p>
          </div>
          <div>
            <p className="text-xs text-ink-faint">API status</p>
            <p className="mt-1 text-ink">{health.data?.status ?? '—'}</p>
          </div>
          <div>
            <p className="text-xs text-ink-faint">Database</p>
            <p className="mt-1 text-ink">{health.data?.database ?? '—'}</p>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Limits and retention</CardTitle>
              <CardDescription>Enforced by the backend, shown to the client.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-ink-muted">Maximum upload</span>
              <span className="font-mono text-ink">
                {config.data ? formatBytes(config.data.max_upload_bytes) : '—'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-ink-muted">Maximum attachment scan size</span>
              <span className="font-mono text-ink">
                {config.data ? formatBytes(config.data.max_attachment_bytes) : '—'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-ink-muted">Retention</span>
              <span className="font-mono text-ink">
                {config.data ? `${config.data.retention_days} days` : '—'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-ink-muted">Module timeout</span>
              <span className="font-mono text-ink">
                {config.data ? `${config.data.module_timeout_seconds}s` : '—'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-ink-muted">ML model artifact</span>
              <Badge tone={config.data?.ml_available ? 'ok' : 'neutral'}>
                {config.data?.ml_available ? 'available' : 'unavailable'}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div>
              <CardTitle>Integration availability</CardTitle>
              <CardDescription>
                External checks are optional; missing integrations stay unknown.
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {config.data
              ? Object.entries(config.data.integrations).map(([name, enabled]) => (
                  <div key={name} className="flex items-center justify-between text-sm">
                    <span className="text-ink-muted">{INTEGRATION_LABELS[name] ?? name}</span>
                    <Badge tone={enabled ? 'ok' : 'neutral'}>
                      {enabled ? 'enabled' : 'disabled'}
                    </Badge>
                  </div>
                ))
              : null}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Readiness checks</CardTitle>
            <CardDescription>Live dependency checks reported by the backend.</CardDescription>
          </div>
          <Badge tone={readiness.data?.ready ? 'ok' : 'warn'}>
            {readiness.data?.ready ? 'ready' : 'not ready'}
          </Badge>
        </CardHeader>
        <CardContent className="space-y-2">
          {readiness.data
            ? Object.entries(readiness.data.checks).map(([name, ok]) => (
                <div key={name} className="flex items-center justify-between text-sm">
                  <span className="text-ink-muted">{name}</span>
                  <Badge tone={ok ? 'ok' : 'critical'}>{ok ? 'ok' : 'failed'}</Badge>
                </div>
              ))
            : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Detection modules</CardTitle>
            <CardDescription>Availability of each analysis module in this environment.</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {modules.data?.map((module) => (
            <div key={module.name} className="flex items-start justify-between gap-4 text-sm">
              <div>
                <p className="text-ink">{module.title}</p>
                <p className="text-xs text-ink-faint">
                  {module.available ? module.description : (module.reason ?? module.description)}
                </p>
              </div>
              <Badge tone={module.available ? 'ok' : 'neutral'}>
                {module.available ? 'available' : 'unavailable'}
              </Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
