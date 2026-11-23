export type BadgeTone = 'neutral' | 'ok' | 'warn' | 'critical' | 'accent'

export function severityTone(severity: string): BadgeTone {
  switch (severity.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'critical'
    case 'medium':
      return 'warn'
    case 'low':
      return 'accent'
    default:
      return 'neutral'
  }
}

export function riskTone(level: string | null | undefined): BadgeTone {
  switch ((level ?? '').toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'critical'
    case 'MEDIUM':
      return 'warn'
    case 'GUARDED':
      return 'accent'
    case 'LOW':
      return 'ok'
    default:
      return 'neutral'
  }
}
