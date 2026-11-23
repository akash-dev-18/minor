import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Badge } from '../components/ui/badge'
import { riskTone, severityTone } from '../lib/tones'

describe('Badge', () => {
  it('renders its content', () => {
    render(<Badge tone="ok">ready</Badge>)
    expect(screen.getByText('ready')).toBeInTheDocument()
  })

  it('maps severities to tones', () => {
    expect(severityTone('critical')).toBe('critical')
    expect(severityTone('medium')).toBe('warn')
    expect(severityTone('low')).toBe('accent')
    expect(severityTone('informational')).toBe('neutral')
  })

  it('maps risk levels to tones', () => {
    expect(riskTone('CRITICAL')).toBe('critical')
    expect(riskTone('GUARDED')).toBe('accent')
    expect(riskTone('LOW')).toBe('ok')
    expect(riskTone(null)).toBe('neutral')
  })
})
