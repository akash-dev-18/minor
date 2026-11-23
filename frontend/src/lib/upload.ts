import { ApiError } from './api'
import type { AnalysisSubmission } from '../types/api'

export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024

export function validateEmailFile(file: File, maxBytes = MAX_UPLOAD_BYTES): string | null {
  const name = file.name.toLowerCase()
  if (!name.endsWith('.eml')) {
    return 'Only .eml files are accepted.'
  }
  if (file.size === 0) {
    return 'The selected file is empty.'
  }
  if (file.size > maxBytes) {
    return `File exceeds the ${Math.round(maxBytes / (1024 * 1024))} MB limit.`
  }
  return null
}

export async function uploadEmail(file: File): Promise<AnalysisSubmission> {
  const form = new FormData()
  form.append('file', file)

  let response: Response
  try {
    response = await fetch('/api/v1/analyses', {
      method: 'POST',
      headers: { Accept: 'application/json' },
      body: form,
    })
  } catch {
    throw new ApiError(0, 'network_error', 'Could not reach the analysis API.')
  }

  const text = await response.text()
  const payload = text ? (JSON.parse(text) as unknown) : null

  if (!response.ok) {
    const body = payload as { error?: { code?: string; message?: string; details?: Record<string, unknown> | null } } | null
    throw new ApiError(
      response.status,
      body?.error?.code ?? 'upload_failed',
      body?.error?.message ?? `Upload failed with status ${response.status}`,
      body?.error?.details ?? null,
    )
  }

  return payload as AnalysisSubmission
}
