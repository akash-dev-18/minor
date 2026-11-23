import type { ApiErrorBody } from '../types/api'

const API_PREFIX = '/api/v1'

export class ApiError extends Error {
  readonly code: string
  readonly status: number
  readonly details: Record<string, unknown> | null

  constructor(status: number, code: string, message: string, details: Record<string, unknown> | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_PREFIX}${path}`, {
    headers: { Accept: 'application/json', ...(init?.body ? {} : {}) },
    ...init,
  })

  if (response.status === 204) {
    return undefined as T
  }

  const text = await response.text()
  const payload = text ? (JSON.parse(text) as unknown) : null

  if (!response.ok) {
    const errorBody = payload as ApiErrorBody | null
    throw new ApiError(
      response.status,
      errorBody?.error?.code ?? 'request_failed',
      errorBody?.error?.message ?? `Request failed with status ${response.status}`,
      errorBody?.error?.details ?? null,
    )
  }

  return payload as T
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body: BodyInit, headers: Record<string, string> = {}) =>
    request<T>(path, { method: 'POST', body, headers }),
  delete: (path: string) => request<void>(path, { method: 'DELETE' }),
}
