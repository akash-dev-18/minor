import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../lib/api'
import { MAX_UPLOAD_BYTES, uploadEmail, validateEmailFile } from '../lib/upload'

function emailFile(name = 'message.eml', content = 'From: a@example.com') {
  return new File([content], name, { type: 'message/rfc822' })
}

describe('validateEmailFile', () => {
  it('accepts a small .eml file', () => {
    expect(validateEmailFile(emailFile())).toBeNull()
  })

  it('rejects other extensions', () => {
    expect(validateEmailFile(emailFile('message.txt'))).toMatch(/\.eml/)
  })

  it('rejects empty files', () => {
    expect(validateEmailFile(emailFile('message.eml', ''))).toMatch(/empty/)
  })

  it('rejects files over the limit', () => {
    const oversized = new File(['x'], 'big.eml')
    Object.defineProperty(oversized, 'size', { value: MAX_UPLOAD_BYTES + 1 })
    expect(validateEmailFile(oversized)).toMatch(/MB limit/)
  })
})

describe('uploadEmail', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('posts multipart form data and returns the submission', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          analysis_id: '11111111-1111-1111-1111-111111111111',
          status: 'PENDING',
          message: 'queued',
        }),
        { status: 202, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    const result = await uploadEmail(emailFile())
    expect(result.status).toBe('PENDING')

    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/v1/analyses')
    expect(init.method).toBe('POST')
    expect(init.body).toBeInstanceOf(FormData)
  })

  it('raises ApiError with the backend envelope', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ error: { code: 'invalid_file', message: 'Not an email', details: null } }),
          { status: 422, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )

    await expect(uploadEmail(emailFile())).rejects.toMatchObject({
      name: 'ApiError',
      status: 422,
      code: 'invalid_file',
      message: 'Not an email',
    })
  })

  it('wraps network failures', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))
    await expect(uploadEmail(emailFile())).rejects.toBeInstanceOf(ApiError)
  })
})
