import { CheckCircle2, FileText, Loader2, UploadCloud, X } from 'lucide-react'
import { useRef, useState } from 'react'
import type { ChangeEvent, DragEvent } from 'react'
import { useNavigate } from 'react-router-dom'

import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { useConfig, useUploadEmail } from '../hooks/queries'
import { ApiError } from '../lib/api'
import { MAX_UPLOAD_BYTES, validateEmailFile } from '../lib/upload'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function AnalyzePage() {
  const navigate = useNavigate()
  const config = useConfig()
  const upload = useUploadEmail()
  const maxBytes = config.data?.max_upload_bytes ?? MAX_UPLOAD_BYTES
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)

  function choose(next: File | null) {
    setError(null)
    upload.reset()
    if (!next) {
      setFile(null)
      return
    }
    const problem = validateEmailFile(next, maxBytes)
    if (problem) {
      setFile(null)
      setError(problem)
      return
    }
    setFile(next)
  }

  function onInput(event: ChangeEvent<HTMLInputElement>) {
    choose(event.target.files?.[0] ?? null)
    event.target.value = ''
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setDragging(false)
    choose(event.dataTransfer.files?.[0] ?? null)
  }

  async function submit() {
    if (!file) return
    setError(null)
    try {
      const result = await upload.mutateAsync(file)
      navigate(`/analyses/${result.analysis_id}`)
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Upload failed unexpectedly.')
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-ink">Analyze Email</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Submit an .eml file for multi-module security analysis.
        </p>
      </header>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Email submission</CardTitle>
            <CardDescription>
              The file is stored privately and never opened as HTML or executed. Maximum size{' '}
              {formatBytes(maxBytes)}.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div
            role="button"
            tabIndex={0}
            onClick={() => inputRef.current?.click()}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') inputRef.current?.click()
            }}
            onDragOver={(event) => {
              event.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed px-6 py-14 text-center transition-colors ${
              dragging
                ? 'border-accent bg-accent-soft/40'
                : 'border-line-strong hover:border-accent/60 hover:bg-raised/40'
            }`}
          >
            <UploadCloud className="h-7 w-7 text-ink-faint" strokeWidth={1.5} />
            <p className="mt-3 text-sm text-ink">Drop an .eml file here or click to browse</p>
            <p className="mt-1 max-w-md text-xs text-ink-muted">
              Only raw email messages exported with the .eml extension are accepted.
            </p>
            <input
              ref={inputRef}
              type="file"
              accept=".eml,message/rfc822"
              className="hidden"
              onChange={onInput}
            />
          </div>

          {file ? (
            <div className="flex items-center justify-between gap-3 rounded-md border border-line bg-raised px-4 py-3">
              <div className="flex min-w-0 items-center gap-3">
                <FileText className="h-4 w-4 shrink-0 text-accent" />
                <div className="min-w-0">
                  <p className="truncate text-sm text-ink">{file.name}</p>
                  <p className="text-xs text-ink-faint">{formatBytes(file.size)}</p>
                </div>
              </div>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Remove selected file"
                onClick={(event) => {
                  event.stopPropagation()
                  choose(null)
                }}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          ) : null}

          {error ? (
            <p role="alert" className="rounded-md border border-critical/25 bg-critical/10 px-4 py-3 text-sm text-critical">
              {error}
            </p>
          ) : null}

          <div className="flex items-center justify-between gap-3">
            <p className="flex items-center gap-1.5 text-xs text-ink-faint">
              {upload.isPending ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Uploading and queuing analysis…
                </>
              ) : (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Modules run concurrently with per-module timeouts.
                </>
              )}
            </p>
            <Button onClick={submit} disabled={!file || upload.isPending}>
              {upload.isPending ? 'Submitting…' : 'Analyze email'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
