# Phase 2 — Email Processing

**Goal:** Turn an uploaded `.eml` into a validated, normalized `EmailObject`.

## Scope
- Upload endpoint with extension check, content sniffing, and size limits.
- Server-generated storage names; files stored outside the web root.
- MIME parsing: sender, recipients, subject, plain text, HTML, headers.
- Attachment extraction with filename, declared MIME, size, payload (bounded).
- URL extraction from plain text and HTML attributes.
- Safe handling of malformed, nested, and multipart messages.
- Persistence of the analysis record at submission time.

## Module contract
`parse_email(raw_bytes) -> EmailObject` — pure, no database or network access.

## Verification
- Unit tests with fixtures: simple, multipart/alternative, nested, attachment,
  encoded headers, broken MIME, oversized input.
- `POST /api/v1/analyses` stores the file and returns `PENDING`.

## Done when
- [x] All fixture emails parse without exceptions.
- [x] Malformed emails produce a controlled error or partial result, never a crash.
- [x] Extracted URLs include HTML `href` values.
- [x] Upload validation rejects wrong types and oversized files.
- [x] Tests pass; docs and `TASKS.md` updated.
