# Sentinel — Task Tracker

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked · `[−]` dropped

Last updated: Phase 8 complete — all phases delivered.

---

## Phase 1 — Project Foundation

- [x] Initialize git repository and monorepo layout
- [x] Documentation skeleton (roadmap, tasks, ADRs, phase docs)
- [x] Backend project bootstrap (`requirements.txt`, package layout)
- [x] Settings via `pydantic-settings` + `.env.example`
- [x] SQLAlchemy 2.0 async engine/session (SQLite + WAL + FK enforcement)
- [x] ORM models: `analyses`, `analysis_modules`, `security_findings`, `attachments`, `ml_model_versions`
- [x] Alembic configuration (batch mode) + initial migration
- [x] Shared Pydantic schemas (enums, module result, finding, analysis)
- [x] FastAPI app factory, CORS, error model, logging
- [x] Endpoints: `/health`, `/ready`, `/modules`, `/analyses` (list/get/delete), `/ml/*`
- [x] `AnalysisRunner` + orchestrator interface skeleton
- [x] Frontend scaffold (Vite + React + TS + Tailwind + shadcn/ui base)
- [x] Frontend shell: layout, sidebar, routing, dark theme tokens
- [x] Verify: migrations apply, OpenAPI served, frontend builds

## Phase 2 — Email Processing

- [x] Upload validation (extension, content sniff, size limit, server-side name)
- [x] Safe file storage outside web root
- [x] MIME parser: sender, recipients, subject, text/html, headers
- [x] Attachment extraction with metadata
- [x] URL extraction from text and HTML
- [x] Malformed/multipart/nested email handling
- [x] `POST /analyses` upload endpoint (persist + enqueue)
- [x] Unit tests with `.eml` fixtures

## Phase 3 — Detection Modules

- [x] URL analysis (IP URLs, shorteners, encoding, typosquat, redirects, SSRF guard)
- [x] Domain reputation (DNS, RDAP, disposable, SPF records, lookalikes)
- [x] Header analysis (SPF/DKIM/DMARC interpretation, routing, mismatches)
- [x] Content analysis (urgency, credentials, OTP, payment, hidden HTML)
- [x] Attachment analysis (magic bytes, mismatch, hashes, limits, archives)
- [x] Threat-intelligence adapter layer (VirusTotal, Safe Browsing, AbuseIPDB)
- [x] Per-module unit tests

## Phase 4 — Risk Scoring Engine

- [x] Severity weights + aggregation algorithm
- [x] Finding deduplication/overlap handling
- [x] ML signal integration (independent; `UNAVAILABLE` tolerant)
- [x] Conflict rules (verified malicious beats legitimate ML)
- [x] Explanation generation and recommendations
- [x] Risk engine unit tests

## Phase 5 — Frontend

- [x] Dashboard with real metrics
- [x] Analyze page (drag/drop, validation, progress)
- [x] Results page (assessment, modules, findings, email info, auth, explanations)
- [x] History (search, filters, sort, pagination, delete)
- [x] Model page (real metrics or honest unavailability)
- [x] Settings page (server-side config only, no secrets)
- [x] Empty/loading/error states, keyboard nav, responsive

## Phase 6 — Integration

- [x] Orchestrator concurrency and per-module timeouts
- [x] Persistence of modules/findings/attachments
- [x] Partial reports and failure handling
- [x] Progress polling
- [x] End-to-end workflow verification

## Phase 7 — Testing & Hardening

- [x] Security tests (SSRF, traversal, oversize, malformed MIME, redirects)
- [x] Full backend + frontend test pass
- [x] Dockerfiles + docker-compose with SQLite volume
- [x] README, `.env.example`, model report placeholder
- [x] Clean-install verification

## Phase 8 — Machine Learning

- [x] Dataset acquisition and licensing documentation
- [x] Preprocessing pipeline
- [x] Train MultinomialNB, LogisticRegression, LinearSVC, RandomForest
- [x] Evaluation (accuracy, precision, recall, F1, confusion, per-class, CV)
- [x] Model selection by phishing recall/precision
- [x] Artifact + metadata versioning, `ml_model_versions` row
- [x] Inference service + model status/metrics endpoints
- [x] Model page shows real metrics; `docs/model_report.md` complete

Phase 8 additions: conservative ML weighting in the risk engine (standalone ML
never decides), startup registration of the active model version, Docker
artifact bind mount, and documented out-of-distribution limitations.
