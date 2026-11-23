# Architecture

## Overview

```
Browser (React SPA)
        │  /api/v1 (JSON)
        ▼
    FastAPI app
        │
        ├── API layer            app/api/v1/endpoints
        ├── Orchestrator         app/services/analysis_orchestrator.py
        │       │
        │       ├── email_parser ─────────────► EmailObject
        │       ├── url_analysis ─────────────┐
        │       ├── domain_reputation ────────┤
        │       ├── header_analysis ──────────┤──► ModuleResult[]
        │       ├── content_analysis ─────────┤
        │       ├── attachment_analysis ──────┤
        │       └── ml_classification ────────┘
        │                        │
        │                        ▼
        │                 Risk Scoring Engine ──► report
        │                        │
        └────────────────────────▼
                            SQLite (WAL)
                    analyses / modules / findings /
                    attachments / ml_model_versions
```

## Layers

| Layer | Location | Responsibility |
|---|---|---|
| API | `app/api/v1` | HTTP validation, pagination, error mapping. No business logic. |
| Orchestration | `app/services` | Runs modules, applies timeouts, persists results, builds reports. |
| Modules | `app/modules/<name>` | Independent analysis. Own schemas, tests and status. |
| Risk | `app/services/risk_scoring.py` | Aggregates findings + ML signal into an explainable score. |
| Persistence | `app/models`, `app/database` | SQLAlchemy 2.0 models, async sessions, migrations. |
| Frontend | `frontend/src` | Presentation and server-state management only. |

## Module contract

Every analysis module is a pure async callable:

```python
async def analyze(email: EmailObject, context: AnalysisContext) -> ModuleResult
```

Rules:

- No module imports another module's internals.
- Network access only through shared HTTP helpers with timeouts, size caps and
  SSRF protection.
- External service failures return `UNAVAILABLE` with a reason. They never raise
  into the orchestrator.
- Every result carries `module`, `status`, `duration_ms`, `findings`, `data`,
  `error`.

## Status semantics

| Status | Meaning |
|---|---|
| `PENDING` | Queued, not started. |
| `RUNNING` | Currently executing. |
| `COMPLETED` | Finished and produced a result. |
| `FAILED` | Raised an unexpected error; captured in `error_message`. |
| `SKIPPED` | Deliberately not run (configuration or input). |
| `UNAVAILABLE` | Prerequisite missing (API key, binary, model). |

`UNAVAILABLE` and `FAILED` are **not** safe. The risk engine treats them as
unknown and reflects that in the explanation and confidence.

## Risk scoring

`app/services/risk_scoring.py` is deterministic and independent of the ML
classifier.

- Severity weights: informational 0, low 10, medium 25, high 45, critical 60.
- Each finding is multiplied by `0.5 + 0.5 × confidence` when a confidence is
  present; absent confidence is treated as full weight.
- Findings that describe the same underlying cause share a category (for example
  all impersonation findings). The highest-severity occurrence represents the
  category and the rest are recorded as suppressed duplicates.
- Categories are sorted by severity and receive diminishing multipliers
  (`1.0, 0.6, 0.4, 0.3, 0.2, 0.15, 0.1`) so repeated findings cannot exhaust the
  scale.
- The ML prediction is a separate, deliberately conservative signal: PHISHING
  `+20 × confidence`, SPAM `+8 × confidence`, LEGITIMATE `−10 × confidence`. A
  missing model adds nothing and lowers `assessment_confidence`.
- ML never decides the classification on its own. Its contribution is added to
  the score like any other signal, because the current model is trained on
  older, source-specific corpora and can over-flag modern benign mail.
- Any verified malicious indicator (VirusTotal, Safe Browsing, ClamAV or a
  malicious attachment hash) floors the score at 80 and forces a PHISHING
  classification. A legitimate ML prediction cannot override this.
- Final score is clamped to 0–100. Classification: PHISHING for verified
  threats or score ≥ 40; SPAM for score ≥ 20; otherwise LEGITIMATE. The ML label
  influences the verdict only through its score contribution.
- Every contribution is persisted on its finding (`risk_contribution`) and
  returned in the report as a category with evidence and suppressed count.

## Trust boundaries

- Uploaded email content is untrusted: never executed, never rendered as HTML
  in the UI, never shell-interpolated.
- Header authentication claims (`Authentication-Results`) are untrusted until
  independently verifiable; the default is `not_verified`.
- URLs are untrusted: fetching is restricted to HTTP(S), private/loopback
  destinations are blocked, redirects are re-validated, responses are size-capped.
- Attachments are untrusted: identified by magic bytes, never opened by the host.
- External API responses are untrusted: schema-checked, bounded, and recorded as
  claims with a timestamp.

## Data model

```
analyses 1───n analysis_modules
         1───n security_findings
         1───n attachments
ml_model_versions (independent)
```

- UUID primary keys stored as `TEXT(36)`.
- JSON columns use SQLAlchemy's portable `JSON` type.
- SQLite runs with WAL, foreign keys enabled, `busy_timeout=5000`.
- Deletes cascade from `analyses`; stored files are removed first.

## Execution model

- The API accepts an upload, writes a `PENDING` row, stores the file, and hands
  the analysis ID to the in-process runner (ADR 0002).
- The runner executes one analysis per task; modules run concurrently with a
  per-module timeout.
- Results are persisted in a single transaction at the end of the run.
- Stale `RUNNING` rows are reconciled to `FAILED` on startup.
- Module failures and timeouts are persisted as `FAILED`; they never abort the
  analysis. The report still completes with the available evidence and lists the
  missing checks as unknown.
- Docker Compose runs the backend (migrations on start, non-root user) behind an
  nginx-served frontend. SQLite and uploads live on the `sentinel_data` volume;
  `./ml/artifacts` is mounted read-only so the image stays immutable. Both
  services expose health checks.
- On startup the backend records the active artifact in `ml_model_versions`
  (metadata, dataset hash, full metrics) and marks older versions inactive.

## Frontend

- TanStack Query for all server state; no client-side fabricated data.
- Routes: Dashboard, Analyze, Results, History, Model, Settings.
- Design tokens live in `src/index.css` under `@theme`; components are shadcn-style
  primitives in `src/components/ui`.

## ML lifecycle

- Offline scripts: `ml/preprocessing/build_dataset.py` (download, clean,
  deduplicate, group-aware split), `ml/training/train.py` (vectorize, compare
  four models, select, save), `ml/evaluation/evaluate.py` (per-source
  diagnostics, calibration error, metrics update).
- One artifact directory per version containing the full pipeline, metadata and
  metrics. Inference loads the newest directory or `ML_ACTIVE_VERSION`, lazily
  and off the event loop.
- Missing or corrupt artifacts produce `UNAVAILABLE`/`FAILED`; never random or
  default predictions.
- See [`model_report.md`](model_report.md) for datasets, metrics and known
  limitations, including source/temporal shift.
