# Sentinel — Roadmap

Source of truth for scope is [`srd.md`](./srd.md). This roadmap defines the
implementation order and the exit criteria for each phase. Task-level status
lives in [`TASKS.md`](./TASKS.md).

## Principles

- The application must run at the end of every phase.
- No fabricated data, metrics, or threat intelligence at any point.
- Modules are independently testable and never import each other's internals.
- Every phase updates docs, `TASKS.md`, and `progress/log.md`.
- External services are optional adapters that degrade honestly to `UNAVAILABLE`.

## Stack deviations from the SRD

See `docs/decisions/`. Summary:

| Area | SRD | Actual | ADR |
|---|---|---|---|
| Database | PostgreSQL | SQLite (Postgres-compatible schema) | 0001 |
| Background jobs | Celery + Redis | In-process async runner | 0002 |
| Authentication | (none specified) | None — single-tenant local tool | 0003 |
| Deployment timing | Docker Compose | Docker Compose in hardening phase | 0004 |
| External services | VirusTotal, ClamAV, etc. | Optional adapters, `UNAVAILABLE` without config | 0005 |
| ML order | Phase 4 | **Last phase**, after all functionality | 0006 |

## Phases

### Phase 1 — Project Foundation
Monorepo, FastAPI app, settings, SQLite + SQLAlchemy 2.0 + Alembic, shared
schemas, React/Vite/Tailwind shell, health endpoints, docs skeleton.
**Exit:** API serves OpenAPI, migrations create the DB, frontend builds.

### Phase 2 — Email Processing
`.eml` upload with validation, safe storage, MIME parser, normalized
`EmailObject`, URL/attachment extraction, malformed-email handling.
**Exit:** multipart, nested, and malformed fixtures parse; unit tests pass.

### Phase 3 — Detection Modules
URL, domain reputation, header/auth, content, attachment analysis. Independent
schemas, tests, statuses, timeouts, graceful failure.
**Exit:** each module passes standalone tests and returns structured findings.

### Phase 4 — Risk Scoring Engine
Finding aggregation, severity weights, overlap handling, ML as an independent
signal, explainable breakdown, recommendations, final classification.
**Exit:** scoring tests cover caps, overlaps, unknown data, and conflict rules.

### Phase 5 — Frontend
Dashboard, Analyze, Results, History, Model, Settings on real APIs.
**Exit:** every control works; empty/loading/error states exist; responsive.

### Phase 6 — Integration
Orchestrator wiring, concurrency, per-module timeouts, persistence, progress,
partial reports, failure handling, end-to-end workflows.
**Exit:** upload → analysis → report → history works end to end.

### Phase 7 — Testing & Hardening
Security tests, full test suite, Docker/Compose, README, clean-install check.
**Exit:** all tests pass, deployment works, no dead features.

### Phase 8 — Machine Learning (final)
Datasets, preprocessing, training of 4 models, evaluation, model selection,
artifact versioning, inference service, model report.
**Exit:** real trained model serves predictions; metrics page shows real values.

> Before Phase 8 (historical), `ml_classification` returned `UNAVAILABLE` with an
> explicit reason. It has never substituted random or fake predictions.

## Definition of done

The SRD's acceptance criteria in §16 remain the final gate.
