# Phase 1 — Project Foundation

**Goal:** A running skeleton with real persistence and a buildable frontend shell.

## Scope
- Monorepo layout, git, root files (`.gitignore`, `.env.example`, `README.md`).
- FastAPI app factory with settings, logging, error handling, CORS.
- SQLite via SQLAlchemy 2.0 async; WAL + foreign keys enabled.
- Tables: `analyses`, `analysis_modules`, `security_findings`, `attachments`, `ml_model_versions`.
- Alembic with batch rendering and the initial migration.
- Shared Pydantic enums/schemas used by API and modules.
- `AnalysisRunner` interface + orchestrator skeleton.
- `/health`, `/ready`, `/modules`.
- Vite + React + TS + Tailwind shell with dark theme tokens and navigation.

## Decisions
ADR 0001 (SQLite), 0002 (in-process runner), 0003 (no auth), 0004 (Docker later),
0005 (optional integrations), 0006 (ML last).

## Verification
```bash
cd backend && uv venv && uv pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload      # /docs, /api/v1/health
cd frontend && npm install && npm run build
```

## Done when
- [x] `alembic upgrade head` creates `data/sentinel.db` with all tables/indexes.
- [x] OpenAPI is served and `/api/v1/health` returns DB status.
- [x] `/api/v1/modules` lists the six modules with honest availability.
- [x] Frontend builds and renders the shell with working navigation.
- [x] `TASKS.md` and this document are updated.
