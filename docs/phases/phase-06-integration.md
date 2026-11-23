# Phase 6 — Integration

**Goal:** A complete working workflow from upload to persisted, explainable report.

## Scope
- Orchestrator runs the parser, five modules, ML, and risk engine.
- Independent modules run concurrently with per-module timeouts.
- Failures and unavailability produce partial reports, never whole-request failure.
- Persist modules, findings, attachments, and final assessment transactionally.
- Progress reporting so the UI can poll real module status.
- Stale `RUNNING` analyses reconciled on startup.
- End-to-end verification of happy path and failure paths.

## Done when
- [x] Upload → analysis → results → history works end to end.
- [x] A module timeout yields a partial but coherent report.
- [x] Deleted analyses remove stored files and dependent rows.
- [x] Dashboard metrics match database contents.
- [x] Docs and `TASKS.md` updated.
