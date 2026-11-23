# ADR 0002 — In-process async analysis runner instead of Celery/Redis

**Status:** Accepted
**Date:** Phase 1

## Context
The SRD specifies Celery with Redis. The deployment target is a single-node,
single-user local application with SQLite.

## Decision
Run analyses in-process: a background `asyncio` task executes the orchestrator,
which runs independent modules concurrently with `asyncio.gather` and per-module
timeouts. The runner is hidden behind an `AnalysisRunner` interface.

## Consequences
- No Redis broker or worker container required.
- Analyses are lost on process restart; the runner reconciles stale `RUNNING`
  rows on startup and marks them `FAILED`.
- Long-running or CPU-heavy work must not block the event loop; blocking calls
  run via `asyncio.to_thread`.
- Celery can be introduced later by implementing the same interface.
