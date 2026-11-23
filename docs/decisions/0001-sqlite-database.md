# ADR 0001 — Use SQLite instead of PostgreSQL

**Status:** Accepted
**Date:** Phase 1

## Context
The SRD specifies PostgreSQL. The project owner requested SQLite as the database.

## Decision
Use SQLite as the default database, accessed through SQLAlchemy 2.0 async with
`aiosqlite`. The connection string remains `DATABASE_URL`-driven so PostgreSQL can
be restored without code changes.

## Consequences
- Zero external database service required; simpler local setup and CI.
- JSON columns use SQLAlchemy's portable `JSON` type; a migration can move
  them to JSONB if PostgreSQL is adopted.
- Alembic runs with `render_as_batch=True`.
- Single-writer model; use WAL journal mode, foreign keys ON, short transactions.
- History search uses `lower(col) LIKE` rather than PostgreSQL `ILIKE`.
- UUID primary keys stored as TEXT.
