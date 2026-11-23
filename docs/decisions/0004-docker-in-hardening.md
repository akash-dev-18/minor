# ADR 0004 — Defer Docker Compose to the hardening phase

**Status:** Accepted
**Date:** Phase 1

## Context
Containerization is required by the SRD but slows iteration during development.

## Decision
Develop and test natively. Add Dockerfiles, Docker Compose, health checks and
documented startup in Phase 7.

## Consequences
- Phase 7 must verify a clean containerized start with a persistent SQLite
  volume.
- Nothing in the code may assume host-only paths; storage locations are
  settings-driven.
