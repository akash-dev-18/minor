# Phase 7 — Testing and Hardening

**Goal:** Prove the system is safe, tested, and reproducible.

## Scope
- Security tests: malformed MIME, oversized uploads, path traversal, SSRF
  attempts, malicious redirects, archive bombs, invalid MIME types, unexpected
  external API responses.
- Full backend suite and frontend Vitest/RTL suite.
- Dockerfiles for backend and frontend; Docker Compose with a persistent SQLite
  volume, health checks, service dependencies, and restart policies.
- README with prerequisites, setup, env vars, migrations, tests, model training,
  and access URLs.
- Clean-install verification.

## Done when
- [x] `pytest` and `npm test` pass.
- [x] `docker compose up --build` starts the full stack.
- [x] A fresh clone can be brought up using only documented commands.
- [x] No secrets in the repository.
- [x] Docs and `TASKS.md` updated.
