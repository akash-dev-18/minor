# ADR 0003 — No authentication layer

**Status:** Accepted
**Date:** Phase 1

## Context
The SRD defines no authentication or user model. Sentinel is specified as a
single-tenant analysis tool.

## Decision
Do not implement authentication in the initial scope. CORS is restricted to
configured origins. Settings endpoints never expose secrets.

## Consequences
- The app must not be exposed to untrusted networks without a reverse proxy or
  auth layer; documented in the README.
- All analyses are visible to any client that can reach the API.
