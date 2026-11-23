# ADR 0005 — External services are optional adapters

**Status:** Accepted
**Date:** Phase 1

## Context
VirusTotal, Google Safe Browsing, AbuseIPDB, RDAP and ClamAV require credentials
or binaries that are not available in this environment.

## Decision
Implement each integration behind an adapter interface. When unconfigured or
unreachable, the adapter returns an explicit `UNAVAILABLE` status with a reason.
Core local analysis (parsing, header interpretation, content heuristics, URL
structural analysis, attachment identification, risk scoring) works with no
credentials.

## Consequences
- Unavailable results are never treated as safe by the risk engine.
- ClamAV scans report `UNAVAILABLE` unless the binary and socket are configured.
- Workspace scanning stays offline unless explicitly enabled in settings.
