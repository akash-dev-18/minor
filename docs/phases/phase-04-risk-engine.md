# Phase 4 — Risk Scoring Engine

**Goal:** Convert module findings and the ML signal into one explainable score.

## Scope
- Severity weights: informational 0, low 10, medium 25, high 45, critical 60.
- Documented aggregation with a 100-point cap and diminishing contributions.
- Overlap handling so duplicate underlying causes are not double-counted.
- ML as an independent signal, weighted by confidence.
- Conflict rule: verified malicious evidence outranks a legitimate ML prediction.
- Missing data is `unknown`, never `safe`.
- Output: classification, risk score, risk level, findings, positives,
  unknowns, recommendations, and a human-readable explanation.

## Risk levels
0–19 Low · 20–39 Guarded · 40–59 Medium · 60–79 High · 80–100 Critical.

## Done when
- [x] Unit tests cover caps, overlaps, unknown modules, and ML conflicts.
- [x] Every score contribution is traceable to a finding or the ML signal.
- [x] A missing ML model changes confidence, not correctness.
- [x] Docs and `TASKS.md` updated.
