# ADR 0006 — Implement machine learning last

**Status:** Accepted
**Date:** Phase 1

## Context
The SRD places ML at Phase 4. The project owner requires all other
functionality to be completed first.

## Decision
Move ML to the final phase. The orchestrator and API call the
`ml_classification` module from the beginning, but it reports `UNAVAILABLE`
until a trained, versioned artifact exists.

## Consequences
- Risk scoring must handle a missing ML signal without treating it as safe.
- No placeholder predictions, fabricated probabilities, or invented metrics.
- The Model page shows an explicit "no model available" state until Phase 8.
