# Phase 5 — Frontend

**Goal:** A professional SOC-style interface backed only by real API data.

## Design
Dark near-black surfaces, restrained electric-blue accent, semantic severity
colors, Inter/Geist, Lucide icons, minimal shadows, consistent radii. No
decorative gradients, glassmorphism, fake terminals, or placeholder charts.

## Pages
1. **Dashboard** — totals, classification/risk distribution, recent activity,
   module status, quick analyze action.
2. **Analyze** — drag-and-drop, validation, submission, module progress.
3. **Results** — assessment, per-module panels, findings with evidence and
   recommendations, email metadata, SPF/DKIM/DMARC, expandable technical detail.
4. **History** — search, filters, sort, pagination, open, delete.
5. **Model** — real metrics or an explicit unavailable state.
6. **Settings** — limits, retention, integration availability, app info; no secrets.

## Rules
- TanStack Query for server state; no mock data in production paths.
- Every control performs a real action.
- Loading, empty, and error states are designed, not accidental.
- Responsive + keyboard navigable + accessible contrast.

## Done when
- [x] All pages render from live endpoints.
- [x] Filters and search hit the backend.
- [x] No dead buttons, no fabricated metrics.
- [x] Docs and `TASKS.md` updated.
