# Progress Log

Chronological record of implementation sessions. Newest entries at the bottom.

## 2026-11-08 — Phase 1: Project Foundation

**Completed**

- Initialized monorepo and git repository; root files (`README`, `.gitignore`,
  `.env.example`, `LICENSE`).
- Documentation structure: roadmap, task tracker, ADRs 0001–0006, phase docs,
  architecture, API reference, model report placeholder.
- Backend bootstrap with pinned dependencies and a Python 3.13 virtualenv.
- Settings via `pydantic-settings`; SQLite path resolution; CORS configuration.
- SQLAlchemy 2.0 async engine with WAL, foreign keys and busy timeout.
- Models: `analyses`, `analysis_modules`, `security_findings`, `attachments`,
  `ml_model_versions`, with cascade deletes and indexes.
- Alembic configured in batch mode; initial migration generated and applied.
- Shared Pydantic schemas and enums for modules, findings, email object and API.
- FastAPI app factory, structured error envelope, exception handlers.
- Endpoints: `/health`, `/ready`, `/modules`, `/analyses` (list/get/delete),
  `/ml/status`, `/ml/metrics`.
- In-process `AnalysisRunner` interface (used from Phase 2).
- Frontend scaffold: Vite + React 19 + TypeScript + Tailwind v4, dark design
  tokens, app shell, six routed pages backed by real API calls.

**Verification**

- `alembic upgrade head` created all tables.
- Backend: 9 tests passing; live smoke check confirmed health, modules, docs,
  readiness.
- Frontend: `npm run build`, `npm run lint` clean; 3 Vitest tests passing.

**Decisions**

- ADR 0001 SQLite · ADR 0002 in-process jobs · ADR 0003 no auth ·
  ADR 0004 Docker later · ADR 0005 optional integrations · ADR 0006 ML last.

**Notes**

- JSON columns use SQLAlchemy's portable `JSON` type; JSONB remains a migration
  option if PostgreSQL is adopted.
- `POST /analyses` is intentionally absent until Phase 2.
- ML endpoints are honest: no model, no metrics.

**Next**

- Phase 2: upload validation, safe storage, MIME parser, `EmailObject`, fixtures.

## 2026-11-08 — Phase 2: Email Processing

**Completed**

- `parse_email()` using the stdlib MIME parser with `policy.default`; handles
  multipart/alternative, attachments, encoded headers, unknown charsets and
  truncated MIME without raising.
- Normalization into `EmailObject`: sender/name, Reply-To, Return-Path,
  recipients, subject, text/HTML bodies, headers, URLs, attachments, defects.
- URL extraction from text and HTML attributes (`href`, `src`, `action`,
  `formaction`), deduplicated with trailing punctuation trimmed.
- Attachment metadata: filename sanitization, declared MIME, size, SHA-256,
  bounded payload retention and oversize marking.
- Upload validation: extension, size, NUL-byte heuristic, libmagic detection,
  blocked binary/archive types, header-line requirement.
- Safe storage with UUID filenames, `0600` mode, atomic replace, and
  traversal-safe deletion.
- `POST /api/v1/analyses` stores the file, creates a `PENDING` row and submits
  to the in-process runner; `202` response matches the SRD schema.
- Orchestrator parses, persists parser results and attachment metadata, and
  marks the analysis `COMPLETED` or `FAILED`.
- Startup reconciliation marks interrupted `PENDING`/`RUNNING` analyses failed.

**Verification**

- 24 backend tests passing (parsing, upload, validation, lifecycle, deletion).
- Malformed and binary inputs do not crash the pipeline.

**Notes**

- Parser results stored in the database contain metadata only, not body content.
- Analyses currently complete without classification/risk: detection modules and
  the risk engine are not built yet. The report explanation states this.
- Phase 3 will run the five modules; Phase 4 will fill classification and score.

**Next**

- Phase 3: URL, domain, header, content and attachment modules with tests.

## 2026-11-08 — Phase 3: Detection Modules

**Completed**

- **URL analysis:** IP-literal hosts, shorteners, typosquatting, brand-subdomain
  impersonation, punycode, suspicious TLDs, over-long/encoded URLs, embedded
  credentials, non-HTTPS links, redirect chains with per-hop SSRF validation,
  VirusTotal / Safe Browsing / AbuseIPDB adapters.
- **Domain reputation:** disposable domains, lookalike brands, suspicious
  patterns, DNS existence/MX, SPF and DMARC record presence, RDAP age checks,
  Reply-To and Return-Path mismatch.
- **Header analysis:** SPF/DKIM/DMARC interpreted strictly as untrusted claims,
  missing/partial results, multiple From, display-name brand impersonation,
  Message-ID domain mismatch, Received-chain analysis, parse defects.
- **Content analysis:** urgency, credential/OTP/payment/suspension/financial
  rules, hidden HTML, password forms, anchor-text mismatch, empty content.
- **Attachment analysis:** dangerous/macro/archive extensions, double
  extensions, magic-byte mismatch, oversize handling, SHA-256, ClamAV adapter,
  VirusTotal hash lookups.
- Shared SSRF-safe HTTP and DNS utilities; brand data moved to a common module.
- Orchestrator now runs all modules concurrently with per-module timeouts,
  isolates failures, persists module results, findings and attachment scan
  status.

**Verification**

- 52 backend tests passing (module units, isolation, upload + phishing flow).
- Network-dependent checks disabled in tests via configuration flags.

**Notes**

- ClamAV and threat-intelligence services report `UNAVAILABLE` without
  configuration; nothing is treated as safe because a check did not run.
- SPF/DKIM/DMARC are not independently verified yet; they are reported as
  claims with `authentication_verified=false`.

**Next**

- Phase 4: risk scoring, deduplication, explanation and final classification.

## 2026-11-08 — Phase 4: Risk Scoring Engine

**Completed**

- Deterministic `risk_scoring.assess()`: severity weights, confidence scaling,
  category-based deduplication with suppression counts, diminishing returns,
  0–100 clamp.
- ML treated as an independent signal weighted by confidence; missing model
  lowers `assessment_confidence` instead of affecting correctness.
- Verified malicious evidence (VirusTotal, Safe Browsing, ClamAV, malicious hash)
  floors the score at 80 and forces PHISHING; a legitimate ML prediction cannot
  override it.
- Classification, risk level, positives, unknowns, contributions, recommendations
  and explanation persisted into `analyses.report` and exposed by the detail API.
- Per-finding `risk_contribution` persisted on `security_findings`.

**Verification**

- 62 backend tests passing, including caps, duplicate suppression, unknown
  modules, contribution traceability and the ML conflict rule.
- Phishing upload flow now returns PHISHING with score ≥ 40 and a populated
  explanation.

**Next**

- Phase 5: wire the dashboard, analysis form, history and results pages to the
  real API.

## 2026-11-08 — Phase 5: Frontend

**Completed**

- Analyze: drag-and-drop/click upload, client validation mirroring server rules,
  server-reported size limit, error envelope surfacing, redirect to live results.
- Results: automatic polling while PENDING/RUNNING, score/level/classification,
  assessment confidence, ML prediction or honest unavailable state, grouped score
  contributions, positives, unknowns, per-module status and duration, auth claims,
  findings with evidence/recommendations, recommended actions, explanation.
- History: backend search, classification/risk filters, sorting, pagination and
  delete with confirmation.
- Dashboard: real totals, phishing count, 24-hour activity, average score,
  classification/risk distributions, recent activity, module and health status.
- Settings: server-reported limits, retention, module timeout, ML artifact state
  and integration availability; no secrets.
- Added `GET /config` and `GET /analyses/stats` endpoints; upload limit is now
  read from the server instead of being hardcoded.

**Verification**

- `npm run build`, `npm run lint` and 10 frontend tests pass.
- 63 backend tests pass.
- Smoke-tested a real upload + poll + report + stats over HTTP against a fresh
  SQLite database.

**Next**

- Phase 6: cross-module integration review and end-to-end flow hardening.

## 2026-11-08 — Phase 6: Integration

**Completed**

- Verified upload → parse → concurrent modules → risk engine → persisted report →
  results/history/stats end to end.
- Added integration tests for per-module timeout producing a coherent partial
  report, delete removing stored files and dependent rows, and dashboard stats
  matching database contents.
- Fixed a real integration bug found by the Docker smoke test: an unresolvable
  hostname was classified as a blocked SSRF destination. It is now a medium
  `url_host_unresolved` finding; only private/reserved destinations are blocked.
- Test fixture simplified to use resolvable example domains so the clean message
  scores as LEGITIMATE.

**Verification**

- 94 backend tests passing (unit, security, integration).

**Next**

- Phase 7: hardening, Docker packaging, documentation.

## 2026-11-08 — Phase 7: Testing and Hardening

**Completed**

- Security suite: SSRF targets (loopback, private, link-local, reserved, IPv6,
  non-HTTP schemes, disallowed ports, over-long URLs, DNS rebinding to private
  addresses, redirect-to-private, redirect limits), upload traversal, disguised
  PDF, null bytes, invalid extension, empty and oversized uploads, malformed MIME.
- Dockerfiles for backend (non-root, migrations on start, libmagic, health check)
  and frontend (multi-stage build, nginx SPA + `/api` proxy), Compose with named
  volumes and health-gated startup.
- README rewritten: real setup commands, Docker usage, configuration table,
  tests, security notes, ML status.
- Teardown verified via `docker compose up --build` and an upload through the
  nginx proxy.

**Verification**

- 94 backend tests and 10 frontend tests pass; build and lint clean.
- Backend and frontend containers healthy; end-to-end upload works through port
  8080.
- No secrets are committed; `.env` is ignored.

**Next**

- Phase 8: train, evaluate and deploy the ML classifier; replace the
  `UNAVAILABLE` state with real predictions and metrics.

## 2026-11-09 — Phase 8: Machine Learning

**Completed**

- Dataset builder: SpamAssassin public corpus (ham/spam) and Nazario phishing
  corpus (2023–2025); source parsing, exact dedup, MinHash LSH grouping and
  group-aware stratified 70/15/15 split. 5,949 raw → 5,750 records (2,722
  legitimate, 1,808 spam, 1,220 phishing), 199 duplicates removed.
- Training: word + character TF-IDF, calibrated MultinomialNB,
  LogisticRegression, calibrated LinearSVC and RandomForest; shared-vectorization
  CV, selection by validation phishing F1/recall. Selected LogisticRegression.
- Held-out test: accuracy 0.9861, macro F1 0.9865, phishing precision 0.9945,
  recall 0.9891, F1 0.9918; ECE 0.0523. Per-source diagnostics recorded.
- Artifact `1.0.0` (full pipeline, metadata, metrics); backend registers the
  active version in `ml_model_versions` at startup and serves real
  `/ml/status` and `/ml/metrics`.
- Model page renders held-out metrics, per-class table, confusion matrix,
  calibration, per-source diagnostics and CV comparison; honest 404 state.
- Risk engine ML weighting made conservative (`+20/+8/−10 × confidence`) and ML
  no longer decides the verdict. Modern benign fixtures that the model
  over-flagged exposed the out-of-distribution weakness; docs now state it.
- Docker Compose bind-mounts `./ml/artifacts` read-only instead of a named ML
  volume, so the trained artifact is used by the container.
- Docs: full `model_report.md`, dataset README, phase 8, architecture, API,
  README, TASKS, roadmap.

**Verification**

- 99 backend tests pass (including artifact, corrupt-artifact, missing-model and
  model-registration tests); 10 frontend tests pass; build and lint clean.
- Compose stack healthy; `/ml/status` reports `1.0.0`; `/ml/metrics` returns real
  metrics; uploads: benign fixtures `LEGITIMATE` (15/19), phishing fixture
  `PHISHING` (100).
- `ml_model_versions` contains one active row with dataset hash and metrics.

**Decisions**

- ML is a scored signal only. In-distribution metrics are strong, but training
  ham/spam predates the phishing corpus; a licensed modern benign corpus is the
  next improvement.
