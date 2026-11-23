# API Reference

Base path: `/api/v1` · Interactive docs: `/docs` · OpenAPI: `/openapi.json`

All errors use a consistent envelope:

```json
{ "error": { "code": "not_found", "message": "Analysis not found", "details": null } }
```

## System

### `GET /health`

```json
{
  "status": "ok",
  "version": "0.1.0",
  "database": "ok",
  "timestamp": "2026-11-08T17:56:40.318787Z"
}
```

### `GET /ready`

Returns `200` when all checks pass, `503` otherwise.

```json
{ "ready": true, "checks": { "database": true, "storage": true } }
```

## Modules

### `GET /modules`

```json
[
  {
    "name": "ml_classification",
    "title": "ML Classification",
    "description": "Classifies emails as legitimate, spam or phishing using a trained model.",
    "available": false,
    "reason": "No trained model artifact is available"
  }
]
```

## Analyses

### `GET /analyses`

Query parameters:

| Name | Type | Default | Notes |
|---|---|---|---|
| `page` | int ≥ 1 | 1 | |
| `page_size` | int 1–100 | 20 | |
| `q` | string ≤ 200 | – | Case-insensitive sender/subject search |
| `classification` | enum | – | `LEGITIMATE`, `SPAM`, `PHISHING` |
| `risk_level` | enum | – | `LOW`, `GUARDED`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `sort` | `created_at` \| `risk_score` | `created_at` | |
| `order` | `asc` \| `desc` | `desc` | |

```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "page_size": 20,
  "pages": 1
}
```

### `GET /analyses/stats`

Aggregates over stored analyses. Values always include every enum key.

```json
{
  "total": 12,
  "threats": 4,
  "last_24_hours": 3,
  "average_risk_score": 41.7,
  "by_classification": {"LEGITIMATE": 5, "SPAM": 3, "PHISHING": 4},
  "by_risk_level": {"LOW": 5, "GUARDED": 1, "MEDIUM": 2, "HIGH": 2, "CRITICAL": 2}
}
```

### `GET /analyses/{id}`

Returns the full report: summary, module results, findings, authentication,
recommendations and explanation. Derived fields come from the persisted report:

```json
{
  "classification": "PHISHING",
  "risk_score": 72,
  "risk_level": "HIGH",
  "assessment_confidence": 0.83,
  "explanation": "Risk score 72/100, classified as PHISHING. ...",
  "recommendations": ["..."],
  "positives": ["No dangerous attachments were detected"],
  "unknowns": [{"module": "ml_classification", "status": "UNAVAILABLE", "reason": "..."}],
  "contributions": [
    {
      "category": "impersonation",
      "finding_type": "typosquatting_domain",
      "title": "Lookalike domain",
      "severity": "high",
      "module": "url_analysis",
      "contribution": 43,
      "raw_contribution": 43,
      "evidence": "...",
      "suppressed_duplicates": 0
    }
  ],
  "ml_prediction": null
}
```

`assessment_confidence` is the share of expected modules that completed. It is
reduced when modules fail or are unavailable; those modules are listed in
`unknowns` and must not be read as safe.

### `DELETE /analyses/{id}`

`204` on success, removes dependent rows and the stored file. `404` if unknown.

### `POST /analyses`

`multipart/form-data` with a single `file` field. Accepts `.eml` only, up to
the configured upload limit (see `GET /config`). Returns `202`:

```json
{
  "analysis_id": "…",
  "status": "PENDING",
  "message": "Email submitted for security analysis"
}
```

Poll `GET /analyses/{id}` until `COMPLETED` or `FAILED`. Validation failures
return `413`, `415`, `422` or `400` with the standard error envelope.

## Configuration

### `GET /config`

Safe runtime configuration for the UI. Never includes secrets.

```json
{
  "app_name": "Sentinel",
  "app_env": "development",
  "version": "0.1.0",
  "max_upload_bytes": 10485760,
  "max_attachment_bytes": 5242880,
  "retention_days": 30,
  "module_timeout_seconds": 30.0,
  "ml_available": true,
  "integrations": {
    "url_fetch": true,
    "dns_lookups": true,
    "rdap": false,
    "virustotal": false,
    "safe_browsing": false,
    "abuseipdb": false,
    "clamav": false
  }
}
```

## Machine learning

### `GET /ml/status`

```json
{
  "available": true,
  "model_name": "sentinel-email-classifier",
  "model_version": "1.0.0",
  "algorithm": "LogisticRegression",
  "trained_at": "2026-11-08T18:49:02.770958+00:00",
  "reason": null
}
```

### `GET /ml/metrics`

Returns the active model's real evaluation metrics: `test` (accuracy, macro F1,
per-class, confusion matrix), `cross_validation`, `validation`, `selection`,
`diagnostics.calibration` and `diagnostics.by_source`. `404` with
`model_unavailable` when no model exists and `metrics_unavailable` when metrics
are missing. Never returns placeholder values.
