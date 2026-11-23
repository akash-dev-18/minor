# Sentinel — Email Spam & Phishing Detection

Local-first email security analysis. Upload an `.eml` file and Sentinel runs
independent detection modules plus an ML classifier, produces an explainable
risk score, and stores the result in a React dashboard.

This README covers running the backend and frontend **directly on your machine**
(no Docker or Docker Compose required).

## Stack

- **Backend:** Python 3.13, FastAPI, SQLAlchemy 2.0 (async), Alembic, SQLite
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, TanStack Query
- **ML:** scikit-learn, word + character TF-IDF, calibrated Logistic Regression
- **Optional:** VirusTotal, Google Safe Browsing, AbuseIPDB, RDAP, ClamAV

## Repository layout

```
backend/   FastAPI app, detection modules, risk engine, migrations, tests
frontend/  React dashboard (Vite dev server proxies /api to the backend)
ml/        dataset builder, training, evaluation, artifact directory
docs/      SRD, architecture, API reference, phase notes, model report
data/      local SQLite DB and uploaded files (created at runtime, not committed)
```

## How it works

```
React (Vite :5173)
   │  /api/*  (dev proxy)
   ▼
FastAPI (:8000)
   ├─ upload validation → file stored under data/uploads/
   ├─ analysis row created, background runner starts
   ├─ 6 checks run concurrently (per-module timeout):
   │    URL · sender domain · headers · content · attachments · ML
   ├─ risk engine aggregates findings, ML signal and unknown checks
   ├─ report + findings + module results saved to SQLite
   └─ dashboard polls GET /api/v1/analyses/{id} for progress and results
```

- Each module is independent. A timeout/failure marks that module `FAILED` or
  `UNAVAILABLE`; the analysis still completes with partial evidence.
- `UNAVAILABLE` is never treated as safe. It is listed under `unknowns` and
  lowers the assessment confidence.
- The ML prediction is one weighted signal. Verified malicious evidence and
  rule-based findings remain authoritative.
- Optional integrations stay `UNAVAILABLE` until keys/services are configured.
  See `.env.example` and `docs/api.md`.

## Prerequisites

- Python **3.13+**
- [uv](https://docs.astral.sh/uv/) (recommended) or `python -m venv` + `pip`
- Node.js **20+** and npm
- Optional: ClamAV daemon for malware scanning

## Setup

### 1. Environment

```bash
cd /path/to/minor
cp .env.example .env
```

`.env` is git-ignored. Defaults work for local development. Add API keys later
if you want the optional threat-intelligence checks:

| Variable | Where to get it |
|---|---|
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Cloud Console → enable Safe Browsing API → API key |
| `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/account/api |

Set `RDAP_ENABLED=true` for domain registration lookups (no key required).

### 2. Backend

```bash
cd backend

# Create the virtualenv once
uv venv --python 3.13
uv pip install --python .venv/bin/python -r requirements.txt

# Create/update the SQLite schema
.venv/bin/alembic upgrade head

# Run the API with auto-reload
.venv/bin/uvicorn app.main:app --reload --port 8000
```

- API: http://localhost:8000/api/v1/health
- Swagger: http://localhost:8000/docs

Without `uv`:

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 3. Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. Vite proxies `/api` to `http://127.0.0.1:8000`, so
no frontend API URL configuration is needed.

### 4. Reload environment changes

Settings are read when the backend process starts. `.env` changes are **not**
picked up by `uvicorn --reload` (that only watches Python files). Stop and
restart the backend after editing `.env`:

```bash
# Ctrl+C in the backend terminal, then
.venv/bin/uvicorn app.main:app --reload --port 8000
```

## Using the app

1. Open http://localhost:5173.
2. Go to **Analyze** and upload a `.eml` file.
3. The results page polls until the analysis completes.
4. Review classification, risk score, module status, findings, unknowns and
   per-finding contributions.
5. History supports search, filters, sorting, pagination and delete.
6. **Model** shows the active model version and real evaluation metrics.

## Machine learning (optional after a fresh clone)

The trained artifact under `ml/artifacts/` is intentionally not committed (large
binary). Without it, everything else runs and the ML module reports
`UNAVAILABLE`.

To train the model locally:

```bash
# from the repository root, using the backend virtualenv
backend/.venv/bin/python ml/preprocessing/build_dataset.py
backend/.venv/bin/python ml/training/train.py --version 1.0.0
backend/.venv/bin/python ml/evaluation/evaluate.py --version 1.0.0 --update
```

Then restart the backend. It automatically uses the newest artifact (or set
`ML_ACTIVE_VERSION=1.0.0` in `.env`). Training downloads public research
corpora; datasets are git-ignored. Sources, licenses, metrics and limitations
are documented in [`docs/model_report.md`](docs/model_report.md).

## Tests

```bash
cd backend
.venv/bin/python -m pytest -q

cd ../frontend
npm test
npm run lint
npm run build
```

Backend tests are hermetic: outbound URL fetching, DNS lookups, RDAP and ClamAV
are disabled in the test environment.

## Troubleshooting

- **Port 8000 already in use:** stop the other process or run
  `uvicorn ... --port 8001`, then update the Vite proxy target in
  `frontend/vite.config.ts`.
- **`ModuleNotFoundError`:** commands must use `backend/.venv/bin/python` (or
  activate the virtualenv) from the `backend/` directory.
- **Analysis stays `RUNNING`:** URL fetching and DNS can take up to the module
  timeout. For offline use, set `URL_FETCH_ENABLED=false` and
  `DNS_LOOKUPS_ENABLED=false` in `.env`, then restart the backend.
- **ML reports `UNAVAILABLE`:** train an artifact as described above and
  restart; verify `ml/artifacts/<version>/pipeline.joblib` exists.
- **Reset local data:** stop the backend, delete `data/sentinel.db` (and
  optionally `data/uploads/`), then run `.venv/bin/alembic upgrade head` again.
- **CORS errors:** use the Vite URL (5173) or add your origin to
  `CORS_ORIGINS`. The dev proxy avoids CORS entirely.

## Security notes

- There is no authentication. Do not expose the API or dev server to untrusted
  networks.
- Uploaded emails are never executed or rendered as HTML.
- URL fetching blocks private/loopback targets unless explicitly allowed.
- Missing external checks are reported as unknown, never as safe.
- Never commit `.env`; `.gitignore` excludes it along with databases, uploads,
  datasets and model artifacts.

## Documentation

- [Architecture](docs/architecture.md)
- [API reference](docs/api.md)
- [Model report](docs/model_report.md)
- [Roadmap](docs/ROADMAP.md) · [Tasks](docs/TASKS.md)
- [SRD](docs/srd.md)
