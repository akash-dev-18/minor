# Phase 8 — Machine Learning (final)

**Goal:** A real, evaluated, versioned three-class email classifier.

## Datasets
Public, documented corpora only. Target: SpamAssassin corpus (ham/spam) plus a
documented phishing corpus (e.g. Nazario, subject to terms). Record source,
license, counts, and cleaning decisions in `docs/model_report.md`. Use a
documented subset for reproducibility; never invent samples or sizes.

## Pipeline
Clean → text preprocessing → TF-IDF (word + character n-grams) → train →
evaluate → select → save full pipeline (vectorizer + model) → serve.

## Models
MultinomialNB, LogisticRegression, LinearSVC (calibrated if probabilities are
reported), RandomForest comparison. Stratified split, no leakage, class-imbalance
awareness, cross-validation.

## Selection
Chosen by phishing recall/precision and per-class F1 — not overall accuracy.
Confidence must come from calibrated probabilities; otherwise confidence is not
reported.

## Deliverables
- `ml/artifacts/<version>/` with pipeline, `metrics.json`, `metadata.json`.
- Active row in `ml_model_versions`.
- `/api/v1/ml/status` and `/api/v1/ml/metrics` backed by real artifacts.
- `docs/model_report.md` with confusion matrix and per-class metrics.

## Done when
- [x] Training is reproducible from documented commands.
- [x] Metrics are real and displayed on the Model page.
- [x] Missing model yields an explicit error, not random predictions.
- [x] Docs and `TASKS.md` updated.

## Delivered

- Dataset: 5,750 records from SpamAssassin (ham/spam) and Nazario (phishing);
  exact dedup + MinHash LSH grouping; group-aware 70/15/15 split. Sources,
  licenses and counts in `docs/model_report.md`.
- Models: calibrated MultinomialNB, LogisticRegression, calibrated LinearSVC,
  RandomForest with word + character TF-IDF. Selected LogisticRegression by
  validation phishing F1/recall; test accuracy 0.9861, phishing F1 0.9918.
- Artifact `1.0.0` contains the full pipeline, metadata and metrics; the backend
  registers it in `ml_model_versions` at startup and serves status/metrics.
- Model page shows held-out metrics, confusion matrix, per-class results,
  calibration, per-source diagnostics and CV comparison.
- Conservative risk weighting: ML is a scored signal only (phishing
  `+20 × confidence`) and never decides the verdict alone, because out-of-
  distribution false positives were observed on modern benign mail.

## Known limitation

Training ham/spam is from 2003–2005 while phishing is from 2023–2025. Metrics
are in-distribution; a licensed modern benign corpus is the next improvement.
