"""Train and evaluate the three-class email classifier.

Compares Multinomial Naive Bayes, Logistic Regression, Linear SVM (calibrated)
and Random Forest on word + character TF-IDF features. Model selection favours
phishing F1/recall, then macro F1. The held-out test split is evaluated once
with the refitted best model, and the complete pipeline is versioned.

Usage:
    python ml/training/train.py
    python ml/training/train.py --version 1.0.0 --cv-folds 3
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

LABELS = ("LEGITIMATE", "SPAM", "PHISHING")
MAX_TEXT_CHARS = 8_000
SEED = 20261108
warnings.filterwarnings("ignore", category=UserWarning)


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def texts(records: list[dict]) -> list[str]:
    return [
        f"{record.get('subject', '')}\n{record.get('body', '')}"[:MAX_TEXT_CHARS]
        for record in records
    ]


def make_features() -> FeatureUnion:
    return FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    max_features=60_000,
                    min_df=2,
                    sublinear_tf=True,
                    strip_accents="unicode",
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    max_features=80_000,
                    min_df=3,
                    sublinear_tf=True,
                ),
            ),
        ]
    )


def candidate_models() -> dict[str, object]:
    return {
        "MultinomialNB": CalibratedClassifierCV(
            MultinomialNB(alpha=0.1), cv=3, method="sigmoid"
        ),
        "LogisticRegression": LogisticRegression(
            C=4.0,
            max_iter=2_000,
            solver="liblinear",
            class_weight="balanced",
        ),
        "LinearSVC": CalibratedClassifierCV(
            LinearSVC(C=0.5, class_weight="balanced", dual="auto", max_iter=5_000),
            cv=3,
            method="sigmoid",
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced_subsample",
            max_features="sqrt",
            n_jobs=-1,
            random_state=SEED,
        ),
    }


def metrics_for(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    accuracy = float(accuracy_score(y_true, y_pred))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=list(LABELS), zero_division=0
    )
    per_class = {
        label: {
            "precision": round(float(precision[index]), 4),
            "recall": round(float(recall[index]), 4),
            "f1": round(float(f1[index]), 4),
            "support": int(support[index]),
        }
        for index, label in enumerate(LABELS)
    }
    macro = precision_recall_fscore_support(
        y_true, y_pred, labels=list(LABELS), average="macro", zero_division=0
    )
    return {
        "accuracy": round(accuracy, 4),
        "macro_precision": round(float(macro[0]), 4),
        "macro_recall": round(float(macro[1]), 4),
        "macro_f1": round(float(macro[2]), 4),
        "phishing_precision": per_class["PHISHING"]["precision"],
        "phishing_recall": per_class["PHISHING"]["recall"],
        "phishing_f1": per_class["PHISHING"]["f1"],
        "per_class": per_class,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=list(LABELS)).tolist(),
        "labels": list(LABELS),
    }


def cross_validate_models(
    records: list[dict], labels: np.ndarray, folds: int
) -> dict[str, dict]:
    splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED)
    scores: dict[str, list[dict]] = {name: [] for name in candidate_models()}
    data = texts(records)

    for fold, (train_index, valid_index) in enumerate(splitter.split(data, labels), start=1):
        train_texts = [data[index] for index in train_index]
        valid_texts = [data[index] for index in valid_index]
        y_train = labels[train_index]
        y_valid = labels[valid_index]

        features = make_features()
        started = time.monotonic()
        matrix_train = features.fit_transform(train_texts)
        matrix_valid = features.transform(valid_texts)
        print(f"fold {fold}: features {matrix_train.shape} in {time.monotonic() - started:.1f}s")

        for name, model in candidate_models().items():
            started = time.monotonic()
            fitted = clone(model).fit(matrix_train, y_train)
            fold_metrics = metrics_for(y_valid, fitted.predict(matrix_valid))
            scores[name].append(fold_metrics)
            print(f"fold {fold}: {name} f1={fold_metrics['macro_f1']:.3f} in {time.monotonic() - started:.1f}s")

    summary: dict[str, dict] = {}
    for name, folds_metrics in scores.items():
        summary[name] = {
            key: round(float(np.mean([fold[key] for fold in folds_metrics])), 4)
            for key in (
                "accuracy",
                "macro_precision",
                "macro_recall",
                "macro_f1",
                "phishing_precision",
                "phishing_recall",
                "phishing_f1",
            )
        }
        summary[name]["folds"] = folds_metrics
    return summary


def fit_evaluate(
    model, train_texts: list[str], y_train: np.ndarray, eval_texts: list[str], y_eval: np.ndarray
) -> tuple[Pipeline, dict]:
    pipeline = Pipeline([("features", make_features()), ("model", clone(model))])
    started = time.monotonic()
    pipeline.fit(train_texts, y_train)
    metrics = metrics_for(y_eval, pipeline.predict(eval_texts))
    print(f"fit+evaluate {type(model).__name__} in {time.monotonic() - started:.1f}s")
    return pipeline, metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--version", default=None)
    parser.add_argument("--cv-folds", type=int, default=3)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    root: Path = args.root
    processed = root / "datasets" / "processed"
    train = load_jsonl(processed / "train.jsonl")
    validation = load_jsonl(processed / "validation.jsonl")
    test = load_jsonl(processed / "test.jsonl")
    card = json.loads((processed / "dataset_card.json").read_text(encoding="utf-8"))

    train_texts = texts(train)
    validation_texts = texts(validation)
    test_texts = texts(test)
    y_train = np.array([record["label"] for record in train])
    y_validation = np.array([record["label"] for record in validation])
    y_test = np.array([record["label"] for record in test])

    print(f"train={len(train)} validation={len(validation)} test={len(test)}")

    cv_results = cross_validate_models(train, y_train, args.cv_folds)

    validation_results: dict[str, dict] = {}
    fitted_on_train: dict[str, Pipeline] = {}
    for name, model in candidate_models().items():
        pipeline, result = fit_evaluate(
            model, train_texts, y_train, validation_texts, y_validation
        )
        validation_results[name] = result
        fitted_on_train[name] = pipeline

    best_name = max(
        validation_results,
        key=lambda name: (
            validation_results[name]["phishing_f1"],
            validation_results[name]["phishing_recall"],
            validation_results[name]["macro_f1"],
        ),
    )
    print(f"selected {best_name} on validation")

    combined = train + validation
    combined_texts = texts(combined)
    y_combined = np.concatenate([y_train, y_validation])
    final_pipeline, test_metrics = fit_evaluate(
        candidate_models()[best_name], combined_texts, y_combined, test_texts, y_test
    )

    version = args.version or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    trained_at = datetime.now(timezone.utc).isoformat()
    dataset_hash = hashlib.sha256(
        b"".join(
            (processed / name).read_bytes()
            for name in ("train.jsonl", "validation.jsonl", "test.jsonl")
        )
    ).hexdigest()

    artifact_dir = root / "artifacts" / version
    artifact_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_pipeline, artifact_dir / "pipeline.joblib")

    metadata = {
        "model_name": "sentinel-email-classifier",
        "model_version": version,
        "algorithm": best_name,
        "trained_at": trained_at,
        "seed": args.seed,
        "dataset_hash": dataset_hash,
        "train_counts": {label: int(np.sum(y_combined == label)) for label in LABELS},
        "test_counts": {label: int(np.sum(y_test == label)) for label in LABELS},
        "features": {
            "text": "subject + body, truncated",
            "max_text_chars": MAX_TEXT_CHARS,
            "word_ngrams": [1, 2],
            "char_ngrams": [3, 5],
        },
        "dataset_card": card,
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
    }
    metrics = {
        "model_version": version,
        "algorithm": best_name,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "total_records": card["total_records"],
            "label_counts": card["label_counts"],
            "source_counts": card["source_counts"],
            "sources": card["sources"],
            "dataset_hash": dataset_hash,
            "split": card["split_counts"],
        },
        "cross_validation": {
            "folds": args.cv_folds,
            "results": cv_results,
        },
        "validation": validation_results,
        "selection": {
            "metric_order": ["phishing_f1", "phishing_recall", "macro_f1"],
            "selected": best_name,
        },
        "test": test_metrics,
    }
    (artifact_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (artifact_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print(json.dumps({"artifact": str(artifact_dir), "test": test_metrics}, indent=2))


if __name__ == "__main__":
    main()
