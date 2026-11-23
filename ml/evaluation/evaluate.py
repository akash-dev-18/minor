"""Re-evaluate a saved model artifact on the held-out test split.

Produces honest diagnostics that the training script does not fabricate:
per-source recall (which exposes cross-corpus behaviour), and expected
calibration error for the predicted confidence. Use ``--update`` to merge the
diagnostics into the artifact's metrics.json.

Usage:
    python ml/evaluation/evaluate.py --version 1.0.0 --update
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

LABELS = ("LEGITIMATE", "SPAM", "PHISHING")
MAX_TEXT_CHARS = 8_000


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def texts(records: list[dict]) -> list[str]:
    return [
        f"{record.get('subject', '')}\n{record.get('body', '')}"[:MAX_TEXT_CHARS]
        for record in records
    ]


def expected_calibration_error(confidences: np.ndarray, correct: np.ndarray, bins: int = 10) -> float:
    total = len(confidences)
    if total == 0:
        return 0.0
    error = 0.0
    edges = np.linspace(0.0, 1.0, bins + 1)
    for low, high in zip(edges[:-1], edges[1:]):
        mask = (confidences > low) & (confidences <= high)
        count = int(mask.sum())
        if count:
            accuracy = float(correct[mask].mean())
            average_confidence = float(confidences[mask].mean())
            error += (count / total) * abs(accuracy - average_confidence)
    return round(error, 4)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--version", required=True)
    parser.add_argument("--split", default="test", choices=["validation", "test"])
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()

    artifact_dir = args.root / "artifacts" / args.version
    pipeline = joblib.load(artifact_dir / "pipeline.joblib")
    records = load_jsonl(args.root / "datasets" / "processed" / f"{args.split}.jsonl")
    data = texts(records)
    y_true = np.array([record["label"] for record in records])

    probabilities = pipeline.predict_proba(data)
    classes = [str(label) for label in pipeline.classes_]
    predictions = np.array([classes[index] for index in probabilities.argmax(axis=1)])
    confidences = probabilities.max(axis=1)
    correct = predictions == y_true

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, predictions, labels=list(LABELS), zero_division=0
    )
    overall = {
        "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
        "per_class": {
            label: {
                "precision": round(float(precision[index]), 4),
                "recall": round(float(recall[index]), 4),
                "f1": round(float(f1[index]), 4),
                "support": int(support[index]),
            }
            for index, label in enumerate(LABELS)
        },
    }

    by_source: dict[str, dict] = {}
    for source in sorted({record["source"] for record in records}):
        indices = [index for index, record in enumerate(records) if record["source"] == source]
        source_true = y_true[indices]
        source_pred = predictions[indices]
        labels_present = [label for label in LABELS if label in set(source_true)]
        entry: dict = {
            "records": len(indices),
            "labels": {label: int(np.sum(source_true == label)) for label in LABELS},
            "accuracy": round(float(accuracy_score(source_true, source_pred)), 4),
            "predicted": {
                label: int(np.sum(source_pred == label)) for label in LABELS
            },
        }
        for label in labels_present:
            mask = source_true == label
            entry[f"{label.lower()}_recall"] = round(
                float(np.mean(source_pred[mask] == label)), 4
            )
        by_source[source] = entry

    diagnostics = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "split": args.split,
        "overall": overall,
        "by_source": by_source,
        "calibration": {
            "expected_calibration_error": expected_calibration_error(confidences, correct),
            "mean_confidence": round(float(confidences.mean()), 4),
            "accuracy": overall["accuracy"],
            "bins": 10,
        },
        "notes": [
            "Legitimate and spam messages come from the 2003-2005 SpamAssassin corpus, "
            "while phishing messages come from the 2023-2025 Nazario corpus. Cross-source "
            "and temporal generalization is therefore weaker than these in-distribution "
            "numbers suggest.",
            "Near-duplicate messages are grouped before splitting so they cannot cross "
            "train/test boundaries.",
        ],
    }

    print(json.dumps(diagnostics, indent=2))

    if args.update:
        metrics_path = artifact_dir / "metrics.json"
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        metrics["diagnostics"] = diagnostics
        metrics_path.write_text(
            json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"updated {metrics_path}")


if __name__ == "__main__":
    main()
