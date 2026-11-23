from __future__ import annotations

import json
from pathlib import Path

import joblib
import pytest
from sqlalchemy import select
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from app.core.config import settings
from app.database.session import SessionLocal
from app.models.ml_model import MlModelVersion
from app.modules.ml_classification.classifier import analyze
from app.services.model_registry import sync_ml_model_versions
from app.schemas.enums import AnalysisStatus
from tests.helpers import context, make_email


def build_artifact(root: Path) -> Path:
    artifact = root / "test-version"
    artifact.mkdir(parents=True)
    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer()),
            ("model", LogisticRegression(max_iter=200)),
        ]
    )
    samples = [
        ("hello team please find the report attached", "LEGITIMATE"),
        ("cheap pills buy now limited offer", "SPAM"),
        ("your account is suspended verify your password now", "PHISHING"),
    ] * 4
    pipeline.fit([text for text, _ in samples], [label for _, label in samples])
    joblib.dump(pipeline, artifact / "pipeline.joblib")
    (artifact / "metadata.json").write_text(
        json.dumps(
            {
                "model_name": "test-classifier",
                "model_version": "test-version",
                "algorithm": "LogisticRegression",
                "trained_at": "2026-11-09T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    (artifact / "metrics.json").write_text(
        json.dumps({"accuracy": 1.0, "labels": ["LEGITIMATE", "SPAM", "PHISHING"]}),
        encoding="utf-8",
    )
    return artifact


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()
    artifact_dir = build_artifact(root)
    monkeypatch.setattr(settings, "ml_artifact_dir", str(root))
    return artifact_dir


async def test_inference_uses_saved_pipeline(artifact):
    result = await analyze(
        make_email(subject="Account suspended", body_text="Verify your password immediately"),
        context(),
    )
    assert result.status == AnalysisStatus.COMPLETED
    assert result.data["prediction"] in {"LEGITIMATE", "SPAM", "PHISHING"}
    assert 0 <= result.data["confidence"] <= 1
    assert abs(sum(result.data["probabilities"].values()) - 1) < 0.01
    assert result.data["model_version"] == "test-version"
    assert result.data["algorithm"] == "LogisticRegression"


async def test_corrupt_artifact_fails_instead_of_predicting(artifact):
    (artifact / "pipeline.joblib").write_bytes(b"not-a-model")
    result = await analyze(make_email(body_text="hello"), context())
    assert result.status == AnalysisStatus.FAILED
    assert result.error and "inference failed" in result.error.lower()
    assert result.data == {}


async def test_ml_status_and_metrics_expose_real_artifact(client, artifact):
    status = (await client.get("/api/v1/ml/status")).json()
    assert status["available"] is True
    assert status["model_version"] == "test-version"
    assert status["algorithm"] == "LogisticRegression"

    metrics = await client.get("/api/v1/ml/metrics")
    assert metrics.status_code == 200
    assert metrics.json()["accuracy"] == 1.0


async def test_missing_artifact_reports_404(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "ml_artifact_dir", str(tmp_path / "empty"))
    response = await client.get("/api/v1/ml/metrics")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "model_unavailable"


async def test_active_model_is_registered(artifact):
    await sync_ml_model_versions()
    async with SessionLocal() as session:
        active = (
            await session.execute(
                select(MlModelVersion).where(MlModelVersion.is_active.is_(True))
            )
        ).scalars().all()
    assert [row.model_version for row in active] == ["test-version"]
    assert active[0].dataset_reference is None
