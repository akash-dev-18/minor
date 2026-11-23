from __future__ import annotations

import asyncio

from app.modules.base import AnalysisContext, unavailable
from app.schemas.analysis import EmailObject, ModuleResult
from app.schemas.enums import ModuleName

MODULE = ModuleName.ML_CLASSIFICATION


def _artifact_dir():
    from app.core.config import settings

    root = settings.ml_artifact_path
    if settings.ml_active_version:
        candidate = root / settings.ml_active_version
        return candidate if candidate.is_dir() else None
    candidates = sorted((path for path in root.glob("*") if path.is_dir()), reverse=True)
    return candidates[0] if candidates else None


def _infer_sync(email: EmailObject, artifact_dir) -> ModuleResult:
    import json

    import joblib

    pipeline = joblib.load(artifact_dir / "pipeline.joblib")
    metadata = {}
    metadata_file = artifact_dir / "metadata.json"
    if metadata_file.is_file():
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))

    body = email.body_text
    if not body and email.body_html:
        from app.utils.html import strip_html

        body = strip_html(email.body_html)
    text = f"{email.subject}\n{body}".strip()[:8000]

    probabilities = pipeline.predict_proba([text])[0]
    classes = [str(label) for label in pipeline.classes_]
    ranking = sorted(
        zip(classes, (float(value) for value in probabilities)),
        key=lambda item: item[1],
        reverse=True,
    )
    label, confidence = ranking[0]

    return ModuleResult(
        module=MODULE,
        status="COMPLETED",
        findings=[],
        data={
            "prediction": label,
            "confidence": round(confidence, 6),
            "probabilities": {name: round(value, 6) for name, value in ranking},
            "model_version": metadata.get("model_version"),
            "algorithm": metadata.get("algorithm"),
        },
    )


async def analyze(email: EmailObject, context: AnalysisContext) -> ModuleResult:
    from app.modules.registry import ml_artifact_available

    if not ml_artifact_available():
        return unavailable(MODULE, "No trained model artifact is available")

    artifact_dir = _artifact_dir()
    if artifact_dir is None:
        return unavailable(MODULE, "No trained model artifact is available")

    try:
        return await asyncio.to_thread(_infer_sync, email, artifact_dir)
    except ImportError as exc:
        return unavailable(MODULE, f"ML runtime dependencies are unavailable: {exc}")
    except Exception as exc:  # noqa: BLE001
        return ModuleResult(
            module=MODULE,
            status="FAILED",
            error=f"Model inference failed: {type(exc).__name__}",
        )
