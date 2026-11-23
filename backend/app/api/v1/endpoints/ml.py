from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter

from app.core.config import settings
from app.core.errors import APIError
from app.modules.registry import ml_artifact_available

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ml", tags=["ml"])


def _active_artifact_dir():
    root = settings.ml_artifact_path
    if settings.ml_active_version:
        candidate = root / settings.ml_active_version
        return candidate if candidate.is_dir() else None
    candidates = sorted((p for p in root.glob("*") if p.is_dir()), reverse=True)
    return candidates[0] if candidates else None


@router.get("/status")
async def ml_status() -> dict[str, Any]:
    available = ml_artifact_available()
    artifact = _active_artifact_dir() if available else None
    metadata: dict[str, Any] = {}
    if artifact and (artifact / "metadata.json").is_file():
        try:
            metadata = json.loads((artifact / "metadata.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read model metadata: %s", exc)

    return {
        "available": available,
        "model_name": metadata.get("model_name"),
        "model_version": metadata.get("model_version"),
        "algorithm": metadata.get("algorithm"),
        "trained_at": metadata.get("trained_at"),
        "reason": None if available else "No trained model artifact is available",
    }


@router.get("/metrics")
async def ml_metrics() -> dict[str, Any]:
    artifact = _active_artifact_dir()
    if artifact is None:
        raise APIError(
            404,
            "model_unavailable",
            "No trained model artifact is available. Train a model in the ML phase.",
        )

    metrics_file = artifact / "metrics.json"
    if not metrics_file.is_file():
        raise APIError(
            404, "metrics_unavailable", "The active model has no evaluation metrics recorded"
        )

    try:
        return json.loads(metrics_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read model metrics: %s", exc)
        raise APIError(500, "metrics_unreadable", "Model metrics could not be read") from exc
