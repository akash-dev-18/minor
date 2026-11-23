from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select, update

from app.core.config import settings
from app.database.session import SessionLocal
from app.models.ml_model import MlModelVersion

logger = logging.getLogger(__name__)


def _active_artifact_dir():
    root = settings.ml_artifact_path
    if settings.ml_active_version:
        candidate = root / settings.ml_active_version
        return candidate if candidate.is_dir() else None
    candidates = sorted((path for path in root.glob("*") if path.is_dir()), reverse=True)
    return candidates[0] if candidates else None


def _read_json(path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return {}


async def sync_ml_model_versions() -> None:
    artifact = _active_artifact_dir()
    if artifact is None or not (artifact / "pipeline.joblib").is_file():
        return

    metadata = _read_json(artifact / "metadata.json")
    metrics = _read_json(artifact / "metrics.json")
    model_name = metadata.get("model_name")
    model_version = metadata.get("model_version") or artifact.name
    algorithm = metadata.get("algorithm")
    if not model_name or not algorithm:
        logger.warning("Model artifact %s is missing required metadata", artifact)
        return

    async with SessionLocal() as session:
        await session.execute(update(MlModelVersion).values(is_active=False))
        existing = (
            await session.execute(
                select(MlModelVersion).where(
                    MlModelVersion.model_name == model_name,
                    MlModelVersion.model_version == model_version,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            existing = MlModelVersion(
                model_name=model_name,
                model_version=model_version,
                algorithm=algorithm,
            )
            session.add(existing)
        existing.algorithm = algorithm
        existing.dataset_reference = (
            f"sha256:{metadata['dataset_hash']}" if metadata.get("dataset_hash") else None
        )
        existing.metrics = metrics or None
        existing.is_active = True
        await session.commit()
    logger.info("Activated ML model %s %s", model_name, model_version)
