from __future__ import annotations

import logging
import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.database.session import check_database
from app.schemas.analysis import ReadinessResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["system"])


@router.get("/ready", response_model=ReadinessResponse)
async def ready() -> JSONResponse:
    checks: dict[str, bool] = {}

    try:
        checks["database"] = await check_database()
    except Exception:  # noqa: BLE001
        checks["database"] = False

    try:
        settings.upload_path.mkdir(parents=True, exist_ok=True)
        checks["storage"] = os.access(settings.upload_path, os.W_OK)
    except Exception:  # noqa: BLE001
        checks["storage"] = False

    is_ready = all(checks.values())
    payload = ReadinessResponse(ready=is_ready, checks=checks)
    return JSONResponse(status_code=200 if is_ready else 503, content=payload.model_dump())
