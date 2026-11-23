from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import analyses, health, ml, modules, ready

router = APIRouter()
router.include_router(health.router)
router.include_router(ready.router)
router.include_router(modules.router)
router.include_router(analyses.router)
router.include_router(ml.router)
