from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Protocol

logger = logging.getLogger(__name__)


class AnalysisRunner(Protocol):
    def submit(self, analysis_id: str) -> None: ...

    async def shutdown(self) -> None: ...


class InProcessRunner:
    """Runs analyses as asyncio tasks inside the API process.

    Swappable with a Celery-backed runner later (ADR 0002).
    """

    def __init__(self, handler: Callable[[str], Awaitable[None]]) -> None:
        self._handler = handler
        self._tasks: set[asyncio.Task[None]] = set()

    def submit(self, analysis_id: str) -> None:
        task = asyncio.create_task(self._run(analysis_id), name=f"analysis:{analysis_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run(self, analysis_id: str) -> None:
        try:
            await self._handler(analysis_id)
        except asyncio.CancelledError:
            logger.info("Analysis %s cancelled", analysis_id)
            raise
        except Exception:
            logger.exception("Analysis %s crashed", analysis_id)

    async def shutdown(self) -> None:
        if not self._tasks:
            return
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
