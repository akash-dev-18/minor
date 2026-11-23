from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TEST_DIR = Path(tempfile.mkdtemp(prefix="sentinel-tests-"))
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DIR / 'test.db'}"
os.environ["UPLOAD_DIR"] = str(_TEST_DIR / "uploads")
os.environ["ML_ARTIFACT_DIR"] = str(_TEST_DIR / "artifacts")
os.environ["APP_ENV"] = "test"
os.environ["URL_FETCH_ENABLED"] = "false"
os.environ["DNS_LOOKUPS_ENABLED"] = "false"
os.environ["RDAP_ENABLED"] = "false"
os.environ["CLAMAV_ENABLED"] = "false"

import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.database.session import engine  # noqa: E402
from app.models import Base  # noqa: E402


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _schema():
    Path(os.environ["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["ML_ARTIFACT_DIR"]).mkdir(parents=True, exist_ok=True)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


@pytest_asyncio.fixture
async def client():
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http
