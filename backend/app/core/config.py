from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

BASE_DIR = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(BASE_DIR / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "Sentinel"
    app_env: str = "development"
    debug: bool = True
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"

    database_url: str = f"sqlite+aiosqlite:///{BASE_DIR / 'data' / 'sentinel.db'}"

    upload_dir: str = str(BASE_DIR / "data" / "uploads")
    max_upload_bytes: int = 10 * 1024 * 1024
    max_attachment_bytes: int = 5 * 1024 * 1024
    retention_days: int = 30

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    module_timeout_seconds: float = 30.0
    url_fetch_enabled: bool = True
    url_fetch_timeout_seconds: float = 8.0
    url_max_redirects: int = 5
    url_max_response_bytes: int = 1024 * 1024
    url_analysis_max_urls: int = 50
    allow_private_url_fetch: bool = False
    dns_lookups_enabled: bool = True
    rdap_enabled: bool = False

    virustotal_api_key: str | None = None
    google_safe_browsing_api_key: str | None = None
    abuseipdb_api_key: str | None = None

    clamav_enabled: bool = False
    clamav_host: str = "localhost"
    clamav_port: int = 3310

    ml_artifact_dir: str = str(BASE_DIR / "ml" / "artifacts")
    ml_active_version: str | None = None

    @field_validator("database_url")
    @classmethod
    def _absolutize_sqlite(cls, value: str) -> str:
        if not value.startswith("sqlite"):
            return value
        url = make_url(value)
        database = url.database
        if database and database != ":memory:" and not Path(database).is_absolute():
            url = url.set(database=str((BASE_DIR / database).resolve()))
        return url.render_as_string(hide_password=False)

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def upload_path(self) -> Path:
        path = Path(self.upload_dir)
        return path if path.is_absolute() else (BASE_DIR / path).resolve()

    @property
    def ml_artifact_path(self) -> Path:
        path = Path(self.ml_artifact_dir)
        return path if path.is_absolute() else (BASE_DIR / path).resolve()


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s %(name)s :: %(message)s",
)
