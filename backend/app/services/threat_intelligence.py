from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.config import Settings

logger = logging.getLogger(__name__)

VT_API = "https://www.virustotal.com/api/v3"
SAFE_BROWSING_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"


@dataclass
class LookupResult:
    available: bool
    source: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "source": self.source,
            "data": self.data,
            "error": self.error,
        }


class ThreatIntelligence:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def virustotal_enabled(self) -> bool:
        return bool(self._settings.virustotal_api_key)

    @property
    def safe_browsing_enabled(self) -> bool:
        return bool(self._settings.google_safe_browsing_api_key)

    @property
    def abuseipdb_enabled(self) -> bool:
        return bool(self._settings.abuseipdb_api_key)

    def _timeout(self) -> httpx.Timeout:
        return httpx.Timeout(self._settings.url_fetch_timeout_seconds)

    async def virustotal_url(self, url: str) -> LookupResult:
        if not self.virustotal_enabled:
            return LookupResult(False, "virustotal", error="API key not configured")
        identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            async with httpx.AsyncClient(timeout=self._timeout()) as client:
                response = await client.get(
                    f"{VT_API}/urls/{identifier}",
                    headers={"x-apikey": self._settings.virustotal_api_key or ""},
                )
            if response.status_code == 404:
                return LookupResult(True, "virustotal", data={"verdict": "unknown"})
            if response.status_code != 200:
                return LookupResult(False, "virustotal", error=f"HTTP {response.status_code}")
            stats = (
                response.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return LookupResult(True, "virustotal", data={"stats": stats})
        except Exception as exc:  # noqa: BLE001
            logger.debug("VirusTotal URL lookup failed: %s", exc)
            return LookupResult(False, "virustotal", error=type(exc).__name__)

    async def virustotal_hash(self, sha256: str) -> LookupResult:
        if not self.virustotal_enabled:
            return LookupResult(False, "virustotal", error="API key not configured")
        try:
            async with httpx.AsyncClient(timeout=self._timeout()) as client:
                response = await client.get(
                    f"{VT_API}/files/{sha256}",
                    headers={"x-apikey": self._settings.virustotal_api_key or ""},
                )
            if response.status_code == 404:
                return LookupResult(True, "virustotal", data={"verdict": "unknown"})
            if response.status_code != 200:
                return LookupResult(False, "virustotal", error=f"HTTP {response.status_code}")
            stats = (
                response.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return LookupResult(True, "virustotal", data={"stats": stats})
        except Exception as exc:  # noqa: BLE001
            logger.debug("VirusTotal hash lookup failed: %s", exc)
            return LookupResult(False, "virustotal", error=type(exc).__name__)

    async def safe_browsing_url(self, url: str) -> LookupResult:
        if not self.safe_browsing_enabled:
            return LookupResult(False, "safe_browsing", error="API key not configured")
        payload = {
            "client": {"clientId": "sentinel", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout()) as client:
                response = await client.post(
                    SAFE_BROWSING_API,
                    params={"key": self._settings.google_safe_browsing_api_key},
                    json=payload,
                )
            if response.status_code != 200:
                return LookupResult(False, "safe_browsing", error=f"HTTP {response.status_code}")
            matches = response.json().get("matches", []) or []
            return LookupResult(
                True,
                "safe_browsing",
                data={"matches": [m.get("threatType") for m in matches]},
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Safe Browsing lookup failed: %s", exc)
            return LookupResult(False, "safe_browsing", error=type(exc).__name__)

    async def abuseipdb_ip(self, ip: str) -> LookupResult:
        if not self.abuseipdb_enabled:
            return LookupResult(False, "abuseipdb", error="API key not configured")
        try:
            async with httpx.AsyncClient(timeout=self._timeout()) as client:
                response = await client.get(
                    ABUSEIPDB_API,
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": self._settings.abuseipdb_api_key or "",
                        "Accept": "application/json",
                    },
                )
            if response.status_code != 200:
                return LookupResult(False, "abuseipdb", error=f"HTTP {response.status_code}")
            data = response.json().get("data", {})
            return LookupResult(
                True,
                "abuseipdb",
                data={
                    "abuse_confidence_score": data.get("abuseConfidenceScore"),
                    "total_reports": data.get("totalReports"),
                    "country_code": data.get("countryCode"),
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("AbuseIPDB lookup failed: %s", exc)
            return LookupResult(False, "abuseipdb", error=type(exc).__name__)


def get_threat_intelligence(settings: Settings) -> ThreatIntelligence:
    return ThreatIntelligence(settings)
