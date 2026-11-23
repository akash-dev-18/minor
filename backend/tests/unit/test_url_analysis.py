from __future__ import annotations

from app.modules.url_analysis.analyzer import analyze
from app.schemas.enums import AnalysisStatus
from tests.helpers import context, make_email


def types(result) -> set[str]:
    return {item.type for item in result.findings}


async def test_flags_ip_url_shortener_and_typosquat():
    email = make_email(
        urls=[
            "http://192.168.10.25/login",
            "https://bit.ly/abc123",
            "https://paypa1.com/verify",
            "https://www.google.com/search?q=report",
        ]
    )
    result = await analyze(email, context())

    assert result.status == AnalysisStatus.COMPLETED
    assert result.data["urls_analyzed"] == 4
    found = types(result)
    assert "ip_address_url" in found
    assert "url_shortener" in found
    assert "typosquatting_domain" in found
    assert "insecure_scheme" in found
    assert all(item.source_module.value == "url_analysis" for item in result.findings)


async def test_marks_http_as_low_severity():
    result = await analyze(make_email(urls=["http://example.com/a"]), context())
    findings = [item for item in result.findings if item.type == "insecure_scheme"]
    assert findings and findings[0].severity.value == "low"


async def test_no_urls_is_clean():
    result = await analyze(make_email(urls=[]), context())
    assert result.status == AnalysisStatus.COMPLETED
    assert result.findings == []
    assert result.data["urls_analyzed"] == 0


async def test_skips_url_fetch_when_disabled():
    result = await analyze(make_email(urls=["https://example.com/a"]), context())
    record = result.data["urls"][0]
    assert "redirects" not in record


async def test_url_cap_is_reported():
    urls = [f"https://example.com/{index}" for index in range(5)]
    result = await analyze(make_email(urls=urls), context())
    assert result.data["urls_total"] == 5
    assert result.data["truncated"] is False


async def test_unresolved_host_is_medium_severity(monkeypatch):
    from app.core.config import settings
    from app.modules.url_analysis import analyzer
    from app.utils.net import FetchResult

    monkeypatch.setattr(settings, "url_fetch_enabled", True)

    async def fake_fetch(url: str, _settings) -> FetchResult:
        return FetchResult(error=f"Host could not be resolved: {url}")

    monkeypatch.setattr(analyzer, "fetch_redirect_chain", fake_fetch)

    result = await analyze(make_email(urls=["https://missing.example/a"]), context())
    items = [item for item in result.findings if item.type == "url_host_unresolved"]
    assert items and items[0].severity.value == "medium"
    assert "unsafe_url_target" not in types(result)
