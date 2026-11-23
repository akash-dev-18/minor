from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.database.session import SessionLocal
from app.models.analysis import Analysis
from app.schemas.enums import AnalysisStatus
from app.services.upload_validation import validate_upload
from app.utils.net import UnsafeTargetError, fetch_redirect_chain, validate_target
from tests.integration.test_analysis_upload import load, submit, wait_for_completion

HEADER = b"From: alice@example.com\nTo: bob@example.org\nSubject: Test\n\nHello\n"


def test_path_traversal_filename_is_reduced_to_basename():
    validate_upload(HEADER, "../../../../etc/evil.eml")
    validate_upload(HEADER, "..\\..\\windows\\evil.eml")


def test_upload_rejects_non_eml_extension():
    with pytest.raises(Exception) as error:
        validate_upload(HEADER, "payload.txt")
    assert getattr(error.value, "status_code", None) == 415


def test_upload_rejects_empty_file():
    with pytest.raises(Exception) as error:
        validate_upload(b"", "empty.eml")
    assert getattr(error.value, "status_code", None) == 422


def test_upload_rejects_null_bytes():
    with pytest.raises(Exception) as error:
        validate_upload(HEADER + b"\x00\x01\x02", "binary.eml")
    assert getattr(error.value, "status_code", None) == 415


def test_upload_rejects_pdf_disguised_as_eml():
    with pytest.raises(Exception) as error:
        validate_upload(b"%PDF-1.7\n" + HEADER, "document.eml")
    assert getattr(error.value, "status_code", None) == 415


async def test_oversized_upload_rejected(client, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 1024)
    payload = HEADER + b"x" * 4096
    response = await submit(client, payload)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "file_too_large"


async def test_traversal_filename_does_not_escape_upload_dir(client):
    response = await submit(client, load("simple.eml"), filename="../../../../tmp/evil.eml")
    assert response.status_code == 202
    analysis_id = response.json()["analysis_id"]

    async with SessionLocal() as session:
        analysis = await session.get(Analysis, analysis_id)
        assert analysis is not None
        stored = Path(analysis.stored_path or "")
        upload_root = Path(settings.upload_dir).resolve()
        assert stored.resolve().is_relative_to(upload_root)
        assert analysis.original_filename == "evil.eml"


async def test_malformed_mime_still_produces_a_report(client):
    response = await submit(client, load("malformed.eml"))
    detail = await wait_for_completion(client, response.json()["analysis_id"])
    assert detail["status"] == "COMPLETED"
    modules = {module["module_name"]: module for module in detail["modules"]}
    assert modules["email_parser"]["execution_status"] == "COMPLETED"
    assert detail["risk_level"] is not None


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/file",
        "gopher://example.com/",
        "http://127.0.0.1/admin",
        "http://[::1]/admin",
        "http://10.0.0.5/",
        "http://192.168.1.10/",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/",
        "http://224.0.0.1/",
        "http://example.com:22/",
        "http://example.com:6379/",
        "http://example.com/" + "a" * 5000,
    ],
)
async def test_ssrf_targets_are_blocked(url):
    with pytest.raises(UnsafeTargetError):
        await validate_target(url, settings)


async def test_private_dns_resolution_is_blocked(monkeypatch):
    async def fake_resolve(host: str) -> list[str]:
        return ["10.1.2.3"]

    monkeypatch.setattr("app.utils.net.resolve_host", fake_resolve)
    with pytest.raises(UnsafeTargetError):
        await validate_target("https://internal.example.com/", settings)


async def test_private_fetch_allowed_only_when_explicit(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_url_fetch", True)
    addresses = await validate_target("http://127.0.0.1/", settings)
    assert addresses == ["127.0.0.1"]


class _FakeResponse:
    def __init__(self, status_code: int, headers: dict[str, str]):
        self.status_code = status_code
        self.headers = headers

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def aiter_bytes(self):
        yield b"hello"


class _FakeClient:
    requests: list[str] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def stream(self, method: str, url: str):
        _FakeClient.requests.append(url)
        if len(_FakeClient.requests) == 1:
            return _FakeResponse(302, {"location": "http://127.0.0.1/admin"})
        return _FakeResponse(200, {})


async def test_redirect_to_private_address_is_blocked(monkeypatch):
    _FakeClient.requests = []
    monkeypatch.setattr("app.utils.net.httpx.AsyncClient", _FakeClient)
    monkeypatch.setattr(settings, "url_fetch_enabled", True)

    result = await fetch_redirect_chain("https://example.com/start", settings)

    assert result.blocked is True
    assert result.error and "Redirect blocked" in result.error
    assert len(_FakeClient.requests) == 1


async def test_redirect_chain_is_bounded(monkeypatch):
    class LoopClient(_FakeClient):
        def stream(self, method: str, url: str):
            _FakeClient.requests.append(url)
            return _FakeResponse(302, {"location": "https://example.com/next"})

    _FakeClient.requests = []
    monkeypatch.setattr("app.utils.net.httpx.AsyncClient", LoopClient)
    monkeypatch.setattr(settings, "url_fetch_enabled", True)
    monkeypatch.setattr(settings, "url_max_redirects", 3)

    result = await fetch_redirect_chain("https://example.com/start", settings)
    assert result.error == "Too many redirects"
    assert len(result.chain) == 4


async def test_unresolvable_host_is_not_marked_as_blocked(monkeypatch):
    from app.utils.net import TargetUnresolvedError

    async def fake_validate(url: str, _settings):
        raise TargetUnresolvedError("Host could not be resolved: missing.example")

    monkeypatch.setattr("app.utils.net.validate_target", fake_validate)
    monkeypatch.setattr(settings, "url_fetch_enabled", True)

    result = await fetch_redirect_chain("https://missing.example/", settings)
    assert result.blocked is False
    assert result.error and "could not be resolved" in result.error
