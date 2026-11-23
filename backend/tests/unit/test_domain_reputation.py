from __future__ import annotations

from app.modules.domain_reputation.analyzer import analyze
from app.schemas.enums import AnalysisStatus
from tests.helpers import context, make_email


def types(result) -> set[str]:
    return {item.type for item in result.findings}


async def test_disposable_domain_is_flagged():
    result = await analyze(make_email(sender="throwaway@mailinator.com"), context())
    assert result.status == AnalysisStatus.COMPLETED
    assert "disposable_email_domain" in types(result)


async def test_reply_to_and_return_path_mismatch():
    result = await analyze(
        make_email(
            sender="alice@example.com",
            reply_to="alice@other-domain.example",
            return_path="<bounce@third-domain.example>",
        ),
        context(),
    )
    found = types(result)
    assert "reply_to_mismatch" in found
    assert "return_path_mismatch" in found


async def test_typosquat_domain_is_flagged():
    result = await analyze(make_email(sender="service@paypa1.com"), context())
    assert "domain_impersonation" in types(result)


async def test_dns_disabled_is_reported_not_silent():
    result = await analyze(make_email(sender="alice@example.com"), context())
    record = result.data["domains"][0]
    assert record["dns"]["available"] is False
    assert "nonexistent_domain" not in types(result)


async def test_missing_sender():
    result = await analyze(make_email(sender=None), context())
    assert "missing_sender" in types(result)
