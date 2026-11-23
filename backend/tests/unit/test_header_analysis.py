from __future__ import annotations

from app.modules.header_analysis.analyzer import analyze
from app.schemas.enums import AnalysisStatus, AuthStatus
from tests.helpers import context, make_email

AUTH_FAIL = (
    "mx.example.org; spf=fail smtp.mailfrom=evil.example; "
    "dkim=fail header.d=evil.example; dmarc=fail header.from=evil.example"
)


def types(result) -> set[str]:
    return {item.type for item in result.findings}


async def test_auth_failures_are_reported_as_claims():
    email = make_email(
        sender="support@evil.example",
        headers={
            "from": ["Support <support@evil.example>"],
            "authentication-results": [AUTH_FAIL],
        },
    )
    result = await analyze(email, context())

    assert result.status == AnalysisStatus.COMPLETED
    assert result.data["authentication"] == {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
    }
    assert result.data["authentication_verified"] is False
    found = types(result)
    assert {"spf_failed", "dkim_failed", "dmarc_failed"} <= found
    assert all(
        item.metadata.get("verified") is False
        for item in result.findings
        if item.type.endswith("_failed")
    )


async def test_missing_authentication_header_is_explicit():
    result = await analyze(make_email(headers={"from": ["a@example.com"]}), context())
    assert "authentication_results_missing" in types(result)
    assert result.data["authentication"]["spf"] == AuthStatus.NOT_VERIFIED.value


async def test_display_name_impersonation():
    email = make_email(
        sender="billing@evil.example",
        headers={"from": ["PayPal Support <billing@evil.example>"]},
    )
    result = await analyze(email, context())
    assert "display_name_impersonation" in types(result)


async def test_message_id_domain_mismatch():
    email = make_email(
        sender="alice@example.com",
        headers={
            "from": ["alice@example.com"],
            "message-id": ["<abc123@other.example>"],
        },
    )
    result = await analyze(email, context())
    assert "message_id_domain_mismatch" in types(result)


async def test_softfail_maps_to_fail_but_keeps_raw_claim():
    email = make_email(
        sender="alice@example.com",
        headers={
            "from": ["alice@example.com"],
            "authentication-results": ["mx.example.org; spf=softfail smtp.mailfrom=example.com"],
        },
    )
    result = await analyze(email, context())
    assert result.data["authentication"]["spf"] == "fail"
    assert "softfail" in result.data["authentication_claims"][0]["raw"].lower()
