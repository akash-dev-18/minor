from __future__ import annotations

import re
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.modules.base import AnalysisContext, build_result, finding
from app.modules.content_analysis.data import CONTENT_RULES, HTML_HIDDEN_PATTERNS
from app.schemas.analysis import EmailObject, Finding, ModuleResult
from app.schemas.enums import ModuleName, Severity
from app.utils.domains import registered_domain
from app.utils.html import strip_html

MODULE = ModuleName.CONTENT_ANALYSIS
RECOMMENDATION = "Treat unexpected requests for action as suspicious and verify independently."

URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _evidence(text: str, start: int, end: int, radius: int = 60) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    excerpt = " ".join(text[left:right].split())
    return excerpt[:300]


class _HtmlContentCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms = 0
        self.password_inputs = 0
        self.form_actions: list[str] = []
        self.hidden_elements = 0
        self.mismatched_anchors: list[tuple[str, str]] = []
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        attributes = {name.lower(): (value or "") for name, value in attrs}
        style = attributes.get("style", "").lower()

        if lowered == "form":
            self.forms += 1
            action = attributes.get("action", "")
            if action:
                self.form_actions.append(action)
        elif lowered == "input" and attributes.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif lowered == "a":
            self._anchor_href = attributes.get("href", "")
            self._anchor_text = []

        if "hidden" in attributes:
            self.hidden_elements += 1
        elif style and any(re.search(pattern, style) for pattern in HTML_HIDDEN_PATTERNS):
            self.hidden_elements += 1

    def handle_data(self, data: str) -> None:
        if self._anchor_href is not None:
            self._anchor_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._anchor_href is not None:
            text = " ".join("".join(self._anchor_text).split())
            href = self._anchor_href
            if text and href.lower().startswith(("http://", "https://")):
                text_match = URL_IN_TEXT_RE.search(text)
                visible = text_match.group(0) if text_match else text
                visible_host = None
                if text_match:
                    try:
                        visible_host = urlsplit(visible).hostname
                    except ValueError:
                        visible_host = None
                elif "." in visible and " " not in visible:
                    visible_host = visible
                try:
                    href_host = urlsplit(href).hostname
                except ValueError:
                    href_host = None
                if (
                    visible_host
                    and href_host
                    and registered_domain(visible_host) != registered_domain(href_host)
                ):
                    self.mismatched_anchors.append((visible, href))
            self._anchor_href = None
            self._anchor_text = []


async def analyze(email: EmailObject, context: AnalysisContext) -> ModuleResult:
    started = time.monotonic()
    findings: list[Finding] = []

    html_body = email.body_html or ""
    text_body = email.body_text or ""
    if not text_body and html_body:
        text_body = strip_html(html_body)
    haystack = f"{email.subject}\n{text_body}"
    lowered = haystack.lower()

    matched: list[str] = []
    for rule in CONTENT_RULES:
        for pattern in rule["patterns"]:
            match = re.search(pattern, lowered, re.IGNORECASE)
            if not match:
                continue
            matched.append(rule["type"])
            findings.append(
                finding(
                    MODULE,
                    rule["type"],
                    rule["title"],
                    Severity(rule["severity"]),
                    rule["description"],
                    evidence=_evidence(haystack, match.start(), match.end()),
                    recommendation=rule["recommendation"],
                    confidence=0.5,
                )
            )
            break

    collector = _HtmlContentCollector()
    parse_error = None
    if html_body:
        try:
            collector.feed(html_body)
            collector.close()
        except Exception as exc:  # noqa: BLE001
            parse_error = type(exc).__name__

    if collector.password_inputs > 0:
        findings.append(
            finding(
                MODULE,
                "password_form",
                "HTML body contains a password input",
                Severity.HIGH,
                "Embedding a password field in an email is a strong credential-phishing "
                "indicator; legitimate services send users to their own site.",
                evidence=f"{collector.password_inputs} password input(s) in HTML body",
                recommendation="Do not enter credentials into forms embedded in emails.",
                confidence=0.85,
            )
        )
    elif collector.forms > 0:
        findings.append(
            finding(
                MODULE,
                "html_form",
                "HTML body contains a form",
                Severity.MEDIUM,
                "Forms embedded in emails can submit data to attacker-controlled endpoints.",
                evidence=", ".join(collector.form_actions[:3]) or f"{collector.forms} form(s)",
                recommendation="Open the service directly instead of submitting email forms.",
                confidence=0.6,
            )
        )

    if collector.hidden_elements > 0:
        findings.append(
            finding(
                MODULE,
                "hidden_html_content",
                "HTML body contains hidden elements",
                Severity.MEDIUM,
                "Hidden text is used to slip content past filters or to deceive recipients.",
                evidence=f"{collector.hidden_elements} hidden element(s) detected",
                recommendation=RECOMMENDATION,
                confidence=0.55,
            )
        )

    if collector.mismatched_anchors:
        visible, href = collector.mismatched_anchors[0]
        findings.append(
            finding(
                MODULE,
                "anchor_text_mismatch",
                "Link text does not match its destination",
                Severity.HIGH,
                "The visible link text points to a different domain than the actual "
                "destination, a classic link-spoofing technique.",
                evidence=f"text={visible[:120]} → href={href[:180]}",
                recommendation="Do not click the link; inspect the destination manually.",
                confidence=0.75,
            )
        )

    if not lowered.strip() and not html_body:
        findings.append(
            finding(
                MODULE,
                "empty_content",
                "Email has no analyzable text content",
                Severity.LOW,
                "A message with no text body cannot be assessed for social engineering cues.",
                recommendation=RECOMMENDATION,
                confidence=0.4,
            )
        )

    return build_result(
        MODULE,
        started_at=started,
        findings=findings,
        data={
            "matched_rules": sorted(set(matched)),
            "subject_length": len(email.subject),
            "text_length": len(text_body),
            "has_html": bool(html_body),
            "forms": collector.forms,
            "password_inputs": collector.password_inputs,
            "form_actions": collector.form_actions[:10],
            "hidden_elements": collector.hidden_elements,
            "anchor_mismatches": [
                {"text": visible[:200], "href": href[:500]}
                for visible, href in collector.mismatched_anchors[:10]
            ],
            "html_parse_error": parse_error,
        },
    )
