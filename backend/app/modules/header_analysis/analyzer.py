from __future__ import annotations

import logging
import re
import time
from email.utils import getaddresses

from app.modules.base import AnalysisContext, build_result, finding
from app.schemas.analysis import AuthenticationResults, EmailObject, Finding, ModuleResult
from app.schemas.enums import AuthStatus, ModuleName, Severity
from app.utils.brand_data import BRANDS
from app.utils.domains import registered_domain

logger = logging.getLogger(__name__)

MODULE = ModuleName.HEADER_ANALYSIS
RECOMMENDATION = "Treat the sender identity as unverified and confirm through an official channel."

AUTH_MECHANISM_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([A-Za-z_]+)", re.IGNORECASE
)
AUTHSERV_ID_RE = re.compile(r"^\s*([A-Za-z0-9.-]+)\s*;", re.IGNORECASE)
FROM_CLAUSE_RE = re.compile(r"\bfrom\s+([A-Za-z0-9._-]+)", re.IGNORECASE)

_VALID_STATUSES = {status.value for status in AuthStatus}


def _status(value: str) -> AuthStatus:
    lowered = value.lower()
    if lowered == "softfail":
        return AuthStatus.FAIL
    if lowered in _VALID_STATUSES:
        return AuthStatus(lowered)
    return AuthStatus.UNKNOWN


def _parse_authentication_results(headers: dict[str, list[str]]) -> tuple[AuthenticationResults, list[dict], bool]:
    claims_raw = headers.get("authentication-results") or []
    claims: list[dict] = []

    for index, raw in enumerate(claims_raw):
        authserv = AUTHSERV_ID_RE.match(raw)
        entry: dict = {
            "index": index,
            "authserv_id": authserv.group(1) if authserv else None,
            "raw": raw[:500],
            "mechanisms": {},
        }
        for match in AUTH_MECHANISM_RE.finditer(raw):
            mechanism = match.group(1).lower()
            entry["mechanisms"].setdefault(mechanism, _status(match.group(2)).value)
        claims.append(entry)

    primary = claims[0]["mechanisms"] if claims else {}
    values = {name: _status(str(primary.get(name, "not_verified"))) for name in ("spf", "dkim", "dmarc")}
    return AuthenticationResults(spf=values["spf"], dkim=values["dkim"], dmarc=values["dmarc"]), claims, bool(claims_raw)


def _addresses(values: list[str]) -> list[str]:
    parsed = getaddresses(values)
    return [address for _name, address in parsed if address]


def _display_names(values: list[str]) -> list[str]:
    parsed = getaddresses(values)
    return [name for name, _address in parsed if name]


def _brand_impersonation_in_display(name: str, sender_domain: str | None) -> str | None:
    if not name or not sender_domain:
        return None
    lowered = name.lower()
    base = sender_domain.split(".")[0]
    for brand_name, label in BRANDS.items():
        if label in lowered and base != label:
            return brand_name
    return None


async def analyze(email: EmailObject, context: AnalysisContext) -> ModuleResult:
    started = time.monotonic()
    findings: list[Finding] = []
    headers = email.headers

    from_values = headers.get("from", [])
    from_addresses = _addresses(from_values)
    from_names = _display_names(from_values)
    sender_domain = registered_domain(email.sender.split("@")[-1]) if email.sender else None

    authentication, claims, has_auth_header = _parse_authentication_results(headers)

    if not has_auth_header:
        findings.append(
            finding(
                MODULE,
                "authentication_results_missing",
                "No Authentication-Results header present",
                Severity.INFORMATIONAL,
                "SPF, DKIM and DMARC could not be determined from the message headers. "
                "Authentication status remains unverified.",
                recommendation=RECOMMENDATION,
                confidence=0.5,
            )
        )
    else:
        if authentication.spf == AuthStatus.FAIL:
            findings.append(
                finding(
                    MODULE,
                    "spf_failed",
                    "SPF authentication failed",
                    Severity.HIGH,
                    "The sending server is not authorized by the sender domain's SPF policy.",
                    evidence=claims[0]["raw"][:300] if claims else None,
                    recommendation=RECOMMENDATION,
                    confidence=0.6,
                    metadata={"verified": False, "source": "authentication-results-claim"},
                )
            )
        if authentication.dkim == AuthStatus.FAIL:
            findings.append(
                finding(
                    MODULE,
                    "dkim_failed",
                    "DKIM signature validation failed",
                    Severity.MEDIUM,
                    "A DKIM signature is present but reported as failing, which suggests "
                    "tampering or misconfiguration.",
                    evidence=claims[0]["raw"][:300] if claims else None,
                    recommendation=RECOMMENDATION,
                    confidence=0.55,
                    metadata={"verified": False, "source": "authentication-results-claim"},
                )
            )
        if authentication.dmarc == AuthStatus.FAIL:
            findings.append(
                finding(
                    MODULE,
                    "dmarc_failed",
                    "DMARC policy check failed",
                    Severity.HIGH,
                    "The visible From domain does not align with authenticated SPF/DKIM "
                    "identities under the domain's DMARC policy.",
                    evidence=claims[0]["raw"][:300] if claims else None,
                    recommendation=RECOMMENDATION,
                    confidence=0.6,
                    metadata={"verified": False, "source": "authentication-results-claim"},
                )
            )
        if authentication.dmarc == AuthStatus.NONE:
            findings.append(
                finding(
                    MODULE,
                    "dmarc_not_applied",
                    "No DMARC policy is applied to the sender domain",
                    Severity.LOW,
                    "The receiving system reported DMARC=none, so sender alignment was not "
                    "enforced.",
                    recommendation=RECOMMENDATION,
                    confidence=0.4,
                )
            )

        mechanisms = claims[0]["mechanisms"] if claims else {}
        for mechanism in ("spf", "dkim", "dmarc"):
            if mechanism not in mechanisms:
                findings.append(
                    finding(
                        MODULE,
                        f"{mechanism}_not_reported",
                        f"{mechanism.upper()} result not reported",
                        Severity.INFORMATIONAL,
                        f"The Authentication-Results header does not include a {mechanism.upper()} result.",
                        recommendation=RECOMMENDATION,
                        confidence=0.3,
                    )
                )

    if len(from_addresses) > 1:
        findings.append(
            finding(
                MODULE,
                "multiple_from_addresses",
                "Email declares multiple From addresses",
                Severity.HIGH,
                "Multiple From addresses are abnormal and can be used to confuse mail "
                "clients and filters.",
                evidence=", ".join(from_addresses[:5]),
                recommendation=RECOMMENDATION,
                confidence=0.7,
            )
        )

    if not from_addresses:
        findings.append(
            finding(
                MODULE,
                "from_header_missing",
                "From header is missing or unparseable",
                Severity.MEDIUM,
                "A message without a parseable From header cannot be attributed to a sender.",
                recommendation=RECOMMENDATION,
                confidence=0.6,
            )
        )

    for display_name in from_names:
        brand = _brand_impersonation_in_display(display_name, sender_domain)
        if brand:
            findings.append(
                finding(
                    MODULE,
                    "display_name_impersonation",
                    "Sender display name imitates a brand",
                    Severity.HIGH,
                    f"The display name contains {brand}, but the sending domain is not the "
                    "official domain.",
                    evidence=f"{display_name} <{email.sender or 'unknown'}>",
                    recommendation=RECOMMENDATION,
                    confidence=0.65,
                )
            )
            break

    reply_addresses = _addresses(headers.get("reply-to", []))
    if reply_addresses and from_addresses and reply_addresses[0].lower() != from_addresses[0].lower():
        findings.append(
            finding(
                MODULE,
                "header_reply_to_mismatch",
                "Reply-To address differs from the From address",
                Severity.MEDIUM,
                "Replies are directed to a different mailbox than the declared sender.",
                evidence=f"From {from_addresses[0]} → Reply-To {reply_addresses[0]}",
                recommendation=RECOMMENDATION,
                confidence=0.5,
            )
        )

    return_path = email.return_path.strip().strip("<>") if email.return_path else None
    if return_path and from_addresses and return_path.lower() != from_addresses[0].lower():
        findings.append(
            finding(
                MODULE,
                "header_return_path_mismatch",
                "Return-Path differs from the From address",
                Severity.LOW,
                "The envelope sender differs from the visible sender address.",
                evidence=f"From {from_addresses[0]} → Return-Path {return_path}",
                recommendation=RECOMMENDATION,
                confidence=0.4,
            )
        )

    message_ids = headers.get("message-id", [])
    message_id = message_ids[0].strip() if message_ids else None
    if not message_id:
        findings.append(
            finding(
                MODULE,
                "message_id_missing",
                "Message-ID header is missing",
                Severity.LOW,
                "Legitimate mail transfer agents normally add a Message-ID header.",
                recommendation=RECOMMENDATION,
                confidence=0.4,
            )
        )
    else:
        match = re.search(r"@([A-Za-z0-9.-]+)>?\s*$", message_id)
        message_domain = registered_domain(match.group(1)) if match else None
        if sender_domain and message_domain and message_domain != sender_domain:
            findings.append(
                finding(
                    MODULE,
                    "message_id_domain_mismatch",
                    "Message-ID domain differs from the sender domain",
                    Severity.MEDIUM,
                    "The Message-ID was generated by a different domain than the declared "
                    "sender, which can indicate spoofing or relayed bulk mail.",
                    evidence=f"{message_id} (sender domain {sender_domain})",
                    recommendation=RECOMMENDATION,
                    confidence=0.45,
                )
            )

    received = headers.get("received", [])
    hops = []
    for raw in received:
        match = FROM_CLAUSE_RE.search(raw)
        if match:
            hops.append(match.group(1).lower())

    if len(received) > 6:
        findings.append(
            finding(
                MODULE,
                "excessive_received_hops",
                "Message passed through many mail relays",
                Severity.LOW,
                f"The message has {len(received)} Received headers, which can obscure its origin.",
                evidence=" → ".join(hops[:10]),
                recommendation=RECOMMENDATION,
                confidence=0.35,
            )
        )

    if received and hops:
        sender_registered = registered_domain(email.sender.split("@")[-1]) if email.sender else None
        if sender_registered and sender_registered not in " ".join(hops):
            findings.append(
                finding(
                    MODULE,
                    "sender_not_in_received_chain",
                    "Sender domain does not appear in the routing chain",
                    Severity.MEDIUM,
                    "None of the Received headers reference the declared sender domain, "
                    "which weakens the message's provenance.",
                    evidence=" → ".join(hops[:10]),
                    recommendation=RECOMMENDATION,
                    confidence=0.45,
                )
            )

    if email.parse_defects:
        findings.append(
            finding(
                MODULE,
                "malformed_message",
                "Email structure contains parsing defects",
                Severity.LOW,
                "The message failed strict MIME parsing, which can indicate tampering or a "
                "poorly constructed phishing template.",
                evidence=", ".join(email.parse_defects[:5]),
                recommendation=RECOMMENDATION,
                confidence=0.4,
            )
        )

    return build_result(
        MODULE,
        started_at=started,
        findings=findings,
        data={
            "authentication": authentication.model_dump(mode="json"),
            "authentication_claims": claims,
            "authentication_verified": False,
            "from_addresses": from_addresses,
            "reply_to_addresses": reply_addresses,
            "return_path": return_path,
            "message_id": message_id,
            "received_hops": hops,
            "received_count": len(received),
        },
    )
