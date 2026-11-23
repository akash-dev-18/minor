from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.core.config import Settings
from app.modules.base import AnalysisContext, build_result, finding
from app.modules.domain_reputation.data import (
    DISPOSABLE_DOMAINS,
    NEW_DOMAIN_DAYS,
    YOUNG_DOMAIN_DAYS,
)
from app.schemas.analysis import EmailObject, Finding, ModuleResult
from app.schemas.enums import ModuleName, Severity
from app.utils.brand_data import BRANDS
from app.utils.domains import (
    hostname_from_address,
    lookalike_brand,
    registered_domain,
)

logger = logging.getLogger(__name__)

MODULE = ModuleName.DOMAIN_REPUTATION
RECOMMENDATION = "Verify the sender using an independent, official contact channel."


def _make_resolver() -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 4.0
    return resolver


async def _resolve_records(domain: str) -> dict:
    resolver = _make_resolver()
    summary: dict = {"domain": domain, "lookup": "attempted"}
    nxd = False

    try:
        answers = await resolver.resolve(domain, "A")
        summary["addresses"] = [str(r) for r in answers][:10]
    except dns.resolver.NXDOMAIN:
        nxd = True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        summary["addresses"] = []
    except Exception as exc:  # noqa: BLE001
        summary["address_error"] = type(exc).__name__

    try:
        answers = await resolver.resolve(domain, "MX")
        summary["mx"] = [str(r.exchange).rstrip(".") for r in answers][:10]
    except dns.resolver.NXDOMAIN:
        nxd = True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        summary["mx"] = []
    except Exception as exc:  # noqa: BLE001
        summary["mx_error"] = type(exc).__name__

    summary["exists"] = not nxd and bool(summary.get("addresses") or summary.get("mx"))

    try:
        answers = await resolver.resolve(domain, "TXT")
        records = [" ".join(r.strings[0].decode("utf-8", "replace").split()) if r.strings else "" for r in answers]
        summary["spf"] = next((r for r in records if r.lower().startswith("v=spf1")), None)
    except Exception:  # noqa: BLE001
        summary["spf"] = None

    try:
        answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
        records = [" ".join(r.strings[0].decode("utf-8", "replace").split()) if r.strings else "" for r in answers]
        summary["dmarc"] = next((r for r in records if r.lower().startswith("v=dmarc1")), None)
    except Exception:  # noqa: BLE001
        summary["dmarc"] = None

    return summary


async def _rdap_lookup(domain: str, settings: Settings) -> dict:
    if not settings.rdap_enabled:
        return {"available": False, "reason": "RDAP lookups are disabled"}
    try:
        async with httpx.AsyncClient(timeout=settings.url_fetch_timeout_seconds) as client:
            response = await client.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/rdap+json"},
            )
        if response.status_code != 200:
            return {"available": False, "reason": f"RDAP returned {response.status_code}"}
        payload = response.json()
        registered = None
        for event in payload.get("events", []):
            if event.get("eventAction") == "registration" and event.get("eventDate"):
                registered = event["eventDate"]
                break
        age_days = None
        if registered:
            try:
                moment = datetime.fromisoformat(registered.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - moment).days
            except ValueError:
                age_days = None
        return {"available": True, "registered": registered, "age_days": age_days}
    except Exception as exc:  # noqa: BLE001
        logger.debug("RDAP lookup failed for %s: %s", domain, exc)
        return {"available": False, "reason": type(exc).__name__}


async def _analyze_domain(
    domain: str, role: str, settings: Settings
) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    record: dict = {"domain": domain, "role": role}
    base = registered_domain(domain) or domain
    record["registered_domain"] = base

    if base in DISPOSABLE_DOMAINS:
        findings.append(
            finding(
                MODULE,
                "disposable_email_domain",
                "Sender uses a disposable email domain",
                Severity.HIGH,
                "Disposable email providers are frequently used to create throwaway "
                "accounts for abuse and fraud.",
                evidence=domain,
                recommendation=RECOMMENDATION,
                confidence=0.85,
            )
        )

    brand = lookalike_brand(base, BRANDS)
    if brand:
        findings.append(
            finding(
                MODULE,
                "domain_impersonation",
                "Domain resembles a known brand",
                Severity.HIGH,
                f"The {role} domain resembles {brand} but is not the official domain.",
                evidence=domain,
                recommendation=RECOMMENDATION,
                confidence=0.65,
            )
        )

    label = base.split(".")[0]
    if label.count("-") >= 2 or sum(char.isdigit() for char in label) >= 4:
        findings.append(
            finding(
                MODULE,
                "suspicious_domain_pattern",
                "Domain name has a suspicious structure",
                Severity.LOW,
                "Unusual hyphenation or excessive digits are common in automatically "
                "generated malicious domains.",
                evidence=domain,
                recommendation=RECOMMENDATION,
                confidence=0.4,
            )
        )

    if settings.dns_lookups_enabled:
        dns_summary = await _resolve_records(domain)
        record["dns"] = dns_summary

        if dns_summary.get("exists") is False:
            findings.append(
                finding(
                    MODULE,
                    "nonexistent_domain",
                    "Sender domain does not resolve",
                    Severity.HIGH,
                    "The domain has no A or MX records, so it cannot send or receive mail "
                    "reliably. This suggests a forged or abandoned sender domain.",
                    evidence=domain,
                    recommendation=RECOMMENDATION,
                    confidence=0.75,
                )
            )
        elif not dns_summary.get("mx"):
            findings.append(
                finding(
                    MODULE,
                    "no_mx_records",
                    "Sender domain has no mail exchange records",
                    Severity.MEDIUM,
                    "A legitimate mail-sending domain normally publishes MX records.",
                    evidence=domain,
                    recommendation=RECOMMENDATION,
                    confidence=0.5,
                )
            )

        if not dns_summary.get("spf"):
            findings.append(
                finding(
                    MODULE,
                    "missing_spf_record",
                    "Sender domain has no SPF policy",
                    Severity.LOW,
                    "Without an SPF record, receivers cannot verify which servers are "
                    "authorized to send mail for this domain.",
                    evidence=domain,
                    recommendation=RECOMMENDATION,
                    confidence=0.4,
                )
            )
        if not dns_summary.get("dmarc"):
            findings.append(
                finding(
                    MODULE,
                    "missing_dmarc_record",
                    "Sender domain has no DMARC policy",
                    Severity.LOW,
                    "A missing DMARC policy weakens protection against sender spoofing.",
                    evidence=domain,
                    recommendation=RECOMMENDATION,
                    confidence=0.35,
                )
            )
    else:
        record["dns"] = {"available": False, "reason": "DNS lookups are disabled"}

    rdap = await _rdap_lookup(base, settings)
    record["rdap"] = rdap
    age_days = rdap.get("age_days")
    if isinstance(age_days, int):
        if age_days <= NEW_DOMAIN_DAYS:
            findings.append(
                finding(
                    MODULE,
                    "newly_registered_domain",
                    "Domain was registered very recently",
                    Severity.HIGH,
                    f"The domain is approximately {age_days} days old. Newly registered "
                    "domains are strongly associated with phishing campaigns.",
                    evidence=f"{base} registered {rdap.get('registered')}",
                    recommendation=RECOMMENDATION,
                    confidence=0.7,
                )
            )
        elif age_days <= YOUNG_DOMAIN_DAYS:
            findings.append(
                finding(
                    MODULE,
                    "young_domain",
                    "Domain is recently registered",
                    Severity.MEDIUM,
                    f"The domain is approximately {age_days} days old, which is young for "
                    "an established organization.",
                    evidence=f"{base} registered {rdap.get('registered')}",
                    recommendation=RECOMMENDATION,
                    confidence=0.5,
                )
            )

    return findings, record


async def analyze(email: EmailObject, context: AnalysisContext) -> ModuleResult:
    started = time.monotonic()
    settings = context.settings

    roles: dict[str, str] = {}
    if email.sender:
        roles.setdefault(hostname_from_address(email.sender) or "", "sender")
    if email.reply_to:
        roles.setdefault(hostname_from_address(email.reply_to) or "", "reply_to")
    if email.return_path:
        roles.setdefault(hostname_from_address(email.return_path) or "", "return_path")
    roles.pop("", None)

    findings: list[Finding] = []
    records: list[dict] = []

    if not email.sender:
        findings.append(
            finding(
                MODULE,
                "missing_sender",
                "Email has no usable sender address",
                Severity.MEDIUM,
                "A message without a valid From address cannot be attributed and is often "
                "malformed or forged.",
                recommendation=RECOMMENDATION,
                confidence=0.6,
            )
        )

    sender_domain = registered_domain(hostname_from_address(email.sender))
    reply_domain = registered_domain(hostname_from_address(email.reply_to))
    return_domain = registered_domain(hostname_from_address(email.return_path))

    if sender_domain and reply_domain and sender_domain != reply_domain:
        findings.append(
            finding(
                MODULE,
                "reply_to_mismatch",
                "Reply-To domain differs from the sender domain",
                Severity.MEDIUM,
                "Replies would be routed to a different domain than the one shown as the "
                "sender, which is a common phishing technique.",
                evidence=f"From {sender_domain} → Reply-To {reply_domain}",
                recommendation=RECOMMENDATION,
                confidence=0.55,
            )
        )

    if sender_domain and return_domain and sender_domain != return_domain:
        findings.append(
            finding(
                MODULE,
                "return_path_mismatch",
                "Return-Path domain differs from the sender domain",
                Severity.MEDIUM,
                "The envelope sender differs from the visible From domain, which can "
                "indicate spoofing or bulk-mail infrastructure abuse.",
                evidence=f"From {sender_domain} → Return-Path {return_domain}",
                recommendation=RECOMMENDATION,
                confidence=0.5,
            )
        )

    for domain, role in roles.items():
        domain_findings, record = await _analyze_domain(domain, role, settings)
        findings.extend(domain_findings)
        records.append(record)

    return build_result(
        MODULE,
        started_at=started,
        findings=findings,
        data={
            "sender_domain": sender_domain,
            "reply_to_domain": reply_domain,
            "return_path_domain": return_domain,
            "domains": records,
            "dns_enabled": settings.dns_lookups_enabled,
        },
    )
