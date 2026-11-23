from __future__ import annotations

import logging
import time
from urllib.parse import urlsplit

from app.core.config import Settings
from app.modules.base import AnalysisContext, build_result, finding
from app.modules.url_analysis.data import (
    MAX_FETCHED_URLS,
    MAX_TI_URLS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
)
from app.schemas.analysis import EmailObject, Finding, ModuleResult
from app.schemas.enums import ModuleName, Severity
from app.services.threat_intelligence import ThreatIntelligence, get_threat_intelligence
from app.utils.brand_data import BRANDS
from app.utils.domains import is_ip_host, lookalike_brand, registered_domain
from app.utils.net import fetch_redirect_chain

logger = logging.getLogger(__name__)

MODULE = ModuleName.URL_ANALYSIS
RECOMMENDATION = "Do not click this link. Verify the destination through an official channel."


async def _inspect_redirects(url: str, settings: Settings) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    result = await fetch_redirect_chain(url, settings)
    summary = result.to_dict()

    if result.blocked:
        findings.append(
            finding(
                MODULE,
                "unsafe_url_target",
                "URL targets a blocked destination",
                Severity.HIGH,
                "The URL resolves to a private, loopback or otherwise disallowed address. "
                "This is a common sign of SSRF-style phishing infrastructure.",
                evidence=url,
                recommendation=RECOMMENDATION,
                confidence=0.9,
            )
        )
    elif result.error and "could not be resolved" in result.error:
        findings.append(
            finding(
                MODULE,
                "url_host_unresolved",
                "URL host does not resolve",
                Severity.MEDIUM,
                "The URL's hostname has no DNS records. Phishing infrastructure is often "
                "taken down quickly, leaving links that no longer resolve.",
                evidence=url,
                recommendation=RECOMMENDATION,
                confidence=0.6,
            )
        )
        return findings, summary

    if result.error and not result.chain:
        summary["note"] = "Destination could not be inspected"
        return findings, summary

    hosts: list[str] = []
    for hop in result.chain:
        if hop.url:
            host = urlsplit(hop.url).hostname
            if host:
                hosts.append(host.lower())

    distinct_domains = {registered_domain(host) for host in hosts if host}
    distinct_domains.discard(None)
    if len(distinct_domains) > 1:
        findings.append(
            finding(
                MODULE,
                "cross_domain_redirect",
                "URL redirects across domains",
                Severity.MEDIUM,
                "The link redirects through multiple registered domains, which is often "
                "used to obscure the final destination.",
                evidence=" -> ".join(hosts[:8]),
                recommendation=RECOMMENDATION,
                confidence=0.6,
            )
        )

    if len(result.chain) > 3:
        findings.append(
            finding(
                MODULE,
                "long_redirect_chain",
                "URL uses a long redirect chain",
                Severity.LOW,
                "Several consecutive redirects can be used to bypass URL filters.",
                evidence=" -> ".join(hosts[:10]),
                recommendation=RECOMMENDATION,
                confidence=0.5,
            )
        )

    return findings, summary


async def _analyze_url(
    url: str,
    settings: Settings,
    allow_fetch: bool,
    include_ti: bool,
    ti: ThreatIntelligence,
) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    record: dict = {"url": url}

    try:
        parts = urlsplit(url)
    except ValueError:
        return findings, record

    host = (parts.hostname or "").lower()
    record["host"] = host
    record["scheme"] = parts.scheme

    if parts.scheme == "http":
        findings.append(
            finding(
                MODULE,
                "insecure_scheme",
                "URL does not use HTTPS",
                Severity.LOW,
                "The link uses unencrypted HTTP, so credentials or content could be "
                "intercepted or modified in transit.",
                evidence=url,
                recommendation=RECOMMENDATION,
                confidence=0.8,
            )
        )

    if is_ip_host(host):
        findings.append(
            finding(
                MODULE,
                "ip_address_url",
                "URL uses an IP address instead of a domain",
                Severity.HIGH,
                "Legitimate services rarely link directly to raw IP addresses. This is a "
                "common phishing indicator.",
                evidence=url,
                recommendation=RECOMMENDATION,
                confidence=0.7,
            )
        )
    elif "xn--" in host:
        findings.append(
            finding(
                MODULE,
                "punycode_domain",
                "URL uses an internationalized (punycode) domain",
                Severity.MEDIUM,
                "Punycode domains can visually imitate legitimate brands.",
                evidence=url,
                recommendation=RECOMMENDATION,
                confidence=0.6,
            )
        )
    else:
        domain = registered_domain(host) or ""
        brand = lookalike_brand(domain, BRANDS)
        if brand:
            findings.append(
                finding(
                    MODULE,
                    "typosquatting_domain",
                    "URL domain resembles a known brand",
                    Severity.HIGH,
                    f"The domain resembles {brand} but is not the official domain. This is "
                    "consistent with typosquatting or brand impersonation.",
                    evidence=host,
                    recommendation=RECOMMENDATION,
                    confidence=0.65,
                )
            )

        base_label = domain.split(".")[0] if domain else ""
        for brand_name, brand_label in BRANDS.items():
            if brand_label != base_label and brand_label in host and domain != f"{brand_label}.com":
                findings.append(
                    finding(
                        MODULE,
                        "brand_subdomain_impersonation",
                        "Brand name appears in a non-brand domain",
                        Severity.HIGH,
                        f"The URL places {brand_name} in the hostname while the registered "
                        f"domain is {domain or 'unknown'}.",
                        evidence=url,
                        recommendation=RECOMMENDATION,
                        confidence=0.6,
                    )
                )
                break

        if domain in SHORTENER_DOMAINS:
            findings.append(
                finding(
                    MODULE,
                    "url_shortener",
                    "URL uses a link shortener",
                    Severity.MEDIUM,
                    "Shortened links hide the final destination and are frequently used to "
                    "evade URL reputation checks.",
                    evidence=url,
                    recommendation=RECOMMENDATION,
                    confidence=0.7,
                )
            )

        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            findings.append(
                finding(
                    MODULE,
                    "suspicious_tld",
                    "URL uses a frequently abused top-level domain",
                    Severity.LOW,
                    f"The .{tld} TLD is disproportionately used in spam and phishing campaigns.",
                    evidence=url,
                    recommendation=RECOMMENDATION,
                    confidence=0.4,
                )
            )

        if host.count(".") >= 4:
            findings.append(
                finding(
                    MODULE,
                    "excessive_subdomains",
                    "URL uses an excessive number of subdomains",
                    Severity.MEDIUM,
                    "Deep subdomain chains are often used to make a URL appear legitimate.",
                    evidence=host,
                    recommendation=RECOMMENDATION,
                    confidence=0.5,
                )
            )

    if len(url) > 200:
        findings.append(
            finding(
                MODULE,
                "excessive_url_length",
                "URL is unusually long",
                Severity.LOW,
                "Very long URLs can be used to hide the real destination or evade filters.",
                evidence=f"{url[:180]}…",
                recommendation=RECOMMENDATION,
                confidence=0.4,
            )
        )

    encoded_count = url.count("%")
    if encoded_count >= 6 or "%25" in url:
        findings.append(
            finding(
                MODULE,
                "suspicious_url_encoding",
                "URL contains heavy or double encoding",
                Severity.MEDIUM,
                "Excessive percent-encoding can hide the true target of a link.",
                evidence=url,
                recommendation=RECOMMENDATION,
                confidence=0.5,
            )
        )

    if parts.username or parts.password:
        findings.append(
            finding(
                MODULE,
                "credentials_in_url",
                "URL embeds credentials",
                Severity.HIGH,
                "Embedded user info in URLs is a deceptive pattern and can be used to "
                "disguise the real hostname.",
                evidence=url,
                recommendation=RECOMMENDATION,
                confidence=0.8,
            )
        )

    record["finding_count"] = len(findings)

    if allow_fetch:
        redirect_findings, redirect_summary = await _inspect_redirects(url, settings)
        findings.extend(redirect_findings)
        record["redirects"] = redirect_summary
        record["finding_count"] = len(findings)

    if include_ti:
        if ti.virustotal_enabled:
            vt = await ti.virustotal_url(url)
            record["virustotal"] = vt.to_dict()
            stats = vt.data.get("stats") if vt.available else None
            malicious = int(stats.get("malicious", 0)) if isinstance(stats, dict) else 0
            if malicious > 0:
                findings.append(
                    finding(
                        MODULE,
                        "virustotal_malicious_url",
                        "URL is flagged by VirusTotal",
                        Severity.CRITICAL,
                        f"VirusTotal reports {malicious} security engine(s) flagging this URL.",
                        evidence=url,
                        recommendation="Block this URL and do not interact with the site.",
                        confidence=0.9,
                        metadata={"engine_detections": malicious, "source": "virustotal"},
                    )
                )

        if ti.safe_browsing_enabled:
            sb = await ti.safe_browsing_url(url)
            record["safe_browsing"] = sb.to_dict()
            matches = sb.data.get("matches") if sb.available else None
            if matches:
                findings.append(
                    finding(
                        MODULE,
                        "safe_browsing_threat",
                        "URL is listed as a threat by Google Safe Browsing",
                        Severity.CRITICAL,
                        "Google Safe Browsing matched this URL against known threat lists.",
                        evidence=f"{url} ({', '.join(str(m) for m in matches)})",
                        recommendation="Block this URL and do not interact with the site.",
                        confidence=0.9,
                        metadata={"threat_types": matches, "source": "safe_browsing"},
                    )
                )

        if is_ip_host(host) and ti.abuseipdb_enabled:
            abuse = await ti.abuseipdb_ip(host)
            record["abuseipdb"] = abuse.to_dict()
            score = abuse.data.get("abuse_confidence_score") if abuse.available else None
            if isinstance(score, int) and score >= 50:
                findings.append(
                    finding(
                        MODULE,
                        "abuseipdb_reported_ip",
                        "URL host IP has a poor abuse reputation",
                        Severity.HIGH,
                        f"AbuseIPDB reports an abuse confidence score of {score} for this IP.",
                        evidence=host,
                        recommendation="Block this IP-based URL and verify the sender.",
                        confidence=0.8,
                        metadata={"abuse_confidence_score": score, "source": "abuseipdb"},
                    )
                )

    record["finding_count"] = len(findings)
    return findings, record


async def analyze(email: EmailObject, context: AnalysisContext) -> ModuleResult:
    started = time.monotonic()
    settings = context.settings
    urls = email.urls[: settings.url_analysis_max_urls]

    findings: list[Finding] = []
    records: list[dict] = []
    ti = get_threat_intelligence(settings)

    for index, url in enumerate(urls):
        try:
            url_findings, record = await _analyze_url(
                url,
                settings,
                allow_fetch=settings.url_fetch_enabled and index < MAX_FETCHED_URLS,
                include_ti=index < MAX_TI_URLS,
                ti=ti,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("URL analysis failed for %s", url)
            records.append({"url": url, "error": type(exc).__name__})
            continue
        findings.extend(url_findings)
        records.append(record)

    return build_result(
        MODULE,
        started_at=started,
        findings=findings,
        data={
            "urls_analyzed": len(urls),
            "urls_total": len(email.urls),
            "truncated": len(email.urls) > len(urls),
            "urls": records,
        },
    )
