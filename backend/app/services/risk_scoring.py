from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.modules.base import SEVERITY_ORDER
from app.schemas.analysis import EmailObject, ModuleResult
from app.schemas.enums import (
    AnalysisStatus,
    AuthStatus,
    Classification,
    ModuleName,
    RiskLevel,
    Severity,
)

SEVERITY_WEIGHTS: dict[str, int] = {
    "informational": 0,
    "low": 10,
    "medium": 25,
    "high": 45,
    "critical": 60,
}

DIMINISHING_FACTORS = (1.0, 0.6, 0.4, 0.3, 0.2, 0.15, 0.1)
VERIFIED_THREAT_TYPES = {
    "virustotal_malicious_url",
    "safe_browsing_threat",
    "malware_detected",
    "malicious_attachment_hash",
}
VERIFIED_FLOOR = 80

CATEGORY_MAP: dict[str, str] = {
    "reply_to_mismatch": "identity_reply_to",
    "header_reply_to_mismatch": "identity_reply_to",
    "return_path_mismatch": "identity_return_path",
    "header_return_path_mismatch": "identity_return_path",
    "domain_impersonation": "impersonation",
    "typosquatting_domain": "impersonation",
    "brand_subdomain_impersonation": "impersonation",
    "display_name_impersonation": "impersonation",
    "nonexistent_domain": "domain_delivery",
    "no_mx_records": "domain_delivery",
    "virustotal_malicious_url": "verified_threat",
    "safe_browsing_threat": "verified_threat",
    "malware_detected": "verified_threat",
    "malicious_attachment_hash": "verified_threat",
    "dangerous_attachment_executable": "dangerous_attachment",
    "dangerous_attachment_script": "dangerous_attachment",
    "dangerous_attachment_macro": "dangerous_attachment",
    "dangerous_attachment_shortcut": "dangerous_attachment",
    "dangerous_attachment_disk_image": "dangerous_attachment",
    "dangerous_attachment_web": "dangerous_attachment",
    "dangerous_attachment_archive": "dangerous_attachment",
    "missing_spf_record": "spf_policy",
}

EXPECTED_MODULES = {
    ModuleName.URL_ANALYSIS,
    ModuleName.DOMAIN_REPUTATION,
    ModuleName.HEADER_ANALYSIS,
    ModuleName.CONTENT_ANALYSIS,
    ModuleName.ATTACHMENT_ANALYSIS,
    ModuleName.ML_CLASSIFICATION,
}


@dataclass
class RiskAssessment:
    classification: Classification
    risk_score: int
    risk_level: RiskLevel
    report: dict[str, Any] = field(default_factory=dict)
    finding_contributions: list[int] = field(default_factory=list)


def _level_for(score: int) -> RiskLevel:
    if score <= 19:
        return RiskLevel.LOW
    if score <= 39:
        return RiskLevel.GUARDED
    if score <= 59:
        return RiskLevel.MEDIUM
    if score <= 79:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _confidence_factor(confidence: float | None) -> float:
    if confidence is None:
        return 1.0
    bounded = max(0.0, min(1.0, confidence))
    return 0.5 + 0.5 * bounded


def _ml_component(ml_result: ModuleResult | None) -> tuple[int, dict[str, Any] | None]:
    if ml_result is None or ml_result.status != AnalysisStatus.COMPLETED:
        return 0, None
    prediction = str(ml_result.data.get("prediction", "")).upper()
    confidence = ml_result.data.get("confidence")
    try:
        confidence_value = float(confidence)
    except (TypeError, ValueError):
        confidence_value = 0.0
    confidence_value = max(0.0, min(1.0, confidence_value))

    weight = {"PHISHING": 20, "SPAM": 8, "LEGITIMATE": -10}.get(prediction, 0)
    contribution = int(round(weight * confidence_value))
    signal = {
        "label": prediction,
        "confidence": round(confidence_value, 4),
        "contribution": contribution,
        "model_version": ml_result.data.get("model_version"),
    }
    return contribution, signal


def assess(module_results: list[ModuleResult], email: EmailObject) -> RiskAssessment:
    flat: list[tuple[ModuleName, Any]] = []
    for result in module_results:
        for item in result.findings:
            flat.append((result.module, item))

    category_entries: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for module, item in flat:
        category = CATEGORY_MAP.get(item.type, item.type)
        if category not in category_entries:
            category_entries[category] = {
                "category": category,
                "finding": item,
                "module": module,
                "suppressed": 0,
                "severity": item.severity,
            }
            order.append(category)
            continue
        entry = category_entries[category]
        entry["suppressed"] += 1
        current_rank = SEVERITY_ORDER[entry["severity"]]
        new_rank = SEVERITY_ORDER[item.severity]
        if new_rank > current_rank:
            entry["severity"] = item.severity
            entry["finding"] = item
            entry["module"] = module

    entries = [category_entries[name] for name in order]
    entries.sort(
        key=lambda entry: (
            SEVERITY_ORDER[entry["severity"]],
            entry["finding"].confidence or 0.0,
        ),
        reverse=True,
    )

    contributions_reported: list[dict[str, Any]] = []
    base_score = 0.0
    for index, entry in enumerate(entries):
        weight = SEVERITY_WEIGHTS[entry["severity"].value]
        factor = _confidence_factor(entry["finding"].confidence)
        contribution = weight * factor
        multiplier = DIMINISHING_FACTORS[min(index, len(DIMINISHING_FACTORS) - 1)]
        effective = contribution * multiplier
        base_score += effective
        entry["contribution"] = int(round(effective))
        entry["raw_contribution"] = int(round(contribution))
        contributions_reported.append(
            {
                "category": entry["category"],
                "finding_type": entry["finding"].type,
                "title": entry["finding"].title,
                "severity": entry["severity"].value,
                "module": entry["module"].value,
                "contribution": entry["contribution"],
                "raw_contribution": entry["raw_contribution"],
                "evidence": entry["finding"].evidence,
                "suppressed_duplicates": entry["suppressed"],
            }
        )

    ml_result = next(
        (r for r in module_results if r.module == ModuleName.ML_CLASSIFICATION), None
    )
    ml_contribution, ml_signal = _ml_component(ml_result)

    score = int(round(base_score)) + ml_contribution

    verified = any(entry["finding"].type in VERIFIED_THREAT_TYPES for entry in entries)
    floor_applied = False
    if verified and score < VERIFIED_FLOOR:
        score = VERIFIED_FLOOR
        floor_applied = True

    score = max(0, min(100, score))

    unknown_modules: list[dict[str, str]] = []
    completed_modules = 0
    for result in module_results:
        if result.status == AnalysisStatus.COMPLETED:
            completed_modules += 1
        elif result.status in {
            AnalysisStatus.FAILED,
            AnalysisStatus.UNAVAILABLE,
            AnalysisStatus.SKIPPED,
        }:
            unknown_modules.append(
                {
                    "module": result.module.value,
                    "status": result.status.value,
                    "reason": result.error or "No result was produced",
                }
            )

    expected = len(EXPECTED_MODULES)
    assessment_confidence = round(min(1.0, completed_modules / expected), 2)

    positives = _positives(module_results, email)
    recommendations = _recommendations(entries)

    if verified or score >= 40:
        classification = Classification.PHISHING
    elif score >= 20:
        classification = Classification.SPAM
    else:
        classification = Classification.LEGITIMATE

    explanation = _explain(
        score=score,
        classification=classification,
        entries=entries,
        ml_signal=ml_signal,
        unknown_modules=unknown_modules,
        floor_applied=floor_applied,
        verified=verified,
    )

    finding_contributions = _map_finding_contributions(
        flat, entries, category_entries
    )

    report = {
        "classification": classification.value,
        "risk_score": score,
        "risk_level": _level_for(score).value,
        "assessment_confidence": assessment_confidence,
        "explanation": explanation,
        "recommendations": recommendations,
        "positives": positives,
        "unknowns": unknown_modules,
        "contributions": contributions_reported,
        "ml_prediction": ml_signal,
        "verified_threat": verified,
        "verified_floor_applied": floor_applied,
        "module_statuses": {
            result.module.value: result.status.value for result in module_results
        },
    }

    return RiskAssessment(
        classification=classification,
        risk_score=score,
        risk_level=_level_for(score),
        report=report,
        finding_contributions=finding_contributions,
    )


def _map_finding_contributions(flat, entries, category_entries) -> list[int]:
    assigned: dict[str, int] = {
        entry["category"]: entry.get("contribution", 0) for entry in entries
    }
    contributions: list[int] = []
    seen: set[str] = set()
    for _module, item in flat:
        category = CATEGORY_MAP.get(item.type, item.type)
        if category in seen:
            contributions.append(0)
            continue
        seen.add(category)
        contributions.append(assigned.get(category, 0))
    return contributions


def _positives(module_results: list[ModuleResult], email: EmailObject) -> list[str]:
    positives: list[str] = []
    for result in module_results:
        module = result.module
        if result.status != AnalysisStatus.COMPLETED:
            continue
        if module in {ModuleName.URL_ANALYSIS, ModuleName.ATTACHMENT_ANALYSIS, ModuleName.CONTENT_ANALYSIS}:
            if not result.findings:
                label = {
                    ModuleName.URL_ANALYSIS: "No suspicious URLs were detected",
                    ModuleName.ATTACHMENT_ANALYSIS: "No dangerous attachments were detected",
                    ModuleName.CONTENT_ANALYSIS: "No content-based indicators were detected",
                }[module]
                positives.append(label)
        if module == ModuleName.HEADER_ANALYSIS:
            auth = result.data.get("authentication") or {}
            for mechanism in ("spf", "dkim", "dmarc"):
                if auth.get(mechanism) == AuthStatus.PASS.value:
                    positives.append(f"{mechanism.upper()} reported as passing")
    if not email.attachments:
        positives.append("The message has no attachments")
    return positives


def _recommendations(entries) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for entry in entries:
        recommendation = entry["finding"].recommendation
        if recommendation and recommendation not in seen:
            seen.add(recommendation)
            ordered.append(recommendation)
    if not ordered:
        ordered.append("No action required, but continue to treat unexpected requests cautiously.")
    return ordered[:12]


def _explain(
    *,
    score: int,
    classification: Classification,
    entries,
    ml_signal: dict[str, Any] | None,
    unknown_modules: list[dict[str, str]],
    floor_applied: bool,
    verified: bool,
) -> str:
    parts = [
        f"Risk score {score}/100, classified as {classification.value}."
    ]
    if entries:
        top = entries[:3]
        descriptions = ", ".join(
            f"{entry['finding'].title} (+{entry['contribution']})" for entry in top
        )
        parts.append(f"Main contributors: {descriptions}.")
    else:
        parts.append("No security findings contributed to the score.")
    if ml_signal:
        parts.append(
            f"The ML classifier predicted {ml_signal['label']} with "
            f"{ml_signal['confidence']:.2f} confidence "
            f"({ml_signal['contribution']:+d} points)."
        )
    else:
        parts.append("No ML prediction was available.")
    if floor_applied:
        parts.append(
            "Verified malicious evidence raised the score to the critical floor; "
            "a legitimate ML prediction cannot override it."
        )
    elif verified:
        parts.append("Verified malicious indicators were present.")
    if unknown_modules:
        names = ", ".join(item["module"] for item in unknown_modules)
        parts.append(
            f"Unavailable or failed modules ({names}) mean parts of the assessment are "
            "unknown and must not be interpreted as safe."
        )
    return " ".join(parts)
