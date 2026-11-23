from __future__ import annotations

from app.modules.base import build_result, finding
from app.schemas.enums import AnalysisStatus, ModuleName, Severity
from app.services.risk_scoring import assess
from tests.helpers import make_email

URL = ModuleName.URL_ANALYSIS
DOMAIN = ModuleName.DOMAIN_REPUTATION
ML = ModuleName.ML_CLASSIFICATION


def result(module: ModuleName, *findings, status=AnalysisStatus.COMPLETED, data=None):
    return build_result(module, status=status, findings=list(findings), data=data or {})


def f(module, finding_type, severity, confidence=0.9):
    return finding(
        module,
        finding_type,
        finding_type.replace("_", " ").title(),
        severity,
        "description",
        confidence=confidence,
        recommendation=f"Fix {finding_type}",
    )


def test_clean_email_is_legitimate_and_low():
    assessment = assess([result(URL)], make_email())
    assert assessment.risk_score == 0
    assert assessment.risk_level.value == "LOW"
    assert assessment.classification.value == "LEGITIMATE"
    assert assessment.report["positives"]


def test_duplicate_categories_are_suppressed():
    email = make_email()
    dupes = [
        f(DOMAIN, "domain_impersonation", Severity.HIGH),
        f(DOMAIN, "typosquatting_domain", Severity.HIGH),
    ]
    assessment = assess([result(DOMAIN, *dupes)], email)

    assert assessment.risk_score == 43
    categories = [c for c in assessment.report["contributions"] if c["category"] == "impersonation"]
    assert len(categories) == 1
    assert categories[0]["suppressed_duplicates"] == 1
    assert assessment.risk_score < 45


def test_single_high_finding_scores_medium():
    assessment = assess([result(URL, f(URL, "insecure_scheme", Severity.HIGH))], make_email())
    assert assessment.risk_score == 43
    assert assessment.risk_level.value == "MEDIUM"
    assert assessment.classification.value == "PHISHING"


def test_multiple_signals_reach_phishing():
    findings = [
        f(URL, "typosquatting_domain", Severity.HIGH),
        f(URL, "url_shortener", Severity.MEDIUM),
        f(DOMAIN, "reply_to_mismatch", Severity.MEDIUM),
        f(ModuleName.CONTENT_ANALYSIS, "credential_request", Severity.HIGH),
    ]
    modules = [
        result(URL, findings[0], findings[1]),
        result(DOMAIN, findings[2]),
        result(ModuleName.CONTENT_ANALYSIS, findings[3]),
    ]
    assessment = assess(modules, make_email())
    assert assessment.classification.value == "PHISHING"
    assert assessment.risk_score >= 40
    assert assessment.report["contributions"]


def test_verified_threat_applies_critical_floor():
    assessment = assess(
        [result(URL, f(URL, "virustotal_malicious_url", Severity.CRITICAL))],
        make_email(),
    )
    assert assessment.risk_score >= 80
    assert assessment.risk_level.value == "CRITICAL"
    assert assessment.classification.value == "PHISHING"
    assert assessment.report["verified_floor_applied"] is True


def test_legitimate_ml_never_overrides_verified_threat():
    ml = result(
        ML,
        status=AnalysisStatus.COMPLETED,
        data={"prediction": "LEGITIMATE", "confidence": 0.99, "model_version": "test"},
    )
    assessment = assess(
        [
            result(URL, f(URL, "safe_browsing_threat", Severity.CRITICAL)),
            ml,
        ],
        make_email(),
    )
    assert assessment.classification.value == "PHISHING"
    assert assessment.risk_score >= 80


def test_ml_phishing_alone_contributes_but_does_not_decide():
    ml = result(
        ML,
        status=AnalysisStatus.COMPLETED,
        data={"prediction": "PHISHING", "confidence": 1.0, "model_version": "test"},
    )
    assessment = assess([result(URL), ml], make_email())
    assert assessment.report["ml_prediction"]["contribution"] == 20
    assert assessment.risk_score == 20
    assert assessment.classification.value == "SPAM"


def test_unavailable_modules_are_reported_not_safe():
    modules = [
        result(URL, status=AnalysisStatus.FAILED, data={}),
        result(ML, status=AnalysisStatus.UNAVAILABLE),
        result(DOMAIN),
    ]
    assessment = assess(modules, make_email())

    unknowns = {item["module"]: item["status"] for item in assessment.report["unknowns"]}
    assert unknowns == {"url_analysis": "FAILED", "ml_classification": "UNAVAILABLE"}
    assert assessment.report["assessment_confidence"] < 1
    assert "must not be interpreted as safe" in assessment.report["explanation"]


def test_contributions_align_with_findings():
    modules = [
        result(URL, f(URL, "insecure_scheme", Severity.LOW), f(URL, "ip_address_url", Severity.HIGH)),
        result(DOMAIN, f(DOMAIN, "typosquatting_domain", Severity.HIGH)),
    ]
    assessment = assess(modules, make_email())
    assert len(assessment.finding_contributions) == 3
    assert sum(assessment.finding_contributions) > 0
    assert assessment.finding_contributions[0] > 0
    assert assessment.finding_contributions[1] > 0
    assert assessment.finding_contributions[2] > 0


def test_score_is_capped_at_100():
    many = [f(URL, f"unique_issue_{index}", Severity.CRITICAL) for index in range(12)]
    assessment = assess([result(URL, *many)], make_email())
    assert assessment.risk_score == 100
