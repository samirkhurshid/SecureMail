"""
Validation test suite for the risk scoring engine.
Run with: pytest tests/test_risk_scorer.py -v

This is the regression test that guards against the exact bug reported:
legitimate emails scoring as suspicious, and confirmed threats being under-scored.
"""

from app.services.risk_scorer import compute_email_risk_score
from tests.test_cases import LEGIT_CASES, MALICIOUS_CASES


def _run(case):
    return compute_email_risk_score(
        case["auth"], case["phishing"], case["urls"],
        case["attachments"], case["ip_reputation"], case["headers"],
    )


def test_legitimate_emails_score_clean_or_low():
    """No legitimate email should score medium or above."""
    failures = []
    for case in LEGIT_CASES:
        score, level, _ = _run(case)
        if level not in ("clean", "low"):
            failures.append(f"{case['name']}: scored {score}/100 ({level}) — expected clean/low")
    assert not failures, "False positives found:\n" + "\n".join(failures)


def test_malicious_emails_score_high_or_critical():
    """No real threat should score below high."""
    failures = []
    for case in MALICIOUS_CASES:
        score, level, _ = _run(case)
        if level not in ("high", "critical"):
            failures.append(f"{case['name']}: scored {score}/100 ({level}) — expected high/critical")
    assert not failures, "Missed threats found:\n" + "\n".join(failures)


def test_confirmed_malware_never_diluted_below_high():
    """A VirusTotal-confirmed malware attachment must score >= 75, regardless of other signals."""
    case = next(c for c in MALICIOUS_CASES if "Malware attachment" in c["name"])
    score, level, _ = _run(case)
    assert score >= 75, f"Confirmed malware scored only {score}/100 — ground-truth floor not applied"


def test_missing_headers_alone_does_not_trigger_risk():
    """A plain-text paste with zero other signals should score clean, not just from missing auth headers."""
    case = {
        "headers": {"subject": "hello", "from_domain": "example.com", "from_email": "a@example.com"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": False, "credential_request": False, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": False, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 0,
        },
        "urls": [], "attachments": [], "ip_reputation": None,
    }
    score, level, _ = _run(case)
    assert level == "clean", f"Email with zero real signals scored {score}/100 ({level}) — should be clean"
