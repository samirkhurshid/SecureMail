"""
SecureMail — Automated Test Runner for Sample Malicious & Clean Emails.
Evaluates all sample .eml files against SecureMail's parsing, heuristic,
homograph, optical quishing, and risk scoring engines.
"""

import os
import sys
import glob

# Ensure utf-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure backend modules can be imported
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "Backend"))

from app.services import email_parser, risk_scorer, qr_scanner, homograph_service, ml_classifier

SAMPLE_DIR = os.path.dirname(os.path.abspath(__file__))

EXPECTED_RESULTS = {
    "01_credential_phishing.eml": {
        "min_score": 80,
        "expected_level": ["high", "critical"],
        "threat_keywords": ["phishing", "spoofing"],
    },
    "02_eicar_malware_attachment.eml": {
        "min_score": 50,
        "expected_level": ["medium", "high", "critical"],
        "threat_keywords": ["malicious_attachment"],
    },
    "03_quishing_qr_code.eml": {
        "min_score": 60,
        "expected_level": ["high", "critical"],
        "threat_keywords": ["quishing"],
    },
    "04_extortion_blackmail_btc.eml": {
        "min_score": 75,
        "expected_level": ["high", "critical"],
        "threat_keywords": ["extortion", "social_engineering"],
    },
    "05_ceo_impersonation_bec.eml": {
        "min_score": 60,
        "expected_level": ["high", "critical"],
        "threat_keywords": ["spoofing", "social_engineering", "phishing"],
    },
    "06_macro_malware_docm.eml": {
        "min_score": 30,
        "expected_level": ["medium", "high", "critical"],
        "threat_keywords": ["malicious_attachment"],
    },
    "07_clean_legitimate_newsletter.eml": {
        "max_score": 15,
        "expected_level": ["clean", "low"],
        "threat_keywords": ["clean"],
    },
}


def test_file(filepath: str) -> dict:
    filename = os.path.basename(filepath)
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        raw_email = f.read()

    parsed = email_parser.parse_raw_email(raw_email)
    headers = parsed.get("headers", {})
    phishing = parsed.get("phishing_indicators", {})
    urls = parsed.get("urls", [])
    attachments = parsed.get("attachments", [])
    auth = email_parser.parse_auth_header(headers.get("authentication_results", ""))

    # Step 1: Base Risk Score
    score, risk_level, threat_types = risk_scorer.compute_email_risk_score(
        auth=auth,
        phishing=phishing,
        urls=urls,
        attachments=attachments,
        ip_reputation=None,
        headers=headers,
        hop_audit=parsed.get("received_hop_audit"),
        weighted_phishing=parsed.get("weighted_phishing_analysis"),
    )

    # Step 2: Quishing Optical QR Analysis
    quishing_result = qr_scanner.scan_email_for_quishing(raw_email, parsed)
    if quishing_result.get("has_qr_codes") and quishing_result.get("risk_score", 0) >= 35:
        score = max(score, quishing_result["risk_score"])
        if "quishing" not in threat_types:
            threat_types.append("quishing")
        if score >= 80:
            risk_level = "critical"
        elif score >= 55:
            risk_level = "high"
        elif score >= 35:
            risk_level = "medium"

    # Step 3: Domain Homograph Analysis
    from_dom = headers.get("from_domain", "")
    if from_dom:
        hv = homograph_service.evaluate_domain_homograph(from_dom)
        if hv.get("is_lookalike"):
            score = max(score, hv.get("risk_score", 85))
            if "homograph_impersonation" not in threat_types:
                threat_types.append("homograph_impersonation")
            risk_level = "critical" if score >= 80 else "high"

    for u in urls:
        ha = u.get("homograph_analysis") or {}
        if ha.get("is_lookalike"):
            score = max(score, ha.get("risk_score", 80))
            if "homograph_impersonation" not in threat_types:
                threat_types.append("homograph_impersonation")
            risk_level = "critical" if score >= 80 else "high"

    if risk_level == "clean":
        threat_types = ["clean"]

    return {
        "filename": filename,
        "score": score,
        "risk_level": risk_level,
        "threat_types": threat_types,
        "attachments_count": len(attachments),
        "urls_count": len(urls),
        "has_qr": quishing_result.get("has_qr_codes", False),
        "qr_count": quishing_result.get("qr_count", 0),
        "qr_payloads": [d.get("decoded_payload") for d in quishing_result.get("detections", [])],
        "subject": headers.get("subject", ""),
        "from": headers.get("from_raw", ""),
    }


def main():
    files = sorted(glob.glob(os.path.join(SAMPLE_DIR, "*.eml")))
    print("=" * 80)
    print("  SECUREMAIL TEST SUITE — SAMPLE MALICIOUS & CLEAN EMAIL VERIFICATION")
    print("=" * 80)
    print(f"Loaded {len(files)} test samples from: {SAMPLE_DIR}\n")

    all_passed = True

    for filepath in files:
        fname = os.path.basename(filepath)
        result = test_file(filepath)
        exp = EXPECTED_RESULTS.get(fname, {})

        # Assertions
        passed = True
        reason = []

        if "min_score" in exp and result["score"] < exp["min_score"]:
            passed = False
            reason.append(f"Score {result['score']} < expected min {exp['min_score']}")

        if "max_score" in exp and result["score"] > exp["max_score"]:
            passed = False
            reason.append(f"Score {result['score']} > expected max {exp['max_score']}")

        if "expected_level" in exp and result["risk_level"] not in exp["expected_level"]:
            passed = False
            reason.append(f"Risk level '{result['risk_level']}' not in {exp['expected_level']}")

        if not passed:
            all_passed = False

        status_badge = "✅ PASS" if passed else "❌ FAIL"

        print(f"[{status_badge}] {fname}")
        print(f"       From:        {result['from']}")
        print(f"       Subject:     {result['subject']}")
        print(f"       Score:       {result['score']}/100 ({result['risk_level'].upper()})")
        print(f"       Threats:     {', '.join(result['threat_types'])}")
        if result['has_qr']:
            print(f"       QR Codes:    {result['qr_count']} detected -> {result['qr_payloads']}")
        if result['attachments_count'] > 0:
            print(f"       Attachments: {result['attachments_count']} file(s)")
        if not passed:
            print(f"       ⚠️  Failure Reason: {', '.join(reason)}")
        print("-" * 80)

    print("=" * 80)
    if all_passed:
        print("  🎉 ALL SAMPLE TESTS PASSED PERFECTLY (100% ACCURACY)")
    else:
        print("  ⚠️ SOME SAMPLE TESTS FAILED ASSERTIONS")
    print("=" * 80)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
