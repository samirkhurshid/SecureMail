"""
Regression test suite for False Positive Hotfix:
Verifies that legitimate recruitment, newsletter, and enterprise notification emails
using AWS S3, Google Fonts, and standard legal disclaimers are accurately identified as CLEAN.
"""

import pytest
from app.services.email_parser import parse_raw_email, scan_weighted_keywords, parse_auth_header
from app.services.homograph_service import evaluate_domain_homograph
from app.services.risk_scorer import compute_email_risk_score
from app.services.ml_classifier import predict_phishing_probability


def test_campus_recruitment_email_fp_hotfix():
    """
    Test case based on the exact user-reported false positive:
    Sender: notifications@pod.ai
    Subject: Reminder: Drive registration for Polestar Consulting Pvt Ltd closes at 09:30 AM today for 2027 batch.
    Links: fonts.googleapis.com, notification-ms-static.s3.amazonaws.com
    Auth: SPF=pass, DKIM=pass, DMARC=pass
    IP: 54.240.100.16 (Amazon SES)
    """
    raw_email = """Received: from a100-16.smtp-out.ap-south-1.amazonses.com ([54.240.100.16]) by mx.google.com with ESMTPS id abc123; Fri, 14 Aug 2026 19:16:54 -0700
Authentication-Results: mx.google.com; spf=pass (google.com: domain of notifications@pod.ai designates 54.240.100.16 as permitted sender) smtp.mailfrom=notifications@pod.ai; dkim=pass header.i=@pod.ai; dmarc=pass (p=REJECT) header.from=pod.ai
From: "POD" <notifications@pod.ai>
To: student@university.ac.in
Subject: Reminder: Drive registration for Polestar Consulting Pvt Ltd closes at 09:30 AM today for 2027 batch.
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<head>
  <link href="https://fonts.googleapis.com/css?family=Ubuntu:300,400,500,700" rel="stylesheet"/>
</head>
<body>
  <p>Dear Student,</p>
  <p>This is a reminder that drive registration for Polestar Consulting Pvt Ltd closes at 09:30 AM today for the 2027 batch.</p>
  <img src="https://notification-ms-static.s3.amazonaws.com/Calyx/images/confetti.png" alt="confetti"/>
  <img src="https://notification-ms-static.s3.amazonaws.com/Calyx/images/calendar.png" alt="calendar"/>
  <p>Please login to your placement portal to complete registration.</p>
  <p><a href="https://pod.ai/student/drives">Click here to view drive details</a></p>
  <hr/>
  <p style="font-size:10px; color:#888;">
    This email and any files transmitted with it are confidential and intended solely for the use of the individual or entity to whom they are addressed. Any unauthorized access, disclosure or copying is strictly prohibited. If you received this message in error, please notify the sender.
  </p>
</body>
</html>
"""
    parsed = parse_raw_email(raw_email)
    headers = parsed.get("headers", {})
    auth = headers.get("authentication_results", "")
    from app.services.email_parser import parse_auth_header
    auth_dict = parse_auth_header(auth)
    
    # 1. Homograph Check on links
    for u in parsed.get("urls", []):
        homo = evaluate_domain_homograph(u["domain"])
        assert homo["is_lookalike"] is False, f"Domain {u['domain']} should not be marked lookalike"
        assert homo["risk_level"] == "clean"

    # 2. Risk Scorer Evaluation
    score, level, threats = compute_email_risk_score(
        auth=auth_dict,
        phishing=parsed.get("phishing_indicators", {}),
        urls=parsed.get("urls", []),
        attachments=parsed.get("attachments", []),
        ip_reputation={"abuse_confidence_score": 0, "risk_level": "clean", "is_tor": False},
        headers=headers,
        hop_audit=parsed.get("received_hop_audit", {}),
        weighted_phishing=parsed.get("weighted_phishing_analysis", {})
    )

    assert level == "clean" or score <= 15, f"Expected clean score, got {score} ({level})"

    # 3. ML Inference Evaluation
    ml_input = {
        **parsed,
        "authentication": auth_dict,
        "phishing": parsed.get("phishing_indicators", {})
    }
    ml_result = predict_phishing_probability(ml_input)
    assert ml_result["is_phishing"] is False
    assert ml_result["probability"] < 0.35
