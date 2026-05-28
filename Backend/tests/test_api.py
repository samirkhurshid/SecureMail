"""
Tests for Email Security Gateway API.
Run: pytest tests/ -v
"""

import pytest
import json
from fastapi.testclient import TestClient
from app.main import app
from app.services import email_parser, risk_scorer

client = TestClient(app)

# ── Sample data ───────────────────────────────────────────────────

PHISHING_EMAIL = """From: PayPal Support <noreply@paypa1-support.ru>
Reply-To: help@secure-login.net
To: victim@example.com
Subject: Urgent: Your account has been suspended
Date: Mon, 26 May 2026 10:00:00 +0000
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Received: from mail.evil.ru (mail.evil.ru [185.234.218.47])
  by mx.example.com with ESMTP id abc123

Dear Customer, verify your account immediately or it will be closed.
Click here: http://paypa1-login.ru/verify?token=abc
Your password and username are required to restore access.
"""

CLEAN_EMAIL = """From: Alice Smith <alice@legitimate.com>
To: bob@example.com
Subject: Meeting tomorrow
Date: Mon, 26 May 2026 09:00:00 +0000
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Received: from mail.legitimate.com (mail.legitimate.com [198.51.100.1])
  by mx.example.com with ESMTP

Hi Bob, just confirming our meeting tomorrow at 2pm. See you then!
"""

HEADERS_ONLY = """Received: from mail.evil.ru (mail.evil.ru [185.234.218.47])
  by mx.example.com with ESMTP
From: Apple Support <noreply@mail2036.xyz>
Reply-To: support@secure-apple.net
Subject: Your Apple ID was accessed
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail
"""


# ── Health checks ─────────────────────────────────────────────────

def test_root():
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "online"


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


# ── Email parser unit tests ───────────────────────────────────────

def test_parse_phishing_email():
    parsed = email_parser.parse_raw_email(PHISHING_EMAIL)
    assert parsed["headers"]["from_domain"] == "paypa1-support.ru"
    assert parsed["headers"]["display_name_spoof"] is True
    assert parsed["headers"]["reply_to_mismatch"] is True
    assert parsed["headers"]["originating_ip"] == "185.234.218.47"
    assert len(parsed["urls"]) >= 1


def test_parse_clean_email():
    parsed = email_parser.parse_raw_email(CLEAN_EMAIL)
    assert parsed["headers"]["display_name_spoof"] is False
    assert parsed["headers"]["reply_to_mismatch"] is False


def test_url_extraction():
    parsed = email_parser.parse_raw_email(PHISHING_EMAIL)
    urls = parsed["urls"]
    assert any("paypa1-login.ru" in u["url"] for u in urls)
    assert any(u["is_lookalike"] for u in urls)


def test_auth_header_parsing():
    auth_str = "mx.example.com; spf=fail; dkim=none; dmarc=fail"
    result = email_parser.parse_auth_header(auth_str)
    assert result["spf"] == "fail"
    assert result["dkim"] == "none"
    assert result["dmarc"] == "fail"


def test_auth_header_pass():
    auth_str = "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
    result = email_parser.parse_auth_header(auth_str)
    assert result["spf"] == "pass"
    assert result["dkim"] == "pass"


def test_ip_extraction():
    parsed = email_parser.parse_raw_email(PHISHING_EMAIL)
    assert parsed["headers"]["originating_ip"] == "185.234.218.47"


# ── Risk scorer unit tests ────────────────────────────────────────

def test_risk_score_high_for_phishing():
    auth = {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    phishing = {
        "urgency_language": True, "credential_request": True,
        "domain_lookalike": True, "display_name_spoof": True,
        "reply_to_mismatch": True, "subject_suspicious": False,
        "shortened_urls": False,
    }
    score, level, threats = risk_scorer.compute_email_risk_score(
        auth=auth, phishing=phishing, urls=[], attachments=[], ip_reputation=None, headers={}
    )
    assert score >= 70
    assert level in ("high", "critical")
    assert "phishing" in threats


def test_risk_score_clean():
    auth = {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    phishing = {
        "urgency_language": False, "credential_request": False,
        "domain_lookalike": False, "display_name_spoof": False,
        "reply_to_mismatch": False, "subject_suspicious": False,
        "shortened_urls": False,
    }
    score, level, threats = risk_scorer.compute_email_risk_score(
        auth=auth, phishing=phishing, urls=[], attachments=[], ip_reputation=None, headers={}
    )
    assert score < 20
    assert level in ("clean", "low")


def test_risk_summary_generation():
    summary = risk_scorer.summarise(87, "critical", ["phishing", "malicious_attachment"])
    assert "CRITICAL" in summary
    assert "87" in summary


# ── API endpoint tests ────────────────────────────────────────────

def test_scan_email_phishing():
    resp = client.post("/api/scan/email", json={"raw_email": PHISHING_EMAIL})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] > 30
    assert data["risk_level"] in ("medium", "high", "critical")
    assert data["authentication"]["spf"] == "fail"
    assert data["header_analysis"]["display_name_spoof"] is True


def test_scan_email_clean():
    resp = client.post("/api/scan/email", json={"raw_email": CLEAN_EMAIL})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] < 40
    assert data["authentication"]["spf"] == "pass"


def test_scan_email_no_input():
    resp = client.post("/api/scan/email", json={})
    assert resp.status_code == 400


def test_scan_url():
    resp = client.post("/api/scan/url", json={"url": "https://example.com"})
    assert resp.status_code == 200
    assert "scan_result" in resp.json()


def test_scan_url_empty():
    resp = client.post("/api/scan/url", json={"url": "  "})
    assert resp.status_code == 422


def test_check_ip():
    resp = client.post("/api/scan/ip", json={"ip": "8.8.8.8"})
    assert resp.status_code == 200
    assert "result" in resp.json()


def test_header_analysis():
    resp = client.post("/api/headers/analyze", json={"raw_headers": HEADERS_ONLY})
    assert resp.status_code == 200
    data = resp.json()
    assert data["authentication"]["spf"] == "fail"
    assert data["sender"]["display_name_spoof"] is True
    assert data["originating_ip"] == "185.234.218.47"


def test_demo_scan():
    resp = client.get("/api/scan/demo")
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] > 0
    assert "scan_id" in data


# ── Forensics tests ───────────────────────────────────────────────

def test_forensics_list():
    resp = client.get("/api/forensics/")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "logs" in data


def test_forensics_stats():
    resp = client.get("/api/forensics/stats")
    assert resp.status_code == 200
    assert "total" in resp.json()


def test_forensics_export_json():
    resp = client.get("/api/forensics/export/json")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"


def test_forensics_export_csv():
    resp = client.get("/api/forensics/export/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]


def test_forensics_not_found():
    resp = client.get("/api/forensics/nonexistent-id-12345")
    assert resp.status_code == 404


# ── Advanced Heuristics Tests ────────────────────────────────────

def test_levenshtein_distance():
    from app.services.email_parser import levenshtein_distance
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("google", "g00gle") == 2
    assert levenshtein_distance("apple", "apple") == 0


def test_check_domain_lookalike():
    from app.services.email_parser import _check_domain_lookalike
    is_look, brand = _check_domain_lookalike("paypa1-support.com")
    assert is_look is True
    assert brand == "paypal"
    
    is_look, brand = _check_domain_lookalike("legitimate.com")
    assert is_look is False


def test_audit_received_hops():
    from app.services.email_parser import audit_received_hops
    headers = [
        "Received: from mail.evil.ru (mail.evil.ru [185.234.218.47]) by mx.example.com with ESMTP id abc123",
        "Received: from internal.relay.local by mail.evil.ru with ESMTP"
    ]
    audit = audit_received_hops(headers)
    assert audit["hop_count"] == 2
    assert len(audit["hops"]) == 2
    assert audit["hops"][0]["ip"] == "185.234.218.47"


def test_scan_weighted_keywords():
    from app.services.email_parser import scan_weighted_keywords
    content = "This is an URGENT request! Verify your account credentials now by clicking here and entering your password."
    score, matches = scan_weighted_keywords(content)
    assert score > 50
    assert any(m["keyword"] == "password" for m in matches)

