"""
Unit & Integration Tests for SOC Forensic PDF Report Generator
"""

import pytest
from app.services.report_generator import generate_forensic_pdf, defang_ioc


def test_defang_ioc():
    """Verify malicious URLs, domains, and IPs are properly defanged."""
    assert defang_ioc("http://evil-phish.ru/login") == "hxxp://evil-phish[.]ru/login"
    assert defang_ioc("https://secure.paypal.com") == "hxxps://secure[.]paypal[.]com"
    assert defang_ioc("185.234.218.47") == "185[.]234[.]218[.]47"
    assert defang_ioc("user@domain.com") == "user@domain[.]com"
    assert defang_ioc("") == ""


def test_generate_forensic_pdf_clean_email():
    """Verify PDF generation on a benign clean email."""
    scan_data = {
        "scan_id": "INC-TEST-0001",
        "timestamp": "2026-08-16 08:30:00 UTC",
        "sender_email": "Windowsinsiderprogram@e-mails.microsoft.com",
        "subject": "See what is coming next in Windows 11",
        "risk_score": 0,
        "risk_level": "clean",
        "threat_types": ["clean"],
        "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass", "arc": "pass"},
        "headers": {
            "from_email": "Windowsinsiderprogram@e-mails.microsoft.com",
            "from_domain": "e-mails.microsoft.com",
            "originating_ip": "66.117.24.181",
            "ip_reputation": {"abuse_confidence_score": 0, "country_code": "US", "isp": "Microsoft Corporation"}
        },
        "urls": [
            {"url": "https://cdn-dynmedia-1.microsoft.com/logo.png", "is_official": True, "domain": "cdn-dynmedia-1.microsoft.com"}
        ],
        "attachments": [],
        "phishing_indicators": {"mitre_techniques": []},
        "ml_classifier": {"probability": 0.02, "confidence": "low", "verdict": "clean", "top_signals": []},
        "received_hop_audit": {"hops": []}
    }
    
    pdf_bytes = generate_forensic_pdf(scan_data, incident_id="INC-TEST-0001")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-1.4") or pdf_bytes.startswith(b"%PDF")


def test_generate_forensic_pdf_phishing_email():
    """Verify PDF generation on a high-risk multi-hop phishing email."""
    scan_data = {
        "scan_id": "INC-TEST-0002",
        "timestamp": "2026-08-16 08:45:00 UTC",
        "sender_email": "payroll-update@evil-lookalike-domain.ru",
        "subject": "URGENT: Mandatory Wire Authorization Required",
        "risk_score": 95,
        "risk_level": "critical",
        "threat_types": ["phishing", "homograph", "extortion"],
        "authentication": {"spf": "fail", "dkim": "fail", "dmarc": "fail", "arc": "none"},
        "headers": {
            "from_email": "payroll-update@evil-lookalike-domain.ru",
            "from_domain": "evil-lookalike-domain.ru",
            "originating_ip": "185.234.218.47",
            "ip_reputation": {"abuse_confidence_score": 98, "country_code": "RU", "isp": "Bad Hosting LLC"}
        },
        "urls": [
            {"url": "http://evil-lookalike-domain.ru/login", "is_lookalike": True, "domain": "evil-lookalike-domain.ru"},
            {"url": "http://paypa1-support.ru/verify", "is_homograph": True, "domain": "paypa1-support.ru"}
        ],
        "attachments": [
            {"filename": "invoice_malicious.exe", "size_bytes": 1048576, "is_malicious": True, "is_dangerous_ext": True, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        ],
        "phishing_indicators": {
            "mitre_techniques": [
                "T1566.002 (Spearphishing Link)",
                "T1036 (Masquerading)",
                "T1657 (Financial Theft — Extortion)"
            ]
        },
        "ml_classifier": {
            "probability": 0.94,
            "confidence": "high",
            "verdict": "phishing",
            "top_signals": [
                {"label": "Direct Credential Request", "weight_delta": 0.85, "direction": "threat"},
                {"label": "SPF Authentication Failed", "weight_delta": 0.65, "direction": "threat"}
            ]
        },
        "received_hop_audit": {
            "hops": [
                {"hop_number": 1, "ip": "185.234.218.47", "host_from": "mail.evil.ru", "city": "Moscow", "country": "Russia", "country_code": "RU", "isp": "Bad Hosting LLC", "delay_seconds": 0},
                {"hop_number": 2, "ip": "50.110.8.10", "host_from": "relay01.frankfurt.de", "city": "Frankfurt", "country": "Germany", "country_code": "DE", "isp": "Cloud Relay DE", "delay_seconds": 20}
            ]
        }
    }
    
    pdf_bytes = generate_forensic_pdf(scan_data, incident_id="INC-TEST-0002")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 4000
    assert pdf_bytes.startswith(b"%PDF")


@pytest.mark.asyncio
async def test_pdf_report_endpoint():
    """Verify the /api/scan/report/pdf endpoint returns binary application/pdf."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "scan_id": "INC-TEST-API",
            "risk_score": 85,
            "risk_level": "high",
            "sender_email": "test@phish.com",
            "subject": "Test Incident",
            "threat_types": ["phishing"]
        }
        res = await client.post("/api/scan/report/pdf", json=payload)
        assert res.status_code == 200
        assert "application/pdf" in res.headers.get("content-type", "")
        assert len(res.content) > 1000
        assert res.content.startswith(b"%PDF")
