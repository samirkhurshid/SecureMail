"""
Unit & Integration Tests for Phase 3.2: Real-time Scan Integration & Enriched Domain Reputation
================================================================================================
Tests live Threat Vault correlation during email and URL scans, risk score
escalation floors, domain age heuristics, and authentic email immunity.
"""

import pytest
from unittest.mock import AsyncMock, patch
from app.services import threat_intel_service, enrichment_service, virustotal, abuseipdb
from app.auth import get_optional_user, CurrentUser


def test_domain_enrichment_metadata():
    """Verify domain age and infrastructure enrichment logic."""
    # 1. Enterprise domain should be mature and clean
    ent = enrichment_service.enrich_domain_metadata("microsoft.com")
    assert ent["age_category"] == "mature"
    assert ent["age_risk"] == "clean"
    assert ent["is_enterprise_root"] is True
    assert ent["is_disposable"] is False
    
    # 2. High abuse TLD should be flagged as disposable_new
    disp = enrichment_service.enrich_domain_metadata("secure-login-portal.xyz")
    assert disp["age_category"] == "disposable_new"
    assert disp["age_risk"] == "high"
    assert disp["is_high_abuse_tld"] is True
    assert disp["is_disposable"] is True


@pytest.mark.asyncio
async def test_email_scan_threat_intel_url_hit(monkeypatch):
    """Verify email scan with URLhaus/OpenPhish URL escalates to CRITICAL/HIGH risk."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    # Fast mock for external VT calls
    monkeypatch.setattr(virustotal, "scan_url", AsyncMock(return_value={"detections": 0, "positives": 0}))
    
    app.dependency_overrides[get_optional_user] = lambda: CurrentUser(
        uid="test_soc_analyst", email="analyst@securemail.io", email_verified=True, name="SOC Analyst"
    )
    
    raw_email = (
        "From: service@paypa1-support.ru\r\n"
        "To: victim@example.com\r\n"
        "Subject: Urgent: Verify your account immediately\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Please confirm your credentials here: http://paypa1-login.ru/verify?token=abc123&next=account"
    )
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/scan/email", json={"raw_email": raw_email})
        assert res.status_code == 200
        data = res.json()
        
        # Verify Threat Vault hits
        assert "threat_intel_matches" in data
        assert len(data["threat_intel_matches"]) >= 1
        
        # Verify score escalation
        assert data["risk_score"] >= 85
        assert data["risk_level"] == "critical"
        assert any(t in ("threat_intel_phishing", "phishing") for t in data["threat_types"])
        
        # Verify ML classifier also flagged
        assert data["ml_prediction"]["is_phishing"] is True
    
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_email_scan_threat_intel_c2_ip_hit(monkeypatch):
    """Verify email scan with malicious C2 originating IP escalates risk."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    monkeypatch.setattr(abuseipdb, "check_ip", AsyncMock(return_value={"abuse_confidence_score": 0, "is_tor": False}))
    monkeypatch.setattr(virustotal, "scan_url", AsyncMock(return_value={"detections": 0}))
    
    app.dependency_overrides[get_optional_user] = lambda: CurrentUser(
        uid="test_soc_analyst", email="analyst@securemail.io", email_verified=True, name="SOC Analyst"
    )
    
    raw_email = (
        "From: billing@untrusted-network.com\r\n"
        "To: target@example.com\r\n"
        "Subject: Invoice update\r\n"
        "X-Originating-IP: 185.234.218.47\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Please review invoice."
    )
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/scan/email", json={"raw_email": raw_email})
        assert res.status_code == 200
        data = res.json()
        
        assert len(data["threat_intel_matches"]) >= 1
        assert any(m["ioc_value"] == "185.234.218.47" for m in data["threat_intel_matches"])
        assert "c2_infrastructure" in data["threat_types"]
        assert data["risk_score"] >= 80
        
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_clean_authentic_email_preserves_clean_verdict(monkeypatch):
    """Verify legitimate authentic email is unaffected by Threat Vault and remains clean."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    monkeypatch.setattr(virustotal, "scan_url", AsyncMock(return_value={"detections": 0}))
    monkeypatch.setattr(abuseipdb, "check_ip", AsyncMock(return_value={"abuse_confidence_score": 0, "is_tor": False}))
    
    app.dependency_overrides[get_optional_user] = lambda: CurrentUser(
        uid="test_soc_analyst", email="analyst@securemail.io", email_verified=True, name="SOC Analyst"
    )
    
    clean_email = (
        "From: insider-program@e-mails.microsoft.com\r\n"
        "To: user@example.com\r\n"
        "Subject: Welcome to the Windows Insider Program\r\n"
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Thank you for joining the Windows Insider Program. Explore new features at https://insider.windows.com."
    )
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/scan/email", json={"raw_email": clean_email})
        assert res.status_code == 200
        data = res.json()
        
        assert len(data["threat_intel_matches"]) == 0
        assert data["risk_score"] == 0
        assert data["risk_level"] == "clean"
        assert "clean" in data["threat_types"]
        
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_url_scan_threat_vault_correlation(monkeypatch):
    """Verify standalone URL scan cross-references Threat Vault."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    monkeypatch.setattr(virustotal, "scan_url", AsyncMock(return_value={"detections": 0}))
    
    app.dependency_overrides[get_optional_user] = lambda: CurrentUser(
        uid="test_soc_analyst", email="analyst@securemail.io", email_verified=True, name="SOC Analyst"
    )
    
    malware_url = "http://malware-drop-zone.com/invoice.exe"
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/scan/url", json={"url": malware_url})
        assert res.status_code == 200
        data = res.json()
        
        assert data["is_threat"] is True
        assert data["threat_intel_match"] is not None
        assert data["threat_intel_match"]["threat_type"] == "malware_download"
        
    app.dependency_overrides.clear()
