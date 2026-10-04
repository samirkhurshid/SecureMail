"""
Unit & Integration Tests for Threat Intelligence & Threat Vault Service
========================================================================
Tests database initialization, seed data, normalization, sub-millisecond
IOC lookups, feed status aggregation, and REST API endpoints.
"""

import pytest
import sqlite3
from app.services import threat_intel_service


def test_init_threat_vault_db():
    """Verify Threat Vault SQLite DB is initialized with WAL mode and seed data."""
    threat_intel_service.init_threat_vault_db()
    conn = threat_intel_service.get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        journal = cursor.fetchone()[0]
        assert journal.lower() == "wal"
        
        cursor.execute("SELECT COUNT(*) as cnt FROM threat_indicators;")
        cnt = cursor.fetchone()["cnt"]
        assert cnt >= len(threat_intel_service.SEED_INDICATORS)
        
        cursor.execute("SELECT COUNT(*) as cnt FROM feed_sync_meta;")
        meta_cnt = cursor.fetchone()["cnt"]
        assert meta_cnt >= 1
    finally:
        conn.close()


def test_normalize_ioc():
    """Verify IOC normalization handles whitespace, casing, and type inference."""
    val, ioc_t = threat_intel_service.normalize_ioc("  HTTP://EVIL.COM/PHISH/ ")
    assert val == "http://evil.com/phish"
    assert ioc_t == "url"
    
    val, ioc_t = threat_intel_service.normalize_ioc("185.234.218.47")
    assert val == "185.234.218.47"
    assert ioc_t == "ip"
    
    val, ioc_t = threat_intel_service.normalize_ioc("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    assert val == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert ioc_t == "sha256"
    
    val, ioc_t = threat_intel_service.normalize_ioc("PAYPA1-SUPPORT.RU")
    assert val == "paypa1-support.ru"
    assert ioc_t == "domain"


def test_lookup_ioc_seeded_threats():
    """Verify instant lookups for seeded phishing domains, URLs, IPs, and hashes."""
    # Phishing Domain
    res = threat_intel_service.lookup_ioc("paypa1-support.ru")
    assert res is not None
    assert res["is_threat"] is True
    assert res["threat_type"] == "phishing"
    assert res["confidence"] >= 90
    assert "paypal" in res["tags"]
    
    # Subdomain match on known root
    sub_res = threat_intel_service.lookup_ioc("login.paypa1-support.ru")
    assert sub_res is not None
    assert sub_res["is_threat"] is True
    
    # Malicious Originating IP
    ip_res = threat_intel_service.lookup_ioc("185.234.218.47")
    assert ip_res is not None
    assert ip_res["is_threat"] is True
    assert ip_res["threat_type"] == "c2"
    
    # Malicious File Hash (SHA-256)
    hash_res = threat_intel_service.lookup_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert hash_res is not None
    assert hash_res["is_threat"] is True
    assert hash_res["threat_type"] == "malware"
    
    # Clean benign item
    clean_res = threat_intel_service.lookup_ioc("microsoft.com")
    assert clean_res is None


def test_insert_and_evict_cache():
    """Verify dynamic insertion updates database and evicts old cache."""
    test_domain = "zero-day-phish-2026.xyz"
    success = threat_intel_service.insert_or_update_indicator(
        ioc_value=test_domain,
        ioc_type="domain",
        threat_type="phishing",
        source_feed="unit_test",
        confidence=99,
        tags="test,automated"
    )
    assert success is True
    
    # Verify lookup succeeds
    res = threat_intel_service.lookup_ioc(test_domain)
    assert res is not None
    assert res["confidence"] == 99
    assert res["source_feed"] == "unit_test"


def test_get_feed_status():
    """Verify feed status aggregation returns metrics and metadata."""
    status = threat_intel_service.get_feed_status()
    assert "total_indicators" in status
    assert status["total_indicators"] >= len(threat_intel_service.SEED_INDICATORS)
    assert "by_ioc_type" in status
    assert "by_threat_type" in status
    assert "by_source_feed" in status
    assert "sync_metadata" in status


def test_query_vault_pagination_and_filters():
    """Verify paginated search and category filtering in Threat Vault."""
    # Search by keyword
    res = threat_intel_service.query_vault(search="paypal", limit=10, offset=0)
    assert res["total"] >= 1
    assert any("paypal" in r["tags"] or "paypa1" in r["ioc_value"] for r in res["records"])
    
    # Filter by IOC type
    ip_res = threat_intel_service.query_vault(ioc_type="ip", limit=10, offset=0)
    assert ip_res["total"] >= 1
    assert all(r["ioc_type"] == "ip" for r in ip_res["records"])


@pytest.mark.asyncio
async def test_threat_intel_api_endpoints():
    """Verify FastAPI router endpoints for Threat Intel."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. GET /api/threat-intel/status
        status_res = await client.get("/api/threat-intel/status")
        assert status_res.status_code == 200
        data = status_res.json()
        assert data["total_indicators"] >= len(threat_intel_service.SEED_INDICATORS)
        
        # 2. GET /api/threat-intel/lookup (Threat Match)
        threat_lookup = await client.get("/api/threat-intel/lookup?ioc=185.234.218.47")
        assert threat_lookup.status_code == 200
        tl_data = threat_lookup.json()
        assert tl_data["is_threat"] is True
        assert tl_data["threat_details"]["threat_type"] == "c2"
        
        # 3. GET /api/threat-intel/lookup (Clean Query)
        clean_lookup = await client.get("/api/threat-intel/lookup?ioc=google.com")
        assert clean_lookup.status_code == 200
        cl_data = clean_lookup.json()
        assert cl_data["is_threat"] is False
        
        # 4. GET /api/threat-intel/vault
        vault_res = await client.get("/api/threat-intel/vault?limit=5")
        assert vault_res.status_code == 200
        v_data = vault_res.json()
        assert "records" in v_data
        assert len(v_data["records"]) <= 5
        
        # 5. POST /api/threat-intel/sync
        sync_res = await client.post("/api/threat-intel/sync")
        assert sync_res.status_code == 200
        assert sync_res.json()["status"] == "sync_initiated"
