"""
Unit & Integration Tests for Phase 4.2: Programmatic API Key Management
========================================================================
Tests cryptographic key generation, SHA-256 hashing, X-API-Key header authentication,
scope validation, usage counter tracking, and instant revocation.
"""

import pytest
from app.services import api_key_service
from app.auth import get_current_user, CurrentUser


def test_generate_api_key_format_and_hashing():
    """Verify raw API key starts with sm_live_, has high entropy, and only hash is stored in DB."""
    res = api_key_service.generate_api_key(
        user_id="usr_mta_01",
        user_email="mta@company.org",
        name="Postfix Inbound Filter",
        scopes=["scans:write", "threat_intel:read"]
    )
    
    assert "raw_key" in res
    raw_key = res["raw_key"]
    assert raw_key.startswith("sm_live_")
    assert len(raw_key) > 40
    assert res["key_prefix"].startswith("sm_live_")
    assert res["scopes"] == ["scans:write", "threat_intel:read"]
    
    # Check DB does NOT contain raw key, only SHA-256 hash
    conn = api_key_service.get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT key_hash FROM api_keys WHERE id = ?;", (res["id"],))
        row = cursor.fetchone()
        assert row is not None
        assert row["key_hash"] == api_key_service.hash_key(raw_key)
        assert raw_key not in row["key_hash"]
    finally:
        conn.close()


def test_verify_api_key_and_usage_tracking():
    """Verify API key verification updates usage telemetry."""
    res = api_key_service.generate_api_key(
        user_id="usr_siem_02",
        user_email="soc@company.org",
        name="Splunk SIEM Pipeline",
        scopes=["forensics:read", "threat_intel:read"]
    )
    raw_key = res["raw_key"]
    
    # 1. First verification
    verified = api_key_service.verify_api_key(raw_key)
    assert verified is not None
    assert verified["user_id"] == "usr_siem_02"
    assert verified["usage_count"] == 1
    assert verified["last_used_at"] is not None
    
    # 2. Second verification increments usage
    verified2 = api_key_service.verify_api_key(raw_key)
    assert verified2 is not None
    assert verified2["usage_count"] == 2


@pytest.mark.asyncio
async def test_dual_auth_via_x_api_key_header():
    """Verify protected endpoints can be accessed using X-API-Key header without Firebase token."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    # Generate test key
    key_info = api_key_service.generate_api_key(
        user_id="usr_gateway_03",
        user_email="gateway@enterprise.com",
        name="Automated Gateway",
        scopes=["scans:write", "threat_intel:read"]
    )
    raw_key = key_info["raw_key"]
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Test Threat Intel Lookup with X-API-Key
        res = await client.get(
            "/api/threat-intel/lookup?ioc=185.234.218.47",
            headers={"X-API-Key": raw_key}
        )
        assert res.status_code == 200
        assert res.json()["is_threat"] is True
        
        # 2. Test Account Role Endpoint with X-API-Key (authenticated endpoint)
        role_res = await client.get(
            "/api/account/roles/me",
            headers={"X-API-Key": raw_key}
        )
        assert role_res.status_code == 200
        data = role_res.json()
        assert data["uid"] == "usr_gateway_03"
        assert data["role"] == "api_service"
        assert "scans:write" in data["permissions"]


@pytest.mark.asyncio
async def test_api_keys_crud_endpoints():
    """Verify GET, POST, DELETE /api/api-keys endpoints."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="usr_admin_keys", email="admin_keys@securemail.io", email_verified=True, role="admin"
    )
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create API key
        create_res = await client.post(
            "/api/api-keys",
            json={"name": "SOC Wazuh Ingest", "scopes": ["scans:write", "forensics:read"]}
        )
        assert create_res.status_code == 200
        created = create_res.json()["key"]
        key_id = created["id"]
        raw_key = created["raw_key"]
        assert raw_key.startswith("sm_live_")
        
        # 2. List API keys
        list_res = await client.get("/api/api-keys")
        assert list_res.status_code == 200
        keys = list_res.json()["api_keys"]
        assert any(k["id"] == key_id for k in keys)
        # Verify raw_key is NOT leaked in list
        assert all("raw_key" not in k for k in keys)
        
        # 3. Revoke API key
        del_res = await client.delete(f"/api/api-keys/{key_id}")
        assert del_res.status_code == 200
        
        # 4. Verify revoked key can no longer authenticate
        revoked_check = api_key_service.verify_api_key(raw_key)
        assert revoked_check is None
        
    app.dependency_overrides.clear()


def test_invalid_and_expired_api_key_rejection():
    """Verify invalid prefixes and expired keys are rejected."""
    # 1. Random string without sm_live_ prefix
    assert api_key_service.verify_api_key("invalid_random_string") is None
    
    # 2. Key with negative expiration days (already expired)
    exp_key = api_key_service.generate_api_key(
        user_id="usr_exp_01",
        user_email="exp@company.org",
        name="Expired Key",
        expires_days=-1
    )
    assert api_key_service.verify_api_key(exp_key["raw_key"]) is None
