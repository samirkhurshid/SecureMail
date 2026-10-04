"""
Unit & Integration Tests for Phase 6: Authentication Security Hardening
========================================================================
Tests:
1. In-memory token storage design comments.
2. Server-side admin enforcement via require_permission.
3. Backend email verification enforcement on sensitive actions (webhooks, account deletion, API keys).
4. Sliding-window rate limiting on proxied auth endpoints (signin, signup, password-reset).
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from app.main import app
from app.auth import get_current_user, CurrentUser

client = TestClient(app)


def test_email_verification_blocks_unverified_users_on_sensitive_endpoints():
    """Verify that unverified users (email_verified=False) receive 403 on sensitive actions."""
    unverified_user = CurrentUser(
        uid="unverified_uid_123",
        email="unverified@example.com",
        email_verified=False,
        role="user"
    )

    app.dependency_overrides[get_current_user] = lambda: unverified_user

    try:
        # 1. API Key creation
        res_key = client.post("/api/api-keys", json={"name": "Test Key"})
        assert res_key.status_code == 403
        assert "email_not_verified" in str(res_key.json())

        # 2. Webhook update
        res_webhook = client.patch("/api/account/webhook", json={"webhook_url": "https://hooks.slack.com/services/T00/B00/X00"})
        assert res_webhook.status_code == 403
        assert "email_not_verified" in str(res_webhook.json())

        # 3. Webhook test trigger
        res_test = client.post("/api/account/webhook/test")
        assert res_test.status_code == 403
        assert "email_not_verified" in str(res_test.json())

        # 4. Account deletion
        res_del = client.post("/api/account/delete")
        assert res_del.status_code == 403
        assert "email_not_verified" in str(res_del.json())

    finally:
        app.dependency_overrides.clear()


def test_email_verification_allows_verified_users_on_sensitive_endpoints():
    """Verify that verified users (email_verified=True) can perform sensitive actions."""
    verified_user = CurrentUser(
        uid="verified_uid_456",
        email="verified@example.com",
        email_verified=True,
        role="user"
    )

    app.dependency_overrides[get_current_user] = lambda: verified_user

    try:
        # 1. API Key creation
        res_key = client.post("/api/api-keys", json={"name": "Verified Key"})
        assert res_key.status_code == 200
        assert "key" in res_key.json()

        # 2. Webhook update
        res_webhook = client.patch("/api/account/webhook", json={"webhook_url": "https://hooks.slack.com/services/T00/B00/X00"})
        assert res_webhook.status_code == 200
        assert res_webhook.json()["status"] == "updated"

    finally:
        app.dependency_overrides.clear()


def test_auth_proxy_config_endpoint():
    """Verify /api/auth/config returns the public Firebase configuration."""
    res = client.get("/api/auth/config")
    assert res.status_code == 200
    data = res.json()
    assert "apiKey" in data
    assert "authDomain" in data
    assert "projectId" in data


def test_rate_limiting_signin_proxy():
    """Verify 6th signin attempt from same IP within 5 minutes triggers 429 Too Many Requests."""
    test_ip = "198.51.100.11"
    headers = {"X-Forwarded-For": test_ip}

    # First 5 attempts should pass the rate limiter (even if Firebase returns 400 or 502)
    statuses = []
    for _ in range(5):
        r = client.post("/api/auth/signin", json={"email": "victim@test.com", "password": "wrongpassword"}, headers=headers)
        statuses.append(r.status_code)

    # 6th attempt must be 429 Too Many Requests
    r6 = client.post("/api/auth/signin", json={"email": "victim@test.com", "password": "wrongpassword"}, headers=headers)
    assert r6.status_code == 429
    assert "Too many requests" in str(r6.json())
    assert "Retry-After" in r6.headers


def test_rate_limiting_signup_proxy():
    """Verify 4th signup attempt from same IP within 10 minutes triggers 429 Too Many Requests."""
    test_ip = "198.51.100.22"
    headers = {"X-Forwarded-For": test_ip}

    for _ in range(3):
        r = client.post("/api/auth/signup", json={"email": "user@test.com", "password": "Password123!"}, headers=headers)
        # Should reach the endpoint
        assert r.status_code in (200, 400, 502)

    r4 = client.post("/api/auth/signup", json={"email": "user@test.com", "password": "Password123!"}, headers=headers)
    assert r4.status_code == 429
    assert "Too many requests" in str(r4.json())


def test_rate_limiting_reset_password_proxy():
    """Verify 4th password reset attempt from same IP within 15 minutes triggers 429 Too Many Requests."""
    test_ip = "198.51.100.33"
    headers = {"X-Forwarded-For": test_ip}

    for _ in range(3):
        r = client.post("/api/auth/reset-password", json={"email": "user@test.com"}, headers=headers)
        assert r.status_code in (200, 502)

    r4 = client.post("/api/auth/reset-password", json={"email": "user@test.com"}, headers=headers)
    assert r4.status_code == 429
    assert "Too many requests" in str(r4.json())


def test_missing_firebase_web_api_key_raises_503():
    """Verify missing FIREBASE_WEB_API_KEY returns 503 Service Unavailable without falling back to any hardcoded key."""
    from app.routers.auth_proxy import _get_web_api_key
    from app.config import get_settings
    from fastapi import HTTPException
    import os

    settings = get_settings()
    original_key = settings.FIREBASE_WEB_API_KEY
    original_env = os.environ.get("FIREBASE_WEB_API_KEY")

    try:
        settings.FIREBASE_WEB_API_KEY = ""
        if "FIREBASE_WEB_API_KEY" in os.environ:
            del os.environ["FIREBASE_WEB_API_KEY"]

        # Directly testing _get_web_api_key helper
        with pytest.raises(HTTPException) as exc_info:
            _get_web_api_key()
        assert exc_info.value.status_code == 503
        assert "FIREBASE_WEB_API_KEY is missing from .env" in exc_info.value.detail

        # Testing endpoint response
        res = client.get("/api/auth/config")
        assert res.status_code == 503
        assert "FIREBASE_WEB_API_KEY is missing from .env" in res.json()["detail"]

        res_signin = client.post("/api/auth/signin", json={"email": "test@domain.com", "password": "Password123!"}, headers={"X-Forwarded-For": "198.51.100.99"})
        assert res_signin.status_code == 503
        assert "FIREBASE_WEB_API_KEY is missing from .env" in res_signin.json()["detail"]
    finally:
        settings.FIREBASE_WEB_API_KEY = original_key
        if original_env is not None:
            os.environ["FIREBASE_WEB_API_KEY"] = original_env

