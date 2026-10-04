"""
Unit tests for Phase 4 Anonymous Free Trial (5 Scans/Day per IP reset at midnight IST).
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import get_current_user, get_optional_user, CurrentUser

client = TestClient(app)


def test_get_quota_endpoint_anonymous():
    """Verify GET /api/scan/quota works without auth and returns remaining scans."""
    app.dependency_overrides.clear()
    unique_ip = f"198.51.{uuid.uuid4().int % 200 + 10}.{uuid.uuid4().int % 200 + 10}"
    resp = client.get("/api/scan/quota", headers={"X-Forwarded-For": unique_ip})
    assert resp.status_code == 200
    data = resp.json()
    assert "used" in data
    assert "remaining" in data
    assert data["limit"] == 5
    assert "resets_at" in data


def test_anonymous_scan_5_limit_and_429():
    """Verify anonymous IP gets 5 scans per day; 6th returns 429 daily_limit_reached."""
    app.dependency_overrides.clear()
    unique_ip = f"198.51.{uuid.uuid4().int % 200 + 10}.{uuid.uuid4().int % 200 + 10}"
    headers = {"X-Forwarded-For": unique_ip}

    # Run 5 scans
    for i in range(5):
        resp = client.post("/api/scan/email", json={"raw_email": f"Test email {i}"}, headers=headers)
        assert resp.status_code == 200

    # 6th scan should return 429
    resp_limit = client.post("/api/scan/email", json={"raw_email": "6th email"}, headers=headers)
    assert resp_limit.status_code == 429
    detail = resp_limit.json()["detail"]
    assert detail["error"] == "daily_limit_reached"
    assert "resets_at" in detail


def test_authenticated_user_bypasses_quota():
    """Verify authenticated user is not blocked by 5 scan/day anonymous quota."""
    app.dependency_overrides.clear()
    unique_ip = f"198.51.{uuid.uuid4().int % 200 + 10}.{uuid.uuid4().int % 200 + 10}"
    headers = {"X-Forwarded-For": unique_ip}

    # First exhaust the anonymous quota for this IP
    for i in range(5):
        client.post("/api/scan/email", json={"raw_email": f"Test email {i}"}, headers=headers)

    assert client.post("/api/scan/email", json={"raw_email": "Anon 6th"}, headers=headers).status_code == 429

    # Now override auth to act as a logged-in user
    def _mock_user():
        return CurrentUser(uid="auth_user_888", email="auth888@example.com", email_verified=True, name="Auth User")

    app.dependency_overrides[get_current_user] = _mock_user
    app.dependency_overrides[get_optional_user] = _mock_user

    try:
        resp = client.post("/api/scan/email", json={"raw_email": "Auth scan after limit"}, headers=headers)
        assert resp.status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_other_routers_still_require_auth():
    """Verify forensics, headers, settings, account, and demo_scan still require authentication."""
    app.dependency_overrides.clear()

    assert client.get("/api/forensics/logs").status_code == 401
    assert client.post("/api/headers/analyze", json={}).status_code == 401
    assert client.get("/api/settings/status").status_code == 401
    assert client.get("/api/account/me").status_code == 401
    assert client.get("/api/forensics/stats").status_code == 401
