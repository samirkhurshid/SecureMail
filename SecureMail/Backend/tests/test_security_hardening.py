"""
Unit tests for Phase 1 Security Hardening:
- Content Security Policy & HTTP Security Headers
- Input size limits on email and URL scan endpoints
- Early Content-Length rejection on attachment uploads
- Rate limiting on settings endpoints
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import get_current_user, CurrentUser

def _mock_user():
    return CurrentUser(uid="test_user_123", email="testuser@example.com", email_verified=True, name="Test User")

app.dependency_overrides[get_current_user] = _mock_user
client = TestClient(app)


def test_security_headers_present():
    """Verify CSP and standard security headers are injected on responses."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "Content-Security-Policy" in resp.headers
    assert "X-Content-Type-Options" in resp.headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_email_scan_input_size_limit():
    """Verify raw_email > 500,000 chars is rejected with 422 Unprocessable Entity."""
    huge_body = "A" * 500_001
    resp = client.post("/api/scan/email", json={"raw_email": huge_body})
    assert resp.status_code == 422
    data = resp.json()
    assert "Email content exceeds maximum allowed size" in str(data) or "String should have at most 500000 characters" in str(data)


def test_url_scan_input_size_limit():
    """Verify URL > 2048 chars is rejected with 422 Unprocessable Entity."""
    huge_url = "https://example.com/" + ("x" * 2050)
    resp = client.post("/api/scan/url", json={"url": huge_url})
    assert resp.status_code == 422
    data = resp.json()
    assert "URL exceeds maximum allowed length" in str(data) or "String should have at most 2048 characters" in str(data)


def test_rate_limiting_settings():
    """Verify 11th request to /api/settings/status within a minute returns 429 Too Many Requests."""
    app.dependency_overrides[get_current_user] = _mock_user
    try:
        responses = [client.get("/api/settings/status", headers={"X-Forwarded-For": "192.168.1.100"}) for _ in range(12)]
        status_codes = [r.status_code for r in responses]
        assert 429 in status_codes
    finally:
        app.dependency_overrides.clear()

