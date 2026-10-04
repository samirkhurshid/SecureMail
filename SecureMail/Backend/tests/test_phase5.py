"""
Unit tests for Phase 5 Retention & Integration features:
- Weekly digest email generation & dispatch script
- Webhook alert configuration & test trigger
- GDPR data export with decrypted login history
"""

import pytest
import json
from fastapi.testclient import TestClient
from app.main import app
from app.auth import get_current_user, get_optional_user, CurrentUser
from app.services import digest, email_sender, user_service, encryption, forensics
from app.scripts.send_weekly_digests import run_weekly_digests

import uuid

def _mock_user():
    return CurrentUser(uid="phase5_user_999", email="phase5@example.com", email_verified=True, name="Phase5 User")

client = TestClient(app)


def test_digest_summary_generation_and_rendering():
    """Verify generate_digest_for_user compiles 7-day stats and renders HTML."""
    uid = f"phase5_digest_test_{uuid.uuid4().hex[:8]}"


    # Initially zero logs
    assert digest.generate_digest_for_user(uid) is None

    # Save a log
    sample_log = {
        "scan_id": "digest-log-1",
        "risk_score": 85,
        "risk_level": "high",
        "subject": "Phishing Test Alert",
        "sender_email": "attacker@bad-domain.com",
        "summary": "High risk phishing email detected.",
    }
    forensics.save_forensic_log(sample_log, user_id=uid)

    summary = digest.generate_digest_for_user(uid)
    assert summary is not None
    assert summary["total_scans"] >= 1
    assert summary["risk_breakdown"]["high"] >= 1
    assert summary["highest_risk_log"]["risk_score"] == 85

    html = digest.render_digest_html("phase5@example.com", summary)
    assert "SecureMail Weekly Digest" in html
    assert "phase5@example.com" in html
    assert "Phishing Test Alert" in html


def test_weekly_digests_script():
    """Verify send_weekly_digests script processes users and respects opt-out."""
    uid = "phase5_script_user"
    user_service.get_or_create_user_doc(uid, email="script_user@example.com", name="Script User")

    # Opt-out
    user_service.update_user_preferences(uid, digest_enabled=False)

    stats = run_weekly_digests()
    assert stats["skipped_opted_out"] >= 1


def test_account_preferences_endpoint():
    """Verify PATCH /api/account/preferences updates digest_enabled."""
    app.dependency_overrides[get_current_user] = _mock_user
    try:
        resp = client.patch("/api/account/preferences", json={"digest_enabled": False})
        assert resp.status_code == 200
        assert resp.json()["digest_enabled"] is False

        # Turn back on
        resp2 = client.patch("/api/account/preferences", json={"digest_enabled": True})
        assert resp2.status_code == 200
        assert resp2.json()["digest_enabled"] is True
    finally:
        app.dependency_overrides.clear()


def test_webhook_configuration_and_test_trigger():
    """Verify webhook URL validation and test alert trigger."""
    app.dependency_overrides[get_current_user] = _mock_user
    try:
        # Reject invalid HTTP url
        bad_resp = client.patch("/api/account/webhook", json={"webhook_url": "http://insecure-webhook.com"})
        assert bad_resp.status_code == 400

        # Accept valid HTTPS url
        ok_resp = client.patch("/api/account/webhook", json={"webhook_url": "https://hooks.slack.com/services/TEST/123/456"})
        assert ok_resp.status_code == 200
        assert ok_resp.json()["webhook_url"] == "https://hooks.slack.com/services/TEST/123/456"

        # Test trigger endpoint
        test_resp = client.post("/api/account/webhook/test")
        assert test_resp.status_code == 200
        assert test_resp.json()["status"] == "sent"
    finally:
        app.dependency_overrides.clear()


def test_gdpr_data_export_endpoint():
    """Verify GET /api/account/export returns downloadable JSON with decrypted login events."""
    app.dependency_overrides[get_current_user] = _mock_user
    try:
        # Record an encrypted login event first
        user_service.record_user_login_event("phase5_user_999", "198.51.100.42", "Mozilla/5.0 TestAgent")

        resp = client.get("/api/account/export")
        assert resp.status_code == 200
        assert "attachment; filename=\"securemail-data-export-" in resp.headers["content-disposition"]

        data = resp.json()
        assert "exported_at" in data
        assert "account" in data
        assert "forensic_logs" in data
        assert "login_history" in data

        # Check decrypted login history
        logins = data["login_history"]
        assert len(logins) > 0
        latest_login = logins[-1]
        assert latest_login["ip_address"] == "198.51.100.42"
        assert latest_login["user_agent"] == "Mozilla/5.0 TestAgent"
    finally:
        app.dependency_overrides.clear()
