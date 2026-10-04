"""
Unit tests for Phase 3 Encrypted Session Logging & Usage Tracking.
"""

import pytest
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet
from app.main import app
from app.auth import get_current_user, CurrentUser
from app.services import encryption, usage_tracker, user_service
from app.config import Settings

def _mock_user():
    return CurrentUser(uid="phase3_user_123", email="phase3@example.com", email_verified=True, name="Phase3 User")

app.dependency_overrides[get_current_user] = _mock_user
client = TestClient(app)


def test_encryption_decryption_roundtrip():
    """Verify encrypt_field and decrypt_field work correctly."""
    ip = "192.168.1.50"
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    enc_ip = encryption.encrypt_field(ip)
    enc_ua = encryption.encrypt_field(user_agent)

    assert enc_ip != ip
    assert enc_ua != user_agent

    dec_ip = encryption.decrypt_field(enc_ip)
    dec_ua = encryption.decrypt_field(enc_ua)

    assert dec_ip == ip
    assert dec_ua == user_agent


def test_decryption_error_on_invalid_data():
    """Verify decrypt_field raises DecryptionError on corrupt ciphertext."""
    with pytest.raises(encryption.DecryptionError):
        encryption.decrypt_field("gAAAAABinvalidciphertext12345")


def test_record_login_endpoint():
    """Verify POST /api/account/record-login records encrypted IP and User-Agent."""
    app.dependency_overrides[get_current_user] = _mock_user
    resp = client.post(
        "/api/account/record-login",
        headers={"User-Agent": "Pytest-Agent/1.0", "X-Forwarded-For": "203.0.113.195"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "recorded"

    # Inspect stored local user records
    local_store = user_service._load_local_users()
    user_data = local_store.get("phase3_user_123", {})
    events = user_data.get("login_events", [])
    assert len(events) > 0

    latest = events[-1]
    assert "timestamp" in latest
    assert latest["ip_encrypted"] != "203.0.113.195"
    assert latest["user_agent_encrypted"] != "Pytest-Agent/1.0"

    # Verify decrypt_field recovers real IP and User-Agent
    assert encryption.decrypt_field(latest["ip_encrypted"]) == "203.0.113.195"
    assert encryption.decrypt_field(latest["user_agent_encrypted"]) == "Pytest-Agent/1.0"


def test_usage_tracking_sqlite():
    """Verify record_scan_usage increments scan counts in usage_tracking.db for today's IST date."""
    uid = "test_usage_uid_777"
    today_str = usage_tracker._get_ist_date_str()

    stats_before = usage_tracker.get_usage_stats(uid)
    before_count = stats_before.get(today_str, 0)

    usage_tracker.record_scan_usage(uid)
    usage_tracker.record_scan_usage(uid)

    stats_after = usage_tracker.get_usage_stats(uid)
    after_count = stats_after.get(today_str, 0)

    assert after_count == before_count + 2


def test_missing_encryption_key_validation():
    """Verify Settings fails validation when SESSION_ENCRYPTION_KEY is missing/empty."""
    with pytest.raises(Exception) as exc_info:
        Settings(SESSION_ENCRYPTION_KEY="")
    assert "SESSION_ENCRYPTION_KEY" in str(exc_info.value)
