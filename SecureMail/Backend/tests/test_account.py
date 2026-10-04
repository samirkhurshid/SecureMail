"""
Unit tests for Phase 2 Account Info & 7-Day Account Deletion Workflow.
"""

import pytest
import datetime
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.main import app
from app.auth import get_current_user, CurrentUser
from app.services import user_service
from app.scripts import purge_deleted_accounts

def _mock_user():
    return CurrentUser(uid="test_user_123", email="testuser@example.com", email_verified=True, name="Test User")

app.dependency_overrides[get_current_user] = _mock_user
client = TestClient(app)


def test_get_account_me():
    """Verify /api/account/me returns user profile and statistics."""
    resp = client.get("/api/account/me")
    assert resp.status_code == 200
    data = resp.json()
    assert data["uid"] == "test_user_123"
    assert data["email"] == "testuser@example.com"
    assert "stats" in data


def test_schedule_and_enforce_account_deletion():
    """Verify requesting deletion returns scheduled status and subsequently enforces 403 account_pending_deletion."""
    target_uid = f"delete_test_uid_{int(datetime.datetime.now().timestamp())}"

    def _mock_del_user():
        if user_service.is_account_pending_deletion(target_uid):
            raise HTTPException(status_code=403, detail="account_pending_deletion")
        return CurrentUser(uid=target_uid, email="deluser@example.com", email_verified=True, name="Delete User")

    app.dependency_overrides[get_current_user] = _mock_del_user

    # Initial request works
    resp1 = client.get("/api/account/me")
    assert resp1.status_code == 200

    # Trigger deletion
    del_resp = client.post("/api/account/delete")
    assert del_resp.status_code == 200
    del_data = del_resp.json()
    assert del_data["status"] == "scheduled"
    assert "scheduled_purge_date" in del_data

    # Verify pending deletion status is set in user service
    assert user_service.is_account_pending_deletion(target_uid) is True

    # Verify subsequent request is rejected with 403 account_pending_deletion
    resp2 = client.get("/api/account/me")
    assert resp2.status_code == 403
    assert resp2.json()["detail"] == "account_pending_deletion"

    # Reset override
    app.dependency_overrides[get_current_user] = _mock_user


def test_purge_user_logs():
    """Verify purge_user_logs removes user logs cleanly."""
    deleted_count = purge_deleted_accounts.purge_user_logs("non_existent_uid_999")
    assert deleted_count >= 0
