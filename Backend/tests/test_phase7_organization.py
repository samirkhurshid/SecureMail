"""
Unit & Integration Tests for Enterprise Organization Sandbox & Team Management
=============================================================================
Tests multi-tenant boundary enforcement, employee invitations, role delegation,
and tenant-isolated scan aggregation.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import get_current_user, CurrentUser


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_user():
    return CurrentUser(
        uid="admin_test_uid",
        email="sameerkhurshed2@gmail.com",
        name="Samir Khurshid",
        role="admin",
        permissions=["*"]
    )


@pytest.fixture
def regular_user():
    return CurrentUser(
        uid="regular_test_uid",
        email="regular.employee@paruluniversity.ac.in",
        name="Regular Employee",
        role="user",
        permissions=["scans:create", "scans:read_own"]
    )


def test_get_org_overview_as_admin(client, admin_user):
    app.dependency_overrides[get_current_user] = lambda: admin_user
    res = client.get("/api/org/overview")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["name"] == "Parul University SOC"
    assert data["domain"] == "paruluniversity.ac.in"
    assert "stats" in data
    assert data["stats"]["total_members"] >= 1
    assert "members" in data
    assert len(data["members"]) >= 1


def test_invite_member_success(client, admin_user):
    app.dependency_overrides[get_current_user] = lambda: admin_user
    res = client.post("/api/org/invite", json={
        "email": "test.invitee@paruluniversity.ac.in",
        "role": "soc_analyst",
        "display_name": "Test Invitee"
    })
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert "SOC_ANALYST" in body["message"]

    # Verify member appears in roster
    overview_res = client.get("/api/org/overview")
    members = overview_res.json()["data"]["members"]
    matching = [m for m in members if m["user_email"] == "test.invitee@paruluniversity.ac.in"]
    assert len(matching) == 1
    assert matching[0]["role"] == "soc_analyst"
    assert matching[0]["status"] == "invited"


def test_invite_member_forbidden_for_regular_user(client, regular_user):
    app.dependency_overrides[get_current_user] = lambda: regular_user
    res = client.post("/api/org/invite", json={
        "email": "unauthorized@paruluniversity.ac.in",
        "role": "admin",
        "display_name": "Hacker"
    })
    assert res.status_code == 403


def test_update_member_role(client, admin_user):
    app.dependency_overrides[get_current_user] = lambda: admin_user
    # First invite
    client.post("/api/org/invite", json={
        "email": "role.change@paruluniversity.ac.in",
        "role": "user",
        "display_name": "Role Change Test"
    })

    # Update to auditor
    res = client.patch("/api/org/members/role", json={
        "email": "role.change@paruluniversity.ac.in",
        "role": "auditor"
    })
    assert res.status_code == 200
    assert "AUDITOR" in res.json()["message"]

    # Verify update in roster
    overview = client.get("/api/org/overview").json()["data"]
    member = next(m for m in overview["members"] if m["user_email"] == "role.change@paruluniversity.ac.in")
    assert member["role"] == "auditor"


def test_remove_member(client, admin_user):
    app.dependency_overrides[get_current_user] = lambda: admin_user
    # Invite
    client.post("/api/org/invite", json={
        "email": "to.be.removed@paruluniversity.ac.in",
        "role": "user",
        "display_name": "Temporary User"
    })

    # Remove
    res = client.request("DELETE", "/api/org/members", json={
        "email": "to.be.removed@paruluniversity.ac.in"
    })
    assert res.status_code == 200
    assert "Removed" in res.json()["message"]

    # Verify member is gone
    overview = client.get("/api/org/overview").json()["data"]
    emails = [m["user_email"] for m in overview["members"]]
    assert "to.be.removed@paruluniversity.ac.in" not in emails
