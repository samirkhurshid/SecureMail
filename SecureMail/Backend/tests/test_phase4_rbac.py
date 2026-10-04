"""
Unit & Integration Tests for Phase 4.1: Role-Based Access Control (RBAC) Engine
=================================================================================
Tests role-to-permission mapping, SQLite role persistence, dependency guards,
role assignment endpoints, and 403 Forbidden enforcement on restricted actions.
"""

import pytest
from app.services import rbac_service
from app.auth import get_current_user, get_optional_user, CurrentUser


def test_rbac_role_permissions_matrix():
    """Verify permission matrices for all 4 defined security roles."""
    # Admin has all capabilities
    assert rbac_service.ROLE_PERMISSIONS["admin"].issuperset({
        "scans:create", "scans:read_all", "forensics:read", "forensics:delete",
        "reports:export", "threat_intel:sync", "users:manage_roles", "settings:manage"
    })
    
    # SOC Analyst has operations capabilities but CANNOT delete logs or manage roles
    analyst_perms = rbac_service.ROLE_PERMISSIONS["soc_analyst"]
    assert "scans:create" in analyst_perms
    assert "threat_intel:sync" in analyst_perms
    assert "forensics:delete" not in analyst_perms
    assert "users:manage_roles" not in analyst_perms
    
    # Auditor is read-only (no scans:create, no settings:manage, no forensics:delete)
    auditor_perms = rbac_service.ROLE_PERMISSIONS["auditor"]
    assert "scans:read_all" in auditor_perms
    assert "forensics:read" in auditor_perms
    assert "scans:create" not in auditor_perms
    assert "forensics:delete" not in auditor_perms
    assert "settings:manage" not in auditor_perms
    
    # Standard User has personal capabilities only
    user_perms = rbac_service.ROLE_PERMISSIONS["user"]
    assert "scans:create" in user_perms
    assert "scans:read_own" in user_perms
    assert "scans:read_all" not in user_perms
    assert "forensics:delete" not in user_perms


def test_assign_and_get_user_role():
    """Verify role assignment and persistent SQLite lookup."""
    target_uid = "usr_analyst_007"
    target_email = "analyst007@securemail.io"
    
    # Default role should be 'user'
    assert rbac_service.get_user_role("unknown_uid_999") == "user"
    
    # Assign SOC Analyst role
    res = rbac_service.assign_user_role(
        target_uid=target_uid,
        target_email=target_email,
        new_role="soc_analyst",
        assigned_by_uid="admin_root"
    )
    assert res["role"] == "soc_analyst"
    assert rbac_service.get_user_role(target_uid) == "soc_analyst"
    assert rbac_service.has_permission(target_uid, "threat_intel:sync") is True
    assert rbac_service.has_permission(target_uid, "users:manage_roles") is False


@pytest.mark.asyncio
async def test_get_my_role_endpoint():
    """Verify /api/account/roles/me returns current user's role and permission set."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    usr = CurrentUser(
        uid="usr_soc_test", email="soc@securemail.io", email_verified=True, role="soc_analyst"
    )
    app.dependency_overrides[get_current_user] = lambda: usr
    app.dependency_overrides[get_optional_user] = lambda: usr
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/account/roles/me")
        assert res.status_code == 200
        data = res.json()
        
        assert data["uid"] == "usr_soc_test"
        assert data["role"] == "soc_analyst"
        assert "threat_intel:sync" in data["permissions"]
        assert "admin" in data["available_roles"]
        
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_admin_can_manage_roles_and_list_users():
    """Verify Admin can view all user roles and assign roles."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="admin_01", email="admin@securemail.io", email_verified=True, role="admin"
    )
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Assign role
        assign_res = await client.post(
            "/api/account/users/usr_auditor_99/role",
            json={"role": "auditor", "email": "auditor@securemail.io"}
        )
        assert assign_res.status_code == 200
        assert assign_res.json()["status"] == "success"
        
        # 2. List all users
        list_res = await client.get("/api/account/users")
        assert list_res.status_code == 200
        users = list_res.json()["users"]
        assert any(u["user_id"] == "usr_auditor_99" and u["role"] == "auditor" for u in users)
        
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_unauthorized_user_blocked_with_403_on_role_management():
    """Verify non-admin user receives 403 Forbidden when trying to manage roles."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    # Act as standard user
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="regular_user_1", email="user1@example.com", email_verified=True, role="user"
    )
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/account/users")
        assert res.status_code == 403
        assert res.json()["detail"]["error"] == "permission_denied"
        
        post_res = await client.post(
            "/api/account/users/target/role",
            json={"role": "admin"}
        )
        assert post_res.status_code == 403
        
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_forensics_delete_permission_enforcement():
    """Verify log deletion is allowed for Admin but returns 403 Forbidden for Analyst/Auditor."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    transport = ASGITransport(app=app)
    
    # 1. SOC Analyst should be rejected (403 Forbidden)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="analyst_user", email="analyst@securemail.io", email_verified=True, role="soc_analyst"
    )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.delete("/api/forensics/log-12345")
        assert res.status_code == 403
        assert res.json()["detail"]["error"] == "permission_denied"
        assert res.json()["detail"]["required_permission"] == "forensics:delete"
        
    # 2. Auditor should also be rejected (403 Forbidden)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="auditor_user", email="auditor@securemail.io", email_verified=True, role="auditor"
    )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.delete("/api/forensics/log-12345")
        assert res.status_code == 403
        
    app.dependency_overrides.clear()
