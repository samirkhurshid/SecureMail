"""
Unit & Integration Tests for Phase 4.3: SOC Compliance Audit Trail
===================================================================
Tests immutable audit logging, event categorization, permission guards (403 for standard user,
allowed for admin/analyst/auditor), query filtering, and compliance CSV exports.
"""

import pytest
from app.services import audit_service
from app.auth import get_current_user, CurrentUser


def test_audit_event_logging_and_retrieval():
    """Verify logging various security events and querying records."""
    # 1. Log events
    id1 = audit_service.log_audit_event(
        event_type=audit_service.EVENT_API_KEY_CREATE,
        user_id="usr_admin_01",
        user_email="admin@securemail.io",
        user_role="admin",
        ip_address="192.168.1.50",
        resource_id="key-uuid-101",
        details={"name": "Postfix Ingest Key", "scopes": ["scans:write"]}
    )
    assert id1 > 0
    
    id2 = audit_service.log_audit_event(
        event_type=audit_service.EVENT_ROLE_ASSIGN,
        user_id="usr_admin_01",
        user_email="admin@securemail.io",
        user_role="admin",
        ip_address="192.168.1.50",
        resource_id="usr_analyst_02",
        details={"assigned_role": "soc_analyst"}
    )
    assert id2 > 0
    
    # 2. Query logs
    res = audit_service.query_audit_logs(limit=10)
    assert res["total"] >= 2
    records = res["records"]
    assert any(r["id"] == id1 and r["event_type"] == "API_KEY_CREATE" for r in records)
    assert any(r["id"] == id2 and r["event_type"] == "ROLE_ASSIGN" for r in records)


def test_audit_trail_filtering_by_event_and_search():
    """Verify filtering by event_type and searching within details."""
    audit_service.log_audit_event(
        event_type=audit_service.EVENT_SCAN_EMAIL,
        user_id="usr_soc_03",
        user_email="soc_investigator@enterprise.com",
        user_role="soc_analyst",
        ip_address="10.0.0.12",
        resource_id="scan-xyz-999",
        details={"sender": "attacker@evil-domain.ru", "risk_score": 95}
    )
    
    # Filter by event_type
    filtered = audit_service.query_audit_logs(event_type=audit_service.EVENT_SCAN_EMAIL)
    assert all(r["event_type"] == "SCAN_EMAIL" for r in filtered["records"])
    
    # Search for specific email or resource
    searched = audit_service.query_audit_logs(search="scan-xyz-999")
    assert len(searched["records"]) >= 1
    assert searched["records"][0]["resource_id"] == "scan-xyz-999"


@pytest.mark.asyncio
async def test_audit_trail_permission_enforcement():
    """Verify Admin, SOC Analyst, and Auditor can access audit logs; standard User gets 403."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    transport = ASGITransport(app=app)
    
    # 1. Admin should succeed (200 OK)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="admin_uid", email="admin@securemail.io", email_verified=True, role="admin"
    )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res_admin = await client.get("/api/audit-trail")
        assert res_admin.status_code == 200
        assert "records" in res_admin.json()
        
    # 2. Auditor should succeed (200 OK)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="auditor_uid", email="auditor@securemail.io", email_verified=True, role="auditor"
    )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res_auditor = await client.get("/api/audit-trail")
        assert res_auditor.status_code == 200
        
    # 3. SOC Analyst should succeed (200 OK)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="soc_uid", email="soc@securemail.io", email_verified=True, role="soc_analyst"
    )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res_soc = await client.get("/api/audit-trail")
        assert res_soc.status_code == 200
        
    # 4. Standard User must be rejected with 403 Forbidden
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="user_uid", email="user@example.com", email_verified=True, role="user"
    )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res_user = await client.get("/api/audit-trail")
        assert res_user.status_code == 403
        assert res_user.json()["detail"]["error"] == "permission_denied"
        assert res_user.json()["detail"]["required_permission"] == "audit_trail:read"
        
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_audit_csv_export_endpoint():
    """Verify /api/audit-trail/export/csv streams valid compliance CSV."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        uid="auditor_uid", email="auditor@securemail.io", email_verified=True, role="auditor"
    )
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/audit-trail/export/csv")
        assert res.status_code == 200
        assert "text/csv" in res.headers["content-type"]
        csv_text = res.text
        assert "Timestamp" in csv_text
        assert "Event_Type" in csv_text
        assert "User_Email" in csv_text
        
    app.dependency_overrides.clear()
