"""
FastAPI Router for SOC Compliance Audit Trail
=============================================
Provides endpoints for querying, filtering, and exporting immutable compliance
audit logs for SOC analysts, auditors, and security administrators.
"""

import io
import csv
import json
from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse
from typing import Dict, Any, Optional
from app.auth import get_current_user, CurrentUser
from app.services import audit_service
from app.services.rbac_service import require_permission

router = APIRouter()


@router.get("", summary="Query paginated compliance audit logs")
async def get_audit_trail(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    search: Optional[str] = Query(None, description="Search term for email, IP, or resource"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require_permission("audit_trail:read"))
) -> Dict[str, Any]:
    """
    Returns paginated audit records with event metadata and parameters.
    Requires 'audit_trail:read' permission (Admin, SOC Analyst, Auditor).
    """
    return audit_service.query_audit_logs(
        event_type=event_type,
        user_id=user_id,
        search=search,
        limit=limit,
        offset=offset
    )


@router.get("/export/csv", summary="Export SOC compliance audit trail as CSV")
async def export_audit_csv(
    event_type: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=2000),
    user: CurrentUser = Depends(require_permission("audit_trail:read"))
):
    """
    Downloads audit trail records formatted as a compliance CSV file.
    Requires 'audit_trail:read' permission.
    """
    data = audit_service.query_audit_logs(
        event_type=event_type,
        user_id=user_id,
        search=search,
        limit=limit,
        offset=0
    )
    records = data.get("records", [])
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # CSV Header
    writer.writerow(["ID", "Timestamp", "Event_Type", "User_ID", "User_Email", "User_Role", "IP_Address", "Resource_ID", "Details"])
    
    for r in records:
        details_str = json.dumps(r.get("details", {}), ensure_ascii=False)
        writer.writerow([
            r.get("id", ""),
            r.get("timestamp", ""),
            r.get("event_type", ""),
            r.get("user_id", ""),
            r.get("user_email", ""),
            r.get("user_role", ""),
            r.get("ip_address", ""),
            r.get("resource_id", ""),
            details_str
        ])
        
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=SecureMail-SOC-AuditTrail.csv"}
    )
