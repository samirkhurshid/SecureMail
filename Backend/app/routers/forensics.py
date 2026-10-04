from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import StreamingResponse
import io
import csv
import json
from app.services import forensics as forensics_service
from app.auth import get_current_user, CurrentUser

router = APIRouter()

@router.get("")
@router.get("/")
async def list_logs(
    limit: int = Query(50, ge=1),
    offset: int = Query(0, ge=0),
    risk_level: str = Query(None),
    search: str = Query(None),
    user: CurrentUser = Depends(get_current_user)
):
    logs = forensics_service.get_all_logs(user_id=user.uid, user_email=user.email)
    
    # Filter by risk_level
    if risk_level:
        logs = [log for log in logs if log.get("risk_level", "").lower() == risk_level.lower()]
        
    # Filter by search term
    if search:
        search_lower = search.lower()
        logs = [
            log for log in logs 
            if search_lower in log.get("sender_email", "").lower() 
            or search_lower in log.get("subject", "").lower()
            or search_lower in log.get("summary", "").lower()
        ]
        
    total = len(logs)
    paginated_logs = logs[offset : offset + limit]
    
    return {"total": total, "logs": paginated_logs}

@router.get("/stats")
async def get_stats(user: CurrentUser = Depends(get_current_user)):
    return forensics_service.get_stats(user_id=user.uid, user_email=user.email)

@router.get("/export/json")
async def export_json(user: CurrentUser = Depends(get_current_user)):
    logs = forensics_service.get_all_logs(user_id=user.uid, user_email=user.email)
    data = json.dumps(logs, indent=2)
    return StreamingResponse(
        io.BytesIO(data.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=forensics_export.json"}
    )

@router.get("/export/csv")
async def export_csv(user: CurrentUser = Depends(get_current_user)):
    logs = forensics_service.get_all_logs(user_id=user.uid, user_email=user.email)
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header row
    writer.writerow(["scan_id", "scanned_at", "risk_score", "risk_level", "sender_email", "subject", "summary"])
    
    for log in logs:
        writer.writerow([
            log.get("scan_id", ""),
            log.get("scanned_at", ""),
            log.get("risk_score", 0),
            log.get("risk_level", ""),
            log.get("sender_email", ""),
            log.get("subject", ""),
            log.get("summary", "")
        ])
        
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=forensics_export.csv"}
    )

@router.get("/{log_id}")
async def get_log(log_id: str, user: CurrentUser = Depends(get_current_user)):
    log = forensics_service.get_log_by_id(log_id, user_id=user.uid, user_email=user.email)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log


from app.services import audit_service
from app.services.rbac_service import require_permission


@router.get("/{log_id}/pdf", summary="Export stored forensic record as executive PDF report")
async def export_log_pdf(log_id: str, user: CurrentUser = Depends(get_current_user)):
    from app.services import report_generator
    log = forensics_service.get_log_by_id(log_id, user_id=user.uid, user_email=user.email)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
        
    audit_service.log_audit_event(
        event_type=audit_service.EVENT_PDF_REPORT_EXPORT,
        user_id=user.uid,
        user_email=user.email,
        user_role=user.role,
        resource_id=log_id,
        details={"incident_id": log.get("scan_id", log_id), "risk_score": log.get("risk_score")}
    )
    
    pdf_bytes = report_generator.generate_forensic_pdf(log, incident_id=log.get("scan_id", log_id))
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="SecureMail-Incident-{log_id}.pdf"'}
    )


@router.delete("/{log_id}")
async def delete_log(log_id: str, user: CurrentUser = Depends(require_permission("forensics:delete"))):
    success = forensics_service.delete_log_by_id(log_id, user_id=user.uid, user_email=user.email)
    if not success:
        raise HTTPException(status_code=404, detail="Log not found")
        
    audit_service.log_audit_event(
        event_type=audit_service.EVENT_LOG_DELETE,
        user_id=user.uid,
        user_email=user.email,
        user_role=user.role,
        resource_id=log_id,
        details={"status": "deleted"}
    )
    
    return {"status": "success", "message": f"Log {log_id} deleted"}


@router.post("/save")
async def save_log(result: dict, user: CurrentUser = Depends(get_current_user)):
    """
    Manually save a scan result as a forensic log.
    Called by the browser extension popup Save button.
    """
    if not result:
        raise HTTPException(status_code=400, detail="No scan result provided")
    result["user_id"] = user.uid
    if user.email:
        result["user_email"] = user.email
    log_id = forensics_service.save_forensic_log(result, user_id=user.uid, user_email=user.email)
    return {"status": "saved", "log_id": log_id}

