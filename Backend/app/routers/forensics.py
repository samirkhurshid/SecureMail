from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
import io
import csv
import json
from app.services import forensics as forensics_service

router = APIRouter()

@router.get("/")
async def list_logs(
    limit: int = Query(50, ge=1),
    offset: int = Query(0, ge=0),
    risk_level: str = Query(None),
    search: str = Query(None)
):
    logs = forensics_service.get_all_logs()
    
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
async def get_stats():
    return forensics_service.get_stats()

@router.get("/export/json")
async def export_json():
    logs = forensics_service.get_all_logs()
    data = json.dumps(logs, indent=2)
    return StreamingResponse(
        io.BytesIO(data.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=forensics_export.json"}
    )

@router.get("/export/csv")
async def export_csv():
    logs = forensics_service.get_all_logs()
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
async def get_log(log_id: str):
    log = forensics_service.get_log_by_id(log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log

@router.delete("/{log_id}")
async def delete_log(log_id: str):
    success = forensics_service.delete_log_by_id(log_id)
    if not success:
        raise HTTPException(status_code=404, detail="Log not found")
    return {"status": "success", "message": f"Log {log_id} deleted"}
