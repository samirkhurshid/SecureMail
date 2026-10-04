"""
FastAPI Router for Threat Intelligence & Threat Vault
=====================================================
Exposes endpoints for checking IOC reputation, querying the Threat Vault,
monitoring feed synchronization health, and triggering on-demand feed updates.
"""

from fastapi import APIRouter, Query, HTTPException, BackgroundTasks, Depends
from typing import Optional, Dict, Any
from app.services import threat_intel_service

router = APIRouter()


@router.get("/status", summary="Get Threat Vault status and feed synchronization health")
async def get_status() -> Dict[str, Any]:
    """
    Returns total active indicators, breakdown by feed, breakdown by threat type,
    and the status of recent background feed synchronizations.
    """
    return threat_intel_service.get_feed_status()


@router.get("/lookup", summary="Instant Threat Intelligence IOC reputation lookup")
async def lookup_ioc(
    ioc: str = Query(..., description="The IOC value to inspect (URL, domain, IP, or SHA-256 hash)"),
    ioc_type: Optional[str] = Query(None, description="Optional IOC type ('url', 'domain', 'ip', 'sha256', 'md5')")
) -> Dict[str, Any]:
    """
    Performs sub-millisecond local reputation lookup against active Threat Vault feeds.
    Returns threat details if malicious, or clean status if no match.
    """
    if not ioc or not ioc.strip():
        raise HTTPException(status_code=400, detail="IOC value required")
        
    result = threat_intel_service.lookup_ioc(ioc.strip(), ioc_type)
    if result:
        return {
            "query": ioc.strip(),
            "is_threat": True,
            "threat_details": result
        }
    return {
        "query": ioc.strip(),
        "is_threat": False,
        "threat_details": None,
        "message": "No active threat intelligence match found in local vault"
    }


@router.get("/vault", summary="Search and browse Threat Vault indicators")
async def get_vault_records(
    search: Optional[str] = Query(None, description="Search keyword in IOC value or tags"),
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type ('url', 'domain', 'ip', 'sha256')"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type ('phishing', 'malware_download', 'c2')"),
    source_feed: Optional[str] = Query(None, description="Filter by source feed ('urlhaus', 'openphish', 'internal_seed')"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
) -> Dict[str, Any]:
    """
    Returns paginated threat intelligence records matching specified filters.
    """
    return threat_intel_service.query_vault(
        search=search,
        ioc_type=ioc_type,
        threat_type=threat_type,
        source_feed=source_feed,
        limit=limit,
        offset=offset
    )


from app.services import audit_service
from app.auth import get_optional_user, CurrentUser


@router.post("/sync", summary="Trigger on-demand synchronization of threat intelligence feeds")
async def trigger_feed_sync(
    background_tasks: BackgroundTasks,
    user: Optional[CurrentUser] = Depends(get_optional_user)
) -> Dict[str, Any]:
    """
    Triggers an asynchronous background synchronization of URLhaus and OpenPhish threat feeds.
    """
    background_tasks.add_task(threat_intel_service.sync_all_feeds)
    
    uid = user.uid if user else "system_console"
    email = user.email if user else "console@securemail.io"
    role = getattr(user, "role", "admin")
    
    background_tasks.add_task(
        audit_service.log_audit_event,
        event_type=audit_service.EVENT_FEED_SYNC,
        user_id=uid,
        user_email=email,
        user_role=role,
        resource_id="urlhaus,openphish",
        details={"status": "sync_initiated"}
    )
    
    return {
        "status": "sync_initiated",
        "message": "Threat feed synchronization task scheduled in background"
    }
