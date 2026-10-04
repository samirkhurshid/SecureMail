"""
FastAPI Router for Programmatic API Key Management
===================================================
Enables generating scoped API keys (sm_live_...), viewing active keys,
and revoking keys for machine-to-machine integrations.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from app.auth import get_current_user, CurrentUser
from app.services import api_key_service, audit_service
from app.services.rbac_service import require_permission

router = APIRouter()


class CreateAPIKeyRequest(BaseModel):
    name: str
    scopes: Optional[List[str]] = None
    expires_days: Optional[int] = None


@router.get("", summary="List all API keys for authenticated user")
async def list_api_keys(
    user: CurrentUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Returns all active and revoked API keys for the current user/organization
    including prefix, assigned scopes, usage count, and last active timestamp.
    """
    keys = api_key_service.list_user_api_keys(user.uid)
    return {
        "api_keys": keys,
        "available_scopes": sorted(list(api_key_service.VALID_SCOPES))
    }


@router.post("", summary="Generate a new scoped API key")
async def create_api_key(
    body: CreateAPIKeyRequest,
    user: CurrentUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Generates a cryptographically secure API key. Requires verified email.
    IMPORTANT: The raw key is returned ONLY in this response and cannot be retrieved again.
    """
    if not user.email_verified:
        raise HTTPException(
            status_code=403,
            detail="email_not_verified",
            headers={"X-Error-Reason": "Email verification required"}
        )

    if not body.name or not body.name.strip():
        raise HTTPException(status_code=400, detail="Key name is required")
        
    try:
        res = api_key_service.generate_api_key(
            user_id=user.uid,
            user_email=user.email or "unknown@api.user",
            name=body.name,
            scopes=body.scopes,
            expires_days=body.expires_days
        )
        
        # Log audit event
        audit_service.log_audit_event(
            event_type=audit_service.EVENT_API_KEY_CREATE,
            user_id=user.uid,
            user_email=user.email,
            user_role=user.role,
            resource_id=res["id"],
            details={"name": body.name, "prefix": res["key_prefix"], "scopes": res["scopes"]}
        )
        
        return {
            "status": "success",
            "message": "API key generated successfully. Store the raw key securely — it will not be shown again.",
            "key": res
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{key_id}", summary="Revoke an API key immediately")
async def revoke_api_key(
    key_id: str,
    user: CurrentUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Revokes the specified API key immediately so it can no longer authenticate.
    """
    success = api_key_service.revoke_api_key(key_id, user.uid)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found or already revoked")
        
    # Log audit event
    audit_service.log_audit_event(
        event_type=audit_service.EVENT_API_KEY_REVOKE,
        user_id=user.uid,
        user_email=user.email,
        user_role=user.role,
        resource_id=key_id,
        details={"status": "revoked"}
    )
    
    return {
        "status": "success",
        "message": f"API key {key_id} has been revoked."
    }
