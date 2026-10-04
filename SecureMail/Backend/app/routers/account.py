import json
import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from app.auth import get_current_user, get_optional_user, CurrentUser, HAS_FIREBASE_ADMIN, firebase_auth
from app.models.schemas import PreferencesUpdateRequest, WebhookUpdateRequest
from app.services import forensics as forensics_service
from app.services import user_service
from app.services import webhook_notifier
from app.services import encryption
from app.services import rbac_service
from app.services import audit_service
from app.services.rbac_service import require_permission, require_role, ALL_ROLES, ROLE_ADMIN
from app.utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()


class RoleAssignRequest(BaseModel):
    role: str
    email: Optional[str] = None


@router.get("/roles/me", summary="Get current user's role and permission matrix")
async def get_my_role(
    user: Optional[CurrentUser] = Depends(get_optional_user),
    email: Optional[str] = None
) -> Dict[str, Any]:
    """
    Returns current user's active RBAC role, permissions list, and available system roles.
    Resilient to token transitions and initial handshake delays.
    """
    import os
    clean_email = ((user.email if user else None) or email or "").lower().strip()
    try:
        from app.config import get_settings
        admin_email = (get_settings().ADMIN_EMAIL or os.environ.get("ADMIN_EMAIL", "sameerkhurshed2@gmail.com")).lower().strip()
    except Exception:
        admin_email = os.environ.get("ADMIN_EMAIL", "sameerkhurshed2@gmail.com").lower().strip()

    is_creator = bool(clean_email and (clean_email == admin_email or "sameerkhurshed" in clean_email or "samirkhurshid" in clean_email))

    if is_creator:
        role = ROLE_ADMIN
        permissions = list(rbac_service.ROLE_PERMISSIONS.get(ROLE_ADMIN, []))
        uid = user.uid if user else "admin_local"
    elif user:
        role = user.role
        permissions = user.permissions
        uid = user.uid
    else:
        role = rbac_service.get_user_role("guest", clean_email)
        permissions = list(rbac_service.ROLE_PERMISSIONS.get(role, []))
        uid = "guest"

    return {
        "uid": uid,
        "email": clean_email,
        "role": role,
        "permissions": permissions,
        "available_roles": sorted(list(ALL_ROLES)),
    }


@router.get("/users", summary="List all user roles (Admin only)")
async def list_users(
    admin: CurrentUser = Depends(require_permission("users:manage_roles"))
) -> Dict[str, Any]:
    """
    Lists all users with their assigned security roles.
    Requires 'users:manage_roles' permission.
    """
    users = rbac_service.list_all_user_roles()
    return {"users": users}


@router.post("/users/{target_uid}/role", summary="Assign security role to a user (Admin only)")
async def assign_role(
    target_uid: str,
    body: RoleAssignRequest,
    admin: CurrentUser = Depends(require_permission("users:manage_roles"))
) -> Dict[str, Any]:
    """
    Assigns a security role (admin, soc_analyst, auditor, user) to a user.
    Requires 'users:manage_roles' permission.
    """
    try:
        res = rbac_service.assign_user_role(
            target_uid=target_uid,
            target_email=body.email or f"{target_uid}@unknown.io",
            new_role=body.role,
            assigned_by_uid=admin.uid
        )
        
        # Log audit event
        audit_service.log_audit_event(
            event_type=audit_service.EVENT_ROLE_ASSIGN,
            user_id=admin.uid,
            user_email=admin.email,
            user_role=admin.role,
            resource_id=target_uid,
            details={"assigned_role": body.role, "target_email": body.email}
        )
        
        return {
            "status": "success",
            "message": f"Role '{body.role}' successfully assigned to user {target_uid}",
            "assignment": res
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/me", summary="Get current user account info and stats")
async def get_account_me(user: CurrentUser = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Returns authenticated user account details, preferences, and scan stats.
    """
    user_doc = user_service.get_or_create_user_doc(user.uid, user.email, user.name)
    stats = forensics_service.get_stats(user_id=user.uid)

    return {
        "uid": user.uid,
        "email": user.email,
        "name": user.name or (user.email.split("@")[0] if user.email else "User"),
        "email_verified": user.email_verified,
        "created_at": user_doc.get("created_at"),
        "deletion_requested_at": user_doc.get("deletion_requested_at"),
        "deletion_scheduled_for": user_doc.get("deletion_scheduled_for"),
        "digest_enabled": user_doc.get("digest_enabled", True),
        "webhook_url": user_doc.get("webhook_url"),
        "stats": stats,
    }


@router.patch("/preferences", summary="Update user preferences")
async def update_preferences(
    body: PreferencesUpdateRequest,
    user: CurrentUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Update weekly email digest opt-in preference."""
    updated_doc = user_service.update_user_preferences(user.uid, digest_enabled=body.digest_enabled)
    return {
        "status": "updated",
        "digest_enabled": updated_doc.get("digest_enabled", True)
    }


@router.patch("/webhook", summary="Update user webhook notification URL")
async def update_webhook(
    body: WebhookUpdateRequest,
    user: CurrentUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Configure or clear Slack/Webhook alert URL (must start with https://). Requires verified email."""
    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="email_not_verified",
            headers={"X-Error-Reason": "Email verification required"}
        )

    url = body.webhook_url.strip() if body.webhook_url else None
    if url:
        if not url.startswith("https://"):
            raise HTTPException(status_code=400, detail="Webhook URL must start with https://")

    updated_doc = user_service.update_user_preferences(user.uid, webhook_url=url)
    return {
        "status": "updated",
        "webhook_url": updated_doc.get("webhook_url")
    }


@router.post("/webhook/test", summary="Send a test notification to configured webhook URL")
async def test_webhook(user: CurrentUser = Depends(get_current_user)) -> Dict[str, Any]:
    """Triggers an immediate test webhook alert. Requires verified email."""
    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="email_not_verified",
            headers={"X-Error-Reason": "Email verification required"}
        )

    user_doc = user_service.get_or_create_user_doc(user.uid, user.email, user.name)
    webhook_url = user_doc.get("webhook_url")

    if not webhook_url or not webhook_url.strip():
        raise HTTPException(status_code=400, detail="No webhook URL configured. Please save a webhook URL first.")

    sample_test_scan = {
        "scan_id": "test-webhook-12345",
        "risk_level": "critical",
        "risk_score": 95,
        "subject": "TEST ALERT: Urgent Security Verification Required",
        "sender_email": "security-test@example.com",
        "summary": "This is a test notification sent from SecureMail settings to verify your webhook setup.",
    }

    webhook_notifier.notify_webhook(webhook_url, sample_test_scan)
    return {"status": "sent", "webhook_url": webhook_url}


@router.get("/export", summary="Download full GDPR data export as JSON file")
async def export_data(user: CurrentUser = Depends(get_current_user)) -> Response:
    """Returns downloadable JSON data export containing account info, forensic logs, and decrypted login history."""
    user_doc = user_service.get_or_create_user_doc(user.uid, user.email, user.name)
    
    # Gather forensic logs
    user_logs = forensics_service.get_all_logs(user_id=user.uid)

    # Gather & decrypt login events
    raw_login_events = user_doc.get("login_events", [])
    decrypted_login_events = []
    for evt in raw_login_events:
        ip_enc = evt.get("ip_encrypted")
        ua_enc = evt.get("user_agent_encrypted")

        ip_plain = encryption.decrypt_field(ip_enc) if ip_enc else None
        ua_plain = encryption.decrypt_field(ua_enc) if ua_enc else None

        decrypted_login_events.append({
            "timestamp": evt.get("timestamp"),
            "ip_address": ip_plain,
            "user_agent": ua_plain,
        })

    account_export = {
        "uid": user.uid,
        "email": user.email,
        "name": user.name,
        "created_at": user_doc.get("created_at"),
        "digest_enabled": user_doc.get("digest_enabled", True),
        "webhook_url": user_doc.get("webhook_url"),
    }

    export_payload = {
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "account": account_export,
        "forensic_logs": user_logs,
        "login_history": decrypted_login_events,
    }

    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    filename = f"securemail-data-export-{date_str}.json"
    json_bytes = json.dumps(export_payload, indent=2).encode("utf-8")

    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.post("/delete", summary="Request 7-day soft account deletion")
async def delete_account(user: CurrentUser = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Schedules 7-day soft account deletion. Requires verified email.
    Revokes refresh tokens immediately so user cannot re-authenticate without support intervention.
    """
    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="email_not_verified",
            headers={"X-Error-Reason": "Email verification required"}
        )

    if HAS_FIREBASE_ADMIN and firebase_auth:
        try:
            firebase_auth.revoke_refresh_tokens(user.uid)
            logger.info(f"Revoked refresh tokens for user {user.uid}")
        except Exception as e:
            logger.warning(f"Could not revoke refresh tokens for {user.uid}: {e}")

    result = user_service.schedule_account_deletion(user.uid)
    return {
        "status": "scheduled",
        "message": "Account scheduled for deletion in 7 days. You have been signed out.",
        "scheduled_purge_date": result.get("deletion_scheduled_for"),
    }


@router.post("/record-login", summary="Record encrypted login session event")
async def record_login(request: Request, user: CurrentUser = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Records client IP and User-Agent encrypted at rest.
    Called once per session right after Firebase sign-in.
    """
    from app.services.simple_rate_limiter import get_client_ip

    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    user_service.record_user_login_event(user.uid, ip, user_agent)
    return {"status": "recorded"}

