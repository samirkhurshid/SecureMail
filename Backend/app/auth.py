"""
Firebase authentication middleware.

Verifies the Firebase ID token sent in the Authorization: Bearer <token>
header on every protected request. Requires firebase-admin SDK and a
service account JSON key file (never commit this file — see .env.example).

Install: pip install firebase-admin
"""

import os
from fastapi import Header, HTTPException, Depends
from typing import Optional
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

try:
    import firebase_admin
    from firebase_admin import credentials, auth as firebase_auth
    HAS_FIREBASE_ADMIN = True
except ImportError:
    HAS_FIREBASE_ADMIN = False
    firebase_admin = None
    credentials = None
    firebase_auth = None

# ── Initialize Firebase Admin SDK once at import time ──────────────
_firebase_app = None


def _init_firebase():
    global _firebase_app
    if _firebase_app is not None:
        return _firebase_app

    if not HAS_FIREBASE_ADMIN:
        logger.warning(
            "firebase-admin package is not installed. "
            "Install it via 'pip install firebase-admin' or 'pip install -r requirements.txt' "
            "to enable authentication."
        )
        return None

    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH", "./firebase-service-account.json")

    if not os.path.exists(service_account_path):
        candidates = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "firebase-service-account.json"),
            os.path.join(os.getcwd(), "Backend", "firebase-service-account.json"),
            os.path.join(os.getcwd(), "firebase-service-account.json")
        ]
        for c in candidates:
            if os.path.exists(c):
                service_account_path = c
                break

    if not os.path.exists(service_account_path):
        logger.warning(
            f"Firebase service account not found at '{service_account_path}'. "
            "Auth-protected endpoints will reject all requests until this is configured. "
            "Download it from Firebase Console > Project Settings > Service Accounts."
        )
        return None

    try:
        cred = credentials.Certificate(service_account_path)
        _firebase_app = firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin SDK initialized successfully")
        return _firebase_app
    except Exception as e:
        logger.error(f"Failed to initialize Firebase Admin SDK: {e}")
        return None
        return None


# Initialize on module load
_init_firebase()


class CurrentUser:
    """Represents the authenticated user extracted from a verified Firebase token."""

    def __init__(
        self,
        uid: str,
        email: Optional[str] = None,
        email_verified: bool = False,
        name: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[list] = None,
    ):
        self.uid = uid
        self.email = email
        self.email_verified = email_verified
        self.name = name
        
        # Resolve RBAC role & permissions
        if role is not None:
            self.role = role
        else:
            from app.services import rbac_service
            self.role = rbac_service.get_user_role(uid, email)
            
        if permissions is not None:
            self.permissions = list(permissions)
        else:
            from app.services import rbac_service
            self.permissions = list(rbac_service.ROLE_PERMISSIONS.get(self.role, rbac_service.ROLE_PERMISSIONS[rbac_service.ROLE_USER]))

    def __repr__(self):
        return f"<CurrentUser uid={self.uid} email={self.email} role={self.role}>"


async def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> CurrentUser:
    """
    FastAPI dependency — verifies either:
      1. Programmatic API Key (via X-API-Key: sm_live_... or Authorization: Api-Key sm_live_...)
      2. Firebase ID token (via Authorization: Bearer <token>)
    """
    # ── 1. Check for API Key Authentication ──
    raw_api_key = None
    if x_api_key and x_api_key.strip():
        raw_api_key = x_api_key.strip()
    elif authorization:
        auth_str = authorization.strip()
        if auth_str.startswith("Api-Key ") or auth_str.startswith("ApiKey "):
            raw_api_key = auth_str.split(" ", 1)[1].strip()
        elif auth_str.startswith("Bearer sm_live_"):
            raw_api_key = auth_str.split("Bearer ", 1)[1].strip()

    if raw_api_key:
        from app.services import api_key_service
        key_data = api_key_service.verify_api_key(raw_api_key)
        if not key_data:
            raise HTTPException(status_code=401, detail="Invalid, expired, or revoked API key")

        return CurrentUser(
            uid=key_data["user_id"],
            email=key_data["user_email"],
            email_verified=True,
            name=key_data["name"],
            role="api_service",
            permissions=key_data["scopes"],
        )

    # ── 2. Check for Firebase JWT Token Authentication ──
    if _firebase_app is None:
        raise HTTPException(
            status_code=503,
            detail="Authentication is not configured on this server. "
                   "Set FIREBASE_SERVICE_ACCOUNT_PATH in .env."
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = authorization.split("Bearer ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token")

    try:
        decoded = firebase_auth.verify_id_token(token)
    except firebase_auth.ExpiredIdTokenError:
        raise HTTPException(status_code=401, detail="Token expired — please sign in again")
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except firebase_auth.RevokedIdTokenError:
        raise HTTPException(status_code=401, detail="Token has been revoked — please sign in again")
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")

    uid = decoded.get("uid")
    email = decoded.get("email")
    name = decoded.get("name")

    # Check 7-day soft-delete status
    from app.services.user_service import is_account_pending_deletion
    if uid and is_account_pending_deletion(uid):
        raise HTTPException(status_code=403, detail="account_pending_deletion")

    return CurrentUser(
        uid=uid,
        email=email,
        email_verified=decoded.get("email_verified", False),
        name=name,
    )


async def get_optional_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> Optional[CurrentUser]:
    """
    Same as get_current_user but returns None instead of raising when no
    token is provided. Use for endpoints that work both authenticated and anonymous.
    """
    if not authorization and not x_api_key:
        return None
    try:
        return await get_current_user(authorization=authorization, x_api_key=x_api_key)
    except HTTPException:
        return None
