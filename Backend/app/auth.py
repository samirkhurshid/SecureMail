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

    def __init__(self, uid: str, email: Optional[str], email_verified: bool, name: Optional[str]):
        self.uid = uid
        self.email = email
        self.email_verified = email_verified
        self.name = name

    def __repr__(self):
        return f"<CurrentUser uid={self.uid} email={self.email}>"


async def get_current_user(authorization: Optional[str] = Header(None)) -> CurrentUser:
    """
    FastAPI dependency — verifies the Firebase ID token and returns the user.
    Use as: async def endpoint(user: CurrentUser = Depends(get_current_user)):

    Raises 401 if:
      - No Authorization header provided
      - Token is malformed, expired, or invalid
      - Firebase Admin SDK is not configured on the server
    """
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


async def get_optional_user(authorization: Optional[str] = Header(None)) -> Optional[CurrentUser]:
    """
    Same as get_current_user but returns None instead of raising when no
    token is provided. Use for endpoints that work both authenticated and
    anonymous (rare — most of SecureMail requires full auth per your spec).
    """
    if not authorization:
        return None
    try:
        return await get_current_user(authorization)
    except HTTPException:
        return None
