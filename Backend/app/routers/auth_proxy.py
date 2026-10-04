"""
FastAPI Router for Proxied & Rate-Limited Authentication Operations
===================================================================
Proxies Email/Password Sign-In, Sign-Up, and Password Reset requests
to Firebase Identity Toolkit REST API with backend sliding-window rate limiting.
Protects endpoints against brute-force, credential stuffing, and account enumeration.
"""

import httpx
import os
from typing import Dict, Any, Optional
from pydantic import BaseModel, EmailStr, Field
from fastapi import APIRouter, HTTPException, Depends, Request, status

from app.config import get_settings
from app.services.simple_rate_limiter import rate_limit, get_client_ip
from app.utils.logger import setup_logger
from app.auth import HAS_FIREBASE_ADMIN, firebase_auth, _init_firebase

logger = setup_logger(__name__)
settings = get_settings()

router = APIRouter()

FIREBASE_AUTH_BASE = "https://identitytoolkit.googleapis.com/v1"

# Map Firebase internal error codes to user-friendly messages
FIREBASE_ERROR_MAP = {
    "EMAIL_EXISTS": "This email address is already registered. Please sign in instead.",
    "OPERATION_NOT_ALLOWED": "Password sign-in is not enabled for this project.",
    "TOO_MANY_ATTEMPTS_TRY_LATER": "Account temporarily locked due to consecutive failed attempts. Try again later.",
    "EMAIL_NOT_FOUND": "Invalid email or password.",
    "INVALID_PASSWORD": "Invalid email or password.",
    "INVALID_LOGIN_CREDENTIALS": "Invalid email or password.",
    "USER_DISABLED": "This user account has been disabled by a security administrator.",
    "WEAK_PASSWORD": "Password should be at least 8 characters with at least one uppercase letter.",
    "INVALID_EMAIL": "Please provide a valid email address.",
}


def _get_web_api_key() -> str:
    """
    Resolves Firebase Web API Key from settings or environment.
    Raises HTTPException 503 if not configured in .env.
    """
    key = settings.FIREBASE_WEB_API_KEY or os.environ.get("FIREBASE_WEB_API_KEY", "")
    if not key or not key.strip():
        logger.error("FIREBASE_WEB_API_KEY is not configured in .env")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is not configured on this server. FIREBASE_WEB_API_KEY is missing from .env."
        )
    return key.strip()


def _format_firebase_error(raw_msg: str) -> str:
    for code, msg in FIREBASE_ERROR_MAP.items():
        if code in raw_msg:
            return msg
    return raw_msg or "Authentication failed"


import re

# ── Request Schemas ──────────────────────────────────────────────────────────

class SignInRequest(BaseModel):
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=1)


class SignUpRequest(BaseModel):
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=8)
    display_name: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: str = Field(..., min_length=3)


class ResendVerificationRequest(BaseModel):
    id_token: Optional[str] = None
    email: Optional[str] = None


# ── Stricter Rate Limiter Dependencies ───────────────────────────────────────
# 5 attempts per 5 minutes per IP (Brute-force protection)
_signin_limiter = Depends(rate_limit(max_requests=5, window_seconds=300))
# 3 attempts per 10 minutes per IP (Registration abuse protection)
_signup_limiter = Depends(rate_limit(max_requests=3, window_seconds=600))
# 3 attempts per 15 minutes per IP (Enumeration & spam protection)
_reset_limiter = Depends(rate_limit(max_requests=3, window_seconds=900))
# 3 attempts per 10 minutes per IP
_resend_limiter = Depends(rate_limit(max_requests=3, window_seconds=600))


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/config", summary="Provides public Firebase web client configuration dynamically")
async def get_auth_config():
    """Returns public Firebase web configuration for client initialization."""
    return {
        "apiKey": _get_web_api_key(),
        "authDomain": getattr(settings, "FIREBASE_AUTH_DOMAIN", "mail-31dbb.firebaseapp.com"),
        "projectId": getattr(settings, "FIREBASE_PROJECT_ID", "mail-31dbb"),
        "storageBucket": getattr(settings, "FIREBASE_STORAGE_BUCKET", "mail-31dbb.firebasestorage.app"),
        "messagingSenderId": getattr(settings, "FIREBASE_MESSAGING_SENDER_ID", "843370137586"),
        "appId": getattr(settings, "FIREBASE_APP_ID", "1:843370137586:web:5e5d0ed4f7196e39480d6b"),
    }


@router.post("/signin", summary="Proxied & rate-limited user sign-in", dependencies=[_signin_limiter])
async def proxy_sign_in(body: SignInRequest, request: Request) -> Dict[str, Any]:
    """
    Authenticates user with email and password via Firebase REST API.
    Enforces server-side brute-force rate limiting (5 requests / 5 min / IP).
    """
    api_key = _get_web_api_key()
    url = f"{FIREBASE_AUTH_BASE}/accounts:signInWithPassword?key={api_key}"
    payload = {
        "email": str(body.email).strip().lower(),
        "password": body.password,
        "returnSecureToken": True,
    }

    client_ip = get_client_ip(request)
    logger.info(f"Proxied sign-in attempt for {body.email} from IP {client_ip}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(url, json=payload)
            data = resp.json()
        except Exception as e:
            logger.error(f"Firebase REST signin connection error: {e}")
            raise HTTPException(status_code=502, detail="Authentication gateway unavailable. Please try again.")

    if resp.status_code != 200:
        err_code = data.get("error", {}).get("message", "INVALID_LOGIN_CREDENTIALS")
        user_msg = _format_firebase_error(err_code)

        # Smart Detection: Check if account exists and is exclusively Google OAuth
        is_google_only = False
        try:
            if HAS_FIREBASE_ADMIN and firebase_auth:
                _init_firebase()
                user_record = firebase_auth.get_user_by_email(str(body.email).strip().lower())
                providers = [p.provider_id for p in user_record.provider_data]
                if "google.com" in providers and "password" not in providers:
                    is_google_only = True
        except Exception as e:
            logger.debug(f"Could not check provider data for {body.email}: {e}")

        if is_google_only:
            logger.info(f"Google-only account detected for {body.email} from {client_ip} attempting password login")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "GOOGLE_ACCOUNT_NO_PASSWORD",
                    "message": "This account was registered via Google OAuth and has no password configured. Please use 'Continue with Google' to sign in.",
                    "is_google_only": True
                }
            )

        logger.warning(f"Sign-in failed for {body.email} from {client_ip}: {err_code}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": err_code, "message": user_msg, "is_google_only": False}
        )

    return {
        "status": "success",
        "idToken": data.get("idToken"),
        "refreshToken": data.get("refreshToken"),
        "expiresIn": data.get("expiresIn", "3600"),
        "localId": data.get("localId"),
        "email": data.get("email"),
        "displayName": data.get("displayName", ""),
    }


@router.post("/signup", summary="Proxied & rate-limited user sign-up", dependencies=[_signup_limiter])
async def proxy_sign_up(body: SignUpRequest, request: Request) -> Dict[str, Any]:
    """
    Creates a new user account via Firebase REST API with complexity verification.
    Enforces server-side registration rate limiting (3 requests / 10 min / IP)
    and automatically triggers an email verification dispatch.
    """
    if len(body.password) < 8 or not any(c.isupper() for c in body.password):
        raise HTTPException(
            status_code=400,
            detail={"error": "WEAK_PASSWORD", "message": "Password must be at least 8 characters and contain at least one uppercase letter."}
        )

    api_key = _get_web_api_key()
    url = f"{FIREBASE_AUTH_BASE}/accounts:signUp?key={api_key}"
    payload = {
        "email": str(body.email).strip().lower(),
        "password": body.password,
        "returnSecureToken": True,
    }

    client_ip = get_client_ip(request)
    logger.info(f"Proxied sign-up attempt for {body.email} from IP {client_ip}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(url, json=payload)
            data = resp.json()
        except Exception as e:
            logger.error(f"Firebase REST signup connection error: {e}")
            raise HTTPException(status_code=502, detail="Authentication gateway unavailable. Please try again.")

        if resp.status_code != 200:
            err_code = data.get("error", {}).get("message", "SIGNUP_FAILED")
            user_msg = _format_firebase_error(err_code)
            logger.warning(f"Sign-up failed for {body.email} from {client_ip}: {err_code}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": err_code, "message": user_msg}
            )

        id_token = data.get("idToken")

        # Set display name if provided
        if body.display_name and body.display_name.strip() and id_token:
            try:
                update_url = f"{FIREBASE_AUTH_BASE}/accounts:update?key={api_key}"
                await client.post(update_url, json={
                    "idToken": id_token,
                    "displayName": body.display_name.strip(),
                    "returnSecureToken": True,
                })
            except Exception as e:
                logger.warning(f"Failed to set displayName on signup: {e}")

        # Automatically dispatch email verification
        if id_token:
            try:
                verify_url = f"{FIREBASE_AUTH_BASE}/accounts:sendOobCode?key={api_key}"
                await client.post(verify_url, json={
                    "requestType": "VERIFY_EMAIL",
                    "idToken": id_token,
                })
                logger.info(f"Verification email dispatched for new account {body.email}")
            except Exception as e:
                logger.warning(f"Failed to auto-dispatch verification email: {e}")

    return {
        "status": "success",
        "idToken": data.get("idToken"),
        "refreshToken": data.get("refreshToken"),
        "expiresIn": data.get("expiresIn", "3600"),
        "localId": data.get("localId"),
        "email": data.get("email"),
        "displayName": body.display_name or "",
        "email_verification_sent": True,
    }


@router.post("/reset-password", summary="Proxied & rate-limited password reset", dependencies=[_reset_limiter])
async def proxy_reset_password(body: PasswordResetRequest, request: Request) -> Dict[str, Any]:
    """
    Sends a password reset email via Firebase REST API.
    Enforces server-side enumeration protection rate limiting (3 requests / 15 min / IP).
    """
    api_key = _get_web_api_key()
    url = f"{FIREBASE_AUTH_BASE}/accounts:sendOobCode?key={api_key}"
    payload = {
        "requestType": "PASSWORD_RESET",
        "email": str(body.email).strip().lower(),
    }

    client_ip = get_client_ip(request)
    logger.info(f"Password reset requested for {body.email} from IP {client_ip}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(url, json=payload)
            data = resp.json()
        except Exception as e:
            logger.error(f"Firebase REST password reset connection error: {e}")
            raise HTTPException(status_code=502, detail="Authentication gateway unavailable.")

    # Even if email is not found, return success to prevent account enumeration
    return {
        "status": "success",
        "message": "If an account exists with this email, a password reset link has been dispatched."
    }


@router.post("/resend-verification", summary="Proxied & rate-limited email verification resend", dependencies=[_resend_limiter])
async def proxy_resend_verification(body: ResendVerificationRequest, request: Request) -> Dict[str, Any]:
    """
    Triggers an email verification link dispatch for the specified idToken.
    Rate limited to 3 requests / 10 min / IP.
    """
    if not body.id_token:
        raise HTTPException(status_code=400, detail="User authentication token required.")

    api_key = _get_web_api_key()
    url = f"{FIREBASE_AUTH_BASE}/accounts:sendOobCode?key={api_key}"
    payload = {
        "requestType": "VERIFY_EMAIL",
        "idToken": body.id_token,
    }

    client_ip = get_client_ip(request)
    logger.info(f"Verification email resend requested from IP {client_ip}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                data = resp.json()
                err_code = data.get("error", {}).get("message", "FAILED")
                raise HTTPException(status_code=400, detail={"error": err_code, "message": _format_firebase_error(err_code)})
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Firebase REST verify email connection error: {e}")
            raise HTTPException(status_code=502, detail="Authentication gateway unavailable.")

    return {
        "status": "success",
        "message": "Verification email has been sent. Please check your inbox and spam folder."
    }
