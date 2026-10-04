"""
Email Security Gateway — FastAPI Backend
Scans emails, attachments, URLs and headers for threats.
Integrates with VirusTotal and AbuseIPDB APIs.
"""

from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import time
import os

from app.routers import (
    scan, forensics, headers, attachments,
    settings as settings_router, ai as ai_router,
    account as account_router, threat_intel as threat_intel_router,
    api_keys as api_keys_router, audit as audit_router,
    auth_proxy as auth_proxy_router, organization as organization_router,
)
from app.services import threat_intel_service, rbac_service, api_key_service, audit_service, organization_service
from app.utils.logger import setup_logger
from app.config import get_settings
from app.auth import get_current_user

logger = setup_logger(__name__)
settings = get_settings()

# Initialize Threat Vault, RBAC, API Keys, Audit Trail & Organization databases
try:
    threat_intel_service.init_threat_vault_db()
    rbac_service.init_user_roles_db()
    api_key_service.init_api_keys_db()
    audit_service.init_audit_db()
    organization_service.init_org_db()
except Exception as _e:
    logger.warning(f"Database initialization warning: {_e}")

# Resolve the Frontend directory (Backend/app/main.py -> Backend/ -> project root -> Frontend/)
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.normpath(os.path.join(_BACKEND_DIR, "..", "Frontend"))


app = FastAPI(
    title="Email Security Gateway API",
    description="Real-time email threat detection and forensic analysis",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS Configuration ───────────────────────────────────────────────────────
cors_origins = settings.cors_origins
has_wildcard = "*" in cors_origins

if has_wildcard:
    logger.warning(
        "WARNING: CORS is set to allow all origins (*). This is insecure for production. "
        "Set CORS_ALLOWED_ORIGINS in .env before deploying publicly."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    # Browsers reject allow_credentials=True when allow_origins is wildcard "*"
    allow_credentials=not has_wildcard,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Inject Security Headers on all HTTP responses.
    CSP Policy allows Firebase SDK, Google Auth popups, and frontend inline scripts.
    NOTE: 'unsafe-inline' is included in script-src to support embedded scripts in index.html.
    """
    response = await call_next(request)
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://www.gstatic.com https://apis.google.com",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https://*.googleusercontent.com",
        "connect-src 'self' https://*.googleapis.com https://*.firebaseapp.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com",
        "frame-src https://mail-31dbb.firebaseapp.com https://accounts.google.com",
        "font-src 'self' data:",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 2)
    logger.info(f"{request.method} {request.url.path} -> {response.status_code} ({duration}ms)")
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {exc}")
    # Never expose raw exception details in production
    detail = str(exc) if settings.APP_ENV == "development" else "An unexpected error occurred"
    return JSONResponse(status_code=500, content={"error": "Internal server error", "detail": detail})


# Public / Optional Auth routers
app.include_router(auth_proxy_router.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan.router, prefix="/api/scan", tags=["Email Scanning"])
app.include_router(ai_router.router, prefix="/api/ai", tags=["AI Analysis"])
app.include_router(threat_intel_router.router, prefix="/api/threat-intel", tags=["Threat Intelligence"])
app.include_router(account_router.router, prefix="/api/account", tags=["Account"])

# Protected routers — requests must carry a valid Firebase ID token
_auth_dep = [Depends(get_current_user)]

app.include_router(forensics.router, prefix="/api/forensics", tags=["Forensics"], dependencies=_auth_dep)
app.include_router(headers.router, prefix="/api/headers", tags=["Header Analysis"], dependencies=_auth_dep)
app.include_router(attachments.router, prefix="/api/attachments", tags=["Attachments"], dependencies=_auth_dep)
app.include_router(settings_router.router, prefix="/api/settings", tags=["Settings"], dependencies=_auth_dep)
app.include_router(api_keys_router.router, prefix="/api/api-keys", tags=["API Keys"], dependencies=_auth_dep)
app.include_router(audit_router.router, prefix="/api/audit-trail", tags=["Compliance Audit Trail"], dependencies=_auth_dep)
app.include_router(organization_router.router, prefix="/api/org", tags=["Organization Sandbox"], dependencies=_auth_dep)


@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
async def health():
    return {"status": "healthy", "timestamp": time.time()}


# ── Serve the Frontend dashboard ──────────────────────────────────────────────
# Mounting the Frontend folder lets the browser load index.html from the same
# origin as the API (http://localhost:8000), eliminating all file:// CORS issues.

if os.path.isdir(FRONTEND_DIR):
    # Serve index.html at the root
    @app.get("/", tags=["Dashboard"])
    async def serve_dashboard():
        """Serve the SecureMail dashboard."""
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    # Mount everything else (images, fonts, etc.) under /assets
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
else:
    logger.warning(f"Frontend directory not found at {FRONTEND_DIR} — dashboard not served")

    @app.get("/", tags=["Health"])
    async def root():
        return {"status": "online", "service": "Email Security Gateway", "version": "3.0.0"}
