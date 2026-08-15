"""
Email Security Gateway — FastAPI Backend
Scans emails, attachments, URLs and headers for threats.
Integrates with VirusTotal and AbuseIPDB APIs.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import time
import os

from fastapi import Depends
from app.routers import scan, forensics, headers, attachments, settings as settings_router, ai as ai_router, account as account_router
from app.utils.logger import setup_logger
from app.config import get_settings
from app.auth import get_current_user

logger = setup_logger(__name__)
settings = get_settings()

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


# Scan and AI routers allow optional auth for anonymous trial scans
app.include_router(scan.router, prefix="/api/scan", tags=["Email Scanning"])
app.include_router(ai_router.router, prefix="/api/ai", tags=["AI Analysis"])

# Protected routers — requests must carry a valid Firebase ID token
_auth_dep = [Depends(get_current_user)]

app.include_router(forensics.router, prefix="/api/forensics", tags=["Forensics"], dependencies=_auth_dep)
app.include_router(headers.router, prefix="/api/headers", tags=["Header Analysis"], dependencies=_auth_dep)
app.include_router(attachments.router, prefix="/api/attachments", tags=["Attachments"], dependencies=_auth_dep)
app.include_router(settings_router.router, prefix="/api/settings", tags=["Settings"], dependencies=_auth_dep)
app.include_router(account_router.router, prefix="/api/account", tags=["Account"], dependencies=_auth_dep)


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "timestamp": time.time()}


@app.get("/api/auth/config", tags=["Authentication"])
async def get_auth_config():
    """Provides public Firebase web client configuration dynamically."""
    return {
        "apiKey": settings.FIREBASE_WEB_API_KEY or os.environ.get("FIREBASE_WEB_API_KEY", ""),
        "authDomain": settings.FIREBASE_AUTH_DOMAIN,
        "projectId": settings.FIREBASE_PROJECT_ID,
        "storageBucket": settings.FIREBASE_STORAGE_BUCKET,
        "messagingSenderId": settings.FIREBASE_MESSAGING_SENDER_ID,
        "appId": settings.FIREBASE_APP_ID,
    }


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
