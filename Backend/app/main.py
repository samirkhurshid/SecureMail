"""
Email Security Gateway — FastAPI Backend
Scans emails, attachments, URLs and headers for threats.
Integrates with VirusTotal and AbuseIPDB APIs.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time

from app.routers import scan, forensics, headers, attachments, settings as settings_router
from app.utils.logger import setup_logger
from app.config import get_settings

logger = setup_logger(__name__)
settings = get_settings()


app = FastAPI(
    title="Email Security Gateway API",
    description="Real-time email threat detection and forensic analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


app.include_router(scan.router, prefix="/api/scan", tags=["Email Scanning"])
app.include_router(forensics.router, prefix="/api/forensics", tags=["Forensics"])
app.include_router(headers.router, prefix="/api/headers", tags=["Header Analysis"])
app.include_router(attachments.router, prefix="/api/attachments", tags=["Attachments"])
app.include_router(settings_router.router, prefix="/api/settings", tags=["Settings"])


@app.get("/", tags=["Health"])
async def root():
    return {"status": "online", "service": "Email Security Gateway", "version": "1.0.0"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "timestamp": time.time()}
