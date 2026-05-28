"""
Settings router.
POST /api/settings/keys  — Save API keys from the frontend UI
GET  /api/settings/status — Check which integrations are active
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import os
from app.utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()


class KeysPayload(BaseModel):
    virustotal_api_key: Optional[str] = ""
    abuseipdb_api_key: Optional[str] = ""


@router.post("/keys", summary="Update API keys at runtime")
async def save_keys(payload: KeysPayload):
    """
    Set VirusTotal and AbuseIPDB keys from the frontend Settings page.
    Keys are applied to the running process immediately (no restart needed).
    They are also written to .env so they survive restarts.
    """
    updated = []

    if payload.virustotal_api_key and payload.virustotal_api_key.strip():
        os.environ["VIRUSTOTAL_API_KEY"] = payload.virustotal_api_key.strip()
        updated.append("VIRUSTOTAL_API_KEY")
        # Bust the settings cache so services pick up the new key
        from app.config import get_settings
        get_settings.cache_clear()
        logger.info("VirusTotal API key updated via UI")

    if payload.abuseipdb_api_key and payload.abuseipdb_api_key.strip():
        os.environ["ABUSEIPDB_API_KEY"] = payload.abuseipdb_api_key.strip()
        updated.append("ABUSEIPDB_API_KEY")
        from app.config import get_settings
        get_settings.cache_clear()
        logger.info("AbuseIPDB API key updated via UI")

    # Persist to .env file
    if updated:
        _write_env_keys(
            payload.virustotal_api_key or "",
            payload.abuseipdb_api_key or "",
        )

    return {
        "success": True,
        "updated": updated,
        "message": f"Updated {len(updated)} key(s). Active immediately." if updated else "No keys provided.",
    }


@router.get("/status", summary="Check integration status")
async def get_status():
    """Returns which API integrations are currently configured."""
    from app.config import get_settings
    s = get_settings()
    return {
        "virustotal": {
            "configured": bool(s.VIRUSTOTAL_API_KEY),
            "key_preview": f"{s.VIRUSTOTAL_API_KEY[:6]}…" if s.VIRUSTOTAL_API_KEY else None,
            "rate_limit": f"{s.VT_REQUESTS_PER_MINUTE} req/min",
        },
        "abuseipdb": {
            "configured": bool(s.ABUSEIPDB_API_KEY),
            "key_preview": f"{s.ABUSEIPDB_API_KEY[:6]}…" if s.ABUSEIPDB_API_KEY else None,
            "rate_limit": f"{s.ABUSEIPDB_REQUESTS_PER_DAY} req/day",
        },
        "forensics_dir": s.FORENSICS_LOG_DIR,
        "max_attachment_mb": s.MAX_ATTACHMENT_SIZE_MB,
    }


def _write_env_keys(vt: str, abuse: str):
    """Merge new keys into .env file without clobbering other values."""
    env_path = ".env"
    lines = []
    if os.path.exists(env_path):
        with open(env_path) as f:
            lines = f.readlines()

    def _set(lines, key, value):
        if not value:
            return lines
        for i, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                return lines
        lines.append(f"{key}={value}\n")
        return lines

    lines = _set(lines, "VIRUSTOTAL_API_KEY", vt)
    lines = _set(lines, "ABUSEIPDB_API_KEY", abuse)

    with open(env_path, "w") as f:
        f.writelines(lines)
    logger.info("API keys written to .env")
