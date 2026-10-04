"""
Settings router.
GET  /api/settings/status  — Show which integrations are active (keys masked)
GET  /api/settings/test    — Live ping both APIs with real HTTP calls
NOTE: POST /api/settings/keys is intentionally REMOVED.
      API keys are managed ONLY via the server .env file — never from frontend.
"""

import time
from fastapi import APIRouter, Depends
from app.config import get_settings
from app.utils.logger import setup_logger
from app.services.simple_rate_limiter import rate_limit

logger = setup_logger(__name__)
router = APIRouter()

# 10 requests per minute rate limit on sensitive settings endpoints
_rate_limiter = Depends(rate_limit(max_requests=10, window_seconds=60))


@router.get("/status", summary="Integration status — keys always masked", dependencies=[_rate_limiter])
async def get_status():
    """
    Returns which API integrations are configured.
    Keys are ALWAYS masked — full values never exposed through any endpoint.
    """
    s = get_settings()
    return {
        "virustotal": {
            "configured": bool(s.VIRUSTOTAL_API_KEY),
            "key_preview": s.mask_key(s.VIRUSTOTAL_API_KEY),
            "rate_limit": f"{s.VT_REQUESTS_PER_MINUTE} req/min",
        },
        "abuseipdb": {
            "configured": bool(s.ABUSEIPDB_API_KEY),
            "key_preview": s.mask_key(s.ABUSEIPDB_API_KEY),
            "rate_limit": f"{s.ABUSEIPDB_REQUESTS_PER_DAY} req/day",
        },
        "anthropic": {
            "configured": bool(s.ANTHROPIC_API_KEY),
            "key_preview": s.mask_key(s.ANTHROPIC_API_KEY),
        },
        "gemini": {
            "configured": bool(s.GEMINI_API_KEY),
            "key_preview": s.mask_key(s.GEMINI_API_KEY),
        },
        "forensics_dir": s.FORENSICS_LOG_DIR,
        "max_attachment_mb": s.MAX_ATTACHMENT_SIZE_MB,
        "_note": "API keys are managed via server .env file only"
    }


@router.get("/test", summary="Live connection test — pings all 3 APIs", dependencies=[_rate_limiter])
async def test_connections():
    """
    Makes real HTTP calls to VirusTotal, AbuseIPDB and Anthropic.
    Proves the keys work without ever returning the actual key values.
    """
    import httpx
    s = get_settings()
    results = {}

    # ── VirusTotal ────────────────────────────────────────────────
    if not s.VIRUSTOTAL_API_KEY:
        results["virustotal"] = {"status": "not_configured", "connected": False,
                                 "message": "Add VIRUSTOTAL_API_KEY to .env"}
    else:
        t0 = time.time()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQ",
                    headers={"x-apikey": s.VIRUSTOTAL_API_KEY},
                    timeout=10,
                )
            ms = round((time.time()-t0)*1000)
            if resp.status_code == 200:
                attrs = resp.json().get("data",{}).get("attributes",{})
                stats = attrs.get("last_analysis_stats",{})
                results["virustotal"] = {
                    "status": "ok", "connected": True, "http_status": 200,
                    "response_time_ms": ms,
                    "message": "✓ Connected to VirusTotal v3",
                    "proof": {
                        "endpoint": "GET /api/v3/urls/{id}",
                        "test_url": "google.com",
                        "engines_total": sum(stats.values()) if stats else 0,
                        "key_preview": s.mask_key(s.VIRUSTOTAL_API_KEY),
                    }
                }
            elif resp.status_code == 401:
                results["virustotal"] = {"status": "invalid_key", "connected": True,
                                         "http_status": 401, "response_time_ms": ms,
                                         "message": "✗ API key rejected by VirusTotal"}
            elif resp.status_code == 429:
                results["virustotal"] = {"status": "rate_limited", "connected": True,
                                         "http_status": 429, "response_time_ms": ms,
                                         "message": "⚠ Key valid but quota exceeded"}
            else:
                results["virustotal"] = {"status": "error", "connected": True,
                                         "http_status": resp.status_code, "response_time_ms": ms,
                                         "message": f"HTTP {resp.status_code}"}
        except Exception as e:
            results["virustotal"] = {"status": "error", "connected": False, "message": str(e)}

    # ── AbuseIPDB ─────────────────────────────────────────────────
    if not s.ABUSEIPDB_API_KEY:
        results["abuseipdb"] = {"status": "not_configured", "connected": False,
                                "message": "Add ABUSEIPDB_API_KEY to .env"}
    else:
        t0 = time.time()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": s.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
                    timeout=10,
                )
            ms = round((time.time()-t0)*1000)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                results["abuseipdb"] = {
                    "status": "ok", "connected": True, "http_status": 200,
                    "response_time_ms": ms,
                    "message": "✓ Connected to AbuseIPDB v2",
                    "proof": {
                        "endpoint": "GET /api/v2/check",
                        "test_ip": "8.8.8.8 (Google DNS)",
                        "abuse_score": data.get("abuseConfidenceScore", 0),
                        "isp": data.get("isp", ""),
                        "key_preview": s.mask_key(s.ABUSEIPDB_API_KEY),
                    }
                }
            elif resp.status_code == 401:
                results["abuseipdb"] = {"status": "invalid_key", "connected": True,
                                        "http_status": 401, "response_time_ms": ms,
                                        "message": "✗ API key rejected by AbuseIPDB"}
            elif resp.status_code == 429:
                results["abuseipdb"] = {"status": "rate_limited", "connected": True,
                                        "http_status": 429, "response_time_ms": ms,
                                        "message": "⚠ Daily quota exceeded"}
            else:
                results["abuseipdb"] = {"status": "error", "connected": True,
                                        "http_status": resp.status_code, "response_time_ms": ms,
                                        "message": f"HTTP {resp.status_code}"}
        except Exception as e:
            results["abuseipdb"] = {"status": "error", "connected": False, "message": str(e)}

    # ── Anthropic ─────────────────────────────────────────────────
    if not s.ANTHROPIC_API_KEY:
        results["anthropic"] = {"status": "not_configured", "connected": False,
                                "message": "Add ANTHROPIC_API_KEY to .env"}
    else:
        t0 = time.time()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": s.ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-3-5-haiku-20241022",
                        "max_tokens": 10,
                        "messages": [{"role": "user", "content": "ping"}],
                    },
                    timeout=10,
                )
            ms = round((time.time()-t0)*1000)
            if resp.status_code == 200:
                results["anthropic"] = {
                    "status": "ok", "connected": True, "http_status": 200,
                    "response_time_ms": ms,
                    "message": "✓ Connected to Anthropic API",
                    "proof": {
                        "model": "claude-3-5-sonnet-20241022 (for explanations)",
                        "key_preview": s.mask_key(s.ANTHROPIC_API_KEY),
                    }
                }
            elif resp.status_code == 401:
                results["anthropic"] = {"status": "invalid_key", "connected": True,
                                        "http_status": 401, "response_time_ms": ms,
                                        "message": "✗ API key rejected by Anthropic"}
            elif resp.status_code == 429:
                results["anthropic"] = {"status": "rate_limited", "connected": True,
                                        "http_status": 429, "response_time_ms": ms,
                                        "message": "⚠ Rate limit hit"}
            else:
                results["anthropic"] = {"status": "error", "connected": True,
                                        "http_status": resp.status_code, "response_time_ms": ms,
                                        "message": f"HTTP {resp.status_code}"}
        except Exception as e:
            results["anthropic"] = {"status": "error", "connected": False, "message": str(e)}

    overall = all(r.get("status") == "ok" for r in results.values())
    return {
        "overall": "fully_operational" if overall else "partial_or_offline",
        "tested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "services": results,
    }
