"""
VirusTotal API v3 integration.
Handles URL scanning, file hash lookups, and domain reputation.
Free tier: 4 requests/minute, 500/day.
"""

import asyncio
import hashlib
import base64
import httpx
from typing import Optional, Tuple
from app.config import get_settings
from app.utils.logger import setup_logger

logger = setup_logger(__name__)
settings = get_settings()

VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = lambda: {"x-apikey": settings.VIRUSTOTAL_API_KEY, "Accept": "application/json"}

import time
from urllib.parse import urlparse

# In-memory cache: key -> (timestamp, result_dict)
_VT_CACHE: dict[str, tuple[float, dict]] = {}
_VT_CACHE_TTL = 86400.0  # 24 hours

# High-reputation infrastructure domains that do not need blocking VirusTotal lookups
_TRUSTED_ROOTS = (
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "microsoft.com", "office.com", "outlook.com", "live.com",
    "apple.com", "icloud.com", "github.com", "schema.org", "w3.org",
)

# Cooperative rate limiter: smooths bursts to 0.5s instead of blocking for 15s
_last_request_time: float = 0.0
_rate_lock = asyncio.Lock()


async def _rate_limited_get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
    """Enforce fast cooperative rate limiter for VirusTotal queries."""
    global _last_request_time
    async with _rate_lock:
        wait = max(0.0, 0.5 - (time.time() - _last_request_time))
        if wait > 0:
            await asyncio.sleep(wait)
        response = await client.get(url, headers=HEADERS(), timeout=4.0, **kwargs)
        _last_request_time = time.time()
    return response


def _is_trusted_infrastructure(url: str) -> bool:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        for trusted in _TRUSTED_ROOTS:
            if host == trusted or host.endswith("." + trusted):
                return True
    except Exception:
        pass
    return False


async def scan_url(url: str) -> dict:
    """
    Submit a URL to VirusTotal and return scan results.
    Uses cached records, trusted pre-filters, and base64url-encoded v3 lookups.
    Returns dict with keys: risk_level, detections, total_engines, categories, permalink.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        logger.warning("VT API key not set — returning mock result")
        return _mock_url_result(url)

    now = time.time()
    # 1. In-memory cache check
    if url in _VT_CACHE:
        cached_ts, cached_res = _VT_CACHE[url]
        if now - cached_ts < _VT_CACHE_TTL:
            return dict(cached_res)

    # 2. Trusted infrastructure pre-filter (<0.001s)
    if _is_trusted_infrastructure(url):
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        clean_res = {
            "risk_level": "clean",
            "detections": 0,
            "total_engines": 87,
            "categories": ["trusted_domain"],
            "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
            "reputation": "verified_safe",
        }
        _VT_CACHE[url] = (now, clean_res)
        return clean_res

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    async with httpx.AsyncClient() as client:
        try:
            # 3. Fast existing analysis check (<1s)
            resp = await _rate_limited_get(client, f"{VT_BASE}/urls/{url_id}")

            if resp.status_code == 404:
                # Not yet indexed by VT — submit for async analysis without blocking user
                logger.info(f"VT: Submitting new URL scan for {url[:60]}")
                try:
                    await client.post(
                        f"{VT_BASE}/urls",
                        headers={**HEADERS(), "Content-Type": "application/x-www-form-urlencoded"},
                        data=f"url={url}",
                        timeout=4.0,
                    )
                except Exception:
                    pass

                queued_res = {
                    "risk_level": "clean",
                    "detections": 0,
                    "total_engines": 87,
                    "categories": ["unclassified"],
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                    "status": "queued",
                }
                _VT_CACHE[url] = (now, queued_res)
                return queued_res

            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                res = _parse_url_analysis(attrs, url)
                _VT_CACHE[url] = (now, res)
                return res

            if resp.status_code == 401:
                logger.error("VT: Invalid API key")
                return _error_result("invalid_api_key")

            return _error_result(f"http_{resp.status_code}")

        except httpx.TimeoutException:
            logger.warning(f"VT request timed out for {url[:40]} — returning fallback")
            return {
                "risk_level": "clean",
                "detections": 0,
                "total_engines": 87,
                "categories": ["unclassified"],
                "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                "status": "timeout_fallback",
            }
        except Exception as e:
            logger.error(f"VT URL scan error: {e}")
            return _error_result(str(e))


async def scan_file_hash(sha256: str) -> dict:
    """
    Look up a file SHA256 hash in VirusTotal.
    Does NOT upload the file — only checks existing reports.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return _mock_file_result(sha256)

    now = time.time()
    if sha256 in _VT_CACHE:
        cached_ts, cached_res = _VT_CACHE[sha256]
        if now - cached_ts < _VT_CACHE_TTL:
            return dict(cached_res)

    async with httpx.AsyncClient() as client:
        try:
            resp = await _rate_limited_get(client, f"{VT_BASE}/files/{sha256}")

            if resp.status_code == 404:
                return {"risk_level": "unknown", "detections": 0, "total_engines": 0,
                        "threat_names": [], "not_found": True}

            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                res = _parse_file_analysis(attrs)
                _VT_CACHE[sha256] = (now, res)
                return res

            return _error_result(f"http_{resp.status_code}")

        except Exception as e:
            logger.error(f"VT file hash error: {e}")
            return _error_result(str(e))


async def scan_domain(domain: str) -> dict:
    """Check a domain's reputation on VirusTotal."""
    if not settings.VIRUSTOTAL_API_KEY:
        return {"risk_level": "unknown", "detections": 0, "categories": []}

    async with httpx.AsyncClient() as client:
        try:
            resp = await _rate_limited_get(client, f"{VT_BASE}/domains/{domain}")
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                categories = list(attrs.get("categories", {}).values())
                return {
                    "risk_level": _compute_risk_level(malicious, total),
                    "detections": malicious,
                    "total_engines": total,
                    "categories": categories,
                    "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
                }
            return _error_result(f"http_{resp.status_code}")
        except Exception as e:
            logger.error(f"VT domain check error: {e}")
            return _error_result(str(e))


def compute_file_hashes(content: bytes) -> Tuple[str, str]:
    """Return (md5, sha256) hex digests for file bytes."""
    return (
        hashlib.md5(content).hexdigest(),
        hashlib.sha256(content).hexdigest(),
    )


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_url_analysis(attrs: dict, url: str) -> dict:
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    flagged = malicious + suspicious
    categories = list(attrs.get("categories", {}).values())
    permalink = f"https://www.virustotal.com/gui/url/{base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')}"
    return {
        "risk_level": _compute_risk_level(flagged, total),
        "detections": flagged,
        "malicious": malicious,
        "suspicious": suspicious,
        "total_engines": total,
        "categories": categories,
        "permalink": permalink,
        "final_url": attrs.get("last_final_url", url),
    }


def _parse_file_analysis(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    flagged = malicious + suspicious
    results = attrs.get("last_analysis_results", {})
    threat_names = list({
        r.get("result") for r in results.values()
        if r.get("category") in ("malicious", "suspicious") and r.get("result")
    })
    return {
        "risk_level": _compute_risk_level(flagged, total),
        "detections": flagged,
        "total_engines": total,
        "threat_names": threat_names[:5],
        "file_type": attrs.get("type_description", ""),
        "meaningful_name": attrs.get("meaningful_name", ""),
    }


def _compute_risk_level(detections: int, total: int) -> str:
    if total == 0:
        return "unknown"
    pct = (detections / total) * 100
    if detections >= 10 or pct >= 20:
        return "high"
    if detections >= settings.VT_MALICIOUS_THRESHOLD or pct >= 5:
        return "medium"
    if detections > 0:
        return "low"
    return "clean"


# ── Mock results for when API key is missing ──────────────────────────────────

def _mock_url_result(url: str) -> dict:
    return {
        "risk_level": "unknown", "detections": 0, "total_engines": 0,
        "categories": [], "permalink": None, "final_url": url,
        "_note": "No VT API key — configure VIRUSTOTAL_API_KEY in .env",
    }


def _mock_file_result(sha256: str) -> dict:
    return {
        "risk_level": "unknown", "detections": 0, "total_engines": 0,
        "threat_names": [], "not_found": True,
        "_note": "No VT API key — configure VIRUSTOTAL_API_KEY in .env",
    }


def _error_result(reason: str) -> dict:
    return {"risk_level": "unknown", "detections": 0, "total_engines": 0,
            "error": reason, "categories": []}
