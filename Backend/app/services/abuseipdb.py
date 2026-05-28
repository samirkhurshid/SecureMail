"""
AbuseIPDB API v2 integration.
Checks IP addresses for abuse history, geolocation and reputation.
Free tier: 1000 checks/day.
"""

import httpx
from app.config import get_settings
from app.utils.logger import setup_logger

logger = setup_logger(__name__)
settings = get_settings()

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


async def check_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for an IP address.
    Returns: abuse_confidence, country, isp, domain, reports, is_tor, risk_level.
    """
    if not settings.ABUSEIPDB_API_KEY:
        logger.warning("AbuseIPDB key not set — returning mock result")
        return _mock_result(ip)

    if not _is_routable(ip):
        return {"ip": ip, "risk_level": "clean", "abuse_confidence_score": 0,
                "country_code": "LOCAL", "isp": "Private/Reserved", "total_reports": 0,
                "_note": "Private/reserved IP — not queried"}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{ABUSEIPDB_BASE}/check",
                headers={
                    "Key": settings.ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=settings.SCAN_TIMEOUT_SECONDS,
            )

            if resp.status_code == 401:
                logger.error("AbuseIPDB: Invalid API key")
                return _error_result(ip, "invalid_api_key")

            if resp.status_code == 429:
                logger.warning("AbuseIPDB: Rate limit hit")
                return _error_result(ip, "rate_limited")

            if resp.status_code == 422:
                return _error_result(ip, "invalid_ip_format")

            if resp.status_code != 200:
                logger.error(f"AbuseIPDB HTTP {resp.status_code} for IP {ip}")
                return _error_result(ip, f"http_{resp.status_code}")

            data = resp.json().get("data", {})
            return _parse_response(data)

    except httpx.TimeoutException:
        logger.error(f"AbuseIPDB timeout for IP {ip}")
        return _error_result(ip, "timeout")
    except Exception as e:
        logger.error(f"AbuseIPDB error for IP {ip}: {e}")
        return _error_result(ip, str(e))


async def check_multiple_ips(ips: list) -> dict:
    """Check a list of IPs — returns dict keyed by IP."""
    import asyncio
    tasks = [check_ip(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {
        ip: (result if not isinstance(result, Exception) else _error_result(ip, str(result)))
        for ip, result in zip(ips, results)
    }


async def report_ip(ip: str, categories: list, comment: str) -> dict:
    """
    Report an IP address for abuse.
    Category codes: https://www.abuseipdb.com/categories
    Common: 18=Brute-Force, 19=Bad Web Bot, 20=Exploited Host, 21=Web App Attack
    """
    if not settings.ABUSEIPDB_API_KEY:
        return {"success": False, "error": "No API key configured"}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{ABUSEIPDB_BASE}/report",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                data={
                    "ip": ip,
                    "categories": ",".join(str(c) for c in categories),
                    "comment": comment[:1024],
                },
                timeout=10,
            )
            if resp.status_code == 200:
                return {"success": True, "data": resp.json().get("data", {})}
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_response(data: dict) -> dict:
    score = data.get("abuseConfidenceScore", 0)
    total_reports = data.get("totalReports", 0)

    risk_level = "clean"
    if score >= 80 or total_reports >= 50:
        risk_level = "high"
    elif score >= settings.ABUSEIPDB_CONFIDENCE_THRESHOLD or total_reports >= 10:
        risk_level = "medium"
    elif score > 0 or total_reports > 0:
        risk_level = "low"

    # Extract recent report categories
    recent = data.get("reports", [])[:5]
    seen_categories = []
    for report in recent:
        seen_categories.extend(report.get("categories", []))
    seen_categories = list(set(seen_categories))

    return {
        "ip": data.get("ipAddress", ""),
        "risk_level": risk_level,
        "abuse_confidence_score": score,
        "country_code": data.get("countryCode", ""),
        "country_name": data.get("countryName", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "total_reports": total_reports,
        "distinct_users": data.get("numDistinctUsers", 0),
        "last_reported": data.get("lastReportedAt", ""),
        "is_tor": data.get("isTor", False),
        "is_whitelisted": data.get("isWhitelisted", False),
        "usage_type": data.get("usageType", ""),
        "recent_abuse_categories": seen_categories,
    }


def _is_routable(ip: str) -> bool:
    """Return False for RFC1918, loopback, and other non-routable addresses."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved
                    or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


# ── Mock / error helpers ─────────────────────────────────────────────────────

def _mock_result(ip: str) -> dict:
    return {
        "ip": ip, "risk_level": "unknown", "abuse_confidence_score": 0,
        "country_code": "", "isp": "", "domain": "", "total_reports": 0,
        "last_reported": None, "is_tor": False,
        "_note": "No AbuseIPDB key — configure ABUSEIPDB_API_KEY in .env",
    }


def _error_result(ip: str, reason: str) -> dict:
    return {
        "ip": ip, "risk_level": "unknown", "abuse_confidence_score": 0,
        "country_code": "", "isp": "", "domain": "", "total_reports": 0,
        "error": reason,
    }
