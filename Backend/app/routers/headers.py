"""
Header analysis router.
POST /api/headers/analyze        — Parse raw email headers, IP lookup, risk score
GET  /api/headers/ip-reputation  — Quick IP reputation check (used by frontend Threat Analysis page)
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from app.services import email_parser, abuseipdb, risk_scorer
from app.utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()


class HeaderAnalysisRequest(BaseModel):
    raw_headers: str


@router.post("/analyze")
async def analyze_headers(request: HeaderAnalysisRequest):
    """
    Parse raw email headers.
    - Extracts SPF / DKIM / DMARC / ARC
    - Looks up originating IP via AbuseIPDB
    - Detects display name spoof, reply-to mismatch
    - Computes a risk score based on header signals alone
    """
    if not request.raw_headers or not request.raw_headers.strip():
        raise HTTPException(status_code=400, detail="Headers cannot be empty")

    parsed = email_parser.parse_raw_email(request.raw_headers)
    headers = parsed.get("headers", {})

    auth_raw = headers.get("authentication_results", "")
    auth = email_parser.parse_auth_header(auth_raw)

    if headers.get("dkim_signature") and auth.get("dkim") == "unknown":
        auth["dkim"] = "present_unverified"

    # ── IP reputation lookup ──────────────────────────────────────
    originating_ip = headers.get("originating_ip") or headers.get("x_originating_ip")
    ip_reputation = None
    if originating_ip:
        logger.info(f"Header analysis — checking IP: {originating_ip}")
        ip_reputation = await abuseipdb.check_ip(originating_ip)

    # ── Risk score from header signals only ───────────────────────
    phishing = parsed.get("phishing_indicators", {})
    score, risk_level, threat_types = risk_scorer.compute_email_risk_score(
        auth=auth,
        phishing=phishing,
        urls=[],
        attachments=[],
        ip_reputation=ip_reputation,
        headers=headers,
    )
    summary = risk_scorer.summarise(score, risk_level, threat_types)

    # ── Anomaly list ──────────────────────────────────────────────
    anomalies = []
    if headers.get("display_name_spoof"):
        anomalies.append("Display name impersonates a known brand")
    if headers.get("reply_to_mismatch"):
        anomalies.append("Reply-To domain differs from envelope sender")
    if auth.get("spf") == "fail":
        anomalies.append("SPF authentication failed")
    if auth.get("dkim") in ("fail", "none"):
        anomalies.append("DKIM signature missing or invalid")
    if auth.get("dmarc") == "fail":
        anomalies.append("DMARC policy failed")

    return {
        "authentication": auth,
        "sender": {
            "display_name": headers.get("display_name", ""),
            "display_name_spoof": headers.get("display_name_spoof", False),
            "from_email": headers.get("from_email", ""),
            "from_domain": headers.get("from_domain", ""),
            "reply_to": headers.get("reply_to", ""),
            "reply_to_domain": headers.get("reply_to_domain", ""),
            "reply_to_mismatch": headers.get("reply_to_mismatch", False),
        },
        "originating_ip": originating_ip,
        "ip_reputation": ip_reputation,
        "risk_score": score,
        "risk_level": risk_level,
        "threat_types": threat_types,
        "summary": summary,
        "anomalies": anomalies,
        "date": headers.get("date"),
        "subject": headers.get("subject"),
        "message_id": headers.get("message_id"),
        "x_mailer": headers.get("x_mailer"),
    }


@router.get("/ip-reputation")
async def ip_reputation(ip: str = Query(..., description="IPv4 or IPv6 address to check")):
    """
    Quick IP reputation lookup via AbuseIPDB.
    Used by the Threat Analysis page IP scanner.
    GET /api/headers/ip-reputation?ip=185.234.218.47
    """
    if not ip or not ip.strip():
        raise HTTPException(status_code=400, detail="ip query parameter is required")

    logger.info(f"IP reputation check: {ip}")
    result = await abuseipdb.check_ip(ip.strip())
    return {"ip": ip, "ip_reputation": result}
