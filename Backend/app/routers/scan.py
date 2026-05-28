"""
Email scan router.
POST /api/scan/email  — Full email analysis pipeline
POST /api/scan/url    — Single URL check via VirusTotal
POST /api/scan/ip     — Single IP reputation check via AbuseIPDB
"""

import uuid
import time
import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks
from app.models.schemas import EmailScanRequest, URLScanRequest, IPCheckRequest
from app.services import virustotal, abuseipdb, email_parser, risk_scorer
from app.services.forensics import save_forensic_log
from app.utils.logger import setup_logger
from typing import Any, Dict

logger = setup_logger(__name__)
router = APIRouter()

# ── OpenAPI response examples ────────────────────────────────────
_EMAIL_SCAN_EXAMPLE = {
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "scanned_at": "2026-05-27T10:00:00Z",
    "scan_duration_ms": 820,
    "risk_score": 87,
    "risk_level": "critical",
    "threat_types": ["phishing", "spoofing"],
    "summary": "CRITICAL RISK (score 87/100) — phishing attempt, sender spoofing detected.",
    "sender_email": "noreply@paypa1-support.ru",
    "subject": "Urgent: Your account has been suspended",
    "authentication": {"spf": "fail", "dkim": "fail", "dmarc": "fail", "arc": "unknown"},
    "header_analysis": {
        "originating_ip": "185.234.218.47",
        "ip_reputation": {
            "ip": "185.234.218.47",
            "risk_level": "high",
            "abuse_confidence_score": 92,
            "country_code": "RU",
            "isp": "Selectel LLC",
            "total_reports": 147,
            "is_tor": False,
        },
        "display_name": "PayPal Support",
        "display_name_spoof": True,
        "reply_to_mismatch": True,
        "from_domain": "paypa1-support.ru",
        "anomalies": [
            "Display name impersonates a known brand",
            "Reply-To domain differs from sender domain",
            "SPF FAIL", "DMARC policy failed",
        ],
    },
    "urls": [
        {
            "url": "http://paypa1-login.ru/verify",
            "domain": "paypa1-login.ru",
            "is_lookalike": True,
            "vt_result": {"risk_level": "high", "detections": 34, "total_engines": 87},
        }
    ],
    "attachments": [],
    "phishing": {
        "urgency_language": True,
        "credential_request": True,
        "domain_lookalike": True,
        "display_name_spoof": True,
        "mitre_techniques": ["T1566.001", "T1036.005"],
    },
}

_URL_SCAN_EXAMPLE = {
    "url": "https://suspicious-site.com/login",
    "scanned_at": "2026-05-27T10:00:00Z",
    "scan_result": {
        "risk_level": "high",
        "detections": 22,
        "total_engines": 87,
        "categories": ["phishing", "malware"],
        "permalink": "https://www.virustotal.com/gui/url/...",
    },
}

_IP_CHECK_EXAMPLE = {
    "ip": "185.234.218.47",
    "checked_at": "2026-05-27T10:00:00Z",
    "result": {
        "ip": "185.234.218.47",
        "risk_level": "high",
        "abuse_confidence_score": 92,
        "country_code": "RU",
        "country_name": "Russia",
        "isp": "Selectel LLC",
        "domain": "selectel.ru",
        "total_reports": 147,
        "distinct_users": 38,
        "last_reported": "2026-05-26T22:11:00+00:00",
        "is_tor": False,
        "usage_type": "Data Center/Web Hosting/Transit",
    },
}


@router.post(
    "/email",
    summary="Full email security scan",
    response_description="Complete threat analysis with risk score, authentication results, URL and attachment verdicts",
    responses={
        200: {"description": "Scan completed", "content": {"application/json": {"example": _EMAIL_SCAN_EXAMPLE}}},
        400: {"description": "No scannable input provided"},
    },
)
async def scan_email(request: EmailScanRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """
    Run a full security scan on a raw email.

    Pipeline:
    1. Parse raw email / headers
    2. SPF / DKIM / DMARC authentication analysis
    3. Originating IP → AbuseIPDB reputation
    4. Extract URLs → VirusTotal check
    5. Extract attachments → VirusTotal hash lookup
    6. Phishing heuristics
    7. Risk scoring and forensic log

    Accepts raw .eml, pasted headers+body, or individual fields.
    """
    start = time.time()
    scan_id = str(uuid.uuid4())
    logger.info(f"[{scan_id}] Starting email scan")

    # ── Step 1: Parse ─────────────────────────────────────────────
    parsed = {}
    if request.raw_email:
        parsed = email_parser.parse_raw_email(request.raw_email)
    elif request.headers_raw:
        parsed = email_parser.parse_raw_email(request.headers_raw)

    headers = parsed.get("headers", {})
    phishing = parsed.get("phishing_indicators", {})
    raw_urls = parsed.get("urls", [])
    raw_attachments = parsed.get("attachments", [])

    # Override with explicit fields if provided
    sender_email = request.sender_email or headers.get("from_email", "")
    subject = request.subject or headers.get("subject", "")

    if not sender_email and not request.raw_email and not request.headers_raw:
        raise HTTPException(status_code=400, detail="Provide raw_email, headers_raw, or sender_email")

    # ── Step 2: Authentication ────────────────────────────────────
    auth_raw = headers.get("authentication_results", "")
    auth = email_parser.parse_auth_header(auth_raw)

    # If DKIM-Signature header present but auth header says unknown, mark as present
    if headers.get("dkim_signature") and auth.get("dkim") == "unknown":
        auth["dkim"] = "present_unverified"

    # ── Step 3: IP reputation ─────────────────────────────────────
    originating_ip = (
        headers.get("originating_ip")
        or headers.get("x_originating_ip")
        or None
    )
    ip_result = None
    if originating_ip:
        logger.info(f"[{scan_id}] Checking IP: {originating_ip}")
        ip_result = await abuseipdb.check_ip(originating_ip)

    # ── Step 4: URL scanning ─────────────────────────────────────
    url_results = []
    urls_skipped = 0
    if raw_urls:
        logger.info(f"[{scan_id}] Scanning {len(raw_urls)} URLs via VirusTotal")
        # Scan up to 3 most suspicious URLs (rate limit)
        urls_to_scan = sorted(raw_urls, key=lambda u: u.get("suspicious", False), reverse=True)[:3]
        urls_skipped = max(0, len(raw_urls) - len(urls_to_scan))
        vt_tasks = [virustotal.scan_url(u["url"]) for u in urls_to_scan]
        vt_results = await asyncio.gather(*vt_tasks, return_exceptions=True)
        for u, vt in zip(urls_to_scan, vt_results):
            entry = {**u, "vt_result": vt if not isinstance(vt, Exception) else {"error": str(vt)}}
            url_results.append(entry)

    # ── Step 5: Attachment hash lookup ───────────────────────────
    attachment_results = []
    if raw_attachments:
        logger.info(f"[{scan_id}] Checking {len(raw_attachments)} attachment hashes")
        for att in raw_attachments[:5]:  # Max 5 attachments
            vt_att = await virustotal.scan_file_hash(att["sha256"])
            attachment_results.append({**att, "vt_result": vt_att})

    # ── Heuristics extracts ───────────────────────────────────────
    hop_audit = parsed.get("received_hop_audit")
    weighted_phishing = parsed.get("weighted_phishing_analysis")

    # ── Step 6: Risk scoring ──────────────────────────────────────
    score, risk_level, threat_types = risk_scorer.compute_email_risk_score(
        auth=auth,
        phishing=phishing,
        urls=url_results,
        attachments=attachment_results,
        ip_reputation=ip_result,
        headers=headers,
        hop_audit=hop_audit,
        weighted_phishing=weighted_phishing,
    )
    summary = risk_scorer.summarise(score, risk_level, threat_types)
    duration_ms = round((time.time() - start) * 1000)

    result = {
        "scan_id": scan_id,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_duration_ms": duration_ms,
        "risk_score": score,
        "risk_level": risk_level,
        "threat_types": threat_types,
        "summary": summary,
        "sender_email": sender_email,
        "subject": subject,
        "authentication": auth,
        "header_analysis": {
            "originating_ip": originating_ip,
            "ip_reputation": ip_result,
            "display_name": headers.get("display_name", ""),
            "display_name_spoof": headers.get("display_name_spoof", False),
            "reply_to_mismatch": headers.get("reply_to_mismatch", False),
            "from_domain": headers.get("from_domain", ""),
            "reply_to_domain": headers.get("reply_to_domain", ""),
            "anomalies": _collect_anomalies(headers, auth),
        },
        "urls": url_results,
        "urls_skipped": urls_skipped,
        "attachments": attachment_results,
        "phishing": phishing,
        "received_hop_audit": hop_audit,
        "weighted_phishing_analysis": weighted_phishing,
    }

    # ── Step 7: Auto-save forensic log ───────────────────────────
    if risk_level not in ("clean", "unknown"):
        background_tasks.add_task(save_forensic_log, result)

    logger.info(f"[{scan_id}] Scan complete: {risk_level} ({score}/100) in {duration_ms}ms")
    return result


@router.post("/url", summary="Scan a single URL via VirusTotal",
    response_description="VirusTotal scan result with detection count and risk level",
    responses={200: {"content": {"application/json": {"example": _URL_SCAN_EXAMPLE}}}})
async def scan_url(request: URLScanRequest) -> Dict[str, Any]:
    """Check a URL against VirusTotal's 87+ AV engines."""
    logger.info(f"URL scan: {request.url[:80]}")
    result = await virustotal.scan_url(request.url)
    return {
        "url": request.url,
        "scan_result": result,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@router.post("/ip", summary="Check IP reputation via AbuseIPDB",
    response_description="IP abuse history, geolocation, ISP and risk level",
    responses={200: {"content": {"application/json": {"example": _IP_CHECK_EXAMPLE}}}})
async def check_ip(request: IPCheckRequest) -> Dict[str, Any]:
    """Query AbuseIPDB for an IP address abuse history and geolocation."""
    logger.info(f"IP check: {request.ip}")
    result = await abuseipdb.check_ip(request.ip)
    return {
        "ip": request.ip,
        "result": result,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@router.get("/demo", summary="Run a demo scan with sample phishing email")
async def demo_scan(background_tasks: BackgroundTasks):
    """Runs a scan on a built-in phishing email sample — useful for testing."""
    sample_eml = """From: PayPal Support <noreply@paypa1-support.ru>
Reply-To: help@secure-login.net
To: victim@example.com
Subject: Urgent: Your PayPal account has been suspended
Date: Mon, 26 May 2026 10:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=paypa1-support.ru; s=default
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Received: from mail.evil.ru (mail.evil.ru [185.234.218.47])
  by mx.example.com with ESMTP id abc123;
  Mon, 26 May 2026 10:00:00 +0000
Content-Type: text/plain

Dear Customer,

Your PayPal account has been suspended due to unusual activity.
You must verify your account immediately to avoid permanent closure.

Please click here to verify your credentials:
http://paypa1-login.ru/verify?token=abc123&next=account

Your account will be closed in 24 hours if no action is taken.

PayPal Security Team
"""
    req = EmailScanRequest(raw_email=sample_eml)
    return await scan_email(req, background_tasks)


def _collect_anomalies(headers: dict, auth: dict) -> list:
    anomalies = []
    if headers.get("display_name_spoof"):
        anomalies.append("Display name impersonates a known brand")
    if headers.get("reply_to_mismatch"):
        anomalies.append(f"Reply-To domain differs from sender domain")
    if auth.get("spf") == "fail":
        anomalies.append("SPF authentication failed")
    if auth.get("dkim") in ("fail", "none"):
        anomalies.append("DKIM signature missing or invalid")
    if auth.get("dmarc") == "fail":
        anomalies.append("DMARC policy failed")
    return anomalies
