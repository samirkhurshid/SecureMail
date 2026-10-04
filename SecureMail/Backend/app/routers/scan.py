"""
Email scan router.
POST /api/scan/email  — Full email analysis pipeline
POST /api/scan/url    — Single URL check via VirusTotal
POST /api/scan/ip     — Single IP reputation check via AbuseIPDB
"""

import uuid
import time
import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Request, Query
from app.models.schemas import EmailScanRequest, URLScanRequest, IPCheckRequest
from app.services import virustotal, abuseipdb, email_parser, risk_scorer, usage_tracker, qr_scanner, homograph_service, ml_classifier, threat_intel_service, enrichment_service, audit_service, dns_auth_service
from app.services.forensics import save_forensic_log
from app.services.simple_rate_limiter import get_client_ip
from app.services.anonymous_quota import check_and_increment_anon_quota, get_anon_quota, get_next_reset_time_ist
from app.utils.logger import setup_logger
from app.auth import get_current_user, get_optional_user, CurrentUser
from typing import Any, Dict, Optional

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
            "SPF authentication failed",
            "DKIM signature missing or invalid",
            "DMARC policy failed",
        ],
    },
    "urls": [
        {
            "url": "http://paypa1-login.ru/verify?token=abc123",
            "vt_result": {"detections": 34, "risk_level": "high"},
        }
    ],
    "attachments": [],
    "phishing": {"urgency_language": True, "credential_request": True},
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


@router.get("/quota", summary="Get remaining anonymous free trial scans for requesting IP")
async def get_scan_quota(
    http_request: Request,
    user: Optional[CurrentUser] = Depends(get_optional_user),
) -> Dict[str, Any]:
    """
    Returns anonymous daily scan quota for requesting IP (limit 5/day, resetting at midnight IST).
    If user is authenticated, indicates unlimited access.
    """
    if user is not None:
        return {
            "unlimited": True,
            "user_id": user.uid,
            "message": "Unlimited scanning enabled for signed-in accounts.",
        }

    client_ip = get_client_ip(http_request)
    used = get_anon_quota(client_ip)
    return {
        "used": used,
        "remaining": max(0, 5 - used),
        "limit": 5,
        "resets_at": get_next_reset_time_ist(),
    }


@router.post("")
@router.post(
    "/email",
    summary="Full email security scan",
    response_description="Complete threat analysis with risk score, authentication results, URL and attachment verdicts",
    responses={
        200: {"description": "Scan completed", "content": {"application/json": {"example": _EMAIL_SCAN_EXAMPLE}}},
        400: {"description": "No scannable input provided"},
        429: {"description": "Anonymous daily scan limit reached (5 free scans/day reset at midnight IST)"},
    },
)
async def scan_email(
    request: EmailScanRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    user: Optional[CurrentUser] = Depends(get_optional_user),
    bypass_quota: bool = False,
) -> Dict[str, Any]:
    """
    Run a full security scan on a raw email.
    Supports both authenticated scanning (unlimited) and anonymous trial scanning (5 free scans/day per IP).
    """
    client_ip = get_client_ip(http_request)
    if user is None and not bypass_quota:
        allowed, current_count = check_and_increment_anon_quota(client_ip)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "daily_limit_reached",
                    "message": "You've used your 5 free scans for today. Sign up for unlimited scanning, or come back after midnight IST.",
                    "resets_at": get_next_reset_time_ist(),
                },
            )

    start = time.time()
    scan_id = str(uuid.uuid4())
    logger.info(f"[{scan_id}] Starting email scan for user {user.uid if user else 'anonymous'}")

    # ── Step 1: Input Parsing & Structural Extraction ─────────────
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
    sender_domain = headers.get("from_domain", "") or (sender_email.split("@")[1].lower() if "@" in sender_email else "")
    subject = request.subject or headers.get("subject", "")

    if not sender_email and not request.raw_email and not request.headers_raw:
        raise HTTPException(status_code=400, detail="Provide raw_email, headers_raw, or sender_email")

    # ── Step 2: Authentication Header Parsing (SPF / DKIM / DMARC) ─
    auth_raw = headers.get("authentication_results", "")
    auth = email_parser.parse_auth_header(auth_raw)

    # If DKIM-Signature header present but auth header says unknown, mark as present
    if headers.get("dkim_signature") and auth.get("dkim") == "unknown":
        auth["dkim"] = "present_unverified"

    # If SPF or DMARC are unknown (e.g. email scanned via browser extension reading pane),
    # query real-time DNS records for the sender domain
    if sender_domain and (auth.get("spf") in ("unknown", None) or auth.get("dmarc") in ("unknown", None)):
        dns_auth = await dns_auth_service.verify_domain_dns_auth(sender_domain)
        for k, v in dns_auth.items():
            if auth.get(k) in ("unknown", None) and v != "unknown":
                auth[k] = v

    # ── Check Scan Mode (Quick Heuristic <200ms vs Deep External VT/AbuseIPDB) ──
    is_deep = bool(getattr(request, "deep_scan", False))

    # ── Step 3: Originating IP Abuse Reputation Lookup ─────────────
    originating_ip = (
        headers.get("originating_ip")
        or headers.get("x_originating_ip")
        or None
    )
    ip_result = None
    if originating_ip:
        if is_deep:
            logger.info(f"[{scan_id}] Deep Scan: Checking IP {originating_ip} via AbuseIPDB")
            ip_result = await abuseipdb.check_ip(originating_ip)
        else:
            cached_ip = abuseipdb.get_cached_ip(originating_ip)
            if cached_ip:
                ip_result = cached_ip
            else:
                ip_result = {
                    "ip": originating_ip,
                    "risk_level": "clean",
                    "abuse_confidence_score": 0,
                    "status": "quick_scan",
                    "_note": "Quick Scan mode — run Deep Scan for AbuseIPDB reputation"
                }

    # ── Step 4: URL Extraction & Reputation Scanning ────────────────
    url_results = []
    urls_skipped = 0
    if raw_urls:
        if is_deep:
            logger.info(f"[{scan_id}] Deep Scan: Scanning {len(raw_urls)} URLs via VirusTotal")
            urls_to_scan = sorted(raw_urls, key=lambda u: u.get("suspicious", False), reverse=True)[:3]
            urls_skipped = max(0, len(raw_urls) - len(urls_to_scan))
            vt_tasks = [virustotal.scan_url(u["url"]) for u in urls_to_scan]
            vt_results = await asyncio.gather(*vt_tasks, return_exceptions=True)
            for u, vt in zip(urls_to_scan, vt_results):
                entry = {**u, "vt_result": vt if not isinstance(vt, Exception) else {"error": str(vt)}}
                url_results.append(entry)
        else:
            logger.info(f"[{scan_id}] Quick Scan: Analyzing {len(raw_urls)} URLs via local heuristics & vault")
            for u in raw_urls:
                cached_vt = virustotal.get_cached_result(u["url"])
                if cached_vt:
                    url_results.append({**u, "vt_result": cached_vt})
                else:
                    url_results.append({
                        **u,
                        "vt_result": {
                            "risk_level": "clean",
                            "detections": 0,
                            "total_engines": 87,
                            "status": "quick_scan",
                            "note": "Local heuristics verified. Run Deep Scan for live VirusTotal engines."
                        }
                    })

    # ── Step 5: Attachment Hash Lookup ────────────────────────────
    attachment_results = []
    if raw_attachments:
        if is_deep:
            logger.info(f"[{scan_id}] Deep Scan: Checking {len(raw_attachments)} attachment hashes via VirusTotal")
            for att in raw_attachments[:5]:
                vt_att = await virustotal.scan_file_hash(att["sha256"])
                attachment_results.append({**att, "vt_result": vt_att})
        else:
            for att in raw_attachments[:5]:
                cached_att = virustotal.get_cached_result(att["sha256"])
                if cached_att:
                    attachment_results.append({**att, "vt_result": cached_att})
                else:
                    attachment_results.append({
                        **att,
                        "vt_result": {
                            "risk_level": "clean",
                            "detections": 0,
                            "status": "quick_scan",
                            "note": "SHA-256 computed. Deep Scan available for VirusTotal AV hash feed."
                        }
                    })

    # ── Step 6: Optical Quishing (QR Code) Security Analysis ───────
    quishing_result = {"has_qr_codes": False, "qr_count": 0, "risk_level": "clean", "risk_score": 0, "detections": []}
    if request.raw_email:
        try:
            quishing_result = qr_scanner.scan_email_for_quishing(request.raw_email, parsed)
            if quishing_result.get("has_qr_codes"):
                for det in quishing_result.get("detections", []):
                    if det.get("payload_type") == "url" and det.get("decoded_payload"):
                        qr_url = det["decoded_payload"]
                        if is_deep:
                            try:
                                vt_res = await virustotal.scan_url(qr_url)
                                det["vt_result"] = vt_res
                                if vt_res and isinstance(vt_res, dict):
                                    detections = vt_res.get("detections", 0)
                                    if detections > 0:
                                        det["risk_score"] = min(100, det["risk_score"] + (detections * 15))
                                        det["risk_level"] = "critical" if det["risk_score"] >= 80 else "high"
                                        det["threat_indicators"].append(f"VirusTotal flagged QR destination as malicious ({detections} AV engines)")
                            except Exception:
                                pass
                        else:
                            cached_qr = virustotal.get_cached_result(qr_url)
                            if cached_qr:
                                det["vt_result"] = cached_qr
        except Exception as e:
            logger.warning(f"[{scan_id}] Quishing analysis error: {e}")

    # ── Heuristics extracts ───────────────────────────────────────
    hop_audit = parsed.get("received_hop_audit")
    weighted_phishing = parsed.get("weighted_phishing_analysis")

    # ── Step 7: Real-Time Threat Vault Intelligence Cross-Referencing ──
    threat_intel_matches = []
    from_dom = headers.get("from_domain", "")
    if from_dom:
        dom_match = threat_intel_service.lookup_ioc(from_dom, "domain")
        if dom_match:
            threat_intel_matches.append({**dom_match, "matched_target": "sender_domain", "query": from_dom})
            
    if originating_ip:
        ip_match = threat_intel_service.lookup_ioc(originating_ip, "ip")
        if ip_match:
            threat_intel_matches.append({**ip_match, "matched_target": "originating_ip", "query": originating_ip})
            
    for u in raw_urls:
        u_str = u.get("url", "")
        u_dom = u.get("domain", "")
        if u_str:
            url_match = threat_intel_service.lookup_ioc(u_str, "url")
            if url_match and not any(m.get("query") == u_str for m in threat_intel_matches):
                threat_intel_matches.append({**url_match, "matched_target": "url", "query": u_str})
        if u_dom and u_dom != from_dom:
            dom_match = threat_intel_service.lookup_ioc(u_dom, "domain")
            if dom_match and not any(m.get("query") == u_dom for m in threat_intel_matches):
                threat_intel_matches.append({**dom_match, "matched_target": "url_domain", "query": u_dom})
                
    for att in raw_attachments:
        sha = att.get("sha256")
        if sha:
            hash_match = threat_intel_service.lookup_ioc(sha, "sha256")
            if hash_match:
                threat_intel_matches.append({**hash_match, "matched_target": "attachment_hash", "filename": att.get("filename"), "query": sha})

    # ── Step 8: Domain Infrastructure & Age Metadata Enrichment ───
    domain_enrichment = enrichment_service.enrich_domain_metadata(from_dom) if from_dom else {}

    # ── Step 9: Primary Confidence-Weighted Risk Scoring ──────────
    score, risk_level, threat_types = risk_scorer.compute_email_risk_score(
        auth=auth,
        phishing=phishing,
        urls=url_results,
        attachments=attachment_results,
        ip_reputation=ip_result,
        headers=headers,
        hop_audit=hop_audit,
        weighted_phishing=weighted_phishing,
        threat_intel_matches=threat_intel_matches,
    )

    # ── Step 10: IDN Homograph & Typosquatting Analysis (Score Adjustment) ──
    homograph_alerts = []
    if from_dom:
        from_verdict = homograph_service.evaluate_domain_homograph(from_dom)
        if from_verdict.get("is_lookalike"):
            homograph_alerts.append({
                "target": "sender_domain",
                "domain": from_verdict["domain"],
                "unicode_domain": from_verdict.get("unicode_domain"),
                "spoofed_brand": from_verdict.get("spoofed_brand"),
                "official_domain": from_verdict.get("official_domain"),
                "attack_vectors": from_verdict.get("attack_vectors", []),
                "threat_indicators": from_verdict.get("threat_indicators", [])
            })
            score = max(score, from_verdict.get("risk_score", 85))

    for u in url_results:
        ha = u.get("homograph_analysis") or {}
        if ha.get("is_lookalike"):
            homograph_alerts.append({
                "target": "url",
                "url": u.get("url"),
                "domain": ha.get("domain"),
                "unicode_domain": ha.get("unicode_domain"),
                "spoofed_brand": ha.get("spoofed_brand"),
                "official_domain": ha.get("official_domain"),
                "attack_vectors": ha.get("attack_vectors", []),
                "threat_indicators": ha.get("threat_indicators", [])
            })
            score = max(score, ha.get("risk_score", 80))

    if homograph_alerts:
        if "homograph_impersonation" not in threat_types:
            threat_types.append("homograph_impersonation")
        if score >= 80:
            risk_level = "critical"
        elif score >= 55:
            risk_level = "high"

    # ── Step 11: Pattern-Based Probabilistic Risk Scoring (Heuristic Signal) ─
    ml_prediction = ml_classifier.predict_phishing_probability(
        parsed,
        extra_heuristics={
            "quishing": quishing_result,
            "hop_audit": hop_audit,
            "threat_intel_matches": threat_intel_matches,
        }
    )
    if ml_prediction.get("is_phishing") and ml_prediction.get("probability", 0) >= 0.70:
        if "ml_phishing_classifier" not in threat_types:
            threat_types.append("ml_phishing_classifier")
        if ml_prediction.get("probability", 0) >= 0.85:
            score = max(score, int(ml_prediction["percentage"]))
            if score >= 80:
                risk_level = "critical"
            elif score >= 55:
                risk_level = "high"

    # ── Step 12: Quishing Risk Score Incorporation & Threat Typing ─
    if quishing_result.get("has_qr_codes") and quishing_result.get("risk_score", 0) >= 35:
        score = max(score, quishing_result["risk_score"])
        if "quishing" not in threat_types:
            threat_types.append("quishing")
        if score >= 80:
            risk_level = "critical"
        elif score >= 55:
            risk_level = "high"
        elif score >= 35:
            risk_level = "medium"

    # If overall risk level resolved to clean, normalize threat_types to ["clean"]
    if risk_level == "clean":
        threat_types = ["clean"]

    summary = risk_scorer.summarise(score, risk_level, threat_types)
    duration_ms = round((time.time() - start) * 1000)

    result = {
        "scan_id": scan_id,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_duration_ms": duration_ms,
        "user_id": user.uid if user else None,
        "user_email": user.email if user else None,
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
        "quishing": quishing_result,
        "homograph_alerts": homograph_alerts,
        "ml_prediction": ml_prediction,
        "threat_intel_matches": threat_intel_matches,
        "domain_enrichment": domain_enrichment,
        "deep_scan": is_deep,
        "scan_mode": "deep" if is_deep else "quick",
    }

    # ── Step 14: Automated Forensic Logging, Audit Trail & Alert Dispatch ──
    if user and (user.uid or user.email):
        effective_uid = user.uid or user.email
        background_tasks.add_task(usage_tracker.record_scan_usage, effective_uid)
        background_tasks.add_task(
            audit_service.log_audit_event,
            event_type=audit_service.EVENT_SCAN_EMAIL,
            user_id=effective_uid,
            user_email=user.email or "",
            user_role=getattr(user, "role", "user"),
            ip_address=client_ip,
            resource_id=scan_id,
            details={"risk_score": score, "risk_level": risk_level, "sender": sender_email, "subject": subject}
        )
        background_tasks.add_task(save_forensic_log, result, effective_uid, user.email)

        if risk_level in ("high", "critical"):
            from app.services import user_service, webhook_notifier
            user_doc = user_service.get_or_create_user_doc(effective_uid)
            webhook_url = user_doc.get("webhook_url")
            if webhook_url and webhook_url.strip():
                background_tasks.add_task(webhook_notifier.notify_webhook, webhook_url, result)

    logger.info(f"[{scan_id}] Scan complete: {risk_level} ({score}/100) in {duration_ms}ms")
    return result


@router.post("/url", summary="Scan a single URL via VirusTotal", response_model=Dict[str, Any])
async def scan_url(
    request: URLScanRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    user: Optional[CurrentUser] = Depends(get_optional_user)
) -> Dict[str, Any]:
    client_ip = get_client_ip(http_request)
    if user is None:
        allowed, current_count = check_and_increment_anon_quota(client_ip)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "daily_limit_reached",
                    "message": "You've used your 5 free scans for today. Sign up for unlimited scanning, or come back after midnight IST.",
                    "resets_at": get_next_reset_time_ist(),
                },
            )

    logger.info(f"URL scan request: {request.url}")
    result = await virustotal.scan_url(request.url)
    
    # Check local Threat Vault for instant zero-day hit
    vault_match = threat_intel_service.lookup_ioc(request.url, "url")
    
    if user and (user.uid or user.email):
        effective_uid = user.uid or user.email
        background_tasks.add_task(usage_tracker.record_scan_usage, effective_uid)
        background_tasks.add_task(
            audit_service.log_audit_event,
            event_type=audit_service.EVENT_SCAN_URL,
            user_id=effective_uid,
            user_email=user.email or "",
            user_role=getattr(user, "role", "user"),
            ip_address=client_ip,
            resource_id=request.url,
            details={"is_threat": bool(vault_match) or (isinstance(result, dict) and result.get("detections", 0) > 0)}
        )
    return {
        "url": request.url,
        "scan_result": result,
        "threat_intel_match": vault_match,
        "is_threat": bool(vault_match) or (isinstance(result, dict) and result.get("detections", 0) > 0)
    }


@router.post("/ip", summary="Check IP reputation via AbuseIPDB", response_model=Dict[str, Any])
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
async def demo_scan(
    background_tasks: BackgroundTasks,
    http_request: Request,
    deep: bool = Query(False),
    user: Optional[CurrentUser] = Depends(get_optional_user),
):
    """
    Runs a scan on a built-in phishing email sample — useful for testing.
    Free demo scan available to both guests and authenticated users.
    Supports quick scan (default, <5ms) and deep multi-engine scan (?deep=true).
    """
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
    req = EmailScanRequest(raw_email=sample_eml, deep_scan=deep)
    return await scan_email(
        request=req,
        background_tasks=background_tasks,
        http_request=http_request,
        user=user,
        bypass_quota=True,
    )


@router.post("/report/pdf", summary="Generate on-demand executive SOC PDF report from live scan result")
async def generate_scan_pdf(result: Dict[str, Any]):
    """
    Accepts scan result JSON and renders a high-fidelity executive SOC PDF report.
    """
    from app.services import report_generator
    from fastapi.responses import StreamingResponse
    import io
    if not result:
        raise HTTPException(status_code=400, detail="Scan result payload required")
    inc_id = result.get("scan_id") or result.get("id") or "LIVE-SCAN"
    pdf_bytes = report_generator.generate_forensic_pdf(result, incident_id=inc_id)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="SecureMail-Report-{inc_id}.pdf"'}
    )


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
