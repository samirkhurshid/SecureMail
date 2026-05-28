"""
Risk scoring engine.
Aggregates signals from all scan services into a 0–100 risk score.
"""

from app.config import get_settings

settings = get_settings()


def compute_email_risk_score(
    auth: dict,
    phishing: dict,
    urls: list,
    attachments: list,
    ip_reputation: dict | None,
    headers: dict,
    hop_audit: dict | None = None,
    weighted_phishing: dict | None = None,
) -> tuple[int, str, list]:
    """
    Compute a 0–100 risk score and determine risk level + threat types.
    Returns (score, risk_level, threat_types).
    """
    score = 0
    threat_types = set()

    # ── Authentication failures (max 30 pts) ─────────────────────
    if auth.get("spf") == "fail":
        score += 12
    elif auth.get("spf") in ("softfail", "neutral"):
        score += 5
    if auth.get("dkim") == "fail":
        score += 10
    elif auth.get("dkim") == "none":
        score += 5
    if auth.get("dmarc") == "fail":
        score += 8

    if all(auth.get(k) == "fail" for k in ("spf", "dkim", "dmarc")):
        score += 10  # Bonus for triple failure
        threat_types.add("spoofing")

    # ── IP reputation (max 20 pts) ────────────────────────────────
    if ip_reputation:
        ip_risk = ip_reputation.get("risk_level", "unknown")
        confidence = ip_reputation.get("abuse_confidence_score", 0)
        if ip_risk == "high" or confidence >= 80:
            score += 20
        elif ip_risk == "medium" or confidence >= 25:
            score += 12
        elif ip_risk == "low" or confidence > 0:
            score += 5
        if ip_reputation.get("is_tor"):
            score += 8

    # ── Phishing indicators (max 25 pts) ─────────────────────────
    phishing_score = 0
    if phishing.get("urgency_language"):
        phishing_score += 5
    if phishing.get("credential_request"):
        phishing_score += 10
    if phishing.get("domain_lookalike"):
        phishing_score += 12
    if phishing.get("display_name_spoof"):
        phishing_score += 8
    if phishing.get("reply_to_mismatch"):
        phishing_score += 5
    if phishing.get("subject_suspicious"):
        phishing_score += 3
    phishing_score = min(phishing_score, 30)
    score += phishing_score
    if phishing_score >= 10:
        threat_types.add("phishing")

    # ── Malicious URLs (max 20 pts) ───────────────────────────────
    for url in urls:
        vt = url.get("vt_result", {})
        detections = vt.get("detections", 0)
        if detections >= 10:
            score += 20
            threat_types.add("suspicious_url")
            break
        elif detections >= settings.VT_MALICIOUS_THRESHOLD:
            score += 12
            threat_types.add("suspicious_url")
        elif url.get("is_shortened"):
            score += 3

    # ── Malicious attachments (max 25 pts) ───────────────────────
    for att in attachments:
        vt = att.get("vt_result", {})
        detections = vt.get("detections", 0)
        is_dangerous_ext = att.get("is_dangerous_ext", False)
        if detections >= 5:
            score += 25
            threat_types.add("malicious_attachment")
            break
        elif detections >= 1:
            score += 15
            threat_types.add("malicious_attachment")
        elif is_dangerous_ext:
            score += 8
            threat_types.add("malicious_attachment")

    # ── Header anomalies (max 5 pts) ─────────────────────────────
    if headers.get("reply_to_mismatch"):
        score += 3
        threat_types.add("header_anomaly")

    # ── Received hop anomalies (max 10 pts) ──────────────────────
    if hop_audit:
        anomalies = hop_audit.get("anomalies", [])
        if anomalies:
            score += min(10, len(anomalies) * 5)
            threat_types.add("header_anomaly")

    # ── Weighted phishing keyword score (max 25 pts) ─────────────
    if weighted_phishing:
        wp_score = weighted_phishing.get("score", 0)
        score += min(25, int(wp_score * 0.25))
        if wp_score >= 15:
            threat_types.add("phishing")

    # ── Cap and classify ─────────────────────────────────────────
    score = min(score, 100)
    if score == 0 and not threat_types:
        threat_types.add("clean")

    risk_level = _score_to_level(score)
    return score, risk_level, list(threat_types)


def _score_to_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= settings.RISK_SCORE_HIGH:
        return "high"
    if score >= settings.RISK_SCORE_MEDIUM:
        return "medium"
    if score > 10:
        return "low"
    return "clean"


def summarise(score: int, risk_level: str, threat_types: list) -> str:
    """Generate a human-readable summary string."""
    if risk_level == "clean":
        return "No threats detected. Email appears legitimate."

    parts = []
    if "phishing" in threat_types:
        parts.append("phishing attempt")
    if "malicious_attachment" in threat_types:
        parts.append("malicious attachment")
    if "suspicious_url" in threat_types:
        parts.append("malicious links")
    if "spoofing" in threat_types:
        parts.append("sender spoofing")
    if "header_anomaly" in threat_types:
        parts.append("header anomalies")

    threat_str = ", ".join(parts) if parts else "suspicious activity"
    level_str = risk_level.upper()
    return f"{level_str} RISK (score {score}/100) — {threat_str} detected."
