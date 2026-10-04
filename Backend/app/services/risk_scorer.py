"""
Risk scoring engine — v2 (confidence-weighted).

v1 problem: every signal scored as if it were a CONFIRMED threat, including
weak/ambiguous ones (missing optional headers, single soft keyword). This
made nearly every pasted email — including completely legitimate ones —
cross into "suspicious" territory.

v2 fix: signals are split into three confidence tiers.
  - STRONG  : near-zero false positive rate on their own (malware hash hit,
              Bitcoin wallet + payment demand together, brand domain spoof
              with character substitution). These alone can push to HIGH/CRITICAL.
  - MODERATE: meaningful but not conclusive alone (single auth failure,
              one suspicious keyword, reply-to mismatch). Needs 2-3 to stack
              before mattering.
  - WEAK    : near-zero signal alone (single urgency word, missing OPTIONAL
              auth header on a body-only paste). These are evidence
              multipliers, not point sources — they only count when STRONG
              or MODERATE signals already fired.

Critically: "headers_present" tells us whether this scan had real .eml/raw
header data at all. If NOT, we skip ALL auth-header penalties entirely,
because "unknown" in that context means "user pasted plain text", not
"sender is spoofing". This was the single biggest source of false positives.
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
    threat_intel_matches: list | None = None,
) -> tuple[int, str, list]:
    """
    Compute a 0–100 risk score using confidence-weighted, evidence-stacking logic.
    Returns (score, risk_level, threat_types).
    """
    strong_score = 0
    moderate_score = 0
    weak_signal_count = 0
    threat_types = set()

    # Did this scan actually have raw email headers (.eml / pasted headers),
    # or just a plain-text body? This gates ALL auth-related scoring.
    headers_present = _has_real_headers(headers)

    # ════════════════════════════════════════════════════════════
    # STRONG signals — near-zero false-positive rate alone
    # ════════════════════════════════════════════════════════════

    # Confirmed malware via VirusTotal hash/URL match — this is ground truth,
    # not a heuristic. Always strong regardless of anything else.
    max_url_detections = max((u.get("vt_result", {}).get("detections", 0) for u in urls), default=0)
    max_att_detections = max((a.get("vt_result", {}).get("detections", 0) for a in attachments), default=0)

    # Ground-truth ceiling: a confirmed multi-engine malware detection or a
    # heavily-flagged malicious URL is not a heuristic guess — it's a real
    # antivirus engine consensus.
    ground_truth_floor = 0

    # ── Threat Vault / Threat Intelligence Feed Hits ──
    threat_vault_floor = 0
    for hit in (threat_intel_matches or []):
        t_type = hit.get("threat_type", "threat_intel_match")
        conf = hit.get("confidence", 80)
        strong_score += int(conf * 0.80)
        
        if t_type in ("malware", "malware_download"):
            threat_types.add("malware")
            threat_types.add("threat_intel_malware")
            threat_vault_floor = max(threat_vault_floor, 85)
        elif t_type in ("phishing", "phishing_credential_theft"):
            threat_types.add("phishing")
            threat_types.add("threat_intel_phishing")
            threat_vault_floor = max(threat_vault_floor, 85)
        elif t_type == "c2":
            threat_types.add("c2_infrastructure")
            threat_vault_floor = max(threat_vault_floor, 80)
        else:
            threat_types.add("threat_intel_match")
            threat_vault_floor = max(threat_vault_floor, 75)

    if max_att_detections >= 15:
        strong_score += 60
        ground_truth_floor = max(ground_truth_floor, 85)  # multi-engine consensus = critical
        threat_types.add("malicious_attachment")
    elif max_att_detections >= 5:
        strong_score += 50
        ground_truth_floor = max(ground_truth_floor, 75)  # confirmed malware = at least high
        threat_types.add("malicious_attachment")
    elif max_att_detections >= 1:
        strong_score += 30
        ground_truth_floor = max(ground_truth_floor, 55)
        threat_types.add("malicious_attachment")

    if max_url_detections >= 15:
        strong_score += 50
        ground_truth_floor = max(ground_truth_floor, 80)
        threat_types.add("suspicious_url")
    elif max_url_detections >= 10:
        strong_score += 40
        ground_truth_floor = max(ground_truth_floor, 70)
        threat_types.add("suspicious_url")
    elif max_url_detections >= settings.VT_MALICIOUS_THRESHOLD:
        strong_score += 25
        ground_truth_floor = max(ground_truth_floor, 50)
        threat_types.add("suspicious_url")

    # Confirmed brand impersonation: sender domain uses a character-substituted
    # or typosquatted version of a real brand domain. Very low false-positive —
    # legitimate companies don't send mail from typosquats of themselves.
    if phishing.get("domain_impersonation"):
        strong_score += 30
        threat_types.add("spoofing")

    # Bitcoin wallet address actually present in body + a payment demand —
    # this combination essentially never appears in legitimate mail.
    if phishing.get("bitcoin_wallet_found") and phishing.get("bitcoin_demand"):
        strong_score += 35
        threat_types.add("extortion")

    # Explicit extortion/blackmail language (webcam threats, "I have video of you")
    # combined with a payment or silence demand — very specific, low FP rate.
    if phishing.get("extortion") and (phishing.get("webcam_threat") or phishing.get("do_not_contact_instruction")):
        strong_score += 30
        threat_types.add("extortion")
        threat_types.add("social_engineering")

    # All THREE auth checks explicitly FAIL (not unknown — actually failed).
    # This only happens when we have real headers AND the mail server itself
    # flagged it. Extremely strong signal.
    if headers_present and all(auth.get(k) == "fail" for k in ("spf", "dkim", "dmarc")):
        strong_score += 35
        threat_types.add("spoofing")

    # ════════════════════════════════════════════════════════════
    # MODERATE signals — meaningful but need to stack to matter
    # ════════════════════════════════════════════════════════════

    moderate_hits = []

    # Single auth failures (not full triple-fail) — only counted when we
    # actually have headers to check. A real SPF/DKIM/DMARC fail is moderate
    # evidence on its own, two stacking together becomes much stronger.
    if headers_present:
        if auth.get("spf") == "fail":
            moderate_hits.append(("spf_fail", 14))
        if auth.get("dkim") == "fail":
            moderate_hits.append(("dkim_fail", 12))
        if auth.get("dmarc") == "fail":
            moderate_hits.append(("dmarc_fail", 10))

    if phishing.get("credential_request"):
        moderate_hits.append(("credential_request", 14))

    if phishing.get("domain_lookalike"):
        moderate_hits.append(("domain_lookalike", 16))

    if phishing.get("display_name_spoof"):
        moderate_hits.append(("display_name_spoof", 12))

    if phishing.get("subject_suspicious"):
        moderate_hits.append(("subject_suspicious", 10))

    if ip_reputation:
        ip_risk = ip_reputation.get("risk_level", "unknown")
        confidence = ip_reputation.get("abuse_confidence_score", 0)
        if ip_risk == "high" or confidence >= 80:
            moderate_hits.append(("ip_high_abuse", 18))
        elif ip_risk == "medium" or confidence >= 25:
            moderate_hits.append(("ip_medium_abuse", 10))
        if ip_reputation.get("is_tor"):
            moderate_hits.append(("ip_is_tor", 8))

    if phishing.get("bitcoin_demand") and not phishing.get("bitcoin_wallet_found"):
        # Mentions bitcoin/crypto but no actual wallet address — moderate, not strong
        moderate_hits.append(("bitcoin_mention", 10))

    if phishing.get("extortion") and not (phishing.get("webcam_threat") or phishing.get("do_not_contact_instruction")):
        moderate_hits.append(("extortion_language", 12))

    # Apply moderate hits with DIMINISHING RETURNS — the 1st hit counts in
    # full, the 2nd at 85%, the 3rd at 70%, etc. This rewards genuine
    # multi-signal correlation without letting 5 weak hits = 1 strong hit.
    moderate_hits.sort(key=lambda x: x[1], reverse=True)
    for i, (name, weight) in enumerate(moderate_hits):
        decay = max(0.4, 1.0 - (i * 0.15))
        moderate_score += weight * decay
        if name in ("domain_lookalike", "credential_request"):
            threat_types.add("phishing")
        if name.endswith("_fail"):
            threat_types.add("header_anomaly")

    # ════════════════════════════════════════════════════════════
    # WEAK signals — multipliers only, never scored alone
    # ════════════════════════════════════════════════════════════
    # These only count if at least one MODERATE or STRONG signal already
    # fired. A clean email with just "urgent" in the subject gets 0 extra
    # points. A suspicious email with "urgent" ON TOP of other evidence
    # gets a small boost — because urgency language is a real attacker
    # pattern, just not diagnostic on its own.

    has_real_evidence = (strong_score > 0) or (len(moderate_hits) > 0)

    if has_real_evidence:
        if phishing.get("urgency_language"):
            weak_signal_count += 1
        if phishing.get("reply_to_mismatch"):
            weak_signal_count += 1
        if phishing.get("shortened_urls"):
            weak_signal_count += 1
        if headers_present and auth.get("spf") == "unknown":
            weak_signal_count += 1
        if headers_present and auth.get("dkim") == "unknown":
            weak_signal_count += 1
        if hop_audit and hop_audit.get("anomalies"):
            weak_signal_count += 1

    weak_bonus = min(15, weak_signal_count * 4)

    # Weighted keyword score — scaled down significantly and gated behind
    # already having SOME real evidence, since keyword matching alone
    # (e.g. "account", "verify", "security") fires on tons of legitimate mail.
    kw_score = phishing.get("keyword_score", 0)
    weighted_kw = (weighted_phishing or {}).get("score", 0)
    total_kw = kw_score + weighted_kw
    if has_real_evidence and total_kw > 0:
        weak_bonus += min(10, int(total_kw * 0.08))
    elif total_kw >= 40:
        # Keyword pile-up alone (no other signal) only matters if it's
        # genuinely large — e.g. an email saturated with extortion vocabulary
        weak_bonus += min(8, int((total_kw - 40) * 0.05))

    # ════════════════════════════════════════════════════════════
    # Final aggregation
    # ════════════════════════════════════════════════════════════
    score = strong_score + moderate_score + weak_bonus
    
    # ════════════════════════════════════════════════════════════
    # Trust factors & mitigations (Authentic Sender Discount)
    # ════════════════════════════════════════════════════════════
    auth_all_pass = headers_present and auth.get("spf") == "pass" and auth.get("dkim") == "pass" and auth.get("dmarc") == "pass"
    clean_ip = ip_reputation and ip_reputation.get("abuse_confidence_score", 0) == 0 and not ip_reputation.get("is_tor")
    
    # If the email passed all 3 cryptographic and DNS authentication standards
    # without confirmed malware, threat intel hits, or extortion, apply an authentic sender trust dampener.
    if auth_all_pass and ground_truth_floor == 0 and threat_vault_floor == 0 and not phishing.get("domain_impersonation") and not phishing.get("extortion"):
        trust_discount = 20
        if clean_ip:
            trust_discount += 5
        score = max(0, score - trust_discount)
        
    score = max(0, min(100, round(score)))
    # Apply ground-truth & threat-vault floor: confirmed VT and Threat Vault detections can't be diluted
    score = max(score, ground_truth_floor, threat_vault_floor)

    risk_level = _score_to_level(score)
    if risk_level == "clean":
        threat_types = {"clean"}
    elif not threat_types:
        threat_types.add("unknown")

    return score, risk_level, list(threat_types)


def _has_real_headers(headers: dict) -> bool:
    """
    True only if this scan actually had raw email headers to inspect —
    i.e. a real .eml file or pasted header block — not just a plain-text
    body/subject paste. This is the gate that prevents "missing optional
    header" from being treated the same as "sender failed authentication".
    """
    if not headers:
        return False
    signal_fields = (
        "authentication_results", "received", "dkim_signature",
        "message_id", "return_path",
    )
    return any(headers.get(f) for f in signal_fields)


def _score_to_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= settings.RISK_SCORE_HIGH:
        return "high"
    if score >= settings.RISK_SCORE_MEDIUM:
        return "medium"
    if score > 15:
        return "low"
    return "clean"


def summarise(score: int, risk_level: str, threat_types: list) -> str:
    """Generate a human-readable summary string."""
    if risk_level == "clean":
        return "No significant threats detected. Email appears legitimate."

    parts = []
    if "extortion" in threat_types:
        parts.append("extortion / sextortion scam")
    if "social_engineering" in threat_types and "extortion" not in threat_types:
        parts.append("social engineering")
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

    if risk_level == "low":
        return f"LOW RISK (score {score}/100) — some {threat_str} signals present, but not conclusive. Review before acting."

    return f"{level_str} RISK (score {score}/100) — {threat_str} detected."
