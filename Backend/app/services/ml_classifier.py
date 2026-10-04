"""
Rule-Based Probabilistic Scoring Engine for SecureMail v4.0.

Provides fast (< 5ms), zero-network-dependency, probabilistic phishing scoring
by vectorizing 30+ engineered lexical, structural, psychological, and authentication
features with linear feature attribution.

A rule-based probabilistic scoring model. Feature weights were manually assigned
based on domain judgment about phishing indicator severity, not learned from a
training dataset. This provides a second, independently-computed risk signal
alongside the primary confidence-weighted risk_scorer.py engine.
"""

import re
import math
import time
from typing import Dict, Any, List, Tuple, Optional
from app.utils.logger import setup_logger
from app.services.homograph_service import PUBLIC_INFRASTRUCTURE_ROOTS, is_official_or_whitelisted

logger = setup_logger(__name__)

# ── Psychological & Intent Keywords ──────────────────────────────────────────
URGENCY_PATTERNS = [
    r"\b(urgent|immediately|action required|within 24 hours|account suspended|restricted|final notice|immediate attention|blocked|unauthorized access|deactivation|terminated|will be closed)\b"
]

CREDENTIAL_PATTERNS = [
    r"\b(password|username|pin|security code|verify your account|confirm your identity|update billing|login credentials|sign in to verify|reset password|validate identity)\b"
]

FINANCIAL_PATTERNS = [
    r"\b(wire transfer|bank account|invoice attached|direct deposit|remittance|cryptocurrency|bitcoin|ethereum|gift card|unpaid bill|payment overdue|tax refund)\b"
]

FEAR_PRESSURE_PATTERNS = [
    r"\b(lawsuit|legal action|arrest warrant|fbi|irs|police|suspended permanently|breach detected|penalties apply|court summons)\b"
]

BENIGN_INDICATORS = [
    r"\b(unsubscribe|manage preferences|privacy policy|view in browser|terms of service|copyright \d{4}|all rights reserved|support ticket #\d+|confidentiality notice|intended solely for the use of|if you received this (?:email|message) in error|placement portal|recruitment drive|batch \d{4})\b"
]

# ── Probabilistic Linear-Sigmoid Feature Weights ─────────────────────────────
# Manually assigned heuristic weights based on domain judgment of phishing indicator severity
FEATURE_WEIGHTS: Dict[str, float] = {
    # Psychological & Intent features
    "urgency_score": 1.45,
    "credential_request_score": 1.75,
    "financial_pressure_score": 1.15,
    "fear_pressure_score": 1.35,
    "benign_disclosure_score": -1.20,
    
    # Lexical & Text features
    "subject_uppercase_ratio": 0.85,
    "body_uppercase_ratio": 0.70,
    "exclamation_density": 0.65,
    "question_density": 0.40,
    "subject_urgency": 1.20,
    "short_body_with_link": 0.95,
    
    # Structural & Link features
    "url_count_high": 0.55,
    "external_url_ratio": 0.80,
    "cloud_cdn_assets_ratio": -0.65,
    "ip_in_url": 1.60,
    "url_shortener_present": 1.10,
    "lookalike_domain_present": 1.95,
    "subdomain_trap_present": 1.50,
    "quishing_qr_present": 1.40,
    "dangerous_attachment_present": 1.85,
    "threat_intel_match_present": 2.50,
    
    # Authentication & Header features
    "spf_fail": 1.30,
    "dkim_fail": 1.15,
    "dmarc_fail": 1.45,
    "auth_all_pass": -1.85,
    "display_name_spoof": 1.40,
    "reply_to_mismatch": 1.25,
    "relay_hop_anomaly": 0.75,
    "high_ip_abuse": 1.20,
}

MODEL_BIAS: float = -1.65  # Baseline prior offset for realistic threat distribution (calibrated heuristic baseline)


# ── Feature Vectorizer ───────────────────────────────────────────────────────

def extract_feature_vector(parsed_email: Dict[str, Any], extra_heuristics: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    """
    Extracts 30+ numerical and normalized signals from parsed email dictionary.
    All features are normalized to [0.0, 1.0] scale.
    """
    features: Dict[str, float] = {}
    extra = extra_heuristics or {}
    
    subject = str(parsed_email.get("subject", "") or "")
    body_text = str(parsed_email.get("body_plain", "") or parsed_email.get("body", "") or "")
    combined_text = (subject + " " + body_text).lower()
    
    headers = parsed_email.get("headers", {}) or {}
    auth = parsed_email.get("authentication", {}) or {}
    urls = parsed_email.get("urls", []) or []
    attachments = parsed_email.get("attachments", []) or []
    quishing = parsed_email.get("quishing", {}) or extra.get("quishing", {}) or {}
    hop_audit = parsed_email.get("received_hop_audit", {}) or extra.get("hop_audit", {}) or {}
    
    # ── 1. Psychological & Intent Signals ──
    urgency_matches = sum(len(re.findall(p, combined_text, re.IGNORECASE)) for p in URGENCY_PATTERNS)
    features["urgency_score"] = min(1.0, urgency_matches * 0.35)
    
    cred_matches = sum(len(re.findall(p, combined_text, re.IGNORECASE)) for p in CREDENTIAL_PATTERNS)
    features["credential_request_score"] = min(1.0, cred_matches * 0.40)
    
    fin_matches = sum(len(re.findall(p, combined_text, re.IGNORECASE)) for p in FINANCIAL_PATTERNS)
    features["financial_pressure_score"] = min(1.0, fin_matches * 0.35)
    
    fear_matches = sum(len(re.findall(p, combined_text, re.IGNORECASE)) for p in FEAR_PRESSURE_PATTERNS)
    features["fear_pressure_score"] = min(1.0, fear_matches * 0.45)
    
    benign_matches = sum(len(re.findall(p, combined_text, re.IGNORECASE)) for p in BENIGN_INDICATORS)
    features["benign_disclosure_score"] = min(1.0, benign_matches * 0.30)
    
    # ── 2. Lexical & Stylistic Signals ──
    subj_alpha = [c for c in subject if c.isalpha()]
    features["subject_uppercase_ratio"] = (sum(1 for c in subj_alpha if c.isupper()) / max(1, len(subj_alpha))) if subj_alpha else 0.0
    
    body_alpha = [c for c in body_text if c.isalpha()]
    features["body_uppercase_ratio"] = (sum(1 for c in body_alpha if c.isupper()) / max(1, len(body_alpha))) if body_alpha else 0.0
    
    features["exclamation_density"] = min(1.0, combined_text.count("!") / 5.0)
    features["question_density"] = min(1.0, combined_text.count("?") / 5.0)
    
    subj_urgency_found = any(re.search(p, subject, re.IGNORECASE) for p in URGENCY_PATTERNS)
    features["subject_urgency"] = 1.0 if subj_urgency_found else 0.0
    
    # Short concise body with direct link (classic credential phishing lure)
    is_short_body = 0 < len(body_text.split()) < 40
    features["short_body_with_link"] = 1.0 if (is_short_body and len(urls) > 0) else 0.0
    
    # ── 3. Structural & Link Attack Vectors ──
    # Normal emails contain 1-5 links (headers, buttons, unsubscribe). Only flag if elevated (> 5).
    features["url_count_high"] = max(0.0, min(1.0, (len(urls) - 5) / 8.0))
    
    # IP in URL
    has_ip_url = any(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u.get("url", "")) for u in urls)
    features["ip_in_url"] = 1.0 if has_ip_url else 0.0
    
    # Shortened URLs
    has_shortener = any(u.get("is_shortened", False) for u in urls)
    features["url_shortener_present"] = 1.0 if has_shortener else 0.0
    
    # Lookalike or IDN Homograph domain
    has_lookalike = any(u.get("is_lookalike", False) or u.get("is_homograph", False) for u in urls)
    features["lookalike_domain_present"] = 1.0 if has_lookalike else 0.0
    
    # Subdomain Trap
    has_subdomain_trap = any(u.get("subdomain_spoof", False) for u in urls)
    features["subdomain_trap_present"] = 1.0 if has_subdomain_trap else 0.0
    
    # Quishing QR code presence
    features["quishing_qr_present"] = 1.0 if quishing.get("has_qr_codes", False) else 0.0
    
    # Dangerous attachment extensions
    has_dang_ext = any(a.get("is_dangerous_ext", False) for a in attachments)
    features["dangerous_attachment_present"] = 1.0 if has_dang_ext else 0.0
    
    # Confirmed Threat Intelligence Feed Matches (URLhaus / OpenPhish / Vault)
    threat_matches = parsed_email.get("threat_intel_matches", []) or extra.get("threat_intel_matches", [])
    features["threat_intel_match_present"] = 1.0 if (threat_matches and len(threat_matches) > 0) else 0.0
    
    # External URL ratio compared to sender domain & Trusted Cloud/CDN Assets
    from app.services.email_parser import _is_same_org_domain
    from_dom = headers.get("from_domain", "").lower()
    if urls and from_dom:
        untrusted_ext_count = 0
        cloud_asset_count = 0
        for u in urls:
            dom = u.get("domain", "").lower()
            is_cloud, _, _ = is_official_or_whitelisted(dom)
            if is_cloud or any(dom == pub or dom.endswith("." + pub) for pub in PUBLIC_INFRASTRUCTURE_ROOTS):
                cloud_asset_count += 1
            elif not _is_same_org_domain(dom, from_dom):
                untrusted_ext_count += 1
        features["external_url_ratio"] = untrusted_ext_count / len(urls)
        features["cloud_cdn_assets_ratio"] = cloud_asset_count / len(urls)
    elif urls:
        cloud_asset_count = sum(
            1 for u in urls
            if is_official_or_whitelisted(u.get("domain", "").lower())[0]
            or any(u.get("domain", "").lower() == pub or u.get("domain", "").lower().endswith("." + pub) for pub in PUBLIC_INFRASTRUCTURE_ROOTS)
        )
        features["external_url_ratio"] = 0.0
        features["cloud_cdn_assets_ratio"] = cloud_asset_count / len(urls)
    else:
        features["external_url_ratio"] = 0.0
        features["cloud_cdn_assets_ratio"] = 0.0
        
    # ── 4. Authentication & Header Signals ──
    spf = str(auth.get("spf", "")).lower()
    dkim = str(auth.get("dkim", "")).lower()
    dmarc = str(auth.get("dmarc", "")).lower()
    
    features["spf_fail"] = 1.0 if spf in ("fail", "softfail") else 0.0
    features["dkim_fail"] = 1.0 if dkim == "fail" else 0.0
    features["dmarc_fail"] = 1.0 if dmarc == "fail" else 0.0
    
    all_pass = (spf == "pass" and dkim == "pass" and dmarc == "pass")
    features["auth_all_pass"] = 1.0 if all_pass else 0.0
    
    features["display_name_spoof"] = 1.0 if headers.get("display_name_spoof", False) else 0.0
    features["reply_to_mismatch"] = 1.0 if headers.get("reply_to_mismatch", False) else 0.0
    
    anomalies = hop_audit.get("anomalies", []) if isinstance(hop_audit, dict) else []
    # Exclude benign informational notes so only actual relay anomalies contribute
    real_anomalies = [a for a in anomalies if "No Received headers" not in a and "direct submission" not in a and "direct client submission" not in a]
    features["relay_hop_anomaly"] = min(1.0, len(real_anomalies) * 0.40)
    
    ip_rep = headers.get("ip_reputation", {}) or {}
    abuse_score = ip_rep.get("abuse_confidence_score", 0) if isinstance(ip_rep, dict) else 0
    features["high_ip_abuse"] = min(1.0, abuse_score / 100.0)
    
    return features


# ── Probabilistic Classifier & Attribution ───────────────────────────────────

def sigmoid(z: float) -> float:
    """Standard sigmoid logistic activation function."""
    if z < -40.0:
        return 0.0
    if z > 40.0:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def predict_phishing_probability(parsed_email: Dict[str, Any], extra_heuristics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Executes local high-speed probabilistic heuristic scoring (< 5ms).
    Computes heuristic phishing probability, categorical confidence,
    and top contributing feature signals (linear feature attribution).
    """
    start_time = time.perf_counter()
    
    # 1. Extract feature vector
    features = extract_feature_vector(parsed_email, extra_heuristics)
    
    # 2. Linear combination of weighted signals
    logit = MODEL_BIAS
    attributions: List[Dict[str, Any]] = []
    
    for feat_name, feat_val in features.items():
        weight = FEATURE_WEIGHTS.get(feat_name, 0.0)
        contribution = feat_val * weight
        logit += contribution
        
        if abs(contribution) > 0.05:
            # Human readable label
            label = _format_feature_label(feat_name, feat_val)
            attributions.append({
                "feature": feat_name,
                "label": label,
                "value": round(feat_val, 2),
                "weight": round(weight, 2),
                "contribution": round(contribution, 3),
                "is_positive": contribution > 0,
            })
            
    # 3. Calibrated probability via sigmoid
    probability = sigmoid(logit)
    
    # 4. Sort attributions by absolute impact
    attributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
    top_signals = attributions[:6]
    
    # 5. Categorical confidence classification
    if probability >= 0.85:
        confidence = "critical"
        verdict = "phishing"
    elif probability >= 0.65:
        confidence = "high"
        verdict = "phishing"
    elif probability >= 0.40:
        confidence = "moderate"
        verdict = "suspicious"
    else:
        confidence = "low"
        verdict = "clean"
        
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    
    return {
        "is_phishing": verdict != "clean",
        "verdict": verdict,
        "probability": round(probability, 4),
        "percentage": round(probability * 100, 1),
        "confidence": confidence,
        "model_version": "v4.0-heuristic-ensemble",
        "inference_duration_ms": duration_ms,
        "feature_count": len(features),
        "top_signals": top_signals,
        "all_signals": attributions,
    }


def _format_feature_label(feat_name: str, val: float) -> str:
    """Converts internal feature keys into human-friendly security descriptions."""
    LABELS = {
        "urgency_score": "High-Pressure Urgency Tactics",
        "credential_request_score": "Credential Solicitation Intent",
        "financial_pressure_score": "Financial / Wire Demand",
        "fear_pressure_score": "Coercive Legal / Account Threat",
        "benign_disclosure_score": "Legitimate Unsubscribe Disclosures",
        "subject_uppercase_ratio": "Excessive Subject Capitalization",
        "body_uppercase_ratio": "Excessive Body Capitalization",
        "exclamation_density": "High Exclamation Mark Intensity",
        "question_density": "Interrogative Lure Intensity",
        "subject_urgency": "Urgent Action Subject Header",
        "short_body_with_link": "Concise Call-to-Action Link Lure",
        "url_count_high": "Elevated Link Density",
        "external_url_ratio": "Cross-Domain Destination Mismatch",
        "cloud_cdn_assets_ratio": "Verified Cloud & CDN Static Assets",
        "ip_in_url": "Raw IP Address URL Destination",
        "url_shortener_present": "Obfuscated URL Shortener Link",
        "lookalike_domain_present": "Lookalike / IDN Homograph Target",
        "subdomain_trap_present": "Subdomain Deception Trap",
        "quishing_qr_present": "Embedded Optical QR Code Payload",
        "dangerous_attachment_present": "Executable / Dangerous File Attachment",
        "threat_intel_match_present": "Active Threat Feed Match (URLhaus/OpenPhish/Vault)",
        "spf_fail": "SPF Sender Authorization Failure",
        "dkim_fail": "DKIM Cryptographic Signature Failure",
        "dmarc_fail": "DMARC Policy Rejection",
        "auth_all_pass": "Full Cryptographic Authentication Pass",
        "display_name_spoof": "Executive / Brand Display Name Spoof",
        "reply_to_mismatch": "Reply-To Redirection Mismatch",
        "relay_hop_anomaly": "MTA Relay Chain Anomaly",
        "high_ip_abuse": "High Abuse Reputation IP Source",
    }
    return LABELS.get(feat_name, feat_name.replace("_", " ").title())
