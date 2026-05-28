"""
Email parsing service.
Parses raw .eml content, extracts headers, URLs, attachments, and metadata.
"""

import email
import email.policy
import re
import hashlib
from email.header import decode_header
from typing import List, Tuple, Optional, Dict
from urllib.parse import urlparse
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

# Legitimate global brands dictionary
LEGITIMATE_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "microsoft": "microsoft.com",
    "outlook": "outlook.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "yahoo": "yahoo.com",
    "chase": "chase.com",
    "citibank": "citibank.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "zoom": "zoom.us",
    "adobe": "adobe.com",
    "salesforce": "salesforce.com",
    "ebay": "ebay.com",
    "walmart": "walmart.com",
    "stripe": "stripe.com",
    "fedex": "fedex.com",
    "dhl": "dhl.com",
    "ups": "ups.com",
}

# Weighted Phishing Keywords
PHISHING_WEIGHTS = {
    # High Severity (Credentials & Banking)
    "password": 10, "username": 8, "login": 8, "sign in": 8, "credentials": 10,
    "social security": 10, "credit card": 10, "bank account": 10, "ssn": 10,
    "pin number": 10, "verify your account": 8, "confirm your": 6, "validate": 6,
    "security question": 8,
    
    # Medium Severity (Urgency & Threat)
    "urgent": 6, "immediately": 6, "account suspended": 9, "verify now": 8,
    "click here": 5, "limited time": 4, "action required": 6, "blocked": 7,
    "unusual activity": 7, "expires": 5, "24 hours": 5, "48 hours": 5,
    "unauthorized": 6, "suspended": 7, "restricted": 7,
    
    # Low/Medium Severity (Offers & Fraud Scams)
    "free": 3, "winner": 4, "prize": 4, "lottery": 8, "claim": 4,
    "inheritance": 8, "wire transfer": 8, "advance fee": 8, "investment": 4,
    "billion": 3, "million": 3, "transfer funds": 6,
}

# Common URL shorteners to flag
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "is.gd", "buff.ly", "rebrand.ly", "tiny.cc", "cutt.ly", "rb.gy",
}

# Phishing keyword patterns (compiled for performance)
URGENCY_PATTERNS = re.compile(
    r"\b(urgent|immediately|account.suspended|verify.now|click.here|limited.time|"
    r"action.required|your.account|suspended|blocked|unusual.activity|"
    r"confirm.your|update.your|validate|expires|24.hours|48.hours)\b",
    re.IGNORECASE,
)

CREDENTIAL_PATTERNS = re.compile(
    r"\b(password|username|login|sign.in|credentials|social.security|"
    r"credit.card|bank.account|ssn|date.of.birth|pin.number)\b",
    re.IGNORECASE,
)

SUSPICIOUS_SUBJECT_PATTERNS = re.compile(
    r"\b(free|winner|prize|lottery|claim|inheritance|nigerian|transfer|"
    r"billion|million|investment|wire.transfer|advance.fee)\b",
    re.IGNORECASE,
)

# Regex for extracting URLs from text/html
URL_REGEX = re.compile(
    r'https?://[^\s\'"<>\]\[)(\{\}]+',
    re.IGNORECASE,
)

# Common lookalike domain patterns
BRAND_LOOKALIKE = re.compile(
    r"(paypa1|paypai|payp4l|g00gle|g0ogle|amaz0n|amazonn|micros0ft|"
    r"app1e|appl3|faceb00k|faceb0ok|netfl1x|netf1ix|ins1agram|"
    r"tw1tter|linked1n|dropb0x|g-mail|gmai1)",
    re.IGNORECASE,
)

# Extensions that are dangerous regardless of AV verdict
DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "com", "scr", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "msi", "ps1", "psm1", "psd1", "jar", "py",
    "hta", "reg", "lnk", "iso", "img", "dmg", "apk",
    # Office macros
    "xlsm", "xlsb", "xls", "docm", "doc", "pptm",
}


def parse_raw_email(raw: str) -> dict:
    """
    Parse a raw email string (RFC 2822 / .eml format).
    Returns structured dict with headers, body, urls, attachments, forensics, and weights.
    """
    try:
        msg = email.message_from_string(raw, policy=email.policy.default)
    except Exception as e:
        logger.error(f"Email parse error: {e}")
        return {"error": str(e), "headers": {}, "urls": [], "attachments": []}

    headers = _extract_headers(msg)
    body_text, body_html = _extract_body(msg)
    urls = _extract_urls(body_text + " " + body_html)
    attachments = _extract_attachment_metadata(msg)
    phishing = _analyse_phishing(headers, body_text, body_html, urls)

    # Advanced Heuristics integrations
    received_headers = msg.get_all("Received") or []
    hop_audit = audit_received_hops(received_headers)
    
    # Scan the full email content for weighted phishing indicators
    keyword_score, keyword_matches = scan_weighted_keywords(body_text + " " + body_html + " " + headers.get("subject", ""))

    return {
        "headers": headers,
        "body_text": body_text[:2000],  # Truncate for storage
        "body_html_length": len(body_html),
        "urls": urls,
        "attachments": attachments,
        "phishing_indicators": phishing,
        "received_hop_audit": hop_audit,
        "weighted_phishing_analysis": {
            "score": keyword_score,
            "matches": keyword_matches
        }
    }


def _extract_headers(msg) -> dict:
    """Extract and decode key email headers."""
    def decode(value: Optional[str]) -> str:
        if not value:
            return ""
        parts = decode_header(value)
        result = []
        for part, encoding in parts:
            if isinstance(part, bytes):
                result.append(part.decode(encoding or "utf-8", errors="replace"))
            else:
                result.append(part)
        return " ".join(result)

    from_raw = decode(msg.get("From", ""))
    reply_to = decode(msg.get("Reply-To", ""))
    return_path = decode(msg.get("Return-Path", ""))

    from_email = _extract_email_address(from_raw)
    from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
    reply_domain = _extract_email_address(reply_to).split("@")[-1].lower() if "@" in reply_to else ""

    # Detect display name spoofing
    display_name = _extract_display_name(from_raw)
    display_name_spoof = _detect_display_name_spoof(display_name, from_domain)

    # Extract received chain and originating IP
    received_headers = msg.get_all("Received") or []
    originating_ip = _extract_originating_ip(received_headers)

    return {
        "from_raw": from_raw,
        "from_email": from_email,
        "from_domain": from_domain,
        "display_name": display_name,
        "display_name_spoof": display_name_spoof,
        "reply_to": reply_to,
        "reply_to_domain": reply_domain,
        "reply_to_mismatch": bool(reply_domain and reply_domain != from_domain),
        "return_path": return_path,
        "subject": decode(msg.get("Subject", "")),
        "date": decode(msg.get("Date", "")),
        "message_id": decode(msg.get("Message-ID", "")),
        "received": received_headers,
        "originating_ip": originating_ip,
        "x_mailer": decode(msg.get("X-Mailer", "")),
        "x_originating_ip": decode(msg.get("X-Originating-IP", "")),
        # Auth headers (set by receiving mail server)
        "authentication_results": decode(msg.get("Authentication-Results", "")),
        "arc_authentication_results": decode(msg.get("ARC-Authentication-Results", "")),
        "dkim_signature": bool(msg.get("DKIM-Signature")),
    }


def _extract_body(msg) -> Tuple[str, str]:
    """Walk MIME parts and collect text/plain + text/html bodies."""
    text_parts, html_parts = [], []
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in disposition:
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                    if ctype == "text/plain":
                        text_parts.append(decoded)
                    elif ctype == "text/html":
                        html_parts.append(decoded)
                except Exception:
                    pass
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    html_parts.append(text)
                else:
                    text_parts.append(text)
    except Exception as e:
        logger.warning(f"Body extraction warning: {e}")

    return " ".join(text_parts), " ".join(html_parts)


def _extract_urls(content: str) -> List[Dict]:
    """Extract all URLs from content and classify them."""
    found = URL_REGEX.findall(content)
    seen, results = set(), []

    for url in found:
        url = url.rstrip(".,;:!?\"')")
        if url in seen or len(url) > 2048:
            continue
        seen.add(url)

        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        is_shortened = domain in URL_SHORTENERS
        is_lookalike, spoofed_brand = _check_domain_lookalike(domain)

        results.append({
            "url": url,
            "domain": domain,
            "scheme": parsed.scheme,
            "is_shortened": is_shortened,
            "is_lookalike": is_lookalike,
            "spoofed_brand": spoofed_brand,
            "suspicious": is_shortened or is_lookalike,
        })

    return results[:50]  # Cap at 50 URLs


def _extract_attachment_metadata(msg) -> List[Dict]:
    """Extract attachment names and compute hashes without storing file data."""
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" not in disposition:
            continue
        try:
            filename = part.get_filename() or "unknown"
            payload = part.get_payload(decode=True) or b""
            md5 = hashlib.md5(payload).hexdigest()
            sha256 = hashlib.sha256(payload).hexdigest()
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            attachments.append({
                "filename": filename,
                "extension": ext,
                "size_bytes": len(payload),
                "md5": md5,
                "sha256": sha256,
                "content_type": part.get_content_type(),
                "is_dangerous_ext": ext in DANGEROUS_EXTENSIONS,
            })
        except Exception as e:
            logger.warning(f"Attachment extraction warning: {e}")

    return attachments





def _analyse_phishing(headers: dict, body_text: str, body_html: str, urls: List) -> dict:
    """Heuristic phishing indicator analysis."""
    content = body_text + " " + body_html
    indicators = []
    techniques = []

    urgency = bool(URGENCY_PATTERNS.search(content))
    if urgency:
        indicators.append("urgency language detected")

    credential_request = bool(CREDENTIAL_PATTERNS.search(content))
    if credential_request:
        indicators.append("credential/sensitive data request")
        techniques.append("T1566.002 (Spearphishing Link)")

    domain_lookalike = any(u["is_lookalike"] for u in urls)
    if domain_lookalike:
        indicators.append("brand lookalike domain in links")
        techniques.append("T1566.001 (Spearphishing Attachment)")

    display_name_spoof = headers.get("display_name_spoof", False)
    if display_name_spoof:
        indicators.append("display name spoofing detected")
        techniques.append("T1036.005 (Match Legitimate Name)")

    reply_mismatch = headers.get("reply_to_mismatch", False)
    if reply_mismatch:
        indicators.append("reply-to domain differs from sender")

    subject_suspicious = bool(SUSPICIOUS_SUBJECT_PATTERNS.search(headers.get("subject", "")))
    if subject_suspicious:
        indicators.append("suspicious subject keywords")

    shortened_urls = any(u["is_shortened"] for u in urls)
    if shortened_urls:
        indicators.append("URL shortener used to hide destination")

    return {
        "urgency_language": urgency,
        "credential_request": credential_request,
        "domain_lookalike": domain_lookalike,
        "display_name_spoof": display_name_spoof,
        "reply_to_mismatch": reply_mismatch,
        "subject_suspicious": subject_suspicious,
        "shortened_urls": shortened_urls,
        "suspicious_patterns": indicators,
        "mitre_techniques": list(set(techniques)),
    }


def parse_auth_header(auth_results: str) -> dict:
    """Parse Authentication-Results header into SPF/DKIM/DMARC results."""
    result = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"}
    if not auth_results:
        return result

    mappings = {
        "spf": re.compile(r"spf=(\w+)", re.IGNORECASE),
        "dkim": re.compile(r"dkim=(\w+)", re.IGNORECASE),
        "dmarc": re.compile(r"dmarc=(\w+)", re.IGNORECASE),
        "arc": re.compile(r"arc=(\w+)", re.IGNORECASE),
    }
    for key, pattern in mappings.items():
        match = pattern.search(auth_results)
        if match:
            result[key] = match.group(1).lower()

    return result


def _extract_email_address(raw: str) -> str:
    """Extract plain email address from 'Display Name <email>' format."""
    match = re.search(r"<([^>]+)>", raw)
    if match:
        return match.group(1).strip().lower()
    return raw.strip().lower()


def _extract_display_name(raw: str) -> str:
    """Extract display name from 'Display Name <email>' format."""
    match = re.match(r'^"?([^"<]+)"?\s*<', raw)
    if match:
        return match.group(1).strip()
    return ""


def _detect_display_name_spoof(display_name: str, from_domain: str) -> bool:
    """Detect if display name impersonates a brand while domain doesn't match."""
    if not display_name:
        return False
    brands = [
        ("paypal", "paypal.com"), ("apple", "apple.com"), ("google", "google.com"),
        ("microsoft", "microsoft.com"), ("amazon", "amazon.com"), ("netflix", "netflix.com"),
        ("facebook", "facebook.com"), ("instagram", "instagram.com"), ("twitter", "twitter.com"),
        ("linkedin", "linkedin.com"), ("dropbox", "dropbox.com"), ("bank", None),
    ]
    dn_lower = display_name.lower()
    for brand_name, official_domain in brands:
        if brand_name in dn_lower:
            if official_domain and official_domain not in from_domain:
                return True
            if official_domain is None:
                return True
    return False


def _extract_originating_ip(received_headers: list) -> Optional[str]:
    """Extract the originating external IP from Received headers (last = origin)."""
    ip_pattern = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")
    import ipaddress

    for header in reversed(received_headers):
        matches = ip_pattern.findall(str(header))
        for ip in matches:
            try:
                addr = ipaddress.ip_address(ip)
                if not (addr.is_private or addr.is_loopback):
                    return ip
            except ValueError:
                continue
    return None


# ── Advanced Heuristics Implementations ──────────────────────────────────────

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]


def _check_domain_lookalike(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a domain is an impersonation of a legitimate brand.
    Returns (is_lookalike, spoofed_brand).
    """
    domain = domain.lower()
    if domain in LEGITIMATE_BRANDS.values():
        return False, None
        
    import re
    parts = re.split(r"[\.\-]", domain)
    for part in parts:
        if part in ("www", "mail", "com", "org", "net", "edu", "gov", "co", "io", "ru", "xyz", "info", "biz", "uk", "us"):
            continue
            
        # 1. Substring Impersonation check
        for brand, official in LEGITIMATE_BRANDS.items():
            if brand in part:
                if official not in domain:
                    return True, brand

        # 2. Levenshtein edit distance check
        for brand, official in LEGITIMATE_BRANDS.items():
            if abs(len(part) - len(brand)) <= 2:
                dist = levenshtein_distance(part, brand)
                if 0 < dist <= 2:
                    return True, brand
                    
    return False, None


def audit_received_hops(received_headers: list) -> dict:
    """
    Audits the Received relay chain in the email headers.
    Returns audit statistics and a list of identified anomalies.
    """
    import re
    import ipaddress

    anomalies = []
    parsed_hops = []
    
    ip_pattern = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")
    from_by_pattern = re.compile(r"from\s+(\S+)\s+by\s+(\S+)", re.IGNORECASE)

    for i, header in enumerate(received_headers):
        header_str = str(header)
        ips = ip_pattern.findall(header_str)
        from_by = from_by_pattern.search(header_str)
        
        declared_from = from_by.group(1) if from_by else "unknown"
        received_by = from_by.group(2) if from_by else "unknown"
        
        hop_ip = None
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
                hop_ip = ip
                break
            except ValueError:
                continue
                
        parsed_hops.append({
            "hop": len(received_headers) - i,
            "raw": header_str[:200],
            "from": declared_from,
            "by": received_by,
            "ip": hop_ip
        })

    if len(received_headers) > 5:
        anomalies.append(f"Unusually long relay chain ({len(received_headers)} hops)")
    if len(received_headers) == 0:
        anomalies.append("No Received headers found (likely direct client submission)")

    return {
        "hop_count": len(received_headers),
        "hops": parsed_hops,
        "anomalies": anomalies
    }


def scan_weighted_keywords(content: str) -> Tuple[int, List[Dict]]:
    """
    Scans content for weighted phishing keywords.
    Returns (total_threat_score, list_of_matches).
    """
    total_score = 0
    matches = []
    content_lower = content.lower()
    
    for word, weight in PHISHING_WEIGHTS.items():
        count = content_lower.count(word)
        if count > 0:
            word_score = count * weight
            total_score += word_score
            matches.append({
                "keyword": word,
                "count": count,
                "weight": weight,
                "score": word_score
            })
            
    # Normalize score based on a standard benchmark total
    normalized_score = min(100, int((total_score / 40) * 100))
    return normalized_score, sorted(matches, key=lambda m: m["score"], reverse=True)
