"""
Test battery: legitimate emails (should score LOW/CLEAN) and
malicious emails (should score HIGH/CRITICAL). Used to validate
the risk scorer doesn't false-positive on real-world clean mail.
"""

# ════════════════════════════════════════════════════════════════
# LEGITIMATE emails — pasted as plain body text, no raw headers
# (the most common real-world usage pattern)
# ════════════════════════════════════════════════════════════════

LEGIT_CASES = [
    {
        "name": "Bank 2FA code",
        "headers": {"subject": "Your verification code", "from_domain": "chase.com", "from_email": "alerts@chase.com"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": False, "credential_request": False, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": False, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 5,
        },
        "urls": [], "attachments": [], "ip_reputation": None,
    },
    {
        "name": "Account verification email (real SaaS onboarding)",
        "headers": {"subject": "Please verify your account", "from_domain": "notion.so", "from_email": "team@notion.so"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": False, "credential_request": True, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": False, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 9,
        },
        "urls": [{"url": "https://notion.so/verify", "is_shortened": False, "is_lookalike": False, "vt_result": {}}],
        "attachments": [], "ip_reputation": None,
    },
    {
        "name": "Shipping notification with urgency word",
        "headers": {"subject": "Your package will arrive today", "from_domain": "ups.com", "from_email": "noreply@ups.com"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": True, "credential_request": False, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": False, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 3,
        },
        "urls": [], "attachments": [], "ip_reputation": None,
    },
    {
        "name": "Newsletter with bit.ly link",
        "headers": {"subject": "This week's top stories", "from_domain": "substack.com", "from_email": "writer@substack.com"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": False, "credential_request": False, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": True, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 0,
        },
        "urls": [{"url": "https://bit.ly/abc123", "is_shortened": True, "is_lookalike": False, "vt_result": {}}],
        "attachments": [], "ip_reputation": None,
    },
    {
        "name": "Full .eml with clean SPF/DKIM/DMARC pass",
        "headers": {
            "subject": "Meeting notes from today", "from_domain": "company.com", "from_email": "colleague@company.com",
            "authentication_results": "spf=pass dkim=pass dmarc=pass", "received": ["from mail.company.com"],
            "dkim_signature": True, "message_id": "<abc@company.com>", "return_path": "colleague@company.com",
        },
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass", "arc": "unknown"},
        "phishing": {
            "urgency_language": False, "credential_request": False, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": False, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 0,
        },
        "urls": [], "attachments": [], "ip_reputation": None,
    },
    {
        "name": "Password reset request (legit, has 'verify your identity')",
        "headers": {"subject": "Reset your password", "from_domain": "github.com", "from_email": "noreply@github.com"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": False, "credential_request": True, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": False, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 9,
        },
        "urls": [], "attachments": [], "ip_reputation": None,
    },
    {
        "name": "Invoice from known accounting software",
        "headers": {"subject": "Your invoice #4471 is ready", "from_domain": "quickbooks.com", "from_email": "billing@quickbooks.com"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": False, "credential_request": False, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": False, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 0,
        },
        "urls": [], "attachments": [{"filename": "invoice.pdf", "is_dangerous_ext": False, "vt_result": {}}],
        "ip_reputation": None,
    },
]

# ════════════════════════════════════════════════════════════════
# MALICIOUS emails — should score HIGH or CRITICAL
# ════════════════════════════════════════════════════════════════

MALICIOUS_CASES = [
    {
        "name": "Sextortion / Bitcoin extortion scam",
        "headers": {
            "subject": "I Know What You Did Last Week", "from_domain": "protonmail-secure.net",
            "from_email": "security-alert@protonmail-secure.net",
        },
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": True, "credential_request": False, "domain_lookalike": True,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": True,
            "shortened_urls": False, "extortion": True, "bitcoin_demand": True,
            "bitcoin_wallet_found": True, "webcam_threat": True, "do_not_contact_instruction": True,
            "domain_impersonation": True, "keyword_score": 64,
        },
        "urls": [], "attachments": [], "ip_reputation": None,
    },
    {
        "name": "PayPal phishing with subdomain spoof",
        "headers": {
            "subject": "Urgent: Your Account Will Be Suspended Within 24 Hours",
            "from_domain": "paypai-security-alert.com", "from_email": "support@paypaI-security-alert.com",
            "authentication_results": "spf=fail dkim=fail dmarc=fail", "received": ["from mail.evil.ru"],
        },
        "auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail", "arc": "unknown"},
        "phishing": {
            "urgency_language": True, "credential_request": True, "domain_lookalike": True,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": True,
            "shortened_urls": False, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": True, "keyword_score": 64,
        },
        "urls": [{"url": "http://paypal-verification-center-login.security-check-user.com",
                   "is_shortened": False, "is_lookalike": False, "subdomain_spoof": True, "vt_result": {}}],
        "attachments": [], "ip_reputation": None,
    },
    {
        "name": "Malware attachment confirmed by VirusTotal",
        "headers": {"subject": "Invoice attached", "from_domain": "acme-invoices.ru", "from_email": "billing@acme-invoices.ru"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": False, "credential_request": False, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": False, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 0,
        },
        "urls": [],
        "attachments": [{"filename": "invoice.pdf", "is_dangerous_ext": False, "vt_result": {"detections": 34}}],
        "ip_reputation": None,
    },
    {
        "name": "Malicious link confirmed by VirusTotal + Tor exit node",
        "headers": {"subject": "Check this out", "from_domain": "deals-hub.io", "from_email": "newsletter@deals-hub.io"},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "arc": "unknown"},
        "phishing": {
            "urgency_language": False, "credential_request": False, "domain_lookalike": False,
            "display_name_spoof": False, "reply_to_mismatch": False, "subject_suspicious": False,
            "shortened_urls": True, "extortion": False, "bitcoin_demand": False,
            "bitcoin_wallet_found": False, "webcam_threat": False, "do_not_contact_instruction": False,
            "domain_impersonation": False, "keyword_score": 0,
        },
        "urls": [{"url": "http://bit.ly/3xV2p", "is_shortened": True, "is_lookalike": False, "vt_result": {"detections": 11}}],
        "attachments": [],
        "ip_reputation": {"risk_level": "high", "abuse_confidence_score": 92, "is_tor": True},
    },
]
