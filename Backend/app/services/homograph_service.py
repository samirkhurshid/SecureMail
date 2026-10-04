"""
SecureMail v4.0 — Advanced IDN Homograph & Typosquatting Defense Engine.
Detects Punycode obfuscation, Cyrillic/Greek/Latin homoglyphs, Damerau-Levenshtein transpositions,
combosquatting, subdomain deception traps, and unauthorized brand impersonations across 100+ global brands.
Includes cloud infrastructure whitelist and strict non-ASCII Unicode vs ASCII digit separation.
"""

import re
import unicodedata
from typing import Dict, List, Optional, Tuple, Any

# ── 100+ Curated Global Brand Knowledge Base ─────────────────────────────────
# Maps brand identifier -> primary official domain(s) and aliases
ENTERPRISE_BRANDS: Dict[str, Dict[str, Any]] = {
    # ── Tech Giants & Cloud ──
    "google": {
        "official": [
            "google.com", "google.co.uk", "google.ca", "google.de", "google.fr", "google.com.au",
            "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com",
            "gmail.com", "youtube.com", "youtu.be", "android.com", "googleblog.com"
        ],
        "category": "tech"
    },
    "gmail": {"official": ["gmail.com", "google.com"], "category": "tech"},
    "youtube": {"official": ["youtube.com", "youtu.be", "googlevideo.com"], "category": "tech"},
    "microsoft": {
        "official": [
            "microsoft.com", "msn.com", "live.com", "azure.com", "azureedge.net",
            "windows.net", "microsoftonline.com", "sharepoint.com", "office.com",
            "office365.com", "outlook.com", "hotmail.com", "azurewebsites.net",
            "azure-api.net", "e-mails.microsoft.com"
        ],
        "category": "tech"
    },
    "outlook": {"official": ["outlook.com", "hotmail.com", "live.com", "microsoft.com"], "category": "tech"},
    "office365": {"official": ["office.com", "office365.com", "microsoftonline.com", "microsoft.com"], "category": "tech"},
    "apple": {
        "official": [
            "apple.com", "icloud.com", "mzstatic.com", "apple-dns.net", "aaplimg.com",
            "apple-support.com", "apple.co"
        ],
        "category": "tech"
    },
    "icloud": {"official": ["icloud.com", "apple.com"], "category": "tech"},
    "amazon": {
        "official": [
            "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca", "amazon.in",
            "amazon.co.jp", "amazonaws.com", "cloudfront.net", "amzn.to", "aws.amazon.com",
            "media-amazon.com", "ssl-images-amazon.com"
        ],
        "category": "ecommerce"
    },
    "aws": {
        "official": ["aws.amazon.com", "amazonaws.com", "cloudfront.net", "amazon.com"],
        "category": "cloud"
    },
    "meta": {"official": ["meta.com", "facebook.com", "fb.com", "instagram.com", "whatsapp.com"], "category": "social"},
    "facebook": {"official": ["facebook.com", "fb.com", "fbcdn.net", "meta.com"], "category": "social"},
    "instagram": {"official": ["instagram.com", "cdninstagram.com", "meta.com"], "category": "social"},
    "whatsapp": {"official": ["whatsapp.com", "whatsapp.net", "meta.com"], "category": "social"},
    "netflix": {"official": ["netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net"], "category": "media"},
    "spotify": {"official": ["spotify.com", "scdn.co", "spotifycdn.com"], "category": "media"},
    "twitter": {"official": ["twitter.com", "x.com", "twimg.com", "t.co"], "category": "social"},
    "linkedin": {"official": ["linkedin.com", "licdn.com"], "category": "social"},
    "github": {"official": ["github.com", "github.io", "githubusercontent.com", "githubassets.com"], "category": "developer"},
    "gitlab": {"official": ["gitlab.com", "gitlab.io"], "category": "developer"},
    "openai": {"official": ["openai.com", "chatgpt.com", "oaistatic.com"], "category": "ai"},
    "chatgpt": {"official": ["chatgpt.com", "openai.com", "oaistatic.com"], "category": "ai"},
    "adobe": {"official": ["adobe.com", "typekit.net", "adobeexchange.com", "behance.net"], "category": "software"},
    "dropbox": {"official": ["dropbox.com", "dropboxstatic.com", "dropboxusercontent.com"], "category": "cloud"},
    "zoom": {"official": ["zoom.us", "zoom.com", "zoomgov.com"], "category": "collaboration"},
    "slack": {"official": ["slack.com", "slack-edge.com", "slack-msgs.com"], "category": "collaboration"},
    "salesforce": {"official": ["salesforce.com", "force.com", "salesforceiq.com"], "category": "enterprise"},
    "docusign": {"official": ["docusign.com", "docusign.net"], "category": "enterprise"},
    "intuit": {"official": ["intuit.com", "turbotax.com", "quickbooks.com"], "category": "finance"},
    "quickbooks": {"official": ["quickbooks.intuit.com", "quickbooks.com", "intuit.com"], "category": "finance"},
    "workday": {"official": ["workday.com", "myworkday.com"], "category": "enterprise"},
    "servicenow": {"official": ["servicenow.com", "service-now.com"], "category": "enterprise"},
    "okta": {"official": ["okta.com", "okta-emea.com", "oktapreview.com"], "category": "security"},
    "cloudflare": {"official": ["cloudflare.com", "cdnjs.cloudflare.com", "cloudflareinsights.com", "workers.dev"], "category": "security"},
    "cisco": {"official": ["cisco.com", "webex.com", "umbrella.com"], "category": "networking"},
    "atlassian": {"official": ["atlassian.com", "jira.com", "trello.com", "bitbucket.org", "atlassian.net"], "category": "developer"},
    "yahoo": {"official": ["yahoo.com", "yahoo.co.jp", "yimg.com"], "category": "tech"},

    # ── Global Banking & Wealth Management ──
    "chase": {"official": ["chase.com", "jpmorganchase.com"], "category": "banking"},
    "jpmorgan": {"official": ["jpmorgan.com", "jpmorganchase.com"], "category": "banking"},
    "bankofamerica": {"official": ["bankofamerica.com", "bofa.com"], "category": "banking"},
    "bofa": {"official": ["bofa.com", "bankofamerica.com"], "category": "banking"},
    "wellsfargo": {"official": ["wellsfargo.com"], "category": "banking"},
    "citibank": {"official": ["citibank.com", "citi.com", "citigroup.com"], "category": "banking"},
    "citi": {"official": ["citi.com", "citigroup.com", "citibank.com"], "category": "banking"},
    "capitalone": {"official": ["capitalone.com"], "category": "banking"},
    "hsbc": {"official": ["hsbc.com", "hsbc.co.uk", "hsbc.com.hk"], "category": "banking"},
    "barclays": {"official": ["barclays.com", "barclays.co.uk"], "category": "banking"},
    "santander": {"official": ["santander.com", "santander.co.uk", "santanderbank.com"], "category": "banking"},
    "bnpparibas": {"official": ["bnpparibas.com", "group.bnpparibas"], "category": "banking"},
    "ubs": {"official": ["ubs.com"], "category": "banking"},
    "credit-suisse": {"official": ["credit-suisse.com", "ubs.com"], "category": "banking"},
    "charlesschwab": {"official": ["schwab.com", "charlesschwab.com"], "category": "finance"},
    "schwab": {"official": ["schwab.com", "charlesschwab.com"], "category": "finance"},
    "fidelity": {"official": ["fidelity.com", "fidelityinternational.com"], "category": "finance"},
    "tdbank": {"official": ["td.com", "tdbank.com"], "category": "banking"},
    "pnc": {"official": ["pnc.com"], "category": "banking"},
    "usbank": {"official": ["usbank.com"], "category": "banking"},
    "truist": {"official": ["truist.com"], "category": "banking"},
    "americanexpress": {"official": ["americanexpress.com", "amex.com", "aexp-static.com"], "category": "finance"},
    "amex": {"official": ["amex.com", "americanexpress.com", "aexp-static.com"], "category": "finance"},
    "discover": {"official": ["discover.com", "discovercard.com"], "category": "finance"},

    # ── Payments, Fintech & Crypto ──
    "paypal": {"official": ["paypal.com", "paypal.me", "paypalobjects.com"], "category": "fintech"},
    "stripe": {"official": ["stripe.com", "stripe.network", "stripe.me"], "category": "fintech"},
    "square": {"official": ["squareup.com", "square.online", "block.xyz", "cash.app"], "category": "fintech"},
    "venmo": {"official": ["venmo.com", "paypal.com"], "category": "fintech"},
    "wise": {"official": ["wise.com", "transferwise.com"], "category": "fintech"},
    "revolut": {"official": ["revolut.com", "revolut.me"], "category": "fintech"},
    "zelle": {"official": ["zellepay.com"], "category": "fintech"},
    "klarna": {"official": ["klarna.com", "klarna.net"], "category": "fintech"},
    "affirm": {"official": ["affirm.com"], "category": "fintech"},
    "coinbase": {"official": ["coinbase.com", "pro.coinbase.com", "cb.run"], "category": "crypto"},
    "binance": {"official": ["binance.com", "binance.us", "binance.vision", "binance.org"], "category": "crypto"},
    "kraken": {"official": ["kraken.com"], "category": "crypto"},
    "metamask": {"official": ["metamask.io", "metamask.zendesk.com"], "category": "crypto"},
    "ledger": {"official": ["ledger.com"], "category": "crypto"},
    "trezor": {"official": ["trezor.io"], "category": "crypto"},
    "trustwallet": {"official": ["trustwallet.com"], "category": "crypto"},
    "opensea": {"official": ["opensea.io"], "category": "crypto"},
    "gemini": {"official": ["gemini.com"], "category": "crypto"},
    "robinhood": {"official": ["robinhood.com"], "category": "fintech"},

    # ── Logistics & Shipping ──
    "dhl": {"official": ["dhl.com", "dhl.de", "express.dhl", "dhl-news.com"], "category": "logistics"},
    "fedex": {"official": ["fedex.com", "fedex.co.uk"], "category": "logistics"},
    "ups": {"official": ["ups.com", "tools.ups.com"], "category": "logistics"},
    "usps": {"official": ["usps.com", "tools.usps.com", "uspspostalpki.com"], "category": "logistics"},
    "royalmail": {"official": ["royalmail.com"], "category": "logistics"},
    "canadapost": {"official": ["canadapost-postescanada.ca", "canadapost.ca"], "category": "logistics"},
    "auspost": {"official": ["auspost.com.au"], "category": "logistics"},
    "dpd": {"official": ["dpd.com", "dpd.co.uk", "dpd.de"], "category": "logistics"},
    "hermes": {"official": ["myhermes.co.uk", "hermesworld.com", "evri.com"], "category": "logistics"},
    "evri": {"official": ["evri.com"], "category": "logistics"},

    # ── E-Commerce & Retail ──
    "ebay": {"official": ["ebay.com", "ebay.co.uk", "ebay.de", "ebaystatic.com", "ebayimg.com"], "category": "ecommerce"},
    "walmart": {"official": ["walmart.com", "walmartimages.com"], "category": "retail"},
    "target": {"official": ["target.com", "targetimg1.com"], "category": "retail"},
    "bestbuy": {"official": ["bestbuy.com"], "category": "retail"},
    "shopify": {"official": ["shopify.com", "myshopify.com", "shopifycdn.com"], "category": "ecommerce"},
    "alibaba": {"official": ["alibaba.com", "alibabagroup.com", "alicdn.com"], "category": "ecommerce"},
    "aliexpress": {"official": ["aliexpress.com", "alicdn.com"], "category": "ecommerce"},
    "costco": {"official": ["costco.com"], "category": "retail"},
    "homedepot": {"official": ["homedepot.com"], "category": "retail"},

    # ── Telecom & ISP ──
    "att": {"official": ["att.com", "att.net"], "category": "telecom"},
    "verizon": {"official": ["verizon.com", "verizonwireless.com"], "category": "telecom"},
    "tmobile": {"official": ["t-mobile.com", "tmobile.com"], "category": "telecom"},
    "comcast": {"official": ["comcast.com", "xfinity.com"], "category": "telecom"},
    "xfinity": {"official": ["xfinity.com", "comcast.com"], "category": "telecom"},
    "vodafone": {"official": ["vodafone.com", "vodafone.co.uk"], "category": "telecom"},
}

# ── Public Multi-Tenant Cloud / CDN Infrastructure Roots ────────────────────
# Arbitrary tenant subdomains on these roots are standard and must not be marked as lookalikes
PUBLIC_INFRASTRUCTURE_ROOTS = {
    "amazonaws.com", "cloudfront.net", "s3.amazonaws.com",
    "googleapis.com", "gstatic.com", "googleusercontent.com",
    "azureedge.net", "windows.net", "azurewebsites.net", "blob.core.windows.net",
    "azure-api.net", "sharepoint.com", "office.com", "microsoftonline.com",
    "cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com",
    "fastly.net", "akamaized.net", "salesforce.com", "force.com",
    "github.io", "gitlab.io", "herokuapp.com", "typekit.net"
}

# ── Strictly Non-ASCII Confusable Homoglyph Mapping ─────────────────────────
# Maps visual lookalikes (Cyrillic, Greek, Latin extended diacritics where ord > 127) -> base Latin
UNICODE_HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic small lookalikes
    "а": "a", "б": "b", "в": "b", "г": "r", "д": "d", "е": "e", "ж": "zh",
    "з": "3", "и": "u", "й": "u", "к": "k", "л": "n", "м": "m", "н": "h",
    "о": "o", "п": "n", "р": "p", "с": "c", "т": "t", "у": "y", "ф": "o",
    "х": "x", "ц": "u", "ч": "y", "ш": "w", "щ": "w", "ъ": "b", "ы": "bl",
    "ь": "b", "э": "e", "ю": "io", "я": "r",
    # Cyrillic Ukrainian/Belarusian lookalikes
    "і": "i", "ї": "i", "є": "e", "ґ": "r", "ѕ": "s", "ј": "j",
    # Cyrillic Capital lookalikes
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o",
    "Р": "p", "С": "c", "Т": "t", "У": "y", "Х": "x", "І": "i", "Ј": "j",
    # Greek lookalikes
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ζ": "z", "η": "n",
    "θ": "o", "ι": "i", "κ": "k", "λ": "l", "μ": "u", "ν": "v", "ξ": "e",
    "ο": "o", "π": "n", "ρ": "p", "σ": "o", "τ": "t", "υ": "u", "φ": "o",
    "χ": "x", "ψ": "y", "ω": "w", "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z",
    "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p",
    "Τ": "t", "Υ": "y", "Χ": "x",
    # Latin extended with diacritics / symbols
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a", "ā": "a", "ă": "a", "ą": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e", "ē": "e", "ĕ": "e", "ę": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i", "ī": "i", "ĭ": "i", "į": "i", "ı": "i", "ӏ": "l",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o", "ø": "o", "ō": "o", "ŏ": "o", "ő": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u", "ū": "u", "ŭ": "u", "ů": "u", "ű": "u",
    "ý": "y", "ÿ": "y", "ŷ": "y",
    "ç": "c", "ć": "c", "č": "c", "ĉ": "c", "ċ": "c",
    "ñ": "n", "ń": "n", "ň": "n", "ņ": "n",
    "š": "s", "ś": "s", "ŝ": "s", "ş": "s", "ș": "s",
    "ž": "z", "ź": "z", "ż": "z",
    "ł": "l", "ĺ": "l", "ľ": "l", "ŀ": "l",
    "đ": "d", "ď": "d",
    "ř": "r", "ŕ": "r", "ŗ": "r",
    "ť": "t", "ţ": "t", "ț": "t",
}

# ── ASCII Leetspeak Substitutions (Evaluated strictly on unofficial root domain labels) ──
LEETSPEAK_NUMBER_MAP: Dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a"
}

# Suspicious combosquatting keywords
SECURITY_AFFIXES = {
    "login", "signin", "sign-in", "log-in", "verify", "verification", "auth", "authentication",
    "security", "secure", "update", "support", "help", "account", "portal", "service", "billing",
    "payment", "wallet", "recovery", "recover", "manage", "alert", "notification", "confirm",
    "confirmation", "mfa", "2fa", "sso", "session", "renew", "unlock", "protect", "webscr"
}

# High abuse TLDs frequently paired with brand impersonation
HIGH_ABUSE_TLDS = {
    "xyz", "top", "ru", "cn", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "live", "support", "link", "bid", "loan", "men", "date", "stream", "trade",
    "racing", "download", "party", "review", "country", "science", "gdn"
}

# Common benign domain prefixes/suffixes to ignore in distance checks
BENIGN_PARTS = {"www", "mail", "com", "org", "net", "edu", "gov", "co", "io", "info", "biz", "uk", "us", "de", "ca", "app", "dev"}


# ── Algorithmic Distance Utilities ───────────────────────────────────────────

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculates the Damerau-Levenshtein distance between s1 and s2.
    Supports insertions, deletions, substitutions, and adjacent transpositions (e.g. microsfot -> microsoft).
    """
    len1, len2 = len(s1), len(s2)
    d: Dict[Tuple[int, int], int] = {}

    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,       # deletion
                d[(i, j - 1)] + 1,       # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + cost)  # transposition

    return d[(len1 - 1, len2 - 1)]


def normalize_homoglyphs(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """
    Normalizes strictly non-ASCII confusable Unicode homoglyphs (ord > 127) to base Latin.
    Returns (normalized_text, list_of_replaced_characters).
    Standard ASCII digits (0-9) are NEVER treated as Unicode homoglyphs.
    """
    # Remove zero-width spaces
    cleaned = re.sub(r"[\u200B\u200C\u200D\uFEFF]", "", text)
    
    replaced = []
    result = []
    
    for char in cleaned:
        if ord(char) > 127 and char in UNICODE_HOMOGLYPH_MAP:
            mapped = UNICODE_HOMOGLYPH_MAP[char]
            try:
                char_name = unicodedata.name(char)
            except ValueError:
                char_name = "UNICODE LOOKALIKE"
            replaced.append({
                "char": char,
                "unicode_name": char_name,
                "mapped_to": mapped
            })
            result.append(mapped)
        else:
            result.append(char)
            
    return "".join(result), replaced


def normalize_leetspeak(text: str) -> str:
    """Replaces ASCII numbers (0, 1, 3, etc.) with equivalent Latin characters for typosquatting checks."""
    return "".join(LEETSPEAK_NUMBER_MAP.get(c, c) for c in text)


def decode_punycode_domain(domain: str) -> Tuple[str, str, bool]:
    """
    Converts domain from/to Punycode (e.g. xn--pyp-73da.com -> pаypаl.com).
    Returns (ascii_domain, unicode_domain, is_punycode).
    """
    domain = domain.strip().lower()
    is_punycode = "xn--" in domain
    
    try:
        if is_punycode:
            unicode_domain = domain.encode("ascii").decode("idna")
            ascii_domain = domain
        else:
            ascii_domain = domain.encode("idna").decode("ascii")
            unicode_domain = domain
            if "xn--" in ascii_domain:
                is_punycode = True
    except Exception:
        unicode_domain = domain
        ascii_domain = domain

    return ascii_domain, unicode_domain, is_punycode


def is_official_or_whitelisted(domain: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Checks if domain is an official domain or legitimate cloud subdomain of an enterprise brand.
    Returns (is_official, brand_name, category).
    """
    d = domain.strip().lower().rstrip(".")
    
    # 1. Check direct official match or subdomain match for known enterprise brands
    for brand_key, brand_info in ENTERPRISE_BRANDS.items():
        for off in brand_info["official"]:
            if d == off or d.endswith("." + off):
                return True, brand_key, brand_info["category"]
                
    # 2. Check public infrastructure whitelist
    for pub in PUBLIC_INFRASTRUCTURE_ROOTS:
        if d == pub or d.endswith("." + pub):
            return True, "cloud_infrastructure", "infrastructure"
            
    return False, None, None


# ── Core Domain Evaluation Engine ───────────────────────────────────────────

def evaluate_domain_homograph(raw_domain: str) -> Dict[str, Any]:
    """
    Performs comprehensive multi-vector analysis on a domain name.
    
    Vectors evaluated:
    1. Official domain & public cloud infrastructure verification (Zero False Positive Gate)
    2. IDN Homograph / Punycode non-ASCII script injection
    3. Damerau-Levenshtein transposition typosquatting
    4. Subdomain brand trap deception on unrelated roots
    5. Combosquatting security affix attachment
    6. High-abuse TLD brand mismatches
    
    Returns structured analysis verdict.
    """
    domain = raw_domain.strip().lower().rstrip(".")
    if not domain:
        return {"is_lookalike": False, "risk_level": "clean", "threat_indicators": []}

    # Extract Punycode and Unicode representations
    ascii_domain, unicode_domain, is_punycode = decode_punycode_domain(domain)
    
    # ── Vector 0: Official Brand & Cloud Infrastructure Whitelist Gate ──
    is_off, off_brand, off_category = is_official_or_whitelisted(domain)
    if is_off:
        return {
            "domain": domain,
            "ascii_domain": ascii_domain,
            "unicode_domain": unicode_domain,
            "is_lookalike": False,
            "is_official": True,
            "is_homograph": False,
            "brand": off_brand,
            "brand_category": off_category,
            "risk_level": "clean",
            "risk_score": 0,
            "threat_indicators": []
        }

    # Normalize strictly non-ASCII confusable characters
    normalized_unicode, replaced_chars = normalize_homoglyphs(unicode_domain)
    
    threat_indicators: List[str] = []
    attack_vectors: List[str] = []
    spoofed_brand: Optional[str] = None
    official_domain: Optional[str] = None
    risk_score = 0

    # ── Vector 1: Punycode & True Unicode IDN Homograph Injection ──
    has_unicode_homoglyphs = len(replaced_chars) > 0
    if is_punycode or has_unicode_homoglyphs:
        sorted_brands = sorted(ENTERPRISE_BRANDS.items(), key=lambda x: len(x[0]), reverse=True)
        norm_parts = normalized_unicode.split(".")
        norm_label = norm_parts[0] if norm_parts else ""
        
        for brand_key, brand_info in sorted_brands:
            matched = False
            if len(brand_key) <= 3:
                matched = any(brand_key == part for part in re.split(r"[\.\-_]", normalized_unicode))
            else:
                dist = damerau_levenshtein_distance(norm_label, brand_key)
                matched = (brand_key in normalized_unicode) or (dist <= 2 and len(brand_key) >= 5) or (dist <= 1 and len(brand_key) >= 4)

            if matched:
                spoofed_brand = brand_key
                official_domain = brand_info["official"][0]
                risk_score = max(risk_score, 95)
                attack_vectors.append("idn_homograph_injection")
                
                homoglyph_samples = [f"'{r['char']}' ({r['unicode_name'].split()[0]}) -> '{r['mapped_to']}'" for r in replaced_chars[:3]]
                threat_indicators.append(
                    f"🚨 Critical IDN Homograph: Domain '{domain}' visually mimics legitimate brand '{brand_key}' ({official_domain}) using Unicode character substitutions: {', '.join(homoglyph_samples)}"
                )
                break

    # ── Vector 2: Subdomain Deception Trap (e.g. chase.com.security-verify.ru) ──
    domain_parts = domain.split(".")
    if not spoofed_brand and len(domain_parts) >= 3:
        root_domain = ".".join(domain_parts[-2:])
        subdomain_part = ".".join(domain_parts[:-2])
        
        sorted_brands = sorted(ENTERPRISE_BRANDS.items(), key=lambda x: len(x[0]), reverse=True)
        for brand_key, brand_info in sorted_brands:
            for off in brand_info["official"]:
                off_root = ".".join(off.split(".")[-2:])
                sub_matched = False
                if len(brand_key) <= 3:
                    sub_matched = (off_root in subdomain_part or any(brand_key == p for p in re.split(r"[\.\-_]", subdomain_part)))
                else:
                    sub_matched = (off_root in subdomain_part or brand_key in subdomain_part)

                # Only trigger if the root domain is UNRELATED to the brand
                if sub_matched and root_domain != off_root and not any(root_domain == o or root_domain.endswith("." + o) for o in brand_info["official"]):
                    spoofed_brand = brand_key
                    official_domain = off
                    risk_score = max(risk_score, 90)
                    attack_vectors.append("subdomain_brand_trap")
                    threat_indicators.append(
                        f"⚠️ Subdomain Trap Deception: Brand '{brand_key}' appears in subdomain prefix '{subdomain_part}' on untrusted destination root '{root_domain}'"
                    )
                    break
            if spoofed_brand:
                break

    # ── Vector 3: Combosquatting (e.g. paypal-security-update.com, paypa1-login.ru) ──
    if not spoofed_brand:
        labels = re.split(r"[\.\-_]", domain)
        cleaned_labels = [l for l in labels if l and l not in BENIGN_PARTS]
        leet_domain = normalize_leetspeak(domain)
        cleaned_leet_labels = [normalize_leetspeak(l) for l in cleaned_labels]
        
        sorted_brands = sorted(ENTERPRISE_BRANDS.items(), key=lambda x: len(x[0]), reverse=True)
        for brand_key, brand_info in sorted_brands:
            brand_in_domain = False
            if len(brand_key) <= 3:
                brand_in_domain = any(brand_key == l for l in cleaned_labels) or any(brand_key == l for l in cleaned_leet_labels)
            else:
                brand_in_domain = (brand_key in domain) or (brand_key in leet_domain)

            if brand_in_domain:
                affixes_found = [aff for aff in SECURITY_AFFIXES if aff in domain or aff in leet_domain]
                is_official = any(domain == off or domain.endswith("." + off) for off in brand_info["official"])
                if not is_official and affixes_found:
                    spoofed_brand = brand_key
                    official_domain = brand_info["official"][0]
                    risk_score = max(risk_score, 85)
                    attack_vectors.append("combosquatting_affix")
                    threat_indicators.append(
                        f"⚠️ Combosquatting Detected: Domain combines brand '{brand_key}' with deceptive security keywords [{', '.join(affixes_found[:3])}]"
                    )
                    break

    # ── Vector 4: Damerau-Levenshtein Typosquatting & Leetspeak Transposition ──
    if not spoofed_brand and len(domain_parts) >= 2:
        root_label = domain_parts[-2]  # e.g., 'microsfot' in 'microsfot.com', 'paypa1' in 'paypa1.com'
        sub_labels = [root_label] + [p for p in re.split(r"[\-_]", root_label) if p and p not in BENIGN_PARTS]
        
        for brand_key, brand_info in ENTERPRISE_BRANDS.items():
            if len(brand_key) < 4:
                continue  # Avoid false positive distance collisions on short brands (dhl, ups, citi)
                
            for target_part in sub_labels:
                leet_part = normalize_leetspeak(target_part)
                dist = damerau_levenshtein_distance(target_part, brand_key)
                leet_dist = damerau_levenshtein_distance(leet_part, brand_key) if leet_part != target_part else 99
                
                is_typo = (dist == 1 or (dist == 2 and target_part == root_label)) and (len(brand_key) >= 5 or dist == 1)
                is_leet = (leet_dist == 0 or (leet_dist == 1 and len(brand_key) >= 5)) and leet_part != target_part
                
                if is_typo or is_leet:
                    is_official = any(domain == off or domain.endswith("." + off) for off in brand_info["official"])
                    if not is_official:
                        spoofed_brand = brand_key
                        official_domain = brand_info["official"][0]
                        risk_score = max(risk_score, 80)
                        vec_name = "leetspeak_typosquat" if is_leet else "damerau_levenshtein_typosquat"
                        attack_vectors.append(vec_name)
                        threat_indicators.append(
                            f"⚠️ Typosquatting Match: Domain label '{target_part}' is {dist if not is_leet else 'leetspeak'} edit distance from '{brand_key}' ({official_domain})"
                        )
                        break
            if spoofed_brand:
                break

    # ── Vector 5: High-Abuse TLD Escalation ──
    if spoofed_brand and len(domain_parts) >= 2:
        tld = domain_parts[-1]
        if tld in HIGH_ABUSE_TLDS:
            risk_score = min(100, risk_score + 10)
            attack_vectors.append("high_abuse_tld")
            threat_indicators.append(
                f"🚨 High-Abuse TLD: Domain uses top-level domain '.{tld}' frequently leveraged in automated credential phishing campaigns."
            )

    is_lookalike = spoofed_brand is not None
    
    # Classify overall risk level
    if risk_score >= 80:
        risk_lvl = "critical"
    elif risk_score >= 60:
        risk_lvl = "high"
    elif risk_score > 0:
        risk_lvl = "medium"
    else:
        risk_lvl = "clean"

    return {
        "domain": domain,
        "ascii_domain": ascii_domain,
        "unicode_domain": unicode_domain,
        "is_lookalike": is_lookalike,
        "is_official": False,
        "is_homograph": has_unicode_homoglyphs or is_punycode,
        "spoofed_brand": spoofed_brand,
        "target_brand": spoofed_brand,
        "official_domain": official_domain,
        "risk_level": risk_lvl,
        "risk_score": risk_score,
        "attack_vectors": attack_vectors,
        "threat_indicators": threat_indicators,
        "replaced_characters": replaced_chars
    }


def analyze_urls_for_homographs(urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enriches a list of extracted URL dictionaries with comprehensive IDN homograph analysis.
    """
    enriched = []
    for u in urls:
        dom = u.get("domain", "")
        analysis = evaluate_domain_homograph(dom)
        
        item = dict(u)
        item["homograph_analysis"] = analysis
        item["is_lookalike"] = analysis.get("is_lookalike", False)
        item["is_homograph"] = analysis.get("is_homograph", False)
        item["spoofed_brand"] = analysis.get("spoofed_brand")
        item["official_domain"] = analysis.get("official_domain")
        item["attack_vectors"] = analysis.get("attack_vectors", [])
        item["suspicious"] = item.get("suspicious", False) or item["is_lookalike"]
        enriched.append(item)
        
    return enriched
