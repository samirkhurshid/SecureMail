"""
SecureMail v4.0 — Advanced IDN Homograph & Typosquatting Defense Engine.
Detects Punycode obfuscation, Cyrillic/Greek/Latin homoglyphs, Damerau-Levenshtein transpositions,
combosquatting, subdomain deception traps, and unauthorized brand impersonations across 100+ global brands.
"""

import re
import unicodedata
from typing import Dict, List, Optional, Tuple, Any

# ── 100+ Curated Global Brand Knowledge Base ─────────────────────────────────
# Maps brand identifier -> primary official domain(s) and aliases
ENTERPRISE_BRANDS: Dict[str, Dict[str, Any]] = {
    # ── Tech Giants & Cloud ──
    "google": {"official": ["google.com", "google.co.uk", "google.ca", "google.de", "google.fr", "google.com.au"], "category": "tech"},
    "gmail": {"official": ["gmail.com"], "category": "tech"},
    "youtube": {"official": ["youtube.com", "youtu.be"], "category": "tech"},
    "microsoft": {"official": ["microsoft.com", "msn.com", "live.com"], "category": "tech"},
    "outlook": {"official": ["outlook.com", "hotmail.com"], "category": "tech"},
    "office365": {"official": ["office.com", "office365.com"], "category": "tech"},
    "apple": {"official": ["apple.com"], "category": "tech"},
    "icloud": {"official": ["icloud.com"], "category": "tech"},
    "amazon": {"official": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca", "amazon.in"], "category": "ecommerce"},
    "aws": {"official": ["aws.amazon.com"], "category": "cloud"},
    "meta": {"official": ["meta.com"], "category": "social"},
    "facebook": {"official": ["facebook.com", "fb.com"], "category": "social"},
    "instagram": {"official": ["instagram.com"], "category": "social"},
    "whatsapp": {"official": ["whatsapp.com"], "category": "social"},
    "netflix": {"official": ["netflix.com"], "category": "media"},
    "spotify": {"official": ["spotify.com"], "category": "media"},
    "twitter": {"official": ["twitter.com", "x.com"], "category": "social"},
    "linkedin": {"official": ["linkedin.com"], "category": "social"},
    "github": {"official": ["github.com", "github.io"], "category": "developer"},
    "gitlab": {"official": ["gitlab.com"], "category": "developer"},
    "openai": {"official": ["openai.com", "chatgpt.com"], "category": "ai"},
    "chatgpt": {"official": ["chatgpt.com"], "category": "ai"},
    "adobe": {"official": ["adobe.com"], "category": "software"},
    "dropbox": {"official": ["dropbox.com"], "category": "cloud"},
    "zoom": {"official": ["zoom.us", "zoom.com"], "category": "collaboration"},
    "slack": {"official": ["slack.com"], "category": "collaboration"},
    "salesforce": {"official": ["salesforce.com", "force.com"], "category": "enterprise"},
    "docusign": {"official": ["docusign.com", "docusign.net"], "category": "enterprise"},
    "intuit": {"official": ["intuit.com", "turbotax.com"], "category": "finance"},
    "quickbooks": {"official": ["quickbooks.intuit.com", "quickbooks.com"], "category": "finance"},
    "workday": {"official": ["workday.com"], "category": "enterprise"},
    "servicenow": {"official": ["servicenow.com"], "category": "enterprise"},
    "okta": {"official": ["okta.com", "okta-emea.com"], "category": "security"},
    "cloudflare": {"official": ["cloudflare.com"], "category": "security"},
    "cisco": {"official": ["cisco.com", "webex.com"], "category": "networking"},
    "atlassian": {"official": ["atlassian.com", "jira.com", "trello.com", "bitbucket.org"], "category": "developer"},
    "yahoo": {"official": ["yahoo.com", "yahoo.co.jp"], "category": "tech"},

    # ── Global Banking & Wealth Management ──
    "chase": {"official": ["chase.com"], "category": "banking"},
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
    "credit-suisse": {"official": ["credit-suisse.com"], "category": "banking"},
    "charlesschwab": {"official": ["schwab.com", "charlesschwab.com"], "category": "finance"},
    "schwab": {"official": ["schwab.com", "charlesschwab.com"], "category": "finance"},
    "fidelity": {"official": ["fidelity.com", "fidelityinternational.com"], "category": "finance"},
    "tdbank": {"official": ["td.com", "tdbank.com"], "category": "banking"},
    "pnc": {"official": ["pnc.com"], "category": "banking"},
    "usbank": {"official": ["usbank.com"], "category": "banking"},
    "truist": {"official": ["truist.com"], "category": "banking"},
    "americanexpress": {"official": ["americanexpress.com", "amex.com"], "category": "finance"},
    "amex": {"official": ["amex.com", "americanexpress.com"], "category": "finance"},
    "discover": {"official": ["discover.com", "discovercard.com"], "category": "finance"},

    # ── Payments, Fintech & Crypto ──
    "paypal": {"official": ["paypal.com", "paypal.me"], "category": "fintech"},
    "stripe": {"official": ["stripe.com"], "category": "fintech"},
    "square": {"official": ["squareup.com", "square.online", "block.xyz"], "category": "fintech"},
    "venmo": {"official": ["venmo.com", "paypal.com"], "category": "fintech"},
    "wise": {"official": ["wise.com", "transferwise.com"], "category": "fintech"},
    "revolut": {"official": ["revolut.com"], "category": "fintech"},
    "zelle": {"official": ["zellepay.com"], "category": "fintech"},
    "klarna": {"official": ["klarna.com"], "category": "fintech"},
    "affirm": {"official": ["affirm.com"], "category": "fintech"},
    "coinbase": {"official": ["coinbase.com", "pro.coinbase.com"], "category": "crypto"},
    "binance": {"official": ["binance.com", "binance.us"], "category": "crypto"},
    "kraken": {"official": ["kraken.com"], "category": "crypto"},
    "metamask": {"official": ["metamask.io"], "category": "crypto"},
    "ledger": {"official": ["ledger.com"], "category": "crypto"},
    "trezor": {"official": ["trezor.io"], "category": "crypto"},
    "trustwallet": {"official": ["trustwallet.com"], "category": "crypto"},
    "opensea": {"official": ["opensea.io"], "category": "crypto"},
    "gemini": {"official": ["gemini.com"], "category": "crypto"},
    "robinhood": {"official": ["robinhood.com"], "category": "fintech"},

    # ── Logistics & Shipping ──
    "dhl": {"official": ["dhl.com", "dhl.de", "express.dhl"], "category": "logistics"},
    "fedex": {"official": ["fedex.com"], "category": "logistics"},
    "ups": {"official": ["ups.com"], "category": "logistics"},
    "usps": {"official": ["usps.com", "tools.usps.com"], "category": "logistics"},
    "royalmail": {"official": ["royalmail.com"], "category": "logistics"},
    "canadapost": {"official": ["canadapost-postescanada.ca", "canadapost.ca"], "category": "logistics"},
    "auspost": {"official": ["auspost.com.au"], "category": "logistics"},
    "dpd": {"official": ["dpd.com", "dpd.co.uk", "dpd.de"], "category": "logistics"},
    "hermes": {"official": ["myhermes.co.uk", "hermesworld.com", "evri.com"], "category": "logistics"},
    "evri": {"official": ["evri.com"], "category": "logistics"},

    # ── E-Commerce & Retail ──
    "ebay": {"official": ["ebay.com", "ebay.co.uk", "ebay.de"], "category": "ecommerce"},
    "walmart": {"official": ["walmart.com"], "category": "retail"},
    "target": {"official": ["target.com"], "category": "retail"},
    "bestbuy": {"official": ["bestbuy.com"], "category": "retail"},
    "shopify": {"official": ["shopify.com", "myshopify.com"], "category": "ecommerce"},
    "alibaba": {"official": ["alibaba.com", "alibabagroup.com"], "category": "ecommerce"},
    "aliexpress": {"official": ["aliexpress.com"], "category": "ecommerce"},
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

# ── Confusable Homoglyph Mapping ─────────────────────────────────────────────
# Maps visual lookalikes (Cyrillic, Greek, Latin fullwidth, etc.) -> base Latin character
CONFUSABLE_MAP: Dict[str, str] = {
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
    # Number substitutions common in typosquatting / leetspeak
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a",
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
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + cost) # transposition

    return d[(len1 - 1, len2 - 1)]


def normalize_homoglyphs(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """
    Normalizes confusable Unicode homoglyphs and leetspeak numbers to base Latin.
    Returns (normalized_text, list_of_replaced_characters).
    """
    # Remove zero-width spaces
    cleaned = re.sub(r"[\u200B\u200C\u200D\uFEFF]", "", text)
    
    replaced = []
    result = []
    
    for char in cleaned:
        if char in CONFUSABLE_MAP:
            mapped = CONFUSABLE_MAP[char]
            # Get unicode name if possible
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


# ── Core Domain Evaluation Engine ───────────────────────────────────────────

def evaluate_domain_homograph(raw_domain: str) -> Dict[str, Any]:
    """
    Performs comprehensive multi-vector analysis on a domain name.
    
    Vectors evaluated:
    1. IDN Homograph / Punycode script injection
    2. Character homoglyph substitutions (Cyrillic/Greek lookalikes)
    3. Damerau-Levenshtein transposition & proximity typosquatting
    4. Subdomain brand trap deception
    5. Combosquatting security affix attachment
    6. High-abuse TLD brand mismatches
    
    Returns structured analysis verdict.
    """
    domain = raw_domain.strip().lower().rstrip(".")
    if not domain:
        return {"is_lookalike": False, "risk_level": "clean", "threat_indicators": []}

    # Extract Punycode and Unicode representations
    ascii_domain, unicode_domain, is_punycode = decode_punycode_domain(domain)
    
    # Check for direct official matches
    for brand_key, brand_info in ENTERPRISE_BRANDS.items():
        if domain in brand_info["official"] or ascii_domain in brand_info["official"]:
            return {
                "domain": domain,
                "ascii_domain": ascii_domain,
                "unicode_domain": unicode_domain,
                "is_lookalike": False,
                "is_official": True,
                "brand": brand_key,
                "brand_category": brand_info["category"],
                "risk_level": "clean",
                "risk_score": 0,
                "threat_indicators": []
            }

    # Normalize confusable characters
    normalized_domain, replaced_chars = normalize_homoglyphs(unicode_domain)
    normalized_ascii, _ = normalize_homoglyphs(ascii_domain)
    
    threat_indicators: List[str] = []
    attack_vectors: List[str] = []
    spoofed_brand: Optional[str] = None
    official_domain: Optional[str] = None
    risk_score = 0

    # ── Vector 1: Punycode & IDN Homograph Injection ──
    has_homoglyphs = len(replaced_chars) > 0
    if is_punycode or has_homoglyphs:
        # Sort brands by length descending so specific brands (paypal, microsoft) match before short subsets
        sorted_brands = sorted(ENTERPRISE_BRANDS.items(), key=lambda x: len(x[0]), reverse=True)
        for brand_key, brand_info in sorted_brands:
            matched = False
            if len(brand_key) <= 3:
                # Require label match for 3-char brands like aws, dhl, ups
                matched = any(brand_key == part for part in re.split(r"[\.\-_]", normalized_domain))
            else:
                matched = (brand_key in normalized_domain or brand_key in normalized_ascii)

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

    # ── Vector 2: Subdomain Deception Trap (e.g. paypal.com.evil.ru) ──
    domain_parts = domain.split(".")
    if len(domain_parts) >= 3:
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

                if sub_matched and root_domain != off_root:
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

    # ── Vector 3: Combosquatting (e.g. paypal-security-update.com) ──
    if not spoofed_brand:
        labels = re.split(r"[\.\-_]", domain)
        cleaned_labels = [l for l in labels if l and l not in BENIGN_PARTS]
        
        sorted_brands = sorted(ENTERPRISE_BRANDS.items(), key=lambda x: len(x[0]), reverse=True)
        for brand_key, brand_info in sorted_brands:
            brand_in_domain = False
            if len(brand_key) <= 3:
                brand_in_domain = any(brand_key == l for l in cleaned_labels)
            else:
                brand_in_domain = (brand_key in domain)

            if brand_in_domain:
                affixes_found = [aff for aff in SECURITY_AFFIXES if aff in domain]
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

    # ── Vector 4: Damerau-Levenshtein Typosquatting (Omissions, Transpositions) ──
    if not spoofed_brand:
        for label in cleaned_labels:
            if len(label) < 4:
                continue
            
            # Check normalized label against all brands
            norm_label, _ = normalize_homoglyphs(label)
            
            for brand_key, brand_info in ENTERPRISE_BRANDS.items():
                if abs(len(norm_label) - len(brand_key)) <= 2:
                    dist = damerau_levenshtein_distance(norm_label, brand_key)
                    if 0 < dist <= 2:
                        is_official = any(domain == off or domain.endswith("." + off) for off in brand_info["official"])
                        if not is_official:
                            spoofed_brand = brand_key
                            official_domain = brand_info["official"][0]
                            risk_score = max(risk_score, 80 if dist == 1 else 65)
                            attack_vectors.append("damerau_levenshtein_typosquat")
                            technique = "adjacent transposition" if (len(norm_label) == len(brand_key) and dist == 1) else "character omission/insertion"
                            threat_indicators.append(
                                f"⚠️ Typosquatting ({technique}): Label '{label}' is {dist} edit(s) away from official brand '{brand_key}' ({official_domain})"
                            )
                            break
            if spoofed_brand:
                break

    # ── Vector 5: High-Abuse TLD Brand Escalation ──
    tld = domain_parts[-1] if domain_parts else ""
    if spoofed_brand and tld in HIGH_ABUSE_TLDS:
        risk_score = min(100, risk_score + 15)
        attack_vectors.append("high_abuse_tld")
        threat_indicators.append(
            f"🚩 High-Abuse TLD Alert: Brand impersonation hosted on risk-associated top-level domain (.{tld})"
        )

    # Determine risk level
    is_lookalike = bool(spoofed_brand and risk_score >= 50)
    if risk_score >= 85:
        risk_level = "critical"
    elif risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 40:
        risk_level = "medium"
    else:
        risk_level = "clean"

    return {
        "domain": domain,
        "ascii_domain": ascii_domain,
        "unicode_domain": unicode_domain,
        "is_lookalike": is_lookalike,
        "is_homograph": is_punycode or has_homoglyphs,
        "spoofed_brand": spoofed_brand,
        "official_domain": official_domain,
        "attack_vectors": attack_vectors,
        "confusable_chars": replaced_chars,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_indicators": threat_indicators
    }


def analyze_urls_for_homographs(urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enriches a list of parsed email URL nodes with deep homograph and typosquatting intelligence.
    """
    from urllib.parse import urlparse

    enriched = []
    for item in urls:
        raw_url = item.get("url", "")
        parsed = urlparse(raw_url)
        netloc = parsed.netloc.split(":")[0].strip()
        
        if not netloc:
            enriched.append(item)
            continue
            
        homograph_verdict = evaluate_domain_homograph(netloc)
        
        # Merge analysis properties
        enriched_node = {
            **item,
            "is_lookalike": item.get("is_lookalike", False) or homograph_verdict["is_lookalike"],
            "is_homograph": homograph_verdict["is_homograph"],
            "spoofed_brand": homograph_verdict["spoofed_brand"] or item.get("spoofed_brand"),
            "official_domain": homograph_verdict["official_domain"],
            "homograph_analysis": homograph_verdict,
            "attack_vectors": homograph_verdict["attack_vectors"]
        }
        
        if homograph_verdict["is_lookalike"]:
            enriched_node["suspicious"] = True
            
        enriched.append(enriched_node)
        
    return enriched
