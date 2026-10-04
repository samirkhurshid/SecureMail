"""
Unit tests for SecureMail v4.0 IDN Homograph & Typosquatting Engine (Phase 1.2).
"""

import pytest
from app.services.homograph_service import (
    evaluate_domain_homograph,
    analyze_urls_for_homographs,
    damerau_levenshtein_distance,
    normalize_homoglyphs,
    decode_punycode_domain,
)


def test_damerau_levenshtein_transposition():
    """Verify adjacent transposition counts as 1 edit distance."""
    # microsfot -> microsoft (transposition of f and o)
    assert damerau_levenshtein_distance("microsfot", "microsoft") == 1
    # paypl -> paypal (omission of a)
    assert damerau_levenshtein_distance("paypl", "paypal") == 1
    # appple -> apple (insertion of p)
    assert damerau_levenshtein_distance("appple", "apple") == 1
    # identical
    assert damerau_levenshtein_distance("google", "google") == 0


def test_normalize_cyrillic_homoglyphs():
    """Verify Cyrillic homoglyphs are normalized to base Latin."""
    # 'а' (Cyrillic U+0430) -> 'a'
    normalized, replaced = normalize_homoglyphs("pаypаl")
    assert normalized == "paypal"
    assert len(replaced) == 2
    assert replaced[0]["mapped_to"] == "a"


def test_punycode_decoding():
    """Verify IDN Punycode decoding."""
    # xn--pypl-53dc.com is pаypаl.com (with Cyrillic 'а')
    ascii_d, unicode_d, is_punycode = decode_punycode_domain("xn--pypl-53dc.com")
    assert is_punycode is True
    assert "xn--" in ascii_d
    assert "p" in unicode_d


def test_idn_homograph_attack_detection():
    """Verify Punycode domain impersonating PayPal is flagged as critical."""
    res = evaluate_domain_homograph("xn--pypl-53dc.com")
    assert res["is_lookalike"] is True
    assert res["is_homograph"] is True
    assert res["spoofed_brand"] == "paypal"
    assert res["risk_level"] in ("critical", "high")
    assert "idn_homograph_injection" in res["attack_vectors"]


def test_typosquatting_transposition_detection():
    """Verify adjacent transposition like microsfot.com is flagged."""
    res = evaluate_domain_homograph("microsfot.com")
    assert res["is_lookalike"] is True
    assert res["spoofed_brand"] == "microsoft"
    assert "damerau_levenshtein_typosquat" in res["attack_vectors"]


def test_combosquatting_detection():
    """Verify combosquatting like paypal-security-update.com is flagged."""
    res = evaluate_domain_homograph("paypal-security-update.com")
    assert res["is_lookalike"] is True
    assert res["spoofed_brand"] == "paypal"
    assert "combosquatting_affix" in res["attack_vectors"]


def test_subdomain_trap_detection():
    """Verify multi-level subdomain deception like chase.com.evil-server.ru is flagged."""
    res = evaluate_domain_homograph("chase.com.security-verify.ru")
    assert res["is_lookalike"] is True
    assert res["spoofed_brand"] == "chase"
    assert "subdomain_brand_trap" in res["attack_vectors"]


def test_high_abuse_tld_escalation():
    """Verify lookalike domain on high abuse TLD is escalated."""
    res = evaluate_domain_homograph("netflix-login.xyz")
    assert res["is_lookalike"] is True
    assert res["spoofed_brand"] == "netflix"
    assert "high_abuse_tld" in res["attack_vectors"]


def test_clean_official_domains():
    """Verify official enterprise domains and cloud infrastructure produce zero false positives."""
    clean_domains = [
        "paypal.com",
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "chase.com",
        "netflix.com",
        "dhl.com",
        # Cloud infrastructure & CDN subdomains
        "notification-ms-static.s3.amazonaws.com",
        "fonts.googleapis.com",
        "calyx-production-media.s3.amazonaws.com",
        "assets.github.io",
        "cdnjs.cloudflare.com",
        "portal.azure.com",
    ]
    for d in clean_domains:
        res = evaluate_domain_homograph(d)
        assert res["is_lookalike"] is False
        assert res["risk_level"] == "clean"
        assert res["risk_score"] == 0
        assert len(res["threat_indicators"]) == 0


def test_leetspeak_typosquatting_detection():
    """Verify leetspeak like p4ypal.com is flagged as typosquatting."""
    res = evaluate_domain_homograph("p4ypal.com")
    assert res["is_lookalike"] is True
    assert res["spoofed_brand"] == "paypal"
    assert "leetspeak_typosquat" in res["attack_vectors"]


def test_analyze_urls_enrichment():
    """Verify URL list is enriched with homograph analysis node."""
    sample_urls = [
        {"url": "https://xn--gogle-pra.com/signin", "domain": "xn--gogle-pra.com"},
        {"url": "https://www.google.com/search?q=test", "domain": "google.com"},
        {"url": "https://notification-ms-static.s3.amazonaws.com/img.png", "domain": "notification-ms-static.s3.amazonaws.com"},
    ]
    enriched = analyze_urls_for_homographs(sample_urls)
    assert len(enriched) == 3
    assert enriched[0]["is_lookalike"] is True
    assert enriched[0]["spoofed_brand"] == "google"
    assert enriched[1]["is_lookalike"] is False
    assert enriched[2]["is_lookalike"] is False

