"""
Unit tests for SecureMail v4.0 Hybrid Local ML Phishing Classifier (Phase 1.3).
"""

import pytest
import time
from app.services.ml_classifier import (
    extract_feature_vector,
    predict_phishing_probability,
    sigmoid,
    FEATURE_WEIGHTS,
)


def test_sigmoid_bounds():
    """Verify sigmoid is mathematically stable with extreme values."""
    assert sigmoid(0.0) == 0.5
    assert sigmoid(100.0) == 1.0
    assert sigmoid(-100.0) == 0.0
    assert 0.0 <= sigmoid(2.5) <= 1.0


def test_feature_vector_extraction():
    """Verify feature vectorizer extracts normalized float features."""
    sample_email = {
        "subject": "URGENT: ACTION REQUIRED IMMEDIATELY!!!",
        "body_plain": "Please verify your account password and update billing details within 24 hours at http://192.168.1.1/login",
        "headers": {
            "from_domain": "chase-security.xyz",
            "display_name_spoof": True,
            "reply_to_mismatch": True,
        },
        "authentication": {
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
        },
        "urls": [
            {"url": "http://192.168.1.1/login", "domain": "192.168.1.1", "is_shortened": False, "is_lookalike": True}
        ],
        "attachments": [],
    }

    features = extract_feature_vector(sample_email)
    assert isinstance(features, dict)
    assert len(features) >= 20
    assert features["urgency_score"] > 0
    assert features["credential_request_score"] > 0
    assert features["ip_in_url"] == 1.0
    assert features["spf_fail"] == 1.0
    assert features["dmarc_fail"] == 1.0
    assert features["display_name_spoof"] == 1.0


def test_high_probability_credential_phishing():
    """Verify severe credential harvesting phishing email receives high probability."""
    sample_phish = {
        "subject": "FINAL NOTICE: Account Suspended within 24 hours",
        "body_plain": "Your credentials have expired. Sign in immediately to confirm your identity or your account will be permanently blocked: http://login-verify-account.com",
        "headers": {
            "from_domain": "service-security.ru",
            "display_name_spoof": True,
            "reply_to_mismatch": True,
        },
        "authentication": {
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
        },
        "urls": [
            {"url": "http://login-verify-account.com", "domain": "login-verify-account.com", "is_lookalike": True}
        ],
        "attachments": [],
    }

    res = predict_phishing_probability(sample_phish)
    assert res["is_phishing"] is True
    assert res["probability"] >= 0.85
    assert res["confidence"] == "critical"
    assert len(res["top_signals"]) > 0


def test_clean_newsletter_email():
    """Verify legitimate corporate newsletter with full auth passes as clean."""
    sample_clean = {
        "subject": "Your monthly security newsletter & updates",
        "body_plain": "Here is the summary of tech updates this month. To manage preferences or unsubscribe, please click our privacy policy link below. Copyright 2026 TechCorp. All rights reserved.",
        "headers": {
            "from_domain": "techcorp.com",
            "display_name_spoof": False,
            "reply_to_mismatch": False,
        },
        "authentication": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        },
        "urls": [
            {"url": "https://techcorp.com/newsletter/may", "domain": "techcorp.com", "is_lookalike": False}
        ],
        "attachments": [],
    }

    res = predict_phishing_probability(sample_clean)
    assert res["is_phishing"] is False
    assert res["probability"] <= 0.35
    assert res["confidence"] == "low"
    assert res["verdict"] == "clean"


def test_offline_inference_speed():
    """Verify ML inference executes in under 10ms with zero network dependencies."""
    sample = {
        "subject": "Quick meeting sync",
        "body_plain": "Are we still meeting at 3pm today?",
        "headers": {"from_domain": "company.com"},
        "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "urls": [],
        "attachments": [],
    }

    start = time.perf_counter()
    for _ in range(10):
        predict_phishing_probability(sample)
    duration_avg_ms = ((time.perf_counter() - start) / 10.0) * 1000

    assert duration_avg_ms < 10.0  # Must be fast local inference


def test_top_signals_attribution():
    """Verify explainable AI feature attribution outputs understandable signals."""
    sample = {
        "subject": "URGENT: Password Reset Required",
        "body_plain": "Someone attempted unauthorized access to your account. Reset password immediately.",
        "headers": {"from_domain": "suspicious.xyz"},
        "authentication": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
        "urls": [{"url": "http://short.url/x", "domain": "short.url", "is_shortened": True}],
    }

    res = predict_phishing_probability(sample)
    assert "top_signals" in res
    assert len(res["top_signals"]) >= 3
    
    top_feature_names = [s["feature"] for s in res["top_signals"]]
    assert any("urgency" in f or "credential" in f or "spf" in f or "dmarc" in f or "shortener" in f for f in top_feature_names)
