"""
Unit tests for Quishing (QR Code Phishing) Computer Vision & Threat Analysis Engine.
"""

import io
import base64
import pytest
import qrcode
from PIL import Image

from app.services.qr_scanner import (
    extract_images_from_email,
    decode_qr_codes_from_image,
    evaluate_quishing_payload,
    scan_email_for_quishing,
)


def _generate_test_qr_bytes(payload: str) -> bytes:
    """Generates PNG bytes for a synthetic QR code."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_decode_qr_codes_from_image_clean():
    test_url = "https://legitimate-service.com/mfa-setup"
    img_bytes = _generate_test_qr_bytes(test_url)
    results = decode_qr_codes_from_image(img_bytes)
    assert len(results) >= 1
    assert test_url in results


def test_decode_qr_codes_from_image_empty():
    # Solid black 100x100 image without QR
    img = Image.new("RGB", (100, 100), color="black")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    results = decode_qr_codes_from_image(buf.getvalue())
    assert results == []


def test_evaluate_quishing_payload_typosquatting():
    payload = "https://paypa1-support.ru/verify?id=123"
    evaluated = evaluate_quishing_payload(payload, "test_qr.png", "inline_cid")
    assert evaluated["payload_type"] == "url"
    assert evaluated["risk_level"] in ("high", "critical")
    assert evaluated["risk_score"] >= 45
    assert any("impersonates" in ind or "typosquatting" in ind for ind in evaluated["threat_indicators"])


def test_evaluate_quishing_payload_shortener():
    payload = "https://bit.ly/3xFakeMFA"
    evaluated = evaluate_quishing_payload(payload, "invoice_qr.png", "attachment")
    assert evaluated["is_shortened"] is True
    assert evaluated["risk_score"] >= 35
    assert any("URL shortener" in ind for ind in evaluated["threat_indicators"])


def test_evaluate_quishing_payload_bitcoin():
    payload = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    evaluated = evaluate_quishing_payload(payload, "wallet.png", "inline_cid")
    assert evaluated["payload_type"] == "bitcoin_address"
    assert evaluated["risk_level"] in ("high", "critical")
    assert evaluated["risk_score"] >= 50


def test_scan_email_for_quishing_embedded_base64():
    phish_url = "http://micros0ft-mfa.ru/reset"
    qr_bytes = _generate_test_qr_bytes(phish_url)
    b64_str = base64.b64encode(qr_bytes).decode("ascii")

    raw_email = f"""From: IT Support <it@micros0ft-mfa.ru>
To: user@example.com
Subject: Urgent: Microsoft 365 MFA Re-authentication Required
Content-Type: text/html

<html>
<body>
  <h2>Urgent Security Notice</h2>
  <p>Scan the QR code below using your mobile phone authenticator to restore access:</p>
  <img src="data:image/png;base64,{b64_str}" alt="MFA QR Code" />
</body>
</html>
"""
    result = scan_email_for_quishing(raw_email)
    assert result["has_qr_codes"] is True
    assert result["qr_count"] >= 1
    assert result["risk_level"] in ("high", "critical")
    assert result["risk_score"] >= 50

    detection = result["detections"][0]
    assert detection["decoded_payload"] == phish_url
    assert detection["payload_type"] == "url"


def test_scan_email_for_quishing_clean_email():
    raw_email = """From: Alice <alice@example.com>
To: Bob <bob@example.com>
Subject: Team sync tomorrow
Content-Type: text/plain

Hi Bob, let's meet tomorrow at 10 AM.
"""
    result = scan_email_for_quishing(raw_email)
    assert result["has_qr_codes"] is False
    assert result["qr_count"] == 0
    assert result["risk_level"] == "clean"
    assert result["detections"] == []
