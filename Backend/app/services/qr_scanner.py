"""
SecureMail v4.0 — Quishing (QR Code Phishing) Computer Vision & Threat Engine.
Extracts inline CID images, file attachments, and HTML base64 data URIs from emails,
decodes embedded QR codes using multi-stage OpenCV image preprocessing, and evaluates
destination URLs against threat intelligence.
"""

import io
import re
import base64
import email
from email import policy
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

import numpy as np
from PIL import Image

try:
    import cv2
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

from app.utils.logger import setup_logger

logger = setup_logger(__name__)

# Known URL shortener / redirector domains frequently abused in Quishing campaigns
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "qr.codes", "qrco.de", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "goo.gl", "rebrand.ly", "bl.ink",
    "shorturl.at", "t.ly", "v.gd", "qr-code.me", "linktr.ee"
}

# Image extensions supported for QR inspection
IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tiff")


def extract_images_from_email(
    raw_email: str,
    parsed_dict: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Extracts all image payloads from an email:
    1. Inline MIME parts (with Content-ID)
    2. File attachments matching image formats
    3. Base64 Data URIs embedded inside HTML body tags (<img src="data:image/...">)
    """
    images: List[Dict[str, Any]] = []
    seen_hashes = set()

    if not raw_email or not isinstance(raw_email, str):
        return images

    # ── 1. Parse MIME message structure ──────────────────────────────────────
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        for part in msg.walk():
            # Skip multipart containers
            if part.is_multipart():
                continue

            content_type = (part.get_content_type() or "").lower()
            filename = part.get_filename() or ""
            content_id = (part.get("Content-ID") or "").strip("<>")
            disposition = (part.get("Content-Disposition") or "").lower()

            is_image_type = content_type.startswith("image/")
            is_image_ext = any(filename.lower().endswith(ext) for ext in IMAGE_EXTENSIONS)

            if is_image_type or is_image_ext:
                payload = part.get_payload(decode=True)
                if payload and len(payload) >= 100:
                    # Deduplicate identical images by length + prefix hash
                    img_sig = (len(payload), hash(payload[:256]))
                    if img_sig in seen_hashes:
                        continue
                    seen_hashes.add(img_sig)

                    source = "inline_cid" if (content_id or "inline" in disposition) else "attachment"
                    images.append({
                        "filename": filename or (f"cid_{content_id}.png" if content_id else f"image_{len(images)+1}.png"),
                        "content_id": content_id,
                        "source": source,
                        "content_type": content_type or "image/png",
                        "data": payload,
                        "size_bytes": len(payload)
                    })
    except Exception as e:
        logger.warning(f"Error parsing MIME image parts: {e}")

    # ── 2. Parse Base64 Data URIs from HTML text ─────────────────────────────
    try:
        # Check raw email or body HTML
        data_uri_pattern = re.compile(
            r'data:image\/(?:png|jpeg|jpg|webp|bmp|gif);base64,([A-Za-z0-9+/=]{100,})',
            re.IGNORECASE
        )
        matches = data_uri_pattern.findall(raw_email)
        for idx, b64_str in enumerate(matches[:15]):  # limit max 15 data URIs
            try:
                decoded_bytes = base64.b64decode(b64_str)
                if len(decoded_bytes) >= 100:
                    img_sig = (len(decoded_bytes), hash(decoded_bytes[:256]))
                    if img_sig in seen_hashes:
                        continue
                    seen_hashes.add(img_sig)

                    images.append({
                        "filename": f"embedded_data_uri_{idx+1}.png",
                        "content_id": "",
                        "source": "html_data_uri",
                        "content_type": "image/png",
                        "data": decoded_bytes,
                        "size_bytes": len(decoded_bytes)
                    })
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Error extracting HTML base64 data URIs: {e}")

    return images


def decode_qr_codes_from_image(image_bytes: bytes, filename: str = "image.png") -> List[str]:
    """
    Decodes QR codes from image bytes using a 4-stage computer vision preprocessing pipeline:
    Stage 1: Direct OpenCV QRCodeDetector
    Stage 2: Grayscale + CLAHE Contrast Equalization
    Stage 3: Otsu Global & Adaptive Gaussian Thresholding
    Stage 4: Bitwise Inverted Matrix (Dark Mode White-on-Dark QR codes)
    """
    if not HAS_OPENCV:
        logger.warning("OpenCV is not available; QR code decoding skipped.")
        return []

    if not image_bytes or len(image_bytes) < 100 or len(image_bytes) > 15 * 1024 * 1024:
        return []

    found_payloads: List[str] = []

    try:
        # Load through Pillow to safely normalize all formats (CMYK, RGBA, WebP, GIF frames)
        with Image.open(io.BytesIO(image_bytes)) as pil_img:
            if pil_img.width < 40 or pil_img.height < 40:
                return []
            
            # Convert to RGB mode
            if pil_img.mode != "RGB":
                pil_img = pil_img.convert("RGB")
            
            # Convert PIL RGB to OpenCV BGR NumPy array
            rgb_arr = np.array(pil_img)
            bgr_img = cv2.cvtColor(rgb_arr, cv2.COLOR_RGB2BGR)

    except Exception as e:
        logger.debug(f"Failed to load image bytes for {filename}: {e}")
        return []

    detector = cv2.QRCodeDetector()

    def _try_decode(img_matrix) -> List[str]:
        results = []
        try:
            # Multi-QR detection first
            retval, decoded_info, points, straight_qrcode = detector.detectAndDecodeMulti(img_matrix)
            if retval and decoded_info:
                for text in decoded_info:
                    if text and text.strip() and text.strip() not in results:
                        results.append(text.strip())
        except Exception:
            pass

        if not results:
            try:
                # Single QR fallback
                val, points, straight_qrcode = detector.detectAndDecode(img_matrix)
                if val and val.strip():
                    results.append(val.strip())
            except Exception:
                pass

        return results

    # ── Stage 1: Direct Decode on Raw BGR ────────────────────────────────────
    stage1 = _try_decode(bgr_img)
    if stage1:
        return stage1

    # ── Stage 2: Grayscale & CLAHE Contrast Equalization ────────────────────
    gray = cv2.cvtColor(bgr_img, cv2.COLOR_BGR2GRAY)
    stage2 = _try_decode(gray)
    if stage2:
        return stage2

    try:
        clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        stage2_clahe = _try_decode(enhanced)
        if stage2_clahe:
            return stage2_clahe
    except Exception:
        pass

    # ── Stage 3: Binarization & Adaptive Thresholding ────────────────────────
    try:
        # Otsu thresholding
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        stage3_otsu = _try_decode(otsu)
        if stage3_otsu:
            return stage3_otsu

        # Adaptive Gaussian thresholding (for noisy/textured backgrounds)
        adapt = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 10
        )
        stage3_adapt = _try_decode(adapt)
        if stage3_adapt:
            return stage3_adapt
    except Exception:
        pass

    # ── Stage 4: Bitwise Inversion (White-on-Dark / Dark-Mode QR codes) ─────
    try:
        inverted = cv2.bitwise_not(gray)
        stage4_inv = _try_decode(inverted)
        if stage4_inv:
            return stage4_inv

        _, inv_otsu = cv2.threshold(inverted, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        stage4_inv_otsu = _try_decode(inv_otsu)
        if stage4_inv_otsu:
            return stage4_inv_otsu
    except Exception:
        pass

    return found_payloads


def evaluate_quishing_payload(
    payload: str,
    filename: str,
    source: str
) -> Dict[str, Any]:
    """
    Evaluates a decoded QR code payload for security threats:
    - URL structure and shortener evasion
    - Lookalike brand domain typosquatting
    - Plaintext cryptocurrency addresses or credential directives
    """
    threat_indicators: List[str] = []
    risk_score = 15  # Base score for QR code in email (evasion technique)
    payload_type = "plain_text"
    is_shortened = False
    domain = ""

    # Check if payload is a URL
    url_match = re.match(r'^(https?://|www\.)[^\s/$.?#].[^\s]*$', payload, re.IGNORECASE)
    if url_match or payload.startswith("http://") or payload.startswith("https://"):
        payload_type = "url"
        normalized_url = payload if payload.startswith(("http://", "https://")) else f"https://{payload}"
        try:
            parsed = urlparse(normalized_url)
            domain = (parsed.netloc or "").lower().split(":")[0]

            # Shortener check
            if domain in URL_SHORTENERS:
                is_shortened = True
                risk_score += 30
                threat_indicators.append(f"QR code utilizes URL shortener redirector ({domain}) to conceal landing destination")

            # Lookalike domain check
            from app.services.email_parser import _check_domain_lookalike
            is_lookalike, target_brand = _check_domain_lookalike(domain)
            if is_lookalike:
                risk_score += 45
                threat_indicators.append(f"QR destination domain '{domain}' impersonates '{target_brand}' via typosquatting")

            # Insecure HTTP
            if parsed.scheme == "http":
                risk_score += 15
                threat_indicators.append("QR code uses insecure plain HTTP connection")

            # IP-based URL
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                risk_score += 40
                threat_indicators.append(f"QR code links directly to raw numeric IP address ({domain})")

        except Exception as e:
            logger.debug(f"Error parsing QR URL {payload}: {e}")

    elif re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', payload) or payload.startswith("bc1"):
        payload_type = "bitcoin_address"
        risk_score += 55
        threat_indicators.append(f"QR code embeds Bitcoin cryptocurrency wallet address: {payload}")

    elif re.match(r'^0x[a-fA-F0-9]{40}$', payload):
        payload_type = "ethereum_address"
        risk_score += 55
        threat_indicators.append(f"QR code embeds Ethereum cryptocurrency wallet address: {payload}")

    # General QR Code Evasion flag
    threat_indicators.append("Image-based QR code detected (often leveraged to bypass text-based security filters)")

    # Normalize risk level
    risk_score = min(100, max(0, risk_score))
    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 55:
        risk_level = "high"
    elif risk_score >= 35:
        risk_level = "medium"
    elif risk_score >= 15:
        risk_level = "low"
    else:
        risk_level = "clean"

    return {
        "filename": filename,
        "source": source,
        "decoded_payload": payload,
        "payload_type": payload_type,
        "domain": domain,
        "is_shortened": is_shortened,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_indicators": threat_indicators
    }


def scan_email_for_quishing(
    raw_email: str,
    parsed_dict: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    High-level orchestrator: extracts all images, decodes all QR codes,
    and returns a structured Quishing intelligence block.
    """
    images = extract_images_from_email(raw_email, parsed_dict)
    detections: List[Dict[str, Any]] = []
    seen_payloads = set()

    for img in images:
        payloads = decode_qr_codes_from_image(img["data"], img["filename"])
        for p in payloads:
            if p not in seen_payloads:
                seen_payloads.add(p)
                evaluated = evaluate_quishing_payload(p, img["filename"], img["source"])
                detections.append(evaluated)

    has_qr = len(detections) > 0
    max_score = max((d["risk_score"] for d in detections), default=0) if has_qr else 0

    if max_score >= 80:
        overall_level = "critical"
        summary = f"🚨 {len(detections)} High-Risk Quishing QR Code(s) detected pointing to suspicious or lookalike destinations."
    elif max_score >= 50:
        overall_level = "high"
        summary = f"⚠️ {len(detections)} Suspicious QR Code(s) detected in email. Verification required before scanning."
    elif has_qr:
        overall_level = "medium"
        summary = f"📷 {len(detections)} QR Code(s) detected in email. Inspect destination link carefully."
    else:
        overall_level = "clean"
        summary = "No QR codes detected."

    return {
        "has_qr_codes": has_qr,
        "qr_count": len(detections),
        "risk_level": overall_level,
        "risk_score": max_score,
        "summary": summary,
        "images_analyzed": len(images),
        "detections": detections
    }
