"""
AI threat explainer router.
POST /api/ai/explain  — Stream a Claude AI explanation of a scan result

Keys stay 100% server-side. The frontend never touches Anthropic directly.
"""

import json
import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, model_validator
from typing import Optional, List, Dict, Any
from app.config import get_settings
from app.utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()


class ExplainRequest(BaseModel):
    risk_score: int = 0
    risk_level: str = "unknown"
    threat_types: List[str] = []
    summary: str = ""
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    phishing: dict = {}
    authentication: dict = {}
    header_analysis: dict = {}
    urls: List[dict] = []
    attachments: List[dict] = []
    quishing: Optional[dict] = None

    @model_validator(mode='before')
    @classmethod
    def unpack_nested_scan_result(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # If payload is wrapped inside {"scan_result": {...}}
            if "scan_result" in data and isinstance(data["scan_result"], dict):
                merged = {**data["scan_result"]}
                return merged
        return data


def _build_prompt(d: ExplainRequest) -> str:
    """Build a rich, data-specific prompt from scan result."""
    ph   = d.phishing or {}
    auth = d.authentication or {}
    h    = d.header_analysis or {}
    ip   = h.get("ip_reputation", {}) or {}
    q    = d.quishing or {}

    signals = []
    if q.get("has_qr_codes"):
        qr_count = q.get("qr_count", len(q.get("detections", [])))
        signals.append(f"Quishing attack with {qr_count} embedded QR code(s) detected bypassing text-based filters")
        for det in q.get("detections", [])[:2]:
            if det.get("decoded_payload"):
                signals.append(f"QR payload: {det['decoded_payload']}")
            if det.get("threat_indicators"):
                signals.extend(det["threat_indicators"])
    if ph.get("extortion"):              signals.append("extortion/sextortion content")
    if ph.get("bitcoin_demand"):         signals.append("Bitcoin payment demand")
    if ph.get("webcam_threat"):          signals.append("webcam/spyware blackmail threat")
    if ph.get("domain_impersonation"):   signals.append(f"sender domain impersonates {ph.get('impersonated_brand','a known brand')}")
    if ph.get("credential_request"):     signals.append("credential/identity verification request")
    if ph.get("urgency_language"):       signals.append("urgency pressure tactics")
    if ph.get("domain_lookalike"):       signals.append("brand lookalike domain detected")
    if ph.get("display_name_spoof"):     signals.append("display name spoofing")
    if ph.get("reply_to_mismatch"):      signals.append("Reply-To domain mismatch")
    if auth.get("spf")   == "fail":      signals.append("SPF authentication failed")
    if auth.get("dkim")  == "fail":      signals.append("DKIM signature invalid")
    if auth.get("dmarc") == "fail":      signals.append("DMARC policy failed")
    if all(auth.get(k) in ("unknown","none","") for k in ("spf","dkim","dmarc")):
        signals.append("all authentication headers absent — likely spoofed")

    mal_urls = [u["url"] for u in d.urls if (u.get("vt_result") or {}).get("detections", 0) > 0]
    mal_atts = [a["filename"] for a in d.attachments if (a.get("vt_result") or {}).get("detections", 0) > 0]
    if mal_urls: signals.append(f"malicious URLs: {', '.join(mal_urls[:2])}")
    if mal_atts: signals.append(f"malicious attachments: {', '.join(mal_atts[:2])}")

    kw_hits = ph.get("keyword_hits", {})
    top_kws = sorted(kw_hits.items(), key=lambda x: x[1], reverse=True)[:4]

    prompt = f"""You are a cybersecurity analyst writing for a non-technical audience.

Analyse this email threat scan and write a clear, specific explanation.

SCAN DATA:
- Risk score: {d.risk_score}/100 ({d.risk_level.upper()} risk)
- Sender: {d.sender_email or 'unknown'}
- Subject: {d.subject or 'unknown'}
- Threat types: {', '.join(d.threat_types) if d.threat_types else 'none'}
- Signals detected: {'; '.join(signals) if signals else 'none'}
- Summary: {d.summary}
{f"- Originating country: {ip.get('country_code')}" if ip.get('country_code') else ""}
{f"- IP abuse score: {ip.get('abuse_confidence_score')}%" if ip.get('abuse_confidence_score') else ""}
{f"- Top phishing keywords: {', '.join(k for k,_ in top_kws)}" if top_kws else ""}

Write exactly four sections using this format. Be specific — reference the actual sender, subject, and signals above. Never be generic.

**What is this attack?**
One paragraph explaining the attack type and what the attacker is trying to achieve with THIS specific email.

**Why is it dangerous?**
One paragraph explaining the specific risks if the recipient interacts with this email.

**How was it detected?**
One paragraph explaining which signals flagged it as malicious — reference the actual data above.

**What should you do?**
3-4 bullet points starting with - giving specific actions the recipient should take right now.

Keep each section to 2-4 sentences or bullets. Use plain English. Be direct."""

    return prompt


@router.post("/explain", summary="Stream an AI explanation of a scan result")
async def explain_threat(request: ExplainRequest):
    """
    Proxies to Google Gemini API (preferred free tier) or Anthropic Claude API with streaming.
    All keys stay 100% server-side.
    """
    s = get_settings()

    if not s.GEMINI_API_KEY and not s.ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="AI explanation unavailable — GEMINI_API_KEY or ANTHROPIC_API_KEY not configured on server"
        )

    if s.GEMINI_API_KEY and not (s.GEMINI_API_KEY.startswith("AIzaSy") or s.GEMINI_API_KEY.startswith("AQ.")):
        raise HTTPException(
            status_code=503,
            detail="GEMINI_API_KEY is set but invalid (must start with 'AIzaSy' or 'AQ.'). "
                   "Get a real key at https://aistudio.google.com/app/apikey"
        )

    if s.ANTHROPIC_API_KEY and not s.GEMINI_API_KEY and not s.ANTHROPIC_API_KEY.startswith("sk-ant-"):
        raise HTTPException(
            status_code=503,
            detail="ANTHROPIC_API_KEY is set but invalid (must start with 'sk-ant-'). "
                   "Get a real key at https://console.anthropic.com/settings/keys"
        )

    if request.risk_level == "clean" or request.risk_score == 0:
        raise HTTPException(status_code=400, detail="AI explanation only available for detected threats")

    prompt = _build_prompt(request)

    async def stream_gemini():
        """Stream SSE events from Gemini, translate them to Anthropic structure, and forward."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key={s.GEMINI_API_KEY}"
        payload = {
            "contents": [{
                "role": "user",
                "parts": [{"text": prompt}]
            }]
        }
        headers = {"Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                async with client.stream("POST", url, json=payload, headers=headers) as resp:
                    if resp.status_code == 400:
                        yield f"data: {json.dumps({'error': 'invalid_request'})}\n\n"
                        return
                    if resp.status_code in (401, 403):
                        yield f"data: {json.dumps({'error': 'invalid_api_key'})}\n\n"
                        return
                    if resp.status_code == 429:
                        yield f"data: {json.dumps({'error': 'rate_limited'})}\n\n"
                        return
                    if resp.status_code != 200:
                        yield f"data: {json.dumps({'error': f'http_{resp.status_code}'})}\n\n"
                        return

                    async for line in resp.aiter_lines():
                        if line.startswith("data: "):
                            raw_data = line[6:].strip()
                            try:
                                chunk_data = json.loads(raw_data)
                                text = chunk_data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                                if text:
                                    # Translate to Anthropic content delta event
                                    yield f"data: {json.dumps({'type': 'content_block_delta', 'delta': {'type': 'text_delta', 'text': text}})}\n\n"
                            except Exception as pe:
                                logger.error(f"Gemini parse chunk error: {pe} for line: {line}")
                        elif line == "":
                            continue
        except httpx.ConnectError:
            yield f"data: {json.dumps({'error': 'unreachable'})}\n\n"
        except Exception as e:
            logger.error(f"Gemini explain stream error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    async def stream_claude():
        """Stream SSE events from Anthropic and forward them to the browser."""
        payload = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1000,
            "stream": True,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": s.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                async with client.stream(
                    "POST",
                    "https://api.anthropic.com/v1/messages",
                    json=payload,
                    headers=headers,
                ) as resp:
                    if resp.status_code == 401:
                        yield f"data: {json.dumps({'error': 'invalid_api_key'})}\n\n"
                        return
                    if resp.status_code == 429:
                        yield f"data: {json.dumps({'error': 'rate_limited'})}\n\n"
                        return
                    if resp.status_code != 200:
                        yield f"data: {json.dumps({'error': f'http_{resp.status_code}'})}\n\n"
                        return

                    async for line in resp.aiter_lines():
                        if line.startswith("data: "):
                            yield f"{line}\n\n"
                        elif line == "":
                            continue
        except httpx.ConnectError:
            yield f"data: {json.dumps({'error': 'unreachable'})}\n\n"
        except Exception as e:
            logger.error(f"AI explain stream error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    if s.GEMINI_API_KEY:
        return StreamingResponse(
            stream_gemini(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )
    else:
        return StreamingResponse(
            stream_claude(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )


@router.get("/status", summary="Check if AI explanation is available")
async def ai_status():
    """
    Returns whether AI explanation is configured — without revealing the key.
    Also validates key FORMAT (not just presence) to catch copy-paste mistakes
    like pasting an OAuth token instead of an API key.
    """
    s = get_settings()

    if s.GEMINI_API_KEY:
        if not (s.GEMINI_API_KEY.startswith("AIzaSy") or s.GEMINI_API_KEY.startswith("AQ.")):
            return {
                "available": False,
                "model": None,
                "message": (
                    "GEMINI_API_KEY is set but doesn't look like a valid key "
                    "(should start with 'AIzaSy' or 'AQ.'). Get one at "
                    "https://aistudio.google.com/app/apikey"
                ),
            }
        return {
            "available": True,
            "model": "gemini-2.5-flash",
            "message": "AI explanation ready (using Google Gemini)",
        }

    elif s.ANTHROPIC_API_KEY:
        if not s.ANTHROPIC_API_KEY.startswith("sk-ant-"):
            return {
                "available": False,
                "model": None,
                "message": (
                    "ANTHROPIC_API_KEY is set but doesn't look like a valid key "
                    "(should start with 'sk-ant-'). Get one at "
                    "https://console.anthropic.com/settings/keys"
                ),
            }
        return {
            "available": True,
            "model": "claude-3-5-sonnet-20241022",
            "message": "AI explanation ready (using Anthropic Claude)",
        }

    else:
        return {
            "available": False,
            "model": None,
            "message": "GEMINI_API_KEY or ANTHROPIC_API_KEY not set in .env",
        }
