"""
AI threat explainer router.
POST /api/ai/explain  — Stream a Claude AI explanation of a scan result

Keys stay 100% server-side. The frontend never touches Anthropic directly.
"""

import json
import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
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


def _build_prompt(d: ExplainRequest) -> str:
    """Build a rich, data-specific prompt from scan result."""
    ph   = d.phishing
    auth = d.authentication
    h    = d.header_analysis
    ip   = h.get("ip_reputation", {}) or {}

    signals = []
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
    Proxies to Anthropic Claude API with streaming.
    The Anthropic API key NEVER leaves the server — frontend only calls this endpoint.
    """
    s = get_settings()

    if not s.ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="AI explanation unavailable — ANTHROPIC_API_KEY not configured on server"
        )

    if request.risk_level == "clean" or request.risk_score == 0:
        raise HTTPException(status_code=400, detail="AI explanation only available for detected threats")

    prompt = _build_prompt(request)

    async def stream_claude():
        """Stream SSE events from Anthropic and forward them to the browser."""
        payload = {
            "model": "claude-sonnet-4-6",
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

    return StreamingResponse(
        stream_claude(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/status", summary="Check if AI explanation is available")
async def ai_status():
    """Returns whether AI explanation is configured — without revealing the key."""
    s = get_settings()
    configured = bool(s.ANTHROPIC_API_KEY)
    return {
        "available": configured,
        "model": "claude-sonnet-4-6" if configured else None,
        "message": "AI explanation ready" if configured else "ANTHROPIC_API_KEY not set in .env",
    }
