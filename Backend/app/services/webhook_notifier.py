"""
Slack / Generic Webhook threat notifier.
Dispatches non-blocking alerts when high or critical threats are detected.
"""

import httpx
from typing import Dict, Any
from app.utils.logger import setup_logger

logger = setup_logger(__name__)


def notify_webhook(webhook_url: str, scan_result: Dict[str, Any]):
    """
    Send Slack-compatible JSON POST alert to webhook_url for high/critical threat scan.
    Runs asynchronously/in background tasks. Catches and logs all errors cleanly.
    """
    if not webhook_url or not webhook_url.strip().startswith("https://"):
        logger.warning(f"Invalid or missing webhook URL: {webhook_url}")
        return

    risk_level = (scan_result.get("risk_level") or "UNKNOWN").upper()
    score = scan_result.get("risk_score") or 0
    sender = scan_result.get("sender_email") or "(Unknown sender)"
    subject = scan_result.get("subject") or "(No subject)"
    summary = scan_result.get("summary") or "Threat detected during scan."

    message_text = (
        f"🚨 *SecureMail Threat Alert* 🚨\n"
        f"*Risk Level:* {risk_level} ({score}/100)\n"
        f"*Subject:* {subject}\n"
        f"*Sender:* {sender}\n"
        f"*Summary:* {summary}"
    )

    payload = {
        "text": message_text,
        "scan_id": scan_result.get("scan_id"),
        "risk_level": risk_level.lower(),
        "risk_score": score,
        "sender": sender,
        "subject": subject,
        "summary": summary,
    }

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(webhook_url.strip(), json=payload)
            if resp.status_code in (200, 201, 204):
                logger.info(f"Webhook notification delivered to {webhook_url[:30]}...")
            else:
                logger.error(f"Webhook delivery failed [{resp.status_code}] for {webhook_url[:30]}: {resp.text[:100]}")
    except Exception as e:
        logger.error(f"Error dispatching webhook notification to {webhook_url[:30]}: {e}")
