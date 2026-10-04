"""
Email sender service using Resend REST API (https://resend.com).
Used for sending automated weekly security digests.
"""

import httpx
from app.config import get_settings
from app.utils.logger import setup_logger

logger = setup_logger(__name__)


def send_email(to: str, subject: str, html_body: str) -> bool:
    """
    Send an email via Resend REST API.
    Returns True if sent successfully, False otherwise.
    Logs errors gracefully without raising exceptions.
    """
    settings = get_settings()
    api_key = settings.RESEND_API_KEY.strip()
    from_email = settings.DIGEST_FROM_EMAIL.strip() or "SecureMail <digest@yourdomain.com>"

    if not api_key:
        logger.warning(f"RESEND_API_KEY not configured. Skipping email dispatch to {to}.")
        return False

    payload = {
        "from": from_email,
        "to": [to],
        "subject": subject,
        "html": html_body,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post("https://api.resend.com/emails", json=payload, headers=headers)
            if resp.status_code in (200, 201, 202):
                logger.info(f"Successfully sent email '{subject}' to {to} via Resend")
                return True
            else:
                logger.error(f"Resend email dispatch to {to} failed [{resp.status_code}]: {resp.text}")
                return False
    except Exception as e:
        logger.error(f"Exception during email dispatch to {to}: {e}")
        return False
