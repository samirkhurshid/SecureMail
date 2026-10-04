"""
Weekly threat digest generation and HTML email rendering module.
Summarizes scan activity for each active user over the past 7 days.
"""

import datetime
from typing import Optional, Dict, Any
from app.services import forensics
from app.utils.logger import setup_logger

logger = setup_logger(__name__)


def generate_digest_for_user(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Query past 7 days of forensic logs for user_id and return a summary dict.
    Returns None if user had zero scans in the last 7 days.
    """
    if not user_id:
        return None

    all_logs = forensics.get_all_logs(user_id=user_id)
    if not all_logs:
        return None

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    seven_days_ago = now_utc - datetime.timedelta(days=7)

    recent_logs = []
    for log in all_logs:
        scanned_at_str = log.get("scanned_at") or log.get("created_at") or ""
        if scanned_at_str:
            try:
                # Parse ISO timestamp
                clean_ts = scanned_at_str.replace("Z", "+00:00")
                dt = datetime.datetime.fromisoformat(clean_ts)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                if dt >= seven_days_ago:
                    recent_logs.append(log)
            except Exception:
                # If parsing fails, include log conservatively
                recent_logs.append(log)
        else:
            recent_logs.append(log)

    if not recent_logs:
        return None

    total_scans = len(recent_logs)
    risk_breakdown = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    highest_risk_log = None
    highest_score = -1

    for log in recent_logs:
        level = (log.get("risk_level") or "clean").lower()
        if level in risk_breakdown:
            risk_breakdown[level] += 1
        else:
            risk_breakdown["clean"] += 1

        score = log.get("risk_score") or 0
        if score > highest_score:
            highest_score = score
            highest_risk_log = log

    return {
        "user_id": user_id,
        "total_scans": total_scans,
        "risk_breakdown": risk_breakdown,
        "highest_risk_log": highest_risk_log,
        "period_days": 7,
        "generated_at": now_utc.isoformat(),
    }


def render_digest_html(user_email: str, summary: Dict[str, Any]) -> str:
    """
    Build clean, inline-styled HTML email body for weekly threat digest.
    Email-client safe styling matching SecureMail branding.
    """
    total = summary.get("total_scans", 0)
    bd = summary.get("risk_breakdown", {})
    highest = summary.get("highest_risk_log")

    highest_html = ""
    if highest:
        h_score = highest.get("risk_score", 0)
        h_level = (highest.get("risk_level") or "unknown").upper()
        h_subject = highest.get("subject") or "(No subject)"
        h_sender = highest.get("sender_email") or "(Unknown sender)"

        highest_html = f"""
        <div style="background-color: #1e1b4b; border: 1px solid #4338ca; border-radius: 8px; padding: 16px; margin-top: 20px;">
            <div style="color: #a5b4fc; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">Highest Risk Detected</div>
            <div style="color: #ffffff; font-size: 16px; font-weight: 700; margin-top: 6px;">{h_subject}</div>
            <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">From: {h_sender}</div>
            <div style="margin-top: 10px; display: inline-block; background-color: #ef4444; color: #ffffff; font-size: 12px; font-weight: 700; padding: 4px 10px; border-radius: 4px;">
                {h_level} RISK ({h_score}/100)
            </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 24px;">
            <div style="font-size: 20px; font-weight: 800; color: #818cf8;">🛡️ SecureMail Weekly Digest</div>
        </div>

        <p style="font-size: 15px; color: #cbd5e1; line-height: 1.5;">
            Here is your weekly email threat activity summary for <strong>{user_email}</strong> over the past 7 days.
        </p>

        <div style="background-color: #0f172a; border-radius: 8px; padding: 20px; margin-top: 20px; border: 1px solid #334155;">
            <div style="font-size: 13px; color: #94a3b8; font-weight: 600;">TOTAL EMAILS & URLS SCANNED</div>
            <div style="font-size: 32px; font-weight: 800; color: #818cf8; margin-top: 4px;">{total}</div>
        </div>

        <div style="margin-top: 20px;">
            <div style="font-size: 13px; color: #94a3b8; font-weight: 600; margin-bottom: 10px;">THREAT RISK BREAKDOWN</div>
            <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                <tr>
                    <td style="padding: 8px 0; color: #ef4444; font-weight: 600;">Critical & High Risk</td>
                    <td style="padding: 8px 0; text-align: right; font-weight: 700; color: #ffffff;">{bd.get('critical', 0) + bd.get('high', 0)}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #f59e0b; font-weight: 600;">Medium Risk</td>
                    <td style="padding: 8px 0; text-align: right; font-weight: 700; color: #ffffff;">{bd.get('medium', 0)}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #10b981; font-weight: 600;">Clean & Low Risk</td>
                    <td style="padding: 8px 0; text-align: right; font-weight: 700; color: #ffffff;">{bd.get('clean', 0) + bd.get('low', 0)}</td>
                </tr>
            </table>
        </div>

        {highest_html}

        <div style="margin-top: 32px; padding-top: 20px; border-top: 1px solid #334155; text-align: center;">
            <a href="http://localhost:8000" style="display: inline-block; background-color: #4f46e5; color: #ffffff; text-decoration: none; font-weight: 700; font-size: 14px; padding: 12px 24px; border-radius: 6px;">Open SecureMail Dashboard</a>
        </div>
    </div>
</body>
</html>
"""
