"""
Weekly digest email batch dispatch CLI script.
Queries active users, generates past 7 days threat digests, and emails opted-in users via Resend.

Run manually or via cron:
  python -m app.scripts.send_weekly_digests
"""

import sys
from app.services import user_service
from app.services import digest
from app.services import email_sender
from app.utils.logger import setup_logger

logger = setup_logger(__name__)


def run_weekly_digests() -> dict:
    """
    Execute weekly digest dispatch batch.
    Returns stats dict: { "sent": int, "skipped_no_activity": int, "skipped_opted_out": int, "failed": int }
    """
    logger.info("Starting weekly digest email batch...")
    stats = {"sent": 0, "skipped_no_activity": 0, "skipped_opted_out": 0, "failed": 0}

    # Fetch users from Firestore / local fallback
    local_users = user_service._load_local_users()
    if not local_users:
        logger.info("No user records found to process.")
        return stats

    for uid, user_data in local_users.items():
        try:
            # Skip pending deletion
            if user_data.get("deletion_requested_at"):
                logger.debug(f"Skipping user {uid}: pending account deletion.")
                continue

            # Check opt-out preference (default True if unset)
            if user_data.get("digest_enabled") is False:
                logger.info(f"Skipping user {uid}: opted out of weekly digests.")
                stats["skipped_opted_out"] += 1
                continue

            user_email = user_data.get("email")
            if not user_email:
                logger.warning(f"User {uid} missing email address. Skipping.")
                continue

            # Generate 7-day threat summary
            summary = digest.generate_digest_for_user(uid)
            if not summary:
                logger.info(f"User {user_email} had zero scans in the last 7 days. Skipping email.")
                stats["skipped_no_activity"] += 1
                continue

            # Render HTML and send email
            html_body = digest.render_digest_html(user_email, summary)
            subject = "Your SecureMail Weekly Threat Digest"

            success = email_sender.send_email(user_email, subject, html_body)
            if success:
                stats["sent"] += 1
                logger.info(f"Weekly digest delivered to {user_email}")
            else:
                stats["failed"] += 1
                logger.error(f"Failed to deliver weekly digest to {user_email}")

        except Exception as e:
            stats["failed"] += 1
            logger.error(f"Error processing weekly digest for user {uid}: {e}")

    logger.info(
        f"Weekly digest batch complete. "
        f"Sent: {stats['sent']}, "
        f"Skipped (No Activity): {stats['skipped_no_activity']}, "
        f"Skipped (Opted Out): {stats['skipped_opted_out']}, "
        f"Failed: {stats['failed']}"
    )
    return stats


if __name__ == "__main__":
    results = run_weekly_digests()
    sys.exit(0 if results["failed"] == 0 else 1)
