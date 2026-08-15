"""
Anonymous Free Trial Quota Service.
Enforces 5 scans per day per IP address, resetting at 12:00 AM IST (UTC+5:30).
Persists in SQLite (Backend/usage_tracking.db).
"""

import sqlite3
import datetime
from typing import Tuple
from app.services.usage_tracker import _DB_PATH, _get_ist_date_str
from app.utils.logger import setup_logger

logger = setup_logger(__name__)


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, timeout=10.0)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anon_quota (
            bucket_date TEXT,
            ip_address TEXT,
            scan_count INTEGER,
            PRIMARY KEY (bucket_date, ip_address)
        )
    """)
    conn.commit()
    return conn


def get_next_reset_time_ist() -> str:
    """
    Return ISO 8601 string for the next upcoming 12:00 AM IST (UTC+5:30).
    """
    ist_tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    now_ist = datetime.datetime.now(ist_tz)
    tomorrow_ist_date = now_ist.date() + datetime.timedelta(days=1)
    reset_dt = datetime.datetime.combine(tomorrow_ist_date, datetime.time(0, 0, 0), tzinfo=ist_tz)
    return reset_dt.isoformat()


def get_anon_quota(ip_address: str) -> int:
    """
    Return current scan count for ip_address today in IST.
    """
    if not ip_address:
        return 0

    today_str = _get_ist_date_str()
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT scan_count FROM anon_quota WHERE bucket_date = ? AND ip_address = ?",
                (today_str, ip_address)
            )
            row = cursor.fetchone()
            return row[0] if row else 0
    except Exception as e:
        logger.error(f"Error fetching anon quota for IP {ip_address}: {e}")
        return 0


def check_and_increment_anon_quota(ip_address: str) -> Tuple[bool, int]:
    """
    Check if ip_address is allowed an anonymous scan today in IST (limit 5 scans).
    If count < 5, increments count and returns (True, new_count).
    If count >= 5, returns (False, current_count) without incrementing.
    """
    if not ip_address:
        return False, 5

    today_str = _get_ist_date_str()

    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT scan_count FROM anon_quota WHERE bucket_date = ? AND ip_address = ?",
                (today_str, ip_address)
            )
            row = cursor.fetchone()
            current_count = row[0] if row else 0

            if current_count >= 5:
                return False, current_count

            # Increment count
            new_count = current_count + 1
            conn.execute(
                "INSERT OR IGNORE INTO anon_quota (bucket_date, ip_address, scan_count) VALUES (?, ?, 0)",
                (today_str, ip_address)
            )
            conn.execute(
                "UPDATE anon_quota SET scan_count = ? WHERE bucket_date = ? AND ip_address = ?",
                (new_count, today_str, ip_address)
            )
            conn.commit()
            logger.info(f"Anonymous scan quota for IP {ip_address} on {today_str}: {new_count}/5")
            return True, new_count
    except Exception as e:
        logger.error(f"Error in check_and_increment_anon_quota for IP {ip_address}: {e}")
        # In case of DB error, allow request to fail gracefully or proceed
        return True, 1
