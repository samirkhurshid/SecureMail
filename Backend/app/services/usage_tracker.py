"""
Per-user scan usage tracking module.
Persists daily scan counters in SQLite (Backend/usage_tracking.db) using IST (UTC+5:30) date buckets.
"""

import os
import sqlite3
import datetime
from typing import Dict
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DB_PATH = os.path.join(_BACKEND_DIR, "usage_tracking.db")


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, timeout=10.0)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS daily_usage (
            bucket_date TEXT,
            uid TEXT,
            scan_count INTEGER,
            PRIMARY KEY (bucket_date, uid)
        )
    """)
    conn.commit()
    return conn


def _get_ist_date_str() -> str:
    """Return current IST (UTC+5:30) wall-clock date string (YYYY-MM-DD)."""
    ist_now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=5, minutes=30)
    return ist_now.strftime("%Y-%m-%d")


def record_scan_usage(user_id: str):
    """
    Increment scan usage count for user_id for today's IST calendar date.
    Fire-and-forget background helper.
    """
    if not user_id:
        return

    today_str = _get_ist_date_str()
    try:
        with _get_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO daily_usage (bucket_date, uid, scan_count) VALUES (?, ?, 0)",
                (today_str, user_id)
            )
            conn.execute(
                "UPDATE daily_usage SET scan_count = scan_count + 1 WHERE bucket_date = ? AND uid = ?",
                (today_str, user_id)
            )
            conn.commit()
            logger.debug(f"Recorded scan usage for user {user_id} on {today_str}")
    except Exception as e:
        logger.error(f"Failed to record scan usage for user {user_id}: {e}")


def get_usage_stats(user_id: str, days: int = 30) -> Dict[str, int]:
    """
    Return scan counts for user_id for the last `days` days as { 'YYYY-MM-DD': count }.
    """
    if not user_id:
        return {}

    today_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=5, minutes=30)
    cutoff_dt = today_dt - datetime.timedelta(days=days)
    cutoff_str = cutoff_dt.strftime("%Y-%m-%d")

    results = {}
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT bucket_date, scan_count FROM daily_usage WHERE uid = ? AND bucket_date >= ? ORDER BY bucket_date DESC",
                (user_id, cutoff_str)
            )
            for row in cursor.fetchall():
                results[row[0]] = row[1]
    except Exception as e:
        logger.error(f"Failed to fetch usage stats for user {user_id}: {e}")

    return results
