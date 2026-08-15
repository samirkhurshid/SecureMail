"""
Forensics service — save, retrieve, delete, and export scan logs.
"""

import os
import json
import uuid
import time
from typing import Dict, List, Optional
from app.config import get_settings

_CACHE: Optional[List[Dict]] = None
_CACHE_TIME: float = 0
_CACHE_TTL: float = 5.0  # seconds


def get_log_dir() -> str:
    """
    Resolve the forensics log directory from settings (FORENSICS_LOG_DIR in .env).
    Always resolved relative to the Backend/ folder (where .env lives), NOT
    relative to the current working directory — so it gives the same path
    no matter where uvicorn was launched from.
    """
    settings = get_settings()
    configured = settings.FORENSICS_LOG_DIR or "./forensics_logs"

    if os.path.isabs(configured):
        log_dir = configured
    else:
        # Backend/ root = 3 levels up from this file (app/services/forensics.py)
        backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        log_dir = os.path.abspath(os.path.join(backend_root, configured))

    os.makedirs(log_dir, exist_ok=True)
    return log_dir


def _invalidate_cache() -> None:
    global _CACHE
    _CACHE = None


def save_forensic_log(result: dict, user_id: Optional[str] = None) -> str:
    """Persist a scan result as a JSON log file. Returns the log_id."""
    log_id = result.get("scan_id") or str(uuid.uuid4())
    log_dir = get_log_dir()
    path = os.path.join(log_dir, f"{log_id}.json")

    # Associate log with the logged-in user
    if user_id and "user_id" not in result:
        result["user_id"] = user_id

    # Normalise sender field — always store as sender_email
    if "sender" in result and "sender_email" not in result:
        result["sender_email"] = result["sender"]

    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    _invalidate_cache()
    return log_id


# NOTE: At higher log volumes (100s+), this should move to a per-user subfolder or SQLite instead of scanning all files.
def get_all_logs(user_id: Optional[str] = None) -> List[Dict]:
    """
    Return logs sorted newest-first with caching and per-user filtering.
    Pre-auth legacy logs (missing user_id) are kept untouched on disk for manual/audit reference,
    but excluded from API responses whenever user_id is specified.
    """
    global _CACHE, _CACHE_TIME
    now = time.time()
    if _CACHE is not None and (now - _CACHE_TIME) < _CACHE_TTL:
        raw_logs = _CACHE
    else:
        log_dir = get_log_dir()
        raw_logs = []
        for fname in os.listdir(log_dir):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(log_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Normalise: ensure log_id and sender_email always present
                    if "log_id" not in data:
                        data["log_id"] = data.get("scan_id", fname.replace(".json", ""))
                    if "sender_email" not in data:
                        data["sender_email"] = data.get("sender", "")
                    raw_logs.append(data)
            except (json.JSONDecodeError, OSError):
                continue

        raw_logs.sort(key=lambda x: x.get("scanned_at", ""), reverse=True)
        _CACHE = raw_logs
        _CACHE_TIME = now

    # Filter logs by user_id if provided
    if user_id:
        return [log for log in raw_logs if log.get("user_id") == user_id]
    return raw_logs


def get_log_by_id(log_id: str, user_id: Optional[str] = None) -> Optional[Dict]:
    """
    Fetch a single log by ID.
    If user_id is provided and the log belongs to a different user (or has no user_id),
    returns None to prevent unauthorized access and trigger a 404 in the API router.
    """
    log_dir = get_log_dir()
    path = os.path.join(log_dir, f"{log_id}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "log_id" not in data:
                data["log_id"] = log_id
            if "sender_email" not in data:
                data["sender_email"] = data.get("sender", "")
            
            # Enforce user ownership check
            if user_id and data.get("user_id") != user_id:
                return None
            return data
    except (json.JSONDecodeError, OSError):
        return None


def delete_log_by_id(log_id: str, user_id: Optional[str] = None) -> bool:
    """
    Delete a log by ID.
    Only deletes if the log's stored user_id matches user_id. Returns False if not found
    or owned by another user so the API router returns 404.
    """
    log_dir = get_log_dir()
    path = os.path.join(log_dir, f"{log_id}.json")
    if not os.path.exists(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if user_id and data.get("user_id") != user_id:
                return False
    except (json.JSONDecodeError, OSError):
        return False

    os.remove(path)
    _invalidate_cache()
    return True


def get_stats(user_id: Optional[str] = None) -> Dict:
    """
    Return aggregate statistics filtered by user_id.
    """
    logs = get_all_logs(user_id=user_id)
    total = len(logs)

    by_risk: Dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0, "unknown": 0
    }
    threat_types: Dict[str, int] = {}
    total_attachments = 0
    total_urls = 0
    total_score = 0

    for log in logs:
        level = log.get("risk_level", "unknown").lower()
        by_risk[level] = by_risk.get(level, 0) + 1

        for threat in log.get("threat_types", []):
            threat_types[threat] = threat_types.get(threat, 0) + 1

        total_attachments += len(log.get("attachments", []))
        total_urls += len(log.get("urls", []))
        total_score += log.get("risk_score", 0)

    return {
        "total": total,
        "by_risk_level": by_risk,
        "critical": by_risk["critical"],
        "high": by_risk["high"],
        "medium": by_risk["medium"],
        "low": by_risk["low"],
        "clean": by_risk["clean"],
        "avg_risk_score": round(total_score / total, 1) if total else 0,
        "total_attachments": total_attachments,
        "total_urls": total_urls,
        "threat_types": threat_types,
    }

