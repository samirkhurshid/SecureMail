"""
Forensics service — save, retrieve, delete, and export scan logs.
"""

import os
import json
import uuid
import time
from typing import Dict, List, Optional

_CACHE: Optional[List[Dict]] = None
_CACHE_TIME: float = 0
_CACHE_TTL: float = 5.0  # seconds


def get_log_dir() -> str:
    log_dir = os.path.join(os.path.dirname(__file__), "../../../forensics_logs")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.abspath(log_dir)


def _invalidate_cache() -> None:
    global _CACHE
    _CACHE = None


def save_forensic_log(result: dict) -> str:
    """Persist a scan result as a JSON log file. Returns the log_id."""
    log_id = result.get("scan_id") or str(uuid.uuid4())
    log_dir = get_log_dir()
    path = os.path.join(log_dir, f"{log_id}.json")

    # Normalise sender field — always store as sender_email
    if "sender" in result and "sender_email" not in result:
        result["sender_email"] = result["sender"]

    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    _invalidate_cache()
    return log_id


def get_all_logs() -> List[Dict]:
    """Return all logs sorted newest-first with caching."""
    global _CACHE, _CACHE_TIME
    now = time.time()
    if _CACHE is not None and (now - _CACHE_TIME) < _CACHE_TTL:
        return _CACHE

    log_dir = get_log_dir()
    logs = []
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
                logs.append(data)
        except (json.JSONDecodeError, OSError):
            continue

    logs.sort(key=lambda x: x.get("scanned_at", ""), reverse=True)
    _CACHE = logs
    _CACHE_TIME = now
    return logs


def get_log_by_id(log_id: str) -> Optional[Dict]:
    log_dir = get_log_dir()
    path = os.path.join(log_dir, f"{log_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        if "log_id" not in data:
            data["log_id"] = log_id
        if "sender_email" not in data:
            data["sender_email"] = data.get("sender", "")
        return data


def delete_log_by_id(log_id: str) -> bool:
    log_dir = get_log_dir()
    path = os.path.join(log_dir, f"{log_id}.json")
    if not os.path.exists(path):
        return False
    os.remove(path)
    _invalidate_cache()
    return True


def get_stats() -> Dict:
    """
    Return aggregate statistics.
    Includes by_risk_level breakdown AND total_attachments + total_urls
    so the dashboard stat cards always have real data.
    """
    logs = get_all_logs()
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
        # Legacy flat fields kept for backward compat
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
