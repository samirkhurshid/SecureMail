import os
import json
import time
from typing import List, Dict, Optional
from app.config import get_settings
from app.utils.logger import setup_logger

logger = setup_logger(__name__)
settings = get_settings()

# ── Simple in-memory cache for forensic logs ──────────────────────────────
_cache: dict = {"logs": None, "ts": 0.0}
_CACHE_TTL = 30  # seconds: refresh from disk at most every 30s


def _invalidate_cache() -> None:
    _cache["logs"] = None
    _cache["ts"] = 0.0

def get_log_dir() -> str:
    log_dir = settings.FORENSICS_LOG_DIR
    os.makedirs(log_dir, exist_ok=True)
    return log_dir

def save_forensic_log(result: dict) -> str:
    log_id = result.get("scan_id")
    if not log_id:
        import uuid
        log_id = str(uuid.uuid4())
        result["scan_id"] = log_id
    
    log_dir = get_log_dir()
    
    # Clean up old logs if count exceeds FORENSICS_MAX_LOGS
    try:
        files = [os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith('.json')]
        if len(files) >= settings.FORENSICS_MAX_LOGS:
            # Delete oldest
            files.sort(key=os.path.getmtime)
            for f in files[:len(files) - settings.FORENSICS_MAX_LOGS + 1]:
                os.remove(f)
    except Exception as e:
        logger.error(f"Error cleaning old logs: {e}")
        
    filepath = os.path.join(log_dir, f"{log_id}.json")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved forensic log: {filepath}")
        _invalidate_cache()  # Bust cache so next read picks up the new log
    except Exception as e:
        logger.error(f"Failed to save forensic log {log_id}: {e}")
        
    return log_id

def get_all_logs() -> List[Dict]:
    """Return all forensic logs, using an in-memory cache with TTL to avoid
    reading every file from disk on every request."""
    now = time.time()
    if _cache["logs"] is not None and (now - _cache["ts"]) < _CACHE_TTL:
        return _cache["logs"]

    log_dir = get_log_dir()
    logs = []
    if not os.path.exists(log_dir):
        return logs
    for filename in os.listdir(log_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(log_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    logs.append(json.load(f))
            except Exception as e:
                logger.error(f"Failed to read log {filename}: {e}")
    # Sort by scanned_at descending
    logs.sort(key=lambda x: x.get("scanned_at", ""), reverse=True)

    _cache["logs"] = logs
    _cache["ts"] = now
    return logs

def get_log_by_id(log_id: str) -> Optional[Dict]:
    filepath = os.path.join(get_log_dir(), f"{log_id}.json")
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read log {log_id}: {e}")
        return None

def delete_log_by_id(log_id: str) -> bool:
    filepath = os.path.join(get_log_dir(), f"{log_id}.json")
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            _invalidate_cache()  # Bust cache so deleted log disappears immediately
            return True
        except Exception as e:
            logger.error(f"Failed to delete log {log_id}: {e}")
            return False
    return False

def get_stats() -> Dict:
    logs = get_all_logs()
    total = len(logs)
    stats = {
        "total": total,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "clean": 0,
        "threat_types": {}
    }
    for log in logs:
        level = log.get("risk_level", "unknown").lower()
        if level in stats:
            stats[level] += 1
        for threat in log.get("threat_types", []):
            stats["threat_types"][threat] = stats["threat_types"].get(threat, 0) + 1
    return stats
