"""
User account service — Firestore user documents, deletion scheduling, and pending-deletion checks.
Includes automatic local file fallback if Firestore API is disabled or unavailable.
"""

import os
import json
import time
import datetime
from typing import Dict, Tuple, Optional
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

try:
    import firebase_admin
    from firebase_admin import firestore
    HAS_FIRESTORE = True
except ImportError:
    HAS_FIRESTORE = False
    firestore = None

# Fallback local store path: Backend/user_records.json
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_LOCAL_USERS_FILE = os.path.join(_BACKEND_DIR, "user_records.json")

# In-memory cache for pending deletion checks: { uid: (is_pending: bool, timestamp: float) }
_PENDING_CACHE: Dict[str, Tuple[bool, float]] = {}
_CACHE_TTL_SECONDS = 60.0


def _load_local_users() -> Dict[str, Dict]:
    if not os.path.exists(_LOCAL_USERS_FILE):
        return {}
    try:
        with open(_LOCAL_USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading local user records: {e}")
        return {}


def _save_local_users(data: Dict[str, Dict]):
    try:
        with open(_LOCAL_USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving local user records: {e}")


def _get_db():
    if not HAS_FIRESTORE:
        return None
    try:
        return firestore.client()
    except Exception as e:
        logger.warning(f"Firestore client init fallback: {e}")
        return None


def get_or_create_user_doc(uid: str, email: Optional[str] = None, name: Optional[str] = None) -> Dict:
    """Ensure user document exists in Firestore or local fallback store."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    db = _get_db()

    if db:
        try:
            doc_ref = db.collection("users").document(uid)
            doc = doc_ref.get(timeout=5.0)
            if doc.exists:
                data = doc.to_dict() or {}
                updates = {}
                if email and data.get("email") != email:
                    updates["email"] = email
                if name and data.get("name") != name:
                    updates["name"] = name
                if updates:
                    doc_ref.update(updates, timeout=5.0)
                    data.update(updates)
                return data
            else:
                new_data = {
                    "uid": uid,
                    "email": email or "",
                    "name": name or "",
                    "created_at": now_iso,
                    "deletion_requested_at": None,
                    "deletion_scheduled_for": None,
                }
                doc_ref.set(new_data, timeout=5.0)
                return new_data
        except Exception as e:
            logger.warning(f"Firestore get_or_create_user_doc failed ({e}); using local fallback.")

    # Local fallback
    local_store = _load_local_users()
    if uid in local_store:
        user_data = local_store[uid]
        if email and user_data.get("email") != email:
            user_data["email"] = email
        if name and user_data.get("name") != name:
            user_data["name"] = name
        _save_local_users(local_store)
        return user_data
    else:
        new_data = {
            "uid": uid,
            "email": email or "",
            "name": name or "",
            "created_at": now_iso,
            "deletion_requested_at": None,
            "deletion_scheduled_for": None,
        }
        local_store[uid] = new_data
        _save_local_users(local_store)
        return new_data


def schedule_account_deletion(uid: str) -> Dict:
    """
    Mark a user account for deletion in 7 days.
    Sets deletion_requested_at = now, deletion_scheduled_for = now + 7 days.
    """
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    purge_dt = now_dt + datetime.timedelta(days=7)

    now_iso = now_dt.isoformat()
    purge_iso = purge_dt.isoformat()

    db = _get_db()
    if db:
        try:
            doc_ref = db.collection("users").document(uid)
            doc_ref.set({
                "deletion_requested_at": now_iso,
                "deletion_scheduled_for": purge_iso,
            }, merge=True, timeout=5.0)
        except Exception as e:
            logger.warning(f"Firestore schedule_account_deletion failed ({e}); using local fallback.")

    # Always update local fallback
    local_store = _load_local_users()
    user_data = local_store.get(uid, {"uid": uid, "created_at": now_iso})
    user_data["deletion_requested_at"] = now_iso
    user_data["deletion_scheduled_for"] = purge_iso
    local_store[uid] = user_data
    _save_local_users(local_store)

    # Invalidate / set cache
    _PENDING_CACHE[uid] = (True, time.time())
    logger.info(f"Scheduled 7-day account deletion for user {uid} (purge at {purge_iso})")
    return {
        "status": "scheduled",
        "deletion_requested_at": now_iso,
        "deletion_scheduled_for": purge_iso,
    }


def is_account_pending_deletion(uid: str) -> bool:
    """
    Check if a user account is pending deletion.
    Uses an in-memory 60-second TTL cache to prevent high-frequency DB/file calls.
    """
    now = time.time()
    cached = _PENDING_CACHE.get(uid)
    if cached and (now - cached[1]) < _CACHE_TTL_SECONDS:
        return cached[0]

    db = _get_db()
    if db:
        try:
            doc = db.collection("users").document(uid).get(timeout=5.0)
            if doc.exists:
                data = doc.to_dict() or {}
                is_pending = bool(data.get("deletion_requested_at"))
                _PENDING_CACHE[uid] = (is_pending, now)
                return is_pending
        except Exception as e:
            logger.warning(f"Firestore is_account_pending_deletion failed ({e}); using local fallback.")

    # Local fallback check
    local_store = _load_local_users()
    user_data = local_store.get(uid, {})
    is_pending = bool(user_data.get("deletion_requested_at"))
    _PENDING_CACHE[uid] = (is_pending, now)
    return is_pending


def record_user_login_event(uid: str, ip: str, user_agent: str) -> Dict:
    """
    Encrypt client IP and user agent, then persist login event to Firestore
    (users/{uid}/login_events/{auto-id}) or local JSON fallback store.
    """
    from app.services.encryption import encrypt_field

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    ip_enc = encrypt_field(ip)
    ua_enc = encrypt_field(user_agent)

    event_data = {
        "timestamp": now_iso,
        "ip_encrypted": ip_enc,
        "user_agent_encrypted": ua_enc,
    }

    db = _get_db()
    if db:
        try:
            user_ref = db.collection("users").document(uid)
            user_ref.collection("login_events").add(event_data, timeout=5.0)
            logger.info(f"Recorded login event for user {uid} in Firestore")
            return event_data
        except Exception as e:
            logger.warning(f"Firestore record_user_login_event failed ({e}); using local fallback.")

    # Local fallback
    local_store = _load_local_users()
    user_data = local_store.get(uid, {"uid": uid, "created_at": now_iso})
    login_events = user_data.get("login_events", [])
    login_events.append(event_data)
    user_data["login_events"] = login_events
    local_store[uid] = user_data
    _save_local_users(local_store)
    logger.info(f"Recorded login event for user {uid} in local fallback store")
    return event_data


def update_user_preferences(
    uid: str,
    digest_enabled: Optional[bool] = None,
    webhook_url: Optional[str] = None,
) -> Dict:
    """
    Update user preferences (digest_enabled, webhook_url) in Firestore or local fallback store.
    """
    updates = {}
    if digest_enabled is not None:
        updates["digest_enabled"] = digest_enabled
    if webhook_url is not None:
        updates["webhook_url"] = webhook_url if webhook_url.strip() else None

    if not updates:
        return get_or_create_user_doc(uid)

    db = _get_db()
    if db:
        try:
            doc_ref = db.collection("users").document(uid)
            doc_ref.update(updates, timeout=5.0)
            doc = doc_ref.get(timeout=5.0)
            if doc.exists:
                return doc.to_dict()
        except Exception as e:
            logger.warning(f"Firestore update_user_preferences failed ({e}); updating local fallback store.")

    # Local fallback
    local_store = _load_local_users()
    user_data = local_store.get(uid, {"uid": uid})
    user_data.update(updates)
    local_store[uid] = user_data
    _save_local_users(local_store)
    return user_data


