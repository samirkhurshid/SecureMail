"""
Purge deleted accounts script.
Executes 7-day account deletion for users whose deletion_scheduled_for <= now.

Run via daily cron job:
python -m app.scripts.purge_deleted_accounts
"""

import os
import sys
import datetime
import json
from typing import List, Dict

# Ensure Backend/ directory is in sys.path when executed directly
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.utils.logger import setup_logger
from app.services import forensics as forensics_service
from app.services.user_service import _get_db, _load_local_users, _save_local_users

logger = setup_logger(__name__)

try:
    from firebase_admin import auth as firebase_auth
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False
    firebase_auth = None


def purge_user_logs(uid: str) -> int:
    """Delete all forensic log files for a user and return the count deleted."""
    log_dir = forensics_service.get_log_dir()
    if not os.path.exists(log_dir):
        return 0

    deleted_count = 0
    for fname in os.listdir(log_dir):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(log_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("user_id") == uid:
                    f.close()
                    os.remove(fpath)
                    deleted_count += 1
        except Exception:
            continue

    # Invalidate forensics service cache
    forensics_service._invalidate_cache()
    return deleted_count


def write_audit_log(line: str):
    """Append audit record to Backend/purge_audit.log."""
    audit_path = os.path.join(backend_dir, "purge_audit.log")
    try:
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        logger.error(f"Failed to write to audit log: {e}")


def main():
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    logger.info(f"Starting purge scan at {now_iso}")

    target_users: Dict[str, Dict] = {}

    # 1. Try fetching from Firestore
    db = _get_db()
    if db:
        try:
            users_ref = db.collection("users")
            for doc in users_ref.stream(timeout=5.0):
                d = doc.to_dict() or {}
                d["_doc_ref"] = doc.reference
                target_users[doc.id] = d
        except Exception as e:
            logger.warning(f"Firestore query failed during purge ({e}); loading local store.")

    # 2. Merge with local JSON user store
    local_users = _load_local_users()
    for uid, d in local_users.items():
        if uid not in target_users:
            target_users[uid] = d

    purged_count = 0
    failed_count = 0

    for uid, data in target_users.items():
        sched_iso = data.get("deletion_scheduled_for")
        if not sched_iso:
            continue

        # Check if scheduled time has passed
        try:
            sched_dt = datetime.datetime.fromisoformat(sched_iso)
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            if sched_dt > now_dt:
                continue
        except Exception:
            continue

        email = data.get("email") or "unknown"
        logger.info(f"Purging expired account: {uid} ({email})")

        try:
            # 1. Delete Firebase Auth User
            if HAS_FIREBASE and firebase_auth:
                try:
                    firebase_auth.delete_user(uid)
                    logger.info(f"Deleted Firebase Auth account for {uid}")
                except Exception as fae:
                    logger.warning(f"Firebase Auth deletion note for {uid}: {fae}")

            # 2. Delete forensic logs
            deleted_logs = purge_user_logs(uid)

            # 3. Delete Firestore user document if present
            doc_ref = data.get("_doc_ref")
            if doc_ref:
                try:
                    doc_ref.delete(timeout=5.0)
                except Exception:
                    pass

            # 4. Delete local user document if present
            local_users = _load_local_users()
            if uid in local_users:
                del local_users[uid]
                _save_local_users(local_users)

            # 5. Audit Log
            audit_entry = f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} | SUCCESS | uid={uid} | email={email} | logs_purged={deleted_logs}"
            write_audit_log(audit_entry)
            purged_count += 1

        except Exception as e:
            failed_count += 1
            audit_entry = f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} | PURGE FAILED | uid={uid} | email={email} | error={e}"
            logger.error(audit_entry)
            write_audit_log(audit_entry)

    logger.info(f"Purge complete: {purged_count} accounts purged, {failed_count} failures.")


if __name__ == "__main__":
    main()
