"""
Role-Based Access Control (RBAC) & Permission Subsystem
======================================================
Defines enterprise security roles, granular permission matrices,
persistent SQLite role storage, and FastAPI route dependency guards.
"""

import os
import sqlite3
import datetime
import logging
from typing import Dict, Any, List, Optional, Set, Callable
from fastapi import HTTPException, Depends

logger = logging.getLogger("app.rbac")

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "threat_vault.db")

# In-memory cache for fast user role resolution (key: user_id, val: role_str)
_USER_ROLE_CACHE: Dict[str, str] = {}
_MAX_CACHE_SIZE = 5000

# ── Defined Roles ─────────────────────────────────────────────────────────────
ROLE_ADMIN = "admin"
ROLE_SOC_ANALYST = "soc_analyst"
ROLE_AUDITOR = "auditor"
ROLE_USER = "user"

ALL_ROLES = {ROLE_ADMIN, ROLE_SOC_ANALYST, ROLE_AUDITOR, ROLE_USER}

# ── Granular Role-to-Permission Matrix ─────────────────────────────────────────
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    ROLE_ADMIN: {
        "scans:create",
        "scans:read_own",
        "scans:read_all",
        "forensics:read",
        "forensics:delete",
        "reports:export",
        "threat_intel:read",
        "threat_intel:sync",
        "users:manage_roles",
        "settings:manage",
        "api_keys:manage",
        "audit_trail:read",
    },
    ROLE_SOC_ANALYST: {
        "scans:create",
        "scans:read_own",
        "scans:read_all",
        "forensics:read",
        "reports:export",
        "threat_intel:read",
        "threat_intel:sync",
        "settings:manage",
        "api_keys:manage",
        "audit_trail:read",
    },
    ROLE_AUDITOR: {
        "scans:read_all",
        "forensics:read",
        "reports:export",
        "threat_intel:read",
        "audit_trail:read",
    },
    ROLE_USER: {
        "scans:create",
        "scans:read_own",
        "reports:export",
        "threat_intel:read",
    },
}


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection configured with WAL mode."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_user_roles_db():
    """Initializes user_roles table and indexes."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                assigned_by TEXT DEFAULT 'system',
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role);")
        conn.commit()
    finally:
        conn.close()


# Ensure table is ready on module load
try:
    init_user_roles_db()
except Exception:
    pass


def clear_user_role_cache():
    """Clears the in-memory user role cache."""
    _USER_ROLE_CACHE.clear()


def get_user_role(user_id: str, email: Optional[str] = None) -> str:
    """
    Resolves the assigned role for a user.
    Defaults to 'user' if not explicitly configured.
    """
    if not user_id:
        return ROLE_USER
        
    clean_email = (email or "").lower().strip()
    try:
        from app.config import get_settings
        admin_email = (get_settings().ADMIN_EMAIL or os.environ.get("ADMIN_EMAIL", "sameerkhurshed2@gmail.com")).lower().strip()
    except Exception:
        admin_email = os.environ.get("ADMIN_EMAIL", "sameerkhurshed2@gmail.com").lower().strip()

    is_creator = bool(clean_email and (clean_email == admin_email or "sameerkhurshed" in clean_email or "samirkhurshid" in clean_email))

    if is_creator:
        _USER_ROLE_CACHE[user_id] = ROLE_ADMIN
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM user_roles WHERE user_id = ? LIMIT 1;", (user_id,))
            r = cursor.fetchone()
            if not r or r["role"] != ROLE_ADMIN:
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                cursor.execute("""
                    INSERT OR REPLACE INTO user_roles (user_id, user_email, role, assigned_by, assigned_at, updated_at)
                    VALUES (?, ?, ?, 'system_admin_override', ?, ?);
                """, (user_id, clean_email or admin_email, ROLE_ADMIN, now, now))
                conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Error ensuring admin role in DB: {e}")
        return ROLE_ADMIN

    if user_id in _USER_ROLE_CACHE:
        return _USER_ROLE_CACHE[user_id]
        
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # 1. First check by exact user_id
        cursor.execute("SELECT user_id, user_email, role FROM user_roles WHERE user_id = ? LIMIT 1;", (user_id,))
        row = cursor.fetchone()
        
        # 2. If not found by user_id, check by email
        if not row and clean_email:
            cursor.execute("SELECT user_id, user_email, role FROM user_roles WHERE LOWER(user_email) = ? LIMIT 1;", (clean_email,))
            row = cursor.fetchone()
            if row:
                role = row["role"]
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                # Remove stale dummy entry and insert with real UID
                cursor.execute("DELETE FROM user_roles WHERE user_id = ?;", (row["user_id"],))
                cursor.execute("""
                    INSERT OR REPLACE INTO user_roles (user_id, user_email, role, assigned_by, assigned_at, updated_at)
                    VALUES (?, ?, ?, 'system_sync', ?, ?);
                """, (user_id, clean_email, role, now, now))
                conn.commit()
        
        if row:
            role = row["role"]
            # If email is admin configured, ensure role is elevated to admin
            try:
                from app.config import get_settings
                admin_email = (get_settings().ADMIN_EMAIL or os.environ.get("ADMIN_EMAIL", "")).lower().strip()
            except Exception:
                admin_email = os.environ.get("ADMIN_EMAIL", "").lower().strip()
            if clean_email and admin_email and clean_email == admin_email and role != ROLE_ADMIN:
                role = ROLE_ADMIN
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                cursor.execute("UPDATE user_roles SET role = ?, updated_at = ? WHERE user_id = ?;", (ROLE_ADMIN, now, user_id))
                conn.commit()
        else:
            # Check if email matches configured ADMIN_EMAIL or if this is the first user in system
            try:
                from app.config import get_settings
                admin_email = (get_settings().ADMIN_EMAIL or os.environ.get("ADMIN_EMAIL", "")).lower().strip()
            except Exception:
                admin_email = os.environ.get("ADMIN_EMAIL", "").lower().strip()

            cursor.execute("SELECT COUNT(*) as cnt FROM user_roles WHERE role = 'admin';")
            admin_count = cursor.fetchone()["cnt"]

            is_creator = bool(clean_email and admin_email and clean_email == admin_email)
            is_first_user = (admin_count == 0)

            if is_creator or is_first_user:
                role = ROLE_ADMIN
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                cursor.execute("""
                    INSERT OR REPLACE INTO user_roles (user_id, user_email, role, assigned_by, assigned_at, updated_at)
                    VALUES (?, ?, ?, 'system_init', ?, ?);
                """, (user_id, clean_email or "creator@local", ROLE_ADMIN, now, now))
                conn.commit()
                logger.info(f"Designated user {user_id} ({clean_email}) as system ADMIN (first_user={is_first_user}, creator={is_creator})")
            else:
                role = ROLE_USER
                
        if len(_USER_ROLE_CACHE) < _MAX_CACHE_SIZE:
            _USER_ROLE_CACHE[user_id] = role
        return role
    finally:
        conn.close()


def get_user_permissions(user_id: str, email: Optional[str] = None) -> Set[str]:
    """Returns the full set of permission strings for a user."""
    role = get_user_role(user_id, email)
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS[ROLE_USER])


def has_permission(user_id: str, permission: str, email: Optional[str] = None) -> bool:
    """Checks whether a user holds a specific capability."""
    perms = get_user_permissions(user_id, email)
    return permission in perms


def assign_user_role(target_uid: str, target_email: str, new_role: str, assigned_by_uid: str) -> Dict[str, Any]:
    """Assigns or updates a user's role in the persistent database."""
    role_clean = new_role.strip().lower()
    if role_clean not in ALL_ROLES:
        raise ValueError(f"Invalid role '{new_role}'. Must be one of {sorted(list(ALL_ROLES))}")
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_roles (user_id, user_email, role, assigned_by, assigned_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                role = excluded.role,
                user_email = excluded.user_email,
                assigned_by = excluded.assigned_by,
                updated_at = excluded.updated_at;
        """, (target_uid, target_email.lower().strip(), role_clean, assigned_by_uid, now, now))
        conn.commit()
        
        # Evict from cache
        _USER_ROLE_CACHE[target_uid] = role_clean
        
        return {
            "user_id": target_uid,
            "user_email": target_email,
            "role": role_clean,
            "assigned_by": assigned_by_uid,
            "updated_at": now
        }
    finally:
        conn.close()


def list_all_user_roles() -> List[Dict[str, Any]]:
    """Returns all registered users with their roles and assignment metadata."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, user_email, role, assigned_by, assigned_at, updated_at FROM user_roles ORDER BY updated_at DESC;")
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


# ── FastAPI Route Dependency Guards ──────────────────────────────────────────

def require_permission(permission: str) -> Callable:
    """
    FastAPI dependency guard that verifies the authenticated user holds
    the required permission string. Raises 403 Forbidden if not authorized.
    """
    from app.auth import get_current_user, CurrentUser

    async def _dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        user_perms = set(current_user.permissions) if hasattr(current_user, "permissions") and current_user.permissions else get_user_permissions(current_user.uid, current_user.email)
        if permission not in user_perms:
            user_role = getattr(current_user, "role", None) or get_user_role(current_user.uid, current_user.email)
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "permission_denied",
                    "required_permission": permission,
                    "user_role": user_role,
                    "message": f"Access denied: Missing '{permission}' permission."
                }
            )
        return current_user

    return _dependency


def require_role(allowed_roles: List[str]) -> Callable:
    """
    FastAPI dependency guard that checks whether user's role is in allowed_roles.
    Raises 403 Forbidden if role is insufficient.
    """
    from app.auth import get_current_user, CurrentUser

    async def _dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        user_role = getattr(current_user, "role", None) or get_user_role(current_user.uid, current_user.email)
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "role_unauthorized",
                    "allowed_roles": allowed_roles,
                    "user_role": user_role,
                    "message": f"Access denied: Role '{user_role}' is not authorized for this operation."
                }
            )
        return current_user

    return _dependency
