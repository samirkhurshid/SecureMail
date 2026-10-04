"""
Enterprise Organization & Multi-Tenant Sandboxing Service
=========================================================
Manages multi-tenant organization boundaries, team member invites,
role delegation, and tenant-isolated scan aggregation in SQLite WAL database.
"""

import os
import sqlite3
import datetime
import logging
from typing import Dict, Any, List, Optional
from app.services.rbac_service import assign_user_role, ALL_ROLES, ROLE_USER, ROLE_ADMIN, ROLE_SOC_ANALYST, ROLE_AUDITOR
from app.services.forensics import get_all_logs

logger = logging.getLogger("app.organization")

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "threat_vault.db")


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection configured with WAL mode."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_org_db():
    """Initializes organizations and org_members tables with indices."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                org_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                domain TEXT,
                owner_uid TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS org_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT NOT NULL,
                user_id TEXT,
                user_email TEXT NOT NULL,
                display_name TEXT DEFAULT '',
                role TEXT NOT NULL DEFAULT 'user',
                status TEXT NOT NULL DEFAULT 'active',
                invited_by TEXT DEFAULT 'system',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(org_id, user_email),
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_org_members_email ON org_members(user_email);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_id);")
        conn.commit()
    finally:
        conn.close()


# Initialize on import
try:
    init_org_db()
except Exception as _e:
    logger.warning(f"Failed to auto-init org db: {_e}")


def ensure_default_organization(user_email: str, user_uid: str) -> str:
    """
    Ensures a primary organization exists. If user is system admin or no org exists,
    creates the flagship Parul University SOC Sandbox.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        clean_email = user_email.lower().strip()

        # Check if user is already in an organization
        cursor.execute("""
            SELECT o.org_id FROM organizations o
            JOIN org_members m ON o.org_id = m.org_id
            WHERE LOWER(m.user_email) = ?
            LIMIT 1;
        """, (clean_email,))
        row = cursor.fetchone()
        if row:
            return row["org_id"]

        # Check if any organization exists
        cursor.execute("SELECT org_id FROM organizations LIMIT 1;")
        first_org = cursor.fetchone()

        if not first_org:
            # Create flagship enterprise sandbox
            default_org_id = "org_parul_soc"
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute("""
                INSERT OR IGNORE INTO organizations (org_id, name, domain, owner_uid, owner_email, created_at)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (default_org_id, "Parul University SOC", "paruluniversity.ac.in", user_uid, clean_email, now))

            # Add Owner
            cursor.execute("""
                INSERT OR REPLACE INTO org_members (org_id, user_id, user_email, display_name, role, status, invited_by, joined_at)
                VALUES (?, ?, ?, ?, ?, ?, 'system_root', ?);
            """, (default_org_id, user_uid, clean_email, "Samir Khurshid (Lead SecOps)", ROLE_ADMIN, "active", now))

            # Seed realistic initial team members for enterprise demonstration
            seed_members = [
                ("emp_soc_01", "priya.soc@paruluniversity.ac.in", "Priya Sharma", ROLE_SOC_ANALYST, "active"),
                ("emp_aud_02", "rahul.compliance@paruluniversity.ac.in", "Rahul Patel", ROLE_AUDITOR, "active"),
                ("emp_usr_03", "student.research@paruluniversity.ac.in", "Aarav Desai", ROLE_USER, "active"),
                ("emp_usr_04", "faculty.cs@paruluniversity.ac.in", "Dr. Mehta", ROLE_USER, "invited"),
            ]
            for uid, email, name, role, status in seed_members:
                cursor.execute("""
                    INSERT OR IGNORE INTO org_members (org_id, user_id, user_email, display_name, role, status, invited_by, joined_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """, (default_org_id, uid, email, name, role, status, clean_email, now))

            conn.commit()
            logger.info(f"Initialized flagship organization {default_org_id} with owner {clean_email}")
            return default_org_id
        else:
            # Attach user to existing organization
            org_id = first_org["org_id"]
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute("""
                INSERT OR IGNORE INTO org_members (org_id, user_id, user_email, display_name, role, status, invited_by, joined_at)
                VALUES (?, ?, ?, ?, ?, 'active', 'system_auto_join', ?);
            """, (org_id, user_uid, clean_email, clean_email.split('@')[0], ROLE_USER, now))
            conn.commit()
            return org_id
    finally:
        conn.close()


def get_organization_overview(user_email: str, user_uid: str) -> Dict[str, Any]:
    """
    Fetches the organization metadata, member roster, and sandboxed aggregated telemetry.
    """
    org_id = ensure_default_organization(user_email, user_uid)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM organizations WHERE org_id = ? LIMIT 1;", (org_id,))
        org_row = cursor.fetchone()
        if not org_row:
            return {}

        cursor.execute("""
            SELECT id, org_id, user_id, user_email, display_name, role, status, invited_by, joined_at
            FROM org_members
            WHERE org_id = ?
            ORDER BY 
                CASE role 
                    WHEN 'admin' THEN 1 
                    WHEN 'soc_analyst' THEN 2 
                    WHEN 'auditor' THEN 3 
                    ELSE 4 
                END,
                joined_at DESC;
        """, (org_id,))
        members = [dict(m) for m in cursor.fetchall()]

        # Collect member emails & uids for sandboxed query
        member_emails = {m["user_email"].lower() for m in members if m.get("user_email")}
        member_uids = {m["user_id"] for m in members if m.get("user_id")}

        # Scan telemetry aggregation across this specific organization sandbox
        all_logs = get_all_logs()
        org_scans = []
        threat_count = 0
        clean_count = 0

        for log in all_logs:
            log_user = log.get("user_id")
            log_sender = (log.get("sender_email") or log.get("sender") or "").lower()
            # If log belongs to a member of this org, or was explicitly tagged with this org_id
            if log.get("org_id") == org_id or log_user in member_uids or log_sender in member_emails:
                org_scans.append(log)
                risk_lvl = (log.get("risk_level") or "").lower()
                if risk_lvl in ("high", "critical"):
                    threat_count += 1
                else:
                    clean_count += 1

        total_scans = len(org_scans)
        clean_pct = round((clean_count / total_scans * 100), 1) if total_scans > 0 else 100.0

        return {
            "org_id": org_row["org_id"],
            "name": org_row["name"],
            "domain": org_row["domain"] or "paruluniversity.ac.in",
            "owner_email": org_row["owner_email"],
            "created_at": org_row["created_at"],
            "stats": {
                "total_members": len(members),
                "active_members": len([m for m in members if m["status"] == "active"]),
                "total_scans": total_scans,
                "threats_intercepted": threat_count,
                "clean_scans": clean_count,
                "clean_rate_pct": clean_pct,
                "quota_seats": 1000,
            },
            "members": members,
            "recent_scans": org_scans[:20]
        }
    finally:
        conn.close()


def invite_member(org_id: str, email: str, role: str, invited_by_email: str, display_name: str = "") -> Dict[str, Any]:
    """Invites a new employee / team member to the organization."""
    clean_email = email.lower().strip()
    clean_role = role.strip().lower()
    if clean_role not in ALL_ROLES:
        clean_role = ROLE_USER

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    name = display_name.strip() or clean_email.split('@')[0]

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO org_members (org_id, user_email, display_name, role, status, invited_by, joined_at)
            VALUES (?, ?, ?, ?, 'invited', ?, ?)
            ON CONFLICT(org_id, user_email) DO UPDATE SET
                role = excluded.role,
                status = 'invited',
                invited_by = excluded.invited_by;
        """, (org_id, clean_email, name, clean_role, invited_by_email, now))
        conn.commit()

        # Update role in global RBAC table as well
        try:
            assign_user_role(f"pending_{clean_email}", clean_email, clean_role, invited_by_email)
        except Exception:
            pass

        return {
            "status": "success",
            "message": f"Invitation dispatched to {clean_email} with role '{clean_role.upper()}'",
            "member": {
                "org_id": org_id,
                "user_email": clean_email,
                "display_name": name,
                "role": clean_role,
                "status": "invited",
                "joined_at": now
            }
        }
    finally:
        conn.close()


def update_member_role(org_id: str, email: str, new_role: str, updated_by_email: str) -> Dict[str, Any]:
    """Updates an existing member's role within the organization and global RBAC."""
    clean_email = email.lower().strip()
    clean_role = new_role.strip().lower()
    if clean_role not in ALL_ROLES:
        raise ValueError(f"Invalid role '{new_role}'. Must be one of {sorted(list(ALL_ROLES))}")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE org_members
            SET role = ?
            WHERE org_id = ? AND LOWER(user_email) = ?;
        """, (clean_role, org_id, clean_email))
        conn.commit()

        # Sync with global RBAC
        try:
            assign_user_role(clean_email, clean_email, clean_role, updated_by_email)
        except Exception:
            pass

        return {"status": "success", "message": f"Updated role for {clean_email} to {clean_role.upper()}"}
    finally:
        conn.close()


def remove_member(org_id: str, email: str, removed_by_email: str) -> Dict[str, Any]:
    """Removes a member from the organization."""
    clean_email = email.lower().strip()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Protect owner from self-removal
        cursor.execute("SELECT owner_email FROM organizations WHERE org_id = ?;", (org_id,))
        org = cursor.fetchone()
        if org and org["owner_email"].lower() == clean_email:
            raise ValueError("The organization owner cannot be removed.")

        cursor.execute("""
            DELETE FROM org_members
            WHERE org_id = ? AND LOWER(user_email) = ?;
        """, (org_id, clean_email))
        conn.commit()
        return {"status": "success", "message": f"Removed {clean_email} from organization"}
    finally:
        conn.close()
