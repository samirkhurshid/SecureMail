"""
SOC Compliance Audit Trail Logging Engine
==========================================
Provides an immutable, tamper-evident audit log of all security operations,
email & URL scans, PDF exports, log deletions, API key changes, and role assignments.
"""

import os
import sqlite3
import json
import datetime
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("app.audit")

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "threat_vault.db")

# ── Defined Audit Event Types ─────────────────────────────────────────────────
EVENT_SCAN_EMAIL = "SCAN_EMAIL"
EVENT_SCAN_URL = "SCAN_URL"
EVENT_PDF_REPORT_EXPORT = "PDF_REPORT_EXPORT"
EVENT_LOG_DELETE = "LOG_DELETE"
EVENT_API_KEY_CREATE = "API_KEY_CREATE"
EVENT_API_KEY_REVOKE = "API_KEY_REVOKE"
EVENT_ROLE_ASSIGN = "ROLE_ASSIGN"
EVENT_FEED_SYNC = "FEED_SYNC"
EVENT_USER_LOGIN = "USER_LOGIN"

ALL_AUDIT_EVENTS = [
    EVENT_SCAN_EMAIL,
    EVENT_SCAN_URL,
    EVENT_PDF_REPORT_EXPORT,
    EVENT_LOG_DELETE,
    EVENT_API_KEY_CREATE,
    EVENT_API_KEY_REVOKE,
    EVENT_ROLE_ASSIGN,
    EVENT_FEED_SYNC,
    EVENT_USER_LOGIN,
]


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection configured with WAL mode."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_audit_db():
    """Initializes audit_trail table and indexes."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                user_email TEXT,
                user_role TEXT,
                ip_address TEXT,
                resource_id TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_trail(event_type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_trail(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_trail(timestamp);")
        conn.commit()
    finally:
        conn.close()


# Ensure table is ready on module load
try:
    init_audit_db()
except Exception:
    pass


def log_audit_event(
    event_type: str,
    user_id: str,
    user_email: Optional[str] = None,
    user_role: Optional[str] = None,
    ip_address: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> int:
    """
    Appends an immutable audit event record to the audit_trail table.
    Returns the generated record ID.
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    details_json = json.dumps(details or {}, ensure_ascii=False)
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_trail
            (event_type, user_id, user_email, user_role, ip_address, resource_id, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            event_type,
            user_id or "anonymous",
            user_email or "",
            user_role or "user",
            ip_address or "",
            resource_id or "",
            details_json,
            now,
        ))
        conn.commit()
        record_id = cursor.lastrowid
        logger.info(f"Audit event logged: [{event_type}] by {user_id} (res: {resource_id})")
        return record_id
    except Exception as e:
        logger.error(f"Failed to write audit event: {e}")
        return -1
    finally:
        conn.close()


def query_audit_logs(
    event_type: Optional[str] = None,
    user_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """
    Queries audit records with multi-filter and keyword search support.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        where_clauses = []
        params = []
        
        if event_type:
            where_clauses.append("event_type = ?")
            params.append(event_type.strip())
            
        if user_id:
            where_clauses.append("user_id = ?")
            params.append(user_id.strip())
            
        if search:
            s = f"%{search.strip()}%"
            where_clauses.append("(user_email LIKE ? OR resource_id LIKE ? OR details LIKE ? OR ip_address LIKE ?)")
            params.extend([s, s, s, s])
            
        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        
        # 1. Total count
        count_query = f"SELECT COUNT(*) as total FROM audit_trail{where_sql};"
        cursor.execute(count_query, params)
        total = cursor.fetchone()["total"]
        
        # 2. Paginated records
        query = f"""
            SELECT id, event_type, user_id, user_email, user_role, ip_address, resource_id, details, timestamp
            FROM audit_trail
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?;
        """
        params.extend([limit, offset])
        cursor.execute(query, params)
        
        records = []
        for row in cursor.fetchall():
            d = dict(row)
            try:
                d["details"] = json.loads(d["details"]) if d["details"] else {}
            except Exception:
                d["details"] = {}
            records.append(d)
            
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "records": records,
            "available_event_types": ALL_AUDIT_EVENTS
        }
    finally:
        conn.close()
