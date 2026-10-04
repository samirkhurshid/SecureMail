"""
Cryptographic API Key Management & Ingestion Service
===================================================
Generates high-entropy API keys (sm_live_...), stores SHA-256 digests,
enforces granular scopes (scans:write, threat_intel:read, etc.),
tracks usage telemetry, and provides instant key revocation.
"""

import os
import sqlite3
import secrets
import hashlib
import uuid
import datetime
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("app.api_keys")

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "threat_vault.db")

KEY_PREFIX = "sm_live_"

# ── Valid API Key Scopes ──────────────────────────────────────────────────────
VALID_SCOPES = {
    "scans:write",        # Submit email / URL / IP scans
    "scans:read_own",     # Read own scan results
    "scans:read_all",     # Read all organization scans
    "threat_intel:read",  # Query Threat Vault and lookups
    "threat_intel:sync",  # Trigger threat feed updates
    "forensics:read",     # Query forensics logs
    "reports:export",     # Generate PDF / CSV incident reports
}


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection configured with WAL mode."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_api_keys_db():
    """Initializes api_keys table and indexes."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                user_email TEXT NOT NULL,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                scopes TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                last_used_at TIMESTAMP,
                usage_count INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);")
        conn.commit()
    finally:
        conn.close()


# Ensure table is ready on module import
try:
    init_api_keys_db()
except Exception:
    pass


def hash_key(raw_key: str) -> str:
    """Computes SHA-256 digest of raw API key."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def generate_api_key(
    user_id: str,
    user_email: str,
    name: str,
    scopes: Optional[List[str]] = None,
    expires_days: Optional[int] = None
) -> Dict[str, Any]:
    """
    Generates a cryptographically secure API key.
    The raw plaintext key is returned ONLY ONCE upon creation.
    Only the SHA-256 hash and prefix are stored in the database.
    """
    if not name or not name.strip():
        name = "API Key"
        
    scopes_set = set(scopes) if scopes else {"scans:write", "threat_intel:read", "reports:export"}
    # Validate scopes
    invalid = scopes_set - VALID_SCOPES
    if invalid:
        raise ValueError(f"Invalid scopes: {sorted(list(invalid))}. Allowed: {sorted(list(VALID_SCOPES))}")
        
    # Generate 256 bits of URL-safe entropy
    random_bytes = secrets.token_urlsafe(32)
    raw_key = f"{KEY_PREFIX}{random_bytes}"
    key_prefix = raw_key[:12] + "..."
    key_digest = hash_key(raw_key)
    
    key_id = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    expires_at = None
    if expires_days is not None:
        exp_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=expires_days)
        expires_at = exp_dt.isoformat()
        
    scopes_str = ",".join(sorted(list(scopes_set)))
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO api_keys (id, user_id, user_email, name, key_prefix, key_hash, scopes, created_at, expires_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1);
        """, (key_id, user_id, user_email.lower().strip(), name.strip(), key_prefix, key_digest, scopes_str, now, expires_at))
        conn.commit()
        
        logger.info(f"Generated API key '{name}' (prefix: {key_prefix}) for user {user_id}")
        
        return {
            "id": key_id,
            "name": name.strip(),
            "raw_key": raw_key,  # Returned only once!
            "key_prefix": key_prefix,
            "scopes": sorted(list(scopes_set)),
            "created_at": now,
            "expires_at": expires_at
        }
    finally:
        conn.close()


def verify_api_key(raw_key: str) -> Optional[Dict[str, Any]]:
    """
    Verifies a raw API key.
    If valid, active, and not expired:
      - Increments usage_count
      - Updates last_used_at timestamp
      - Returns key metadata dict (user_id, email, scopes, name)
    Else returns None.
    """
    if not raw_key or not raw_key.startswith(KEY_PREFIX):
        return None
        
    key_digest = hash_key(raw_key)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, user_email, name, key_prefix, scopes, created_at, expires_at, usage_count, is_active
            FROM api_keys
            WHERE key_hash = ? AND is_active = 1
            LIMIT 1;
        """, (key_digest,))
        row = cursor.fetchone()
        
        if not row:
            return None
            
        # Check expiration
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        if row["expires_at"]:
            try:
                exp_dt = datetime.datetime.fromisoformat(row["expires_at"])
                if now_dt > exp_dt:
                    logger.warning(f"API key {row['id']} has expired on {row['expires_at']}")
                    return None
            except Exception:
                pass
                
        # Update usage telemetry
        now_iso = now_dt.isoformat()
        cursor.execute("""
            UPDATE api_keys
            SET usage_count = usage_count + 1, last_used_at = ?
            WHERE id = ?;
        """, (now_iso, row["id"]))
        conn.commit()
        
        scopes_list = [s.strip() for s in row["scopes"].split(",") if s.strip()]
        
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "user_email": row["user_email"],
            "name": row["name"],
            "key_prefix": row["key_prefix"],
            "scopes": scopes_list,
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "usage_count": row["usage_count"] + 1,
            "last_used_at": now_iso
        }
    finally:
        conn.close()


def list_user_api_keys(user_id: str) -> List[Dict[str, Any]]:
    """Lists all active and revoked API keys for a user (without raw key)."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, key_prefix, scopes, created_at, expires_at, last_used_at, usage_count, is_active
            FROM api_keys
            WHERE user_id = ?
            ORDER BY created_at DESC;
        """, (user_id,))
        
        keys = []
        for r in cursor.fetchall():
            scopes_list = [s.strip() for s in r["scopes"].split(",") if s.strip()]
            keys.append({
                "id": r["id"],
                "name": r["name"],
                "key_prefix": r["key_prefix"],
                "scopes": scopes_list,
                "created_at": r["created_at"],
                "expires_at": r["expires_at"],
                "last_used_at": r["last_used_at"],
                "usage_count": r["usage_count"],
                "is_active": bool(r["is_active"])
            })
        return keys
    finally:
        conn.close()


def revoke_api_key(key_id: str, user_id: str) -> bool:
    """Revokes an API key immediately so it can no longer authenticate."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE api_keys
            SET is_active = 0
            WHERE id = ? AND user_id = ?;
        """, (key_id, user_id))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()
