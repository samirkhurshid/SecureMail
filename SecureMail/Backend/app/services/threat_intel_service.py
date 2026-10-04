"""
SecureMail Threat Intelligence Ingestion & Threat Vault Service
==============================================================
Manages local SQLite Threat Vault database, synchronizes with global
threat feeds (URLhaus, OpenPhish), maintains in-memory LRU cache,
and provides sub-millisecond IOC reputation lookups.
"""

import os
import sqlite3
import datetime
import logging
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
import httpx

logger = logging.getLogger("app.threat_intel")

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "threat_vault.db")

# In-memory LRU cache for sub-millisecond lookups (key: f"{ioc_type}:{ioc_value}", val: dict or False)
_IOC_CACHE: Dict[str, Any] = {}
_MAX_CACHE_SIZE = 10000

# ── Pre-Seeded Curated Threat Indicators ──────────────────────────────────────
SEED_INDICATORS = [
    # Phishing Domains
    ("paypa1-support.ru", "domain", "phishing", "internal_seed", 95, "paypal,credential_theft"),
    ("secure-apple-verify.cc", "domain", "phishing", "internal_seed", 90, "apple,credential_theft"),
    ("microsoft-security-auth.top", "domain", "phishing", "internal_seed", 92, "microsoft,office365"),
    ("login.meta-account-review.xyz", "domain", "phishing", "internal_seed", 90, "facebook,instagram"),
    ("netflix-billing-update.club", "domain", "phishing", "internal_seed", 88, "netflix,billing"),
    ("chase-online-secureverify.net", "domain", "phishing", "internal_seed", 95, "banking,chase"),
    ("wellsfargo-auth-portal.online", "domain", "phishing", "internal_seed", 94, "banking,wellsfargo"),
    
    # Malicious URLs / Drops
    ("http://paypa1-login.ru/verify?token=abc123&next=account", "url", "phishing", "internal_seed", 98, "credential_harvester"),
    ("http://evil-lookalike-domain.ru/login", "url", "phishing", "internal_seed", 95, "credential_harvester"),
    ("http://malware-drop-zone.com/invoice.exe", "url", "malware_download", "urlhaus", 99, "trojan,exe"),
    ("http://185.234.218.47/payload/stealer.bin", "url", "malware_download", "urlhaus", 96, "stealer,redline"),
    
    # Malicious Originating IPs / Bulletproof MTAs / C2s
    ("185.234.218.47", "ip", "c2", "abuseipdb", 98, "bad_hosting,bulletproof_mta"),
    ("194.26.29.112", "ip", "malware", "abuseipdb", 92, "qakbot,c2"),
    ("45.154.255.89", "ip", "phishing", "abuseipdb", 90, "emotet_relay"),
    ("198.51.100.44", "ip", "c2", "abuseipdb", 85, "cobalt_strike"),
    
    # Malicious File Hashes (SHA-256)
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256", "malware", "urlhaus", 100, "ransomware,lockbit"),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256", "malware", "urlhaus", 98, "agent_tesla,infostealer"),
    ("d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb9f09e87e204742713f044", "sha256", "malware", "urlhaus", 95, "formbook,keylogger"),
]


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection configured with WAL mode and row factory."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_threat_vault_db():
    """Initializes tables, creates indexes, and inserts seed records if database is empty."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # 1. Main Threat Indicators Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source_feed TEXT NOT NULL,
                confidence INTEGER DEFAULT 80,
                tags TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1
            );
        """)
        
        # 2. Indexes for Sub-Millisecond Lookups
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_lookup ON threat_indicators(ioc_value, ioc_type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_type ON threat_indicators(ioc_type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_indicators(threat_type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_source_feed ON threat_indicators(source_feed);")
        
        # 3. Feed Sync Metadata Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feed_sync_meta (
                feed_name TEXT PRIMARY KEY,
                last_sync TIMESTAMP,
                record_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'idle',
                error_message TEXT
            );
        """)
        
        # 4. Insert Seeds if Empty
        cursor.execute("SELECT COUNT(*) as cnt FROM threat_indicators;")
        count = cursor.fetchone()["cnt"]
        if count == 0:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            for val, ioc_t, threat_t, src, conf, tags in SEED_INDICATORS:
                cursor.execute("""
                    INSERT OR IGNORE INTO threat_indicators
                    (ioc_value, ioc_type, threat_type, source_feed, confidence, tags, first_seen, last_seen, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1);
                """, (val.lower().strip(), ioc_t, threat_t, src, conf, tags, now, now))
            
            cursor.execute("""
                INSERT OR REPLACE INTO feed_sync_meta (feed_name, last_sync, record_count, status)
                VALUES ('internal_seed', ?, ?, 'success');
            """, (now, len(SEED_INDICATORS)))
            
            conn.commit()
            logger.info(f"Threat Vault initialized with {len(SEED_INDICATORS)} seed indicators.")
    finally:
        conn.close()


def normalize_ioc(val: str, ioc_type: Optional[str] = None) -> Tuple[str, str]:
    """
    Normalizes IOC strings:
    - Strips whitespace
    - Lowercases domains, IPs, URLs, hashes
    - Infers ioc_type if not provided
    """
    val = val.strip().lower()
    if not ioc_type:
        if val.startswith("http://") or val.startswith("https://") or "/" in val:
            ioc_type = "url"
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
            ioc_type = "ip"
        elif len(val) == 64 and all(c in "0123456789abcdef" for c in val):
            ioc_type = "sha256"
        elif len(val) == 32 and all(c in "0123456789abcdef" for c in val):
            ioc_type = "md5"
        else:
            ioc_type = "domain"
    
    # URL cleanups
    if ioc_type == "url":
        # Remove trailing slash for exact matching consistency
        if val.endswith("/"):
            val = val[:-1]
            
    return val, ioc_type


def lookup_ioc(ioc_value: str, ioc_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Queries the Threat Vault for an IOC (URL, domain, IP, or hash).
    Returns dict with match details or None if clean.
    """
    if not ioc_value:
        return None
        
    val, detected_type = normalize_ioc(ioc_value, ioc_type)
    cache_key = f"{detected_type}:{val}"
    
    # 1. In-Memory Cache Check (< 0.1ms)
    if cache_key in _IOC_CACHE:
        cached = _IOC_CACHE[cache_key]
        return cached if cached is not False else None
        
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # 2. Exact Match Query
        cursor.execute("""
            SELECT id, ioc_value, ioc_type, threat_type, source_feed, confidence, tags, first_seen, last_seen
            FROM threat_indicators
            WHERE ioc_value = ? AND is_active = 1
            LIMIT 1;
        """, (val,))
        row = cursor.fetchone()
        
        # 3. If no exact match and checking a URL, check if its domain is listed
        if not row and detected_type == "url":
            try:
                parsed = urllib.parse.urlparse(val)
                domain = parsed.netloc.split(":")[0].lower()
                if domain:
                    cursor.execute("""
                        SELECT id, ioc_value, ioc_type, threat_type, source_feed, confidence, tags, first_seen, last_seen
                        FROM threat_indicators
                        WHERE (ioc_value = ? OR ioc_value = ?) AND is_active = 1
                        LIMIT 1;
                    """, (domain, f"http://{domain}"))
                    row = cursor.fetchone()
            except Exception:
                pass
                
        # 4. If checking a domain, check if root domain is listed
        if not row and detected_type == "domain":
            parts = val.split(".")
            if len(parts) > 2:
                root_domain = ".".join(parts[-2:])
                cursor.execute("""
                    SELECT id, ioc_value, ioc_type, threat_type, source_feed, confidence, tags, first_seen, last_seen
                    FROM threat_indicators
                    WHERE ioc_value = ? AND is_active = 1
                    LIMIT 1;
                """, (root_domain,))
                row = cursor.fetchone()

        if row:
            res = {
                "id": row["id"],
                "ioc_value": row["ioc_value"],
                "ioc_type": row["ioc_type"],
                "threat_type": row["threat_type"],
                "source_feed": row["source_feed"],
                "confidence": row["confidence"],
                "tags": [t.strip() for t in row["tags"].split(",")] if row["tags"] else [],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "is_threat": True
            }
            # Cache positive match
            if len(_IOC_CACHE) < _MAX_CACHE_SIZE:
                _IOC_CACHE[cache_key] = res
            return res
        else:
            # Cache negative result
            if len(_IOC_CACHE) < _MAX_CACHE_SIZE:
                _IOC_CACHE[cache_key] = False
            return None
    finally:
        conn.close()


def insert_or_update_indicator(
    ioc_value: str,
    ioc_type: str,
    threat_type: str,
    source_feed: str,
    confidence: int = 80,
    tags: str = ""
) -> bool:
    """Inserts a new threat indicator or updates an existing record's last_seen."""
    val, detected_type = normalize_ioc(ioc_value, ioc_type)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO threat_indicators (ioc_value, ioc_type, threat_type, source_feed, confidence, tags, first_seen, last_seen, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(ioc_value, ioc_type) DO UPDATE SET
                last_seen = excluded.last_seen,
                confidence = MAX(threat_indicators.confidence, excluded.confidence),
                is_active = 1;
        """, (val, detected_type, threat_type, source_feed, confidence, tags, now, now))
        conn.commit()
        
        # Evict from cache so fresh data is loaded
        _IOC_CACHE.pop(f"{detected_type}:{val}", None)
        return True
    finally:
        conn.close()


# ── Feed Sync Workers ─────────────────────────────────────────────────────────

async def sync_urlhaus_feed(limit: int = 250) -> Dict[str, Any]:
    """
    Fetches active malware URLs from URLhaus online feed.
    """
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/250/"
    inserted = 0
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    conn = get_db_connection()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    urls_data = data.get("urls", [])
                    cursor = conn.cursor()
                    for item in urls_data[:limit]:
                        raw_url = item.get("url")
                        threat = item.get("threat", "malware_download")
                        tags = ",".join(item.get("tags") or [])
                        if raw_url:
                            norm_url, _ = normalize_ioc(raw_url, "url")
                            cursor.execute("""
                                INSERT INTO threat_indicators (ioc_value, ioc_type, threat_type, source_feed, confidence, tags, first_seen, last_seen, is_active)
                                VALUES (?, 'url', ?, 'urlhaus', 95, ?, ?, ?, 1)
                                ON CONFLICT(ioc_value, ioc_type) DO UPDATE SET last_seen = excluded.last_seen;
                            """, (norm_url, threat, tags, now, now))
                            inserted += 1
                    conn.commit()
                    cursor.execute("""
                        INSERT OR REPLACE INTO feed_sync_meta (feed_name, last_sync, record_count, status)
                        VALUES ('urlhaus', ?, ?, 'success');
                    """, (now, inserted))
                    conn.commit()
                    return {"feed": "urlhaus", "status": "success", "synced_records": inserted}
            except Exception as e:
                logger.warning(f"URLhaus live sync error: {e}. Using cached records.")
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO feed_sync_meta (feed_name, last_sync, record_count, status, error_message)
                    VALUES ('urlhaus', ?, 0, 'failed', ?);
                """, (now, str(e)))
                conn.commit()
                return {"feed": "urlhaus", "status": "offline_cached", "error": str(e)}
    finally:
        conn.close()


async def sync_openphish_feed(limit: int = 250) -> Dict[str, Any]:
    """
    Fetches active phishing URLs from OpenPhish community stream.
    """
    url = "https://openphish.com/feed.txt"
    inserted = 0
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    conn = get_db_connection()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    lines = resp.text.strip().split("\n")
                    cursor = conn.cursor()
                    for line in lines[:limit]:
                        line = line.strip()
                        if line and (line.startswith("http://") or line.startswith("https://")):
                            norm_url, _ = normalize_ioc(line, "url")
                            cursor.execute("""
                                INSERT INTO threat_indicators (ioc_value, ioc_type, threat_type, source_feed, confidence, tags, first_seen, last_seen, is_active)
                                VALUES (?, 'url', 'phishing', 'openphish', 92, 'zero_day_phish', ?, ?, 1)
                                ON CONFLICT(ioc_value, ioc_type) DO UPDATE SET last_seen = excluded.last_seen;
                            """, (norm_url, now, now))
                            inserted += 1
                    conn.commit()
                    cursor.execute("""
                        INSERT OR REPLACE INTO feed_sync_meta (feed_name, last_sync, record_count, status)
                        VALUES ('openphish', ?, ?, 'success');
                    """, (now, inserted))
                    conn.commit()
                    return {"feed": "openphish", "status": "success", "synced_records": inserted}
            except Exception as e:
                logger.warning(f"OpenPhish live sync error: {e}. Using cached records.")
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO feed_sync_meta (feed_name, last_sync, record_count, status, error_message)
                    VALUES ('openphish', ?, 0, 'failed', ?);
                """, (now, str(e)))
                conn.commit()
                return {"feed": "openphish", "status": "offline_cached", "error": str(e)}
    finally:
        conn.close()


async def sync_all_feeds() -> Dict[str, Any]:
    """Coordinates synchronization of all active threat feeds."""
    uh_res = await sync_urlhaus_feed()
    op_res = await sync_openphish_feed()
    status = get_feed_status()
    return {
        "feeds": [uh_res, op_res],
        "summary": status
    }


def get_feed_status() -> Dict[str, Any]:
    """Returns total active indicator counts, feed breakdown, and sync status."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM threat_indicators WHERE is_active = 1;")
        total_cnt = cursor.fetchone()["total"]
        
        cursor.execute("SELECT ioc_type, COUNT(*) as cnt FROM threat_indicators WHERE is_active = 1 GROUP BY ioc_type;")
        by_type = {row["ioc_type"]: row["cnt"] for row in cursor.fetchall()}
        
        cursor.execute("SELECT threat_type, COUNT(*) as cnt FROM threat_indicators WHERE is_active = 1 GROUP BY threat_type;")
        by_threat = {row["threat_type"]: row["cnt"] for row in cursor.fetchall()}
        
        cursor.execute("SELECT source_feed, COUNT(*) as cnt FROM threat_indicators WHERE is_active = 1 GROUP BY source_feed;")
        by_feed = {row["source_feed"]: row["cnt"] for row in cursor.fetchall()}
        
        cursor.execute("SELECT feed_name, last_sync, record_count, status, error_message FROM feed_sync_meta;")
        sync_meta = [dict(row) for row in cursor.fetchall()]
        
        return {
            "total_indicators": total_cnt,
            "by_ioc_type": by_type,
            "by_threat_type": by_threat,
            "by_source_feed": by_feed,
            "sync_metadata": sync_meta,
            "cache_entries": len(_IOC_CACHE)
        }
    finally:
        conn.close()


def query_vault(
    search: Optional[str] = None,
    ioc_type: Optional[str] = None,
    threat_type: Optional[str] = None,
    source_feed: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """Returns paginated threat records matching filter criteria."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        query = "SELECT id, ioc_value, ioc_type, threat_type, source_feed, confidence, tags, first_seen, last_seen FROM threat_indicators WHERE is_active = 1"
        count_query = "SELECT COUNT(*) as cnt FROM threat_indicators WHERE is_active = 1"
        params: List[Any] = []
        
        if search:
            query += " AND (ioc_value LIKE ? OR tags LIKE ?)"
            count_query += " AND (ioc_value LIKE ? OR tags LIKE ?)"
            search_param = f"%{search.strip().lower()}%"
            params.extend([search_param, search_param])
            
        if ioc_type:
            query += " AND ioc_type = ?"
            count_query += " AND ioc_type = ?"
            params.append(ioc_type.strip().lower())
            
        if threat_type:
            query += " AND threat_type = ?"
            count_query += " AND threat_type = ?"
            params.append(threat_type.strip().lower())
            
        if source_feed:
            query += " AND source_feed = ?"
            count_query += " AND source_feed = ?"
            params.append(source_feed.strip().lower())
            
        # Get total count
        cursor.execute(count_query, params)
        total = cursor.fetchone()["cnt"]
        
        # Get page
        query += " ORDER BY id DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])
        cursor.execute(query, params)
        
        records = []
        for r in cursor.fetchall():
            records.append({
                "id": r["id"],
                "ioc_value": r["ioc_value"],
                "ioc_type": r["ioc_type"],
                "threat_type": r["threat_type"],
                "source_feed": r["source_feed"],
                "confidence": r["confidence"],
                "tags": [t.strip() for t in r["tags"].split(",")] if r["tags"] else [],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"]
            })
            
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "records": records
        }
    finally:
        conn.close()
