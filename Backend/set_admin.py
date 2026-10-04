#!/usr/bin/env python3
"""
SecureMail CLI Admin Promoter
=============================
Assigns the 'admin' role to any user account in the SecureMail SQLite database.

Usage:
    python set_admin.py <user_email>
    python set_admin.py --list
"""

import sys
import os
import sqlite3
import datetime

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "threat_vault.db")


def get_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def list_users():
    conn = get_db()
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
    cursor.execute("SELECT user_id, user_email, role, assigned_by, assigned_at FROM user_roles ORDER BY assigned_at DESC;")
    rows = cursor.fetchall()
    conn.close()

    print("\n" + "=" * 70)
    print(f"{'User ID':<28} | {'Email':<25} | {'Role':<10}")
    print("=" * 70)
    if not rows:
        print(" No users registered in role database yet.")
    for r in rows:
        print(f"{r['user_id']:<28} | {r['user_email']:<25} | {r['role'].upper():<10}")
    print("=" * 70 + "\n")


def promote_user(email: str, role: str = "admin"):
    clean_email = email.strip().lower()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = get_db()
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
    
    # Check if user already exists
    cursor.execute("SELECT user_id, user_email, role FROM user_roles WHERE LOWER(user_email) = ?;", (clean_email,))
    row = cursor.fetchone()
    
    if row:
        cursor.execute("UPDATE user_roles SET role = ?, assigned_by = 'cli_admin', updated_at = ? WHERE user_id = ?;", (role, now, row["user_id"]))
        conn.commit()
        print(f" [SUCCESS] Updated existing account {clean_email} ({row['user_id']}) to role: {role.upper()}")
    else:
        # Insert pre-assigned role by email
        dummy_uid = f"uid_{clean_email.replace('@', '_at_').replace('.', '_')}"
        cursor.execute("""
            INSERT OR REPLACE INTO user_roles (user_id, user_email, role, assigned_by, assigned_at, updated_at)
            VALUES (?, ?, ?, 'cli_admin', ?, ?);
        """, (dummy_uid, clean_email, role, now, now))
        conn.commit()
        print(f" [SUCCESS] Pre-assigned role '{role.upper()}' to email: {clean_email}")
        print(f"   When {clean_email} signs in via Firebase, they will automatically have full {role.upper()} privileges.")

    conn.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python set_admin.py <email_address>     -> Promote email to ADMIN")
        print("  python set_admin.py --list              -> View all user roles\n")
        sys.exit(1)

    arg = sys.argv[1].strip()
    if arg in ("--list", "-l", "list"):
        list_users()
    else:
        target_role = sys.argv[2] if len(sys.argv) > 2 else "admin"
        promote_user(arg, target_role)
