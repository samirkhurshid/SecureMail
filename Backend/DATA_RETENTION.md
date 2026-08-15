# SecureMail — Data Retention & Lifecycle Policy

This document details the data retention behavior, storage locations, encryption controls, and deletion lifecycles across all data components of the SecureMail Security Gateway platform.

---

## 1. Data Classification & Storage Inventory

| Data Category | Description | Storage Location | Encryption at Rest | Retention Lifecycle |
|---|---|---|---|---|
| **User Profiles** | Email, display name, created date, authentication provider | Firestore / `user_records.json` | No (Managed DB / local JSON) | Retained while account active. Deleted on 7-day account purge. |
| **Login Session History** | Client IP address and User-Agent recorded at sign-in | Firestore `login_events` / `user_records.json` | **YES** (Fernet symmetric key) | Retained indefinitely alongside user profile. Decrypted on GDPR export. |
| **Forensic Scan Logs** | Full email scan results, headers, verdicts, risk score, URLs, hashes | `./forensics_logs/{user_id}/{log_id}.json` | No (Plain JSON files) | Retained indefinitely while account active. Deleted individually by user or on account purge. |
| **Uploaded Attachments** | Attachment files uploaded for threat scanning via API | Memory (In-memory buffer) | N/A (Never written to disk) | **0 seconds** — processed in-memory for SHA256 computation and discarded immediately. |
| **Trial Quota Records** | Client IP address & daily scan counts for anonymous users | SQLite `usage_tracking.db` (`anon_quota`) | No (SQLite database) | Date-bucketed rows age out naturally. Candidate for periodic 30-day table vacuuming. |
| **User Preferences** | Weekly digest opt-in (`digest_enabled`), Slack/Webhook alert URL | Firestore / `user_records.json` | No (Plaintext fields) | Retained while account active. |
| **Compliance Audit Log** | Permanent audit record of account purge actions | `purge_audit.log` | No (Append-only log file) | **Indefinite** — preserved for legal compliance and auditing. |

---

## 2. Retention Lifecycles & Purge Mechanics

### A. Active User Accounts
- **Scan History:** Forensic logs are saved automatically to `./forensics_logs/{user_id}/` for all authenticated scans resulting in `low`, `medium`, `high`, or `critical` risk scores. Users can manually delete individual logs at any time via `DELETE /api/forensics/{log_id}`.
- **Login Session Events:** Login events are recorded once per session upon sign-in. Identifying fields (`ip_encrypted` and `user_agent_encrypted`) are encrypted using Fernet base64 keys before storage.

### B. Account Deletion (7-Day Soft Delete & Purge)
1. **User Request:** When a user initiates account deletion (`POST /api/account/delete`), the backend records `deletion_requested_at` and `deletion_scheduled_for` (7 days in the future).
2. **Immediate Lockout:** Firebase refresh tokens are revoked immediately, and any API request carrying the user's token is rejected with HTTP 403 `account_pending_deletion`.
3. **Automated Purge Script:** The cron script `purge_deleted_accounts.py` runs daily:
   - Identifies accounts where `deletion_scheduled_for` is in the past.
   - Deletes the Firebase Auth user record.
   - Deletes all user documents and subcollections in Firestore (or local `user_records.json`).
   - Permanently deletes the user's on-disk forensic log folder (`./forensics_logs/{user_id}/`).
   - Appends an audit entry to `Backend/purge_audit.log`.

### C. Anonymous Free Trial Scans
- Trial scans (`/api/scan/email` and `/api/scan/url` unauthenticated) are 100% **stateless**.
- Trial scan results, email bodies, subjects, headers, and URLs are never written to disk or saved to forensic log files.
- Trial quota is tracked strictly by IP address in `usage_tracking.db` (5 scans per day, resetting at 12:00 AM IST / UTC+5:30).

---

## 3. Security & Compliance Notes for Maintainers

1. **Fernet Key Protection:** `SESSION_ENCRYPTION_KEY` in `.env` is required for decrypting login metadata during GDPR data exports (`GET /api/account/export`). Key loss will render stored session metadata un-decryptable.
2. **Forensic Log Storage stretch item:** Forensic logs on disk are currently stored as standard JSON files (`.json`). If full encryption-at-rest is required for scan content in future enterprise tiers, a Fernet log wrapper can be added to `app/services/forensics.py`.
3. **Purge Audit Log:** `purge_audit.log` is an append-only compliance record that records when an account and its associated forensic logs were permanently destroyed. This log must not be cleared or deleted during routine maintenance.
