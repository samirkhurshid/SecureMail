#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# safe_export.sh — Zip the project WITHOUT leaking secrets.
#
# Run this instead of "Send to > Compressed folder" whenever you
# need to share/upload the project (e.g. to Claude, a teammate,
# or for backup). It strips .env, logs, and other sensitive files
# regardless of what's in .gitignore.
#
# Usage:
#   chmod +x safe_export.sh
#   ./safe_export.sh
# ─────────────────────────────────────────────────────────────────

set -e

PROJECT_NAME="Final Year project"
OUTPUT="SecureMail_safe_export_$(date +%Y%m%d_%H%M%S).zip"

echo "🔒 Building a safe export (no secrets, no logs)..."

zip -r "$OUTPUT" "$PROJECT_NAME" \
  -x "*.env" \
  -x "*/.env" \
  -x "*/.env.*" \
  -x "!*.env.example" \
  -x "*firebase-service-account.json" \
  -x "*/user_records.json" \
  -x "*/usage_tracking.db*" \
  -x "*/purge_audit.log" \
  -x "*/forensics_logs/*" \
  -x "*/__pycache__/*" \
  -x "*.pyc" \
  -x "*/.pytest_cache/*" \
  -x "*/.git/*" \
  -x "*/node_modules/*" \
  -x "*/.DS_Store" \
  -x "*/venv/*" \
  -x "*/.venv/*"

echo ""
echo "✅ Safe export created: $OUTPUT"
echo ""
echo "Verifying no .env file was included..."
if unzip -l "$OUTPUT" | grep -E "\.env$" | grep -v "\.env\.example"; then
  echo "⚠️  WARNING: .env file still found in zip! Do not share this file."
  exit 1
else
  echo "✓ Confirmed clean — no .env file in this zip. Safe to share."
fi
