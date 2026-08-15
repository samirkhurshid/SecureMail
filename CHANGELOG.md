# Changelog

All notable changes to the SecureMail project will be documented in this file.

## [3.0.0] - 2026-08-16

### Added
- **Open Access Architecture**: Unauthenticated visitors can now freely explore the full platform (Email Scanner, Header Analysis, Threat Analysis, Settings, Extension Guides) with an IP-based quota of 5 free scans per day.
- **Inline Auth Gating**: Accessing persistent user features (Personal Dashboard, Forensic Threat Logs, Account Profile) presents a clean, non-intrusive sign-in prompt rather than locking the entire site behind a wall.
- **Dynamic Quota Counter**: Integrated live scan counter in the Scanner panel displaying remaining free scans and direct upgrade pathways.
- **Password Security Hardening**: Enforced 8-character minimum length and at least one uppercase letter requirement on registration.
- **Password Visibility Toggles**: Added interactive eye toggle buttons (reveal/conceal) on all authentication password inputs.
- **Unified Brand Design System**: Standardized official `logo.png` with ambient glow across the web app, login modals, report exports, and browser extension; harmonized light and dark theme glassmorphism gradients.

### Fixed
- **Authentication Loop & Token Refresh**: Resolved session resets by eliminating destructive 401 sign-out triggers in `apiFetch()`. Requests now dynamically fetch fresh Firebase ID tokens and automatically retry with force-refreshed credentials.
- **Guest State Protection**: Updated `loadThreatFeed` and `loadSettings` to render graceful fallback views without firing unauthorized 401 calls.
- **DOM & Navigation Structure**: Resolved container nesting defects and added background backdrop dismissal and close controls on authentication modals.

## [1.3.0] - 2026-06-20

### Fixed
- **Security**: Removed leaked API keys from `.env` that were accidentally included in a project export. Keys must be rotated before deployment.
- **Forensics log path bug**: `get_log_dir()` no longer depends on the current working directory — it now resolves consistently to `Backend/forensics_logs/` by anchoring to the file's own location on disk, regardless of where `uvicorn` is launched from.
- **Duplicate forensics data**: Merged two divergent `forensics_logs/` folders (30 + 54 entries) into a single source of truth at `Backend/forensics_logs/` with zero data loss.
- **AI explainer key validation**: Added format validation for `GEMINI_API_KEY` (must start with `AIzaSy`) and `ANTHROPIC_API_KEY` (must start with `sk-ant-`). Previously an invalid key (e.g. a Google OAuth token pasted by mistake) would fail silently or produce a confusing error mid-stream. Now `/api/ai/status` and `/api/ai/explain` both catch this immediately with a clear message and a link to get a real key.
- **Version consistency**: Synced version string across `Backend/app/main.py` and all `Frontend/index.html` references (previously a mix of 1.2.0 labels alongside the actual codebase).

## [1.2.0] - 2026-05-30

### Added
- Detection heuristics for extortion, blackmail, and sextortion scams.
- Verification patterns for Bitcoin wallet addresses and webcam threats.
- Weighted keyword scoring for phishing and extortion content analysis.
- Standalone `/api/headers/ip-reputation` fast lookup endpoint.
- POST `/api/forensics/save` endpoint allowing direct forensic log persistence from the Chrome extension.
- Advanced sender domain verification against official brand dictionaries to catch lookalike impersonation.
- Local memory caching with a 5-second Time-To-Live (TTL) for optimized logs querying.
- MITRE ATT&CK technique mapping for identified email security threats.

### Changed
- Refactored risk scoring engine to penalize missing authentication headers (unknown SPF/DKIM/DMARC) and brand spoofing patterns.
- Upgraded forensics log service with data normalization for robust rendering.
- Re-styled the landing page floating scan button to a modern, expandable glassmorphic pill featuring customized SVG linear gradients, smooth hover expansions, and click micro-animations.

### Fixed
- Prevented local forensics logs from being tracked in source control.
