# Changelog

All notable changes to the SecureMail project will be documented in this file.

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
