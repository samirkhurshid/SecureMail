# SecureMail Threat Modeling & Detection Methodology 🛡️

## 1. Threat Vectors Covered

| Threat Vector | Real-World Attack Scenario | SecureMail Countermeasure | MITRE ATT&CK ID |
|---|---|---|---|
| **Domain Lookalike & Typosquatting** | Attacker registers `paypa1-security.com` to harvest banking credentials | Levenshtein distance matching, visual character substitution tables (`1`->`l`, `0`->`o`, Cyrillic homoglyphs) | T1566.001, T1036.005 |
| **Optical Quishing (QR Code Phishing)** | Attacker embeds a QR code inside an image or HTML to bypass text-based DLP filters | Multi-stage OpenCV image preprocessing + QR payload extraction + destination threat intel lookup | T1566.002, T1027 |
| **Weaponized Executable Attachments** | Malicious `.exe`, `.scr`, `.bat`, or `.ps1` payload attached as an overdue invoice | Dangerous extension blacklisting + SHA-256 hash lookup against 87+ VirusTotal AV engines | T1204.002, T1059 |
| **Macro-Enabled Malware Documents** | Office `.docm` or `.xlsm` files with malicious Visual Basic for Applications (VBA) code | Office macro file extension detection + heuristic content flags | T1059.005, T1204.002 |
| **Cryptocurrency Extortion / Sextortion** | Blackmail emails demanding Bitcoin to a crypto wallet address under threat of webcam leak | Bitcoin wallet address regex matching (`1...`, `3...`, `bc1...`) + intimidation pattern matching | T1657, T1566 |
| **Business Email Compromise (BEC)** | Attacker spoofs CEO display name and changes `Reply-To` to wire funds | Display name brand audit + `Reply-To` domain mismatch verification + wire transfer urgency heuristics | T1566.001, T1036 |
| **Authentication Spoofing** | Forged sender headers without cryptographic domain proof | RFC-5322 Authentication-Results header parser + live DNS SPF, DKIM, and DMARC verification | T1566, T1036.007 |

---

## 2. Two-Tier Inspection Architecture

To provide an optimal balance between blazing speed and deep forensic accuracy, SecureMail operates in two distinct modes:

### ⚡ Quick Scan Mode (<200ms)
- **Target**: Instant interactive analysis for daily inbox triage and browser extension popups.
- **Engines Active**:
  - Local RFC-5322 MIME & Header Parser
  - DNS Cryptographic Authentication Resolver (SPF / DKIM / DMARC)
  - 4-Stage OpenCV Computer Vision QR Decoder
  - IDN Homoglyph & Lookalike Engine
  - Local Threat Intelligence Vault (known IOC database)
  - Scikit-Learn TF-IDF Phishing Machine Learning Classifier
  - Authentic Sender Trust Discount (eliminates false positives)
- **External Calls**: Zero external blocking API calls.

### 🛡️ Deep Scan Mode (3-6s)
- **Target**: High-assurance forensic analysis and suspicious attachment verification.
- **Engines Active**:
  - All Quick Scan local engines PLUS:
  - **87+ VirusTotal Antivirus Engines** for all extracted URLs and attachment SHA-256 hashes.
  - **AbuseIPDB Global Reputation Database** for originating mail server IP address.
  - Full domain infrastructure age & WHOIS enrichment.
