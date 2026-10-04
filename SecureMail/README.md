# SecureMail — Autonomous Email Threat Intelligence Platform 🛡️

SecureMail is a next-generation cyber defense platform engineered for real-time email security inspection, optical QR quishing analysis, domain homoglyph detection, and multi-engine threat correlation.

---

## 📁 System Architecture & Directory Tree

```
SecureMail/
├── Architecture/                      # Complete system design & threat models
│   ├── SYSTEM_ARCHITECTURE.md         # Multi-tier architecture overview & diagrams
│   ├── THREAT_MODELING.md             # Threat vectors & MITRE ATT&CK framework mapping
│   ├── DATA_FLOWS.md                  # Ingestion & evaluation sequence diagrams
│   └── API_REFERENCE.md               # REST API endpoints & payload specifications
│
├── Backend/                           # FastAPI Cyber-Defense Engine
│   ├── app/                           # Core application package
│   │   ├── routers/                   # Endpoint controllers (scan, forensics, threat vault)
│   │   ├── services/                  # Threat engines (quishing CV, risk scorer, homographs)
│   │   ├── models/                    # Pydantic schemas
│   │   └── utils/                     # Logging & helpers
│   ├── tests/                         # Automated regression test suite (128 passing tests)
│   ├── requirements.txt               # Dependencies
│   └── run_server.py                  # API server startup script
│
├── Frontend/                          # Modular Cyber Defense Web UI
│   ├── index.html                     # Clean, modular semantic HTML interface
│   ├── index.standalone.html          # Single-file standalone build
│   ├── css/style.css                  # Human-readable & editable stylesheet
│   ├── js/auth.js                     # Firebase authentication & session module
│   ├── js/app.js                      # Application controller, charts & scanner UI
│   └── assets/                        # Brand logos and icons
│
├── Extension/                         # Chrome / Edge / Brave Extension
│   ├── manifest.json                  # Manifest V3 extension configuration
│   ├── background.js                  # Service worker & API cache
│   ├── content.js                     # In-page Gmail & Outlook DOM inspector
│   └── popup.html / popup.js          # Toolbar scanner interface
│
├── Test_Suite/                        # Malicious Email & Threat Sample Suite
│   ├── 01_credential_phishing.eml     # Typo-squatting credential theft sample
│   ├── 02_eicar_malware_attachment.eml# Safe EICAR antivirus test file attachment
│   ├── 03_quishing_qr_code.eml        # Optical QR code phishing email
│   ├── 04_extortion_blackmail_btc.eml # Sextortion & Bitcoin ransom demand
│   ├── 05_ceo_impersonation_bec.eml   # Business Email Compromise & CEO spoofing
│   ├── 06_macro_malware_docm.eml      # Macro-enabled Office document attack
│   ├── 07_clean_legitimate_newsletter.eml # Control baseline (clean verified email)
│   ├── attachments/                   # Mock attachments (EICAR, macro docs, QR)
│   └── run_tests.py                   # Automated sample verification runner
│
└── Scripts/                           # Convenience Windows launch scripts
    ├── start_backend.bat              # One-click Backend launch
    ├── start_frontend.bat             # One-click Frontend launch
    └── run_all_tests.py               # Unified test runner
```

---

## ⚡ Quick Start

### 1. Launch Backend API Server
```bash
cd Backend
pip install -r requirements.txt
python run_server.py
```
*API will be live at `http://localhost:8000` (docs at `http://localhost:8000/docs`).*

### 2. Launch Web Frontend
```bash
cd Frontend
python -m http.server 3000
```
*Navigate to `http://localhost:3000` in your web browser.*

### 3. Run Automated Tests
```bash
cd Test_Suite
python run_tests.py
```
*Or from the root directory:*
```bash
python Scripts/run_all_tests.py
```

---

## 🧩 Browser Extension Installation
1. Open Chrome / Edge / Brave and go to `chrome://extensions`.
2. Toggle on **Developer mode** (top right).
3. Click **Load unpacked** and select the `SecureMail/Extension` folder.
