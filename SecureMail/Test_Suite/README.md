# SecureMail Malicious Email & Threat Testing Suite 🛡️

This directory contains synthetic, RFC-5322 compliant `.eml` test emails and mock attachments representing real-world attack vectors. They are designed for testing and demonstrating SecureMail's detection capabilities across heuristics, computer vision quishing, homograph lookalike detection, and multi-engine VirusTotal integration.

> [!NOTE]
> **Safety Guarantee**: All attachments and URLs in this suite are **100% safe, non-weaponized test artifacts**. The executable attachments use the industry-standard **EICAR Anti-Virus Test File** string recognized by antivirus engines worldwide. No harmful binaries or malicious code are included.

---

## 📁 Directory Structure

```
sample_emails/
├── 01_credential_phishing.eml         # Lookalike domain credential harvest
├── 02_eicar_malware_attachment.eml    # Weaponized executable attachment (EICAR)
├── 03_quishing_qr_code.eml            # Quishing: Embedded QR code phishing
├── 04_extortion_blackmail_btc.eml     # Sextortion & Bitcoin wallet demand
├── 05_ceo_impersonation_bec.eml       # Business Email Compromise & CEO spoofing
├── 06_macro_malware_docm.eml          # Dangerous Office macro attachment
├── 07_clean_legitimate_newsletter.eml # Clean control baseline (100% authentic)
├── run_sample_tests.py                # Automated CLI verification test runner
├── attachments/                       # Standalone mock attachments
│   ├── eicar_antivirus_test_file.com  # Official 68-byte EICAR test string
│   ├── invoice_remittance.exe         # Safe executable mock (EICAR payload)
│   ├── purchase_order_macro.docm      # Safe macro document mock
│   └── quishing_mfa_qr.png            # Scannable QR code PNG image
└── README.md                          # Testing documentation (this file)
```

---

## 🧪 Threat Vector Breakdown

| File | Attack Type | Vector / Payload | Expected Risk Score | Engine Modules Triggered |
|---|---|---|---|---|
| `01_credential_phishing.eml` | **Credential Phishing** | Lookalike typosquatting (`paypa1-security.com`), fake urgent security suspension notice, SPF/DKIM fail | **100 / 100 (CRITICAL)** | Domain Homograph, Levenshtein Distance, Phishing Heuristics, Header Auth |
| `02_eicar_malware_attachment.eml` | **Malicious Attachment** | Executable attachment (`invoice_remittance.exe`) with EICAR antivirus payload | **90 / 100 (CRITICAL)** | Dangerous Extension Heuristic, SHA-256 Hash Matching, VirusTotal (Deep Scan: 60+ AV hits) |
| `03_quishing_qr_code.eml` | **Quishing (QR Phishing)** | Microsoft 365 2FA lure with embedded base64 QR code linking to `micros0ft-mfa.ru` | **100 / 100 (CRITICAL)** | OpenCV Computer Vision, QR Payload Decoder, Lookalike Engine, Optical Forensics |
| `04_extortion_blackmail_btc.eml` | **Extortion / Sextortion** | Blackmail claim (webcam spyware) + valid Bitcoin wallet (`1BoatSLRHtKNngkdXEeobR76b53LETtpyT`) | **97 / 100 (CRITICAL)** | Bitcoin Address Regex, Extortion Patterns, Social Engineering Classifier |
| `05_ceo_impersonation_bec.eml` | **CEO Impersonation (BEC)** | Display name spoofing (`Satya Nadella`), reply-to mismatch (`offshore-holdings.cc`), urgent wire request | **100 / 100 (CRITICAL)** | Display Name Spoof Detector, Reply-To Domain Mismatch, BEC Heuristics |
| `06_macro_malware_docm.eml` | **Macro Malware** | Malicious Office macro document (`PO_883011_Billing_Statement.docm`) | **86 / 100 (CRITICAL)** | Dangerous Macro Extension Filter, Heuristic Risk Scorer |
| `07_clean_legitimate_newsletter.eml` | **Clean Baseline (Control)** | Authentic GitHub newsletter with passing SPF (`pass`), DKIM (`pass`), and DMARC (`pass`) | **0 / 100 (CLEAN)** | Authentic Sender Trust Discount, Zero False-Positive Engine |

---

## 🚀 How to Test

### Method 1: Web Dashboard (Drag-and-Drop)
1. Open the SecureMail web dashboard in your browser (e.g., `http://localhost:3000` or deployed frontend).
2. Go to the **Scanner** tab.
3. Locate the drop zone labeled **"Drop .eml file here or paste raw email"**.
4. Drag and drop any `.eml` file from `sample_emails/` directly onto the drop zone.
5. Choose scan mode:
   - **⚡ Quick Scan**: Local heuristics, optical QR decoder, and ML model in `<200ms`.
   - **🛡️ Deep Scan**: Full multi-engine inspection with 87+ VirusTotal antivirus engines.
6. Click **Scan Email** to inspect the real-time breakdown, forensics, and risk score.

### Method 2: Automated CLI Test Runner
Run the included Python verification runner from the project root:
```bash
python sample_emails/run_sample_tests.py
```
This script automatically runs all 7 test files through SecureMail's inspection pipeline and asserts that scores and threat types match security benchmarks.

### Method 3: REST API (cURL / PowerShell)
To scan a sample `.eml` file via the backend API:

```bash
# Using curl (Linux / macOS / Git Bash)
curl -X POST "http://localhost:8000/api/scan/email" \
  -H "Content-Type: application/json" \
  -d "{\"raw_email\": $(python -c 'import json; print(json.dumps(open("sample_emails/01_credential_phishing.eml").read()))'), \"deep_scan\": false}"
```

---

## 🔒 Safe EICAR Test Payload Information
The attachment `eicar_antivirus_test_file.com` and the file embedded in `02_eicar_malware_attachment.eml` contain the standard 68-character EICAR string:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
- **Harmlessness**: It is not a computer virus and cannot cause harm to any operating system.
- **Verification**: When uploaded to VirusTotal, it triggers alerts across virtually all anti-malware scanners, providing an authentic simulation of weaponized malware detection without any risk.
