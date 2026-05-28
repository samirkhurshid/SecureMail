# 🛡️ SecureMail — Email Threat Intelligence Gateway & Forensics Dashboard

<p align="center">
  <img src="Frontend/logo.png" alt="SecureMail Logo" width="120px" style="border-radius: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.15);"/>
</p>

<h3 align="center">SecureMail</h3>
<p align="center"><strong>An Advanced Gateway Email Security Platform, Phishing Analyzer, & Forensic Intelligence Dashboard.</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI Badge"/>
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Badge"/>
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript Badge"/>
  <img src="https://img.shields.io/badge/Chrome_Extension-4285F4?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Chrome Badge"/>
  <img src="https://img.shields.io/badge/Security-Cybersecurity-red?style=for-the-badge&logo=shield&logoColor=white" alt="Security Badge"/>
</p>

---

## 📌 Project Overview
**SecureMail** is an end-to-end email threat detection and forensics gateway. It parses raw email headers and body text (`.eml` or `.msg`), conducts automated DNS security alignment checks, resolves originating server IPs, evaluates links/attachments through global reputation threat intelligence engines, and computes a comprehensive weighted risk score to classify malicious activity.

The system comprises three core components:
1. **🚀 FastAPI Backend**: Performs multi-stage parsing, DNS auditing, IP lookup, Tor exit node detection, and queries VirusTotal & AbuseIPDB APIs.
2. **📊 Glassmorphic Frontend**: A dashboard providing real-time email scan analysis, forensic threat feeds, network routing hop visualizations, and PDF/HTML report generators.
3. **🔌 Browser Extension**: A Chrome/Edge browser addon integrating seamlessly with Gmail and Outlook, allowing analysts to right-click email text for instant reputation lookups.

---

## ⚙️ How It Works (7-Stage Threat Pipeline)
When a raw email is loaded into the SecureMail gateway, it runs through a comprehensive processing sequence:

```
[ Raw Email (.eml) ] ➔ [ 1. Email Parser ] ➔ [ 2. DNS Auth Auditing ] 
                                                      │ (SPF, DKIM, DMARC, ARC)
[ Weighted Risk Score ] 🠔 [ 7. Threat Classification ] 🠔 [ 3. Sender Verification ]
                                                      │ (Lookalike Domains, Spoofs)
[ 5. IP Reputation Audits ] 🠔 [ 4. URL Extraction & VT Rep ] 🠔 [ 6. Attachment Sandbox ]
 (AbuseIPDB, Tor Exits)                                   (Hash Lookup)
```

1. **Email Parser**: Extracts headers, plain text, HTML structures, and attachment metadata.
2. **DNS Auth Auditing**: Decodes authentication blocks to inspect **SPF**, **DKIM**, **DMARC**, and **ARC** status.
3. **Sender Verification**: Detects display-name spoofing, reply-to mismatches, and domain-impersonation lookalikes.
4. **URL Extraction**: Scrapes all embedded links and submits them to the **VirusTotal API** for reputation ratings.
5. **IP Auditing**: Traces the originating hops, checks IPs on **AbuseIPDB**, and maps sender ISP/geographic coordinates.
6. **Attachment Sandbox**: Extracts file hashes to look up known malware signatures on public threat registries.
7. **Risk Score Calc**: Computes a score from 0 to 100 based on weighted security alerts and applies threat classifications (e.g. `phishing`, `spoofing`, `malware`).

---

## ✨ Features
- **🚨 Live Threat Intelligence Feed**: Instantly logs and alerts security analysts of incoming critical threats.
- **🗺️ Forensic Routing Hop Audit**: Visually maps out intermediate email transfer servers to trace origins.
- **📝 Phishing Density Analysis**: Audits HTML and body copy to identify high-density urgency triggers and fraud-related keywords.
- **📑 Exporter Suite**: Instantly download professional print-ready **PDF Incident Reports** or offline **HTML logs** for audits.
- **🌓 Adaptive Theme Modes**: Fully responsive, gorgeous interface in both dark mode and light mode.

---

## 🛠️ Installation & Setup

### 1. Backend Setup (FastAPI Server)
Ensure you have **Python 3.8+** installed.

```bash
# Navigate to the Backend folder
cd Backend

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### Set up Environment Secrets
Create a `.env` file in the `Backend` directory (copy from `.env.example`):
```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```
*(Note: `.env` is already configured in `.gitignore` to prevent exposing your keys on GitHub).*

#### Start the Server
```bash
python -m uvicorn app.main:app --port 8000 --reload
```
The API documentation will be available at `http://localhost:8000/docs`.

---

### 2. Frontend Setup (Dashboard)
Since the frontend uses vanilla HTML, CSS, and JS, no complex node compilation is required:
1. Open the `Frontend` directory.
2. Launch `index.html` in any browser.
3. Make sure the FastAPI backend is running on port `8000` to allow the dashboard to populate live data.

---

### 3. Browser Extension Installation
1. Open Google Chrome or Microsoft Edge and navigate to `chrome://extensions`.
2. Toggle on **Developer mode** (top-right corner).
3. Click **Load unpacked** (top-left button).
4. Select the `extension` folder inside this project directory.
5. The SecureMail shield icon will appear in your browser bar, ready for one-click scans!

---

## 📊 API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/health` | `GET` | Health check route to verify backend status. |
| `/api/scan/email` | `POST` | Scans a raw email text block, computing a comprehensive report. |
| `/api/scan/url` | `POST` | Triggers a reputation query for a custom destination link. |
| `/api/attachments/scan` | `POST` | Uploads a file or queries an attachment hash. |
| `/api/forensics/` | `GET` | Retrieves historical scan logs. |
| `/api/forensics/{id}` | `DELETE` | Removes a threat log entry. |

---

## 🔒 Security Practices
API credentials are never pushed to the repository. The application relies entirely on `.env` files for configuration. If sharing this project, make sure to exclude the local `Backend/.env` file and instead distribute `.env.example` for manual key populating.

---

## 🎓 Final Year Project Submission
Developed as a final year academic project.
**Created by**: Samir Khurshid
**Project Name**: SecureMail Email Threat Intelligence Dashboard
