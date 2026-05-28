# Email Security Gateway — Backend API

A production-ready Python/FastAPI backend for real-time email threat detection and forensic analysis. Integrates with **VirusTotal** (87+ AV engines) and **AbuseIPDB** (IP reputation).

---

## Features

| Module | What it does |
|---|---|
| **Email Scanner** | Parses raw .eml / pasted email, runs full threat pipeline |
| **Header Analysis** | SPF / DKIM / DMARC / ARC parsing, routing hop trace, anomaly detection |
| **URL Scanner** | VirusTotal API v3 — checks 87+ engines, flags lookalikes & shorteners |
| **Attachment Scanner** | SHA256 / MD5 hash lookup on VirusTotal (no file upload to VT) |
| **IP Reputation** | AbuseIPDB check — confidence score, geolocation, ISP, Tor detection |
| **Phishing Heuristics** | Urgency language, credential requests, domain lookalikes, display name spoof |
| **Risk Scorer** | 0–100 score aggregating all signals → critical / high / medium / low / clean |
| **Forensic Logs** | Auto-saved JSON logs with export to JSON / CSV |

---

## Quick Start

### 1. Clone and install

```bash
git clone <repo>
cd email-security-gateway
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp .env.example .env
# Edit .env and add your keys:
#   VIRUSTOTAL_API_KEY=...
#   ABUSEIPDB_API_KEY=...
```

Get free API keys:
- **VirusTotal**: https://www.virustotal.com/gui/join-us (free: 4 req/min, 500/day)
- **AbuseIPDB**: https://www.abuseipdb.com/register (free: 1,000 checks/day)

### 3. Run the server

```bash
uvicorn app.main:app --reload --port 8000
```

The API is now at `http://localhost:8000`
Interactive docs: `http://localhost:8000/docs`

---

## API Endpoints

### Email Scanning

#### `POST /api/scan/email` — Full email scan
```json
{
  "raw_email": "From: attacker@evil.com\nSubject: Urgent...\n\n..."
}
```
Also accepts: `sender_email`, `subject`, `body`, `headers_raw` as individual fields.

**Response:**
```json
{
  "scan_id": "uuid",
  "risk_score": 87,
  "risk_level": "critical",
  "threat_types": ["phishing", "spoofing"],
  "summary": "CRITICAL RISK (score 87/100) — phishing attempt, sender spoofing detected.",
  "authentication": { "spf": "fail", "dkim": "fail", "dmarc": "fail" },
  "header_analysis": {
    "originating_ip": "185.234.218.47",
    "ip_reputation": { "abuse_confidence_score": 92, "country_code": "RU" },
    "display_name_spoof": true,
    "anomalies": ["SPF FAIL", "DMARC policy failed", "Display name spoofing"]
  },
  "urls": [{ "url": "...", "vt_result": { "detections": 34, "risk_level": "high" } }],
  "attachments": [],
  "phishing": { "urgency_language": true, "credential_request": true }
}
```

#### `GET /api/scan/demo` — Run a built-in phishing sample (no input needed)

#### `POST /api/scan/url` — Scan a single URL
```json
{ "url": "https://suspicious-site.com/login" }
```

#### `POST /api/scan/ip` — Check an IP address
```json
{ "ip": "185.234.218.47" }
```

---

### Header Analysis

#### `POST /api/headers/analyze`
```json
{
  "raw_headers": "Received: from mail.evil.ru...\nFrom: PayPal <fake@evil.ru>\n..."
}
```

---

### Attachments

#### `POST /api/attachments/scan` — Upload a file (multipart/form-data)
```bash
curl -X POST http://localhost:8000/api/attachments/scan \
  -F "file=@invoice.pdf"
```

#### `POST /api/attachments/hash` — Check a known hash
```json
{ "hash": "a3f9d1c8e2b4f6a0d7e5c3b1a9f8e2d4c6b0a8f6e4d2c0b8a6f4e2d0c8b6a4f2" }
```

---

### Forensic Logs

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/forensics/` | List all logs (paginated, filterable) |
| GET | `/api/forensics/stats` | Aggregate statistics |
| GET | `/api/forensics/{log_id}` | Get a single log |
| DELETE | `/api/forensics/{log_id}` | Delete a log |
| GET | `/api/forensics/export/json` | Download all logs as JSON |
| GET | `/api/forensics/export/csv` | Download all logs as CSV |

Query parameters for listing: `?limit=50&offset=0&risk_level=high&search=paypal`

---

## Risk Scoring

The engine assigns a **0–100 risk score** by combining:

| Signal | Max pts |
|---|---|
| SPF / DKIM / DMARC all fail | 30 |
| IP abuse score (AbuseIPDB) | 20 |
| Phishing heuristics | 25 |
| Malicious URL detections (VT) | 20 |
| Malicious attachment (VT) | 25 |
| Header anomalies | 5 |

Score thresholds (configurable in `.env`):

| Score | Level |
|---|---|
| 80–100 | Critical |
| 70–79 | High |
| 40–69 | Medium |
| 11–39 | Low |
| 0–10 | Clean |

---

## Running Tests

```bash
pytest tests/ -v
```

Tests run without API keys (services return mock results when keys absent).

---

## Project Structure

```
email-security-gateway/
├── app/
│   ├── main.py                 ← FastAPI app + middleware
│   ├── config.py               ← Settings (env vars)
│   ├── models/
│   │   └── schemas.py          ← Pydantic request/response models
│   ├── routers/
│   │   ├── scan.py             ← /api/scan/* endpoints
│   │   ├── forensics.py        ← /api/forensics/* endpoints
│   │   ├── headers.py          ← /api/headers/* endpoints
│   │   └── attachments.py      ← /api/attachments/* endpoints
│   ├── services/
│   │   ├── virustotal.py       ← VirusTotal API v3 client
│   │   ├── abuseipdb.py        ← AbuseIPDB API v2 client
│   │   ├── email_parser.py     ← .eml parsing, URL/attachment extraction
│   │   ├── risk_scorer.py      ← Signal aggregation → 0-100 score
│   │   └── forensics.py        ← Log persistence + export
│   └── utils/
│       └── logger.py           ← Structured logging
├── tests/
│   └── test_api.py             ← Full test suite
├── forensics_logs/             ← Auto-created at runtime
├── .env.example                ← Config template
├── requirements.txt
└── README.md
```

---

## Connecting to the Frontend

The FastAPI backend serves the dashboard frontend at `http://localhost:8000`.

Update the frontend API base URL to point to this server:
```javascript
const API_BASE = "http://localhost:8000/api";
```

CORS is enabled for all origins in development. Lock it down in production via the `allow_origins` list in `app/main.py`.

---

## Free Tier API Limits

| Service | Free limit | Notes |
|---|---|---|
| VirusTotal | 4 req/min, 500/day | Rate limiter built-in (15s gap) |
| AbuseIPDB | 1,000 checks/day | Skips private/reserved IPs |

Upgrade to paid tiers for production / bulk scanning use.
