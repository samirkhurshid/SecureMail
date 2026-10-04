# SecureMail REST API Specification 📡

Base URL: `http://localhost:8000/api`

## Core Endpoints

### 1. `POST /api/scan/email`
Scans raw email text or RFC-5322 `.eml` content for cyber threats.

**Request Body**:
```json
{
  "raw_email": "From: security@paypa1.com\nSubject: Urgent...",
  "deep_scan": false
}
```

**Response (200 OK)**:
```json
{
  "scan_id": "c8a491e0-82a1-421b-8392-120938491021",
  "score": 100,
  "risk_level": "critical",
  "threat_types": ["phishing", "spoofing", "homograph_impersonation"],
  "summary": "CRITICAL RISK (score 100/100) — phishing attempt, sender spoofing detected.",
  "duration_ms": 42,
  "authentication": {
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail"
  },
  "quishing": {
    "has_qr_codes": false,
    "qr_count": 0
  },
  "urls": [],
  "attachments": []
}
```

---

### 2. `GET /api/forensics/stats`
Retrieves forensic statistics for the authenticated user or organization.

**Response (200 OK)**:
```json
{
  "total_scans": 42,
  "clean_count": 30,
  "suspicious_count": 4,
  "malicious_count": 8,
  "avg_risk_score": 18.5,
  "threat_breakdown": {
    "phishing": 6,
    "malicious_attachment": 4,
    "quishing": 2
  }
}
```

---

### 3. `GET /api/health`
Returns system health, connected modules, and latency metrics.

**Response (200 OK)**:
```json
{
  "status": "healthy",
  "version": "4.2.0",
  "active_services": ["risk_scorer", "qr_scanner", "virustotal", "threat_intel"]
}
```
