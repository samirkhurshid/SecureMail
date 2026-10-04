# SecureMail Backend Engine 🛡️

FastAPI-powered cyber threat intelligence and email inspection engine.

## 📁 Architecture Overview
- `app/main.py`: Entry point, CORS middleware, rate limiting, exception handlers.
- `app/routers/`: API routing layer (`scan.py`, `forensics.py`, `threat_intel.py`, `account.py`, `admin.py`, `organizations.py`, `webhooks.py`, `health.py`).
- `app/services/`: Core cybersecurity heuristics, optical computer vision quishing decoder, Bayesian confidence-weighted risk scorer, domain homograph evaluator, VirusTotal and AbuseIPDB connectors.
- `app/models/`: Pydantic request and response schemas.
- `tests/`: Complete automated regression test suite (128 tests passing).

## 🚀 Setup & Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start API Server
```bash
python run_server.py
# or: uvicorn app.main:app --reload --port 8000
```
API Documentation will be live at: `http://localhost:8000/docs`

### 3. Run Test Suite
```bash
python -m pytest tests/
```
