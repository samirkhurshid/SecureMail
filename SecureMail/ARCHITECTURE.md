# SecureMail Architecture Summary 🛡️

For detailed architectural diagrams and deep-dive specifications, refer to:
- [`Architecture/SYSTEM_ARCHITECTURE.md`](Architecture/SYSTEM_ARCHITECTURE.md)
- [`Architecture/THREAT_MODELING.md`](Architecture/THREAT_MODELING.md)
- [`Architecture/DATA_FLOWS.md`](Architecture/DATA_FLOWS.md)
- [`Architecture/API_REFERENCE.md`](Architecture/API_REFERENCE.md)

---

## Technology Stack

| Layer | Technologies |
|---|---|
| **Backend** | Python 3.10+, FastAPI, Uvicorn, Pydantic, AnyIO |
| **Computer Vision** | OpenCV (cv2), PIL, QRCode, NumPy |
| **Machine Learning** | Scikit-Learn (TF-IDF vectorizer + Naive Bayes/Logistic Regression) |
| **Threat Intelligence** | VirusTotal API v3 (87+ AV engines), AbuseIPDB v2, Custom Threat Vault |
| **Frontend** | Semantic HTML5, Modular CSS3, Vanilla ES6+ JavaScript, Leaflet.js |
| **Authentication** | Firebase Auth SDK (JWT, Google SSO, Email/Password, In-Memory Tokens) |
| **Browser Extension** | Chrome Manifest V3, WebExtensions API, Background Service Workers |
