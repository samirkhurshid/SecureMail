# SecureMail Frontend UI 🎨

Modern cyber intelligence web interface for SecureMail.

## 📁 Directory Structure
```
Frontend/
├── index.html              # Clean, modular semantic HTML interface
├── index.standalone.html   # Standalone self-contained single-file build
├── css/
│   └── style.css           # Modular, human-readable master stylesheet
├── js/
│   ├── auth.js             # Firebase Auth SDK, token refresh & extension sync
│   └── app.js              # Scanning UI, analytics charts, forensics inspector
├── assets/
│   ├── logo.png            # SecureMail high-resolution brand asset
│   └── favicon.png         # Browser favicon
├── privacy.html            # Privacy Policy
├── terms.html              # Terms of Service
└── vercel.json             # Vercel deployment routing configuration
```

## 🚀 Running the Frontend
You can serve the frontend with any static web server:

```bash
# Python built-in server
python -m http.server 3000

# Or using Node.js / npx
npx serve .
```
Then navigate to `http://localhost:3000` in your browser.
