# SecureMail Browser Extension (Chrome / Edge / Brave) 🧩

Real-time in-browser email threat scanning and phishing alerts for Gmail & Outlook Web.

## 📁 Extension Files
- `manifest.json`: Manifest V3 configuration, permissions, and host patterns.
- `background.js`: Background service worker managing backend API calls and caching.
- `content.js`: In-page DOM inspector injected into Gmail & Outlook Web reading panes.
- `content.css`: Injected warning banners, threat badges, and safety shields.
- `popup.html`: Extension toolbar popup window.
- `popup.js`: Quick scan launcher, score gauge, and authentication state sync.
- `icons/`: Standard browser extension icons (16px, 32px, 48px, 128px).

## 🚀 How to Install in Browser
1. Open your browser and navigate to the Extensions page:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
   - Brave: `brave://extensions`
2. Enable **Developer mode** toggle (top right corner).
3. Click **Load unpacked**.
4. Select this `SecureMail/Extension` folder.
5. The SecureMail extension icon will appear in your browser toolbar!
