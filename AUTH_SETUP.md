# SecureMail — Authentication Setup Guide

SecureMail now requires sign-in (email/password or Google) before any part of the app is accessible. This guide walks through the one-time Firebase setup needed to activate it.

---

## Overview

| Layer | What it does |
|---|---|
| **Frontend** (`index.html`) | Firebase Web SDK handles sign-up, sign-in, Google OAuth, and password reset. Every API call automatically attaches the user's ID token. |
| **Backend** (`app/auth.py`) | Firebase Admin SDK verifies the ID token on every request. Invalid/expired/missing tokens get a `401`. |

No passwords are ever stored by SecureMail itself — Firebase (Google's managed auth service) handles all credential storage, hashing, and OAuth flows.

---

## Step 1 — Create a Firebase Project

1. Go to **[console.firebase.google.com](https://console.firebase.google.com)**
2. Click **Add project** → name it (e.g. `securemail-prod`) → follow the prompts (Google Analytics is optional)
3. Once created, you'll land on the project dashboard

---

## Step 2 — Enable Sign-in Methods

1. In the left sidebar: **Build → Authentication**
2. Click **Get started**
3. Under the **Sign-in method** tab, enable:
   - **Email/Password** → toggle on → Save
   - **Google** → toggle on → set a support email → Save

---

## Step 3 — Get your Web App config (for the frontend)

1. In the left sidebar: **Project settings** (gear icon) → **General** tab
2. Scroll to **Your apps** → click the **Web icon** (`</>`)
3. Register the app (any nickname, e.g. "SecureMail Web")
4. Copy the `firebaseConfig` object shown — it looks like:

```js
const firebaseConfig = {
  apiKey: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  authDomain: "securemail-prod.firebaseapp.com",
  projectId: "securemail-prod",
  storageBucket: "securemail-prod.appspot.com",
  messagingSenderId: "123456789012",
  appId: "1:123456789012:web:abc123def456"
};
```

5. Open `Frontend/index.html`, find this block near the top (`<script type="module">`), and replace the placeholder values:

```js
const firebaseConfig = {
  apiKey:            "YOUR_API_KEY",       // ← paste your real values here
  authDomain:        "YOUR_PROJECT.firebaseapp.com",
  projectId:         "YOUR_PROJECT_ID",
  storageBucket:     "YOUR_PROJECT.appspot.com",
  messagingSenderId: "YOUR_SENDER_ID",
  appId:             "YOUR_APP_ID"
};
```

---

## Step 4 — Get your Service Account key (for the backend)

1. Still in **Project settings** → go to the **Service accounts** tab
2. Click **Generate new private key** → confirm → a `.json` file downloads
3. Rename it to `firebase-service-account.json`
4. Move it into your `Backend/` folder (same level as `.env`)

> ⚠️ **This file grants full admin access to your Firebase project. Never commit it to git, never share it, never upload it anywhere public.** It's already added to `.gitignore` for you.

---

## Step 5 — Install the backend dependency

```bash
cd Backend
pip install -r requirements.txt
```

This installs `firebase-admin`, which was added to `requirements.txt`.

---

## Step 6 — Configure `.env`

Open `Backend/.env` (create it from `.env.example` if you haven't) and confirm this line points to your key file:

```
FIREBASE_SERVICE_ACCOUNT_PATH=./firebase-service-account.json
```

---

## Step 7 — Restart everything

```bash
# Backend
cd Backend
uvicorn app.main:app --reload --port 8000
```

Open `http://localhost:8000` — you should now see the SecureMail sign-in screen instead of the dashboard.

---

## How it works end to end

1. User signs up or signs in (email/password or Google) → Firebase issues an **ID token** (JWT), valid for 1 hour
2. The frontend stores this token in memory (`window._authToken`) and silently refreshes it every 55 minutes
3. Every API call now goes through `apiFetch()` instead of raw `fetch()` — this automatically attaches `Authorization: Bearer <token>` to every request
4. On the backend, every router (`/api/scan`, `/api/forensics`, `/api/headers`, `/api/attachments`, `/api/settings`, `/api/ai`) requires a valid token via `Depends(get_current_user)` in `main.py`
5. If the token is missing, expired, or invalid → the backend returns `401` → the frontend automatically signs the user out and shows the login screen again

---

## Testing without setting up Firebase yet

If you want to explore the rest of the app before configuring Firebase, the backend will start normally but log a warning:

```
WARNING: Firebase service account not found at './firebase-service-account.json'.
Auth-protected endpoints will reject all requests until this is configured.
```

All API endpoints will return `503 Authentication is not configured on this server` until you complete Steps 1–6. This is intentional — it fails safely rather than silently allowing unauthenticated access.

---

## Common issues

| Problem | Fix |
|---|---|
| Sign-in screen never disappears after login | Check browser console — likely a `firebaseConfig` typo. Verify all 6 fields match your Firebase console exactly. |
| Google sign-in popup closes immediately | Add `localhost` to **Authentication → Settings → Authorized domains** in Firebase console. |
| Backend returns `401` for every request | Confirm `firebase-service-account.json` exists in `Backend/` and the path in `.env` matches. |
| Backend returns `503` | Same as above — the Admin SDK couldn't initialize. Check the startup logs for the exact error. |
| "Too many requests" on sign-in | Firebase rate-limits repeated failed sign-in attempts from the same IP — wait a few minutes. |
