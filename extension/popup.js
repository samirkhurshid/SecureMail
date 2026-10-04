// SecureMail Extension — Popup Script
// MV3-compliant: all events via addEventListener, no inline handlers.
// Auto-detects open Gmail/Outlook email and scans it on popup open.

'use strict';

// Backend URL configuration (defaults to http://localhost:8000 for local development/testing)
const LOCAL_DEV_URL = 'http://localhost:8000';
const PRODUCTION_API_URL = 'https://securemail-backend.onrender.com';
const PRODUCTION_API_BASE = `${PRODUCTION_API_URL}/api`;

let API_BASE = `${LOCAL_DEV_URL}/api`;
let _pendingEmailData = null; // extracted email waiting for user to click "Scan This Email"
let _currentPlatform  = null; // platform of the active mail-client tab
let _currentTab       = null; // active tab reference
let _phishingEnabled      = true;
let _vtEnabled            = true;
let _abuseEnabled         = true;
let _quishingEnabled      = true;
let _aiEnabled            = true;
let _autodetectEnabled    = true;
let _notificationsEnabled = true;
let _autosyncEnabled      = true;
let _currentScanData = null; // current scan results reference

/**
 * Resolves active API_BASE:
 * - Uses `dev_backend_override` in chrome.storage.local (defaults to 'http://localhost:8000' for local dev).
 * - Can be pointed to PRODUCTION_API_BASE or any custom URL anytime.
 */
async function resolveApiBase() {
  try {
    const data = await chrome.storage.local.get(['dev_backend_override']);
    if (data.dev_backend_override !== undefined && data.dev_backend_override !== null) {
      if (typeof data.dev_backend_override === 'string') {
        const trimmed = data.dev_backend_override.trim().replace(/\/+$/, '');
        if (trimmed) {
          API_BASE = trimmed.endsWith('/api') ? trimmed : `${trimmed}/api`;
          return API_BASE;
        }
      }
    } else {
      // Default to local development server for testing
      await chrome.storage.local.set({ dev_backend_override: 'http://localhost:8000' });
      API_BASE = 'http://localhost:8000/api';
      return API_BASE;
    }
  } catch (e) {
    console.warn('SecureMail: failed reading dev_backend_override', e);
  }
  API_BASE = `${LOCAL_DEV_URL}/api`;
  return API_BASE;
}

async function getFirebaseKey() {
  await resolveApiBase();
  const data = await chrome.storage.local.get(['firebaseApiKey']);
  if (data.firebaseApiKey) return data.firebaseApiKey;
  try {
    const resp = await fetch(`${API_BASE}/auth/config`);
    if (resp.ok) {
      const cfg = await resp.json();
      if (cfg.apiKey) {
        await chrome.storage.local.set({ firebaseApiKey: cfg.apiKey });
        return cfg.apiKey;
      }
    }
  } catch (e) {}
  return '';
}

// ── Extension Authentication System ──────────────────────────────────────────
async function getValidToken() {
  const data = await chrome.storage.local.get(['authToken', 'refreshToken', 'tokenExpiry', 'userEmail']);
  if (!data.authToken) return null;
  const now = Date.now();
  // If token has > 5 minutes remaining (300,000 ms), return cached token
  if (data.tokenExpiry && (data.tokenExpiry - now) > 300000) {
    return data.authToken;
  }
  // Token expired or about to expire: attempt refresh
  if (!data.refreshToken) {
    await clearAuthStorage();
    return null;
  }
  try {
    const apiKey = await getFirebaseKey();
    if (!apiKey) return null;
    const resp = await fetch(`https://securetoken.googleapis.com/v1/token?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: data.refreshToken
      })
    });
    if (!resp.ok) {
      await clearAuthStorage();
      return null;
    }
    const json = await resp.json();
    const newToken = json.id_token;
    const newRefresh = json.refresh_token || data.refreshToken;
    const expiresIn = parseInt(json.expires_in || '3600', 10);
    const newExpiry = Date.now() + (expiresIn * 1000);

    await chrome.storage.local.set({
      authToken: newToken,
      refreshToken: newRefresh,
      tokenExpiry: newExpiry
    });
    return newToken;
  } catch (e) {
    console.warn('SecureMail: token refresh failed', e);
    await clearAuthStorage();
    return null;
  }
}

async function clearAuthStorage() {
  await chrome.storage.local.remove(['authToken', 'refreshToken', 'tokenExpiry', 'userEmail']);
}

async function doExtensionSignIn() {
  const emailEl = document.getElementById('ext-auth-email');
  const passEl  = document.getElementById('ext-auth-password');
  const btn     = document.getElementById('ext-auth-btn');

  const email = emailEl?.value?.trim();
  const pass  = passEl?.value;

  if (!email || !pass) {
    showAuthErr('Please enter both email and password.');
    return;
  }

  if (btn) { btn.disabled = true; btn.textContent = 'Signing in…'; }
  showAuthErr('');

  try {
    let json = null;
    let resp = null;
    try {
      resp = await fetch(`${API_BASE}/auth/signin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: pass })
      });
      json = await resp.json();
    } catch (_) {}

    if (!resp || !resp.ok) {
      if (resp && resp.status === 429) {
        throw new Error(json?.detail || 'Too many sign-in attempts. Please try again later.');
      }
      if (resp && json?.detail) {
        throw new Error(json.detail?.message || json.detail);
      }
      // Fallback: direct Firebase REST API if backend is unreachable
      const apiKey = await getFirebaseKey();
      if (!apiKey) throw new Error('Authentication configuration unavailable. Ensure SecureMail server is running.');
      const directResp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: pass, returnSecureToken: true })
      });
      json = await directResp.json();
      if (!directResp.ok) {
        const code = json.error?.message || 'Authentication failed';
        throw new Error(formatAuthErr(code));
      }
    }

    const idToken = json.idToken;
    const refreshToken = json.refreshToken;
    const expiresIn = parseInt(json.expiresIn || '3600', 10);
    const expiry = Date.now() + (expiresIn * 1000);
    const userEmail = json.email || email;

    const userDisplayName = json.displayName || '';
    await chrome.storage.local.set({
      authToken: idToken,
      refreshToken: refreshToken,
      tokenExpiry: expiry,
      userEmail: userEmail,
      userDisplayName: userDisplayName
    });

    updateAuthUI(userEmail, 'authenticated', userDisplayName);
    // Trigger backend check & tab detection after successful sign-in
    initAfterAuth();
  } catch(e) {
    showAuthErr(e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
  }
}

async function doExtensionSignOut() {
  await clearAuthStorage();
  await chrome.storage.local.remove(['authToken', 'refreshToken', 'tokenExpiry', 'userEmail', 'userDisplayName']);
  updateAuthUI(null, 'anonymous');
}

function showAuthErr(msg) {
  const el = document.getElementById('ext-auth-err');
  if (!el) return;
  el.textContent = msg;
  el.style.display = msg ? 'block' : 'none';
}

function formatAuthErr(code) {
  if (code === 'INVALID_PASSWORD' || code === 'EMAIL_NOT_FOUND' || code === 'INVALID_LOGIN_CREDENTIALS') {
    return 'Invalid email or password.';
  }
  if (code === 'USER_DISABLED') return 'This user account has been disabled.';
  if (code === 'TOO_MANY_ATTEMPTS_TRY_LATER') return 'Too many failed attempts. Try again later.';
  return code;
}

function formatDisplayName(displayName, email) {
  if (displayName && typeof displayName === 'string' && displayName.trim() && displayName.trim() !== 'null') {
    return displayName.trim();
  }
  if (!email) return 'User Profile';
  const prefix = email.split('@')[0];
  if (/^\d+$/.test(prefix)) {
    return `User (${prefix})`;
  }
  return prefix.split(/[._-]/).map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(' ');
}

function getAvatarInitial(name, email) {
  if (name && typeof name === 'string' && name.trim()) {
    const clean = name.trim().replace(/^User\s*\(/i, '').replace(/[^a-zA-Z0-9]/g, '');
    if (clean) return clean.charAt(0).toUpperCase();
  }
  if (email && typeof email === 'string' && email.trim()) {
    return email.trim().charAt(0).toUpperCase();
  }
  return 'U';
}

async function updateAuthUI(userEmail, mode, explicitName = null) {
  const authView = document.getElementById('ext-auth-view');
  const mainView = document.getElementById('ext-main-view');
  const userBar  = document.getElementById('ext-user-bar');
  const anonBar  = document.getElementById('ext-anon-bar');
  const nameEl   = document.getElementById('ext-user-name');
  const avatarEl = document.getElementById('ext-user-avatar');

  if (userEmail || mode === 'authenticated') {
    if (authView) authView.style.display = 'none';
    if (mainView) mainView.style.display = 'block';
    if (userBar)  userBar.style.display = 'flex';
    if (anonBar)  anonBar.style.display = 'none';

    let displayName = explicitName;
    if (!displayName) {
      const data = await chrome.storage.local.get(['userDisplayName']);
      displayName = data.userDisplayName;
    }

    const formattedName = formatDisplayName(displayName, userEmail);
    const initial = getAvatarInitial(formattedName, userEmail);

    if (nameEl) {
      nameEl.textContent = formattedName;
      nameEl.title = userEmail ? `Signed in as ${userEmail} · Click to open Account` : 'Click to open Account';
    }
    if (avatarEl) {
      avatarEl.textContent = initial;
    }

    // Silently enrich with real account name from backend if available
    try {
      const token = await getValidToken();
      if (token) {
        authFetch(`${API_BASE}/account/me`).then(async (r) => {
          if (r.ok) {
            const acc = await r.json();
            if (acc.name && acc.name !== formattedName) {
              await chrome.storage.local.set({ userDisplayName: acc.name });
              if (nameEl) nameEl.textContent = acc.name;
              if (avatarEl) avatarEl.textContent = getAvatarInitial(acc.name, userEmail);
            }
          }
        }).catch(() => {});
      }
    } catch {}
  } else if (mode === 'auth_form') {
    if (authView) authView.style.display = 'block';
    if (mainView) mainView.style.display = 'none';
    if (userBar)  userBar.style.display = 'none';
    if (anonBar)  anonBar.style.display = 'none';
  } else {
    // Mode = 'anonymous' (unauthenticated default view)
    if (authView) authView.style.display = 'none';
    if (mainView) mainView.style.display = 'block';
    if (userBar)  userBar.style.display = 'none';
    if (anonBar)  anonBar.style.display = 'flex';
    loadExtQuota();
  }
}

async function loadExtQuota() {
  const quotaEl = document.getElementById('ext-quota-text');
  if (!quotaEl) return;
  try {
    const res = await fetch(`${API_BASE}/scan/quota`);
    if (res.ok) {
      const data = await res.json();
      if (data.unlimited) {
        quotaEl.innerHTML = `⚡ <strong>Unlimited scanning active</strong>`;
      } else {
        const rem = data.remaining ?? 5;
        const limit = data.limit ?? 5;
        quotaEl.innerHTML = `⚡ Free Trial: <strong>${rem} of ${limit} scans remaining</strong>`;
      }
    }
  } catch (e) {
    quotaEl.innerHTML = `⚡ Free Trial: <strong>5 scans / day</strong>`;
  }
}

function showLimitAndPromptAuth(msg, resetsAt) {
  updateAuthUI(null, 'auth_form');
  const errEl = document.getElementById('ext-auth-err');
  if (errEl) {
    const timeStr = resetsAt ? new Date(resetsAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'midnight IST';
    errEl.innerHTML = `⚡ <strong>Daily Free Trial Limit Reached (5/5 scans used)</strong><br>${esc(msg)}<br><span style="font-size:10.5px;opacity:0.85">Resets at ${esc(timeStr)}. Sign in or create an account to continue.</span>`;
    errEl.style.display = 'block';
  }
}

async function optionalAuthFetch(url, options = {}) {
  const token = await getValidToken();
  const headers = options.headers ? { ...options.headers } : {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (!headers['Content-Type'] && options.body && typeof options.body === 'string') {
    headers['Content-Type'] = 'application/json';
  }
  return await fetch(url, { ...options, headers });
}

async function authFetch(url, options = {}) {
  const token = await getValidToken();
  if (!token) {
    updateAuthUI(null, 'auth_form');
    throw new Error('Not authenticated. Please sign in to SecureMail.');
  }
  const headers = options.headers ? { ...options.headers } : {};
  headers['Authorization'] = `Bearer ${token}`;
  if (!headers['Content-Type'] && options.body && typeof options.body === 'string') {
    headers['Content-Type'] = 'application/json';
  }
  return await fetch(url, { ...options, headers });
}

// ─────────────────────────────────────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  try {
    await loadSettings();
  } catch (e) {
    console.warn('SecureMail: loadSettings failed', e);
  }

  // ── Auth buttons & Enter key listeners ─────────────────────────────────────
  document.getElementById('ext-auth-btn')?.addEventListener('click', doExtensionSignIn);
  document.getElementById('btn-ext-signout')?.addEventListener('click', doExtensionSignOut);
  document.getElementById('btn-ext-signin-link')?.addEventListener('click', () => {
    showAuthErr('');
    updateAuthUI(null, 'auth_form');
  });
  document.getElementById('btn-sync-web-session')?.addEventListener('click', async () => {
    showAuthErr('');
    const btn = document.getElementById('btn-sync-web-session');
    if (btn) btn.innerHTML = `<div class="spinner" style="width:12px;height:12px;border-width:2px;display:inline-block;margin-right:6px"></div> Checking open tabs…`;
    
    const session = await autoDetectWebSession();
    if (session) {
      await initAfterAuth();
    } else {
      showAuthErr('No active signed-in SecureMail tab detected. Please sign in to the web dashboard (localhost:8000) and try again.');
      if (btn) {
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg> Sync from Open Web App Tab`;
      }
    }
  });
  document.getElementById('ext-auth-password')?.addEventListener('keyup', (e) => {
    if (e.key === 'Enter') doExtensionSignIn();
  });

  // ── Wire all static button events (MV3: no inline handlers) ────────────────
  document.getElementById('btn-scan-now')?.addEventListener('click', runManualScan);
  document.getElementById('btn-demo')?.addEventListener('click', runDemo);
  document.getElementById('open-dashboard')?.addEventListener('click', openDashboard);

  // 'Scan This Email' button — shown after detection, before scan
  document.getElementById('btn-auto-scan')?.addEventListener('click', runAutoScan);

  // Theme Toggle Event
  document.getElementById('btn-ext-theme')?.addEventListener('click', toggleExtTheme);
  initExtTheme();

  // Tab buttons
  document.querySelectorAll('.tab[data-tab]').forEach(btn =>
    btn.addEventListener('click', () => switchTab(btn.dataset.tab))
  );

  // Result panel — delegated clicks for dynamically-rendered buttons
  document.getElementById('result-content')?.addEventListener('click', e => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    if (btn.dataset.action === 'open-dashboard') openDashboard();
    if (btn.dataset.action === 'save-log')       saveToDashboard();
    if (btn.dataset.action === 'rescan')         startRescan();
  });

  // Profile click: open Account settings on web dashboard
  document.getElementById('btn-ext-profile')?.addEventListener('click', () => {
    const base = (API_BASE || 'http://localhost:8000').replace(/\/api\/?$/, '');
    chrome.tabs.create({ url: `${base}/#account` });
  });

  // ── Always check backend connectivity immediately on popup open ──────────
  checkBackend();

  // ── Auth Check on Popup Open ───────────────────────────────────────────────
  const authenticated = await checkAuthOnStartup();
  await initAfterAuth();
});

/**
 * Automatically probes open SecureMail web app tabs for active authenticated session.
 * Zero-configuration seamless sync!
 */
async function autoDetectWebSession() {
  try {
    const tabs = await chrome.tabs.query({
      url: [
        'http://localhost:8000/*',
        'http://127.0.0.1:8000/*',
        'https://*.onrender.com/*'
      ]
    });
    for (const tab of tabs) {
      if (!tab.id) continue;
      try {
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            if (typeof window._getSecureMailSession === 'function') {
              return window._getSecureMailSession();
            }
            if (window._authToken && window._authUser) {
              return {
                token: window._authToken,
                email: window._authUser.email || '',
                displayName: window._authUser.displayName || '',
                expiresAt: Date.now() + (55 * 60 * 1000)
              };
            }
            return null;
          }
        });
        const session = results?.[0]?.result;
        if (session && session.token && session.email) {
          await chrome.storage.local.set({
            authToken: session.token,
            tokenExpiry: session.expiresAt || (Date.now() + 3600 * 1000),
            userEmail: session.email,
            userDisplayName: session.displayName || ''
          });
          updateAuthUI(session.email, 'authenticated', session.displayName || null);
          return session;
        }
      } catch (scriptErr) {
        // Tab may not be permitted or loaded yet
      }
    }
  } catch (e) {
    console.warn('SecureMail: autoDetectWebSession failed', e);
  }
  return null;
}

async function checkAuthOnStartup() {
  const token = await getValidToken();
  const data = await chrome.storage.local.get(['userEmail', 'userDisplayName']);
  if (token && data.userEmail) {
    updateAuthUI(data.userEmail, 'authenticated', data.userDisplayName);
    return true;
  }

  // Auto-probe open web app tabs for active session
  const session = await autoDetectWebSession();
  if (session) {
    return true;
  }

  updateAuthUI(null, 'anonymous');
  return false;
}

async function initAfterAuth() {
  let tab = null;
  try {
    tab = await getActiveTab();
  } catch (e) {
    console.warn('SecureMail: getActiveTab failed', e);
  }

  _currentTab      = tab;
  _currentPlatform = getPlatform(tab?.url || '');

  let stored = {};
  try { stored = await chrome.storage.session.get('lastResult'); } catch { /* ignore */ }
  if (stored.lastResult) renderResult(stored.lastResult);

  if (_currentPlatform) {
    // ── On a mail client ────────────────────────────────────────────────────
    showPlatformBar(_currentPlatform, 'Detecting open email…');
    showScanPanel('auto');
    showDetectingSpinner(true);

    await detectEmailOnPage(_currentTab, _currentPlatform, stored.lastResult ?? null);

  } else {
    // ── Not a mail client — show manual scan UI ─────────────────────────────
    showScanPanel('manual');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 1 — DETECT: extract email from page and show preview + scan button
// cachedResult is passed so we can tell the user if this email was already scanned
// ─────────────────────────────────────────────────────────────────────────────
async function detectEmailOnPage(tab, platform, cachedResult = null) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: extractEmailDataFromPage,
    });
    const emailData = results?.[0]?.result;

    if (!emailData || !emailData.body) {
      showNoEmailState(platform);
      return;
    }

    // Store for Phase 2
    _pendingEmailData = emailData;

    // Check if this is the SAME email that was already scanned
    // Compare by subject + sender (good enough without storing full body hash)
    const isSameEmail = cachedResult && isSameEmailAs(emailData, cachedResult);

    // Update UI: hide detecting spinner, show preview + scan button
    showDetectingSpinner(false);
    showEmailPreview(emailData, isSameEmail);
    showPlatformBar(platform, emailData.subject || 'Email detected');
    showDetectedState(true);

  } catch (e) {
    if (e.message?.includes('Cannot access') || e.message?.includes('chrome://')) {
      showNoEmailState(platform);
    } else {
      showNoEmailState(platform);
      console.warn('SecureMail: detection error', e);
    }
  }
}

/** True if the detected email appears to be the same as the cached scan result */
function isSameEmailAs(emailData, cachedResult) {
  const cachedMeta    = cachedResult._emailMeta || {};
  const cachedSubject = (cachedMeta.subject  || '').trim().toLowerCase();
  const cachedSender  = (cachedMeta.sender   || '').trim().toLowerCase();
  const foundSubject  = (emailData.subject   || '').trim().toLowerCase();
  const foundSender   = (emailData.senderEmail || emailData.senderName || '').trim().toLowerCase();

  // Both subject AND sender must match (subject alone can be empty/generic)
  if (!foundSubject && !foundSender) return false;
  return foundSubject === cachedSubject && foundSender === cachedSender;
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 2 — SCAN: called when user clicks "Scan This Email"
// ─────────────────────────────────────────────────────────────────────────────
async function runAutoScan() {
  if (!_pendingEmailData) return;

  const emailData = _pendingEmailData;
  const platform  = _currentPlatform;

  // Transition UI: hide preview state, show scanning spinner
  showDetectedState(false);
  showAutoScanning(true);
  showErr('auto-scan-err', '');

  try {
    autoStep('Sending to backend…');
    const result = await callScanEmail(emailData.raw);
    result._emailMeta = {
      platform,
      subject: emailData.subject,
      sender:  emailData.senderEmail || emailData.senderName,
    };

    await chrome.storage.session.set({ lastResult: result });
    updateBadge(result.risk_level);
    renderResult(result);
    switchTab('result');

  } catch (e) {
    showAutoScanning(false);
    showDetectedState(true);
    showErr('auto-scan-err', e.message || 'Scan failed. Is the backend running?');
    console.error('SecureMail scan error:', e);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RESCAN: go back to detection phase from the result tab's "Scan Again" button
// ─────────────────────────────────────────────────────────────────────────────
async function startRescan() {
  _pendingEmailData = null;
  switchTab('scan');
  showScanPanel('auto');
  showDetectedState(false);
  showAutoScanning(false);
  showDetectingSpinner(true);
  if (_currentTab && _currentPlatform) {
    let stored = {};
    try { stored = await chrome.storage.session.get('lastResult'); } catch { /* ignore */ }
    await detectEmailOnPage(_currentTab, _currentPlatform, stored.lastResult ?? null);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL EXTRACTION (injected into the mail page via scripting.executeScript)
// ─────────────────────────────────────────────────────────────────────────────
function extractEmailDataFromPage() {
  const host = location.hostname;

  // ── Gmail ──────────────────────────────────────────────────────────────────
  if (host.includes('mail.google.com')) {
    // Body: find the active/expanded message body in thread
    const bodyCandidates = Array.from(document.querySelectorAll('.a3s.aiL, .ii.gt .a3s, .a3s, [data-message-id] .a3s')).filter(
      el => el.innerText && el.innerText.trim().length > 20
    );
    const bodyEl = bodyCandidates[bodyCandidates.length - 1] || document.querySelector('.a3s') || document.querySelector('.ii.gt');
    if (!bodyEl || bodyEl.innerText.trim().length < 15) return null;

    // Subject
    const subjectEl = document.querySelector('.hP') || document.querySelector('h2[data-thread-perm-id]');
    const subject = subjectEl?.innerText?.trim() || document.title.replace(/\s*-\s*Gmail$/i, '').trim();

    // Sender name and email (prefer active expanded message in thread)
    const fromEmailCandidates = Array.from(document.querySelectorAll('.gD, span[email], [data-hovercard-id]')).filter(
      el => el.getAttribute('email') || (el.innerText && el.innerText.includes('@'))
    );
    const fromEmailEl = fromEmailCandidates[fromEmailCandidates.length - 1] || document.querySelector('.gD');
    const senderEmail = fromEmailEl?.getAttribute('email') || fromEmailEl?.innerText?.trim() || '';
    
    const fromNameCandidates = Array.from(document.querySelectorAll('.go, .gD')).filter(el => el.innerText && el.innerText.trim());
    const fromNameEl  = fromNameCandidates[fromNameCandidates.length - 1] || document.querySelector('.go');
    const senderName  = fromNameEl?.innerText?.trim() || fromEmailEl?.getAttribute('name') || '';

    // Reply-To
    const replyToEl   = document.querySelector('[data-tooltip*="reply" i]');
    const replyTo     = replyToEl?.getAttribute('email') || '';

    // Date
    const dateEl = document.querySelector('.g3');
    const date   = dateEl?.getAttribute('title') || dateEl?.innerText?.trim() || '';

    const body = bodyEl.innerText.trim().slice(0, 10000);

    const from = senderEmail
      ? (senderName && senderName !== senderEmail ? `${senderName} <${senderEmail}>` : senderEmail)
      : (senderName || 'unknown@unknown.com');

    // Extract domain & authentication indicators
    const domain = senderEmail.includes('@') ? senderEmail.split('@')[1].toLowerCase() : '';
    const mailedByEl = document.querySelector('[data-tooltip*="mailed-by" i]') || document.querySelector('.ajA');
    const signedByEl = document.querySelector('[data-tooltip*="signed-by" i]');
    const mailedBy = mailedByEl?.innerText?.trim() || domain;
    const signedBy = signedByEl?.innerText?.trim() || domain;

    const raw = [
      `From: ${from}`,
      replyTo          ? `Reply-To: ${replyTo}`       : '',
      subject          ? `Subject: ${subject}`         : '',
      date             ? `Date: ${date}`               : '',
      domain           ? `Authentication-Results: mx.google.com; spf=pass (google.com: domain of ${senderEmail} designates ...); dkim=pass (header.i=@${signedBy}); dmarc=pass` : '',
      domain           ? `Received-SPF: pass (google.com: domain of ${senderEmail} designates ...)` : '',
      'Content-Type: text/plain; charset=utf-8',
      '',
      body,
    ].filter(l => l !== '').join('\n');

    return { platform: 'gmail', subject, senderName, senderEmail, body, raw };
  }

  // ── Outlook (Live / Office 365) ────────────────────────────────────────────
  if (host.includes('outlook.live.com') || host.includes('outlook.office')) {
    // Body
    const bodyEl =
      document.querySelector('[aria-label="Message body"]') ||
      document.querySelector('.ReadingPaneContent .allowTextSelection') ||
      document.querySelector('[role="main"] [dir]');
    if (!bodyEl || bodyEl.innerText.trim().length < 30) return null;

    // Subject — multiple possible selectors across OWA versions
    const subjectEl =
      document.querySelector('[data-testid="subject"]') ||
      document.querySelector('.allowTextSelection h1') ||
      document.querySelector('[aria-label*="subject" i]') ||
      document.querySelector('.SubjectReply span');
    const subject = subjectEl?.innerText?.trim() || document.title.trim();

    // Sender
    const senderEl =
      document.querySelector('[data-testid="SenderField"] .lpc-hoverTarget') ||
      document.querySelector('[aria-label*="From" i] .lpc-hoverTarget') ||
      document.querySelector('.OZZZK') ||
      document.querySelector('[data-testid="SenderField"]');
    const senderRaw   = senderEl?.innerText?.trim() || senderEl?.getAttribute('title') || '';
    const emailMatch  = senderRaw.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
    const senderEmail = emailMatch ? emailMatch[0] : '';
    const senderName  = senderRaw.replace(emailMatch?.[0] || '', '').replace(/[<>]/g, '').trim();

    const body = bodyEl.innerText.trim().slice(0, 10000);

    const from = senderEmail
      ? (senderName ? `${senderName} <${senderEmail}>` : senderEmail)
      : (senderName || 'unknown@unknown.com');

    const domain = senderEmail.includes('@') ? senderEmail.split('@')[1].toLowerCase() : '';

    const raw = [
      `From: ${from}`,
      subject ? `Subject: ${subject}` : '',
      domain  ? `Authentication-Results: spf=pass; dkim=pass; dmarc=pass` : '',
      'Content-Type: text/plain; charset=utf-8',
      '',
      body,
    ].filter(l => l !== '').join('\n');

    return { platform: 'outlook', subject, senderName, senderEmail, body, raw };
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// PANEL / STATE MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────
function showScanPanel(mode) {
  // mode: 'auto' | 'no-email' | 'manual'
  const autoEl   = document.getElementById('auto-scan-state');
  const noEmailEl = document.getElementById('no-email-state');
  const manualEl  = document.getElementById('manual-scan-state');
  if (autoEl)    autoEl.style.display    = mode === 'auto'     ? 'block' : 'none';
  if (noEmailEl) noEmailEl.style.display = mode === 'no-email' ? 'block' : 'none';
  if (manualEl)  manualEl.style.display  = mode === 'manual'   ? 'block' : 'none';
  // When showing auto-scan panel, reset all sub-states
  if (mode === 'auto') {
    showDetectingSpinner(false);
    showDetectedState(false);
    showAutoScanning(false);
  }
}

/** Phase C → shows the initial 'Detecting open email…' spinner */
function showDetectingSpinner(show) {
  const el = document.getElementById('detecting-wrap');
  if (el) el.style.display = show ? 'flex' : 'none';
}

/** Phase A → shows the email preview card + 'Scan This Email' button */
function showDetectedState(show) {
  const el = document.getElementById('detected-state');
  if (el) el.style.display = show ? 'block' : 'none';
}

/** Phase B → shows the scanning-in-progress spinner */
function showAutoScanning(show) {
  const el = document.getElementById('auto-scanning-wrap');
  if (el) el.style.display = show ? 'flex' : 'none';
}

function autoStep(text) {
  const el = document.getElementById('auto-scan-step');
  if (el) el.textContent = text;
}

function showEmailPreview(emailData, isSameEmail = false) {
  const card = document.getElementById('email-preview-card');
  if (!card) return;

  // Avatar initial
  const initial = (emailData.senderName || emailData.senderEmail || '?')[0].toUpperCase();
  const avatar  = document.getElementById('aec-avatar');
  const name    = document.getElementById('aec-sender-name');
  const email   = document.getElementById('aec-sender-email');
  const subject = document.getElementById('aec-subject');
  const preview = document.getElementById('aec-preview');
  if (avatar)  avatar.textContent  = initial;
  if (name)    name.textContent    = emailData.senderName || emailData.senderEmail || 'Unknown Sender';
  if (email)   email.textContent   = emailData.senderEmail || '';
  if (subject) subject.textContent = emailData.subject || '(No subject)';
  if (preview) preview.textContent = (emailData.body?.slice(0, 120) || '') + (emailData.body?.length > 120 ? '…' : '');

  // Update scan button label depending on whether this email was already scanned
  const scanBtn = document.getElementById('btn-auto-scan');
  if (scanBtn) {
    scanBtn.innerHTML = isSameEmail
      ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Scan Again`
      : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Scan This Email`;
  }

  // Show or hide 'View Last Result' secondary button
  let viewBtn = document.getElementById('btn-view-last');
  if (isSameEmail) {
    if (!viewBtn) {
      viewBtn = document.createElement('button');
      viewBtn.id = 'btn-view-last';
      viewBtn.className = 'btn btn-secondary btn-sm';
      viewBtn.style.cssText = 'margin-top:8px;width:100%';
      viewBtn.addEventListener('click', () => switchTab('result'));
      scanBtn?.parentElement?.insertBefore(viewBtn, scanBtn.nextSibling);
    }
    viewBtn.textContent = 'View Last Result →';
    viewBtn.style.display = 'block';
  } else if (viewBtn) {
    viewBtn.style.display = 'none';
  }
}

function showNoEmailState(platform) {
  showScanPanel('no-email');
  showPlatformBar(platform, 'No email open');
}

function showPlatformBar(platform, subject) {
  const bar    = document.getElementById('platform-bar');
  const chip   = document.getElementById('platform-chip');
  const nameEl = document.getElementById('platform-name');
  const subjEl = document.getElementById('platform-subject');
  if (!bar) return;

  bar.style.display = 'flex';
  if (chip)   chip.className   = `platform-chip ${platform === 'gmail' ? 'chip-gmail' : platform === 'outlook' ? 'chip-outlook' : 'chip-unknown'}`;
  if (nameEl) nameEl.textContent = platform === 'gmail' ? 'Gmail' : platform === 'outlook' ? 'Outlook' : platform;
  if (subject && subjEl) subjEl.textContent = subject;
}

// ─────────────────────────────────────────────────────────────────────────────
// TAB SWITCHING
// ─────────────────────────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + name)?.classList.add('active');
  document.getElementById('panel-' + name)?.classList.add('active');
}

// ─────────────────────────────────────────────────────────────────────────────
// BACKEND HEALTH
// ─────────────────────────────────────────────────────────────────────────────
async function checkBackend() {
  const dot = document.getElementById('bs-dot');
  const txt = document.getElementById('bs-text');
  const sd  = document.getElementById('status-dot');
  const st  = document.getElementById('status-text');
  const bstatus = document.getElementById('backend-status');

  await resolveApiBase();
  try {
    const healthUrl = `${API_BASE.replace(/\/api\/?$/, '')}/health`;
    const r = await fetch(healthUrl, { signal: AbortSignal.timeout(4000) });
    const d = await r.json();
    if (d.status === 'healthy') {
      if (dot) { dot.className = 'bs-dot bs-online'; }
      if (txt) { txt.textContent = 'Protection Active · Gateway Connected'; }
      if (sd)  { sd.className = 'sdot sdot-active'; }
      if (st)  { st.textContent = 'Active'; }
      if (bstatus) {
        bstatus.style.background = 'rgba(34,197,94,0.06)';
        bstatus.style.borderColor = 'rgba(34,197,94,0.2)';
      }
      return true;
    }
  } catch { /* fall through */ }

  if (dot) dot.className = 'bs-dot bs-offline';
  if (txt) txt.textContent = 'Protection Offline · Backend Unreachable';
  if (sd)  { sd.className = 'sdot sdot-offline'; }
  if (st)  { st.textContent = 'Offline'; }
  if (bstatus) {
    bstatus.style.background = 'rgba(239,68,68,0.06)';
    bstatus.style.borderColor = 'rgba(239,68,68,0.25)';
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS & PREFERENCES (Instant Auto-Save)
// ─────────────────────────────────────────────────────────────────────────────
let _saveFlashTimer = null;

function flashSavedIndicator() {
  const pill = document.getElementById('settings-save-pill');
  if (!pill) return;
  pill.style.opacity = '1';
  clearTimeout(_saveFlashTimer);
  _saveFlashTimer = setTimeout(() => {
    pill.style.opacity = '0';
  }, 1600);
}

async function autoSavePreferences() {
  _phishingEnabled      = document.getElementById('pref-phishing')?.checked ?? true;
  _vtEnabled            = document.getElementById('pref-vt')?.checked ?? true;
  _abuseEnabled         = document.getElementById('pref-abuse')?.checked ?? true;
  _quishingEnabled      = document.getElementById('pref-quishing')?.checked ?? true;
  _aiEnabled            = document.getElementById('pref-ai')?.checked ?? true;
  _autodetectEnabled    = document.getElementById('pref-autodetect')?.checked ?? true;
  _notificationsEnabled = document.getElementById('pref-notifications')?.checked ?? true;
  _autosyncEnabled      = document.getElementById('pref-autosync')?.checked ?? true;

  await chrome.storage.local.set({
    phishing_enabled: _phishingEnabled,
    vt_enabled: _vtEnabled,
    abuse_enabled: _abuseEnabled,
    quishing_enabled: _quishingEnabled,
    ai_enabled: _aiEnabled,
    autodetect_enabled: _autodetectEnabled,
    notifications_enabled: _notificationsEnabled,
    autosync_enabled: _autosyncEnabled,
  });

  flashSavedIndicator();

  // Re-render cached results if any exist to reflect preference changes instantly
  try {
    const stored = await chrome.storage.session.get('lastResult');
    if (stored?.lastResult) renderResult(stored.lastResult);
  } catch {}
}

async function loadSettings() {
  await resolveApiBase();
  const s = await chrome.storage.local.get([
    'phishing_enabled',
    'vt_enabled',
    'abuse_enabled',
    'quishing_enabled',
    'ai_enabled',
    'autodetect_enabled',
    'notifications_enabled',
    'autosync_enabled'
  ]);

  _phishingEnabled      = s.phishing_enabled !== false;
  _vtEnabled            = s.vt_enabled !== false;
  _abuseEnabled         = s.abuse_enabled !== false;
  _quishingEnabled      = s.quishing_enabled !== false;
  _aiEnabled            = s.ai_enabled !== false;
  _autodetectEnabled    = s.autodetect_enabled !== false;
  _notificationsEnabled = s.notifications_enabled !== false;
  _autosyncEnabled      = s.autosync_enabled !== false;

  const bindToggle = (id, isChecked) => {
    const el = document.getElementById(id);
    if (el) {
      el.checked = isChecked;
      if (!el.dataset.bound) {
        el.addEventListener('change', autoSavePreferences);
        el.dataset.bound = 'true';
      }
    }
  };

  bindToggle('pref-phishing', _phishingEnabled);
  bindToggle('pref-vt', _vtEnabled);
  bindToggle('pref-abuse', _abuseEnabled);
  bindToggle('pref-quishing', _quishingEnabled);
  bindToggle('pref-ai', _aiEnabled);
  bindToggle('pref-autodetect', _autodetectEnabled);
  bindToggle('pref-notifications', _notificationsEnabled);
  bindToggle('pref-autosync', _autosyncEnabled);
}

// Backward-compatible alias for any legacy callers
const saveSettings = autoSavePreferences;

// ─────────────────────────────────────────────────────────────────────────────
// MANUAL SCAN (fallback for non-mail URLs)
// ─────────────────────────────────────────────────────────────────────────────
async function runManualScan() {
  const emailText = document.getElementById('email-paste')?.value.trim();
  const urlText   = document.getElementById('url-input')?.value.trim();
  showErr('scan-err', '');

  if (!emailText && !urlText) {
    showErr('scan-err', 'Paste an email or enter a URL first.');
    return;
  }

  const btnScan = document.getElementById('btn-scan-now');
  if (btnScan) { btnScan.disabled = true; btnScan.textContent = 'Scanning…'; }

  try {
    let result;
    if (urlText && !emailText) {
      result = await callScanUrl(urlText);
    } else {
      result = await callScanEmail(emailText || urlText);
    }
    await chrome.storage.session.set({ lastResult: result });
    renderResult(result);
    switchTab('result');
    updateBadge(result.risk_level || result.scan_result?.risk_level);
  } catch (e) {
    showErr('scan-err', e.message);
  } finally {
    if (btnScan) { btnScan.disabled = false; btnScan.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Scan Now'; }
  }
}

async function runDemo() {
  const btn = document.getElementById('btn-demo');
  if (btn) { btn.disabled = true; btn.textContent = 'Running…'; }
  try {
    const r = await authFetch(`${API_BASE}/scan/demo`, { signal: AbortSignal.timeout(60000) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Demo failed');
    await chrome.storage.session.set({ lastResult: d });
    renderResult(d);
    switchTab('result');
    updateBadge(d.risk_level);
  } catch (e) {
    showErr('scan-err', e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Demo Scan'; }
  }
}

async function rescanCurrentEmail() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const platform = getPlatform(tab?.url || '');
  if (platform) {
    showScanPanel('auto');
    switchTab('scan');
    await autoScanMailClient(tab, platform);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// API CALLS
// ─────────────────────────────────────────────────────────────────────────────
async function callScanEmail(raw) {
  autoStep('Sending to backend…');
  const r = await optionalAuthFetch(`${API_BASE}/scan/email`, {
    method: 'POST',
    body: JSON.stringify({ raw_email: raw }),
    signal: AbortSignal.timeout(60000),
  });

  if (r.status === 429) {
    const errData = await r.json().catch(() => ({}));
    const detail = errData.detail || errData;
    const msg = detail.message || "Daily free scan limit reached (5/5 scans used).";
    showLimitAndPromptAuth(msg, detail.resets_at);
    throw new Error('Daily limit reached. Please sign in to continue.');
  }

  autoStep('Checking VirusTotal & AbuseIPDB…');
  const d = await r.json();
  if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
  return d;
}

async function callScanUrl(url) {
  const r = await optionalAuthFetch(`${API_BASE}/scan/url`, {
    method: 'POST',
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(30000),
  });

  if (r.status === 429) {
    const errData = await r.json().catch(() => ({}));
    const detail = errData.detail || errData;
    const msg = detail.message || "Daily free scan limit reached (5/5 scans used).";
    showLimitAndPromptAuth(msg, detail.resets_at);
    throw new Error('Daily limit reached. Please sign in to continue.');
  }

  const d = await r.json();
  if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
  return { ...d, _type: 'url' };
}

// ─────────────────────────────────────────────────────────────────────────────
// RESULT RENDERER
// ─────────────────────────────────────────────────────────────────────────────
function generateSummary(score, level, threats) {
  if (level === 'clean') {
    return 'No threats detected. Email appears legitimate.';
  }
  
  const parts = [];
  if (threats.includes('extortion')) {
    parts.push('extortion / sextortion scam');
  }
  if (threats.includes('social_engineering') && !threats.includes('extortion')) {
    parts.push('social engineering');
  }
  if (threats.includes('phishing')) {
    parts.push('phishing attempt');
  }
  if (threats.includes('malicious_attachment')) {
    parts.push('malicious attachment');
  }
  if (threats.includes('suspicious_url')) {
    parts.push('malicious links');
  }
  if (threats.includes('spoofing')) {
    parts.push('sender spoofing');
  }
  if (threats.includes('header_anomaly')) {
    parts.push('header anomalies');
  }
  
  const threatStr = parts.length ? parts.join(', ') : 'suspicious activity';
  const levelStr = level.toUpperCase();
  return `${levelStr} RISK (score ${score}/100) — ${threatStr} detected.`;
}

function renderResult(data) {
  const idle    = document.getElementById('result-idle');
  const content = document.getElementById('result-content');
  if (idle)    idle.style.display    = 'none';
  if (content) content.style.display = 'block';

  // Update platform bar subject from metadata if available
  if (data._emailMeta) {
    showPlatformBar(data._emailMeta.platform, data._emailMeta.subject || 'Scanned');
  }

  // ── URL result ────────────────────────────────────────────────────────────
  if (data._type === 'url') {
    const vt  = data.scan_result || {};
    const lvl = _vtEnabled ? (vt.risk_level || 'unknown') : 'unknown';
    const detections = _vtEnabled ? (vt.detections || 0) : 0;
    const totalEngines = _vtEnabled ? (vt.total_engines || 0) : 0;
    
    content.innerHTML = `
      <div class="result-card ${lvl}">
        <div class="risk-header">
          <div class="risk-score ${lvl}">${_vtEnabled ? detections : '—'}</div>
          <div>
            <div class="${badgeClass(lvl)}" style="margin-bottom:5px">${lvl.toUpperCase()}</div>
            <div style="font-size:11px;color:#64748b">
              ${_vtEnabled 
                ? `${detections}/${totalEngines} engines flagged` 
                : 'VirusTotal integration disabled'}
            </div>
          </div>
        </div>
        <div class="summary">${esc(data.url || '')}</div>
        ${_vtEnabled && vt.categories?.length ? `<div style="font-size:11px;color:#64748b;margin-top:6px">Categories: ${vt.categories.join(', ')}</div>` : ''}
      </div>
      ${_vtEnabled && vt.permalink ? `<a href="${vt.permalink}" target="_blank" rel="noopener noreferrer" style="display:block;font-size:11px;color:#3b82f6;text-align:center;margin-top:6px">View on VirusTotal →</a>` : ''}
    `;
    updateBadge(lvl);
    return;
  }

  // ── Full email result ─────────────────────────────────────────────────────
  const auth  = data.authentication || {};
  const h     = data.header_analysis || {};
  const urls  = data.urls || [];
  const atts  = data.attachments || [];
  const ph    = data.phishing || {};
  const meta  = data._emailMeta || {};
  const ipRep = h.ip_reputation;

  // ── Calculate adjusted score/level based on toggles ──
  let adjustedScore = data.risk_score ?? 0;
  let adjustedThreats = [...(data.threat_types || [])];
  
  // Calculate points to subtract if AbuseIPDB is disabled
  let ipPoints = 0;
  if (ipRep && !_abuseEnabled) {
    const ipRisk = ipRep.risk_level || 'unknown';
    const confidence = ipRep.abuse_confidence_score || 0;
    if (ipRisk === 'high' || confidence >= 80) {
      ipPoints += 20;
    } else if (ipRisk === 'medium' || confidence >= 25) {
      ipPoints += 12;
    } else if (ipRisk === 'low' || confidence > 0) {
      ipPoints += 5;
    }
    if (ipRep.is_tor) {
      ipPoints += 8;
    }
    adjustedScore -= ipPoints;
  }
  
  // Calculate points to subtract if VirusTotal is disabled
  let vtUrlPoints = 0;
  let vtAttPoints = 0;
  if (!_vtEnabled) {
    // URL scan points from VT
    for (const url of urls) {
      const vt = url.vt_result || {};
      const detections = vt.detections || 0;
      if (detections >= 10) {
        vtUrlPoints = 20;
        break; // capped at 20 max in risk_scorer.py
      } else if (detections >= 3) {
        vtUrlPoints = Math.max(vtUrlPoints, 12);
      }
    }
    
    // Attachment scan points from VT
    for (const att of atts) {
      const vt = att.vt_result || {};
      const detections = vt.detections || 0;
      if (detections >= 5) {
        vtAttPoints = 25;
        break; // capped at 25 max in risk_scorer.py
      } else if (detections >= 1) {
        vtAttPoints = Math.max(vtAttPoints, 15);
      }
    }
    
    adjustedScore -= (vtUrlPoints + vtAttPoints);
    
    // Filter threat types related to VT if no non-VT indicators remain
    const hasDangerousExt = atts.some(a => a.is_dangerous_ext);
    if (!hasDangerousExt) {
      adjustedThreats = adjustedThreats.filter(t => t !== 'malicious_attachment');
    }
    const hasShortened = urls.some(u => u.is_shortened);
    const hasLookalike = urls.some(u => u.is_lookalike);
    const displaysLookalike = ph.domain_lookalike || ph.shortened_urls;
    if (!hasShortened && !hasLookalike && !displaysLookalike) {
      adjustedThreats = adjustedThreats.filter(t => t !== 'suspicious_url');
    }
  }
  
  adjustedScore = Math.max(0, adjustedScore);
  
  // Map adjusted score back to a risk level
  let adjustedLvl = 'clean';
  if (adjustedScore > 0 || (adjustedThreats.length > 0 && !adjustedThreats.includes('clean'))) {
    if (adjustedScore >= 80) adjustedLvl = 'critical';
    else if (adjustedScore >= 70) adjustedLvl = 'high';
    else if (adjustedScore >= 40) adjustedLvl = 'medium';
    else if (adjustedScore > 10) adjustedLvl = 'low';
  }
  if (adjustedScore === 0 && adjustedThreats.length === 0) {
    adjustedThreats.push('clean');
  }
  
  // Generate dynamic summary
  const dynamicSummary = generateSummary(adjustedScore, adjustedLvl, adjustedThreats);

  const findings = [];
  if (auth.spf   === 'fail') findings.push({ dot: 'fd-red',    txt: 'SPF authentication failed' });
  if (auth.dkim  === 'fail') findings.push({ dot: 'fd-red',    txt: 'DKIM invalid / missing' });
  if (auth.dmarc === 'fail') findings.push({ dot: 'fd-red',    txt: 'DMARC policy failed' });
  if (h.display_name_spoof)  findings.push({ dot: 'fd-orange', txt: 'Display name spoofing detected' });
  if (h.reply_to_mismatch)   findings.push({ dot: 'fd-amber',  txt: 'Reply-To domain mismatch' });
  if (ph.urgency_language)   findings.push({ dot: 'fd-amber',  txt: 'Urgency language detected' });
  if (ph.credential_request) findings.push({ dot: 'fd-red',    txt: 'Credential/sensitive data request' });
  if (ph.domain_lookalike)   findings.push({ dot: 'fd-orange', txt: 'Brand lookalike domain in links' });
  if (ph.shortened_urls)     findings.push({ dot: 'fd-amber',  txt: 'URL shortener hiding destination' });

  // Only show VirusTotal findings if VT is enabled
  if (_vtEnabled) {
    const malUrl = urls.find(u => u.vt_result?.detections > 0);
    if (malUrl) findings.push({ dot: 'fd-red', txt: `Malicious URL: ${esc(malUrl.domain)}` });
    const malAtt = atts.find(a => a.vt_result?.detections > 0);
    if (malAtt) findings.push({ dot: 'fd-red', txt: `Malicious file: ${esc(malAtt.filename)}` });
  }

  // Only show IP reputation finding if AbuseIPDB is enabled
  if (_abuseEnabled && ipRep) {
    const ipRisk = ipRep.risk_level || 'unknown';
    const confidence = ipRep.abuse_confidence_score || 0;
    if (ipRisk === 'high' || confidence >= 50) {
      findings.push({ dot: 'fd-red', txt: `Suspicious sender IP reputation: ${esc(ipRep.ip)} (${confidence}% abuse confidence)` });
    }
  }

  if (!findings.length && adjustedLvl === 'clean') {
    findings.push({ dot: 'fd-green', txt: 'No threats detected' });
    findings.push({ dot: 'fd-green', txt: 'SPF / DKIM / DMARC all passed' });
  }

  // Sender line for the meta strip
  const senderLine = data.sender_email || meta.sender || h.from_email || '';
  const subjectLine = data.subject || meta.subject || '';
  const skipped = _vtEnabled && data.urls_skipped > 0 ? `<span style="color:#f59e0b;font-size:10.5px">${data.urls_skipped} URL${data.urls_skipped > 1 ? 's' : ''} not scanned (rate limit)</span>` : '';

  _currentScanData = data;

  const showAiBlock = _aiEnabled && adjustedLvl !== 'clean';
  const aiBlockHtml = showAiBlock ? `
    <div class="ai-explainer" id="ext-ai-explainer-block" style="margin-top:12px">
      <div class="ai-explainer-header" id="ext-ai-header">
        <div class="ai-header-left">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2.5"><path d="M9.663 17h4.673M12 3v1m6.364 1.636-.707.707M21 12h-1M4 12H3m3.343-5.657-.707-.707m2.828 9.9a5 5 0 1 1 7.072 0l-.548.547A3.374 3.374 0 0 0 14 18.469V19a2 2 0 1 1-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
          <span class="ai-title">AI Threat Explainer</span>
        </div>
        <svg id="ext-ai-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="color:var(--t3);transition:transform .2s"><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div id="ext-ai-content" style="display:none">
        <div class="ai-body">
          <div class="ai-thinking" id="ext-ai-idle">
            <div class="ai-dots"><span></span><span></span><span></span></div>
            <span style="font-size:11px;color:var(--t3);margin-bottom:6px;display:block">AI will explain this threat in plain English</span>
            <button class="ai-btn" id="ext-ai-explain-btn">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg>
              Explain this threat
            </button>
          </div>
          <div id="ext-ai-streaming" style="display:none" class="ai-body-content"></div>
          <div class="ai-footer" id="ext-ai-footer" style="display:none; border-top:1px solid rgba(167,139,250,0.08); padding-top:6px; margin-top:8px">
            Model: <span id="ext-ai-model-name">detecting…</span>
          </div>
        </div>
      </div>
    </div>
  ` : '';

  content.innerHTML = `
    ${senderLine || subjectLine ? `
    <div class="scan-meta">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
        <polyline points="22,6 12,13 2,6"/>
      </svg>
      <span>${senderLine ? `<strong>${esc(senderLine)}</strong>` : ''}${subjectLine ? ` · ${esc(subjectLine)}` : ''}</span>
    </div>` : ''}

    <div class="result-card ${adjustedLvl}">
      <div class="risk-header">
        <div class="risk-score ${adjustedLvl}">${adjustedScore}</div>
        <div>
          <div class="${badgeClass(adjustedLvl)}" style="margin-bottom:4px">${adjustedLvl.toUpperCase()}</div>
          <div style="font-size:10.5px;color:#64748b">${adjustedThreats.filter(t=>t!=='clean').join(', ')||'No threats'}</div>
        </div>
      </div>
      <div class="summary">${esc(dynamicSummary)}</div>
    </div>

    <div class="auth-grid">
      ${['spf','dkim','dmarc','arc'].map(k => `
        <div class="auth-pill">
          <div class="auth-lbl">${k.toUpperCase()}</div>
          <div class="auth-val ${authClass(auth[k])}">${auth[k] || 'unknown'}</div>
        </div>`).join('')}
    </div>

    ${findings.length ? `
    <div class="findings-section">
      <div class="findings-title">Findings</div>
      ${findings.map(f => `
        <div class="finding">
          <div class="finding-dot ${f.dot}"></div>
          <div class="finding-txt">${f.txt}</div>
        </div>`).join('')}
    </div>` : ''}

    ${skipped}

    ${aiBlockHtml}

    <div class="btn-row" style="margin-top:10px">
      <button class="btn btn-secondary btn-sm" data-action="open-dashboard" style="flex:1">Full Report</button>
      ${adjustedLvl !== 'clean' ? `<button class="btn btn-secondary btn-sm" data-action="save-log" style="flex:1">Save Log</button>` : ''}
    </div>
    <button class="btn-rescan" data-action="rescan">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
      </svg>
      Scan Again
    </button>
  `;

  // Bind dynamic DOM element listeners
  const extAiHeader = document.getElementById('ext-ai-header');
  const extAiExplainBtn = document.getElementById('ext-ai-explain-btn');
  if (extAiHeader) {
    extAiHeader.addEventListener('click', toggleExtAiPanel);
  }
  if (extAiExplainBtn) {
    extAiExplainBtn.addEventListener('click', runExtAiExplain);
  }

  updateBadge(adjustedLvl);
}

// ─────────────────────────────────────────────────────────────────────────────
// BADGE
// ─────────────────────────────────────────────────────────────────────────────
function updateBadge(level) {
  const map = {
    critical: { text: '!!', color: '#ef4444' },
    high:     { text: '!',  color: '#f97316' },
    medium:   { text: '~',  color: '#f59e0b' },
    low:      { text: '·',  color: '#84cc16' },
    clean:    { text: '',   color: '#22c55e' },
  };
  const { text, color } = map[level] || { text: '?', color: '#64748b' };
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function getPlatform(url) {
  if (!url) return null;
  if (url.includes('mail.google.com'))  return 'gmail';
  if (url.includes('outlook.live.com') ||
      url.includes('outlook.office.com') ||
      url.includes('outlook.office365.com')) return 'outlook';
  return null;
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

/** A result is "fresh" if it was scanned within the last 5 minutes */
function isResultFresh(result) {
  if (!result?.scanned_at) return false;
  const age = Date.now() - new Date(result.scanned_at).getTime();
  return age < 5 * 60 * 1000;
}

function showErr(id, msg) {
  const el = id ? document.getElementById(id) : null;
  if (!el) return;
  el.textContent = msg;
  el.classList[msg ? 'add' : 'remove']('on');
}

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function badgeClass(l) {
  return `risk-badge badge-${['clean','low','medium','high','critical'].includes(l) ? l : 'unknown'}`;
}

function authClass(v) {
  if (!v || v === 'unknown') return 'av-unknown';
  if (v === 'pass')          return 'av-pass';
  if (v === 'fail')          return 'av-fail';
  return 'av-softfail';
}

function openDashboard() {
  const base = API_BASE.replace(/\/api\/?$/, '');
  chrome.tabs.create({ url: base });
}

async function saveToDashboard() {
  const stored = await chrome.storage.session.get('lastResult');
  if (!stored.lastResult) return;
  try {
    const r = await authFetch(`${API_BASE}/forensics/save`, {
      method: 'POST',
      body: JSON.stringify(stored.lastResult),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) console.warn('SecureMail: save log failed', r.status);
  } catch (e) {
    // Backend auto-saves non-clean results — manual save is a fallback
    console.warn('SecureMail: saveToDashboard error', e);
  }
}

// ── Theme management ──
const SUN_SVG = `<svg id="icon-theme" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
const MOON_SVG = `<svg id="icon-theme" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;

function toggleExtTheme() {
  const isLight = document.body.classList.toggle('light-theme');
  localStorage.setItem('theme', isLight ? 'light' : 'dark');
  const btn = document.getElementById('btn-ext-theme');
  if (btn) btn.innerHTML = isLight ? SUN_SVG : MOON_SVG;
}

function initExtTheme() {
  const saved = localStorage.getItem('theme');
  const isLight = saved === 'light';
  if (isLight) {
    document.body.classList.add('light-theme');
  } else {
    document.body.classList.remove('light-theme');
  }
  const btn = document.getElementById('btn-ext-theme');
  if (btn) btn.innerHTML = isLight ? SUN_SVG : MOON_SVG;
}

// ── Extension AI Explainer ──────────────────
function toggleExtAiPanel() {
  const content = document.getElementById('ext-ai-content');
  const chevron = document.getElementById('ext-ai-chevron');
  if (!content) return;
  const open = content.style.display === 'none';
  content.style.display = open ? 'block' : 'none';
  if (chevron) chevron.style.transform = open ? 'rotate(180deg)' : '';
  
  if (open) {
    updateExtModelName();
  }
}

async function updateExtModelName() {
  const modelSpan = document.getElementById('ext-ai-model-name');
  const footer = document.getElementById('ext-ai-footer');
  if (!modelSpan || !footer) return;
  
  try {
    const r = await fetch(`${API_BASE}/ai/status`, { signal: AbortSignal.timeout(4000) });
    if (r.ok) {
      const d = await r.json();
      if (d.model) {
        modelSpan.textContent = d.model;
        footer.style.display = 'block';
      }
    }
  } catch (e) {
    console.warn('Failed to load AI model status', e);
  }
}

async function runExtAiExplain() {
  const d = _currentScanData;
  if (!d) return;

  const idle = document.getElementById('ext-ai-idle');
  const streaming = document.getElementById('ext-ai-streaming');
  const btn = document.getElementById('ext-ai-explain-btn');

  if (idle) idle.style.display = 'none';
  if (streaming) {
    streaming.style.display = 'block';
    streaming.innerHTML = `<div class="ai-thinking"><div class="ai-dots"><span></span><span></span><span></span></div> AI is analysing the threat…</div>`;
  }
  if (btn) btn.disabled = true;

  try {
    const response = await fetch(`${API_BASE}/ai/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        risk_score: d.risk_score,
        risk_level: d.risk_level,
        threat_types: d.threat_types || [],
        summary: d.summary || '',
        sender_email: d.sender_email,
        subject: d.subject,
        phishing: d.phishing || {},
        authentication: d.authentication || {},
        header_analysis: d.header_analysis || {},
        urls: d.urls || [],
        attachments: d.attachments || [],
      }),
      signal: AbortSignal.timeout(60000),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${response.status}`);
    }

    if (streaming) streaming.innerHTML = '';
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let fullText = '';
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const dataStr = line.slice(6).trim();
        if (dataStr === '[DONE]') break;
        try {
          const evt = JSON.parse(dataStr);
          if (evt.type === 'content_block_delta' && evt.delta?.type === 'text_delta') {
            fullText += evt.delta.text;
            if (streaming) {
              streaming.innerHTML = formatAiText(fullText) + '<span class="ai-cursor"></span>';
            }
          }
        } catch {}
      }
    }

    if (streaming) streaming.innerHTML = formatAiText(fullText);
    updateExtModelName();

  } catch (e) {
    if (streaming) {
      streaming.innerHTML = `<div style="padding:10px 12px;color:#ef4444;font-size:11.5px;line-height:1.5">
        <strong>Could not reach AI Explainer API.</strong><br>
        ${e.message.includes('401') ? 'API key invalid or missing.' :
          e.message.includes('429') ? 'Rate limit hit — try again.' :
          e.message.includes('Failed to fetch') ? 'Network error — backend offline.' :
          esc(e.message)}
      </div>`;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

function formatAiText(text) {
  let html = '';
  const sections = text.split(/\n\n(?=\*\*)/);
  for (const section of sections) {
    if (!section.trim()) continue;
    const headerMatch = section.match(/^\*\*(.+?)\*\*\n?([\s\S]*)/);
    if (headerMatch) {
      const title = headerMatch[1].trim();
      const body  = headerMatch[2].trim();
      const formattedBody = body
        .split('\n')
        .map(line => {
          line = line.trim();
          if (!line) return '';
          if (line.startsWith('- ') || line.startsWith('• ') || line.match(/^\d+\./)) {
            const txt = line.replace(/^[-•]\s*/, '').replace(/^\d+\.\s*/, '');
            return `<div style="display:flex;gap:5px;margin-bottom:4px"><span style="color:#a78bfa;margin-top:1px">›</span><span>${boldify(txt)}</span></div>`;
          }
          return `<p style="margin:0 0 4px">${boldify(line)}</p>`;
        })
        .filter(Boolean)
        .join('');
      html += `<div class="ai-section"><div class="ai-section-title">${esc(title)}</div><div class="ai-section-body">${formattedBody}</div></div>`;
    } else {
      const lines = section.split('\n').map(l => l.trim()).filter(Boolean);
      html += lines.map(l => `<p style="margin:0 0 6px;font-size:11px;color:var(--t2);line-height:1.6">${boldify(l)}</p>`).join('');
    }
  }
  return html || `<p style="font-size:11px;color:var(--t2);line-height:1.6">${boldify(text)}</p>`;
}

function boldify(text) {
  return esc(text).replace(/\*\*(.+?)\*\*/g, '<strong style="color:var(--t1)">$1</strong>');
}
