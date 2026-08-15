// SecureMail — Background Service Worker
// Handles: context menus, notifications, badge state, message passing

const DEFAULT_API = 'http://localhost:8000/api';

// ── Install: create context menus ─────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'securemail-scan-selection',
    title: 'SecureMail: Scan selected text',
    contexts: ['selection'],
  });
  chrome.contextMenus.create({
    id: 'securemail-scan-link',
    title: 'SecureMail: Check this link',
    contexts: ['link'],
  });
  chrome.contextMenus.create({
    id: 'securemail-scan-page',
    title: 'SecureMail: Scan this email page',
    contexts: ['page'],
    documentUrlPatterns: [
      'https://mail.google.com/*',
      'https://outlook.live.com/*',
      'https://outlook.office.com/*',
      'https://outlook.office365.com/*',
    ],
  });

  console.log('SecureMail extension installed');
});

// ── Context menu clicks ───────────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const api = await getApiBase();

  if (info.menuItemId === 'securemail-scan-selection' && info.selectionText) {
    await scanAndNotify(api, 'email', info.selectionText, tab);
  }

  if (info.menuItemId === 'securemail-scan-link' && info.linkUrl) {
    await scanAndNotify(api, 'url', info.linkUrl, tab);
  }

  if (info.menuItemId === 'securemail-scan-page') {
    // Inject content script to grab email body, then scan
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const gmailBody = document.querySelector('.a3s.aiL, .ii.gt div');
          if (gmailBody) return gmailBody.innerText.trim().slice(0, 8000);
          const olBody = document.querySelector('[aria-label="Message body"], .ReadingPaneContent');
          if (olBody) return olBody.innerText.trim().slice(0, 8000);
          return null;
        },
      });
      const text = results?.[0]?.result;
      if (text) {
        await scanAndNotify(api, 'email', text, tab);
      } else {
        showNotification('SecureMail', 'No email detected on this page. Open an email first.', 'warning');
      }
    } catch (e) {
      showNotification('SecureMail Error', e.message, 'error');
    }
  }
});

// ── Message passing from content script ──────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'SCAN_EMAIL') {
    (async () => {
      try {
        const base = await getApiBase();
        const result = await scanEmail(base, msg.text);
        updateBadge(result.risk_level, sender.tab?.id);
        // Store for popup
        await chrome.storage.session.set({ lastResult: result });
        sendResponse({ success: true, result });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true; // async response
  }

  if (msg.type === 'SCAN_URL') {
    (async () => {
      try {
        const base = await getApiBase();
        const result = await scanUrl(base, msg.url);
        sendResponse({ success: true, result });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (msg.type === 'GET_STATUS') {
    checkHealth().then(ok => sendResponse({ online: ok }));
    return true;
  }
});

// ── Web App Session Sync Listener ───────────────────────────────────────────
chrome.runtime.onMessageExternal.addListener((msg, sender, sendResponse) => {
  const allowedOrigins = ['http://localhost:8000', 'http://127.0.0.1:8000'];
  if (sender.origin && !allowedOrigins.some(o => sender.origin.startsWith(o))) {
    console.warn('SecureMail background: rejected external message from untrusted origin', sender.origin);
    sendResponse({ success: false, error: 'Unauthorized origin' });
    return;
  }

  if (msg.type === 'SECUREMAIL_AUTH_SYNC' && msg.idToken) {
    chrome.storage.local.set({
      authToken: msg.idToken,
      tokenExpiry: msg.expiresAt || (Date.now() + 3600 * 1000),
      userEmail: msg.userEmail || ''
    }).then(() => {
      console.log('SecureMail background: synced auth session from Web App');
      sendResponse({ success: true });
    }).catch(err => {
      sendResponse({ success: false, error: err.message });
    });
    return true;
  }
});

async function getFirebaseKey() {
  const data = await chrome.storage.local.get(['firebaseApiKey', 'apiBaseUrl']);
  if (data.firebaseApiKey) return data.firebaseApiKey;
  const baseUrl = data.apiBaseUrl || 'http://localhost:8000/api';
  try {
    const resp = await fetch(`${baseUrl}/auth/config`);
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

async function getValidToken() {
  const data = await chrome.storage.local.get(['authToken', 'refreshToken', 'tokenExpiry']);
  if (!data.authToken) return null;
  const now = Date.now();
  if (data.tokenExpiry && (data.tokenExpiry - now) > 300000) {
    return data.authToken;
  }
  if (!data.refreshToken) {
    await chrome.storage.local.remove(['authToken', 'refreshToken', 'tokenExpiry', 'userEmail']);
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
      await chrome.storage.local.remove(['authToken', 'refreshToken', 'tokenExpiry', 'userEmail']);
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
    console.warn('SecureMail background: token refresh failed', e);
    await chrome.storage.local.remove(['authToken', 'refreshToken', 'tokenExpiry', 'userEmail']);
    return null;
  }
}

// ── Core scan functions ───────────────────────────────────────────────────────
async function scanEmail(api, text) {
  const token = await getValidToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const r = await fetch(`${api}/scan/email`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ raw_email: text }),
    signal: AbortSignal.timeout(45000),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
  return d;
}

async function scanUrl(api, url) {
  const token = await getValidToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const r = await fetch(`${api}/scan/url`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(30000),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
  return { ...d, _type: 'url' };
}

async function scanAndNotify(api, type, text, tab) {
  // Show scanning badge
  chrome.action.setBadgeText({ text: '…', tabId: tab?.id });
  chrome.action.setBadgeBackgroundColor({ color: '#3b82f6', tabId: tab?.id });

  try {
    const result = type === 'url'
      ? await scanUrl(api, text)
      : await scanEmail(api, text);

    const level = result.risk_level || result.scan_result?.risk_level || 'unknown';
    updateBadge(level, tab?.id);

    // Store result for popup
    await chrome.storage.session.set({ lastResult: result });

    // Send to content script for inline overlay
    if (tab?.id) {
      chrome.tabs.sendMessage(tab.id, { type: 'SHOW_RESULT', result }).catch(() => {});
    }

    // Notify for threats
    if (['critical', 'high', 'medium'].includes(level)) {
      const summary = result.summary || `Risk level: ${level}`;
      showNotification(
        `⚠ SecureMail: ${level.toUpperCase()} threat`,
        summary.slice(0, 120),
        level,
      );
    }
  } catch (e) {
    chrome.action.setBadgeText({ text: '!', tabId: tab?.id });
    chrome.action.setBadgeBackgroundColor({ color: '#64748b', tabId: tab?.id });
    console.error('SecureMail scan error:', e);
  }
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function updateBadge(level, tabId) {
  const map = {
    critical: { text: '!!', color: '#ef4444' },
    high:     { text: '!',  color: '#f97316' },
    medium:   { text: '~',  color: '#f59e0b' },
    low:      { text: '·',  color: '#84cc16' },
    clean:    { text: '',   color: '#22c55e' },
  };
  const { text, color } = map[level] || { text: '?', color: '#64748b' };
  const opts = tabId ? { text, tabId } : { text };
  const copts = tabId ? { color, tabId } : { color };
  chrome.action.setBadgeText(opts);
  chrome.action.setBadgeBackgroundColor(copts);
}

// ── Notifications ─────────────────────────────────────────────────────────────
function showNotification(title, message, type) {
  const iconMap = {
    critical: 'icons/icon48.png',
    high:     'icons/icon48.png',
    medium:   'icons/icon48.png',
    warning:  'icons/icon48.png',
    error:    'icons/icon48.png',
  };
  chrome.notifications.create({
    type: 'basic',
    iconUrl: iconMap[type] || 'icons/icon48.png',
    title,
    message,
    priority: ['critical', 'high'].includes(type) ? 2 : 1,
  });
}

// ── Health + helpers ──────────────────────────────────────────────────────────
async function checkHealth() {
  try {
    const base = await getApiBase();
    const r = await fetch(base.replace('/api', '') + '/health', {
      signal: AbortSignal.timeout(3000),
    });
    const d = await r.json();
    return d.status === 'healthy';
  } catch {
    return false;
  }
}

async function getApiBase() {
  const s = await chrome.storage.local.get('backend');
  return (s.backend || 'http://localhost:8000') + '/api';
}
