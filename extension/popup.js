// SecureMail Extension — Popup Script
// MV3-compliant: all events via addEventListener, no inline handlers.
// Auto-detects open Gmail/Outlook email and scans it on popup open.

'use strict';

let API_BASE = 'http://localhost:8000/api';
let _pendingEmailData = null; // extracted email waiting for user to click "Scan This Email"
let _currentPlatform  = null; // platform of the active mail-client tab
let _currentTab       = null; // active tab reference

// ─────────────────────────────────────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  try {
    await loadSettings();
  } catch (e) {
    console.warn('SecureMail: loadSettings failed', e);
  }

  // ── Wire all static button events (MV3: no inline handlers) ────────────────
  document.getElementById('btn-scan-now')?.addEventListener('click', runManualScan);
  document.getElementById('btn-demo')?.addEventListener('click', runDemo);
  document.getElementById('btn-save-settings')?.addEventListener('click', saveSettings);
  document.getElementById('btn-test-backend')?.addEventListener('click', checkBackend);
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

  // ── Backend check + tab detection ──────────────────────────────────────────
  let tab = null;
  try {
    [, tab] = await Promise.all([checkBackend(), getActiveTab()]);
  } catch (e) {
    console.warn('SecureMail: init parallel tasks failed', e);
    try { tab = await getActiveTab(); } catch { /* give up */ }
  }

  _currentTab      = tab;
  _currentPlatform = getPlatform(tab?.url || '');

  if (_currentPlatform) {
    // ── On a mail client ────────────────────────────────────────────────────
    showPlatformBar(_currentPlatform, 'Detecting open email…');
    showScanPanel('auto');
    showDetectingSpinner(true);

    // Load any previous result silently into Result tab (user can view it via tab click)
    // But NEVER short-circuit here — always detect what's currently open on screen
    let stored = {};
    try { stored = await chrome.storage.session.get('lastResult'); } catch { /* ignore */ }
    if (stored.lastResult) renderResult(stored.lastResult);

    // Always detect the currently open email — this is the source of truth
    await detectEmailOnPage(_currentTab, _currentPlatform, stored.lastResult ?? null);

  } else {
    // ── Not a mail client — show manual scan UI ─────────────────────────────
    showScanPanel('manual');
    let stored = {};
    try { stored = await chrome.storage.session.get('lastResult'); } catch { /* ignore */ }
    if (stored.lastResult) renderResult(stored.lastResult);
  }
});

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
    // Body: the main email content area
    const bodyEl = document.querySelector('.a3s.aiL') || document.querySelector('.ii.gt .a3s');
    if (!bodyEl || bodyEl.innerText.trim().length < 30) return null;

    // Subject
    const subjectEl = document.querySelector('.hP');
    const subject = subjectEl?.innerText?.trim() || document.title.replace(' - Gmail', '').trim();

    // Sender name and email
    const fromNameEl  = document.querySelector('.go');
    const fromEmailEl = document.querySelector('.gD');
    const senderName  = fromNameEl?.innerText?.trim()  || '';
    const senderEmail = fromEmailEl?.getAttribute('email') || fromEmailEl?.innerText?.trim() || '';

    // Reply-To
    const replyToEl   = document.querySelector('[data-tooltip*="reply"]');
    const replyTo     = replyToEl?.getAttribute('email') || '';

    // Date
    const dateEl = document.querySelector('.g3');
    const date   = dateEl?.getAttribute('title') || dateEl?.innerText?.trim() || '';

    const body = bodyEl.innerText.trim().slice(0, 10000);

    // Build a pseudo RFC2822 email for the backend parser
    const from = senderEmail
      ? (senderName ? `${senderName} <${senderEmail}>` : senderEmail)
      : (senderName || 'unknown@unknown.com');

    const raw = [
      `From: ${from}`,
      replyTo          ? `Reply-To: ${replyTo}`       : '',
      subject          ? `Subject: ${subject}`         : '',
      date             ? `Date: ${date}`               : '',
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

    const raw = [
      `From: ${from}`,
      subject ? `Subject: ${subject}` : '',
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
      : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Scan This Email`;
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

  try {
    const r = await fetch(`${API_BASE.replace('/api', '')}/health`, { signal: AbortSignal.timeout(4000) });
    const d = await r.json();
    if (d.status === 'healthy') {
      if (dot) { dot.className = 'bs-dot bs-online'; }
      if (txt) txt.textContent = 'Backend online ✓';
      if (sd)  { sd.className = 'sdot sdot-active'; }
      if (st)  { st.textContent = 'Active'; }
      return true;
    }
  } catch { /* fall through */ }

  if (dot) dot.className = 'bs-dot bs-offline';
  if (txt) txt.textContent = 'Backend offline — start uvicorn';
  if (sd)  { sd.className = 'sdot sdot-offline'; }
  if (st)  { st.textContent = 'Offline'; }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS
// ─────────────────────────────────────────────────────────────────────────────
async function loadSettings() {
  const s = await chrome.storage.local.get(['backend', 'vt', 'abuse']);
  if (s.backend) {
    API_BASE = s.backend + '/api';
    const el = document.getElementById('cfg-backend');
    if (el) el.value = s.backend;
  }
  const vt = document.getElementById('cfg-vt');
  const ab = document.getElementById('cfg-abuse');
  if (s.vt    && vt) vt.value = s.vt;
  if (s.abuse && ab) ab.value = s.abuse;
}

async function saveSettings() {
  const backend = document.getElementById('cfg-backend').value.trim().replace(/\/$/, '');
  const vt      = document.getElementById('cfg-vt').value.trim();
  const abuse   = document.getElementById('cfg-abuse').value.trim();

  await chrome.storage.local.set({ backend, vt, abuse });
  API_BASE = backend + '/api';

  if (vt || abuse) {
    try {
      await fetch(`${API_BASE}/settings/keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ virustotal_api_key: vt, abuseipdb_api_key: abuse }),
        signal: AbortSignal.timeout(5000),
      });
    } catch { /* keys still saved locally */ }
  }

  const ok = await checkBackend();
  showErr('settings-err', ok ? '' : 'Saved — but backend not reachable at this URL');
  if (ok) switchTab('scan');
}

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
    const r = await fetch(`${API_BASE}/scan/demo`, { signal: AbortSignal.timeout(60000) });
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
  const r = await fetch(`${API_BASE}/scan/email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw_email: raw }),
    signal: AbortSignal.timeout(60000),
  });
  autoStep('Checking VirusTotal & AbuseIPDB…');
  const d = await r.json();
  if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
  return d;
}

async function callScanUrl(url) {
  const r = await fetch(`${API_BASE}/scan/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(30000),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
  return { ...d, _type: 'url' };
}

// ─────────────────────────────────────────────────────────────────────────────
// RESULT RENDERER
// ─────────────────────────────────────────────────────────────────────────────
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
    const lvl = vt.risk_level || 'unknown';
    content.innerHTML = `
      <div class="result-card ${lvl}">
        <div class="risk-header">
          <div class="risk-score ${lvl}">${vt.detections || 0}</div>
          <div>
            <div class="${badgeClass(lvl)}" style="margin-bottom:5px">${lvl.toUpperCase()}</div>
            <div style="font-size:11px;color:#64748b">${vt.detections||0}/${vt.total_engines||0} engines flagged</div>
          </div>
        </div>
        <div class="summary">${esc(data.url || '')}</div>
        ${vt.categories?.length ? `<div style="font-size:11px;color:#64748b;margin-top:6px">Categories: ${vt.categories.join(', ')}</div>` : ''}
      </div>
      ${vt.permalink ? `<a href="${vt.permalink}" target="_blank" rel="noopener noreferrer" style="display:block;font-size:11px;color:#3b82f6;text-align:center;margin-top:6px">View on VirusTotal →</a>` : ''}
    `;
    return;
  }

  // ── Full email result ─────────────────────────────────────────────────────
  const lvl   = data.risk_level || 'unknown';
  const score = data.risk_score ?? '?';
  const auth  = data.authentication || {};
  const h     = data.header_analysis || {};
  const urls  = data.urls || [];
  const atts  = data.attachments || [];
  const ph    = data.phishing || {};
  const meta  = data._emailMeta || {};

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

  const malUrl = urls.find(u => u.vt_result?.detections > 0);
  if (malUrl) findings.push({ dot: 'fd-red', txt: `Malicious URL: ${esc(malUrl.domain)}` });
  const malAtt = atts.find(a => a.vt_result?.detections > 0);
  if (malAtt) findings.push({ dot: 'fd-red', txt: `Malicious file: ${esc(malAtt.filename)}` });

  if (!findings.length && lvl === 'clean') {
    findings.push({ dot: 'fd-green', txt: 'No threats detected' });
    findings.push({ dot: 'fd-green', txt: 'SPF / DKIM / DMARC all passed' });
  }

  // Sender line for the meta strip
  const senderLine = data.sender_email || meta.sender || h.from_email || '';
  const subjectLine = data.subject || meta.subject || '';
  const skipped = data.urls_skipped > 0 ? `<span style="color:#f59e0b;font-size:10.5px">${data.urls_skipped} URL${data.urls_skipped > 1 ? 's' : ''} not scanned (rate limit)</span>` : '';

  content.innerHTML = `
    ${senderLine || subjectLine ? `
    <div class="scan-meta">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
        <polyline points="22,6 12,13 2,6"/>
      </svg>
      <span>${senderLine ? `<strong>${esc(senderLine)}</strong>` : ''}${subjectLine ? ` · ${esc(subjectLine)}` : ''}</span>
    </div>` : ''}

    <div class="result-card ${lvl}">
      <div class="risk-header">
        <div class="risk-score ${lvl}">${score}</div>
        <div>
          <div class="${badgeClass(lvl)}" style="margin-bottom:4px">${lvl.toUpperCase()}</div>
          <div style="font-size:10.5px;color:#64748b">${(data.threat_types||[]).filter(t=>t!=='clean').join(', ')||'No threats'}</div>
        </div>
      </div>
      <div class="summary">${esc(data.summary || '')}</div>
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

    <div class="btn-row" style="margin-top:10px">
      <button class="btn btn-secondary btn-sm" data-action="open-dashboard" style="flex:1">Full Report</button>
      ${lvl !== 'clean' ? `<button class="btn btn-secondary btn-sm" data-action="save-log" style="flex:1">Save Log</button>` : ''}
    </div>
    <button class="btn-rescan" data-action="rescan">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
      </svg>
      Scan Again
    </button>
  `;
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
  const base = document.getElementById('cfg-backend')?.value || 'http://localhost:8000';
  chrome.tabs.create({ url: base });
}

async function saveToDashboard() {
  const stored = await chrome.storage.session.get('lastResult');
  if (!stored.lastResult) return;
  try {
    await fetch(`${API_BASE}/forensics`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stored.lastResult),
      signal: AbortSignal.timeout(5000),
    });
  } catch { /* log already auto-saved by backend for non-clean results */ }
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
