// SecureMail — Content Script
// Injects threat banners + link warnings into Gmail and Outlook

let _overlayVisible = false;
let _scanDebounce   = null;

// ── Init ──────────────────────────────────────────────────────────────────────
(function init() {
  detectPlatform();
  observeEmailOpen();
  interceptLinks();
})();

function detectPlatform() {
  const host = location.hostname;
  if (host.includes('mail.google.com'))        return 'gmail';
  if (host.includes('outlook.live.com'))       return 'outlook';
  if (host.includes('outlook.office'))         return 'outlook365';
  return 'unknown';
}

// ── Watch for email open (Gmail / Outlook MutationObserver) ──────────────────
function observeEmailOpen() {
  const observer = new MutationObserver(() => {
    clearTimeout(_scanDebounce);
    _scanDebounce = setTimeout(tryAutoScan, 1200);
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

async function tryAutoScan() {
  // Only auto-scan if the user is viewing an open email
  const emailEl = getEmailElement();
  if (!emailEl) return;

  // Avoid re-scanning the same email
  const sig = emailEl.innerText.slice(0, 120);
  if (window._lastSig === sig) return;
  window._lastSig = sig;

  const text = emailEl.innerText.trim().slice(0, 8000);
  if (!text || text.length < 50) return;

  // Grab subject and sender for metadata
  const platform = detectPlatform();
  let subject = '', senderName = '', senderEmail = '';
  if (platform === 'gmail') {
    subject     = document.querySelector('.hP')?.innerText?.trim() || '';
    senderName  = document.querySelector('.go')?.innerText?.trim() || '';
    senderEmail = document.querySelector('.gD')?.getAttribute('email') || '';
  } else if (platform !== 'unknown') {
    subject     = (document.querySelector('[data-testid="subject"]') || document.querySelector('.allowTextSelection h1'))?.innerText?.trim() || '';
    const sEl   = document.querySelector('[data-testid="SenderField"] .lpc-hoverTarget') || document.querySelector('.OZZZK');
    const raw   = sEl?.innerText?.trim() || '';
    const match = raw.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
    senderEmail = match ? match[0] : '';
    senderName  = raw.replace(match?.[0] || '', '').replace(/[<>]/g, '').trim();
  }

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'SCAN_EMAIL', text });
    if (resp?.success && resp.result) {
      // Attach metadata so popup can display it without re-extracting
      resp.result._emailMeta = { platform, subject, sender: senderEmail || senderName };
      await chrome.storage.session.set({ lastResult: resp.result });
      showInlineResult(resp.result, emailEl);
    }
  } catch { /* extension may be reloading */ }
}

// ── Get email body element ────────────────────────────────────────────────────
function getEmailElement() {
  // Gmail
  const gEl = document.querySelector('.a3s.aiL');
  if (gEl && gEl.innerText.trim().length > 30) return gEl;
  // Outlook
  const oEl = document.querySelector('[aria-label="Message body"], .ReadingPaneContent .allowTextSelection');
  if (oEl && oEl.innerText.trim().length > 30) return oEl;
  return null;
}

// ── Inline threat banner ──────────────────────────────────────────────────────
function showInlineResult(result, anchorEl) {
  const level = result.risk_level || 'unknown';
  if (level === 'clean') return; // Don't annoy on clean emails

  // Remove old banner if exists
  document.getElementById('securemail-banner')?.remove();

  const colors = {
    critical: { bg: 'rgba(239,68,68,0.12)',   border: 'rgba(239,68,68,0.35)',   text: '#ef4444' },
    high:     { bg: 'rgba(249,115,22,0.10)',  border: 'rgba(249,115,22,0.3)',   text: '#f97316' },
    medium:   { bg: 'rgba(245,158,11,0.10)',  border: 'rgba(245,158,11,0.3)',   text: '#f59e0b' },
    low:      { bg: 'rgba(132,204,22,0.08)',  border: 'rgba(132,204,22,0.25)',  text: '#84cc16' },
  };
  const c = colors[level] || colors.medium;

  const threats = (result.threat_types || []).filter(t => t !== 'clean').join(', ');
  const score   = result.risk_score ?? '?';
  const auth    = result.authentication || {};
  const authStr = ['spf','dkim','dmarc'].map(k =>
    `${k.toUpperCase()}: <strong style="color:${auth[k]==='pass'?'#22c55e':'#ef4444'}">${(auth[k]||'?').toUpperCase()}</strong>`
  ).join(' &nbsp;·&nbsp; ');

  const banner = document.createElement('div');
  banner.id = 'securemail-banner';
  banner.innerHTML = `
    <div style="
      display:flex;align-items:flex-start;gap:12px;
      padding:12px 16px;margin:8px 0 12px;
      background:${c.bg};border:1px solid ${c.border};border-radius:10px;
      font-family:-apple-system,'Inter',sans-serif;font-size:13px;
    ">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
           stroke="${c.text}" stroke-width="2.5" style="flex-shrink:0;margin-top:1px">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">
          <strong style="color:${c.text};font-size:13.5px">
            SecureMail: ${level.toUpperCase()} RISK (${score}/100)
          </strong>
          <span style="background:${c.bg};border:1px solid ${c.border};color:${c.text};
                       font-size:10px;font-weight:700;padding:1px 8px;border-radius:20px;letter-spacing:0.05em">
            ${threats || level}
          </span>
        </div>
        <div style="color:#94a3b8;font-size:12px;margin-bottom:6px;line-height:1.5">
          ${escHtml(result.summary || '')}
        </div>
        <div style="font-size:11.5px;color:#64748b">${authStr}</div>
      </div>
      <button id="securemail-dismiss" style="
        background:none;border:none;cursor:pointer;color:#475569;
        font-size:18px;line-height:1;padding:0;flex-shrink:0;
      " title="Dismiss">×</button>
    </div>
  `;

  // Wire dismiss button via addEventListener — no inline onclick (MV3 CSP)
  banner.querySelector('#securemail-dismiss').addEventListener('click', () => banner.remove());

  anchorEl.parentNode?.insertBefore(banner, anchorEl);
}

// ── Link warning overlay ──────────────────────────────────────────────────────
function interceptLinks() {
  document.addEventListener('mouseover', async (e) => {
    const link = e.target.closest('a[href]');
    if (!link) return;
    const href = link.href;
    if (!href.startsWith('http')) return;

    // Skip already-checked links
    if (link.dataset.smChecked) return;
    link.dataset.smChecked = '1';

    // Only check visually suspicious-looking links (different text vs href)
    const linkText = link.textContent.trim();
    if (!linkText || !linkText.includes('.')) return;
    const textDomain = extractDomain(linkText);
    const hrefDomain = extractDomain(href);
    if (!textDomain || !hrefDomain || textDomain === hrefDomain) return;

    // Domain mismatch — check in background
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'SCAN_URL', url: href });
      if (resp?.result?.scan_result?.risk_level === 'high') {
        link.style.textDecoration = 'line-through';
        link.style.color          = '#ef4444';
        link.title = `⚠ SecureMail: Malicious URL (${resp.result.scan_result.detections} detections)`;
      }
    } catch { /* silent */ }
  });
}

// ── Receive messages from background ─────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'SHOW_RESULT') {
    const emailEl = getEmailElement();
    if (emailEl) showInlineResult(msg.result, emailEl);
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function extractDomain(str) {
  try {
    const url = str.startsWith('http') ? new URL(str) : new URL('https://' + str);
    return url.hostname.replace('www.', '');
  } catch { return null; }
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}
