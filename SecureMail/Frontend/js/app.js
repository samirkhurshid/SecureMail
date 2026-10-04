// SecureMail Main Client Application & Inspection Controller

const API = (typeof window._resolveBackendApi === 'function')
  ? window._resolveBackendApi()
  : (localStorage.getItem('sm_api_base') || window._SECUREMAIL_API_BASE || ((window.location.protocol === 'file:' || !window.location.origin || window.location.origin === 'null' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') ? 'http://localhost:8000/api' : `${window.location.origin}/api`));


// Authenticated fetch — automatically attaches fresh Firebase ID token and retries on 401
async function apiFetch(url, opts={}) {
  let token = window._authToken;
  if (window._fbAuth && window._fbAuth.currentUser) {
    try {
      token = await window._fbAuth.currentUser.getIdToken();
      window._authToken = token;
    } catch (e) {}
  }
  const isFormData = opts.body instanceof FormData;
  const headers = { ...(isFormData ? {} : {'Content-Type':'application/json'}), ...(opts.headers||{}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  let res = await fetch(url, { ...opts, headers });
  
  // If 401 and user is logged in, try forcing a fresh token once and retry
  if (res.status === 401 && window._fbAuth && window._fbAuth.currentUser) {
    try {
      const freshToken = await window._fbAuth.currentUser.getIdToken(true);
      if (freshToken) {
        window._authToken = freshToken;
        headers['Authorization'] = `Bearer ${freshToken}`;
        res = await fetch(url, { ...opts, headers });
      }
    } catch (e) {}
  }

  if (res.status === 403) {
    try {
      const clone = res.clone();
      const d = await clone.json();
      if (d.detail === 'account_pending_deletion') {
        if (window._fbAuth) await window._fbAuth.signOut();
        showPendingDeletionScreen();
        return res;
      }
    } catch (e) {}
  }
  return res;
}

// ── Navigation ────────────────────────────────
const TITLES = {dashboard:'Dashboard',scan:'Email Scanner',threats:'Threat Analysis','threat-intel':'Threat Intelligence Vault',forensics:'Forensic Logs','audit-trail':'Compliance Audit Trail','org-management':'Team & Organization Sandbox',headers:'Header Analysis',extension:'Browser Extension',settings:'Settings',account:'Account'};
const AUTH_REQUIRED_PAGES = ['dashboard', 'forensics', 'audit-trail', 'org-management', 'account'];

function nav(page) {
  // Gate auth-required pages for guests
  if (AUTH_REQUIRED_PAGES.includes(page) && !window._authUser) {
    showAuthScreen();
    showSignIn();
    toast(`Please sign in to access ${TITLES[page] || page}`, 'info');
    return;
  }
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  const targetPage = document.getElementById('page-'+page);
  if(targetPage) targetPage.classList.add('active');
  const el = document.getElementById('nav-'+page);
  if(el) el.classList.add('active');
  const tt = document.getElementById('topbar-title');
  if (tt) tt.textContent = TITLES[page]||page;
  if(page==='forensics') loadForensics();
  if(page==='audit-trail') loadAuditTrailPage();
  if(page==='org-management') loadOrgManagement();
  if(page==='dashboard') loadDashboard();
  if(page==='threats')   loadThreatFeed();
  if(page==='threat-intel') loadThreatIntelDashboard();
  if(page==='settings')  loadSettings();
  if(page==='account')   loadAccountPage();
}

// ── Toast ─────────────────────────────────────
let _tt;
function toast(msg, type='') {
  let t = document.getElementById('toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.className = type ? `show ${type}` : 'show';
  clearTimeout(_tt);
  _tt = setTimeout(() => { if (t) t.className = ''; }, 3200);
}

// ── Helpers ───────────────────────────────────
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function riskColor(l){return{critical:'var(--red)',high:'var(--orange)',medium:'var(--amber)',low:'var(--lime)',clean:'var(--green)'}[l]||'var(--t3)'}
function riskTag(l){const m={critical:'tag-critical',high:'tag-high',medium:'tag-medium',low:'tag-low',clean:'tag-clean'};return`<span class="tag ${m[l]||'tag-info'}">${(l||'').toUpperCase()}</span>`}
function authC(v){if(!v||v==='unknown')return'unknown';if(v==='pass')return'pass';if(v==='fail')return'fail';return'softfail'}
function authClass(v){return authC(v)}
function infoRow(l,v){return`<div class="info-row"><span class="info-label">${l}</span><span class="info-val">${v}</span></div>`}
function loader(id,on){const el=document.getElementById(id);if(el)el.classList[on?'add':'remove']('on')}
function errShow(id,msg){const el=document.getElementById(id);if(!el)return;el.textContent=msg;el.classList[msg?'add':'remove']('on')}
function threatIcon(type,sev){
  const icons={
    phishing:'<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    malicious_attachment:'<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>',
    suspicious_url:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    header_anomaly:'<polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/>',
    clean_email:'<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    clean:'<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    email_scan:'<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>'
  };
  const bg={critical:'var(--red-dim)',high:'var(--orange-dim)',medium:'var(--amber-dim)',low:'var(--lime-dim)',clean:'var(--green-dim)'}[sev]||'var(--cyan-dim)';
  const sc={critical:'var(--red)',high:'var(--orange)',medium:'var(--amber)',low:'var(--lime)',clean:'var(--green)'}[sev]||'var(--cyan)';
  const svgPath = icons[type]||(sev==='clean'?icons.clean_email:icons.phishing);
  return`<div class="threat-icon" style="background:${bg}"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${sc}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${svgPath}</svg></div>`;
}

// ── Dashboard ─────────────────────────────────
async function loadDashboard() {
  try {
    const [statsR, logsR] = await Promise.all([apiFetch(`${API}/forensics/stats`), apiFetch(`${API}/forensics?limit=50`)]);
    if (!statsR.ok || !logsR.ok) return;
    const stats = await statsR.json();
    const logsData = await logsR.json();
    const logs = logsData.logs||[];

    // Stat cards
    const elTot = document.getElementById('ov-total'); if (elTot) elTot.textContent = stats.total??0;
    const byRisk = stats.by_risk_level||{};
    const threats = (byRisk.critical||0)+(byRisk.high||0)+(byRisk.medium||0);
    const elThr = document.getElementById('ov-threats'); if (elThr) elThr.textContent = threats;
    const elCrit = document.getElementById('ov-critical-sub'); if (elCrit) elCrit.textContent = `${(byRisk.critical||0)+(byRisk.high||0)} high/crit · ${byRisk.clean||0} clean`;
    const elAtt = document.getElementById('ov-attach'); if (elAtt) elAtt.textContent = stats.total_attachments??0;
    const elAttSub = document.getElementById('ov-attach-sub'); if (elAttSub) elAttSub.textContent = 'scanned';
    const elLnk = document.getElementById('ov-links'); if (elLnk) elLnk.textContent = stats.total_urls??0;
    const elLnkSub = document.getElementById('ov-links-sub'); if (elLnkSub) elLnkSub.textContent = 'all time';
    const elTod = document.getElementById('ov-today'); if (elTod) elTod.textContent = `+${stats.total??0} total`;

    // Topbar badge
    const threatCountEl = document.getElementById('threats-today-count');
    if (threatCountEl) {
      threatCountEl.textContent = `${threats} threat${threats!==1?'s':''} detected`;
    }

    // Recent scans feed (displays latest scanned items so user sees all activity)
    const recentScans = logs.slice(0, 6);
    const recentListEl = document.getElementById('recent-threats-list');
    if (recentListEl) {
      if(!recentScans.length){
        recentListEl.innerHTML = '<div style="padding:32px;text-align:center;color:var(--t3);font-size:13px">No recent scans yet 🎉</div>';
      } else {
        recentListEl.innerHTML = recentScans.map(l=>{
          const isClean = l.risk_level === 'clean';
          const detectedThreats = (l.threat_types||[]).filter(t=>t!=='clean');
          const type = isClean ? 'clean_email' : (detectedThreats[0] || 'email_scan');
          const typeTitle = isClean ? 'Clean Email' : type.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
          const ago = l.scanned_at ? timeAgo(l.scanned_at) : 'just now';
          return `<div class="threat-item" onclick="viewLog('${l.log_id||l.scan_id}')">
            ${threatIcon(type, l.risk_level||'clean')}
            <div class="threat-body">
              <div class="threat-name">${esc(typeTitle)}</div>
              <div class="threat-desc">${esc(l.summary||l.subject||'—')}</div>
              <div class="threat-meta">From: ${esc(l.sender_email||'—')} · ${ago}</div>
            </div>
            ${riskTag(l.risk_level||'clean')}
          </div>`;
        }).join('');
      }
    }

    // Threat breakdown
    const typeMap = stats.threat_types||{};
    const sorted = Object.entries(typeMap).filter(([k]) => k !== 'clean').sort((a,b)=>b[1]-a[1]).slice(0,5);
    const maxV = sorted[0]?.[1]||1;
    const colors = ['var(--red)','var(--orange)','var(--amber)','var(--lime)','var(--green)'];
    const total2 = Object.values(typeMap).reduce((a,b)=>a+b,0)||1;
    const breakdownEl = document.getElementById('threat-breakdown');
    if (breakdownEl) {
      if (threats === 0 || !sorted.length) {
        breakdownEl.innerHTML = '<div style="padding:28px 12px;text-align:center;color:var(--t3);font-size:13px"><div style="font-size:22px;margin-bottom:6px">🛡️</div><div style="font-weight:600;color:var(--t1);margin-bottom:4px">No threats detected 🎉</div><div style="font-size:11.5px;color:var(--green)">100% of analyzed traffic is clean and verified</div></div>';
      } else {
        breakdownEl.innerHTML = sorted.map(([k,v],i)=>`
          <div style="margin-bottom:14px">
            <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px">
              <span style="color:var(--t2)">${esc(k.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase()))}</span>
              <span style="color:${colors[i%colors.length]};font-weight:600">${Math.round((v/total2)*100)}%</span>
            </div>
            <div class="sbar-wrap"><div class="sbar" style="width:${Math.round((v/maxV)*100)}%;background:${colors[i%colors.length]}"></div></div>
          </div>`).join('');
      }
    }
  } catch(e) { console.warn('Failed to load dashboard:', e); }
}

function timeAgo(iso){
  const d = new Date(iso); const diff = (Date.now()-d)/1000;
  if(diff<60) return Math.round(diff)+'s ago';
  if(diff<3600) return Math.round(diff/60)+' min ago';
  if(diff<86400) return Math.round(diff/3600)+' hr ago';
  return Math.round(diff/86400)+' days ago';
}

// ── Email Scanner ─────────────────────────────
const emailDrop = document.getElementById('email-drop');
emailDrop.addEventListener('dragover',e=>{e.preventDefault();emailDrop.classList.add('over')});
emailDrop.addEventListener('dragleave',()=>emailDrop.classList.remove('over'));
emailDrop.addEventListener('drop',e=>{e.preventDefault();emailDrop.classList.remove('over');if(e.dataTransfer.files[0])readEmlFile(e.dataTransfer.files[0])});
function handleEmlFile(e){if(e.target.files[0])readEmlFile(e.target.files[0])}
function readEmlFile(f){const r=new FileReader();r.onload=e=>document.getElementById('email-input').value=e.target.result;r.readAsText(f)}

// ── Scan Mode State Management (Quick <0.2s vs Deep 87+ VT Engines) ──
let _currentScanMode = 'quick';

function setScanMode(mode) {
  _currentScanMode = mode;
  const btnQ = document.getElementById('btn-mode-quick');
  const btnD = document.getElementById('btn-mode-deep');
  const desc = document.getElementById('scan-mode-desc');
  const scanBtnLabel = document.getElementById('scan-btn-label');
  const icon = document.getElementById('scan-mode-icon');
  
  if (btnQ && btnD) {
    if (mode === 'deep') {
      btnQ.style.background = 'transparent'; btnQ.style.color = 'var(--t2)';
      btnD.style.background = 'var(--accent)'; btnD.style.color = '#fff';
      if (desc) desc.textContent = 'Deep Scan: Queries 87+ VirusTotal AV engines & AbuseIPDB (3-6s)';
      if (scanBtnLabel) scanBtnLabel.textContent = 'Deep Scan (VT)';
      if (icon) icon.textContent = '🛡️';
    } else {
      btnQ.style.background = 'var(--accent)'; btnQ.style.color = '#fff';
      btnD.style.background = 'transparent'; btnD.style.color = 'var(--t2)';
      if (desc) desc.textContent = 'Quick Scan: Instant heuristic, ML classifier & Threat Vault (<200ms)';
      if (scanBtnLabel) scanBtnLabel.textContent = 'Quick Scan';
      if (icon) icon.textContent = '⚡';
    }
  }
}

async function scanEmail(forceDeep = false){
  const raw = document.getElementById('email-input').value.trim();
  if(!raw){errShow('scan-err','Please paste an email first.');return}
  const isDeep = Boolean(forceDeep);
  errShow('scan-err','');
  
  const loaderText = document.getElementById('scan-loader-text');
  if (loaderText) {
    loaderText.textContent = isDeep ? 'Deep Scanning with 87+ VirusTotal Engines & AbuseIPDB…' : 'Running instant heuristics, ML classifier & Threat Vault…';
  }
  loader('scan-loader',true);
  showResultLoading(isDeep ? 'Deep Scanning (VirusTotal 87+ Engines)…' : 'Analyzing instantly…');
  try{
    const r = await apiFetch(`${API}/scan/email`,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({raw_email:raw, deep_scan:isDeep})
    });
    if(r.status === 429) {
      const errData = await r.json().catch(() => ({}));
      const detail = errData.detail || errData;
      const msg = detail.message || "You've used your 5 free scans for today.";
      toast('Daily scan limit reached (5/5). Sign in for unlimited scans.', 'warning');
      errShow('scan-err', msg + ' Sign in for unlimited scanning.');
      showResultReady();
      loader('scan-loader',false);
      loadGuestQuota();
      return;
    }
    const d = await r.json();
    if(!r.ok) throw new Error(d.detail||'Scan failed');
    renderScanResult(d);
    loadGuestQuota();
    if(window._authUser) { setTimeout(() => { loadDashboard().catch(()=>{}); }, 200); }
  }catch(e){errShow('scan-err',e.message);showResultReady()}
  loader('scan-loader',false);
}

function escalateToDeepScan() {
  setScanMode('deep');
  toast('Escalating to Deep Multi-Engine VirusTotal scan…', 'info');
  scanEmail(true);
}

async function runDemo(forceDeep = false){
  nav('scan');
  const isDeep = forceDeep || (_currentScanMode === 'deep');
  errShow('scan-err','');
  const loaderText = document.getElementById('scan-loader-text');
  if (loaderText) {
    loaderText.textContent = isDeep ? 'Deep demo audit via VirusTotal & AbuseIPDB…' : 'Running instant heuristic demo…';
  }
  loader('scan-loader',true);
  showResultLoading(isDeep ? 'Deep Scanning Demo (87+ AV Engines)…' : 'Running Quick Demo…');
  const demoEmail = `From: PayPal Support <noreply@paypa1-support.ru>
Reply-To: help@secure-login.net
To: victim@example.com
Subject: Urgent: Your PayPal account has been suspended
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Received: from mail.evil.ru (mail.evil.ru [185.234.218.47])

Dear Customer,

Your PayPal account has been suspended due to unusual activity.
You must verify your account immediately to avoid permanent closure.

Please click here to verify your credentials:
http://paypa1-login.ru/verify?token=abc123&next=account

PayPal Security Team`;
  const inputEl = document.getElementById('email-input');
  if (inputEl) inputEl.value = demoEmail;
  try{
    const r = await apiFetch(`${API}/scan/demo?deep=${isDeep ? 'true' : 'false'}`);
    const d = await r.json();
    if(!r.ok) throw new Error(d.detail||'Demo failed');
    renderScanResult(d);
    if(window._authUser) { setTimeout(() => { loadDashboard().catch(()=>{}); }, 200); }
  }catch(e){errShow('scan-err',e.message);showResultReady()}
  loader('scan-loader',false);
}

function clearScan(){document.getElementById('email-input').value='';showResultReady();errShow('scan-err','')}

function showResultReady(){
  document.getElementById('scan-result-panel').innerHTML=`<div class="result-ready"><img src="logo.png" alt="Ready" style="width:54px;height:54px;opacity:0.22;border-radius:10px;object-fit:contain;filter:grayscale(30%)"><p>Ready to scan</p></div>`;
}
function showResultLoading(msg = 'Analyzing…'){
  document.getElementById('scan-result-panel').innerHTML=`<div class="result-ready"><div class="spinner" style="width:32px;height:32px;border-width:3px"></div><p>${esc(msg)}</p></div>`;
}

function renderScanResult(d){
  window._currentScanData = d;
  const auth=d.authentication||{};const h=d.header_analysis||{};
  const urls=d.urls||[];const atts=d.attachments||[];
  const ph=d.phishing||{};const ip=h.ip_reputation;
  const audit=d.received_hop_audit||{hops:[], anomalies:[]};
  const wa=d.weighted_phishing_analysis||{score:0, matches:[]};
  const c=riskColor(d.risk_level);
  
  document.getElementById('scan-result-panel').innerHTML=`
    <!-- Risk gauge area -->
    <div style="display:flex;align-items:center;gap:16px;padding:16px 0 14px;border-bottom:1px solid var(--border);margin-bottom:14px">
      <div style="text-align:center">
        <div style="font-size:44px;font-weight:800;letter-spacing:-2px;color:${c};font-family:'JetBrains Mono',monospace;line-height:1">${d.risk_score}</div>
        <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:${c};margin-top:3px">${(d.risk_level||'').toUpperCase()}</div>
        <div style="font-size:10.5px;color:var(--t3);margin-top:2px">Risk Score</div>
      </div>
      <div style="flex:1">
        <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:8px">${(d.threat_types||[]).map(t=>`<span class="tag tag-critical" style="font-size:10px">${t.replace(/_/g,' ')}</span>`).join('')||'<span class="tag tag-clean">Clean</span>'}</div>
        <div style="font-size:12px;color:var(--t2);line-height:1.5">${esc(d.summary||'')}</div>
      </div>
    </div>
    
    <!-- Exporters -->
    <div style="display:flex;gap:8px;margin-bottom:14px">
      <button class="btn btn-secondary btn-sm" onclick="exportIncidentReportHTML()" style="flex:1;justify-content:center">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;margin-right:4px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Download HTML
      </button>
      <button class="btn btn-primary btn-sm" onclick="exportIncidentReportPDF()" style="flex:1;justify-content:center">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;margin-right:4px;"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
        Export PDF
      </button>
    </div>

    <!-- AI Security Explanation -->
    <div style="margin-bottom:14px;background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.2);border-radius:var(--r-sm);padding:14px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#818cf8;display:flex;align-items:center;gap:6px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
          AI Threat Explainer
        </div>
        <button class="btn btn-sm" id="ai-explain-btn" onclick="fetchAIExplanation()" style="background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;font-size:11px;padding:4px 10px">
          ✨ Explain Threat
        </button>
      </div>
      <div id="ai-explain-content" style="font-size:12px;color:var(--t2);line-height:1.6;white-space:pre-wrap">Click "Explain Threat" to generate an AI-powered security assessment.</div>
    </div>

    <!-- Quishing / QR Code Analysis (v4.0) -->
    ${d.quishing && d.quishing.has_qr_codes ? `
    <div style="margin-bottom:14px;background:rgba(239,68,68,0.06);border:1px solid ${d.quishing.risk_level==='critical'?'rgba(239,68,68,0.4)':d.quishing.risk_level==='high'?'rgba(249,115,22,0.4)':'rgba(99,102,241,0.3)'};border-radius:var(--r-sm);padding:14px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:${d.quishing.risk_level==='critical'?'var(--red)':d.quishing.risk_level==='high'?'var(--orange)':'#818cf8'};display:flex;align-items:center;gap:6px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          📷 Quishing / QR Code Security (${d.quishing.qr_count})
        </div>
        ${riskTag(d.quishing.risk_level)}
      </div>
      <div style="font-size:12px;color:var(--t2);line-height:1.5;margin-bottom:10px">${esc(d.quishing.summary)}</div>
      <div style="display:flex;flex-direction:column;gap:8px">
        ${d.quishing.detections.map((det, idx) => `
          <div class="url-item" style="padding:10px;background:rgba(0,0,0,0.25);border-radius:6px;border:1px solid var(--border);">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">
              <span style="font-size:11px;font-weight:700;color:var(--cyan);font-family:'JetBrains Mono',monospace;">[QR #${idx+1} · ${esc(det.source.replace('_',' '))}]</span>
              <div style="display:flex;gap:4px;">
                ${det.is_shortened ? '<span class="tag tag-high" style="font-size:9.5px">Shortener Evasion</span>' : ''}
                ${det.payload_type==='bitcoin_address'?'<span class="tag tag-critical" style="font-size:9.5px">Bitcoin Address</span>':''}
                ${det.payload_type==='ethereum_address'?'<span class="tag tag-critical" style="font-size:9.5px">Ethereum Address</span>':''}
                ${riskTag(det.risk_level)}
              </div>
            </div>
            <div class="url-text" style="font-family:'JetBrains Mono',monospace;font-size:11.5px;word-break:break-all;color:var(--t1);margin-bottom:4px">${esc(det.decoded_payload)}</div>
            ${det.threat_indicators && det.threat_indicators.length ? `
              <div style="margin-top:6px;font-size:11px;color:var(--orange);line-height:1.4;">
                ${det.threat_indicators.map(ind => `<div>⚠ ${esc(ind)}</div>`).join('')}
              </div>
            ` : ''}
          </div>
        `).join('')}
      </div>
    </div>
    ` : ''}


    <!-- Auth -->
    <div style="margin-bottom:14px">
      <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--t3);margin-bottom:8px">Authentication</div>
      <div class="auth-grid">${['spf','dkim','dmarc','arc'].map(k=>`<div class="auth-item"><div class="auth-lbl">${k.toUpperCase()}</div><div class="auth-val ${authC(auth[k])}">${auth[k]||'unknown'}</div></div>`).join('')}</div>
    </div>
    
    <!-- Sender -->
    <div style="margin-bottom:14px">
      <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--t3);margin-bottom:8px">Sender</div>
      ${infoRow('From',esc(d.sender_email||'—'))}
      ${infoRow('Subject',esc(d.subject||'—'))}
      ${infoRow('Domain',esc(h.from_domain||'—'))}
      ${infoRow('Display Name Spoof',h.display_name_spoof?'<span style="color:var(--red)">⚠ YES</span>':'<span style="color:var(--green)">No</span>')}
      ${infoRow('Reply-To Mismatch',h.reply_to_mismatch?'<span style="color:var(--orange)">⚠ YES</span>':'<span style="color:var(--green)">No</span>')}
    </div>
    
    <!-- Forensic Routing Hop Audit -->
    ${audit&&audit.hops&&audit.hops.length?`
    <div style="margin-bottom:14px">
      <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--t3);margin-bottom:8px">Routing Hop Audit (${audit.hop_count} hops)</div>
      ${audit.anomalies&&audit.anomalies.length?`<div class="alert-banner alert-red" style="padding:6px 10px;font-size:11.5px;margin-bottom:8px">${audit.anomalies.map(a=>`<div>⚠ ${esc(a)}</div>`).join('')}</div>`:''}
      <div class="url-item" style="max-height:120px;overflow-y:auto;padding:8px 10px;font-size:11px;font-family:'JetBrains Mono',monospace;line-height:1.4;">
        ${audit.hops.map(hop=>`<div><span style="color:var(--cyan)">[Hop ${hop.hop}]</span> ${esc(hop.from.substring(0,25))} &rarr; <span style="color:var(--t2)">${esc(hop.ip || 'local')}</span></div>`).join('')}
      </div>
    </div>
    `:''}

    <!-- Phishing Indicator Keyword Density -->
    ${wa&&wa.matches&&wa.matches.length?`
    <div style="margin-bottom:14px">
      <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--t3);margin-bottom:8px">Phishing Keyword Density (Weighted)</div>
      <div style="display:flex;flex-direction:column;gap:5px;">
        ${wa.matches.slice(0,5).map(m=>`
          <div class="url-item" style="display:flex;justify-content:space-between;align-items:center;padding:6px 10px;">
            <div><span style="font-weight:600;color:var(--orange)">"${esc(m.keyword)}"</span> <span style="color:var(--t3);font-size:11px">x${m.count}</span></div>
            <span class="tag tag-info" style="font-family:'JetBrains Mono',monospace;font-size:10px;padding:1px 6px;">+${m.score} pts</span>
          </div>
        `).join('')}
      </div>
    </div>
    `:''}

    <!-- Pattern-Based Probabilistic Classifier (v4.0) -->
    ${d.ml_prediction ? `
    <div style="margin-bottom:14px;background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.3);border-radius:var(--r-sm);padding:14px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
        <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--accent);display:flex;align-items:center;gap:6px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M12 2a4 4 0 0 1 4 4c0 1.1-.5 2.1-1.2 2.8l.2.2a6 6 0 0 1 3 5.2v.8a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4v-.8a6 6 0 0 1 3-5.2l.2-.2A4 4 0 0 1 8 6a4 4 0 0 1 4-4z"/><circle cx="12" cy="6" r="1.5"/></svg>
          🧠 Heuristic Risk Signal
        </div>
        <div style="display:flex;align-items:center;gap:6px">
          <span style="font-size:10px;color:var(--t3);font-family:'JetBrains Mono',monospace;">⚡ ${d.ml_prediction.inference_duration_ms || 1.2}ms offline</span>
          <span class="tag ${d.ml_prediction.is_phishing ? (d.ml_prediction.confidence === 'critical' ? 'tag-critical' : 'tag-high') : 'tag-clean'}" style="font-size:10px;text-transform:uppercase">
            ${d.ml_prediction.confidence || 'clean'} confidence
          </span>
        </div>
      </div>

      <!-- Probability Gauge Meter -->
      <div style="margin-bottom:10px;background:rgba(0,0,0,0.3);border-radius:6px;padding:10px;border:1px solid var(--border)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <span style="font-size:11.5px;font-weight:600;color:var(--t1)">Phishing Probability</span>
          <span style="font-size:13px;font-weight:800;font-family:'JetBrains Mono',monospace;color:${d.ml_prediction.percentage >= 65 ? 'var(--red)' : (d.ml_prediction.percentage >= 40 ? 'var(--orange)' : 'var(--green)')}">
            ${d.ml_prediction.percentage}%
          </span>
        </div>
        <div style="height:6px;background:rgba(255,255,255,0.1);border-radius:3px;overflow:hidden">
          <div style="width:${d.ml_prediction.percentage}%;height:100%;background:${d.ml_prediction.percentage >= 65 ? 'var(--red)' : (d.ml_prediction.percentage >= 40 ? 'var(--orange)' : 'var(--green)')};border-radius:3px;transition:width 0.4s ease;"></div>
        </div>
      </div>

      <!-- Top Feature Attribution Signals -->
      ${d.ml_prediction.top_signals && d.ml_prediction.top_signals.length ? `
        <div style="font-size:10.5px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px">Feature Attribution Breakdown</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px;">
          ${d.ml_prediction.top_signals.map(s => `
            <div style="display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:4px;font-size:11px;background:${s.is_positive ? 'rgba(239,68,68,0.12)' : 'rgba(34,197,94,0.12)'};border:1px solid ${s.is_positive ? 'rgba(239,68,68,0.25)' : 'rgba(34,197,94,0.25)'};color:${s.is_positive ? 'var(--red)' : 'var(--green)'}">
              <span>${s.is_positive ? '▲' : '▼'} ${esc(s.label)}</span>
              <span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:10px;opacity:0.85">${s.is_positive ? '+' : ''}${s.contribution}</span>
            </div>
          `).join('')}
        </div>
      ` : ''}
    </div>
    ` : ''}

    <!-- Phishing indicators -->
    <div style="margin-bottom:14px">
      <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--t3);margin-bottom:8px">Phishing Indicators</div>
      ${[['Urgency Language','urgency_language'],['Credential Request','credential_request'],['Lookalike Domain','domain_lookalike'],['Suspicious Subject','subject_suspicious']].map(([l,k])=>infoRow(l,ph[k]?'<span style="color:var(--red)">⚠ Detected</span>':'<span style="color:var(--green)">Clear</span>')).join('')}
    </div>
    
    <!-- IP -->
    ${ip&&ip.ip?`<div style="margin-bottom:14px"><div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--t3);margin-bottom:8px">IP Reputation</div>${infoRow('IP',esc(ip.ip))}${infoRow('Country',esc(ip.country_code||'—'))}${infoRow('Abuse Score',`<span style="color:${(ip.abuse_confidence_score||0)>50?'var(--red)':'var(--green)'}">${ip.abuse_confidence_score}%</span>`)}${infoRow('Tor',ip.is_tor?'<span style="color:var(--red)">YES</span>':'No')}</div>`:''}
    
    <!-- IDN Homograph & Typosquatting Alerts (v4.0) -->
    ${d.homograph_alerts && d.homograph_alerts.length ? `
    <div style="margin-bottom:14px;background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.35);border-radius:var(--r-sm);padding:14px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--red);display:flex;align-items:center;gap:6px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          🌐 IDN Homograph & Typosquatting Alerts (${d.homograph_alerts.length})
        </div>
        <span class="tag tag-critical" style="font-size:10px">Brand Impersonation</span>
      </div>
      <div style="display:flex;flex-direction:column;gap:8px">
        ${d.homograph_alerts.map((al, idx) => `
          <div class="url-item" style="padding:10px;background:rgba(0,0,0,0.25);border-radius:6px;border:1px solid var(--border);">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
              <span style="font-size:11.5px;font-weight:700;color:var(--t1);font-family:'JetBrains Mono',monospace;">
                ${esc(al.unicode_domain || al.domain)}
                ${al.unicode_domain && al.unicode_domain !== al.domain ? `<span style="color:var(--t3);font-size:10px"> (${esc(al.domain)})</span>` : ''}
              </span>
              <span class="tag tag-critical" style="font-size:9.5px">Impersonating ${esc(al.spoofed_brand || 'Brand')}</span>
            </div>
            <div style="font-size:11px;color:var(--t2);margin-bottom:4px">
              Official target: <strong style="color:var(--green)">${esc(al.official_domain || (al.spoofed_brand + '.com'))}</strong>
            </div>
            ${al.threat_indicators && al.threat_indicators.length ? `
              <div style="font-size:11px;color:var(--orange);line-height:1.4;">
                ${al.threat_indicators.map(ind => `<div>• ${esc(ind)}</div>`).join('')}
              </div>
            ` : ''}
          </div>
        `).join('')}
      </div>
    </div>
    ` : ''}

    <!-- Threat Intelligence Overview Card -->
    <div style="margin-bottom:14px;background:rgba(15,23,42,0.6);border:1px solid var(--border);border-radius:var(--r-sm);padding:10px 14px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:16px">${d.deep_scan ? '🛡️' : '⚡'}</span>
        <div>
          <div style="font-size:12px;font-weight:700;color:var(--t1)">
            ${d.deep_scan ? 'Multi-Engine Threat Intelligence (VirusTotal & AbuseIPDB)' : 'Ultra-Fast Heuristic & Local Threat Vault'}
          </div>
          <div style="font-size:11px;color:var(--t2)">
            ${d.deep_scan ? (
              (urls.length ? `VirusTotal analyzed ${urls.length} embedded link${urls.length>1?'s':''} across 87 commercial antivirus engines.` : 'VirusTotal verified: No suspicious external hyperlinks or malicious payloads.') +
              (ip && ip.ip ? ` · AbuseIPDB checked mail server ${esc(ip.ip)} (${ip.risk_level==='clean'?'0% abuse confidence':esc(ip.risk_level)}).` : '')
            ) : (
              `Completed in ${d.scan_duration_ms || '<200'}ms using ML ensemble, IDN lookalike detection, and Threat Vault IOC matching.`
            )}
          </div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:6px">
        <span class="det-pill ${d.deep_scan ? 'det-clean' : 'det-unk'}" style="font-size:10px;font-weight:700">
          ${d.deep_scan ? 'VirusTotal 87+ Engines Active' : '⚡ Quick Scan Mode'}
        </span>
        ${!d.deep_scan ? `
          <button class="btn btn-sm btn-primary" onclick="escalateToDeepScan()" style="font-size:11px;padding:3px 9px" title="Escalate to 87+ VirusTotal Antivirus engines and AbuseIPDB">
            🛡️ Escalate to Deep Scan ↗
          </button>
        ` : ''}
      </div>
    </div>

    <!-- URLs -->
    ${urls.length?`<div style="margin-bottom:14px"><div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--t3);margin-bottom:8px">Scanned URLs (${urls.length})</div>${urls.map(u=>{const vt=u.vt_result||{};const det=vt.detections??null;const isQuick=vt.status==='quick_scan'||!d.deep_scan;const dc=isQuick?'det-unk':(det!==null?(det>3?'det-high':'det-clean'):'det-unk');const dl=isQuick?'⚡ Local Heuristic Verified':(det!==null?`VirusTotal: ${det}/${vt.total_engines||87} Engines`:'VirusTotal: Analyzed');return`<div class="url-item"><div class="url-text">${esc(u.url)}</div><div class="url-meta"><span class="det-pill ${dc}">${dl}</span>${vt.permalink?`<a href="${esc(vt.permalink)}" target="_blank" rel="noopener noreferrer" style="font-size:11px;color:var(--cyan);text-decoration:underline;margin-left:4px" title="Open full scan report on VirusTotal.com">VT Report ↗</a>`:''}${u.is_homograph?'<span class="tag tag-critical" style="font-size:10px">IDN Homograph</span>':''}${u.is_lookalike?`<span class="tag tag-critical" style="font-size:10px">Lookalike (${esc(u.spoofed_brand||'brand')})</span>`:''}${u.subdomain_spoof?'<span class="tag tag-high" style="font-size:10px">Subdomain Trap</span>':''}${u.is_shortened?'<span class="tag tag-high" style="font-size:10px">Shortener</span>':''}</div></div>`}).join('')}</div>`:''}
    
    <!-- Attachments -->
    ${atts.length?`<div><div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--t3);margin-bottom:8px">Scanned Attachments (${atts.length})</div>${atts.map(a=>{const vt=a.vt_result||{};const det=vt.detections??0;const isQuick=vt.status==='quick_scan'||!d.deep_scan;const label=isQuick?'⚡ Local SHA-256 Verified':(det>0?`${det} Malicious Engines`:'0/70 AV Clean');const pillClass=isQuick?'det-unk':(det>0?'det-high':'det-clean');return`<div class="url-item"><div class="url-text">${esc(a.filename)}</div><div class="url-meta"><span class="det-pill ${pillClass}">${label}</span>${a.is_dangerous_ext?'<span class="tag tag-high" style="font-size:10px">Dangerous Ext</span>':''}</div></div>`}).join('')}</div>`:''}
  `;
}

// ── Quick URL scan (scanner page) ─────────────
async function quickUrlScan(){
  const url = document.getElementById('url-quick').value.trim();
  if(!url) return;
  loader('url-loader',true);errShow('url-err','');document.getElementById('url-quick-result').style.display='none';
  try{
    const r=await apiFetch(`${API}/scan/url`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    if(r.status === 429) {
      toast('Daily scan limit reached (5/5). Sign in for unlimited scans.', 'warning');
      errShow('url-err','Free scan limit reached. Sign in for unlimited scanning.');
      loader('url-loader',false);
      loadGuestQuota();
      return;
    }
    const d=await r.json();if(!r.ok)throw new Error(d.detail||'Failed');
    const res=d.scan_result||{};const det=res.detections??0;
    document.getElementById('url-quick-result').innerHTML=`${infoRow('Risk',riskTag(res.risk_level))}${infoRow('Detections',`<span style="color:${det>0?'var(--red)':'var(--green)'};font-weight:600">${det}/${res.total_engines||'?'}</span>`)}${res.permalink?`<a href="${res.permalink}" target="_blank" style="color:var(--cyan);font-size:12px">View on VirusTotal ↗</a>`:''}`;
    document.getElementById('url-quick-result').style.display='block';
    loadGuestQuota();
  }catch(e){errShow('url-err',e.message)}
  loader('url-loader',false);
}

async function quickAttachScan(e){
  const file=e.target.files[0];if(!file)return;
  const fd=new FormData();fd.append('file',file);
  try{
    const r=await apiFetch(`${API}/attachments/scan`,{method:'POST',body:fd});
    const d=await r.json();if(!r.ok)throw new Error(d.detail||'Failed');
    const res=d.scan_result||{};const det=res.detections??0;
    document.getElementById('attach-quick-name').value=d.filename||'';
    toast(`${file.name}: ${det} detection${det!==1?'s':''}`,det>0?'error':'success');
  }catch(e){toast('Attachment scan failed: '+e.message,'error')}
}

// ── Threat Analysis page ──────────────────────
async function loadThreatFeed(){
  if (!window._authUser) {
    const list = document.getElementById('threat-feed-list');
    if (list) {
      list.innerHTML = `
        <div style="padding:36px 20px;text-align:center;color:var(--t2);">
          <div style="font-size:14px;font-weight:700;margin-bottom:6px;color:var(--t1);">Personalized Threat Feed</div>
          <p style="font-size:12.5px;max-width:380px;margin:0 auto 16px;line-height:1.5;">Sign in to view your real-time analyzed threat telemetry, categorized indicators, and threat intelligence feed.</p>
          <button class="btn btn-primary btn-sm" onclick="showAuthScreen(); showSignIn();">Sign In to View</button>
        </div>`;
    }
    return;
  }
  try{
    const r=await apiFetch(`${API}/forensics?limit=100`);
    if (!r.ok) return;
    const d=await r.json();
    const logs=(d.logs||[]).filter(l=>['critical','high','medium'].includes(l.risk_level)).slice(0,8);
    const critical=logs.filter(l=>l.risk_level==='critical').length;
    const badge=document.getElementById('threat-feed-count');
    if(critical>0){badge.textContent=`${critical} critical`;badge.style.display='inline-flex'}
    const alertBanner=document.getElementById('threat-alert-banner');
    if(critical>0){
      document.getElementById('threat-alert-text').textContent=`${critical} critical threat${critical!==1?'s':''} require attention — check logs immediately`;
      alertBanner.style.display='flex';
    }
    document.getElementById('threat-feed-list').innerHTML = logs.length ? logs.map(l=>{
      const type=(l.threat_types||[]).find(t=>t!=='clean')||'phishing';
      return`<div class="threat-item">
        ${threatIcon(type,l.risk_level)}
        <div class="threat-body">
          <div class="threat-name">${esc(type.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase()))}</div>
          <div class="threat-desc">${esc((l.summary||l.subject||'').substring(0,100))}</div>
          <div class="threat-meta">From: ${esc(l.sender_email||'—')} · ${timeAgo(l.scanned_at||'')}</div>
        </div>
        ${riskTag(l.risk_level)}
      </div>`;
    }).join('') : '<div style="padding:32px;text-align:center;color:var(--t3);font-size:13px">No threats found — all clear! 🎉</div>';
  }catch(e){toast('Failed to load threat feed','error')}
}

// ── Threat Intelligence Vault Page ────────────────
let _tiPage = 1;
let _tiSearchTimeout = null;
const _TI_LIMIT = 25;

function defangIOCStr(str) {
  if (!str) return '';
  return str
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/\./g, '[.]');
}

async function loadThreatIntelDashboard() {
  await Promise.all([
    fetchThreatIntelStatus(),
    fetchThreatVaultRecords(1)
  ]);
}

async function fetchThreatIntelStatus() {
  try {
    const res = await apiFetch(`${API}/threat-intel/status`);
    if (!res.ok) return;
    const data = await res.json();
    
    // 1. Total Indicators
    const totalEl = document.getElementById('ti-total-iocs');
    if (totalEl) totalEl.textContent = (data.total_indicators || 0).toLocaleString();
    
    // 2. Feed breakdown
    const byFeed = data.by_source_feed || {};
    const urlhausCnt = byFeed['urlhaus'] || 0;
    const openphishCnt = byFeed['openphish'] || 0;
    
    const uhEl = document.getElementById('ti-urlhaus-count');
    if (uhEl) uhEl.textContent = `${urlhausCnt.toLocaleString()} IOCs`;
    
    const opEl = document.getElementById('ti-openphish-count');
    if (opEl) opEl.textContent = `${openphishCnt.toLocaleString()} IOCs`;
    
    // 3. Cache
    const cacheEl = document.getElementById('ti-cache-count');
    if (cacheEl) cacheEl.textContent = `${data.cache_entries || 0} in RAM`;
    
    // 4. Sync metadata
    const syncs = data.sync_metadata || [];
    const uhMeta = syncs.find(s => s.feed_name === 'urlhaus');
    const opMeta = syncs.find(s => s.feed_name === 'openphish');
    
    const uhSt = document.getElementById('ti-urlhaus-status');
    if (uhSt) {
      uhSt.textContent = uhMeta ? `Status: ${uhMeta.status.toUpperCase()} (${uhMeta.last_sync ? timeAgo(uhMeta.last_sync) : 'never'})` : 'Status: Ready';
    }
    
    const opSt = document.getElementById('ti-openphish-status');
    if (opSt) {
      opSt.textContent = opMeta ? `Status: ${opMeta.status.toUpperCase()} (${opMeta.last_sync ? timeAgo(opMeta.last_sync) : 'never'})` : 'Status: Ready';
    }
  } catch (e) {
    console.warn('Threat status fetch error:', e);
  }
}

async function fetchThreatVaultRecords(page = 1) {
  _tiPage = page;
  const tbody = document.getElementById('ti-tbody');
  const pag = document.getElementById('ti-pagination');
  if (!tbody) return;
  
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--t3)">Querying Threat Vault…</td></tr>';
  
  const search = (document.getElementById('ti-search-input')?.value || '').trim();
  const iocType = document.getElementById('ti-filter-type')?.value || '';
  const threatType = document.getElementById('ti-filter-threat')?.value || '';
  const sourceFeed = document.getElementById('ti-filter-feed')?.value || '';
  
  const offset = (page - 1) * _TI_LIMIT;
  const params = new URLSearchParams({
    limit: _TI_LIMIT,
    offset: offset
  });
  if (search) params.set('search', search);
  if (iocType) params.set('ioc_type', iocType);
  if (threatType) params.set('threat_type', threatType);
  if (sourceFeed) params.set('source_feed', sourceFeed);
  
  try {
    const res = await apiFetch(`${API}/threat-intel/vault?${params.toString()}`);
    if (!res.ok) throw new Error('Failed to query vault');
    const data = await res.json();
    const records = data.records || [];
    const total = data.total || 0;
    
    if (records.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:32px;color:var(--t3)">No matching threat indicators found in local vault.</td></tr>';
      if (pag) pag.innerHTML = '';
      return;
    }
    
    tbody.innerHTML = records.map(r => {
      const defanged = defangIOCStr(r.ioc_value);
      const confColor = r.confidence >= 90 ? 'var(--red)' : r.confidence >= 70 ? 'var(--orange)' : 'var(--amber)';
      const tags = (r.tags || []).map(t => `<span class="tag tag-info" style="font-size:10px;padding:2px 6px">${esc(t)}</span>`).join(' ');
      
      return `<tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11.5px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.ioc_value)}">
          ${esc(defanged)}
        </td>
        <td><span class="tag tag-info" style="text-transform:uppercase;font-size:10px">${esc(r.ioc_type)}</span></td>
        <td><span class="tag ${r.threat_type.includes('malware') ? 'tag-critical' : 'tag-high'}" style="font-size:10px">${esc(r.threat_type.replace(/_/g, ' ').toUpperCase())}</span></td>
        <td style="font-size:12px;color:var(--t2);text-transform:capitalize">${esc(r.source_feed.replace(/_/g, ' '))}</td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <div style="flex:1;min-width:40px;height:5px;background:rgba(255,255,255,0.1);border-radius:3px;overflow:hidden">
              <div style="width:${r.confidence}%;height:100%;background:${confColor}"></div>
            </div>
            <span style="font-size:11px;font-weight:700;color:${confColor}">${r.confidence}%</span>
          </div>
        </td>
        <td>${tags || '<span style="color:var(--t3);font-size:11px">—</span>'}</td>
        <td style="font-size:11.5px;color:var(--t3)">${r.last_seen ? timeAgo(r.last_seen) : '—'}</td>
        <td>
          <div style="display:flex;gap:4px">
            <button class="btn btn-secondary btn-sm" style="padding:3px 7px;font-size:11px" onclick="copyIOCValue('${esc(r.ioc_value)}')">Copy</button>
            <button class="btn btn-primary btn-sm" style="padding:3px 7px;font-size:11px" onclick="setSandboxIOC('${esc(r.ioc_value)}')">Inspect</button>
          </div>
        </td>
      </tr>`;
    }).join('');
    
    // Pagination
    if (pag) {
      const totalPages = Math.ceil(total / _TI_LIMIT) || 1;
      pag.innerHTML = `
        <button class="btn btn-secondary btn-sm" onclick="fetchThreatVaultRecords(${page - 1})" ${page <= 1 ? 'disabled' : ''}>← Prev</button>
        <span style="font-size:12px;color:var(--t2)">Page ${page} of ${totalPages} (${total} items)</span>
        <button class="btn btn-secondary btn-sm" onclick="fetchThreatVaultRecords(${page + 1})" ${page >= totalPages ? 'disabled' : ''}>Next →</button>
      `;
    }
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--red)">Failed to load indicators: ${esc(e.message)}</td></tr>`;
  }
}

function debounceThreatSearch() {
  clearTimeout(_tiSearchTimeout);
  _tiSearchTimeout = setTimeout(() => {
    fetchThreatVaultRecords(1);
  }, 250);
}

function copyIOCValue(val) {
  navigator.clipboard.writeText(val).then(() => {
    toast('IOC value copied to clipboard!', 'success');
  }).catch(() => {
    toast('Copied', 'info');
  });
}

function setSandboxIOC(val) {
  const input = document.getElementById('ti-sandbox-input');
  if (input) {
    input.value = val;
    doInstantIOCLookup();
    input.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

async function doInstantIOCLookup() {
  const input = document.getElementById('ti-sandbox-input');
  const resultBox = document.getElementById('ti-sandbox-result');
  if (!input || !resultBox) return;
  
  const ioc = input.value.trim();
  if (!ioc) {
    toast('Enter an IP, domain, URL, or hash to inspect', 'info');
    return;
  }
  
  resultBox.style.display = 'block';
  resultBox.style.background = 'rgba(15,23,42,0.8)';
  resultBox.style.border = '1px solid rgba(56,189,248,0.3)';
  resultBox.innerHTML = '<div style="display:flex;align-items:center;gap:8px;color:var(--cyan)"><div class="spinner" style="width:14px;height:14px;border-width:2px"></div><span>Querying Threat Vault memory cache…</span></div>';
  
  try {
    const res = await apiFetch(`${API}/threat-intel/lookup?ioc=${encodeURIComponent(ioc)}`);
    const data = await res.json();
    
    if (data.is_threat && data.threat_details) {
      const td = data.threat_details;
      resultBox.style.background = 'rgba(239,68,68,0.1)';
      resultBox.style.border = '1px solid rgba(239,68,68,0.4)';
      resultBox.innerHTML = `
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap">
          <div>
            <div style="font-weight:700;color:var(--red);display:flex;align-items:center;gap:6px;font-size:13px">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              ACTIVE THREAT INTELLIGENCE MATCH
            </div>
            <div style="margin-top:6px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--t1)">${esc(defangIOCStr(td.ioc_value))}</div>
            <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">
              <span class="tag tag-critical" style="font-size:10px">${esc(td.threat_type.toUpperCase())}</span>
              <span class="tag tag-info" style="font-size:10px">SOURCE: ${esc(td.source_feed.toUpperCase())}</span>
              <span class="tag tag-high" style="font-size:10px">CONFIDENCE: ${td.confidence}%</span>
            </div>
          </div>
          <div style="font-size:11.5px;color:var(--t2);text-align:right">
            <div>First Seen: <b>${td.first_seen ? timeAgo(td.first_seen) : 'Unknown'}</b></div>
            <div style="margin-top:2px">Last Active: <b>${td.last_seen ? timeAgo(td.last_seen) : 'Active'}</b></div>
          </div>
        </div>
      `;
    } else {
      resultBox.style.background = 'rgba(34,197,94,0.1)';
      resultBox.style.border = '1px solid rgba(34,197,94,0.3)';
      resultBox.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;color:var(--green);font-size:12.5px;font-weight:600">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          Clean — No known malicious IOC entry in local Threat Vault.
        </div>
      `;
    }
  } catch (e) {
    resultBox.innerHTML = `<span style="color:var(--red)">Lookup error: ${esc(e.message)}</span>`;
  }
}

async function triggerThreatFeedSync() {
  const btn = document.getElementById('btn-sync-feeds');
  if (btn) btn.disabled = true;
  toast('Syncing threat feeds (URLhaus & OpenPhish) in background…', 'info');
  
  try {
    const res = await apiFetch(`${API}/threat-intel/sync`, { method: 'POST' });
    const data = await res.json();
    toast('Threat feeds synchronized successfully!', 'success');
    setTimeout(() => {
      fetchThreatIntelStatus();
      fetchThreatVaultRecords(1);
    }, 1500);
  } catch (e) {
    toast(`Sync error: ${e.message}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function exportThreatVaultCSV() {
  try {
    toast('Generating CSV blocklist…', 'info');
    const res = await apiFetch(`${API}/threat-intel/vault?limit=200`);
    const data = await res.json();
    const records = data.records || [];
    
    let csv = 'Indicator,Type,Threat_Category,Source_Feed,Confidence,Tags,Last_Seen\n';
    records.forEach(r => {
      const val = `"${r.ioc_value.replace(/"/g, '""')}"`;
      const tags = `"${(r.tags || []).join(';').replace(/"/g, '""')}"`;
      csv += `${val},${r.ioc_type},${r.threat_type},${r.source_feed},${r.confidence},${tags},${r.last_seen}\n`;
    });
    
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SecureMail-ThreatVault-Blocklist-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Blocklist exported as CSV', 'success');
  } catch (e) {
    toast('Export failed: ' + e.message, 'error');
  }
}

async function exportThreatVaultJSON() {
  try {
    toast('Generating JSON telemetry export…', 'info');
    const res = await apiFetch(`${API}/threat-intel/vault?limit=200`);
    const data = await res.json();
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SecureMail-ThreatVault-Export-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Threat Vault exported as JSON', 'success');
  } catch (e) {
    toast('Export failed: ' + e.message, 'error');
  }
}

// ── Compliance Audit Trail Controller ──────────────────
let _atPage = 1;
let _atSearchTimeout = null;
const _AT_LIMIT = 30;

async function loadAuditTrailPage() {
  await fetchAuditLogs(1);
}

async function fetchAuditLogs(page = 1) {
  _atPage = page;
  const tbody = document.getElementById('at-tbody');
  const pag = document.getElementById('at-pagination');
  if (!tbody) return;

  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--t3)">Querying immutable compliance audit trail…</td></tr>';

  const search = (document.getElementById('at-search-input')?.value || '').trim();
  const eventType = document.getElementById('at-filter-event')?.value || '';

  const offset = (page - 1) * _AT_LIMIT;
  const params = new URLSearchParams({
    limit: _AT_LIMIT,
    offset: offset
  });
  if (search) params.set('search', search);
  if (eventType) params.set('event_type', eventType);

  try {
    const res = await apiFetch(`${API}/audit-trail?${params.toString()}`);
    if (res.status === 403) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--red)">Access Denied: You need Auditor, SOC Analyst, or Admin permissions to view compliance audit logs.</td></tr>';
      if (pag) pag.innerHTML = '';
      return;
    }
    if (!res.ok) throw new Error('Failed to fetch audit records');
    const data = await res.json();
    const records = data.records || [];
    const total = data.total || 0;

    if (records.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--t3)">No matching compliance audit events recorded.</td></tr>';
      if (pag) pag.innerHTML = '';
      return;
    }

    tbody.innerHTML = records.map(r => {
      const eventBadge = (r.event_type && (r.event_type.includes('DELETE') || r.event_type.includes('REVOKE')))
        ? 'tag-critical'
        : (r.event_type && (r.event_type.includes('CREATE') || r.event_type.includes('ASSIGN')))
        ? 'tag-high'
        : (r.event_type && r.event_type.includes('PDF'))
        ? 'tag-medium'
        : 'tag-info';

      const detailsStr = r.details ? JSON.stringify(r.details) : '{}';

      return `<tr>
        <td style="font-size:11.5px;color:var(--t2);font-family:'JetBrains Mono',monospace;white-space:nowrap">${esc(r.timestamp || '—')}</td>
        <td><span class="tag ${eventBadge}" style="font-size:10px">${esc(r.event_type)}</span></td>
        <td>
          <div style="font-size:12px;font-weight:600;color:var(--t1)">${esc(r.user_email || r.user_id)}</div>
          <div style="font-size:10.5px;color:var(--t3);text-transform:uppercase">${esc(r.user_role || 'user')}</div>
        </td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--t2)">${esc(r.ip_address || '—')}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11.5px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.resource_id)}">${esc(r.resource_id || '—')}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--t2);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(detailsStr)}">${esc(detailsStr)}</td>
      </tr>`;
    }).join('');

    // Pagination
    if (pag) {
      const totalPages = Math.ceil(total / _AT_LIMIT) || 1;
      pag.innerHTML = `
        <button class="btn btn-secondary btn-sm" onclick="fetchAuditLogs(${page - 1})" ${page <= 1 ? 'disabled' : ''}>← Prev</button>
        <span style="font-size:12px;color:var(--t2)">Page ${page} of ${totalPages} (${total} events)</span>
        <button class="btn btn-secondary btn-sm" onclick="fetchAuditLogs(${page + 1})" ${page >= totalPages ? 'disabled' : ''}>Next →</button>
      `;
    }
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--red)">Audit Trail Error: ${esc(e.message)}</td></tr>`;
  }
}

function debounceAuditSearch() {
  clearTimeout(_atSearchTimeout);
  _atSearchTimeout = setTimeout(() => {
    fetchAuditLogs(1);
  }, 250);
}

async function exportAuditTrailCSV() {
  try {
    toast('Generating Compliance Audit CSV…', 'info');
    const search = (document.getElementById('at-search-input')?.value || '').trim();
    const eventType = document.getElementById('at-filter-event')?.value || '';
    const params = new URLSearchParams({ limit: 1000 });
    if (search) params.set('search', search);
    if (eventType) params.set('event_type', eventType);

    const res = await apiFetch(`${API}/audit-trail/export/csv?${params.toString()}`);
    if (!res.ok) throw new Error('Failed to export CSV');

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SecureMail-SOC-AuditTrail-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Compliance Audit Trail exported', 'success');
  } catch (e) {
    toast('Export error: ' + e.message, 'error');
  }
}

// ════════════════════════════════════════════════════════════
// Enterprise Organization & Multi-Tenant Sandboxing
// ════════════════════════════════════════════════════════════
let _orgCache = null;
let _orgMembersCache = [];

async function loadOrgManagement() {
  const tbodyMembers = document.getElementById('org-members-tbody');
  const tbodyScans = document.getElementById('org-scans-tbody');
  if (tbodyMembers) tbodyMembers.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--t3)">Syncing organization perimeter & team directory…</td></tr>';
  if (tbodyScans) tbodyScans.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--t3)">Aggregating live threat telemetry from tenant sandbox…</td></tr>';

  try {
    const res = await apiFetch(`${API}/org/overview`);
    if (res.status === 403) {
      if (tbodyMembers) tbodyMembers.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--red)">Access Restricted: Only Organization Administrators or SOC Analysts can access Team Sandbox management.</td></tr>';
      return;
    }
    if (!res.ok) throw new Error('Failed to retrieve organization overview');

    const json = await res.json();
    const data = json.data || {};
    _orgCache = data;
    _orgMembersCache = data.members || [];

    // Header & Info
    const nameEl = document.getElementById('org-name-header');
    const badgeEl = document.getElementById('org-sandbox-badge');
    const domEl = document.getElementById('org-domain-text');
    const ownerEl = document.getElementById('org-owner-text');

    if (nameEl) nameEl.textContent = data.name || 'Parul University SOC';
    if (badgeEl) badgeEl.textContent = `SANDBOX: ${(data.org_id || 'PARUL-SOC-01').toUpperCase()}`;
    if (domEl) domEl.textContent = data.domain || 'paruluniversity.ac.in';
    if (ownerEl) ownerEl.textContent = data.owner_email || 'sameerkhurshed2@gmail.com';

    // Stats
    const stats = data.stats || {};
    const memEl = document.getElementById('org-stat-members');
    const scanEl = document.getElementById('org-stat-scans');
    const threatEl = document.getElementById('org-stat-threats');
    const cleanEl = document.getElementById('org-stat-clean-rate');
    const badgeCount = document.getElementById('org-member-count-badge');

    if (memEl) memEl.innerHTML = `${stats.total_members || 0} <span style="font-size:13px; color:var(--t3); font-weight:500;">/ ${(stats.quota_seats || 1000).toLocaleString()} Seats</span>`;
    if (scanEl) scanEl.textContent = (stats.total_scans || 0).toLocaleString();
    if (threatEl) threatEl.textContent = (stats.threats_intercepted || 0).toLocaleString();
    if (cleanEl) cleanEl.textContent = `${stats.clean_rate_pct ?? 100}%`;
    if (badgeCount) badgeCount.textContent = (stats.total_members || 0);

    // Render Members Roster
    renderOrgMembersTable(_orgMembersCache);

    // Render Recent Sandboxed Scans
    renderOrgScansTable(data.recent_scans || []);

  } catch (err) {
    console.error('[Organization Sandbox Error]', err);
    if (tbodyMembers) tbodyMembers.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--red)">Failed to load organization data: ${esc(err.message)}</td></tr>`;
  }
}

function renderOrgMembersTable(members) {
  const tbody = document.getElementById('org-members-tbody');
  if (!tbody) return;

  if (!members || members.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--t3)">No employees registered in this sandbox directory yet.</td></tr>';
    return;
  }

  const roleTags = {
    admin: 'tag-critical',
    soc_analyst: 'tag-high',
    auditor: 'tag-medium',
    user: 'tag-info'
  };

  const isSelfAdmin = window._userRole === 'admin';

  tbody.innerHTML = members.map(m => {
    const isOwner = _orgCache && _orgCache.owner_email && _orgCache.owner_email.toLowerCase() === m.user_email.toLowerCase();
    const roleTag = roleTags[m.role] || 'tag-info';
    const statusTag = m.status === 'active' ? 'tag-clean' : 'tag-high';
    const initial = (m.display_name || m.user_email).charAt(0).toUpperCase();

    const roleDropdown = (isSelfAdmin && !isOwner) ? `
      <select class="settings-input" style="padding:4px 8px; font-size:11.5px; margin-right:6px;" onchange="changeOrgMemberRole('${esc(m.user_email)}', this.value)">
        <option value="user" ${m.role==='user'?'selected':''}>User</option>
        <option value="soc_analyst" ${m.role==='soc_analyst'?'selected':''}>SOC Analyst</option>
        <option value="auditor" ${m.role==='auditor'?'selected':''}>Auditor</option>
        <option value="admin" ${m.role==='admin'?'selected':''}>Admin</option>
      </select>
      <button class="btn btn-secondary btn-sm" style="color:var(--red); border-color:rgba(239,68,68,0.4); padding:4px 8px;" onclick="removeOrgMember('${esc(m.user_email)}')">Remove</button>
    ` : isOwner ? `<span style="font-size:11.5px; color:var(--t3); font-style:italic;">Primary Owner</span>` : `<span style="font-size:11.5px; color:var(--t3);">Managed</span>`;

    return `<tr>
      <td>
        <div style="display:flex; align-items:center; gap:10px;">
          <div style="width:30px; height:30px; border-radius:50%; background:linear-gradient(135deg, rgba(99,102,241,0.3), rgba(168,85,247,0.3)); border:1px solid rgba(129,140,248,0.3); display:flex; align-items:center; justify-content:center; font-weight:700; font-size:12px; color:var(--t1);">
            ${esc(initial)}
          </div>
          <div>
            <div style="font-size:12.5px; font-weight:700; color:var(--t1);">${esc(m.display_name || m.user_email.split('@')[0])}</div>
            <div style="font-size:11.5px; color:var(--t3); font-family:'JetBrains Mono',monospace;">${esc(m.user_email)}</div>
          </div>
        </div>
      </td>
      <td><span class="tag ${roleTag}" style="font-size:10px; font-weight:700;">${esc(m.role.replace(/_/g, ' ').toUpperCase())}</span></td>
      <td><span class="tag ${statusTag}" style="font-size:10px; font-weight:700;">${esc(m.status.toUpperCase())}</span></td>
      <td style="font-size:11.5px; color:var(--t2); font-family:'JetBrains Mono',monospace;">${esc(m.joined_at ? new Date(m.joined_at).toLocaleDateString() : '—')}</td>
      <td style="text-align:right;">${roleDropdown}</td>
    </tr>`;
  }).join('');
}

function filterOrgMembers() {
  const query = (document.getElementById('org-member-search')?.value || '').toLowerCase().trim();
  if (!query) {
    renderOrgMembersTable(_orgMembersCache);
    return;
  }
  const filtered = _orgMembersCache.filter(m => 
    (m.display_name || '').toLowerCase().includes(query) || 
    (m.user_email || '').toLowerCase().includes(query) ||
    (m.role || '').toLowerCase().includes(query)
  );
  renderOrgMembersTable(filtered);
}

function renderOrgScansTable(scans) {
  const tbody = document.getElementById('org-scans-tbody');
  if (!tbody) return;

  if (!scans || scans.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--t3)">No scans performed by members in this sandbox yet.</td></tr>';
    return;
  }

  tbody.innerHTML = scans.map(s => {
    const risk = (s.risk_level || 'clean').toLowerCase();
    const tag = riskTag(risk);
    const timeStr = s.scanned_at ? new Date(s.scanned_at).toLocaleString() : '—';
    const sender = s.sender_email || s.sender || '—';
    const ip = s.header_analysis?.originating_ip || s.originating_ip || 'Internal / Cloud';

    return `<tr>
      <td style="font-size:11.5px; color:var(--t2); font-family:'JetBrains Mono',monospace; white-space:nowrap;">${esc(timeStr)}</td>
      <td>
        <span style="font-size:12px; font-weight:600; color:#a5b4fc; font-family:'JetBrains Mono',monospace;">${esc(s.user_email || s.user_id || 'Employee')}</span>
      </td>
      <td>
        <div style="font-size:12.5px; font-weight:600; color:var(--t1); max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${esc(s.subject || 'No Subject')}">${esc(s.subject || 'No Subject')}</div>
        <div style="font-size:11px; color:var(--t3);">${esc(sender)}</div>
      </td>
      <td style="font-size:11.5px; color:var(--t2); font-family:'JetBrains Mono',monospace;">${esc(ip)}</td>
      <td>${tag}</td>
    </tr>`;
  }).join('');
}

async function submitOrgInvite() {
  const emailInput = document.getElementById('org-invite-email');
  const nameInput = document.getElementById('org-invite-name');
  const roleSelect = document.getElementById('org-invite-role');
  const msgEl = document.getElementById('org-invite-msg');
  const btn = document.getElementById('org-btn-invite');

  const email = (emailInput?.value || '').trim();
  const name = (nameInput?.value || '').trim();
  const role = roleSelect?.value || 'user';

  if (!email || !email.includes('@')) {
    if (msgEl) {
      msgEl.style.display = 'block';
      msgEl.style.color = 'var(--red)';
      msgEl.textContent = 'Please provide a valid corporate employee email.';
    }
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Dispatching…';

  try {
    const res = await apiFetch(`${API}/org/invite`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, display_name: name, role: role })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.detail || 'Invitation failed');

    toast(`✅ Invitation dispatched to ${email} as ${role.toUpperCase()}!`, 'success');
    if (emailInput) emailInput.value = '';
    if (nameInput) nameInput.value = '';
    if (msgEl) {
      msgEl.style.display = 'block';
      msgEl.style.color = 'var(--green)';
      msgEl.textContent = `Enrolled ${email} into the sandbox with ${role.toUpperCase()} role.`;
      setTimeout(() => { msgEl.style.display = 'none'; }, 4000);
    }
    loadOrgManagement();
  } catch (e) {
    if (msgEl) {
      msgEl.style.display = 'block';
      msgEl.style.color = 'var(--red)';
      msgEl.textContent = e.message;
    }
    toast('Invitation error: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Invite to Sandbox';
  }
}

async function changeOrgMemberRole(email, newRole) {
  if (!confirm(`Change role for ${email} to ${newRole.toUpperCase()}?`)) {
    loadOrgManagement();
    return;
  }
  try {
    const res = await apiFetch(`${API}/org/members/role`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, role: newRole })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.detail || 'Role change failed');
    toast(`Role updated for ${email} -> ${newRole.toUpperCase()}`, 'success');
    loadOrgManagement();
  } catch (e) {
    toast('Error updating role: ' + e.message, 'error');
    loadOrgManagement();
  }
}

async function removeOrgMember(email) {
  if (!confirm(`Are you sure you want to remove ${email} from this Organization Sandbox? They will lose access to team telemetry.`)) {
    return;
  }
  try {
    const res = await apiFetch(`${API}/org/members`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.detail || 'Removal failed');
    toast(`Removed ${email} from organization.`, 'warning');
    loadOrgManagement();
  } catch (e) {
    toast('Error removing member: ' + e.message, 'error');
  }
}

function exportOrgSandboxReport() {
  if (!_orgCache) {
    toast('Please wait for organization data to load.', 'info');
    return;
  }
  const reportObj = {
    export_type: "ORGANIZATION_SANDBOX_TELEMETRY_AUDIT",
    generated_at: new Date().toISOString(),
    organization: {
      org_id: _orgCache.org_id,
      name: _orgCache.name,
      domain: _orgCache.domain,
      owner_email: _orgCache.owner_email
    },
    sandbox_stats: _orgCache.stats,
    team_roster: _orgCache.members,
    recent_scans: _orgCache.recent_scans
  };

  const blob = new Blob([JSON.stringify(reportObj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `SecureMail-OrgSandbox-${_orgCache.org_id}-${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Organization Sandbox Telemetry Report exported!', 'success');
}

// ── Enterprise API Key Management ──────────────────────
async function loadAPIKeys() {
  const tbody = document.getElementById('api-keys-tbody');
  if (!tbody) return;

  try {
    const res = await apiFetch(`${API}/api-keys`);
    if (!res.ok) return;
    const data = await res.json();
    const keys = data.api_keys || [];

    if (keys.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--t3)">No active API keys found. Generate a key for automated mail transfer or SIEM ingestion.</td></tr>';
      return;
    }

    tbody.innerHTML = keys.map(k => {
      const scopes = (k.scopes || []).map(s => `<span class="tag tag-info" style="font-size:10px;padding:2px 5px">${esc(s)}</span>`).join(' ');
      const statusTag = k.is_active
        ? '<span class="tag tag-clean" style="font-size:10px">ACTIVE</span>'
        : '<span class="tag tag-critical" style="font-size:10px">REVOKED</span>';

      const lastUsed = k.last_used_at ? timeAgo(k.last_used_at) : 'Never';

      return `<tr>
        <td style="font-weight:600;font-size:12.5px;color:var(--t1)">${esc(k.name)}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--cyan)">${esc(k.key_prefix)}</td>
        <td>${scopes}</td>
        <td style="font-weight:700;font-size:12px;color:var(--t1)">${k.usage_count || 0}</td>
        <td style="font-size:11.5px;color:var(--t2)">${lastUsed}</td>
        <td>${statusTag}</td>
        <td>
          ${k.is_active ? `<button class="btn btn-secondary btn-sm" style="color:var(--red);border-color:rgba(239,68,68,0.3);padding:2px 8px;font-size:11px" onclick="revokeAPIKey('${esc(k.id)}')">Revoke</button>` : '<span style="color:var(--t3);font-size:11px">—</span>'}
        </td>
      </tr>`;
    }).join('');
  } catch (e) {
    console.warn('API keys load error:', e);
  }
}

function openCreateAPIKeyModal() {
  const m = document.getElementById('modal-create-api-key');
  if (m) {
    document.getElementById('key-modal-name').value = '';
    m.style.display = 'flex';
  }
}

function closeCreateAPIKeyModal() {
  const m = document.getElementById('modal-create-api-key');
  if (m) m.style.display = 'none';
}

async function submitCreateAPIKey() {
  const name = (document.getElementById('key-modal-name')?.value || '').trim();
  if (!name) {
    toast('Please enter a key name / description', 'error');
    return;
  }

  const scopes = [];
  if (document.getElementById('scope-scans')?.checked) scopes.push('scans:write');
  if (document.getElementById('scope-threat')?.checked) scopes.push('threat_intel:read');
  if (document.getElementById('scope-forensics')?.checked) scopes.push('forensics:read');
  if (document.getElementById('scope-reports')?.checked) scopes.push('reports:export');

  const expiryVal = parseInt(document.getElementById('key-modal-expiry')?.value || '0');
  const expiresDays = expiryVal > 0 ? expiryVal : null;

  try {
    const res = await apiFetch(`${API}/api-keys`, {
      method: 'POST',
      body: JSON.stringify({
        name: name,
        scopes: scopes,
        expires_days: expiresDays
      })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to generate API key');
    }

    const data = await res.json();
    const createdKey = data.key;

    closeCreateAPIKeyModal();
    loadAPIKeys();

    // Show raw key modal
    const showModal = document.getElementById('modal-show-api-key');
    const rawBox = document.getElementById('modal-raw-key-text');
    if (showModal && rawBox) {
      rawBox.value = createdKey.raw_key;
      showModal.style.display = 'flex';
    }
  } catch (e) {
    toast(`Key generation failed: ${e.message}`, 'error');
  }
}

function closeShowAPIKeyModal() {
  const m = document.getElementById('modal-show-api-key');
  if (m) m.style.display = 'none';
}

function copyRawAPIKey() {
  const rawBox = document.getElementById('modal-raw-key-text');
  if (rawBox && rawBox.value) {
    navigator.clipboard.writeText(rawBox.value).then(() => {
      toast('API Key copied to clipboard! Store it securely.', 'success');
    }).catch(() => {
      toast('Copied', 'info');
    });
  }
}

async function revokeAPIKey(keyId) {
  if (!confirm('Are you sure you want to revoke this API key? Automated systems using this key will immediately be blocked.')) {
    return;
  }

  try {
    const res = await apiFetch(`${API}/api-keys/${keyId}`, { method: 'DELETE' });
    if (res.ok) {
      toast('API Key revoked successfully', 'success');
      loadAPIKeys();
    } else {
      toast('Failed to revoke API key', 'error');
    }
  } catch (e) {
    toast(`Revocation error: ${e.message}`, 'error');
  }
}

async function taUrlScan(){
  const url=document.getElementById('ta-url').value.trim();if(!url)return;
  loader('ta-url-loader',true);errShow('ta-url-err','');document.getElementById('ta-url-res').style.display='none';
  try{
    const r=await apiFetch(`${API}/scan/url`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d=await r.json();if(!r.ok)throw new Error(d.detail||'Failed');
    const res=d.scan_result||{};const det=res.detections??0;
    document.getElementById('ta-url-res').innerHTML=`${infoRow('Risk',riskTag(res.risk_level))}${infoRow('Detections',`<span style="color:${det>0?'var(--red)':'var(--green)'}">${det}/${res.total_engines||'?'}</span>`)}`;
    document.getElementById('ta-url-res').style.display='block';
  }catch(e){errShow('ta-url-err',e.message)}
  loader('ta-url-loader',false);
}

async function taIpScan(){
  const ip=document.getElementById('ta-ip').value.trim();if(!ip)return;
  loader('ta-ip-loader',true);errShow('ta-ip-err','');document.getElementById('ta-ip-res').style.display='none';
  try{
    const r=await apiFetch(`${API}/headers/ip-reputation?ip=${encodeURIComponent(ip)}`);
    const d=await r.json();if(!r.ok)throw new Error(d.detail||'Failed');
    const ipd=d.ip_reputation||d;
    document.getElementById('ta-ip-res').innerHTML=[['IP',esc(ipd.ip||ip)],['Country',esc(ipd.country_code||'—')],['ISP',esc(ipd.isp||'—')],['Abuse Score',`<span style="color:${(ipd.abuse_confidence_score||0)>50?'var(--red)':'var(--green)'}">${ipd.abuse_confidence_score??'—'}%</span>`],['Tor',ipd.is_tor?'<span style="color:var(--red)">YES</span>':'No']].map(([l,v])=>infoRow(l,v)).join('');
    document.getElementById('ta-ip-res').style.display='block';
  }catch(e){errShow('ta-ip-err',e.message)}
  loader('ta-ip-loader',false);
}

const taDrop=document.getElementById('ta-drop');
taDrop.addEventListener('dragover',e=>{e.preventDefault();taDrop.classList.add('over')});
taDrop.addEventListener('dragleave',()=>taDrop.classList.remove('over'));
taDrop.addEventListener('drop',e=>{e.preventDefault();taDrop.classList.remove('over');if(e.dataTransfer.files[0])doTaFile(e.dataTransfer.files[0])});
function taFileScan(e){if(e.target.files[0])doTaFile(e.target.files[0])}
async function doTaFile(file){
  loader('ta-file-loader',true);errShow('ta-file-err','');document.getElementById('ta-file-res').style.display='none';
  try{
    const fd=new FormData();fd.append('file',file);
    const r=await apiFetch(`${API}/attachments/scan`,{method:'POST',body:fd});
    const d=await r.json();if(!r.ok)throw new Error(d.detail||'Failed');
    const res=d.scan_result||{};const det=res.detections??0;
    document.getElementById('ta-file-res').innerHTML=`${infoRow('File',esc(d.filename))}${infoRow('Risk',riskTag(res.risk_level))}${infoRow('Detections',`<span style="color:${det>0?'var(--red)':'var(--green)'}">${det}/${res.total_engines||'?'}</span>`)}`;
    document.getElementById('ta-file-res').style.display='block';
  }catch(e){errShow('ta-file-err',e.message)}
  loader('ta-file-loader',false);
}

// ── Forensics ─────────────────────────────────
let _allLogs=[],_fPage=1;const PAGE=15;

async function loadForensics(){
  try{
    const [lr,sr]=await Promise.all([apiFetch(`${API}/forensics?limit=1000`),apiFetch(`${API}/forensics/stats`)]);
    if (!lr.ok) {
      const err = await lr.json().catch(() => ({}));
      throw new Error(err.detail || `Server status ${lr.status}`);
    }
    const ld=await lr.json();
    const stats= sr.ok ? (await sr.json().catch(()=>({}))) : {};
    _allLogs=(ld.logs||[]).map(l=>({...l, sender_email:l.sender_email||l.sender||''}));
    document.getElementById('f-total').textContent=stats.total??_allLogs.length;
    const brl=stats.by_risk_level||{};
    document.getElementById('f-crit').textContent=brl.critical??_allLogs.filter(l=>l.risk_level==='critical').length;
    document.getElementById('f-high').textContent=brl.high??_allLogs.filter(l=>l.risk_level==='high').length;
    document.getElementById('f-clean').textContent=brl.clean??_allLogs.filter(l=>l.risk_level==='clean').length;
    renderLogs(_allLogs,1);
  }catch(e){toast('Failed to load logs: '+e.message,'error')}
}

function filterLogs(){
  const q=document.getElementById('f-search').value.toLowerCase();
  const rv=document.getElementById('f-risk').value;
  const filtered=_allLogs.filter(l=>{
    const mq=!q||(l.sender_email||'').toLowerCase().includes(q)||(l.subject||'').toLowerCase().includes(q);
    const mr=!rv||l.risk_level===rv;
    return mq&&mr;
  });
  renderLogs(filtered,1);
}

function renderLogs(logs,page){
  _fPage=page;
  const slice=logs.slice((page-1)*PAGE,page*PAGE);
  const tbody=document.getElementById('f-tbody');
  if(!slice.length){tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--t3)">No logs found</td></tr>';document.getElementById('f-pag').innerHTML='';return}
  tbody.innerHTML=slice.map(l=>{
    const c=riskColor(l.risk_level);
    return`<tr>
      <td class="mono">${(l.scanned_at||'').replace('T',' ').replace('Z','')}</td>
      <td class="mono" style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(l.sender_email||'—')}</td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(l.subject||'—')}</td>
      <td><div style="font-weight:700;font-size:12.5px;color:${c};font-family:'JetBrains Mono',monospace">${l.risk_score}</div><div class="sbar-wrap" style="width:50px"><div class="sbar" style="width:${l.risk_score}%;background:${c}"></div></div></td>
      <td>${riskTag(l.risk_level)}</td>
      <td><div class="tags-row">${(l.threat_types||[]).filter(t=>t!=='clean').map(t=>`<span class="tag tag-info" style="font-size:10px">${t.replace(/_/g,' ')}</span>`).join('')||'—'}</div></td>
      <td><div style="display:flex;gap:5px">
        <button class="btn btn-secondary btn-sm" onclick="viewLog('${l.log_id||l.scan_id}')" title="View"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
        <button class="btn btn-secondary btn-sm" onclick="downloadForensicLogPDF('${l.log_id||l.scan_id}')" title="Download Forensic PDF"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg></button>
        <button class="btn btn-danger btn-sm" onclick="deleteLog('${l.log_id||l.scan_id}')" title="Delete"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg></button>
      </div></td>
    </tr>`;
  }).join('');
  const pages=Math.ceil(logs.length/PAGE);
  let pag=`<span style="color:var(--t3);font-size:12px;margin-right:6px">${logs.length} records</span>`;
  for(let i=1;i<=Math.min(pages,7);i++) pag+=`<button class="pg-btn${i===page?' active':''}" onclick="renderLogs(window._fl||_allLogs,${i})">${i}</button>`;
  document.getElementById('f-pag').innerHTML=pag;
  window._fl=logs;
}

function viewLog(id){
  const log=_allLogs.find(l=>l.scan_id===id);
  if(!log)return;
  nav('scan');renderScanResult(log);
  toast('Loaded scan log','success');
}

async function deleteLog(id){
  if(!confirm('Delete this scan log?'))return;
  try{
    const r=await apiFetch(`${API}/forensics/${id}`,{method:'DELETE'});
    if(!r.ok){const e=await r.json().catch(()=>({}));throw new Error(e.detail||'Delete failed');}
    _allLogs=_allLogs.filter(l=>l.scan_id!==id);filterLogs();toast('Deleted','success');
  }catch(e){toast(e.message,'error')}
}

async function exportForensics(fmt){
  try{
    toast(`Preparing ${fmt.toUpperCase()} export...`,'info');
    const r=await apiFetch(`${API}/forensics/export/${fmt}`);
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw new Error(d.detail||`Export HTTP ${r.status}`);
    }
    const blob=await r.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url;
    a.download=`securemail_forensics_${Date.now()}.${fmt}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast(`Exported forensic log as ${fmt.toUpperCase()}`,'success');
  }catch(e){
    toast(`Export failed: ${e.message}`,'error');
  }
}

// ── AI Threat Explainer ──────────────────────
async function fetchAIExplanation() {
  const d = window._currentScanData;
  if (!d) return;
  const btn = document.getElementById('ai-explain-btn');
  const box = document.getElementById('ai-explain-content');
  if (btn) btn.disabled = true;
  if (box) box.innerHTML = '<div style="display:flex;align-items:center;gap:8px;color:#818cf8"><div class="spinner" style="width:16px;height:16px;border-width:2px"></div><span>Analyzing threat details with AI…</span></div>';
  try {
    const r = await apiFetch(`${API}/ai/explain`, {
      method: 'POST',
      body: JSON.stringify(d)
    });
    if (!r.ok) {
      const err = await r.json().catch(()=>({}));
      throw new Error(err.detail || 'AI Explanation failed');
    }

    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let accumulatedText = '';
    box.innerHTML = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      const lines = chunk.split('\n');
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const jsonStr = line.slice(6).trim();
          try {
            const parsed = JSON.parse(jsonStr);
            if (parsed.error) {
              if (parsed.error === 'invalid_api_key') throw new Error('AI API Key invalid. Please check your GEMINI_API_KEY in .env');
              if (parsed.error === 'rate_limited') throw new Error('AI rate limit reached. Please try again shortly.');
              throw new Error(parsed.error);
            }
            if (parsed.type === 'content_block_delta' && parsed.delta && parsed.delta.text) {
              accumulatedText += parsed.delta.text;
            } else if (parsed.text) {
              accumulatedText += parsed.text;
            }
            const formatted = esc(accumulatedText)
              .replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--t1)">$1</strong>')
              .replace(/^- (.*)/gm, '<li style="margin-left:14px;color:var(--t2)">$1</li>')
              .replace(/\n\n/g, '<br><br>')
              .replace(/\n/g, '<br>');
            box.innerHTML = `<div style="line-height:1.6;font-size:12px;color:var(--t2);">${formatted}</div>`;
          } catch(pe) {
            // Ignore partial non-JSON stream chunks
          }
        }
      }
    }
    if (!accumulatedText.trim()) {
      box.innerHTML = `<span style="color:var(--t3);font-size:12px;">Scan analysis complete. No additional risk insights generated.</span>`;
    }
  } catch(e) {
    if (box) box.innerHTML = `<span style="color:var(--red);font-size:12px;">⚠ ${esc(e.message)}</span>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── Header Analysis ───────────────────────────
let _hdrMap = null;
let _hdrTileLayer = null;
let _hdrMarkers = [];

function getMapTileUrl() {
  const isLight = document.body.classList.contains('light-theme');
  return isLight
    ? 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
    : 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
}

function updateMapTheme() {
  if (_hdrMap && _hdrTileLayer) {
    _hdrTileLayer.setUrl(getMapTileUrl());
  }
}

function loadSampleHeaders() {
  const sample = `Received: from mx.google.com (mail-wm1-f41.google.com [209.85.218.41]) by mx.secure-enterprise.com with ESMTP id d9a1; Wed, 12 Aug 2026 14:02:40 +0000
Received: from gateway.eu.fastmail.com (fastmail.com [66.111.4.10]) by mx.google.com with ESMTP id f23; Wed, 12 Aug 2026 14:02:22 +0000
Received: from relay01.frankfurt.de (relay01.de [50.110.8.10]) by gateway.eu.fastmail.com with ESMTP id e12; Wed, 12 Aug 2026 14:01:50 +0000
Received: from client.evil-spoofer.ru (mail.evil.ru [185.234.218.47]) by relay01.frankfurt.de with ESMTP; Wed, 12 Aug 2026 14:01:30 +0000
From: "Executive Payroll" <payroll-update@evil-lookalike-domain.ru>
To: "Finance Team" <finance@secure-enterprise.com>
Subject: URGENT: Mandatory Wire Authorization Required
Authentication-Results: spf=fail (sender IP 185.234.218.47); dkim=none; dmarc=fail (p=reject) action=none`;
  document.getElementById('hdr-input').value = sample;
  toast('Sample multi-hop phishing headers loaded!', 'info');
}

function renderHopMap(trajectory, parsedHops) {
  const mapCard = document.getElementById('hdr-map-card');
  const banner = document.getElementById('hdr-trajectory-banner');
  const timeline = document.getElementById('hdr-hop-timeline');
  if (!mapCard || !banner || !timeline) return;

  const hops = (trajectory && trajectory.hops && trajectory.hops.length)
    ? trajectory.hops
    : (parsedHops || []);

  if (!hops.length) {
    mapCard.style.display = 'none';
    return;
  }

  mapCard.style.display = 'block';

  // 1. Render Summary Banner
  const totalTransit = trajectory.total_transit_seconds || 0;
  const anomaliesCount = (trajectory.anomalies || []).length;
  banner.innerHTML = `
    <div class="traj-stat">
      <span class="traj-label">Relay Hops</span>
      <span class="traj-val" style="color:var(--cyan);">${hops.length} MTAs</span>
    </div>
    <div class="traj-stat">
      <span class="traj-label">Transit Time</span>
      <span class="traj-val" style="color:${totalTransit > 300 ? 'var(--orange)' : 'var(--green)'};">${totalTransit}s total</span>
    </div>
    <div class="traj-stat">
      <span class="traj-label">Origin Country</span>
      <span class="traj-val" style="color:var(--red);">${esc(trajectory.origin_country || 'Unknown')}</span>
    </div>
    <div class="traj-stat">
      <span class="traj-label">Destination</span>
      <span class="traj-val" style="color:var(--green);">${esc(trajectory.destination_country || 'Unknown')}</span>
    </div>
    <div class="traj-stat">
      <span class="traj-label">Relay Status</span>
      <span class="traj-val" style="color:${anomaliesCount ? 'var(--orange)' : 'var(--green)'};">
        ${anomaliesCount ? `⚠️ ${anomaliesCount} Anomaly` : '✓ Normal Transit'}
      </span>
    </div>
  `;

  // 2. Initialize Leaflet Map
  if (typeof L === 'undefined') {
    console.warn('Leaflet not loaded');
    return;
  }

  if (_hdrMap) {
    try { _hdrMap.remove(); } catch(e) {}
    _hdrMap = null;
  }

  _hdrMap = L.map('hdr-map', {
    zoomControl: true,
    attributionControl: false,
    minZoom: 2,
    maxZoom: 14
  }).setView([20, 0], 2);

  _hdrTileLayer = L.tileLayer(getMapTileUrl(), {
    maxZoom: 18,
    subdomains: 'abcd'
  }).addTo(_hdrMap);

  _hdrMarkers = [];
  const latLngs = [];

  hops.forEach((h, i) => {
    const lat = h.latitude || 0;
    const lon = h.longitude || 0;
    if (lat === 0 && lon === 0) return;

    latLngs.push([lat, lon]);

    let pinClass = 'hop-pin-relay';
    let roleText = 'Intermediate Relay';
    if (h.is_origin || i === 0) {
      pinClass = 'hop-pin-origin';
      roleText = 'Originating MTA (Sender)';
    } else if (h.is_destination || i === hops.length - 1) {
      pinClass = 'hop-pin-dest';
      roleText = 'Destination MX Gateway';
    } else if (h.is_private) {
      pinClass = 'hop-pin-lan';
      roleText = 'Internal Subnet (RFC-1918)';
    }

    const icon = L.divIcon({
      className: 'custom-leaflet-marker',
      html: `<div class="hop-pin ${pinClass}">${h.hop_number || i + 1}</div>`,
      iconSize: [24, 24],
      iconAnchor: [12, 12],
      popupAnchor: [0, -12]
    });

    const popupHtml = `
      <div class="hop-popup-hdr">
        <span class="hop-popup-title">${roleText}</span>
        <span style="font-size:10px; font-weight:700; color:var(--cyan); background:rgba(59,130,246,0.15); padding:1px 5px; border-radius:4px;">HOP ${h.hop_number || i + 1}</span>
      </div>
      <div class="hop-popup-row"><span>Location</span><span class="hop-popup-val">${esc(h.city || 'Unknown')}, ${esc(h.country || 'Unknown')} (${esc(h.country_code || 'XX')})</span></div>
      <div class="hop-popup-row"><span>IP Address</span><span class="hop-popup-val">${esc(h.ip || '—')}</span></div>
      <div class="hop-popup-row"><span>Network / ISP</span><span class="hop-popup-val">${esc(h.isp || '—')}</span></div>
      <div class="hop-popup-row"><span>MTA Host</span><span class="hop-popup-val" style="max-width:140px; overflow:hidden; text-overflow:ellipsis;">${esc(h.host_from || h.from || '—')}</span></div>
      <div class="hop-popup-row"><span>Transit Delay</span><span class="hop-popup-val" style="color:${(h.delay_seconds || 0) > 60 ? 'var(--orange)' : 'var(--green)'};">+${h.delay_seconds || 0}s</span></div>
      ${h.anomaly ? `<div style="margin-top:6px; font-size:10px; color:#ef4444; font-weight:700;">⚠️ ${esc(h.anomaly)}</div>` : ''}
    `;

    const marker = L.marker([lat, lon], { icon: icon }).addTo(_hdrMap).bindPopup(popupHtml);
    _hdrMarkers.push(marker);
  });

  // 3. Draw Route Polyline
  if (latLngs.length > 1) {
    L.polyline(latLngs, {
      color: '#60a5fa',
      weight: 3,
      opacity: 0.85,
      dashArray: '6, 8'
    }).addTo(_hdrMap);
  }

  // 4. Render Chronological Stepper Cards
  timeline.innerHTML = hops.map((h, i) => {
    const isOrig = h.is_origin || i === 0;
    const isDest = h.is_destination || i === hops.length - 1;
    const roleBadge = isOrig ? '🔴 Origin' : isDest ? '🟢 Destination' : `🟡 Hop ${h.hop_number || i + 1}`;
    const delayTxt = (h.delay_seconds || 0) > 0 ? `+${h.delay_seconds}s` : '0s';

    return `
      <div class="hdr-step-card" id="hdr-step-${i}" onclick="focusHop(${i}, ${h.latitude || 0}, ${h.longitude || 0})">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
          <span style="font-size:10.5px; font-weight:700; color:var(--t1);">${roleBadge}</span>
          <span style="font-size:10.5px; font-weight:700; color:${(h.delay_seconds || 0) > 60 ? 'var(--orange)' : 'var(--green)'};">${delayTxt}</span>
        </div>
        <div style="font-size:12px; font-weight:600; color:var(--t1); margin-bottom:2px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
          ${esc(h.city || 'Unknown')}, ${esc(h.country || 'Unknown')}
        </div>
        <div style="font-size:10.5px; color:var(--t3); font-family:'JetBrains Mono',monospace;">
          ${esc(h.ip || 'Private Subnet')} • ${esc(h.isp || 'MTA')}
        </div>
      </div>
    `;
  }).join('');

  // 5. Invalidate Size and Fit Bounds
  setTimeout(() => {
    if (_hdrMap) {
      _hdrMap.invalidateSize();
      if (latLngs.length > 0) {
        const bounds = L.latLngBounds(latLngs);
        _hdrMap.fitBounds(bounds, { padding: [40, 40], maxZoom: 7 });
      }
    }
  }, 200);
}

function focusHop(idx, lat, lon) {
  document.querySelectorAll('.hdr-step-card').forEach((el, i) => {
    el.classList.toggle('active', i === idx);
  });
  if (_hdrMap && lat !== 0 && lon !== 0) {
    _hdrMap.flyTo([lat, lon], 6, { duration: 1.0 });
    if (_hdrMarkers[idx]) {
      _hdrMarkers[idx].openPopup();
    }
  }
}

async function analyzeHeaders(){
  const raw=document.getElementById('hdr-input').value.trim();if(!raw)return;
  errShow('hdr-err','');loader('hdr-loader',true);document.getElementById('hdr-result').style.display='none';
  try{
    const r=await apiFetch(`${API}/scan/email`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw_email:raw})});
    const d=await r.json();if(!r.ok)throw new Error(d.detail||'Failed');
    const auth=d.authentication||{};const h=d.header_analysis||{};const ip=h.ip_reputation;
    document.getElementById('ha-auth').innerHTML=['spf','dkim','dmarc','arc'].map(k=>`<div class="info-row"><span class="info-label">${k.toUpperCase()}</span><div class="auth-val ${authC(auth[k])}">${auth[k]||'unknown'}</div></div>`).join('');
    document.getElementById('ha-sender').innerHTML=[['From',esc(d.sender_email||'—')],['Subject',esc(d.subject||'—')],['Domain',esc(h.from_domain||'—')],['Spoof',h.display_name_spoof?'<span style="color:var(--red)">⚠ YES</span>':'<span style="color:var(--green)">No</span>'],['Reply-To Mismatch',h.reply_to_mismatch?'<span style="color:var(--orange)">⚠ YES</span>':'<span style="color:var(--green)">No</span>']].map(([l,v])=>infoRow(l,v)).join('');
    document.getElementById('ha-meta').innerHTML=[['Originating IP',esc(h.originating_ip||'Not detected')],['Country',esc(ip?.country_code||'—')],['ISP',esc(ip?.isp||'—')],['Abuse Score',ip?`${ip.abuse_confidence_score}%`:'—'],['Risk Score',`<span style="color:${riskColor(d.risk_level)};font-weight:700">${d.risk_score} — ${(d.risk_level||'').toUpperCase()}</span>`]].map(([l,v])=>infoRow(l,v)).join('');
    document.getElementById('hdr-result').style.display='block';

    // 🗺️ Render SMTP Hop Geolocation Map & Trajectory
    const hopAudit = d.received_hop_audit || {};
    renderHopMap(hopAudit.trajectory || {}, hopAudit.hops || []);
  }catch(e){errShow('hdr-err',e.message)}
  loader('hdr-loader',false);
}

// ── Browser Extension ─────────────────────────
function showExtInst(browser){
  const steps={
    chrome:[
      'Click the <strong>Download Extension (.zip)</strong> button above (or download from the <a href="https://github.com/samirkhurshid/SecureMail" target="_blank" style="color:var(--cyan);text-decoration:underline;font-weight:600">GitHub Repository</a>).',
      'Right-click the downloaded <code style="color:var(--cyan)">securemail-extension.zip</code> file and choose <strong>Extract All…</strong> to unzip it into a folder.',
      'Open Chrome, Edge, or Brave and navigate to <code style="color:var(--cyan)">chrome://extensions</code> (or <code style="color:var(--cyan)">edge://extensions</code> for Edge) in your address bar.',
      'Turn ON <strong>Developer mode</strong> using the toggle switch located in the top-right corner.',
      'Click the <strong>Load unpacked</strong> button in the top-left toolbar, and select the extracted <code style="color:var(--cyan)">extension</code> folder.',
      '<strong>Protection Active!</strong> The SecureMail shield icon appears in your browser toolbar. It automatically connects to the live cloud detection engine!'
    ],
    firefox:[
      'Click the <strong>Download Extension (.zip)</strong> button above (or download from the <a href="https://github.com/samirkhurshid/SecureMail" target="_blank" style="color:var(--cyan);text-decoration:underline;font-weight:600">GitHub Repository</a>).',
      'Extract the downloaded <code style="color:var(--cyan)">securemail-extension.zip</code> file to a folder on your computer.',
      'Open Firefox and navigate to <code style="color:var(--cyan)">about:debugging#/runtime/this-firefox</code> in your address bar.',
      'Click <strong>Load Temporary Add-on…</strong>',
      'Browse into the extracted folder and select the <code style="color:var(--cyan)">manifest.json</code> file.',
      '<strong>Active!</strong> SecureMail is now running and protecting your web mail sessions.'
    ]
  };
  document.getElementById('ext-inst-title').innerHTML = (browser==='chrome'?'Chrome / Edge / Brave Installation Guide':'Firefox Installation Guide') + ' <span style="font-size:12px;color:var(--t2);font-weight:normal;margin-left:8px">(No Chrome Web Store account needed)</span>';
  document.getElementById('ext-inst-body').innerHTML = steps[browser].map((s,i)=>`<div class="ext-step"><div class="ext-step-num">${i+1}</div><div class="ext-step-txt">${s}</div></div>`).join('');
  document.getElementById('ext-inst-card').style.display='block';
  document.getElementById('ext-inst-card').scrollIntoView({behavior:'smooth',block:'nearest'});
}

// ── Settings ──────────────────────────────────
async function loadSettings(){
  const s=JSON.parse(localStorage.getItem('sm_cfg')||'{}');
  document.getElementById('pref-sandbox').checked = s.sandbox !== false;
  document.getElementById('pref-vt').checked = s.vt_integration !== false;
  document.getElementById('pref-url-db').checked = s.url_db !== false;
  document.getElementById('pref-report').checked = s.report !== false;
  document.getElementById('pref-threshold').checked = s.threshold !== false;

  if (!window._authUser) return; // Skip protected settings status for unauthenticated guests

  loadAPIKeys();

  try {
    const r = await apiFetch(`${API}/settings/status`);
    if(r.ok) {
      const data = await r.json();
      if(data.virustotal && data.virustotal.key_preview && !document.getElementById('cfg-vt').value) {
        document.getElementById('cfg-vt').value = data.virustotal.key_preview;
      }
      if(data.abuseipdb && data.abuseipdb.key_preview && !document.getElementById('cfg-abuse').value) {
        document.getElementById('cfg-abuse').value = data.abuseipdb.key_preview;
      }
    }
  } catch(e) {
    console.warn('Settings status load error:', e);
  }
}

async function saveSettings(){
  const cfg={
    vt:document.getElementById('cfg-vt').value,
    abuse:document.getElementById('cfg-abuse').value,
    sandbox:document.getElementById('pref-sandbox').checked,
    vt_integration:document.getElementById('pref-vt').checked,
    url_db:document.getElementById('pref-url-db').checked,
    report:document.getElementById('pref-report').checked,
    threshold:document.getElementById('pref-threshold').checked
  };
  localStorage.setItem('sm_cfg',JSON.stringify(cfg));
  toast('Preferences saved successfully!','success');
}

async function testApiConnections() {
  const resBox = document.getElementById('api-test-results');
  if(resBox) {
    resBox.style.display = 'block';
    resBox.innerHTML = '<div style="display:flex;align-items:center;gap:8px;color:#818cf8;font-size:12px"><div class="spinner" style="width:16px;height:16px;border-width:2px"></div><span>Pinging VirusTotal, AbuseIPDB, and Anthropic APIs...</span></div>';
  }
  try {
    const r = await apiFetch(`${API}/settings/test`);
    if(!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    let html = `<div style="font-size:12px;font-weight:700;color:${d.overall==='fully_operational'?'var(--green)':'var(--amber)'};margin-bottom:8px">Overall Status: ${(d.overall||'').toUpperCase()}</div>`;
    const services = d.services || {};
    for(const [name, info] of Object.entries(services)) {
      const isOk = info.status === 'ok';
      html += `<div style="font-size:11.5px;color:${isOk?'var(--green)':'var(--t3)'};margin-bottom:4px">
        <strong>${name.toUpperCase()}</strong>: ${esc(info.message || info.status)} ${info.response_time_ms ? `(${info.response_time_ms}ms)` : ''}
      </div>`;
    }
    if(resBox) resBox.innerHTML = html;
  } catch(e) {
    if(resBox) resBox.innerHTML = `<span style="color:var(--red);font-size:12px">⚠ Connection test error: ${esc(e.message)}</span>`;
  }
}

// ── Redesigned Settings Actions ───────────────
function connectOutlook(){
  toast('Redirecting to Outlook OAuth interface...', 'info');
}
function chooseLocalFolder(){
  toast('Select local directory opened.', 'success');
}
function syncToCloud(){
  toast('Cloud database synchronization initiated.', 'success');
}

// ── Account Management ────────────────────────
async function loadAccountPage() {
  const user = window._authUser || (window._fbAuth ? window._fbAuth.currentUser : null);
  if (!user) return;

  const rawName = user.displayName || (user.email ? user.email.split('@')[0] : 'User');
  const email   = user.email || '';
  const initial = rawName.charAt(0).toUpperCase();

  const nameEl  = document.getElementById('acc-display-name');
  const emailEl = document.getElementById('acc-email');
  const wrap    = document.getElementById('acc-avatar-wrap');
  const badge   = document.getElementById('acc-provider-badge');
  const roleEl  = document.getElementById('acc-role-badge');
  const pwRow   = document.getElementById('acc-pw-reset-row');

  if (nameEl)  nameEl.textContent  = rawName;
  if (emailEl) emailEl.textContent = email;

  if (wrap) {
    if (user.photoURL) {
      wrap.innerHTML = `<img src="${esc(user.photoURL)}" alt="${esc(rawName)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;" referrerpolicy="no-referrer"/>`;
    } else {
      wrap.innerHTML = `<span id="acc-user-initials">${esc(initial)}</span>`;
    }
  }

  // Update role badge in Account page
  const accEmailClean = (user.email || '').toLowerCase().trim();
  const isAccAdmin = accEmailClean === 'sameerkhurshed2@gmail.com' || accEmailClean.includes('sameerkhurshed') || accEmailClean.includes('samirkhurshid');
  if (isAccAdmin) {
    window._userRole = 'admin';
    if (!window._userPermissions || window._userPermissions.length === 0) window._userPermissions = ['*'];
  }

  if (roleEl && window._userRole) {
    roleEl.textContent = window._userRole.replace(/_/g, ' ').toUpperCase();
    roleEl.className = `tag ${window._userRole === 'admin' ? 'tag-critical' : window._userRole === 'soc_analyst' ? 'tag-high' : window._userRole === 'auditor' ? 'tag-medium' : 'tag-info'}`;
  }

  // Provider detection
  const isPassword = user.providerData && user.providerData.some(p => p.providerId === 'password');
  const isGoogle   = user.providerData && user.providerData.some(p => p.providerId === 'google.com');

  if (badge) {
    if (isPassword && isGoogle) {
      badge.textContent = 'Google OAuth + Password';
      badge.className = 'tag tag-clean';
    } else if (isPassword) {
      badge.textContent = 'Email & Password';
      badge.className = 'tag tag-info';
    } else if (isGoogle) {
      badge.textContent = 'Google OAuth';
      badge.className = 'tag tag-info';
    } else {
      badge.textContent = 'Standard';
      badge.className = 'tag tag-info';
    }
  }

  const resetBtn = document.getElementById('acc-btn-reset-pw');
  const setPwBtn = document.getElementById('acc-btn-set-pw');
  if (resetBtn) resetBtn.style.display = isPassword ? 'inline-flex' : 'none';
  if (setPwBtn) setPwBtn.style.display = (isGoogle && !isPassword) ? 'inline-flex' : 'none';

  // Dates
  const createdEl   = document.getElementById('acc-created-at');
  const lastLoginEl = document.getElementById('acc-last-login');
  if (createdEl)   createdEl.textContent   = user.metadata?.creationTime ? new Date(user.metadata.creationTime).toLocaleString() : '-';
  if (lastLoginEl) lastLoginEl.textContent = user.metadata?.lastSignInTime ? new Date(user.metadata.lastSignInTime).toLocaleString() : '-';

  // Fetch backend account stats & role
  try {
    const [meRes, roleRes] = await Promise.all([
      apiFetch(`${API}/account/me`),
      apiFetch(`${API}/account/roles/me?email=${encodeURIComponent(accEmailClean)}`)
    ]);

    if (roleRes.ok) {
      const roleData = await roleRes.json();
      if (roleData && roleData.role) {
        const finalRole = isAccAdmin ? 'admin' : roleData.role;
        window._userRole = finalRole;
        window._userPermissions = isAccAdmin ? ['*'] : (roleData.permissions || []);
        if (roleEl) {
          roleEl.textContent = finalRole.replace(/_/g, ' ').toUpperCase();
          roleEl.className = `tag ${finalRole === 'admin' ? 'tag-critical' : finalRole === 'soc_analyst' ? 'tag-high' : finalRole === 'auditor' ? 'tag-medium' : 'tag-info'}`;
        }
        const sideBadge = document.getElementById('sidebar-role-badge');
        if (sideBadge) {
          sideBadge.textContent = finalRole.replace(/_/g, ' ').toUpperCase();
          sideBadge.className = `tag ${finalRole === 'admin' ? 'tag-critical' : finalRole === 'soc_analyst' ? 'tag-high' : finalRole === 'auditor' ? 'tag-medium' : 'tag-info'}`;
        }
      }
    }

    if (meRes.ok) {
      const data = await meRes.json();
      const stats = data.stats || {};
      const totalEl   = document.getElementById('acc-stat-total');
      const threatEl  = document.getElementById('acc-stat-threats');
      const cleanEl   = document.getElementById('acc-stat-clean');

      if (totalEl)  totalEl.textContent  = stats.total || 0;
      if (threatEl) threatEl.textContent = (stats.critical || 0) + (stats.high || 0) + (stats.medium || 0);
      if (cleanEl)  cleanEl.textContent  = stats.clean || 0;

      const digestToggle = document.getElementById('acc-digest-toggle');
      const webhookInput = document.getElementById('acc-webhook-url');
      if (digestToggle) digestToggle.checked = data.digest_enabled !== false;
      if (webhookInput) webhookInput.value = data.webhook_url || '';

      // Email verification status
      const isVerified = Boolean(data.email_verified || user.emailVerified);
      const verifyBadge = document.getElementById('acc-verified-badge');
      const verifyBanner = document.getElementById('acc-verify-banner');

      if (verifyBadge) {
        if (isVerified) {
          verifyBadge.textContent = '✓ EMAIL VERIFIED';
          verifyBadge.className = 'tag tag-clean';
        } else {
          verifyBadge.textContent = '⚠ EMAIL UNVERIFIED';
          verifyBadge.className = 'tag tag-medium';
        }
      }
      if (verifyBanner) {
        verifyBanner.style.display = isVerified ? 'none' : 'block';
      }

      // Cosmetic UX: adjust audit-trail visibility based on user permissions
      const auditNav = document.getElementById('nav-audit-trail');
      if (auditNav) {
        const canAudit = window._userPermissions.includes('audit:read') || window._userRole === 'admin' || window._userRole === 'auditor';
        auditNav.style.display = canAudit ? 'flex' : 'none';
      }
    }
  } catch (e) {
    console.warn('Failed to load account stats', e);
  }
}

async function resendAccountVerification() {
  const user = window._authUser || (window._fbAuth ? window._fbAuth.currentUser : null);
  if (!user || !user.email) {
    toast('Please sign in to resend verification email', 'error');
    return;
  }
  try {
    if (window._fbSendVerification && window._fbAuth?.currentUser) {
      await window._fbSendVerification(window._fbAuth.currentUser);
      toast('Verification email dispatched to ' + user.email + '! Check your inbox.', 'success');
    } else if (window._authToken) {
      const res = await apiFetch(`${API}/auth/resend-verification`, {
        method: 'POST',
        body: JSON.stringify({ id_token: window._authToken })
      });
      if (res.ok) {
        toast('Verification email dispatched to ' + user.email + '! Check your inbox.', 'success');
      } else {
        const d = await res.json().catch(() => ({}));
        toast(`Verification dispatch failed: ${d.detail?.message || d.detail || 'Error'}`, 'error');
      }
    }
  } catch (e) {
    console.error('[Resend Verification Error]', e);
    toast(`Failed to dispatch verification email: ${e.message}`, 'error');
  }
}

async function triggerPasswordReset() {
  const user = window._authUser || (window._fbAuth ? window._fbAuth.currentUser : null);
  if (!user || !user.email) {
    toast('No email address associated with account', 'error');
    return;
  }
  try {
    const modules = window._fbAuthModules || {};
    if (modules.sendPasswordResetEmail && window._fbAuth) {
      await modules.sendPasswordResetEmail(window._fbAuth, user.email);
      toast('Password reset link sent to your email address.', 'success');
    } else {
      toast('Password reset service unavailable', 'error');
    }
  } catch (e) {
    toast(`Failed to send reset email: ${e.message}`, 'error');
  }
}

async function toggleDigestPreference(enabled) {
  try {
    const res = await apiFetch(`${API}/account/preferences`, {
      method: 'PATCH',
      body: JSON.stringify({ digest_enabled: enabled })
    });
    if (res.ok) {
      toast(`Weekly digest emails ${enabled ? 'enabled' : 'disabled'}`, 'success');
    } else {
      toast('Failed to update digest preference', 'error');
    }
  } catch (e) {
    toast(`Error updating preferences: ${e.message}`, 'error');
  }
}

async function saveWebhookUrl() {
  const url = (document.getElementById('acc-webhook-url').value || '').trim();
  if (url && !url.startsWith('https://')) {
    toast('Webhook URL must start with https://', 'error');
    return;
  }
  try {
    const res = await apiFetch(`${API}/account/webhook`, {
      method: 'PATCH',
      body: JSON.stringify({ webhook_url: url || null })
    });
    if (res.ok) {
      toast(url ? 'Webhook URL saved successfully' : 'Webhook URL cleared', 'success');
    } else {
      const d = await res.json().catch(() => ({}));
      toast(`Failed to save webhook: ${d.detail || 'Error'}`, 'error');
    }
  } catch (e) {
    toast(`Error saving webhook: ${e.message}`, 'error');
  }
}

async function testWebhookUrl() {
  try {
    const res = await apiFetch(`${API}/account/webhook/test`, { method: 'POST' });
    if (res.ok) {
      toast('Test notification sent to webhook URL!', 'success');
    } else {
      const d = await res.json().catch(() => ({}));
      toast(`Test failed: ${d.detail || 'Check your webhook URL'}`, 'error');
    }
  } catch (e) {
    toast(`Test notification error: ${e.message}`, 'error');
  }
}

async function downloadUserData() {
  try {
    toast('Preparing your data export...', 'info');
    const res = await apiFetch(`${API}/account/export`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    const dateStr = new Date().toISOString().split('T')[0];
    a.download = `securemail-data-export-${dateStr}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    toast('Data export downloaded successfully!', 'success');
  } catch (e) {
    toast(`Export failed: ${e.message}`, 'error');
  }
}

function openDeleteAccountModal() {
  const user = window._currentUser || (window._fbAuth ? window._fbAuth.currentUser : null);
  if (!user || !user.email) return;
  const targetEmailEl = document.getElementById('del-modal-target-email');
  const emailInput    = document.getElementById('del-modal-email-input');
  const btn           = document.getElementById('del-modal-submit-btn');

  if (targetEmailEl) targetEmailEl.textContent = user.email;
  if (emailInput)    emailInput.value = '';
  if (btn) {
    btn.disabled = true;
    btn.style.opacity = '0.5';
    btn.style.cursor  = 'not-allowed';
  }
  const modal = document.getElementById('modal-delete-account');
  if (modal) modal.style.display = 'flex';
}

function closeDeleteAccountModal() {
  const modal = document.getElementById('modal-delete-account');
  if (modal) modal.style.display = 'none';
}

function validateDeleteEmailInput() {
  const user = window._currentUser || (window._fbAuth ? window._fbAuth.currentUser : null);
  if (!user || !user.email) return;
  const inputVal = (document.getElementById('del-modal-email-input').value || '').trim();
  const btn      = document.getElementById('del-modal-submit-btn');
  if (!btn) return;

  if (inputVal.toLowerCase() === user.email.toLowerCase()) {
    btn.disabled = false;
    btn.style.opacity = '1';
    btn.style.cursor  = 'pointer';
  } else {
    btn.disabled = true;
    btn.style.opacity = '0.5';
    btn.style.cursor  = 'not-allowed';
  }
}

async function submitAccountDeletion() {
  try {
    const res = await apiFetch(`${API}/account/delete`, { method: 'POST' });
    if (res.ok) {
      closeDeleteAccountModal();
      toast('Account scheduled for deletion. Signing out...', 'warning');
      setTimeout(async () => {
        if (window._fbAuth) {
          await window._fbAuth.signOut();
        }
      }, 1500);
    } else {
      const d = await res.json();
      toast(`Deletion failed: ${d.detail || 'Error'}`, 'error');
    }
  } catch (e) {
    toast(`Error requesting deletion: ${e.message}`, 'error');
  }
}

function showPendingDeletionScreen(msg) {
  showAuthScreen();
  const errEl = document.getElementById('signin-err');
  if (errEl) {
    errEl.textContent = msg || "This account is scheduled for deletion and can no longer be accessed. Contact support if this was a mistake.";
    errEl.classList.add('on');
  }
}

// ── Init ──────────────────────────────────────
function _initDashboardAfterAuth() {
  nav('dashboard');
  const isCloud = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1';
  const healthUrl = `${API}/health`;
  apiFetch(healthUrl).catch(() => fetch(`${API.replace(/\/api$/, '')}/health`)).then(r=>r.json()).then(d=>{
    if(d.status!=='healthy')throw new Error();
  }).catch(()=>{
    if (isCloud) {
      toast('⏳ Backend is waking up (Render free tier) or reconnecting...', 'info');
    } else {
      toast('⚠ Backend offline. Run: python -m uvicorn app.main:app --port 8000','error');
    }
    const tc = document.getElementById('threats-today-count');
    if(tc) tc.textContent = isCloud ? 'Connecting...' : 'Backend Offline';
    const badge = document.querySelector('.threat-today-badge');
    if(badge) badge.style.borderColor='rgba(239,68,68,0.3)';
  });
}

// ── Theme Management ──────────────────────────
function toggleTheme() {
  const isLight = document.body.classList.toggle('light-theme');
  localStorage.setItem('theme', isLight ? 'light' : 'dark');
  document.getElementById('theme-text').textContent = isLight ? 'Dark Theme' : 'Light Theme';
  updateMapTheme();
  toast('Switched to ' + (isLight ? 'light' : 'dark') + ' theme', 'success');
}

function initTheme() {
  const saved = localStorage.getItem('theme');
  if (saved === 'light') {
    document.body.classList.add('light-theme');
    document.getElementById('theme-text').textContent = 'Dark Theme';
  } else {
    document.getElementById('theme-text').textContent = 'Light Theme';
  }
}


// ════════════════════════════════════════════════════════════
// Auth functions
// ════════════════════════════════════════════════════════════

// ── Password visibility toggle ───────────────────────────────
function togglePwVis(btn) {
  const input = btn.parentElement.querySelector('input');
  if (!input) return;
  const isHidden = input.type === 'password';
  input.type = isHidden ? 'text' : 'password';
  // Swap icon: eye-open ↔ eye-off
  btn.innerHTML = isHidden
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
}

// ── Panel switchers ──────────────────────────────────────────
function showSignIn()       { _authPanel('signin'); }
function showSignUp()       { _authPanel('signup'); }
function showForgotPassword(){ _authPanel('forgot'); }
function _authPanel(name) {
  ['signin','signup','forgot','onboarding'].forEach(p => {
    const el = document.getElementById('auth-'+p);
    if (el) el.style.display = p===name ? '' : 'none';
  });
  ['signin-err','signup-err','forgot-err','forgot-ok','onboard-err'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.textContent=''; el.classList.remove('on'); }
  });
  const googleHint = document.getElementById('signin-google-hint');
  if (googleHint && name !== 'signin') googleHint.style.display = 'none';
  const googleBtn = document.querySelector('#auth-signin .auth-btn-google');
  if (googleBtn && name !== 'signin') googleBtn.classList.remove('pulse-google-btn');
}

// ── Show / hide app ──────────────────────────────────────────
function showApp(user) {
  if (window._isOnboardingActive) {
    return;
  }
  closeAuthModal();
  const trialEl = document.getElementById('trial-screen');
  if (trialEl) trialEl.style.display = 'none';
  document.getElementById('app').style.display = '';
  
  // Hide guest widget, show user widget
  const guestWidget = document.getElementById('sidebar-guest');
  if (guestWidget) guestWidget.classList.remove('visible');
  
  // Safe user details extraction
  const rawName = user.displayName || (user.email ? user.email.split('@')[0] : 'User');
  const email   = user.email || '';
  const initial = rawName.charAt(0).toUpperCase();

  const nameEl  = document.getElementById('user-display-name');
  const emailEl = document.getElementById('user-display-email');
  const wrap    = document.getElementById('user-avatar-wrap');
  const widget  = document.getElementById('sidebar-user');

  if (nameEl)  nameEl.textContent  = rawName;
  if (emailEl) emailEl.textContent = email;

  if (wrap) {
    if (user.photoURL) {
      wrap.innerHTML = `<img src="${esc(user.photoURL)}" alt="${esc(rawName)}" referrerpolicy="no-referrer"/>`;
    } else {
      wrap.innerHTML = `<span id="user-initials">${esc(initial)}</span>`;
    }
  }

  if (widget) widget.classList.add('visible');

  // Immediately identify and apply Admin badge
  const cleanEmail = email.toLowerCase().trim();
  const isAdminEmail = cleanEmail === 'sameerkhurshed2@gmail.com' || cleanEmail.includes('sameerkhurshed') || cleanEmail.includes('samirkhurshid');
  const roleBadge = document.getElementById('sidebar-role-badge');
  const auditNav = document.getElementById('nav-audit-trail');
  const orgNav = document.getElementById('nav-org-management');

  if (isAdminEmail) {
    window._userRole = 'admin';
    window._userPermissions = ['*'];
    if (roleBadge) {
      roleBadge.textContent = 'ADMIN';
      roleBadge.className = 'tag tag-critical';
      roleBadge.style.display = 'inline-block';
    }
    if (auditNav) auditNav.style.display = 'flex';
    if (orgNav) orgNav.style.display = 'flex';
  } else if (window._userRole && roleBadge) {
    roleBadge.textContent = window._userRole.replace(/_/g, ' ').toUpperCase();
    roleBadge.className = `tag ${window._userRole === 'admin' ? 'tag-critical' : window._userRole === 'soc_analyst' ? 'tag-high' : window._userRole === 'auditor' ? 'tag-medium' : 'tag-info'}`;
    if (orgNav) orgNav.style.display = (window._userRole === 'admin' || window._userRole === 'soc_analyst') ? 'flex' : 'none';
  }

  // Fetch and update user RBAC role badge from server
  try {
    apiFetch(`${API}/account/roles/me?email=${encodeURIComponent(cleanEmail)}`).then(r => {
      if (!r.ok) return;
      return r.json();
    }).then(data => {
      if (data && data.role) {
        let finalRole = data.role;
        if (isAdminEmail) finalRole = 'admin';
        window._userRole = finalRole;
        window._userPermissions = data.permissions || (finalRole === 'admin' ? ['*'] : []);
        if (roleBadge) {
          roleBadge.textContent = finalRole.replace(/_/g, ' ').toUpperCase();
          roleBadge.className = `tag ${finalRole === 'admin' ? 'tag-critical' : finalRole === 'soc_analyst' ? 'tag-high' : finalRole === 'auditor' ? 'tag-medium' : 'tag-info'}`;
        }
        if (auditNav) {
          const canAudit = (window._userPermissions || []).includes('audit:read') || finalRole === 'admin' || finalRole === 'auditor';
          auditNav.style.display = canAudit ? 'flex' : 'none';
        }
        if (orgNav) {
          const canManageOrg = finalRole === 'admin' || finalRole === 'soc_analyst';
          orgNav.style.display = canManageOrg ? 'flex' : 'none';
        }
      }
    }).catch(()=>{});
  } catch(e) {}

  // Update quota banner to show unlimited
  const qBanner = document.getElementById('scan-quota-banner');
  if (qBanner) {
    qBanner.style.display = 'flex';
    document.getElementById('scan-quota-text').innerHTML = '✓ Signed in — <strong>unlimited scanning</strong> active.';
  }

  // Detect if user account changed since last sign-in
  if (window._lastUid !== user.uid) {
    window._lastUid = user.uid;
    _allLogs = [];
    window._appInitialized = false;
    window._currentScanData = null;
    showResultReady();
  }

  // First time showing the app for this user — load dashboard + check backend
  if (!window._appInitialized) {
    window._appInitialized = true;
    _initDashboardAfterAuth();
    // Fire-and-forget encrypted login event recording
    apiFetch(`${API}/account/record-login`, { method: 'POST' }).catch(err => {
      console.warn('Failed to record login session:', err);
    });
  }
}

function showAuthScreen() {
  const trialEl = document.getElementById('trial-screen');
  if (trialEl) trialEl.style.display = 'none';
  document.getElementById('auth-screen').classList.add('visible');
  showSignIn();
}

function closeAuthModal() {
  const modal = document.getElementById('auth-screen');
  if (modal) modal.classList.remove('visible');
}

// ── Standalone Trial Screen Logic ─────────────────────────────
function showTrialScreen() {
  // Legacy — now redirects to guest app view
  showAppGuest();
}

// ── Guest App View (full site without login) ──────────────────
function showAppGuest() {
  document.getElementById('auth-screen').classList.remove('visible');
  const trialEl = document.getElementById('trial-screen');
  if (trialEl) trialEl.style.display = 'none';
  document.getElementById('app').style.display = '';

  // Show guest sign-in widget, hide user widget
  document.getElementById('sidebar-user').classList.remove('visible');
  const guestWidget = document.getElementById('sidebar-guest');
  if (guestWidget) guestWidget.classList.add('visible');

  // Hide admin-only navigation from guests
  const orgNav = document.getElementById('nav-org-management');
  if (orgNav) orgNav.style.display = 'none';
  const auditNav = document.getElementById('nav-audit-trail');
  if (auditNav) auditNav.style.display = 'none';

  // Default to scanner page for guests
  nav('scan');

  // Check backend health
  const isCloud = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1';
  const healthUrl = `${API}/health`;
  fetch(healthUrl).catch(() => fetch(`${API.replace(/\/api$/, '')}/health`)).then(r=>r.json()).then(d=>{
    if(d.status!=='healthy')throw new Error();
  }).catch(()=>{
    if (isCloud) {
      toast('⏳ Cloud backend waking up (takes ~30s on free tier). Retrying...', 'info');
      setTimeout(() => {
        fetch(healthUrl).catch(() => fetch(`${API.replace(/\/api$/, '')}/health`)).then(r=>r.json()).then(d=>{
          if (d.status === 'healthy') {
            toast('✔ Cloud backend is online and ready!', 'success');
            loadGuestQuota();
          }
        }).catch(()=>{});
      }, 12000);
    } else {
      toast('⚠ Backend offline. Some features may not work.','error');
    }
  });

  // Load guest quota
  loadGuestQuota();
}

// ── Auth-required page prompt for guests ──────────────────────
function showAuthRequiredPage(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const el = document.getElementById('nav-' + page);
  if (el) el.classList.add('active');
  document.getElementById('topbar-title').textContent = TITLES[page] || page;

  const targetPage = document.getElementById('page-' + page);
  if (targetPage) {
    // Cache original HTML to restore after login (only if not already showing the prompt)
    if (!window._originalPageHTML) window._originalPageHTML = {};
    if (!window._originalPageHTML[page] && !targetPage.querySelector('.auth-required-prompt')) {
      window._originalPageHTML[page] = targetPage.innerHTML;
    }
    targetPage.classList.add('active');
    const descriptions = {
      dashboard: 'Your personal threat dashboard shows scan history, threat statistics, and risk breakdowns — all saved to your account.',
      forensics: 'Forensic logs store detailed records of every email scan. Sign in so we can save and track your analysis history.',
      'audit-trail': 'SOC compliance audit logs track all scan operations, data exports, and policy events.',
      account:   'Manage your account settings, security preferences, and data export options.'
    };
    targetPage.innerHTML = `
      <div class="auth-required-prompt">
        <div class="prompt-icon">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><circle cx="12" cy="11" r="3"/></svg>
        </div>
        <h3>Sign in to access ${esc(TITLES[page] || page)}</h3>
        <p>${descriptions[page] || 'This feature requires an account.'}</p>
        <div class="prompt-actions">
          <button class="btn btn-primary" onclick="showAuthScreen(); showSignIn();">Sign In</button>
          <button class="btn btn-secondary" onclick="showAuthScreen(); showSignUp();">Create Free Account</button>
        </div>
      </div>`;
  }
}

// ── Guest quota display ───────────────────────────────────────
async function loadGuestQuota() {
  const banner = document.getElementById('scan-quota-banner');
  if (!banner) return;
  if (window._authUser) {
    banner.style.display = 'flex';
    document.getElementById('scan-quota-text').innerHTML = '✓ Signed in — <strong>unlimited scanning</strong> active.';
    return;
  }
  try {
    const res = await fetch(`${API}/scan/quota`);
    if (res.ok) {
      const data = await res.json();
      banner.style.display = 'flex';
      if (data.unlimited) {
        document.getElementById('scan-quota-text').innerHTML = '✓ <strong>Unlimited scanning</strong> active.';
      } else {
        const rem = data.remaining ?? 5;
        const limit = data.limit ?? 5;
        const color = rem <= 1 ? 'var(--red)' : rem <= 3 ? 'var(--amber)' : 'var(--t2)';
        document.getElementById('scan-quota-text').innerHTML =
          `<span style="color:${color}"><strong>${rem} of ${limit}</strong> free scans remaining today</span> · <a onclick="showAuthScreen(); showSignIn();">Sign in for unlimited</a>`;
      }
    }
  } catch (e) {
    banner.style.display = 'flex';
    document.getElementById('scan-quota-text').textContent = '5 free scans per day · Sign in for unlimited';
  }
}

function hideTrialScreen() {
  const trialEl = document.getElementById('trial-screen');
  if (trialEl) trialEl.style.display = 'none';
  if (!window._authUser) {
    showAuthScreen();
  }
}

function switchTrialTab(tab) {
  const isEmail = tab === 'email';
  document.getElementById('trial-input-email').style.display = isEmail ? 'block' : 'none';
  document.getElementById('trial-input-url').style.display = isEmail ? 'none' : 'block';
  document.getElementById('trial-tab-email').classList.toggle('active', isEmail);
  document.getElementById('trial-tab-url').classList.toggle('active', !isEmail);
}

function loadTrialSampleEmail() {
  document.getElementById('trial-email-text').value = `From: Security Verification <verify@phish-simulation.example.com>
Reply-To: audit-desk@phish-simulation.example.com
Subject: Notice: Security Compliance Action Required
Date: Mon, 26 May 2026 10:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=phish-simulation.example.com
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

Dear User,
This is a simulated security awareness exercise regarding unauthorized access.
Verify status: https://phish-simulation.example.com/verify-status?id=sim902`;
}

async function loadTrialQuota() {
  const banner = document.getElementById('trial-quota-banner');
  if (!banner) return;
  try {
    const res = await fetch(`${API}/scan/quota`);
    if (res.ok) {
      const data = await res.json();
      if (data.unlimited) {
        banner.innerHTML = `⚡ You are signed in. <strong>Unlimited scanning active.</strong>`;
      } else {
        const rem = data.remaining ?? 5;
        const limit = data.limit ?? 5;
        banner.innerHTML = `⚡ Free Trial: <strong>${rem} of ${limit} scans remaining today</strong> (resets at midnight IST).`;
      }
    }
  } catch (e) {
    banner.textContent = "⚡ Free Trial: 5 scans per day per IP (resets at midnight IST).";
  }
}

async function doTrialScan(type) {
  const resContainer = document.getElementById('trial-scan-result');
  resContainer.innerHTML = `<div class="card card-p" style="text-align:center;"><div class="spinner" style="width:24px;height:24px;margin:0 auto 10px;"></div><div style="font-size:13px;color:var(--t2);">Running threat scan...</div></div>`;

  try {
    let endpoint = `${API}/scan/email`;
    let bodyData = {};

    if (type === 'email') {
      const rawText = document.getElementById('trial-email-text').value.trim();
      if (!rawText) {
        toast('Please paste email content or headers first', 'error');
        resContainer.innerHTML = '';
        return;
      }
      bodyData = { raw_email: rawText };
    } else {
      const urlText = document.getElementById('trial-url-text').value.trim();
      if (!urlText) {
        toast('Please enter a URL first', 'error');
        resContainer.innerHTML = '';
        return;
      }
      endpoint = `${API}/scan/url`;
      bodyData = { url: urlText };
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bodyData)
    });

    if (res.status === 429) {
      const errData = await res.json().catch(() => ({}));
      const detail = errData.detail || errData;
      const msg = detail.message || "You've used your 5 free scans for today.";
      const resetsAt = detail.resets_at ? new Date(detail.resets_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'midnight IST';

      showAuthScreen();
      const errEl = document.getElementById('signin-err');
      if (errEl) {
        errEl.innerHTML = `⚡ <strong>Daily Limit Reached (5/5)</strong><br>${esc(msg)} (Resets at ${esc(resetsAt)}). Sign in or create a free account to continue scanning.`;
        errEl.classList.add('on');
      }
      toast('Free daily limit reached. Sign in to continue.', 'warning');
      resContainer.innerHTML = '';
      return;
    }

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      toast(`Scan error: ${errData.detail || 'Failed'}`, 'error');
      resContainer.innerHTML = '';
      return;
    }

    const data = await res.json();
    renderTrialResult(data, resContainer);
    loadTrialQuota();

  } catch (e) {
    toast(`Scan failed: ${e.message}`, 'error');
    resContainer.innerHTML = '';
  }
}

function renderTrialResult(data, container) {
  if (data.scan_result) {
    const vt = data.scan_result || {};
    const risk = vt.risk_level || 'clean';
    container.innerHTML = `
      <div class="card card-p fu">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
          <div style="font-size:14px; font-weight:700; color:var(--t1);">URL Verdict</div>
          ${riskTag(risk)}
        </div>
        <div style="font-size:13px; color:var(--t2); font-family:monospace; margin-bottom:12px;">${esc(data.url)}</div>
        <div style="font-size:12.5px; color:var(--t2);">Detections: <strong>${vt.detections || 0} / ${vt.total_engines || 87}</strong> AV engines</div>
      </div>
    `;
    return;
  }

  const score = data.risk_score || 0;
  const level = data.risk_level || 'clean';
  const summary = data.summary || 'Scan complete.';
  const auth = data.authentication || {};

  container.innerHTML = `
    <div class="card card-p fu" style="margin-bottom:16px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
        <div>
          <div style="font-size:16px; font-weight:800; color:var(--t1);">Risk Score: ${score} / 100</div>
          <div style="font-size:12.5px; color:var(--t2); margin-top:4px;">${esc(summary)}</div>
        </div>
        ${riskTag(level)}
      </div>

      <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:10px; margin-top:14px; text-align:center; font-size:12px;">
        <div style="padding:8px; background:rgba(0,0,0,0.15); border-radius:var(--r-sm);">SPF: <strong class="${authClass(auth.spf)}">${(auth.spf||'NONE').toUpperCase()}</strong></div>
        <div style="padding:8px; background:rgba(0,0,0,0.15); border-radius:var(--r-sm);">DKIM: <strong class="${authClass(auth.dkim)}">${(auth.dkim||'NONE').toUpperCase()}</strong></div>
        <div style="padding:8px; background:rgba(0,0,0,0.15); border-radius:var(--r-sm);">DMARC: <strong class="${authClass(auth.dmarc)}">${(auth.dmarc||'NONE').toUpperCase()}</strong></div>
      </div>
    </div>
  `;
}

// ── Email / Password sign in (Proxied & Rate-Limited via Backend) ─
async function doSignIn() {
  const email = document.getElementById('signin-email').value.trim();
  const pass  = document.getElementById('signin-password').value;
  const btn   = document.getElementById('signin-btn');
  const err   = document.getElementById('signin-err');
  const hint  = document.getElementById('signin-google-hint');
  const gBtn  = document.querySelector('#auth-signin .auth-btn-google');

  if (hint) hint.style.display = 'none';
  if (gBtn) gBtn.classList.remove('pulse-google-btn');

  if (!email || !pass) { _authErr(err, 'Please fill in both fields'); return; }

  btn.disabled = true; btn.textContent = 'Signing in…';
  err.classList.remove('on');

  try {
    // 1. Authenticate through backend proxy with sliding-window rate limiting
    const resp = await fetch(`${API}/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: pass })
    });

    const data = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      btn.disabled = false; btn.textContent = 'Sign In';

      // Smart Detection Pillar 2: Check if backend identified Google-only account
      const isGoogleOnly = data.detail?.is_google_only || data.detail?.error === 'GOOGLE_ACCOUNT_NO_PASSWORD';
      if (isGoogleOnly) {
        if (hint) {
          hint.style.display = 'block';
          hint.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
        if (gBtn) {
          gBtn.classList.add('pulse-google-btn');
          setTimeout(() => gBtn.classList.remove('pulse-google-btn'), 4500);
        }
        _authErr(err, data.detail?.message || 'This account uses Google Sign-In and has no password.');
        return;
      }

      // Fallback client-side check if backend gave generic error
      if (window._fbGetSignInMethods && (resp.status === 400 || resp.status === 401)) {
        try {
          const methods = await window._fbGetSignInMethods(email);
          if (methods && methods.includes('google.com') && !methods.includes('password')) {
            if (hint) {
              hint.style.display = 'block';
              hint.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
            if (gBtn) {
              gBtn.classList.add('pulse-google-btn');
              setTimeout(() => gBtn.classList.remove('pulse-google-btn'), 4500);
            }
            _authErr(err, 'This account is registered via Google OAuth without a password. Click "Continue with Google" below.');
            return;
          }
        } catch (_) {}
      }

      if (resp.status === 429) {
        const retryMsg = data.detail || 'Too many sign-in attempts. Please try again shortly.';
        _authErr(err, `⏳ ${retryMsg}`);
        return;
      }
      const errMsg = data.detail?.message || data.detail || 'Invalid email or password';
      _authErr(err, errMsg);
      return;
    }

    // 2. Verified successfully via backend gateway -> Establish client session
    if (window._fbSignIn) {
      try {
        await window._fbSignIn(email, pass);
      } catch (clientErr) {
        // Fallback: use returned JWT token directly
        window._authToken = data.idToken;
        window._authUser = { uid: data.localId, email: data.email, displayName: data.displayName };
        showApp(window._authUser);
      }
    } else {
      window._authToken = data.idToken;
      window._authUser = { uid: data.localId, email: data.email, displayName: data.displayName };
      showApp(window._authUser);
    }

    btn.disabled = false; btn.textContent = 'Sign In';
    closeAuthModal();
  } catch(e) {
    console.error('[SecureMail Sign In Error]', e);
    btn.disabled = false; btn.textContent = 'Sign In';
    _authErr(err, 'Network error. Please check connection to SecureMail backend.');
  }
}

// ── Email / Password sign up (Proxied & Rate-Limited via Backend) ─
async function doSignUp() {
  const name    = document.getElementById('signup-name').value.trim();
  const email   = document.getElementById('signup-email').value.trim();
  const pass    = document.getElementById('signup-password').value;
  const confirm = document.getElementById('signup-confirm').value;
  const btn     = document.getElementById('signup-btn');
  const err     = document.getElementById('signup-err');
  if (!name || !email || !pass) { _authErr(err, 'All fields are required'); return; }
  if (pass.length < 8)          { _authErr(err, 'Password must be at least 8 characters'); return; }
  if (!/[A-Z]/.test(pass))      { _authErr(err, 'Password must contain at least one uppercase letter'); return; }
  if (pass !== confirm)         { _authErr(err, 'Passwords do not match'); return; }

  btn.disabled = true; btn.textContent = 'Creating account…';
  err.classList.remove('on');

  try {
    // 1. Create account through backend proxy with rate limiting & auto verification dispatch
    const resp = await fetch(`${API}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: pass, display_name: name })
    });

    const data = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      btn.disabled = false; btn.textContent = 'Create Account';
      if (resp.status === 429) {
        const retryMsg = data.detail || 'Too many account creation attempts. Please try again later.';
        _authErr(err, `⏳ ${retryMsg}`);
        return;
      }
      const errMsg = data.detail?.message || data.detail || 'Failed to create account';
      _authErr(err, errMsg);
      return;
    }

    // 2. Establish client session and trigger client-side verification email
    if (window._fbSignIn) {
      try {
        await window._fbSignIn(email, pass);
        if (window._fbAuth?.currentUser && window._fbSendVerification) {
          try {
            await window._fbSendVerification(window._fbAuth.currentUser);
          } catch (_) {}
        }
      } catch (clientErr) {
        window._authToken = data.idToken;
        window._authUser = { uid: data.localId, email: data.email, displayName: name };
        showApp(window._authUser);
      }
    } else {
      window._authToken = data.idToken;
      window._authUser = { uid: data.localId, email: data.email, displayName: name };
      showApp(window._authUser);
    }

    btn.disabled = false; btn.textContent = 'Create Account';
    closeAuthModal();
    toast(`Account created! Verification email dispatched to ${email}.`, 'success');
  } catch(e) {
    console.error('[SecureMail Sign Up Error]', e);
    btn.disabled = false; btn.textContent = 'Create Account';
    _authErr(err, 'Network error. Please check connection to SecureMail backend.');
  }
}

// ── Google OAuth ─────────────────────────────────────────────
async function doGoogleSignIn() {
  if (!window._fbGoogle) {
    const err = document.getElementById('signin-err') || document.getElementById('signup-err');
    if (err) _authErr(err, 'Authentication service is initializing. Please refresh.');
    return;
  }
  const btns = document.querySelectorAll('.auth-btn-google');
  btns.forEach(b => b.disabled = true);
  try {
    const cred = await window._fbGoogle();
    const user = cred.user;
    const addInfo = window._fbGetAdditionalUserInfo ? window._fbGetAdditionalUserInfo(cred) : null;
    const isNew = addInfo ? !!addInfo.isNewUser : (user.metadata && user.metadata.creationTime === user.metadata.lastSignInTime);
    const onboarded = localStorage.getItem('sm_onboarded_' + user.uid) === 'true';

    if (isNew || !onboarded) {
      window._isOnboardingActive = true;
      showOnboardingModal(user, cred);
    } else {
      closeAuthModal();
      showApp(user);
    }
  } catch(e) {
    console.error('[SecureMail Google OAuth Error]', e);
    if (e.code !== 'auth/popup-closed-by-user') {
      const err = document.getElementById('signin-err') || document.getElementById('signup-err') || document.getElementById('onboard-err');
      if (err) _authErr(err, _fbErrMsg(e));
    }
  } finally {
    btns.forEach(b => b.disabled = false);
  }
}

// ── Google Account Onboarding (Pillar 1) ──────────────────────
function showOnboardingModal(user, cred) {
  window._pendingOnboardUser = user;
  window._isOnboardingActive = true;
  _authPanel('onboarding');

  const nameInput = document.getElementById('onboard-name');
  if (nameInput) nameInput.value = user.displayName || '';

  const avatarWrap = document.getElementById('onboard-avatar-wrap');
  if (avatarWrap) {
    if (user.photoURL) {
      avatarWrap.innerHTML = `<img src="${esc(user.photoURL)}" alt="Avatar" style="width:100%;height:100%;border-radius:50%;object-fit:cover;" referrerpolicy="no-referrer"/>`;
    } else {
      avatarWrap.textContent = (user.displayName || user.email || 'U').charAt(0).toUpperCase();
    }
  }

  const titleEl = document.getElementById('onboard-title');
  if (titleEl) {
    const firstName = (user.displayName || '').split(' ')[0];
    titleEl.textContent = firstName ? `Welcome, ${firstName}!` : 'Complete Account Setup';
  }

  const pwInput = document.getElementById('onboard-password');
  const confInput = document.getElementById('onboard-confirm');
  if (pwInput) pwInput.value = '';
  if (confInput) confInput.value = '';

  const modal = document.getElementById('auth-screen');
  if (modal) modal.classList.add('visible');
}

function toggleOnboardPasswordSection() {
  const fields = document.getElementById('onboard-pw-fields');
  const chevron = document.getElementById('onboard-pw-chevron');
  if (!fields) return;
  const isHidden = fields.style.display === 'none';
  fields.style.display = isHidden ? 'block' : 'none';
  if (chevron) chevron.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
}

async function submitOnboarding() {
  const user = window._pendingOnboardUser || window._authUser || (window._fbAuth ? window._fbAuth.currentUser : null);
  const errEl = document.getElementById('onboard-err');
  const btn = document.getElementById('onboard-submit-btn');
  const agreed = document.getElementById('onboard-agree-terms').checked;

  if (!agreed) {
    _authErr(errEl, 'Please accept the Terms of Service & Privacy Policy to continue.');
    return;
  }

  const newName = (document.getElementById('onboard-name').value || '').trim();
  const org = (document.getElementById('onboard-org').value || '').trim();
  const pass = document.getElementById('onboard-password').value;
  const confirm = document.getElementById('onboard-confirm').value;

  if (pass || confirm) {
    if (pass.length < 8) {
      _authErr(errEl, 'Password must be at least 8 characters long.');
      return;
    }
    if (!/[A-Z]/.test(pass)) {
      _authErr(errEl, 'Password must contain at least one uppercase letter.');
      return;
    }
    if (pass !== confirm) {
      _authErr(errEl, 'Passwords do not match.');
      return;
    }
  }

  btn.disabled = true;
  btn.textContent = 'Finalizing setup…';

  try {
    // 1. Update display name if customized
    if (user && newName && newName !== user.displayName && window._fbUpdate) {
      try {
        await window._fbUpdate(user, { displayName: newName });
      } catch (nameErr) {
        console.warn('Could not update display name:', nameErr);
      }
    }

    // 2. Link password credential if provided
    if (user && pass && window._fbLinkCredential && window._fbEmailCred) {
      try {
        const cred = window._fbEmailCred(user.email, pass);
        await window._fbLinkCredential(user, cred);
        toast('Password linked! You can now sign in using Google or your password.', 'success');
      } catch (linkErr) {
        console.error('Password linking error during onboarding:', linkErr);
        if (linkErr.code === 'auth/credential-already-in-use') {
          _authErr(errEl, 'This email already has a linked password credential.');
          btn.disabled = false;
          btn.textContent = 'Complete Setup & Launch';
          return;
        } else if (linkErr.code === 'auth/weak-password') {
          _authErr(errEl, 'Password is too weak. Please choose a stronger password.');
          btn.disabled = false;
          btn.textContent = 'Complete Setup & Launch';
          return;
        } else {
          toast('Note: Could not link password (' + (linkErr.message || 'error') + '). You can still sign in with Google.', 'warning');
        }
      }
    }

    // 3. Persist organization and mark onboarded
    if (user) {
      if (org) localStorage.setItem('sm_org_' + user.uid, org);
      localStorage.setItem('sm_onboarded_' + user.uid, 'true');
    }

    window._isOnboardingActive = false;
    window._pendingOnboardUser = null;
    btn.disabled = false;
    btn.textContent = 'Complete Setup & Launch';

    closeAuthModal();
    if (user) {
      try {
        showApp(user);
      } catch (appErr) {
        console.warn('UI transition error:', appErr);
      }
    }
    toast('🎉 Welcome to SecureMail! Workspace configured successfully.', 'success');
  } catch (e) {
    btn.disabled = false;
    btn.textContent = 'Complete Setup & Launch';
    _authErr(errEl, 'An error occurred during setup: ' + (e.message || 'Please try again.'));
  }
}

function skipOnboarding() {
  const user = window._pendingOnboardUser || window._authUser || (window._fbAuth ? window._fbAuth.currentUser : null);
  if (user) {
    localStorage.setItem('sm_onboarded_' + user.uid, 'true');
  }
  window._isOnboardingActive = false;
  window._pendingOnboardUser = null;
  closeAuthModal();
  if (user) {
    showApp(user);
  }
  toast('Welcome to SecureMail!', 'info');
}

// ── Set Password Modal for Google OAuth (Pillar 3) ────────────
function openSetPasswordModal() {
  const user = window._authUser || (window._fbAuth ? window._fbAuth.currentUser : null);
  if (!user) { toast('Please sign in first', 'error'); return; }
  const emailInput = document.getElementById('setpw-email-display');
  if (emailInput) emailInput.value = user.email || '';
  const newPw = document.getElementById('setpw-new');
  const confPw = document.getElementById('setpw-confirm');
  const errEl = document.getElementById('setpw-err');
  if (newPw) newPw.value = '';
  if (confPw) confPw.value = '';
  if (errEl) { errEl.textContent = ''; errEl.classList.remove('on'); }

  const modal = document.getElementById('modal-set-password');
  if (modal) modal.style.display = 'flex';
}

function closeSetPasswordModal() {
  const modal = document.getElementById('modal-set-password');
  if (modal) modal.style.display = 'none';
}

async function submitSetPassword() {
  const user = window._authUser || (window._fbAuth ? window._fbAuth.currentUser : null);
  if (!user) { toast('User session not found', 'error'); return; }

  const newPw = (document.getElementById('setpw-new').value || '');
  const confPw = (document.getElementById('setpw-confirm').value || '');
  const errEl = document.getElementById('setpw-err');
  const btn = document.getElementById('setpw-submit-btn');

  if (!newPw || !confPw) { _authErr(errEl, 'Please fill in both password fields'); return; }
  if (newPw.length < 8) { _authErr(errEl, 'Password must be at least 8 characters'); return; }
  if (!/[A-Z]/.test(newPw)) { _authErr(errEl, 'Password must contain at least one uppercase letter'); return; }
  if (newPw !== confPw) { _authErr(errEl, 'Passwords do not match'); return; }

  btn.disabled = true;
  btn.textContent = 'Linking password…';

  try {
    if (!window._fbLinkCredential || !window._fbEmailCred) {
      throw new Error('Firebase Auth linking is not initialized');
    }
    const cred = window._fbEmailCred(user.email, newPw);
    await window._fbLinkCredential(user, cred);

    toast('🎉 Password successfully linked! You can now sign in with either your password or Google.', 'success');
    closeSetPasswordModal();
    loadAccountPage();
  } catch (e) {
    console.error('[Set Password Error]', e);
    btn.disabled = false;
    btn.textContent = 'Link Password';
    if (e.code === 'auth/credential-already-in-use') {
      _authErr(errEl, 'This email already has a password or credential linked.');
    } else if (e.code === 'auth/requires-recent-login') {
      _authErr(errEl, 'Security restriction: Please sign out and sign back in before linking a password.');
    } else {
      _authErr(errEl, _fbErrMsg(e) || e.message || 'Failed to link password.');
    }
  }
}

// ── Forgot password (Proxied & Rate-Limited via Backend) ──────
async function doForgotPassword() {
  const email = document.getElementById('forgot-email').value.trim();
  const err   = document.getElementById('forgot-err');
  const ok    = document.getElementById('forgot-ok');
  if (!email) { _authErr(err, 'Enter your email address'); return; }

  err.classList.remove('on');
  ok.classList.remove('on');

  try {
    const resp = await fetch(`${API}/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email })
    });

    const data = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      if (resp.status === 429) {
        const retryMsg = data.detail || 'Too many password reset attempts. Please try again in 15 minutes.';
        _authErr(err, `⏳ ${retryMsg}`);
        return;
      }
      _authErr(err, data.detail?.message || data.detail || 'Failed to send password reset');
      return;
    }

    ok.textContent = data.message || 'Reset link sent! Check your inbox.';
    ok.classList.add('on');
  } catch(e) {
    console.error('[SecureMail Password Reset Error]', e);
    _authErr(err, 'Network error. Could not contact password reset service.');
  }
}

// ── Sign out ─────────────────────────────────────────────────
async function doSignOut() {
  if (!confirm('Sign out of SecureMail?')) return;
  window._authToken = null;
  window._authUser  = null;
  if (window._fbSignOut) {
    await window._fbSignOut();
  }
  showAppGuest();
}

// ── Helpers ──────────────────────────────────────────────────
function _authErr(el, msg) {
  el.textContent = msg;
  el.classList.add('on');
}
function _fbErrMsg(errOrCode) {
  const code = typeof errOrCode === 'string' ? errOrCode : (errOrCode && errOrCode.code);
  const map = {
    'auth/user-not-found':             'No account found with this email.',
    'auth/wrong-password':             'Incorrect password.',
    'auth/invalid-email':              'Invalid email address format.',
    'auth/email-already-in-use':       'An account with this email already exists.',
    'auth/weak-password':              'Password is too weak (min 8 characters).',
    'auth/too-many-requests':          'Too many failed attempts. Please wait a few minutes.',
    'auth/network-request-failed':     'Network error. Please check your internet connection.',
    'auth/popup-blocked':              'Popup was blocked by your browser. Allow popups to sign in.',
    'auth/invalid-credential':         'Incorrect email or password.',
    'auth/invalid-login-credentials':  'Incorrect email or password.',
    'auth/user-disabled':              'This account has been disabled by an administrator.',
    'auth/operation-not-allowed':      'Email/Password authentication is disabled in Firebase Console.',
    'auth/unauthorized-domain':        'Domain "' + window.location.hostname + '" is not authorized in Firebase Console. Please add it in Firebase Console -> Authentication -> Settings -> Authorized Domains.',
    'auth/missing-password':           'Please enter your password.',
    'auth/missing-email':              'Please enter your email address.',
    'auth/credential-already-in-use':   'This email or credential is already linked to another account.',
    'auth/requires-recent-login':        'Security policy requires recent authentication. Please sign out and sign back in before linking.',
  };
  if (code && map[code]) return map[code];
  if (errOrCode && errOrCode.message && !errOrCode.message.includes('Firebase:')) return errOrCode.message;
  return 'Incorrect email or password, or authentication failed. Please try again.';
}

// Hide app until auth state is resolved
document.getElementById('app').style.display = 'none';

// Call on startup
initTheme();

// ── HTML/PDF Incident Report Exporter ─────────
// ── Boardroom-Ready Executive PDF & HTML Incident Report Generator ─────────
function defang(val) {
  if (!val) return '';
  return String(val)
    .replace(/https?:\/\//gi, m => m.toLowerCase().startsWith('https') ? 'hxxps[://]' : 'hxxp[://]')
    .replace(/\./g, '[.]');
}

function generateExecutiveReportHTML(d) {
  const auth = d.authentication || {};
  const h = d.header_analysis || {};
  const urls = d.urls || [];
  const atts = d.attachments || [];
  const ph = d.phishing || {};
  const ip = h.ip_reputation || {};
  const audit = d.received_hop_audit || { hops: [], anomalies: [] };
  const trajectory = audit.trajectory || {};
  const hops = (trajectory && trajectory.hops && trajectory.hops.length) ? trajectory.hops : (audit.hops || []);
  const wa = d.weighted_phishing_analysis || { score: 0, matches: [] };
  const quishing = d.quishing || { has_qr_codes: false, detections: [] };
  const homographs = d.homograph_alerts || [];
  const ml = d.ml_prediction || {};
  const score = d.risk_score || 0;
  const level = (d.risk_level || 'unknown').toUpperCase();
  const c = riskColor(d.risk_level);
  
  // Calculate SVG needle angle for risk gauge (-90deg to +90deg)
  const gaugeAngle = -90 + (score / 100) * 180;
  const reportId = `SM-${(d.scan_id || 'INC').substring(0, 8).toUpperCase()}`;
  const scanDate = d.scanned_at || new Date().toISOString();

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8"/>
      <title>SecureMail Executive Forensic Report - ${reportId}</title>
      <link rel="preconnect" href="https://fonts.googleapis.com"/>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet"/>
      <style>
        :root {
          --red: #ef4444;
          --orange: #f97316;
          --amber: #f59e0b;
          --green: #10b981;
          --blue: #3b82f6;
          --dark: #0f172a;
          --t2: #475569;
          --t3: #64748b;
          --bg-subtle: #f8fafc;
          --border: #e2e8f0;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          color: #1e293b; background: #ffffff; line-height: 1.5; padding: 32px 40px; font-size: 12px;
        }
        @page { size: A4 portrait; margin: 12mm 15mm; }
        @media print {
          body { padding: 0; }
          .no-print { display: none !important; }
        }
        .avoid-break { page-break-inside: avoid; }

        /* Header */
        .exec-header {
          display: flex; justify-content: space-between; align-items: flex-start;
          border-bottom: 2px solid var(--dark); padding-bottom: 16px; margin-bottom: 20px;
        }
        .brand-title { font-size: 20px; font-weight: 800; letter-spacing: -0.5px; color: var(--dark); }
        .brand-sub { font-size: 10px; font-weight: 700; color: var(--t3); text-transform: uppercase; letter-spacing: 0.08em; }
        .banner-tag {
          display: inline-block; padding: 4px 8px; font-size: 9.5px; font-weight: 800;
          letter-spacing: 0.08em; text-transform: uppercase; background: #fef2f2; color: #dc2626;
          border: 1px solid #fecaca; border-radius: 4px; margin-bottom: 6px;
        }

        /* Executive Gauge & Summary */
        .exec-hero {
          display: grid; grid-template-columns: auto 1fr; gap: 20px;
          background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 10px;
          padding: 18px 22px; margin-bottom: 20px; align-items: center;
        }
        .gauge-wrap { display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .hero-title { font-size: 16px; font-weight: 800; color: var(--dark); margin-bottom: 4px; }
        .hero-summary { font-size: 12.5px; color: var(--t2); line-height: 1.6; }
        .hero-badge {
          display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px;
          font-weight: 800; text-transform: uppercase; margin-left: 6px;
        }

        /* 4-Column KRI Matrix */
        .kri-grid {
          display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px;
        }
        .kri-card {
          background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 8px;
          padding: 12px; display: flex; flex-direction: column; justify-content: space-between;
        }
        .kri-lbl { font-size: 9.5px; font-weight: 700; color: var(--t3); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }
        .kri-val { font-size: 14px; font-weight: 800; color: var(--dark); }
        .kri-sub { font-size: 10px; color: var(--t3); margin-top: 3px; font-weight: 500; }

        /* Meta Grid */
        .meta-grid {
          display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px;
        }
        .meta-box {
          background: #ffffff; border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px;
        }
        .meta-lbl { font-size: 9.5px; font-weight: 700; color: var(--t3); text-transform: uppercase; margin-bottom: 3px; }
        .meta-txt { font-size: 12px; font-weight: 600; color: var(--dark); word-break: break-all; }

        /* Section Headings */
        .sec-title {
          font-size: 11.5px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.06em;
          color: var(--dark); border-bottom: 1.5px solid var(--border); padding-bottom: 5px; margin: 20px 0 10px;
        }

        /* Data Tables */
        table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 11px; }
        th {
          text-align: left; background: #f1f5f9; padding: 7px 10px; font-weight: 700;
          color: var(--t2); border-bottom: 1px solid var(--border); text-transform: uppercase; font-size: 9.5px; letter-spacing: 0.04em;
        }
        td { padding: 7px 10px; border-bottom: 1px solid #f1f5f9; color: #334155; vertical-align: middle; }
        .mono { font-family: 'JetBrains Mono', monospace; font-size: 10.5px; }
        
        .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 9.5px; font-weight: 700; text-transform: uppercase; }
        .badge-red { background: #fee2e2; color: #dc2626; border: 1px solid #fecaca; }
        .badge-green { background: #dcfce7; color: #16a34a; border: 1px solid #bbf7d0; }
        .badge-amber { background: #fef3c7; color: #d97706; border: 1px solid #fde68a; }
        .badge-blue { background: #dbeafe; color: #2563eb; border: 1px solid #bfdbfe; }

        /* Sign-off */
        .sign-off {
          margin-top: 35px; border-top: 2px dashed #cbd5e1; padding-top: 20px;
          display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; font-size: 11px;
        }
        .sign-line { border-bottom: 1px solid #94a3b8; height: 32px; margin-top: 4px; }
      </style>
    </head>
    <body>

      <!-- Executive Header -->
      <div class="exec-header">
        <div>
          <div class="banner-tag">CONFIDENTIAL // SOC INCIDENT AUDIT</div>
          <div class="brand-title">SecureMail Forensic Security Gateway v4.0</div>
          <div class="brand-sub">Boardroom Threat Intelligence & Incident Response Briefing</div>
        </div>
        <div style="text-align: right; font-size: 10.5px; color: var(--t3);">
          <div><strong>REPORT ID:</strong> <span class="mono" style="color:var(--dark); font-weight:700;">${reportId}</span></div>
          <div style="margin-top:2px;"><strong>AUDIT DATE:</strong> ${scanDate}</div>
          <div style="margin-top:2px;"><strong>CLASSIFICATION:</strong> TLP:AMBER // STRICT</div>
        </div>
      </div>

      <!-- Executive Speedometer & Threat Summary -->
      <div class="exec-hero avoid-break">
        <div class="gauge-wrap">
          <svg viewBox="0 0 200 120" style="width:150px; height:90px;">
            <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round"/>
            <path d="M 20 100 A 80 80 0 0 1 50 43" fill="none" stroke="#22c55e" stroke-width="14" stroke-linecap="round"/>
            <path d="M 50 43 A 80 80 0 0 1 100 20" fill="none" stroke="#f59e0b" stroke-width="14"/>
            <path d="M 100 20 A 80 80 0 0 1 150 43" fill="none" stroke="#f97316" stroke-width="14"/>
            <path d="M 150 43 A 80 80 0 0 1 180 100" fill="none" stroke="#ef4444" stroke-width="14" stroke-linecap="round"/>
            <g transform="rotate(${gaugeAngle}, 100, 100)">
              <line x1="100" y1="100" x2="100" y2="30" stroke="#0f172a" stroke-width="3.5" stroke-linecap="round"/>
              <circle cx="100" cy="100" r="6" fill="#0f172a"/>
            </g>
            <text x="100" y="116" text-anchor="middle" font-size="15" font-weight="800" fill="#0f172a" font-family="'Inter',sans-serif">${score}/100</text>
          </svg>
        </div>
        <div>
          <div class="hero-title">
            Executive Assessment: 
            <span class="hero-badge" style="background: ${d.risk_level === 'clean' ? '#dcfce7' : (d.risk_level === 'critical' || d.risk_level === 'high') ? '#fee2e2' : '#fef3c7'}; color: ${c};">
              ${level}
            </span>
          </div>
          <div class="hero-summary">${esc(d.summary || 'Automated multi-vector email threat detection performed across headers, DNS, optical quishing, and pattern heuristics.')}</div>
        </div>
      </div>

      <!-- 4-Column Key Risk Indicators (KRI) Matrix -->
      <div class="kri-grid avoid-break">
        <div class="kri-card">
          <div class="kri-lbl">⚡ Heuristic Risk Signal</div>
          <div class="kri-val" style="color:${ml.is_phishing ? 'var(--red)' : 'var(--green)'};">
            ${ml.percentage || (ml.probability ? (ml.probability * 100).toFixed(1) + '%' : 'N/A')}
          </div>
          <div class="kri-sub">Verdict: ${(ml.verdict || 'Clean').toUpperCase()}</div>
        </div>
        <div class="kri-card">
          <div class="kri-lbl">🛡️ Email Authentication</div>
          <div class="kri-val" style="font-size:12px; font-family:'JetBrains Mono',monospace;">
            ${(auth.spf || 'NONE').toUpperCase()} / ${(auth.dkim || 'NONE').toUpperCase()}
          </div>
          <div class="kri-sub">DMARC: ${(auth.dmarc || 'NONE').toUpperCase()}</div>
        </div>
        <div class="kri-card">
          <div class="kri-lbl">🌐 IDN Homoglyphs</div>
          <div class="kri-val" style="color:${homographs.length ? 'var(--red)' : 'var(--green)'};">
            ${homographs.length ? `${homographs.length} Alert` : '0 Traps'}
          </div>
          <div class="kri-sub">${homographs.length ? `Spoofed: ${esc(homographs[0].target_brand || 'Brand')}` : 'Clean Punycode'}</div>
        </div>
        <div class="kri-card">
          <div class="kri-lbl">📱 Quishing & QR</div>
          <div class="kri-val" style="color:${quishing.has_qr_codes ? 'var(--orange)' : 'var(--green)'};">
            ${quishing.has_qr_codes ? `${quishing.detections.length} QR Code` : '0 Found'}
          </div>
          <div class="kri-sub">${quishing.has_qr_codes ? 'Payload Decoded' : 'Clean Optical Scan'}</div>
        </div>
      </div>

      <!-- Incident Metadata Details -->
      <div class="meta-grid avoid-break">
        <div class="meta-box">
          <div class="meta-lbl">Envelope Sender & Identity</div>
          <div class="meta-txt">${esc(d.sender_email || '—')}</div>
          <div style="font-size:11px; color:var(--t3); margin-top:4px;"><strong>Subject:</strong> ${esc(d.subject || '—')}</div>
        </div>
        <div class="meta-box">
          <div class="meta-lbl">Originating Server & Routing</div>
          <div class="meta-txt mono">IP: ${defang(h.originating_ip || 'Not detected')}</div>
          <div style="font-size:11px; color:var(--t3); margin-top:4px;">
            <strong>Geo/ISP:</strong> ${esc(ip?.country_code || 'XX')} - ${esc(ip?.isp || 'Unknown')} 
            ${ip?.abuse_confidence_score ? `(Abuse: ${ip.abuse_confidence_score}%)` : ''}
          </div>
        </div>
      </div>

      <!-- Indicators of Compromise (IOC): Network URLs & Domains -->
      ${urls.length ? `
      <div class="avoid-break">
        <div class="sec-title">1. Network Indicators of Compromise (Defanged URLs & Domains)</div>
        <table>
          <thead>
            <tr>
              <th>Defanged Destination URL</th>
              <th>Domain Classification</th>
              <th>VirusTotal Engines</th>
              <th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            ${urls.map(u => {
              const det = u.vt_result?.detections ?? null;
              const detStr = det !== null ? `${det} / ${u.vt_result.total_engines || '87'}` : 'Offline Cached';
              const detLvl = det !== null ? (det > 0 ? 'badge badge-red' : 'badge badge-green') : 'badge';
              const lookBadge = u.is_lookalike ? '<span class="badge badge-red">⚠️ IMPERSONATION</span>' : '<span class="badge badge-green">Legitimate</span>';
              return `
                <tr>
                  <td class="mono" style="word-break:break-all;">${defang(u.url)}</td>
                  <td>${lookBadge}</td>
                  <td class="mono">${detStr}</td>
                  <td><span class="${detLvl}">${u.suspicious ? 'MALICIOUS' : 'BENIGN'}</span></td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
      ` : ''}

      <!-- Indicators of Compromise: Attachments & File Hashes -->
      ${atts.length ? `
      <div class="avoid-break">
        <div class="sec-title">2. File Artifact Indicators of Compromise (SHA-256 Hashes)</div>
        <table>
          <thead>
            <tr>
              <th>Attachment Filename</th>
              <th>MIME Content Type</th>
              <th>File Size</th>
              <th>SHA-256 Hash</th>
              <th>Engine Verdict</th>
            </tr>
          </thead>
          <tbody>
            ${atts.map(a => `
              <tr>
                <td><strong>${esc(a.filename || 'attachment')}</strong></td>
                <td class="mono">${esc(a.content_type || 'application/octet-stream')}</td>
                <td>${(a.size ? (a.size / 1024).toFixed(1) + ' KB' : '—')}</td>
                <td class="mono" style="font-size:9.5px; word-break:break-all;">${esc(a.sha256 || '—')}</td>
                <td><span class="badge ${a.vt_result?.detections > 0 ? 'badge-red' : 'badge-green'}">${a.vt_result?.detections > 0 ? 'MALICIOUS' : 'CLEAN'}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
      ` : ''}

      <!-- Indicators of Compromise: IDN Homoglyph & Typosquatting Traps -->
      ${homographs.length ? `
      <div class="avoid-break">
        <div class="sec-title">3. IDN Homograph & Brand Impersonation IOCs</div>
        <table>
          <thead>
            <tr>
              <th>Extracted Lookalike Domain</th>
              <th>Punycode ASCII Form</th>
              <th>Target Brand Spoofed</th>
              <th>Attack Vector</th>
            </tr>
          </thead>
          <tbody>
            ${homographs.map(h => `
              <tr>
                <td class="mono" style="color:var(--red); font-weight:700;">${defang(h.domain)}</td>
                <td class="mono">${defang(h.punycode)}</td>
                <td><span class="badge badge-amber">${esc(h.target_brand)}</span></td>
                <td>${esc(h.attack_type || 'Unicode Homoglyph')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
      ` : ''}

      <!-- Physical SMTP Relay Trajectory -->
      ${hops && hops.length ? `
      <div class="avoid-break">
        <div class="sec-title">4. Physical SMTP Relay Trajectory (Chronological Hop Breakdown)</div>
        <table>
          <thead>
            <tr>
              <th>Hop</th>
              <th>Relay Role</th>
              <th>Declared Hostname</th>
              <th>Relaying IP Address</th>
              <th>Geographic Location</th>
              <th>Transit Latency</th>
            </tr>
          </thead>
          <tbody>
            ${hops.map((hop, idx) => `
              <tr>
                <td class="mono"><strong>#${hop.hop_number || idx + 1}</strong></td>
                <td>${hop.is_origin || idx === 0 ? '<span class="badge badge-red">Origin MTA</span>' : (hop.is_destination || idx === hops.length - 1) ? '<span class="badge badge-green">Destination MX</span>' : '<span class="badge badge-blue">Relay Server</span>'}</td>
                <td class="mono" style="max-width:140px; overflow:hidden; text-overflow:ellipsis;">${esc(hop.host_from || hop.from || '—')}</td>
                <td class="mono">${defang(hop.ip || 'LAN Subnet')}</td>
                <td>${esc(hop.city || 'Unknown')}, ${esc(hop.country || 'Unknown')} (${esc(hop.country_code || 'XX')})</td>
                <td class="mono" style="font-weight:700;">+${hop.delay_seconds || 0}s</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
      ` : ''}

      <!-- SOC Compliance & Sign-Off Block -->
      <div class="sign-off avoid-break">
        <div>
          <div class="meta-lbl">Lead Incident Forensic Analyst</div>
          <div style="font-size:12px; font-weight:700; margin-top:8px; color:var(--dark);">
            SOC Tier-3 Cyber Analyst
          </div>
          <div class="sign-line"></div>
          <div style="font-size:9.5px; color:var(--t3); margin-top:4px;">Signature & Verification Stamp</div>
        </div>
        <div>
          <div class="meta-lbl">Incident Response Action</div>
          <div style="font-size:11px; margin-top:8px; font-weight:600;">
            ${d.risk_level === 'clean' ? '☑ PASS THROUGH (CLEAN)' : '☒ QUARANTINED AT GATEWAY'}
          </div>
          <div class="sign-line"></div>
          <div style="font-size:9.5px; color:var(--t3); margin-top:4px;">Enforcement Determination</div>
        </div>
        <div>
          <div class="meta-lbl">Certification & Sign-Off</div>
          <div style="font-size:11px; margin-top:8px; font-weight:600;">
            SecureMail Defense System v4.0
          </div>
          <div class="sign-line"></div>
          <div style="font-size:9.5px; color:var(--t3); margin-top:4px;">Date: ${new Date().toISOString().substring(0,10)}</div>
        </div>
      </div>

      <div style="margin-top:30px; text-align:center; font-size:9.5px; color:var(--t3);">
        This executive report was compiled by the SecureMail v4.0 Threat Intelligence Engine. All malicious artifacts are defanged for secure distribution.
      </div>
    </body>
    </html>
  `;
}

async function exportIncidentReportPDF() {
  if (!window._currentScanData) return;
  const d = window._currentScanData;
  toast('Generating Executive Forensic PDF...', 'info');
  try {
    const res = await apiFetch(`${API}/scan/report/pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(d)
    });
    if (!res.ok) throw new Error('Backend PDF generation failed');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const incId = (d.scan_id || d.id || 'INCIDENT').substring(0, 16);
    a.download = `SecureMail-Incident-${incId}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast('Forensic PDF report downloaded!', 'success');
  } catch (err) {
    console.warn('Falling back to print view:', err);
    const reportHtml = generateExecutiveReportHTML(d);
    const w = window.open();
    w.document.write(reportHtml);
    w.document.close();
    w.focus();
    setTimeout(() => { w.print(); }, 500);
  }
}

async function downloadForensicLogPDF(logId) {
  if (!logId) return;
  toast('Generating Executive Forensic PDF...', 'info');
  try {
    const res = await apiFetch(`${API}/forensics/${logId}/pdf`);
    if (!res.ok) throw new Error('Failed to export PDF');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SecureMail-Incident-${logId}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast('Forensic PDF report downloaded!', 'success');
  } catch (err) {
    toast('Failed to download PDF: ' + err.message, 'error');
  }
}

function exportIncidentReportHTML() {
  if (!window._currentScanData) return;
  const d = window._currentScanData;
  const reportHtml = generateExecutiveReportHTML(d);
  const blob = new Blob([reportHtml], { type: 'text/html' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `SecureMail_Executive_Forensic_Report_${(d.scan_id || 'scan').substring(0,8)}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  toast('Executive Forensic Report downloaded!', 'success');
}
