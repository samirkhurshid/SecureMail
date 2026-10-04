// SecureMail Firebase Authentication & Session Sync Module

import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js';
    import {
      getAuth, onAuthStateChanged, signInWithEmailAndPassword,
      createUserWithEmailAndPassword, signInWithPopup,
      GoogleAuthProvider, signOut, updateProfile, sendPasswordResetEmail,
      sendEmailVerification, linkWithCredential, EmailAuthProvider,
      fetchSignInMethodsForEmail, getAdditionalUserInfo, updatePassword
    } from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';

    function resolveBackendApi() {
      const saved = localStorage.getItem('sm_api_base');
      if (saved) return saved.replace(/\/+$/, '');
      if (window._SECUREMAIL_API_BASE) return window._SECUREMAIL_API_BASE.replace(/\/+$/, '');
      if (window.location.protocol === 'file:' || !window.location.origin || window.location.origin === 'null' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        return 'http://localhost:8000/api';
      }
      return `${window.location.origin}/api`;
    }
    const API_ROOT = resolveBackendApi();
    window._resolveBackendApi = resolveBackendApi;

    // Chrome Extension ID for seamless Web-App-to-Extension Auth Session Sync.
    // Can also be set dynamically via localStorage.setItem('securemail_ext_id', 'your_id')
    window._SECUREMAIL_EXTENSION_ID = window._SECUREMAIL_EXTENSION_ID || localStorage.getItem('securemail_ext_id') || "djnpegjpbblkbenbcgknfnfmncgcijfb";

    let fbConfig = {
      apiKey: "AIzaSyBUQbf_FrTPxY47Do9Ldp3d5dIXDscUfz8",
      authDomain: "mail-31dbb.firebaseapp.com",
      projectId: "mail-31dbb",
      storageBucket: "mail-31dbb.firebasestorage.app",
      messagingSenderId: "843370137586",
      appId: "1:843370137586:web:5e5d0ed4f7196e39480d6b"
    };

    try {
      const res = await fetch(`${API_ROOT}/auth/config`);
      if (res.ok) {
        const remoteCfg = await res.json();
        fbConfig = { ...fbConfig, ...remoteCfg };
      }
    } catch (e) {}

    if (fbConfig.apiKey) {
      const app      = initializeApp(fbConfig);
      const auth     = getAuth(app);
      const provider = new GoogleAuthProvider();

      // Expose to global scope so non-module scripts can call them
      window._fbAuth                 = auth;
      window._fbProvider             = provider;
      window._fbSignIn               = (e,p) => signInWithEmailAndPassword(auth, e, p);
      window._fbSignUp               = (e,p) => createUserWithEmailAndPassword(auth, e, p);
      window._fbGoogle               = ()    => signInWithPopup(auth, provider);
      window._fbSignOut              = ()    => signOut(auth);
      window._fbReset                = (e)   => sendPasswordResetEmail(auth, e);
      window._fbUpdate               = (u,d) => updateProfile(u, d);
      window._fbSendVerification     = (u)   => sendEmailVerification(u);
      window._fbLinkCredential       = (u,c) => linkWithCredential(u, c);
      window._fbEmailCred            = (e,p) => EmailAuthProvider.credential(e, p);
      window._fbGetSignInMethods     = (e)   => fetchSignInMethodsForEmail(auth, e);
      window._fbGetAdditionalUserInfo = (res) => getAdditionalUserInfo(res);
      window._fbUpdatePassword       = (u,p) => updatePassword(u, p);

      // Helper for extension tab probe
      window._getSecureMailSession = () => {
        if (window._authToken && window._authUser) {
          return {
            token: window._authToken,
            email: window._authUser.email || '',
            displayName: window._authUser.displayName || '',
            expiresAt: Date.now() + (55 * 60 * 1000)
          };
        }
        return null;
      };

      // Listen for session sync requests from extension content script
      window.addEventListener('message', (event) => {
        if (event.data && event.data.type === 'SECUREMAIL_REQUEST_AUTH_SYNC') {
          if (window._authToken && window._authUser) {
            window.postMessage({
              type: 'SECUREMAIL_AUTH_SYNC',
              idToken: window._authToken,
              expiresAt: Date.now() + (55 * 60 * 1000),
              userEmail: window._authUser.email || '',
              email: window._authUser.email || '',
              displayName: window._authUser.displayName || ''
            }, '*');
          }
        }
      });

      // ── Auth state gate ──────────────────────────────────────
      onAuthStateChanged(auth, async (user) => {
        if (user) {
          // Get fresh ID token and attach to every API request
          const token = await user.getIdToken();
          // Intentionally in-memory only — do not persist to localStorage/sessionStorage, this is a deliberate XSS-mitigation choice
          window._authToken = token;
          window._authUser  = user;

          // Broadcast session to extension content script (zero-config sync)
          window.postMessage({
            type: 'SECUREMAIL_AUTH_SYNC',
            idToken: token,
            expiresAt: Date.now() + (55 * 60 * 1000),
            userEmail: user.email,
            email: user.email,
            displayName: user.displayName || ''
          }, '*');

          // Refresh token every 55 min (tokens expire at 60 min)
          clearInterval(window._tokenRefreshInterval);
          window._tokenRefreshInterval = setInterval(async () => {
            // Intentionally in-memory only — do not persist to localStorage/sessionStorage, this is a deliberate XSS-mitigation choice
            const freshToken = await user.getIdToken(true);
            window._authToken = freshToken;

            // Broadcast refreshed token to content script
            window.postMessage({
              type: 'SECUREMAIL_AUTH_SYNC',
              idToken: freshToken,
              expiresAt: Date.now() + (55 * 60 * 1000),
              userEmail: user.email,
              email: user.email,
              displayName: user.displayName || ''
            }, '*');

            try {
              const extId = window._SECUREMAIL_EXTENSION_ID || localStorage.getItem('securemail_ext_id');
              if (extId && extId !== "the_real_extension_id_here" && window.chrome && chrome.runtime && chrome.runtime.sendMessage) {
                chrome.runtime.sendMessage(extId, {
                  type: 'SECUREMAIL_AUTH_SYNC',
                  idToken: freshToken,
                  expiresAt: Date.now() + (55 * 60 * 1000),
                  userEmail: user.email,
                  email: user.email,
                  displayName: user.displayName || ''
                }, () => { if (chrome.runtime.lastError) {} });
              }
            } catch (e) {}
          }, 55 * 60 * 1000);

          // Opportunistically sync auth token to extension if extension is installed
          try {
            const extId = window._SECUREMAIL_EXTENSION_ID || localStorage.getItem('securemail_ext_id');
            if (extId && extId !== "the_real_extension_id_here" && window.chrome && chrome.runtime && chrome.runtime.sendMessage) {
              chrome.runtime.sendMessage(extId, {
                type: 'SECUREMAIL_AUTH_SYNC',
                idToken: token,
                expiresAt: Date.now() + (55 * 60 * 1000),
                userEmail: user.email,
                email: user.email,
                displayName: user.displayName || ''
              }, () => { if (chrome.runtime.lastError) {} });
            }
          } catch (e) {}

          if (window._isOnboardingActive) {
            return;
          }
          showApp(user);
        } else {
          // Intentionally in-memory only — do not persist to localStorage/sessionStorage, this is a deliberate XSS-mitigation choice
          window._authToken = null;
          window._authUser  = null;
          // Unauthenticated: show full app as guest (scanner default, 5 scans/day)
          showAppGuest();
        }
      });
    } else {
      // Intentionally in-memory only — do not persist to localStorage/sessionStorage, this is a deliberate XSS-mitigation choice
      window._authToken = null;
      window._authUser  = null;
      showAppGuest();
    }
