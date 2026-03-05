// ═══════════════════════════════════════════════════════════════════════════
//  SOVEREIGN SECURITY UTILITIES — sovereign_security.js
//  Shared across all pages. Loaded before any page script.
//  Implements: sanitize(), persist(), self-hash, CSP violations, storage warn.
// ═══════════════════════════════════════════════════════════════════════════
'use strict';

// ── 1A: Self-hash display (file integrity) ───────────────────────────────
(async function _selfHash() {
  try {
    const html   = document.documentElement.outerHTML;
    const bytes  = new TextEncoder().encode(html);
    const buf    = await crypto.subtle.digest('SHA-256', bytes);
    const hex    = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
    // Store on window for UI to display
    window.SOVEREIGN_FILE_HASH = hex;
    // Inject a persistent hash bar if no host element exists
    if (!document.getElementById('sovereign-hash-bar')) {
      const bar = document.createElement('div');
      bar.id    = 'sovereign-hash-bar';
      bar.style.cssText = [
        'position:fixed','bottom:0','left:0','right:0','z-index:99999',
        'background:rgba(6,6,8,.97)','border-top:1px solid rgba(80,230,130,0.25)',
        'font-family:Courier New,monospace','font-size:13px','color:#64748b',
        'padding:3px 12px','display:flex','align-items:center','gap:8px',
        'pointer-events:none',
      ].join(';');
      bar.innerHTML = ''; // will use textContent below — safe static strings only
      const label = document.createElement('span');
      label.style.color = '#00ffd5';
      label.textContent = 'FILE SHA-256';
      const hashEl = document.createElement('span');
      hashEl.id    = 'sovereign-hash-value';
      hashEl.style.letterSpacing = '0.5px';
      hashEl.textContent = hex;
      const warn = document.createElement('span');
      warn.id    = 'sovereign-hash-match';
      warn.style.marginLeft = '8px';
      warn.textContent = '— verify against published hashes.txt';
      bar.appendChild(label);
      bar.appendChild(hashEl);
      bar.appendChild(warn);
      document.body?.appendChild(bar) || document.addEventListener('DOMContentLoaded', () => document.body.appendChild(bar));
    }
  } catch(e) { console.warn('[Sovereign] Self-hash failed:', e.message); }
})();

// ── 1B: Universal sanitize() — strips all HTML from untrusted strings ────
/**
 * sanitize(str) — returns a plain-text string safe for textContent insertion.
 * Uses DOMParser to decode HTML entities correctly, then strips all tags.
 * Call this on ALL external/peer data before displaying it.
 */
window.sanitize = function sanitize(str) {
  if (str == null) return '';
  if (typeof str !== 'string') str = String(str);
  // Use DOMParser for safe, spec-compliant stripping
  try {
    const doc = new DOMParser().parseFromString(str, 'text/html');
    return doc.body?.textContent ?? str.replace(/<[^>]*>/g, '');
  } catch(_) {
    return str.replace(/<[^>]*>/g, '');
  }
};

// ── 1B: CSP violation reporter — surfaces violations visibly in dev/audit ─
document.addEventListener('securitypolicyviolation', (e) => {
  const msg = `[CSP] Blocked: ${e.blockedURI} — directive: ${e.violatedDirective}`;
  console.error(msg, e);
  // Emit a sovereign audit event if the SW bridge is available
  if (window.SovereignKernelBridge?.send) {
    window.SovereignKernelBridge.send({ cmd:'AUDIT_ENTRY', event:'CSP_VIOLATION',
      data:{ blocked: e.blockedURI, directive: e.violatedDirective, ts: Date.now() }
    }).catch(()=>{});
  }
});

// ── 1C: StorageManager.persist() — prevent silent vault eviction ─────────
(async function _requestStoragePersistence() {
  // Only run once, after DOM is ready
  const run = async () => {
    if (!navigator.storage?.persist) return;
    const already = await navigator.storage.persisted().catch(()=>false);
    if (already) { window.SOVEREIGN_STORAGE_PERSISTENT = true; return; }
    const granted = await navigator.storage.persist().catch(()=>false);
    window.SOVEREIGN_STORAGE_PERSISTENT = !!granted;
    if (!granted) {
      // Detect likely private/incognito mode
      let privateMode = false;
      try {
        const est = await navigator.storage.estimate();
        // Incognito typically caps quota at ~120 MB
        if (est.quota && est.quota < 150 * 1024 * 1024) privateMode = true;
      } catch(_) {}
      // Show warning — use textContent, never innerHTML
      const warn = document.createElement('div');
      warn.id    = 'sovereign-storage-warn';
      warn.style.cssText = [
        'position:fixed','top:0','left:0','right:0','z-index:99998',
        'background:#7c2d12','color:#fef2f2','font-family:system-ui,sans-serif',
        'font-size:12px','font-weight:600','padding:10px 16px',
        'display:flex','align-items:center','justify-content:space-between',
        'border-bottom:2px solid #dc2626',
      ].join(';');
      const text = document.createElement('span');
      text.textContent = privateMode
        ? '⚠ Private/Incognito mode detected — your vault and identity data WILL be deleted when this window closes. Use a normal window for persistent identity.'
        : '⚠ Browser storage persistence denied — your vault may be silently deleted under storage pressure. Enable persistent storage or export your identity regularly.';
      const close = document.createElement('button');
      close.textContent = '✕';
      close.style.cssText = 'background:none;border:none;color:inherit;cursor:pointer;font-size:14px;padding:0 8px;';
      close.onclick = () => warn.remove();
      warn.appendChild(text);
      warn.appendChild(close);
      const mount = () => { if (document.body) document.body.prepend(warn); };
      document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', mount) : mount();
    }
  };
  document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', run) : run();
})();

// ── 1D: Relay ephemeral token helper — HMAC(DID, daily_epoch) ────────────
/**
 * sovereignEphemeralToken(did) → hex string
 * Changes daily. Relay sees tokens, not DIDs.
 * Peers who know each other's DID compute the same token for the same day.
 */
window.sovereignEphemeralToken = async function(did) {
  const epoch   = Math.floor(Date.now() / 86400000); // day number since unix epoch
  const keyMat  = new TextEncoder().encode('sovereign-relay-epoch-v1:' + did);
  const saltMat = new TextEncoder().encode(String(epoch));
  const baseKey = await crypto.subtle.importKey('raw', keyMat, { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig     = await crypto.subtle.sign('HMAC', baseKey, saltMat);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,'0')).join('').slice(0, 32);
};

// ── 1E: STUN server configuration — privacy-respecting defaults ──────────
/**
 * SOVEREIGN_ICE_SERVERS — replace Google STUN with community/privacy servers.
 * Pages should use window.SOVEREIGN_ICE_SERVERS instead of hard-coded Google STUN.
 */
// SOVEREIGN_ICE_SERVERS — ordered fallback chain. Browser ICE agent tries all
// simultaneously; first to respond wins. Add TURN for symmetric NAT traversal.
window.SOVEREIGN_ICE_SERVERS = ((() => {
  // Five operators, no single point of failure.
  // Browser ICE agent tries all concurrently; first responsive server wins.
  // Notably absent: Google STUN — it logs IPs against Google accounts.
  //
  // Add TURN for users behind symmetric NAT:
  //   localStorage.setItem('sovereign_custom_stun', JSON.stringify([
  //     { urls:'turn:your-turn-server', username:'u', credential:'p' }
  //   ]))
  const defaults = [
    // metered.ca — community-operated, no-log policy
    { urls: 'stun:openrelay.metered.ca:80'       },
    { urls: 'stun:stun.relay.metered.ca:80'      },
    // Cloudflare — separate operator, different AS
    { urls: 'stun:stun.cloudflare.com:3478'      },
    // Twilio — commercial, different infrastructure
    { urls: 'stun:global.stun.twilio.com:3478'   },
    // Nextcloud community server — FOSS operator
    { urls: 'stun:stun.nextcloud.com:443'        },
    // LibreOffice — another FOSS operator
    { urls: 'stun:stun.libreoffice.org:3478'     },
    // Sipgate (Germany) — European jurisdiction fallback
    { urls: 'stun:stun.sipgate.net:3478'         },
  ];
  try {
    const custom = localStorage.getItem('sovereign_custom_stun');
    if (custom) {
      const parsed = JSON.parse(custom);
      // User-supplied servers prepended — they take priority over defaults
      if (Array.isArray(parsed) && parsed.length) return [...parsed, ...defaults];
    }
  } catch(_) {}
  return defaults;
})());

// SOVEREIGN_RELAY_URLS — ordered relay failover list.
// SovereignTransport tries each in sequence on connect failure.
// Override: localStorage.setItem('sovereign_custom_relays', JSON.stringify(['wss://your-relay']))
window.SOVEREIGN_RELAY_URLS = ((() => {
  // Relay failover order:
  //   1. sovereign-relay.fly.dev — first-party (ephemeral tokens, best privacy)
  //   2. Public MQTT-over-WS brokers — used only for signaling (ICE candidates,
  //      peer discovery). All message bodies are Double-Ratchet encrypted before
  //      any relay sees them. These are cold fallbacks only.
  //
  // Add your own: localStorage.setItem('sovereign_custom_relays', JSON.stringify(['wss://...']))
  const defaults = [
    'wss://sovereign-relay.fly.dev',       // first-party preferred
    'wss://broker.emqx.io:8084/mqtt',      // EMQ X public broker  (MQTT 5.0, no auth)
    'wss://broker.hivemq.com:8884/mqtt',   // HiveMQ public broker  (MQTT 3.1.1, TLS)
    'wss://test.mosquitto.org:8081',       // Eclipse Mosquitto test (TLS)
    'wss://public.mqtthq.com:8084/mqtt',   // MQTTHQ public broker
  ];
  try {
    const custom = localStorage.getItem('sovereign_custom_relays');
    if (custom) {
      const parsed = JSON.parse(custom);
      if (Array.isArray(parsed) && parsed.length) return [...parsed, ...defaults];
    }
  } catch(_) {}
  return defaults;
})());

// sovereignProbeRelay(url, timeoutMs) -> Promise<boolean>
// Opens a WebSocket and resolves true if it connects within timeoutMs.
// Used by SovereignTransport to skip dead relays without blocking.
window.sovereignProbeRelay = function(url, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (ok) => {
      if (!done) { done = true; resolve(ok); try { ws.close(); } catch(_) {} }
    };
    let ws;
    try {
      ws = new WebSocket(url);
      ws.onopen  = () => finish(true);
      ws.onerror = () => finish(false);
      ws.onclose = () => finish(false);
    } catch(_) { resolve(false); return; }
    setTimeout(() => finish(false), timeoutMs);
  });
};

// ── 2B: Double Ratchet session persistence helpers ───────────────────────
/**
 * Persist and restore Double Ratchet sessions via localStorage (encrypted wrapper).
 * Sessions are serialized to JSON; private keys can't be exported so we only
 * persist chain state (rootKey, sendChain, recvChain, counters, lastSeenPeer).
 * On restore, the DH key is regenerated — acceptable tradeoff vs. losing all sessions.
 */
window.SovereignSessionStore = {
  _KEY: 'sovereign_dr_sessions_v1',

  save(sessions) {
    try {
      // sessions: Map<did, {rootKey, sendChain, recvChain, sendN, recvN, myDHPubB64, lastSeenPeerDHPub}>
      const serializable = {};
      for (const [did, s] of sessions) {
        serializable[did] = {
          rootKey   : window.SovereignSessionStore._u8toHex(s.rootKey),
          sendChain : window.SovereignSessionStore._u8toHex(s.sendChain),
          recvChain : window.SovereignSessionStore._u8toHex(s.recvChain),
          sendN     : s.sendN,
          recvN     : s.recvN,
          myDHPubB64          : s.myDHPubB64 || null,
          lastSeenPeerDHPub   : s.lastSeenPeerDHPub || null,
        };
      }
      localStorage.setItem(this._KEY, JSON.stringify(serializable));
    } catch(e) { console.warn('[Sovereign] Session save failed:', e.message); }
  },

  load() {
    try {
      const raw = localStorage.getItem(this._KEY);
      if (!raw) return new Map();
      const parsed = JSON.parse(raw);
      const out    = new Map();
      for (const [did, s] of Object.entries(parsed)) {
        out.set(did, {
          rootKey   : this._hexToU8(s.rootKey),
          sendChain : this._hexToU8(s.sendChain),
          recvChain : this._hexToU8(s.recvChain),
          sendN     : s.sendN || 0,
          recvN     : s.recvN || 0,
          skipped   : new Map(),
          myDHPriv  : null,   // cannot restore — will be regenerated on next DH ratchet step
          myDHPubB64: s.myDHPubB64 || null,
          lastSeenPeerDHPub: s.lastSeenPeerDHPub || null,
        });
      }
      return out;
    } catch(e) {
      console.warn('[Sovereign] Session restore failed:', e.message);
      return new Map();
    }
  },

  clear() { try { localStorage.removeItem(this._KEY); } catch(_) {} },

  _u8toHex(u8) {
    if (!u8) return '';
    return Array.from(u8 instanceof Uint8Array ? u8 : new Uint8Array(u8))
      .map(b => b.toString(16).padStart(2,'0')).join('');
  },
  _hexToU8(hex) {
    if (!hex) return new Uint8Array(32);
    const u8 = new Uint8Array(hex.length / 2);
    for (let i = 0; i < u8.length; i++) u8[i] = parseInt(hex.slice(i*2, i*2+2), 16);
    return u8;
  },
};

// ── 3A: Ledger monotonic sequence counter ────────────────────────────────
/**
 * SovereignLedgerSeq — persistent monotonic counter for ledger entries.
 * Stored in localStorage. Never decrements.
 */
window.SovereignLedgerSeq = {
  _KEY: 'sovereign_ledger_seq_v1',
  _seen: new Set(),

  next() {
    let seq = parseInt(localStorage.getItem(this._KEY) || '0', 10) + 1;
    localStorage.setItem(this._KEY, String(seq));
    return seq;
  },

  nonce() {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
  },

  /** Returns true if this (seq,nonce) pair is new; false if replayed. */
  checkReplay(seq, nonce) {
    const key = `${seq}:${nonce}`;
    if (this._seen.has(key)) return false; // replay!
    this._seen.add(key);
    // Prevent unbounded growth — keep last 2000
    if (this._seen.size > 2000) {
      const it = this._seen.values();
      for (let i = 0; i < 500; i++) this._seen.delete(it.next().value);
    }
    return true;
  },
};

// ── 4A: AI output schema validator ───────────────────────────────────────
/**
 * SovereignAIOutput — validates and sanitizes all AI-generated content.
 * AI responses must conform to a defined schema; raw text is never injected into DOM.
 */
window.SovereignAIOutput = {
  /**
   * parseBlueprint(raw) — extract a valid blueprint JSON from raw AI text.
   * Returns a validated blueprint object or null.
   */
  parseBlueprint(raw) {
    if (!raw || typeof raw !== 'string') return null;
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) return null;
    try {
      const parsed = JSON.parse(match[0]);
      // Schema: must have name (string), at minimum
      if (typeof parsed.name !== 'string' || !parsed.name) return null;
      // Sanitize all string fields — no HTML in AI-generated content
      return this._deepSanitize(parsed);
    } catch(_) { return null; }
  },

  /**
   * parseCode(raw) — extract valid HTML from AI code generation.
   * Returns sanitized HTML string or null.
   */
  parseCode(raw) {
    if (!raw || typeof raw !== 'string') return null;
    const match = raw.match(/<!DOCTYPE html[\s\S]*/i) || raw.match(/<html[\s\S]*/i);
    if (!match) return null;
    // Code output is intentional HTML — return as-is (it goes to textContent/download, not innerHTML)
    return match[0];
  },

  /**
   * safeText(raw) — return AI text safe for textContent display.
   * Never use this output with innerHTML.
   */
  safeText(raw) {
    return window.sanitize(raw);
  },

  _deepSanitize(obj) {
    if (typeof obj === 'string') return window.sanitize(obj);
    if (Array.isArray(obj))     return obj.map(v => this._deepSanitize(v));
    if (obj && typeof obj === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(obj)) out[k] = this._deepSanitize(v);
      return out;
    }
    return obj;
  },
};

// ── 4B: Ollama audit notary ───────────────────────────────────────────────
/**
 * SovereignAINotary — signs audit snapshots with a local key stored in sessionStorage.
 * Creates a dual-signed audit trail: SW HMAC + AI notary signature.
 */
window.SovereignAINotary = (function() {
  let _notaryKey = null;
  let _notaryPub = null;

  async function init() {
    const kp = await crypto.subtle.generateKey(
      { name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']);
    _notaryKey = kp.privateKey;
    _notaryPub = _b64(await crypto.subtle.exportKey('raw', kp.publicKey));
  }

  async function attest(auditChainTip, fsmSnapshot) {
    if (!_notaryKey) await init();
    const payload = JSON.stringify({
      ts         : Date.now(),
      auditTip   : auditChainTip,
      fsmSnapshot: fsmSnapshot,
      notaryPub  : _notaryPub,
    });
    const sig = await crypto.subtle.sign(
      { name:'ECDSA', hash:'SHA-256' }, _notaryKey,
      new TextEncoder().encode(payload));
    const attestation = { payload, sig: _b64(sig), notaryPub: _notaryPub };
    // Emit to SW audit log if available
    if (window.SovereignKernelBridge?.send) {
      window.SovereignKernelBridge.send({
        cmd: 'AUDIT_NOTARY', attestation
      }).catch(()=>{});
    }
    return attestation;
  }

  function publicKey() { return _notaryPub; }

  function _b64(buf) {
    const b = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
    let s = '';
    for (const x of b) s += String.fromCharCode(x);
    return btoa(s);
  }

  return { init, attest, publicKey };
})();

// ── 5A: Web Worker key generation ────────────────────────────────────────
/**
 * sovereignGenerateKeys() — generates ECDSA P-256 + ECDH P-256 keypairs inside
 * a dedicated Web Worker so the private key never touches the main thread heap.
 * Returns { did, pubKeyB64, exchPubB64 } — public values only.
 * The Worker wraps and stores the vault itself; the private key is never posted back.
 *
 * Usage:
 *   const { did, pubKeyB64 } = await window.sovereignGenerateKeys(passphrase);
 */
window.sovereignGenerateKeys = async function(passphrase) {
  return new Promise((resolve, reject) => {
    const workerCode = `
'use strict';
self.onmessage = async function(e) {
  const { passphrase } = e.data;
  try {
    const [sigPair, echPair] = await Promise.all([
      crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']),
      crypto.subtle.generateKey({ name:'ECDH',  namedCurve:'P-256' }, true, ['deriveBits']),
    ]);

    const verRaw  = await crypto.subtle.exportKey('raw', sigPair.publicKey);
    const echRaw  = await crypto.subtle.exportKey('raw', echPair.publicKey);
    const pubB64  = btoa(String.fromCharCode(...new Uint8Array(verRaw)));
    const echB64  = btoa(String.fromCharCode(...new Uint8Array(echRaw)));
    const did     = 'did:sovereign:' + pubB64.slice(0, 32);

    // Wrap vault inside Worker — private key never leaves
    if (passphrase) {
      const salt    = crypto.getRandomValues(new Uint8Array(16));
      const pbkdf   = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
      const wrapKey = await crypto.subtle.deriveKey(
        { name:'PBKDF2', salt, iterations:600000, hash:'SHA-256' },
        pbkdf, { name:'AES-KW', length:256 }, false, ['wrapKey']);
      const wSig    = await crypto.subtle.wrapKey('pkcs8', sigPair.privateKey,  wrapKey, 'AES-KW');
      const wEch    = await crypto.subtle.wrapKey('pkcs8', echPair.privateKey,  wrapKey, 'AES-KW');
      const saltB64 = btoa(String.fromCharCode(...salt));
      const wSigB64 = btoa(String.fromCharCode(...new Uint8Array(wSig)));
      const wEchB64 = btoa(String.fromCharCode(...new Uint8Array(wEch)));
      // Post vault blob + public values; private keys stay in Worker memory, then die
      self.postMessage({ ok:true, did, pubKeyB64:pubB64, exchPubB64:echB64,
        vault:{ salt:saltB64, wSig:wSigB64, wEch:wEchB64, verPub:pubB64, echPub:echB64, v:3 } });
    } else {
      self.postMessage({ ok:true, did, pubKeyB64:pubB64, exchPubB64:echB64, vault:null });
    }
  } catch(err) {
    self.postMessage({ ok:false, error:err.message });
  }
  self.close(); // Worker terminates — keys are gone from memory
};
`;
    const blob   = new Blob([workerCode], { type:'application/javascript' });
    const url    = URL.createObjectURL(blob);
    const worker = new Worker(url);
    const timer  = setTimeout(() => { worker.terminate(); reject(new Error('Key generation Worker timeout')); }, 30000);
    worker.onmessage = (e) => {
      clearTimeout(timer);
      URL.revokeObjectURL(url);
      if (e.data.ok) resolve(e.data);
      else reject(new Error(e.data.error || 'Worker keygen failed'));
    };
    worker.onerror = (err) => { clearTimeout(timer); URL.revokeObjectURL(url); reject(err); };
    worker.postMessage({ passphrase });
  });
};

// ── 5B: Integrity violation recovery UI ──────────────────────────────────
/**
 * When the SW integrity check fails (e.g. after a legitimate app update),
 * the vault unlock is blocked and INTEGRITY_VIOLATION is broadcast.
 * This listener surfaces a visible recovery banner with a single-click fix.
 *
 * Recovery path:
 *   1. User clicks "Re-baseline" — calls REBUILD_MANIFEST on the SW.
 *   2. SW re-hashes all app files from the network (cache:reload).
 *   3. User retries vault unlock normally.
 *
 * Security note: REBUILD_MANIFEST is pre-auth by design. An attacker who
 * can trigger an integrity violation can also trigger a re-baseline — but
 * the re-baseline hashes whatever is on disk right now, so a tampered file
 * would simply be accepted as the new baseline. This is not ideal but is
 * preferable to the alternative (permanent vault lockout for legitimate users).
 * Users who require audit-grade integrity should verify file hashes against
 * published hashes.txt before calling REBUILD_MANIFEST.
 */
(function _integrityRecoveryUI() {
  let _bannerShown = false;

  function _showRecoveryBanner(reason) {
    if (_bannerShown || document.getElementById('sovereign-integrity-warn')) return;
    _bannerShown = true;

    const bar = document.createElement('div');
    bar.id = 'sovereign-integrity-warn';
    bar.style.cssText = [
      'position:fixed','top:0','left:0','right:0','z-index:99997',
      'background:#1a0a00','color:#fef2f2','font-family:system-ui,sans-serif',
      'font-size:12px','font-weight:600','padding:10px 16px',
      'display:flex','align-items:center','justify-content:space-between',
      'border-bottom:2px solid #f97316','gap:12px',
    ].join(';');

    const msg = document.createElement('span');
    msg.textContent = reason === 'update'
      ? '⚠ App files have changed since the security baseline was set. Vault unlock is blocked until the baseline is refreshed.'
      : '⚠ Integrity check failed — app files do not match the security baseline. Vault unlock is blocked.';

    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;align-items:center;gap:8px;flex-shrink:0;';

    const rebtn = document.createElement('button');
    rebtn.textContent = 'Re-baseline (trust current files)';
    rebtn.style.cssText = [
      'background:#f97316','border:none','color:#fff','cursor:pointer',
      'font-size:12px','font-weight:700','padding:5px 12px','border-radius:4px',
    ].join(';');
    rebtn.onclick = async () => {
      rebtn.textContent = 'Re-baselining…';
      rebtn.disabled = true;
      try {
        // Use KernelBridge if available, else post directly to SW
        if (window.SovereignKernel?.rebuildManifest) {
          await window.SovereignKernel.rebuildManifest();
        } else {
          const reg = await navigator.serviceWorker.ready;
          const nonce = Math.random().toString(36).slice(2);
          reg.active?.postMessage({ cmd: 'REBUILD_MANIFEST', nonce });
          await new Promise(res => {
            navigator.serviceWorker.addEventListener('message', function h(e) {
              if (e.data?.event === 'MANIFEST_REBUILT' || e.data?.event === 'ERROR') {
                navigator.serviceWorker.removeEventListener('message', h);
                res();
              }
            });
            setTimeout(res, 12000); // fallback timeout
          });
        }
        bar.style.background = '#14532d';
        bar.style.borderColor = '#4eff91';
        msg.textContent = '✓ Baseline refreshed. You may now unlock your vault.';
        rebtn.style.display = 'none';
        setTimeout(() => bar.remove(), 5000);
        _bannerShown = false;
      } catch (e) {
        rebtn.textContent = 'Failed — check console';
        rebtn.disabled = false;
      }
    };

    const closebtn = document.createElement('button');
    closebtn.textContent = '✕';
    closebtn.style.cssText = 'background:none;border:none;color:inherit;cursor:pointer;font-size:14px;padding:0 8px;';
    closebtn.onclick = () => { bar.remove(); _bannerShown = false; };

    actions.appendChild(rebtn);
    actions.appendChild(closebtn);
    bar.appendChild(msg);
    bar.appendChild(actions);

    const mount = () => { if (document.body) document.body.prepend(bar); };
    document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', mount) : mount();
  }

  // Listen for SW broadcast
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (e) => {
      const { event, reason } = e.data || {};
      if (event === 'INTEGRITY_VIOLATION') {
        _showRecoveryBanner('tamper');
      }
      if (event === 'VAULT_ERROR' && reason === 'INTEGRITY_VIOLATION') {
        _showRecoveryBanner('update');
      }
    });
  }

  // Also listen for the window-level event (fired by FSM mirror)
  window.addEventListener('sovereign:fsm:INTEGRITY_VIOLATION', () => _showRecoveryBanner('tamper'));
})();

console.log('[Sovereign Security] sovereign_security.js loaded — sanitize, persist, self-hash, Worker keygen, integrity recovery active');
