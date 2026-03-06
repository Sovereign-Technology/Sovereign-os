/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SOVEREIGN SECURITY UTILITIES  v3.0  —  sovereign_security.js
 *
 *  Shared across all Sovereign pages. Must be loaded FIRST.
 *  No external dependencies.
 *
 *  Implements:
 *    §1  File integrity self-hash (SHA-256 of current page DOM)
 *    §2  sanitize() — DOMParser + allowlist HTML sanitizer
 *    §3  CSP violation reporter with audit bridge
 *    §4  StorageManager.persist() — prevent silent vault eviction
 *    §5  sovereignEphemeralToken() — daily HMAC relay privacy token
 *    §6  STUN/ICE server configuration
 *    §7  SovereignSessionStore — namespaced, typed IndexedDB wrapper
 *    §8  memZero() — best-effort memory zeroing for sensitive buffers
 *    §9  timingSafeEqual() — constant-time comparison
 *    §10 SovereignCSPNonce — nonce generation and injection
 *    §11 deepFreeze() — structural clone + freeze for untrusted data
 *    §12 rateLimit() — token-bucket rate limiter
 *    §13 subresourceIntegrityCheck() — verify CDN resources
 *
 *  © James Chapman (XheCarpenXer) · iconoclastdao@gmail.com
 *  Dual License — see LICENSE.md
 * ═══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
//  §1 — FILE INTEGRITY SELF-HASH
//  Hashes the outer HTML of the current document and displays a verification
//  bar at the bottom of the page. Users can compare against published hashes.
// ─────────────────────────────────────────────────────────────────────────────
(async function _selfHash() {
  try {
    const html  = document.documentElement.outerHTML;
    const bytes = new TextEncoder().encode(html);
    const buf   = await crypto.subtle.digest('SHA-256', bytes);
    const hex   = Array.from(new Uint8Array(buf))
                    .map(b => b.toString(16).padStart(2,'0')).join('');

    window.SOVEREIGN_FILE_HASH = hex;

    // Only inject the bar once
    if (document.getElementById('sovereign-hash-bar')) return;

    const mount = () => {
      if (!document.body) return;

      const bar  = document.createElement('div');
      bar.id     = 'sovereign-hash-bar';
      Object.assign(bar.style, {
        position:       'fixed',
        bottom:         '0',
        left:           '0',
        right:          '0',
        height:         '22px',
        zIndex:         '99999',
        background:     'rgba(4,4,6,0.97)',
        borderTop:      '1px solid rgba(0,232,124,0.2)',
        fontFamily:     '"JetBrains Mono",Courier New,monospace',
        fontSize:       '10px',
        color:          '#475569',
        padding:        '0 12px',
        display:        'flex',
        alignItems:     'center',
        gap:            '10px',
        pointerEvents:  'none',
        userSelect:     'none',
        overflow:       'hidden',
        whiteSpace:     'nowrap',
      });

      const label = _el('span', { color:'#00e87c', fontWeight:'600' }, 'FILE SHA-256');
      const hash  = _el('span', { letterSpacing:'0.5px', color:'#64748b' }, hex);
      const note  = _el('span', {}, '— verify against hashes.txt');

      bar.append(label, hash, note);
      document.body.appendChild(bar);

      hash.id = 'sovereign-hash-value';
    };

    document.readyState === 'loading'
      ? document.addEventListener('DOMContentLoaded', mount)
      : mount();

  } catch (e) {
    console.warn('[Sovereign] Self-hash failed:', e.message);
  }

  function _el(tag, styles, text) {
    const el = document.createElement(tag);
    Object.assign(el.style, styles);
    el.textContent = text;
    return el;
  }
})();

// ─────────────────────────────────────────────────────────────────────────────
//  §2 — SANITIZE
//  sanitize(str) → plain-text string safe for textContent insertion.
//  sanitizeHTML(str, allowedTags?) → HTML string with only allowed tags retained.
//  All external / peer data MUST pass through one of these before any DOM use.
// ─────────────────────────────────────────────────────────────────────────────

/** Strip all HTML — safe for textContent. */
window.sanitize = function sanitize(str) {
  if (str == null) return '';
  if (typeof str !== 'string') str = String(str);
  try {
    const doc = new DOMParser().parseFromString(str, 'text/html');
    return doc.body?.textContent ?? str.replace(/<[^>]*>/g, '');
  } catch (_) {
    return str.replace(/<[^>]*>/g, '');
  }
};

/**
 * Allow a restricted subset of HTML through.
 * Default allowlist: b, i, em, strong, a (href only, no javascript:), code, pre, br, p, ul, ol, li
 * Suitable for rendering peer-submitted rich text in trusted UI contexts.
 */
window.sanitizeHTML = function sanitizeHTML(str, allowed) {
  if (str == null) return '';
  if (typeof str !== 'string') str = String(str);

  const ALLOWED_TAGS = new Set(allowed ?? [
    'b','i','em','strong','a','code','pre','br','p','ul','ol','li','span','blockquote',
  ]);
  const ALLOWED_ATTRS = {
    a:    ['href','title'],
    span: ['class'],
  };

  try {
    const doc     = new DOMParser().parseFromString(str, 'text/html');
    const walker  = document.createTreeWalker(doc.body, NodeFilter.SHOW_ELEMENT);
    const toRemove = [];

    let node = walker.nextNode();
    while (node) {
      const tag = node.tagName.toLowerCase();
      if (!ALLOWED_TAGS.has(tag)) {
        toRemove.push(node);
      } else {
        // Strip disallowed attributes
        const permittedAttrs = ALLOWED_ATTRS[tag] ?? [];
        for (const attr of [...node.attributes]) {
          if (!permittedAttrs.includes(attr.name)) {
            node.removeAttribute(attr.name);
          }
        }
        // Never allow javascript: hrefs
        if (tag === 'a') {
          const href = node.getAttribute('href') ?? '';
          if (/^\s*javascript:/i.test(href) || /^\s*data:/i.test(href)) {
            node.removeAttribute('href');
          }
        }
      }
      node = walker.nextNode();
    }

    // Replace disallowed elements with their text content
    for (const n of toRemove) {
      const text = document.createTextNode(n.textContent);
      n.parentNode?.replaceChild(text, n);
    }

    return doc.body.innerHTML;
  } catch (_) {
    return window.sanitize(str); // fallback to full strip
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  §3 — CSP VIOLATION REPORTER
//  Surfaces violations visibly in dev/audit mode.
//  Forwards to the Security Kernel audit log via SovereignKernelBridge.
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener('securitypolicyviolation', (e) => {
  const msg = `[CSP] Blocked: ${e.blockedURI} — directive: ${e.violatedDirective}`;
  console.error(msg, e);

  if (window.SovereignKernelBridge?.send) {
    window.SovereignKernelBridge.send({
      cmd:   'AUDIT_ENTRY',
      event: 'CSP_VIOLATION',
      data:  {
        blocked:   e.blockedURI,
        directive: e.violatedDirective,
        ts:        Date.now(),
      },
    }).catch(() => {});
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  §4 — STORAGE PERSISTENCE
//  Request persistent storage to prevent silent vault eviction.
//  Warns visibly if denied (private mode, restricted browser, etc.)
// ─────────────────────────────────────────────────────────────────────────────
(async function _requestPersistence() {
  const run = async () => {
    if (!navigator.storage?.persist) return;
    const already = await navigator.storage.persisted().catch(() => false);
    if (already) { window.SOVEREIGN_STORAGE_PERSISTENT = true; return; }

    const granted = await navigator.storage.persist().catch(() => false);
    window.SOVEREIGN_STORAGE_PERSISTENT = !!granted;
    if (granted) return;

    // Probe for private/incognito mode
    let privateMode = false;
    try {
      const est = await navigator.storage.estimate();
      if (est.quota && est.quota < 200 * 1024 * 1024) privateMode = true;
    } catch (_) {}

    _injectStorageWarning(privateMode);
  };

  document.readyState === 'loading'
    ? document.addEventListener('DOMContentLoaded', run)
    : run();

  function _injectStorageWarning(privateMode) {
    if (document.getElementById('sovereign-storage-warn')) return;
    const bar   = document.createElement('div');
    bar.id      = 'sovereign-storage-warn';
    Object.assign(bar.style, {
      position:       'fixed',
      top:            '0',
      left:           '0',
      right:          '0',
      zIndex:         '99998',
      background:     '#7c1d1d',
      color:          '#fef2f2',
      fontFamily:     'system-ui,sans-serif',
      fontSize:       '12px',
      fontWeight:     '600',
      padding:        '10px 16px',
      display:        'flex',
      alignItems:     'center',
      justifyContent: 'space-between',
      borderBottom:   '2px solid #dc2626',
    });
    const text = document.createElement('span');
    text.textContent = privateMode
      ? '⚠ Private/Incognito mode — your vault WILL be deleted when this window closes. Use a normal window.'
      : '⚠ Storage persistence denied — vault may be silently deleted under pressure. Export your identity regularly.';
    const close = document.createElement('button');
    Object.assign(close.style, {
      background: 'none', border: 'none', color: 'inherit',
      cursor: 'pointer', fontSize: '16px', padding: '0 8px',
    });
    close.textContent = '✕';
    close.onclick = () => bar.remove();
    bar.appendChild(text);
    bar.appendChild(close);
    document.body?.prepend(bar);
  }
})();

// ─────────────────────────────────────────────────────────────────────────────
//  §5 — EPHEMERAL RELAY TOKEN
//  HMAC(DID, daily_epoch) — changes every UTC day.
//  The relay sees this token, never the DID.
//  Peers who know each other's DID compute the same token for the same day.
// ─────────────────────────────────────────────────────────────────────────────
window.sovereignEphemeralToken = async function(did) {
  const epoch  = Math.floor(Date.now() / 86_400_000);
  const keyMat = new TextEncoder().encode('sovereign-relay-epoch-v2:' + did);
  const salt   = new TextEncoder().encode(String(epoch));
  const base   = await crypto.subtle.importKey(
    'raw', keyMat, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig    = await crypto.subtle.sign('HMAC', base, salt);
  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2,'0')).join('').slice(0, 32);
};

// ─────────────────────────────────────────────────────────────────────────────
//  §6 — ICE / STUN / TURN CONFIGURATION
//  Ordered fallback chain. Browser ICE agent tries all concurrently.
//  Google STUN is intentionally absent — it logs IPs against Google accounts.
// ─────────────────────────────────────────────────────────────────────────────
window.SOVEREIGN_ICE_SERVERS = (() => {
  // Allow runtime override via localStorage (e.g. for TURN-behind-symmetric-NAT users)
  try {
    const custom = localStorage.getItem('sovereign_custom_stun');
    if (custom) return JSON.parse(custom);
  } catch (_) {}

  return [
    { urls: 'stun:openrelay.metered.ca:80'      },  // metered.ca — privacy policy OK
    { urls: 'stun:stun.relay.metered.ca:80'     },
    { urls: 'stun:stun.cloudflare.com:3478'     },  // Cloudflare STUN
    { urls: 'stun:global.stun.twilio.com:3478'  },  // Twilio STUN
    { urls: 'stun:stun.nextcloud.com:3478'      },  // Nextcloud STUN
    { urls: 'stun:stun.libreoffice.org:3478'    },  // LibreOffice STUN
    // Add TURN entries here for symmetric NAT traversal:
    // { urls: 'turn:your-domain.com:3478', username: '...', credential: '...' }
  ];
})();

// ─────────────────────────────────────────────────────────────────────────────
//  §7 — SOVEREIGN SESSION STORE
//  Namespaced, typed wrapper around IndexedDB.
//  Provides get/set/delete/list/clear with a clean Promise API.
// ─────────────────────────────────────────────────────────────────────────────
window.SovereignSessionStore = (() => {

  const DB_NAME    = 'sovereign_v3';
  const DB_VERSION = 3;
  const STORES     = ['vault','identity','peers','messages','settings','audit','governance'];

  let _db = null;

  function _open() {
    if (_db) return Promise.resolve(_db);
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        for (const name of STORES) {
          if (!db.objectStoreNames.contains(name)) {
            db.createObjectStore(name, { keyPath: 'key' });
          }
        }
      };
      req.onsuccess  = () => { _db = req.result; resolve(_db); };
      req.onerror    = () => reject(req.error);
    });
  }

  async function _tx(store, mode, fn) {
    const db  = await _open();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(store, mode);
      const obj = tx.objectStore(store);
      const req = fn(obj);
      req.onsuccess = () => resolve(req.result);
      req.onerror   = () => reject(req.error);
    });
  }

  return {
    async get(store, key) {
      const row = await _tx(store, 'readonly', s => s.get(key));
      return row?.value ?? null;
    },
    async set(store, key, value) {
      return _tx(store, 'readwrite', s => s.put({ key, value, ts: Date.now() }));
    },
    async delete(store, key) {
      return _tx(store, 'readwrite', s => s.delete(key));
    },
    async list(store) {
      return new Promise(async (resolve, reject) => {
        const db  = await _open();
        const tx  = db.transaction(store, 'readonly');
        const obj = tx.objectStore(store);
        const req = obj.getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
      });
    },
    async clear(store) {
      return _tx(store, 'readwrite', s => s.clear());
    },
    async keys(store) {
      const rows = await this.list(store);
      return rows.map(r => r.key);
    },
  };

})();

// ─────────────────────────────────────────────────────────────────────────────
//  §8 — MEMORY ZEROING (best-effort)
//  memZero(buffer) — overwrites a TypedArray with zeros.
//  Use on raw key material and secret byte arrays after they are no longer needed.
//  The JS runtime may still retain copies in GC'd memory — this is a mitigation,
//  not a guarantee. Do not rely on it as the only defense.
// ─────────────────────────────────────────────────────────────────────────────
window.memZero = function memZero(buf) {
  if (!buf) return;
  if (buf instanceof ArrayBuffer) {
    new Uint8Array(buf).fill(0);
  } else if (ArrayBuffer.isView(buf)) {
    new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).fill(0);
  } else if (Array.isArray(buf)) {
    buf.fill(0);
  }
  // Attempt GC hint (non-standard, no-op in most environments)
  try { global?.gc?.(); } catch (_) {}
};

// ─────────────────────────────────────────────────────────────────────────────
//  §9 — TIMING-SAFE COMPARISON
//  timingSafeEqual(a, b) — compare two Uint8Arrays in constant time.
//  Prevents timing-oracle attacks on MACs / HMACs / tokens.
// ─────────────────────────────────────────────────────────────────────────────
window.timingSafeEqual = function timingSafeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    throw new TypeError('timingSafeEqual: both arguments must be Uint8Array');
  }
  if (a.length !== b.length) return false; // length leak is acceptable — caller controls it
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  §10 — CSP NONCE GENERATION & INJECTION
//  SovereignCSPNonce.generate() → 16-byte base64url nonce
//  SovereignCSPNonce.inject(el) → attaches a fresh nonce to a script/style element
//  Use when dynamically injecting trusted scripts at runtime.
// ─────────────────────────────────────────────────────────────────────────────
window.SovereignCSPNonce = (() => {
  const _pool = new Uint8Array(16);

  function generate() {
    crypto.getRandomValues(_pool);
    return (()=>{let _s='';for(let _i=0;_i<_pool.length;_i++)_s+=String.fromCharCode(_pool[_i]);return btoa(_s)})()
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  function inject(element) {
    const nonce = generate();
    element.nonce = nonce;
    return nonce;
  }

  return { generate, inject };
})();

// ─────────────────────────────────────────────────────────────────────────────
//  §11 — DEEP FREEZE (for untrusted structured data)
//  deepFreeze(obj) — recursively Object.freeze()s an object.
//  Use on peer-supplied payloads before passing them to UI code.
// ─────────────────────────────────────────────────────────────────────────────
window.deepFreeze = function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  // Use structuredClone to sever all external references first
  let clone;
  try { clone = structuredClone(obj); } catch (_) { clone = obj; }
  Object.freeze(clone);
  for (const key of Object.keys(clone)) {
    if (typeof clone[key] === 'object' && clone[key] !== null) {
      deepFreeze(clone[key]);
    }
  }
  return clone;
};

// ─────────────────────────────────────────────────────────────────────────────
//  §12 — TOKEN-BUCKET RATE LIMITER
//  rateLimit(key, limit, windowMs) → boolean (true = allowed)
//  Per-key counters stored in memory. Resets automatically per window.
//  Use on relay message handlers, crypto operations, etc.
// ─────────────────────────────────────────────────────────────────────────────
window.rateLimit = (() => {
  const _buckets = new Map(); // key → { count, resetAt }

  return function rateLimit(key, limit = 60, windowMs = 60_000) {
    const now    = Date.now();
    let   bucket = _buckets.get(key);

    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      _buckets.set(key, bucket);
    }

    if (bucket.count >= limit) return false;
    bucket.count++;
    return true;
  };
})();

// ─────────────────────────────────────────────────────────────────────────────
//  §13 — SUBRESOURCE INTEGRITY CHECK
//  sovereignSRICheck(url, expectedSHA256Hex) → Promise<boolean>
//  Fetches a resource and verifies its SHA-256 against an expected hash.
//  Use before executing any dynamically loaded external script.
// ─────────────────────────────────────────────────────────────────────────────
window.sovereignSRICheck = async function(url, expectedHex) {
  try {
    const res  = await fetch(url, { cache: 'no-store' });
    const buf  = await res.arrayBuffer();
    const hash = await crypto.subtle.digest('SHA-256', buf);
    const hex  = Array.from(new Uint8Array(hash))
                   .map(b => b.toString(16).padStart(2,'0')).join('');
    return hex === expectedHex;
  } catch (err) {
    console.warn('[Sovereign] SRI check failed:', url, err.message);
    return false;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  KERNEL BRIDGE
//  Provides a message-channel interface to the Security Kernel (genesis_sw.js).
//  Pages post commands via SW.postMessage; responses arrive via navigator.serviceWorker.
//  SovereignKernelBridge.send(cmd) → Promise resolving to SW response.
// ─────────────────────────────────────────────────────────────────────────────
window.SovereignKernelBridge = (() => {

  const _pending = new Map();
  let   _nonce   = 0;

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (e) => {
      const { _nonce: n, ...rest } = e.data ?? {};
      if (n != null && _pending.has(n)) {
        _pending.get(n)(rest);
        _pending.delete(n);
      }
    });
  }

  async function send(cmd) {
    const sw = await navigator.serviceWorker?.ready;
    if (!sw?.active) return Promise.reject(new Error('No active service worker'));

    const id      = ++_nonce;
    const payload = { ...cmd, _nonce: id };

    return new Promise((resolve, reject) => {
      _pending.set(id, resolve);
      // 10-second timeout for all kernel commands
      setTimeout(() => {
        if (_pending.has(id)) {
          _pending.delete(id);
          reject(new Error(`Kernel command timeout: ${cmd.cmd}`));
        }
      }, 10_000);
      sw.active.postMessage(payload);
    });
  }

  return { send };
})();

// ─────────────────────────────────────────────────────────────────────────────
//  SOVEREIGN SERVICE WORKER REGISTRATION
//  Registers genesis_sw.js if not already active.
//  Fires 'sovereign:sw:ready' on window when the kernel is online.
// ─────────────────────────────────────────────────────────────────────────────
(async function _registerSW() {
  if (!('serviceWorker' in navigator)) {
    console.warn('[Sovereign] Service Worker not supported — key isolation unavailable.');
    return;
  }
  try {
    const reg = await navigator.serviceWorker.register('./genesis_sw.js', { scope: './' });

    const fire = () => window.dispatchEvent(new CustomEvent('sovereign:sw:ready', { detail: { reg } }));

    if (navigator.serviceWorker.controller) {
      fire();
    } else {
      navigator.serviceWorker.addEventListener('controllerchange', fire, { once: true });
    }

    reg.addEventListener('updatefound', () => {
      const w = reg.installing;
      w?.addEventListener('statechange', () => {
        if (w.state === 'installed' && navigator.serviceWorker.controller) {
          window.dispatchEvent(new CustomEvent('sovereign:sw:update-available'));
        }
      });
    });

  } catch (err) {
    console.error('[Sovereign] SW registration failed:', err.message);
  }
})();

console.log('[Sovereign Security v3.0] Utilities loaded — §1–§13 active');
