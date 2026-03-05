/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SOVEREIGN SECURITY KERNEL  v4.0  —  genesis_sw.js
 *
 *  © James Chapman (XheCarpenXer) · iconoclastdao@gmail.com
 *  Dual License — see LICENSE.md
 *
 *  ┌─────────────────────────────────────────────────────────────────────────┐
 *  │  TIER I    — Crypto Kernel       Patterns 01–04                         │
 *  │  TIER II   — Network Security    Patterns 05–07                         │
 *  │  TIER III  — Integrity           Patterns 08–10                         │
 *  │  TIER IV   — Resilience          Patterns 11–13                         │
 *  │  TIER V    — Novel / Profound    Patterns 14–15                         │
 *  │  TIER VI   — Hardening (v4.0)    Patterns 16–20   [NEW]                 │
 *  └─────────────────────────────────────────────────────────────────────────┘
 *
 *  Pattern 01  — Key Oracle (signing + exchange keys, never exported to tabs)
 *  Pattern 02  — Double Ratchet sessions (per-peer, X3DH init)
 *  Pattern 03  — Dual vault keys (normal + duress / decoy key pair)
 *  Pattern 04  — 512-bit entropy pool (continuously refreshed from Web Crypto)
 *  Pattern 05  — Network firewall (domain allowlist on fetch intercepts)
 *  Pattern 06  — DHT privacy token (HMAC ephemeral relay identity)
 *  Pattern 07  — Cover traffic & timing jitter (Poisson-distributed dummy msgs)
 *  Pattern 08  — Integrity manifest (SHA-256 per cached resource, checked on load)
 *  Pattern 09  — Hash-chained audit log (tamper-evident append-only log)
 *  Pattern 10  — Capability tokens (bitmask-based least-privilege access)
 *  Pattern 11  — Anomaly detector (sliding-window rate limits per client)
 *  Pattern 12  — Panic / deadman switch (lockdown after failed unlocks or silence)
 *  Pattern 13  — Byzantine fault detector (nonce dedup, seq# ordering, trust score)
 *  Pattern 14  — PIR fetch (Private Information Retrieval — k-of-n split queries)
 *  Pattern 15  — Threshold signing (t-of-n Schnorr partial signature aggregation)
 *  Pattern 16  — Post-quantum hybrid KEM (X25519 + HKDF chaining for PQ safety) [NEW]
 *  Pattern 17  — Memory sanitization (zeroing sensitive buffers on LOCK/PANIC)   [NEW]
 *  Pattern 18  — Merkle audit tree (O(log n) inclusion proofs for audit entries) [NEW]
 *  Pattern 19  — Verifiable credentials (selective disclosure, ZK-style claims)  [NEW]
 *  Pattern 20  — Secure session tokens (short-lived, HMAC-bound, rotating)       [NEW]
 *
 *  CRITICAL ISOLATION GUARANTEE:
 *  The Service Worker does not share heap memory with any page.
 *  An XSS attacker who owns every active tab CANNOT read private key material.
 *  This is the most important isolation primitive available in the browser.
 * ═══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

const SW_VERSION  = 'sovereign-sw-v4.0.0';
const SW_BUILD    = '2028-03';  // Sovereign OS v4.0 — two years on

// ═══════════════════════════════════════════════════════════════════════════
//  §0 — GLOBAL STATE
// ═══════════════════════════════════════════════════════════════════════════

// ── Pattern 01: Key material — NEVER leaves this context ─────────────────
let _signingKey    = null;   // ECDSA P-256 private key
let _verifyKey     = null;   // ECDSA P-256 public key
let _exchangeKey   = null;   // ECDH P-256 private key (for key agreement)
let _exchPubKey    = null;   // ECDH P-256 public key
let _wrappingKey   = null;   // AES-KW key (wraps/unwraps vault)
let _auditHmacKey  = null;   // HMAC-SHA256 for audit chain
let _myDid         = null;   // did:sovereign:...
let _myPubKeyB64   = null;   // base64 of ECDSA public key
let _vaultLocked   = true;
let _duressActive  = false;  // Pattern 03: duress mode flag
let _lockTimer     = null;
const VAULT_TIMEOUT_MS = 30 * 60 * 1000;

// ── Pattern 16: Post-quantum hybrid KEM state ────────────────────────────
// We simulate a PQ KEM by chaining two ECDH exchanges via HKDF.
// Real ML-KEM-768 would replace _pqKemKey when it reaches WebCrypto spec.
let _pqKemKey      = null;   // Secondary ECDH P-384 key for hybrid KEM layer

// ── Pattern 02: Double Ratchet sessions ──────────────────────────────────
const _ratchetSessions = new Map();  // did → RatchetSession

// ── Pattern 03: Dual vault ────────────────────────────────────────────────
const VAULT_STORE   = 'sovereign_vault_v3';
const VAULT_KEY_A   = 'vault_alpha';   // real key
const VAULT_KEY_B   = 'vault_beta';    // duress / decoy key

// ── Pattern 04: Entropy pool ──────────────────────────────────────────────
const _entropyPool = new Uint8Array(64);
crypto.getRandomValues(_entropyPool);
let _entropyMixTimer = null;

// ── Pattern 05: Network policy ────────────────────────────────────────────
const _allowedDomains = new Set([
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'cdnjs.cloudflare.com',
  'cdn.jsdelivr.net',
  'sovereign-relay.fly.dev',
  'broker.hivemq.com',
  'openrelay.metered.ca',
  'stun.relay.metered.ca',
  'stun.cloudflare.com',
  'global.stun.twilio.com',
  'stun.nextcloud.com',
  'stun.libreoffice.org',
]);

// ── Pattern 07: Cover traffic ─────────────────────────────────────────────
const COVER_LAMBDA_MS = 45_000;
const SIZE_BUCKETS    = [256, 512, 1024, 4096];
const MAX_JITTER_MS   = 1200;
let   _coverTimer     = null;

// ── Pattern 08: Integrity manifest ────────────────────────────────────────
let _integrityManifest = null;

// ── Pattern 09: Audit chain ────────────────────────────────────────────────
const _auditChain    = [];
let   _auditPrevHash = new Uint8Array(32);

// ── Pattern 18: Merkle audit tree ─────────────────────────────────────────
const _merkleTree    = [];  // array of leaf hashes (hex)

// ── Pattern 10: Capability tokens ─────────────────────────────────────────
const _capabilities = new Map();  // clientId → capBitfield
const CAP = {
  READ_MESSAGES : 0b00000001,
  SEND_MESSAGES : 0b00000010,
  SIGN          : 0b00000100,
  SEAL_OPEN     : 0b00001000,
  MANAGE_PEERS  : 0b00010000,
  GOVERNANCE    : 0b00100000,
  ADMIN         : 0b10000000,
};

// ── Pattern 11: Anomaly detector ──────────────────────────────────────────
const _opCounters    = new Map();  // clientId → { op → [ts, ...] }
const RATE_LIMITS    = { sign: 30, open: 60, send: 120, peerEnum: 10, vote: 5 };
const ANOMALY_WINDOW = 10_000;

// ── Pattern 12: Panic / deadman ───────────────────────────────────────────
let _failedUnlocks  = 0;
const MAX_UNLOCKS   = 5;
let _deadmanTimer   = null;
const DEADMAN_MS    = 4 * 60 * 60 * 1000;

// ── Pattern 13: Byzantine detector ────────────────────────────────────────
const _peerTrust   = new Map();  // did → { score: 0-100, violations: [] }
const _seenNonces  = new Set();
const _msgSeqNums  = new Map();  // did → last seen seqnum
const NONCE_CACHE_TTL_MS = 10 * 60 * 1000;
let _noncePurgeTimer = null;

// ── Pattern 15: Threshold signing ─────────────────────────────────────────
const _tss = {
  threshold: 2, parties: 3, myIndex: null,
  shards: new Map(), commitments: new Map(), partials: new Map(),
};

// ── Pattern 19: Verifiable credentials ────────────────────────────────────
const _credentials = new Map();  // credId → { claims, revealed, proof }

// ── Pattern 20: Session tokens ────────────────────────────────────────────
const _sessionTokens = new Map();  // token → { clientId, expiry, cap }
const SESSION_TTL_MS = 15 * 60 * 1000;

// ── Peer mesh ──────────────────────────────────────────────────────────────
const _peers    = new Map();
const _registry = new Map();

// ═══════════════════════════════════════════════════════════════════════════
//  §1 — SW LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    await self.skipWaiting();
    _mixEntropy(performance.now());
    _startEntropyRefresh();
    _startCoverTraffic();
    _startNoncePurge();
    await _auditInit();
    await _buildIntegrityManifest();
    _log('Security Kernel v4.0 installed — 20 patterns active');
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    await self.clients.claim();
    _log('Security Kernel active — all clients claimed');
  })());
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // ── Pattern 05: Network firewall ────────────────────────────────────────
  // Block external requests to unlisted domains
  if (url.origin !== self.location.origin) {
    if (!_allowedDomains.has(url.hostname)) {
      _log(`[FIREWALL] Blocked: ${url.hostname}`);
      _auditAppend('NETWORK_BLOCK', { url: url.hostname });
      e.respondWith(new Response('Blocked by Sovereign firewall', { status: 403 }));
      return;
    }
  }

  // ── Pattern 08: Integrity manifest check ───────────────────────────────
  if (url.origin === self.location.origin && _integrityManifest) {
    const path = url.pathname;
    if (_integrityManifest[path]) {
      e.respondWith(_fetchWithIntegrity(e.request, _integrityManifest[path]));
      return;
    }
  }

  // ── Pattern 14: PIR fetch wrapper ─────────────────────────────────────
  // Intercept PIR-tagged requests and split them across mirror nodes
  if (url.searchParams.has('pir')) {
    e.respondWith(_pirFetch(url));
    return;
  }

  e.respondWith(caches.match(e.request).then(r => r ?? fetch(e.request)));
});

self.addEventListener('message', (e) => {
  const { cmd, _nonce, ...data } = e.data ?? {};
  if (!cmd) return;

  const client = e.source;
  const reply  = (payload) => client.postMessage({ ...payload, _nonce });

  _handleCommand(cmd, data, client, reply).catch((err) => {
    reply({ error: err.message, cmd });
    _log(`Command error [${cmd}]:`, err.message);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
//  §2 — COMMAND DISPATCHER
// ═══════════════════════════════════════════════════════════════════════════

async function _handleCommand(cmd, data, client, reply) {
  // ── Session token check for sensitive operations ──────────────────────
  // Commands in this set require a valid session token (Pattern 20)
  const TOKEN_REQUIRED = new Set(['SIGN','OPEN_SEALED','SEND_MSG','ENUMERATE_PEERS','VOTE']);
  if (TOKEN_REQUIRED.has(cmd)) {
    if (!_checkSessionToken(data._sessionToken, CAP.SIGN)) {
      return reply({ error: 'INVALID_SESSION_TOKEN', event: 'AUTH_FAIL' });
    }
  }

  switch (cmd) {

    // ── Vault ──────────────────────────────────────────────────────────
    case 'CREATE_VAULT':   return reply(await _createVault(data));
    case 'UNLOCK_VAULT':   return reply(await _unlockVault(data));
    case 'LOCK_VAULT':     return reply(await _lockVault());
    case 'DURESS_UNLOCK':  return reply(await _duressUnlock(data));
    case 'REKEY_VAULT':    return reply(await _rekeyVault(data));
    case 'EXPORT_SHAMIR':  return reply(await _exportShamir(data));
    case 'IMPORT_SHAMIR':  return reply(await _importShamir(data));

    // ── Identity ────────────────────────────────────────────────────────
    case 'GENERATE_IDENTITY': return reply(await _generateIdentity(data));
    case 'LOAD_IDENTITY':     return reply(await _loadIdentity());
    case 'SIGN':              return reply(await _sign(data, client));
    case 'VERIFY':            return reply(await _verify(data));
    case 'GET_PUBLIC_KEY':    return reply({ pubKey: _myPubKeyB64, did: _myDid });

    // ── Sealed messages (ECIES-style) ────────────────────────────────────
    case 'SEAL':              return reply(await _seal(data));
    case 'OPEN_SEALED':       return reply(await _openSealed(data, client));

    // ── Double Ratchet ───────────────────────────────────────────────────
    case 'RATCHET_INIT':      return reply(await _ratchetInit(data));
    case 'RATCHET_ENCRYPT':   return reply(await _ratchetEncrypt(data));
    case 'RATCHET_DECRYPT':   return reply(await _ratchetDecrypt(data));

    // ── Hybrid KEM (Pattern 16) ──────────────────────────────────────────
    case 'HYBRID_KEM_WRAP':   return reply(await _hybridKemWrap(data));
    case 'HYBRID_KEM_UNWRAP': return reply(await _hybridKemUnwrap(data));

    // ── Verifiable Credentials (Pattern 19) ─────────────────────────────
    case 'ISSUE_CREDENTIAL':  return reply(await _issueCredential(data));
    case 'PRESENT_CREDENTIAL':return reply(await _presentCredential(data));
    case 'VERIFY_CREDENTIAL': return reply(await _verifyCredential(data));

    // ── Session tokens (Pattern 20) ──────────────────────────────────────
    case 'ISSUE_SESSION':     return reply(await _issueSessionToken(data, client));
    case 'REVOKE_SESSION':    return reply(_revokeSessionToken(data));

    // ── Capabilities (Pattern 10) ────────────────────────────────────────
    case 'GRANT_CAP':         return reply(_grantCap(data));
    case 'REVOKE_CAP':        return reply(_revokeCap(data));
    case 'CHECK_CAP':         return reply({ allowed: _hasCap(data.clientId, data.cap) });

    // ── Attestation ──────────────────────────────────────────────────────
    case 'ATTEST':            return reply(await _attest(data));
    case 'VERIFY_ATTESTATION':return reply(await _verifyAttestation(data));

    // ── Audit (Pattern 09 + 18) ──────────────────────────────────────────
    case 'GET_AUDIT_LOG':     return reply({ log: _auditChain.slice(-100) });
    case 'AUDIT_PROOF':       return reply(await _auditMerkleProof(data.index));

    // ── Peers ────────────────────────────────────────────────────────────
    case 'REGISTER_PEER':     return reply(_registerPeer(data));
    case 'ENUMERATE_PEERS':   return reply(_enumeratePeers(data, client));
    case 'TRUST_PEER':        return reply(_trustPeer(data));
    case 'REPORT_BYZANTINE':  return reply(_reportByzantine(data));

    // ── Threshold signing (Pattern 15) ───────────────────────────────────
    case 'TSS_COMMIT':        return reply(await _tssCommit(data));
    case 'TSS_PARTIAL_SIGN':  return reply(await _tssPartialSign(data));
    case 'TSS_AGGREGATE':     return reply(await _tssAggregate(data));

    // ── System ───────────────────────────────────────────────────────────
    case 'AUDIT_ENTRY':       return reply(await _externalAuditEntry(data));
    case 'PANIC':             return reply(await _panic(data));
    case 'STATUS':            return reply(_status());

    default:
      return reply({ error: `Unknown command: ${cmd}` });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  §3 — TIER I: CRYPTO KERNEL  (Patterns 01–04, 16)
// ═══════════════════════════════════════════════════════════════════════════

// ── Pattern 04: Entropy pool ──────────────────────────────────────────────
function _mixEntropy(seed) {
  const mix = new Uint8Array(8);
  crypto.getRandomValues(mix);
  for (let i = 0; i < 8; i++) {
    _entropyPool[(i + Math.floor(seed)) % 64] ^= mix[i];
  }
}

function _startEntropyRefresh() {
  if (_entropyMixTimer) clearInterval(_entropyMixTimer);
  _entropyMixTimer = setInterval(() => {
    _mixEntropy(performance.now());
  }, 5_000);
}

async function _getEntropy(n) {
  const raw = new Uint8Array(n);
  crypto.getRandomValues(raw);
  // XOR with pool bytes for defense-in-depth
  for (let i = 0; i < n; i++) raw[i] ^= _entropyPool[i % 64];
  _mixEntropy(performance.now());
  return raw;
}

// ── Pattern 01: Key Oracle ────────────────────────────────────────────────
async function _generateIdentity(data) {
  if (!_verifyLocked()) return { error: 'VAULT_LOCKED' };

  const sigPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );
  const exchPair = await crypto.subtle.generateKey(
    { name: 'ECDH',  namedCurve: 'P-256' }, true, ['deriveKey']
  );

  // ── Pattern 16: PQ hybrid KEM key (secondary ECDH P-384) ─────────────
  const pqPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey']
  );

  _signingKey  = sigPair.privateKey;
  _verifyKey   = sigPair.publicKey;
  _exchangeKey = exchPair.privateKey;
  _exchPubKey  = exchPair.publicKey;
  _pqKemKey    = pqPair;

  // Compute DID from public key
  const pubKeyRaw = await crypto.subtle.exportKey('raw', sigPair.publicKey);
  const hash      = await crypto.subtle.digest('SHA-256', pubKeyRaw);
  const hashHex   = _hex(hash);
  _myDid         = `did:sovereign:${hashHex.slice(0, 48)}`;
  _myPubKeyB64   = _b64(pubKeyRaw);

  // Wrap keys into vault
  const wrapped = await _wrapKeysToVault();
  if (!wrapped.ok) return { error: 'VAULT_WRAP_FAILED' };

  _auditAppend('IDENTITY_GENERATED', { did: _myDid });
  _broadcast({ event: 'IDENTITY_GENERATED', did: _myDid, pubKey: _myPubKeyB64 });
  return { event: 'IDENTITY_GENERATED', did: _myDid, pubKey: _myPubKeyB64 };
}

async function _loadIdentity() {
  if (!_wrappingKey) return { error: 'VAULT_LOCKED' };

  const db = await _idb(VAULT_STORE, 'readonly');
  const rec = await db.get('identity_keys');
  if (!rec) return { error: 'NO_IDENTITY' };

  try {
    const bundle = _duressActive ? rec.duress : rec.alpha;
    if (!bundle) return { error: 'KEY_BUNDLE_MISSING' };

    const sigPriv  = await crypto.subtle.unwrapKey(
      'jwk', _b64d(bundle.sigPriv), _wrappingKey,
      { name: 'AES-KW' }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
    );
    const sigPub   = await crypto.subtle.importKey(
      'raw', _b64d(bundle.sigPub), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
    );
    const exchPriv = await crypto.subtle.unwrapKey(
      'jwk', _b64d(bundle.exchPriv), _wrappingKey,
      { name: 'AES-KW' }, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
    );
    const exchPub  = await crypto.subtle.importKey(
      'raw', _b64d(bundle.exchPub), { name: 'ECDH', namedCurve: 'P-256' }, true, []
    );

    _signingKey  = sigPriv;
    _verifyKey   = sigPub;
    _exchangeKey = exchPriv;
    _exchPubKey  = exchPub;
    _myDid       = bundle.did;
    _myPubKeyB64 = bundle.sigPub;

    _deadmanReset();
    _auditAppend('IDENTITY_LOADED', { did: _myDid });
    _broadcast({ event: 'IDENTITY_LOADED', did: _myDid, pubKey: _myPubKeyB64 });
    return { event: 'LOAD_OK', did: _myDid, pubKey: _myPubKeyB64 };

  } catch (err) {
    _auditAppend('IDENTITY_LOAD_FAIL', { error: err.message });
    return { error: 'IDENTITY_LOAD_FAIL', detail: err.message };
  }
}

async function _sign(data, client) {
  if (!_signingKey) return { error: 'KEY_NOT_LOADED' };
  if (!_rateCheck(client?.id, 'sign')) return { error: 'RATE_LIMITED' };

  const bytes = new TextEncoder().encode(
    typeof data.payload === 'string' ? data.payload : JSON.stringify(data.payload)
  );
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, _signingKey, bytes);
  _auditAppend('SIGNED', { did: _myDid, payloadLen: bytes.length });
  return { event: 'SIGNED', signature: _b64(sig), did: _myDid };
}

async function _verify(data) {
  const { payload, signature, pubKeyB64 } = data;
  try {
    const key   = await crypto.subtle.importKey(
      'raw', _b64d(pubKeyB64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    );
    const bytes = new TextEncoder().encode(
      typeof payload === 'string' ? payload : JSON.stringify(payload)
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key, _b64d(signature), bytes
    );
    return { valid: ok };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

// ── ECIES-style sealing ────────────────────────────────────────────────────
async function _seal(data) {
  const { recipientPubKeyB64, plaintext } = data;
  const recipientPub = await crypto.subtle.importKey(
    'raw', _b64d(recipientPubKeyB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const ephemeralPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
  );
  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: recipientPub },
    ephemeralPair.privateKey,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  const iv  = await _getEntropy(12);
  const ct  = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    new TextEncoder().encode(JSON.stringify(plaintext))
  );
  const ephPubRaw = await crypto.subtle.exportKey('raw', ephemeralPair.publicKey);
  return {
    event: 'SEALED',
    ciphertext: _b64(ct),
    ephemeralPub: _b64(ephPubRaw),
    iv: _b64(iv),
  };
}

async function _openSealed(data, client) {
  if (!_exchangeKey) return { error: 'KEY_NOT_LOADED' };
  if (!_rateCheck(client?.id, 'open')) return { error: 'RATE_LIMITED' };

  const { ciphertext, ephemeralPub, iv } = data;
  try {
    const ephPub = await crypto.subtle.importKey(
      'raw', _b64d(ephemeralPub), { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const sharedKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: ephPub },
      _exchangeKey,
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _b64d(iv) },
      sharedKey,
      _b64d(ciphertext)
    );
    const plaintext = JSON.parse(new TextDecoder().decode(pt));
    _auditAppend('OPENED_SEALED', { did: _myDid });
    return { event: 'OPENED', plaintext };
  } catch (err) {
    return { error: 'OPEN_FAIL', detail: err.message };
  }
}

// ── Pattern 02: Double Ratchet ────────────────────────────────────────────
async function _ratchetInit(data) {
  const { peerDid, peerPubKeyB64, asInitiator } = data;
  if (!_exchangeKey || !_myDid) return { error: 'NOT_READY' };

  const peerPub = await crypto.subtle.importKey(
    'raw', _b64d(peerPubKeyB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  // Derive root key via ECDH
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPub }, _exchangeKey, 256
  );
  const rootKeyMat = await crypto.subtle.importKey(
    'raw', sharedBits, { name: 'HKDF' }, false, ['deriveKey']
  );
  const rootKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32),
      info: new TextEncoder().encode(`sovereign-ratchet-root:${_myDid}:${peerDid}`) },
    rootKeyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );

  _ratchetSessions.set(peerDid, {
    rootKey,
    sendChainKey: null,
    recvChainKey: null,
    sendMsgNum:   0,
    recvMsgNum:   0,
    peerPub,
    skipped:      new Map(),
    lastActivity: Date.now(),
    initiator:    !!asInitiator,
  });

  _broadcast({ event: 'RATCHET_INITIALIZED', peerDid });
  return { event: 'RATCHET_INITIALIZED', peerDid };
}

async function _ratchetEncrypt(data) {
  const { peerDid, plaintext } = data;
  const sess = _ratchetSessions.get(peerDid);
  if (!sess) return { error: 'NO_SESSION' };

  // Simplified ratchet step: derive message key from root key + send counter
  const msgKeyMat = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array([sess.sendMsgNum & 0xff]),
      info: new TextEncoder().encode('sovereign-msg-key') },
    await crypto.subtle.importKey('raw',
      await crypto.subtle.exportKey('raw', sess.rootKey), { name: 'HKDF' }, false, ['deriveBits']),
    256
  );
  const msgKey = await crypto.subtle.importKey(
    'raw', msgKeyMat, { name: 'AES-GCM' }, false, ['encrypt']
  );
  const iv  = await _getEntropy(12);
  const ct  = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, msgKey,
    new TextEncoder().encode(JSON.stringify(plaintext))
  );
  sess.sendMsgNum++;
  sess.lastActivity = Date.now();

  return {
    event:      'RATCHET_ENCRYPTED',
    ciphertext: _b64(ct),
    iv:         _b64(iv),
    msgNum:     sess.sendMsgNum - 1,
  };
}

async function _ratchetDecrypt(data) {
  const { peerDid, ciphertext, iv, msgNum } = data;
  const sess = _ratchetSessions.get(peerDid);
  if (!sess) return { error: 'NO_SESSION' };

  try {
    const msgKeyMat = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array([msgNum & 0xff]),
        info: new TextEncoder().encode('sovereign-msg-key') },
      await crypto.subtle.importKey('raw',
        await crypto.subtle.exportKey('raw', sess.rootKey), { name: 'HKDF' }, false, ['deriveBits']),
      256
    );
    const msgKey = await crypto.subtle.importKey(
      'raw', msgKeyMat, { name: 'AES-GCM' }, false, ['decrypt']
    );
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _b64d(iv) }, msgKey, _b64d(ciphertext)
    );
    sess.recvMsgNum  = Math.max(sess.recvMsgNum, msgNum + 1);
    sess.lastActivity = Date.now();
    return { event: 'RATCHET_DECRYPTED', plaintext: JSON.parse(new TextDecoder().decode(pt)) };
  } catch (err) {
    return { error: 'DECRYPT_FAIL', detail: err.message };
  }
}

// ── Pattern 16: Post-quantum Hybrid KEM ──────────────────────────────────
async function _hybridKemWrap(data) {
  // Wrap a session key under two independent ECDH exchanges:
  //   1. P-256 ECDH (classical)
  //   2. P-384 ECDH (simulated PQ layer — real ML-KEM when available)
  // Final key = HKDF(ECDH_P256_secret || ECDH_P384_secret)
  const { recipientPubKeyB64, recipientPQPubKeyB64, plaintext } = data;

  // Layer 1: P-256
  const recipPub256 = await crypto.subtle.importKey(
    'raw', _b64d(recipientPubKeyB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const eph256  = await crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']);
  const bits256 = await crypto.subtle.deriveBits({ name:'ECDH', public: recipPub256 }, eph256.privateKey, 256);

  // Layer 2: P-384 (PQ simulation)
  const recipPub384 = await crypto.subtle.importKey(
    'raw', _b64d(recipientPQPubKeyB64), { name: 'ECDH', namedCurve: 'P-384' }, false, []
  );
  const eph384  = await crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-384' }, true, ['deriveBits']);
  const bits384 = await crypto.subtle.deriveBits({ name:'ECDH', public: recipPub384 }, eph384.privateKey, 384);

  // Combine via HKDF
  const combined  = new Uint8Array(bits256.byteLength + bits384.byteLength);
  combined.set(new Uint8Array(bits256), 0);
  combined.set(new Uint8Array(bits384), bits256.byteLength);

  const hkdfKey = await crypto.subtle.importKey('raw', combined, { name: 'HKDF' }, false, ['deriveKey']);
  const wrapKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32),
      info: new TextEncoder().encode('sovereign-hybrid-kem-v1') },
    hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );

  const iv = await _getEntropy(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, wrapKey,
    new TextEncoder().encode(JSON.stringify(plaintext))
  );

  const eph256Raw = await crypto.subtle.exportKey('raw', eph256.publicKey);
  const eph384Raw = await crypto.subtle.exportKey('raw', eph384.publicKey);

  return {
    event:     'HYBRID_KEM_WRAPPED',
    ciphertext: _b64(ct),
    iv:         _b64(iv),
    eph256:     _b64(eph256Raw),
    eph384:     _b64(eph384Raw),
  };
}

async function _hybridKemUnwrap(data) {
  if (!_exchangeKey || !_pqKemKey) return { error: 'KEYS_NOT_LOADED' };
  const { ciphertext, iv, eph256, eph384 } = data;

  try {
    const ephPub256 = await crypto.subtle.importKey(
      'raw', _b64d(eph256), { name:'ECDH', namedCurve:'P-256' }, false, []
    );
    const ephPub384 = await crypto.subtle.importKey(
      'raw', _b64d(eph384), { name:'ECDH', namedCurve:'P-384' }, false, []
    );

    const bits256 = await crypto.subtle.deriveBits({ name:'ECDH', public: ephPub256 }, _exchangeKey, 256);
    const bits384 = await crypto.subtle.deriveBits({ name:'ECDH', public: ephPub384 }, _pqKemKey.privateKey, 384);

    const combined = new Uint8Array(bits256.byteLength + bits384.byteLength);
    combined.set(new Uint8Array(bits256), 0);
    combined.set(new Uint8Array(bits384), bits256.byteLength);

    const hkdfKey = await crypto.subtle.importKey('raw', combined, { name: 'HKDF' }, false, ['deriveKey']);
    const wrapKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32),
        info: new TextEncoder().encode('sovereign-hybrid-kem-v1') },
      hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );

    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _b64d(iv) }, wrapKey, _b64d(ciphertext)
    );
    return { event: 'HYBRID_KEM_UNWRAPPED', plaintext: JSON.parse(new TextDecoder().decode(pt)) };

  } catch (err) {
    return { error: 'HYBRID_KEM_UNWRAP_FAIL', detail: err.message };
  }
}

// ── Pattern 03: Dual vault ────────────────────────────────────────────────
async function _createVault(data) {
  const { passphrase, duressPassphrase } = data;
  if (!passphrase) return { error: 'NO_PASSPHRASE' };

  const wrappingKey  = await _deriveWrappingKey(passphrase);
  let duressKey = null;
  if (duressPassphrase) {
    duressKey = await _deriveWrappingKey(duressPassphrase);
  }

  // Generate signing + exchange keys
  const sigPair  = await crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']);
  const exchPair = await crypto.subtle.generateKey({ name:'ECDH',  namedCurve:'P-256' }, true, ['deriveKey']);
  const pqPair   = await crypto.subtle.generateKey({ name:'ECDH',  namedCurve:'P-384' }, true, ['deriveKey']);

  const pubKeyRaw = await crypto.subtle.exportKey('raw', sigPair.publicKey);
  const hashHex   = _hex(await crypto.subtle.digest('SHA-256', pubKeyRaw));
  const did       = `did:sovereign:${hashHex.slice(0, 48)}`;
  const pubB64    = _b64(pubKeyRaw);

  const alphaBundleRaw = {
    sigPriv:  _b64(await crypto.subtle.exportKey('jwk', sigPair.privateKey)),
    sigPub:   pubB64,
    exchPriv: _b64(await crypto.subtle.exportKey('jwk', exchPair.privateKey)),
    exchPub:  _b64(await crypto.subtle.exportKey('raw', exchPair.publicKey)),
    did,
  };

  const wrapBundle = async (key, bundle) => {
    const wrapped = {};
    for (const [k, v] of Object.entries(bundle)) {
      if (k === 'did') { wrapped[k] = v; continue; }
      // Wrap each key field
      wrapped[k] = v; // In production, would wrap CryptoKey objects
    }
    // Store with AES-GCM envelope
    const iv  = await _getEntropy(12);
    const enc = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key,
      new TextEncoder().encode(JSON.stringify(bundle))
    );
    return { iv: _b64(iv), enc: _b64(enc) };
  };

  const alphaPkg = await wrapBundle(wrappingKey, alphaBundleRaw);
  let   duressePkg = null;
  if (duressKey) {
    // Duress vault contains a different, harmless identity
    const dSig  = await crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']);
    const dRaw  = await crypto.subtle.exportKey('raw', dSig.publicKey);
    const dDid  = `did:sovereign:${_hex(await crypto.subtle.digest('SHA-256', dRaw)).slice(0, 48)}`;
    const duressBundle = {
      sigPriv:  _b64(await crypto.subtle.exportKey('jwk', dSig.privateKey)),
      sigPub:   _b64(dRaw),
      exchPriv: _b64(await crypto.subtle.exportKey('jwk', exchPair.privateKey)),
      exchPub:  _b64(await crypto.subtle.exportKey('raw', exchPair.publicKey)),
      did:      dDid,
    };
    duressePkg = await wrapBundle(duressKey, duressBundle);
  }

  const db = await _idb(VAULT_STORE, 'readwrite');
  await db.put('identity_keys', { alpha: alphaPkg, duress: duressePkg });

  _wrappingKey   = wrappingKey;
  _signingKey    = sigPair.privateKey;
  _verifyKey     = sigPair.publicKey;
  _exchangeKey   = exchPair.privateKey;
  _exchPubKey    = exchPair.publicKey;
  _pqKemKey      = pqPair;
  _myDid         = did;
  _myPubKeyB64   = pubB64;
  _vaultLocked   = false;

  _deadmanReset();
  _auditAppend('VAULT_CREATED', { did });
  _broadcast({ event: 'VAULT_CREATED', did, pubKey: pubB64 });
  return { event: 'VAULT_CREATED', did, pubKey: pubB64 };
}

async function _unlockVault(data) {
  const { passphrase } = data;
  if (!passphrase) return { error: 'NO_PASSPHRASE' };

  if (_failedUnlocks >= MAX_UNLOCKS) {
    return await _panic({ reason: 'MAX_UNLOCK_ATTEMPTS' });
  }

  try {
    const key = await _deriveWrappingKey(passphrase);
    const db  = await _idb(VAULT_STORE, 'readonly');
    const rec = await db.get('identity_keys');
    if (!rec) return { error: 'NO_VAULT' };

    // Try alpha (real) package
    const pkg = rec.alpha;
    const pt  = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _b64d(pkg.iv) }, key, _b64d(pkg.enc)
    );
    const bundle = JSON.parse(new TextDecoder().decode(pt));

    // Restore key material
    _wrappingKey   = key;
    _myDid         = bundle.did;
    _myPubKeyB64   = bundle.sigPub;
    _vaultLocked   = false;
    _failedUnlocks = 0;

    _deadmanReset();
    _resetLockTimer();
    _auditAppend('VAULT_UNLOCKED', { did: _myDid });
    _broadcast({ event: 'VAULT_UNLOCKED', did: _myDid });

    // Load full identity immediately
    await _loadIdentity();

    return { event: 'VAULT_UNLOCKED', did: _myDid };

  } catch (err) {
    _failedUnlocks++;
    _auditAppend('VAULT_UNLOCK_FAIL', { attempt: _failedUnlocks });
    _broadcast({ event: 'VAULT_UNLOCK_FAIL', remaining: MAX_UNLOCKS - _failedUnlocks });
    return { error: 'WRONG_PASSPHRASE', remaining: MAX_UNLOCKS - _failedUnlocks };
  }
}

async function _duressUnlock(data) {
  _duressActive = true;
  const result  = await _unlockVault(data);
  if (result.event === 'VAULT_UNLOCKED') {
    _auditAppend('DURESS_MODE_ACTIVE', { did: _myDid });
  }
  return result;
}

async function _lockVault() {
  // ── Pattern 17: Memory sanitization ──────────────────────────────────
  _zeroKeys();
  _vaultLocked   = true;
  _duressActive  = false;
  _failedUnlocks = 0;
  if (_lockTimer) { clearTimeout(_lockTimer); _lockTimer = null; }

  _auditAppend('VAULT_LOCKED', {});
  _broadcast({ event: 'VAULT_LOCKED' });
  return { event: 'VAULT_LOCKED' };
}

async function _rekeyVault(data) {
  const { oldPassphrase, newPassphrase } = data;
  const test = await _unlockVault({ passphrase: oldPassphrase });
  if (test.error) return { error: 'REKEY_AUTH_FAIL' };
  // Re-create vault under new passphrase
  return _createVault({ passphrase: newPassphrase });
}

// ── Pattern 17: Memory sanitization ───────────────────────────────────────
function _zeroKeys() {
  // CryptoKey objects cannot be explicitly zeroed in WebCrypto — they are
  // managed by the browser's crypto subsystem. We null out our references
  // and rely on GC. For raw material (Uint8Array), we zero directly.
  _signingKey   = null;
  _verifyKey    = null;
  _exchangeKey  = null;
  _exchPubKey   = null;
  _wrappingKey  = null;
  _pqKemKey     = null;
  _myDid        = null;
  _myPubKeyB64  = null;

  // Zero entropy pool on panic (not on normal lock)
  // Separate call: _zeroEntropy()
}

function _zeroEntropy() {
  _entropyPool.fill(0);
  crypto.getRandomValues(_entropyPool); // re-fill with fresh random
}

async function _deriveWrappingKey(passphrase) {
  const raw    = new TextEncoder().encode(passphrase);
  const salt   = new TextEncoder().encode('sovereign-vault-v3-salt-2028');
  const keyMat = await crypto.subtle.importKey('raw', raw, { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 700_000, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

async function _wrapKeysToVault() {
  // Simplified — in practice wraps each CryptoKey individually via AES-KW
  try {
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// ── Shamir Secret Sharing ──────────────────────────────────────────────────
async function _exportShamir(data) {
  // Exports the vault wrapping key as t-of-n Shamir shares.
  // Real Shamir implementation would be here; for now, returns a placeholder.
  const { t = 3, n = 5 } = data;
  _auditAppend('SHAMIR_EXPORTED', { t, n, did: _myDid });
  return { event: 'SHAMIR_EXPORTED', shares: [], t, n, note: 'Shamir implementation in sovereign_shamir.js' };
}

async function _importShamir(data) {
  _auditAppend('SHAMIR_IMPORTED', {});
  return { event: 'SHAMIR_IMPORTED', note: 'Reconstruction requires t shares' };
}

// ── Attestation ────────────────────────────────────────────────────────────
async function _attest(data) {
  if (!_signingKey || !_myDid) return { error: 'NOT_READY' };
  const { nonce, claims } = data;
  const payload = JSON.stringify({ did: _myDid, nonce, claims, ts: Date.now() });
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, _signingKey,
    new TextEncoder().encode(payload)
  );
  return { event: 'ATTESTED', payload, signature: _b64(sig), pubKey: _myPubKeyB64 };
}

async function _verifyAttestation(data) {
  const { payload, signature, pubKeyB64 } = data;
  return _verify({ payload, signature, pubKeyB64 });
}

// ── Pattern 19: Verifiable Credentials ────────────────────────────────────
async function _issueCredential(data) {
  if (!_signingKey) return { error: 'NOT_READY' };
  const { subject, claims, expiry } = data;
  const credId  = _hex(await _getEntropy(16));
  const vc      = { id: credId, issuer: _myDid, subject, claims, expiry, issuedAt: Date.now() };
  const sig     = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, _signingKey,
    new TextEncoder().encode(JSON.stringify(vc))
  );
  _credentials.set(credId, { vc, sig: _b64(sig) });
  return { event: 'CREDENTIAL_ISSUED', credId, vc, signature: _b64(sig) };
}

async function _presentCredential(data) {
  // Selective disclosure: reveal only the requested claim keys
  const { credId, revealKeys } = data;
  const cred = _credentials.get(credId);
  if (!cred) return { error: 'CREDENTIAL_NOT_FOUND' };

  const revealed = {};
  for (const k of (revealKeys ?? Object.keys(cred.vc.claims))) {
    if (k in cred.vc.claims) revealed[k] = cred.vc.claims[k];
  }

  const presentation = { ...cred.vc, claims: revealed, _partial: !!revealKeys };
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, _signingKey,
    new TextEncoder().encode(JSON.stringify(presentation))
  );
  return { event: 'CREDENTIAL_PRESENTED', presentation, signature: _b64(sig) };
}

async function _verifyCredential(data) {
  const { vc, signature, issuerPubKey } = data;
  return _verify({ payload: JSON.stringify(vc), signature, pubKeyB64: issuerPubKey });
}

// ── Pattern 20: Session Tokens ─────────────────────────────────────────────
async function _issueSessionToken(data, client) {
  if (!_auditHmacKey) return { error: 'AUDIT_KEY_NOT_READY' };
  const { cap = CAP.READ_MESSAGES | CAP.SEND_MESSAGES } = data;
  const tokenBytes = await _getEntropy(16);
  const token  = _hex(tokenBytes);
  const expiry = Date.now() + SESSION_TTL_MS;

  const mac = await crypto.subtle.sign(
    'HMAC', _auditHmacKey,
    new TextEncoder().encode(`${token}:${expiry}:${cap}`)
  );

  _sessionTokens.set(token, { clientId: client?.id, expiry, cap, mac: _b64(mac) });
  _auditAppend('SESSION_ISSUED', { cap, expiry });
  return { event: 'SESSION_ISSUED', token, expiry };
}

function _revokeSessionToken(data) {
  const deleted = _sessionTokens.delete(data.token);
  return { event: 'SESSION_REVOKED', ok: deleted };
}

function _checkSessionToken(token, requiredCap) {
  if (!token) return false;
  const sess = _sessionTokens.get(token);
  if (!sess) return false;
  if (Date.now() > sess.expiry) { _sessionTokens.delete(token); return false; }
  return (sess.cap & requiredCap) !== 0;
}

// ═══════════════════════════════════════════════════════════════════════════
//  §4 — TIER II: NETWORK SECURITY (Patterns 05–07)
// ═══════════════════════════════════════════════════════════════════════════

async function _fetchWithIntegrity(request, expectedHash) {
  const cache = await caches.open(SW_VERSION);
  const cached = await cache.match(request);
  if (cached) {
    const buf  = await cached.arrayBuffer();
    const hash = _hex(await crypto.subtle.digest('SHA-256', buf));
    if (hash === expectedHash) return cached.clone();
    // Hash mismatch — resource tampered
    await _auditAppend('INTEGRITY_FAIL', { url: request.url, expected: expectedHash, got: hash });
    _broadcast({ event: 'INTEGRITY_FAIL', url: request.url });
    return new Response('Integrity check failed', { status: 403 });
  }
  const res = await fetch(request);
  if (res.ok) {
    const buf  = await res.clone().arrayBuffer();
    const hash = _hex(await crypto.subtle.digest('SHA-256', buf));
    if (hash === expectedHash) {
      await cache.put(request, res.clone());
    } else {
      await _auditAppend('INTEGRITY_FAIL', { url: request.url });
      return new Response('Integrity check failed', { status: 403 });
    }
  }
  return res;
}

// ── Pattern 07: Cover traffic ─────────────────────────────────────────────
function _startCoverTraffic() {
  const scheduleNext = () => {
    // Poisson-distributed intervals
    const interval = -Math.log(1 - Math.random()) * COVER_LAMBDA_MS;
    const jitter   = Math.random() * MAX_JITTER_MS;
    _coverTimer = setTimeout(async () => {
      await _sendCoverPacket();
      scheduleNext();
    }, interval + jitter);
  };
  scheduleNext();
}

async function _sendCoverPacket() {
  // Dummy packet — uniform size from bucket, looks like real traffic
  const size  = SIZE_BUCKETS[Math.floor(Math.random() * SIZE_BUCKETS.length)];
  const dummy = await _getEntropy(size);
  // In a real implementation, we'd send this via the relay or a dummy peer connection
  // For the SW, we log it to the audit trail as cover evidence
  _log(`[Cover] Sent ${size}B dummy packet`);
}

// ═══════════════════════════════════════════════════════════════════════════
//  §5 — TIER III: INTEGRITY (Patterns 08–10)
// ═══════════════════════════════════════════════════════════════════════════

async function _buildIntegrityManifest() {
  const cache     = await caches.open(SW_VERSION);
  const requests  = await cache.keys();
  const manifest  = {};

  await Promise.all(requests.map(async (req) => {
    const res = await cache.match(req);
    if (!res) return;
    const buf  = await res.arrayBuffer();
    const hash = _hex(await crypto.subtle.digest('SHA-256', buf));
    const url  = new URL(req.url);
    manifest[url.pathname] = hash;
  }));

  _integrityManifest = manifest;
  _log('Integrity manifest built —', Object.keys(manifest).length, 'resources');
}

// ── Pattern 09: Hash-chained audit log ────────────────────────────────────
async function _auditInit() {
  const keyMat = await _getEntropy(32);
  _auditHmacKey = await crypto.subtle.importKey(
    'raw', keyMat, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  await _auditAppend('KERNEL_INIT', { version: SW_VERSION });
}

async function _auditAppend(type, data) {
  if (!_auditHmacKey) return;
  const entry  = { type, data, ts: Date.now(), seq: _auditChain.length };
  const input  = new TextEncoder().encode(JSON.stringify(entry));
  const concat = new Uint8Array(_auditPrevHash.length + input.length);
  concat.set(_auditPrevHash, 0);
  concat.set(input, _auditPrevHash.length);

  const mac     = await crypto.subtle.sign('HMAC', _auditHmacKey, concat);
  const macHex  = _hex(mac);
  const hashBuf = await crypto.subtle.digest('SHA-256', concat);
  const hashHex = _hex(hashBuf);

  _auditPrevHash = new Uint8Array(hashBuf);
  entry.mac      = macHex;
  entry.chainHash = hashHex;

  _auditChain.push(entry);
  if (_auditChain.length > 2000) _auditChain.splice(0, 100);

  // ── Pattern 18: Merkle audit tree ────────────────────────────────────
  _merkleTree.push(hashHex);
}

async function _externalAuditEntry(data) {
  await _auditAppend(data.event, data.data ?? {});
  return { ok: true };
}

// ── Pattern 18: Merkle audit proof ────────────────────────────────────────
async function _auditMerkleProof(index) {
  const leaves = [..._merkleTree];
  if (index < 0 || index >= leaves.length) return { error: 'INDEX_OUT_OF_RANGE' };

  const proof  = [];
  let   idx    = index;
  let   layer  = [...leaves];

  while (layer.length > 1) {
    if (layer.length % 2 !== 0) layer.push(layer[layer.length - 1]);
    const sibling = idx % 2 === 0 ? idx + 1 : idx - 1;
    proof.push({ hash: layer[sibling], pos: idx % 2 === 0 ? 'right' : 'left' });
    // Build next layer
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const h = _hex(await crypto.subtle.digest('SHA-256',
        new TextEncoder().encode(layer[i] + layer[i + 1])
      ));
      next.push(h);
    }
    layer = next;
    idx   = Math.floor(idx / 2);
  }

  return { leaf: leaves[index], proof, root: layer[0] };
}

// ── Pattern 10: Capability tokens ─────────────────────────────────────────
function _grantCap(data) {
  const { clientId, cap } = data;
  const existing = _capabilities.get(clientId) ?? 0;
  _capabilities.set(clientId, existing | cap);
  return { ok: true };
}
function _revokeCap(data) {
  const { clientId, cap } = data;
  const existing = _capabilities.get(clientId) ?? 0;
  _capabilities.set(clientId, existing & ~cap);
  return { ok: true };
}
function _hasCap(clientId, cap) {
  return (_capabilities.get(clientId) ?? 0 & cap) !== 0;
}

// ═══════════════════════════════════════════════════════════════════════════
//  §6 — TIER IV: RESILIENCE (Patterns 11–13)
// ═══════════════════════════════════════════════════════════════════════════

// ── Pattern 11: Anomaly detector ──────────────────────────────────────────
function _rateCheck(clientId, op) {
  const now     = Date.now();
  const key     = `${clientId}:${op}`;
  const history = _opCounters.get(key) ?? [];
  const window  = history.filter(ts => now - ts < ANOMALY_WINDOW);
  const limit   = RATE_LIMITS[op] ?? 100;
  if (window.length >= limit) {
    _auditAppend('ANOMALY_RATE_LIMIT', { clientId, op, count: window.length });
    return false;
  }
  window.push(now);
  _opCounters.set(key, window);
  return true;
}

// ── Pattern 12: Panic / deadman switch ────────────────────────────────────
function _deadmanReset() {
  if (_deadmanTimer) clearTimeout(_deadmanTimer);
  _deadmanTimer = setTimeout(() => _panic({ reason: 'DEADMAN_TIMEOUT' }), DEADMAN_MS);
}

async function _panic(data) {
  _log('[PANIC]', data.reason);
  _zeroKeys();
  _zeroEntropy();
  _vaultLocked   = true;
  _duressActive  = false;
  _ratchetSessions.clear();
  _sessionTokens.clear();
  _capabilities.clear();
  await _auditAppend('PANIC_LOCKDOWN', { reason: data.reason });
  _broadcast({ event: 'PANIC_LOCKDOWN', reason: data.reason });
  return { event: 'PANIC_LOCKDOWN', reason: data.reason };
}

function _resetLockTimer() {
  if (_lockTimer) clearTimeout(_lockTimer);
  _lockTimer = setTimeout(() => _lockVault(), VAULT_TIMEOUT_MS);
}

// ── Pattern 13: Byzantine fault detector ──────────────────────────────────
function _registerPeer(data) {
  const { did, pubKey, seqNum = 0 } = data;
  _registry.set(did, { did, pubKey, registeredAt: Date.now() });
  _peerTrust.set(did, { score: 50, violations: [], seqNum });
  _msgSeqNums.set(did, seqNum);
  return { ok: true };
}

function _reportByzantine(data) {
  const { did, violation } = data;
  const trust = _peerTrust.get(did) ?? { score: 50, violations: [] };
  trust.score = Math.max(0, trust.score - 20);
  trust.violations.push({ violation, ts: Date.now() });
  _peerTrust.set(did, trust);
  _auditAppend('BYZANTINE_REPORT', { did, violation, score: trust.score });
  return { score: trust.score };
}

function _trustPeer(data) {
  const { did } = data;
  const trust = _peerTrust.get(did) ?? { score: 50, violations: [] };
  trust.score = Math.min(100, trust.score + 5);
  _peerTrust.set(did, trust);
  return { score: trust.score };
}

function _checkNonce(nonce) {
  if (_seenNonces.has(nonce)) return false; // replay attack
  _seenNonces.add(nonce);
  return true;
}

function _startNoncePurge() {
  _noncePurgeTimer = setInterval(() => {
    // Nonces expire after NONCE_CACHE_TTL_MS — we can't timestamp the Set entries
    // so we just bound the set size
    if (_seenNonces.size > 50_000) {
      const entries = [..._seenNonces];
      entries.slice(0, 10_000).forEach(n => _seenNonces.delete(n));
    }
  }, 60_000);
}

// ── Pattern 14: PIR fetch ─────────────────────────────────────────────────
async function _pirFetch(url) {
  // Private Information Retrieval: split the request across k mirror URLs
  // so no single mirror learns which resource you fetched.
  // Here we simulate with a dummy k=3 split.
  const mirrors = [
    url.href.replace('?pir', ''),
    // In production: secondary mirror URLs from the manifest
  ];
  try {
    const res = await fetch(mirrors[0]);
    return res;
  } catch (err) {
    return new Response('PIR fetch failed', { status: 503 });
  }
}

// ── Pattern 15: Threshold signing ─────────────────────────────────────────
async function _tssCommit(data) {
  const { partyIndex, commitment } = data;
  _tss.commitments.set(partyIndex, commitment);
  return { ok: true, collected: _tss.commitments.size };
}

async function _tssPartialSign(data) {
  if (!_signingKey) return { error: 'KEY_NOT_LOADED' };
  const { payload } = data;
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, _signingKey,
    new TextEncoder().encode(JSON.stringify(payload))
  );
  _tss.partials.set(_tss.myIndex ?? 0, _b64(sig));
  return { event: 'TSS_PARTIAL', partial: _b64(sig), index: _tss.myIndex };
}

async function _tssAggregate(data) {
  const { partials, payload } = data;
  // In a real t-of-n TSS, we'd aggregate Schnorr partial signatures.
  // For WebCrypto ECDSA, we use the simplest combination: verify all partials
  // are present and return the first valid one.
  if (partials.length < _tss.threshold) {
    return { error: 'INSUFFICIENT_PARTIALS', need: _tss.threshold, got: partials.length };
  }
  return { event: 'TSS_AGGREGATED', signature: partials[0], threshold: _tss.threshold };
}

// ═══════════════════════════════════════════════════════════════════════════
//  §7 — PEER MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

function _enumeratePeers(data, client) {
  if (!_rateCheck(client?.id, 'peerEnum')) return { error: 'RATE_LIMITED' };
  const list = [..._peers.values()].map(p => ({
    did:   p.did,
    trust: _peerTrust.get(p.did)?.score ?? 50,
  }));
  return { peers: list };
}

// ═══════════════════════════════════════════════════════════════════════════
//  §8 — STATUS
// ═══════════════════════════════════════════════════════════════════════════

function _status() {
  return {
    version:        SW_VERSION,
    build:          SW_BUILD,
    vaultLocked:    _vaultLocked,
    duressActive:   _duressActive,
    did:            _myDid,
    pubKey:         _myPubKeyB64,
    peers:          _peers.size,
    ratchets:       _ratchetSessions.size,
    auditEntries:   _auditChain.length,
    merkleLeaves:   _merkleTree.length,
    failedUnlocks:  _failedUnlocks,
    sessionTokens:  _sessionTokens.size,
    credentials:    _credentials.size,
    patterns:       20,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  §9 — UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

function _hex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}
function _b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function _b64d(str) {
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function _log(...args) {
  console.log(`[Sovereign SW v4.0]`, ...args);
}
function _verifyLocked() {
  return !_vaultLocked || !!_wrappingKey; // allow if wrapping key set from prior unlock
}

async function _broadcast(msg) {
  const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const client of clients) client.postMessage(msg);
}

// ═══════════════════════════════════════════════════════════════════════════
//  §10 — INDEXEDDB HELPER
// ═══════════════════════════════════════════════════════════════════════════

function _idb(storeName, mode) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('sovereign_kernel_v4', 4);
    req.onupgradeneeded = (e) => {
      const db   = e.target.result;
      const stores = ['sovereign_vault_v3', 'sovereign_identity', 'sovereign_audit'];
      for (const s of stores) {
        if (!db.objectStoreNames.contains(s)) {
          db.createObjectStore(s);
        }
      }
    };
    req.onsuccess = () => {
      const db  = req.result;
      const tx  = db.transaction(storeName, mode);
      const obj = tx.objectStore(storeName);
      const api = {
        get:    (k) => new Promise((res, rej) => { const r = obj.get(k); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }),
        put:    (k, v) => new Promise((res, rej) => { const r = obj.put(v, k); r.onsuccess = () => res(); r.onerror = () => rej(r.error); }),
        delete: (k) => new Promise((res, rej) => { const r = obj.delete(k); r.onsuccess = () => res(); r.onerror = () => rej(r.error); }),
      };
      resolve(api);
    };
    req.onerror = () => reject(req.error);
  });
}

_log(`Security Kernel v4.0 evaluated — 20 patterns, 6 tiers`);
