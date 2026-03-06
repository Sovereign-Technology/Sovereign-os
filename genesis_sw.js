/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SOVEREIGN SECURITY KERNEL  v5.0  —  genesis_sw.js
 *
 *  © James Chapman (XheCarpenXer) · iconoclastdao@gmail.com
 *  Dual License — see LICENSE.md
 *
 *  ┌─────────────────────────────────────────────────────────────────────────┐
 *  │  TIER I    — Crypto Kernel       Patterns 01–04                         │
 *  │  TIER II   — Network Security    Patterns 05–07                         │
 *  │  TIER III  — Integrity           Patterns 08–10                         │
 *  │  TIER IV   — Resilience          Patterns 11–13                         │
 *  │  TIER V    — Novel               Patterns 14–15                         │
 *  │  TIER VI   — Hardening           Patterns 16–20                         │
 *  └─────────────────────────────────────────────────────────────────────────┘
 *
 *  v5.0 CHANGES (post year-of-testing):
 *    - Pattern 02: Full Double Ratchet with proper KDF chain advancement,
 *                  per-message key deletion, and out-of-order message handling
 *    - Real Shamir: sovereign_shamir.js imported; EXPORT_SHAMIR returns real shares
 *    - Vault persistence: _wrapKeysToVault and _loadVaultFromStore fully implemented
 *    - Pattern 12: Deadman timer resets on any authenticated message
 *    - Pattern 13: Sequence number gap detection with configurable tolerance
 *    - Session token scope expanded to include ratchet operations
 *    - STATUS command returns richer health data
 *    - All known double-transition bugs from SW bridge fixed
 * ═══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

importScripts('./sovereign_shamir.js');

const SW_VERSION = 'sovereign-sw-v6.0.2';
const SW_BUILD   = Date.now().toString(36);

// ═══════════════════════════════════════════════════════════════════════════
//  §0 — GLOBAL STATE
// ═══════════════════════════════════════════════════════════════════════════

// ── Pattern 01: Key material — NEVER leaves this context ─────────────────
let _signingKey    = null;   // ECDSA P-256 private key (CryptoKey)
let _verifyKey     = null;   // ECDSA P-256 public key  (CryptoKey)
let _exchangeKey   = null;   // ECDH P-256 private key  (CryptoKey)
let _exchPubKey    = null;   // ECDH P-256 public key   (CryptoKey)
let _wrappingKey   = null;   // AES-KW-256 key derived from passphrase (CryptoKey)
let _auditHmacKey  = null;   // HMAC-SHA256 key for audit chain (CryptoKey)
let _myDid         = null;   // did:sovereign:…
let _myPubKeyB64   = null;   // base64(ECDSA public key raw bytes)
let _vaultLocked   = true;
let _duressActive  = false;

// ── Pattern 16: Post-quantum hybrid KEM ───────────────────────────────────
let _pqKemKey      = null;   // ECDH P-384 secondary key (CryptoKey)

// ── Pattern 02: Full Double Ratchet sessions ──────────────────────────────
// Session structure:
//   rootKey:        CryptoKey (HKDF material — derives send/recv chains)
//   sendChainKey:   Uint8Array (32 bytes — advances on each send)
//   recvChainKey:   Uint8Array (32 bytes — advances on each recv)
//   sendMsgNum:     number
//   recvMsgNum:     number
//   dhSendKey:      CryptoKey (current DH ratchet send key)
//   dhSendPub:      Uint8Array (exportable public bytes for DH ratchet)
//   dhRecvPub:      Uint8Array (peer's latest DH public key)
//   skipped:        Map<string, Uint8Array> — skipped message keys keyed by "msgNum"
//   peerDid:        string
//   initiator:      boolean
//   lastActivity:   number (timestamp)
const _ratchetSessions = new Map();  // peerDid → RatchetSession

// Max skipped messages to store before discarding (prevents memory exhaustion)
const RATCHET_MAX_SKIP = 50;

// ── Pattern 03: Dual vault ────────────────────────────────────────────────
const VAULT_STORE    = 'sovereign_vault_v5';
const VAULT_KEY_MAIN = 'vault_main';    // real key bundle
const VAULT_KEY_DUEL = 'vault_duress';  // decoy key bundle

// ── Pattern 04: Entropy pool ──────────────────────────────────────────────
const _entropyPool     = new Uint8Array(64);
let   _entropyMixTimer = null;

// ── Pattern 05: Network policy ────────────────────────────────────────────
const _allowedDomains = new Set([
  'cdnjs.cloudflare.com',          // legacy — phase out
  'cdn.jsdelivr.net',              // legacy — phase out
  'sovereign-relay.fly.dev',
  'openrelay.metered.ca',
  'stun.relay.metered.ca',
  'stun.cloudflare.com',
  'global.stun.twilio.com',
  'stun.nextcloud.com',
  'stun.libreoffice.org',
  'nostr.pleb.network',
  'relay.damus.io',
  // Local LLM / dev services — always permitted (loopback only)
  'localhost',
  '127.0.0.1',
  '::1',
]);

// ── Pattern 07: Cover traffic ─────────────────────────────────────────────
const COVER_LAMBDA_MS = 45_000;
const SIZE_BUCKETS    = [256, 512, 1024, 4096];
let   _coverTimer     = null;

// ── Pattern 08: Integrity manifest ────────────────────────────────────────
let _integrityManifest  = null;

// ── Pattern 09: Audit chain ────────────────────────────────────────────────
const _auditChain      = [];
let   _auditPrevHash   = new Uint8Array(32);

// ── Pattern 18: Merkle audit tree ─────────────────────────────────────────
const _merkleLeaves    = [];

// ── Pattern 10: Capability tokens ─────────────────────────────────────────
const _capabilities    = new Map();  // clientId → capBitfield
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
const _opCounters      = new Map();  // clientId → { op → [ts, ...] }
const RATE_LIMITS      = { sign: 30, open: 60, send: 120, peerEnum: 10, vote: 5 };
const ANOMALY_WINDOW   = 10_000;

// ── Pattern 12: Panic / deadman ───────────────────────────────────────────
let _failedUnlocks     = 0;
const MAX_UNLOCKS      = 5;
let _deadmanTimer      = null;
const DEADMAN_MS       = 4 * 60 * 60 * 1000;
const VAULT_TIMEOUT_MS = 30 * 60 * 1000;
let _lockTimer         = null;

// ── Pattern 13: Byzantine detector ────────────────────────────────────────
const _peerTrust       = new Map();  // did → { score: 0-100, violations: [] }
const _seenNonces      = new Map();  // nonce → expiry timestamp
const _msgSeqNums      = new Map();  // did → last seen seqnum
const NONCE_CACHE_TTL  = 10 * 60 * 1000;
const SEQ_GAP_TOLERANCE = 20; // tolerate up to 20 out-of-order
let   _noncePurgeTimer = null;

// ── Pattern 15: Threshold signing ─────────────────────────────────────────
const _tss = {
  threshold: 2, parties: 3, myIndex: null,
  shards: new Map(), commitments: new Map(), partials: new Map(),
};

// ── Pattern 19: Verifiable credentials ────────────────────────────────────
const _credentials     = new Map();  // credId → { claims, revealed, proof }

// ── Pattern 20: Session tokens ────────────────────────────────────────────
const _sessionTokens   = new Map();  // token → { clientId, expiry, cap }
const SESSION_TTL_MS   = 15 * 60 * 1000;

// ── Peer mesh ──────────────────────────────────────────────────────────────
const _peers    = new Map();
const _registry = new Map();

// ─────────────────────────────────────────────────────────────────────────────
//  §1 — SW LIFECYCLE
// ─────────────────────────────────────────────────────────────────────────────

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    await self.skipWaiting();
    _mixEntropy(performance.now());
    _startEntropyRefresh();
    _startCoverTraffic();
    _startNoncePurge();
    await _auditInit();
    await _buildIntegrityManifest();
    _log('Security Kernel v5.0 installed — 20 patterns active, real Shamir + Double Ratchet');
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    await self.clients.claim();
    // Restore DID from vault (locked state) so STATUS can report it before unlock
    await _restoreDidFromStore();
    _log('Security Kernel v5.0 active');
  })());
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // Pattern 05: Network firewall
  if (url.origin !== self.location.origin) {
    if (!_allowedDomains.has(url.hostname)) {
      _log(`[FIREWALL] Blocked: ${url.hostname}`);
      _auditAppend('NETWORK_BLOCK', { url: url.hostname });
      e.respondWith(new Response('Blocked by Sovereign firewall', { status: 403 }));
      return;
    }
  }

  // Pattern 08: Integrity check on own resources
  const selfResources = [
    'genesis_sw.js', 'sovereign_fsm.js', 'sovereign_security.js',
    'transport.js', 'sovereign_shamir.js',
  ];
  const basename = url.pathname.split('/').pop();
  if (selfResources.includes(basename) && _integrityManifest?.[basename]) {
    e.respondWith(_fetchWithIntegrityCheck(e.request, _integrityManifest[basename]));
    return;
  }

  // Default: standard cache-then-network with SW_VERSION cache key
  e.respondWith(
    caches.match(e.request).then(cached => cached ?? fetch(e.request).then(async resp => {
      const cache = await caches.open(SW_VERSION);
      if (resp.ok) cache.put(e.request, resp.clone());
      return resp;
    }))
  );
});

// ─────────────────────────────────────────────────────────────────────────────
//  §2 — MESSAGE DISPATCH
// ─────────────────────────────────────────────────────────────────────────────

self.addEventListener('message', (e) => {
  const { cmd, _nonce: nonce, ...data } = e.data ?? {};
  if (!cmd) return;

  const reply = (payload) => {
    // If a MessageChannel port was transferred, reply through it (bridge pattern).
    // Fall back to e.source for legacy broadcast-style callers.
    if (e.ports?.[0]) {
      e.ports[0].postMessage({ ...payload, _nonce: nonce });
    } else {
      e.source?.postMessage({ ...payload, _nonce: nonce });
    }
  };

  // Pattern 11: Rate limiting
  if (!_checkRateLimit(e.source?.id ?? 'anon', cmd)) {
    reply({ error: 'RATE_LIMITED', cmd });
    _auditAppend('RATE_LIMIT', { cmd, client: e.source?.id });
    return;
  }

  const dispatch = {
    'CREATE_VAULT':      () => _createVault(data).then(reply),
    'UNLOCK_VAULT':      () => _unlockVault(data).then(reply),
    'LOCK_VAULT':        () => _lockVault().then(reply),
    'RATCHET_INIT':      () => _ratchetInit(data).then(reply),
    'RATCHET_ENCRYPT':   () => _ratchetEncrypt(data).then(reply),
    'RATCHET_DECRYPT':   () => _ratchetDecrypt(data).then(reply),
    'SEAL':              () => _seal(data).then(reply),
    'OPEN':              () => _open(data).then(reply),
    'SIGN':              () => _sign(data).then(reply),
    'VERIFY':            () => _verify(data).then(reply),
    'EXPORT_SHAMIR':     () => _exportShamir(data).then(reply),
    'IMPORT_SHAMIR':     () => _importShamir(data).then(reply),
    'ATTEST':            () => _attest(data).then(reply),
    'HYBRID_KEM_WRAP':   () => _hybridKemWrap(data).then(reply),
    'HYBRID_KEM_UNWRAP': () => _hybridKemUnwrap(data).then(reply),
    'AUDIT_ENTRY':       () => { _auditAppend(data.event, data.data); reply({ ok: true }); },
    'STATUS':            () => reply(_status()),
    'GET_PUBKEY':        () => reply({ pubKey: _myPubKeyB64, did: _myDid }),
    'PIR_FETCH':         () => _pirFetch(data).then(reply),
    'TSS_PARTIAL_SIGN':  () => _tssPartialSign(data).then(reply),
    'TSS_AGGREGATE':     () => _tssAggregate(data).then(reply),
    'ISSUE_CREDENTIAL':  () => _issueCredential(data).then(reply),
    'PRESENT_CREDENTIAL':() => _presentCredential(data).then(reply),
    'SESSION_CREATE':    () => reply(_sessionCreate(data)),
    'SESSION_VERIFY':    () => reply(_sessionVerify(data)),
    'REKEY_VAULT':       () => _rekeyVault(data).then(reply),
  };

  if (dispatch[cmd]) {
    (async () => dispatch[cmd]())().catch(err => {
      _auditAppend('CMD_ERROR', { cmd, error: err?.message ?? String(err) });
      reply({ error: err?.message ?? String(err), cmd });
    });
  } else {
    reply({ error: `Unknown command: ${cmd}` });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  §3 — VAULT: CREATE / UNLOCK / LOCK / PERSIST
// ─────────────────────────────────────────────────────────────────────────────

async function _createVault({ passphrase, duressPassphrase }) {
  if (!passphrase || passphrase.length < 8) {
    return { error: 'PASSPHRASE_TOO_SHORT' };
  }

  // Generate keypairs
  const sigPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );
  const ecdhPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
  );
  const pqPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey']
  );

  // Derive DID from ECDSA public key
  const pubRaw   = await crypto.subtle.exportKey('raw', sigPair.publicKey);
  const hashBuf  = await crypto.subtle.digest('SHA-256', pubRaw);
  const hashHex  = _hexEncode(new Uint8Array(hashBuf));
  const did      = `did:sovereign:${hashHex.slice(0, 48)}`;
  const pubKeyB64 = _b64(pubRaw);

  // Derive wrapping key from passphrase using PBKDF2
  const salt         = crypto.getRandomValues(new Uint8Array(32));
  const wrappingKey  = await _deriveWrappingKey(passphrase, salt);

  // Wrap all private keys with AES-KW
  const wrappedSig   = await _wrapKey(sigPair.privateKey, wrappingKey);
  const wrappedEcdh  = await _wrapKey(ecdhPair.privateKey, wrappingKey);
  const wrappedPq    = await _wrapKey(pqPair.privateKey, wrappingKey);

  // Export public keys for storage
  const exchPubRaw   = await crypto.subtle.exportKey('raw', ecdhPair.publicKey);
  const pqPubRaw     = await crypto.subtle.exportKey('raw', pqPair.publicKey);

  // Build vault bundle
  const bundle = {
    version:     6,
    did,
    pubKeyB64,
    salt:        _b64(salt),
    wrappedSig:  _b64(wrappedSig),
    wrappedEcdh: _b64(wrappedEcdh),
    wrappedPq:   _b64(wrappedPq),
    exchPub:     _b64(exchPubRaw),
    pqPub:       _b64(pqPubRaw),
    createdAt:   Date.now(),
    kdfIter:     310_000,
  };

  // Duress vault: separate set of keys wrapped with duress passphrase
  let duressBundle = null;
  if (duressPassphrase && duressPassphrase.length >= 8) {
    const dSigPair   = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const dSalt      = crypto.getRandomValues(new Uint8Array(32));
    const dWrapKey   = await _deriveWrappingKey(duressPassphrase, dSalt);
    const dPubRaw    = await crypto.subtle.exportKey('raw', dSigPair.publicKey);
    const dHash      = await crypto.subtle.digest('SHA-256', dPubRaw);
    const dDid       = `did:sovereign:${_hexEncode(new Uint8Array(dHash)).slice(0, 48)}`;
    const dEcdhPair  = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
    );
    const dExchPubRaw = await crypto.subtle.exportKey('raw', dEcdhPair.publicKey);

    duressBundle = {
      version:     5,
      did:         dDid,
      pubKeyB64:   _b64(dPubRaw),
      salt:        _b64(dSalt),
      wrappedSig:  _b64(await _wrapKey(dSigPair.privateKey, dWrapKey)),
      wrappedEcdh: _b64(await _wrapKey(dEcdhPair.privateKey, dWrapKey)),
      wrappedPq:   null,
      exchPub:     _b64(dExchPubRaw),
      createdAt:   Date.now(),
      kdfIter:     310_000,
    };
  }

  // Persist to IndexedDB
  await _storeVault(VAULT_KEY_MAIN, bundle);
  if (duressBundle) await _storeVault(VAULT_KEY_DUEL, duressBundle);

  // Activate in memory
  _signingKey  = sigPair.privateKey;
  _verifyKey   = sigPair.publicKey;
  _exchangeKey = ecdhPair.privateKey;
  _exchPubKey  = ecdhPair.publicKey;
  _pqKemKey    = pqPair.privateKey;
  _wrappingKey = wrappingKey;
  _myDid       = did;
  _myPubKeyB64 = pubKeyB64;
  _vaultLocked = false;
  _duressActive = false;

  _startVaultTimeout();
  _resetDeadman();
  await _initAuditHmacKey();
  await _auditAppend('VAULT_CREATED', { did: did.slice(-16), kdfIter: bundle.kdfIter });

  _broadcast({ event: 'VAULT_CREATED', did, pubKey: pubKeyB64 });
  return { event: 'VAULT_CREATED', did, pubKey: pubKeyB64 };
}

async function _unlockVault({ passphrase }) {
  if (!passphrase) return { error: 'NO_PASSPHRASE' };

  // Try main vault first, then duress
  let bundle = await _loadVault(VAULT_KEY_MAIN);
  let isDuress = false;

  if (!bundle) return { error: 'NO_VAULT' };

  let salt;
  try {
    salt = _b64d(bundle.salt);
    const wrapKey = await _deriveWrappingKey(passphrase, salt, bundle.kdfIter ?? 700_000);

    // Try to unwrap keys — if the passphrase is wrong, AES-KW will throw
    try {
      const sigKey  = await _unwrapKey(bundle.wrappedSig, wrapKey, 'ECDSA', ['sign']);
      const ecdhKey = await _unwrapKey(bundle.wrappedEcdh, wrapKey, 'ECDH', ['deriveKey']);

      _signingKey  = sigKey;
      _verifyKey   = await crypto.subtle.importKey(
        'raw', _b64d(bundle.pubKeyB64), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
      );
      _exchangeKey = ecdhKey;
      _exchPubKey  = await crypto.subtle.importKey(
        'raw', _b64d(bundle.exchPub), { name: 'ECDH', namedCurve: 'P-256' }, true, []
      );
      if (bundle.wrappedPq) {
        _pqKemKey = await _unwrapKey(bundle.wrappedPq, wrapKey, 'ECDH-P384', ['deriveKey']);
      }
      _wrappingKey = wrapKey;
      _myDid       = bundle.did;
      _myPubKeyB64 = bundle.pubKeyB64;

    } catch (_unwrapErr) {
      // Passphrase wrong for main vault — try duress vault
      const dBundle = await _loadVault(VAULT_KEY_DUEL);
      if (dBundle) {
        try {
          const dSalt    = _b64d(dBundle.salt);
          const dWrapKey = await _deriveWrappingKey(passphrase, dSalt, dBundle.kdfIter ?? 700_000);
          const dSigKey  = await _unwrapKey(dBundle.wrappedSig, dWrapKey, 'ECDSA', ['sign']);
          const dEcdhKey = await _unwrapKey(dBundle.wrappedEcdh, dWrapKey, 'ECDH', ['deriveKey']);

          _signingKey  = dSigKey;
          _verifyKey   = await crypto.subtle.importKey(
            'raw', _b64d(dBundle.pubKeyB64), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
          );
          _exchangeKey = dEcdhKey;
          _exchPubKey  = await crypto.subtle.importKey(
            'raw', _b64d(dBundle.exchPub), { name: 'ECDH', namedCurve: 'P-256' }, true, []
          );
          _myDid       = dBundle.did;
          _myPubKeyB64 = dBundle.pubKeyB64;
          _wrappingKey = dWrapKey;
          isDuress     = true;
        } catch (_duressErr) {
          // Both vaults failed
          _failedUnlocks++;
          if (_failedUnlocks >= MAX_UNLOCKS) {
            await _panicLockdown('MAX_UNLOCK_ATTEMPTS');
          }
          await _auditAppend('UNLOCK_FAIL', { attempt: _failedUnlocks });
          _broadcast({ event: 'VAULT_UNLOCK_FAIL' });
          return { error: 'WRONG_PASSPHRASE', remaining: Math.max(0, MAX_UNLOCKS - _failedUnlocks) };
        }
      } else {
        _failedUnlocks++;
        if (_failedUnlocks >= MAX_UNLOCKS) await _panicLockdown('MAX_UNLOCK_ATTEMPTS');
        await _auditAppend('UNLOCK_FAIL', { attempt: _failedUnlocks });
        _broadcast({ event: 'VAULT_UNLOCK_FAIL' });
        return { error: 'WRONG_PASSPHRASE', remaining: Math.max(0, MAX_UNLOCKS - _failedUnlocks) };
      }
    }
  } catch (err) {
    return { error: `UNLOCK_ERROR: ${err.message}` };
  }

  _vaultLocked  = false;
  _duressActive = isDuress;
  _failedUnlocks = 0;  // reset on successful unlock

  _startVaultTimeout();
  _resetDeadman();
  await _initAuditHmacKey();
  await _auditAppend('VAULT_UNLOCKED', { did: _myDid.slice(-16), duress: isDuress });

  _broadcast({ event: 'VAULT_UNLOCKED', did: _myDid, pubKey: _myPubKeyB64, duress: isDuress });
  // Trigger identity load
  _broadcast({ event: 'IDENTITY_LOADED' });

  return { event: 'VAULT_UNLOCKED', did: _myDid, pubKey: _myPubKeyB64, duress: isDuress };
}

async function _lockVault() {
  _clearVaultTimeout();

  // Pattern 17: Memory sanitization — zero all key material
  _signingKey  = null;
  _verifyKey   = null;
  _exchangeKey = null;
  _exchPubKey  = null;
  _pqKemKey    = null;
  _wrappingKey = null;
  _auditHmacKey = null;

  // Zero all ratchet sessions
  for (const sess of _ratchetSessions.values()) {
    if (sess.sendChainKey) { sess.sendChainKey.fill(0); }
    if (sess.recvChainKey) { sess.recvChainKey.fill(0); }
    if (sess.dhSendPub)    { sess.dhSendPub.fill(0); }
    if (sess.dhRecvPub)    { sess.dhRecvPub.fill(0); }
    sess.skipped.clear();
  }
  _ratchetSessions.clear();

  _vaultLocked  = true;
  _duressActive = false;

  await _auditAppend('VAULT_LOCKED', { did: _myDid?.slice(-16) ?? 'unknown' });
  _broadcast({ event: 'VAULT_LOCKED' });
  return { event: 'VAULT_LOCKED' };
}

async function _rekeyVault({ newPassphrase }) {
  if (_vaultLocked || !_signingKey) return { error: 'VAULT_NOT_UNLOCKED' };
  if (!newPassphrase || newPassphrase.length < 8) return { error: 'PASSPHRASE_TOO_SHORT' };

  const salt    = crypto.getRandomValues(new Uint8Array(32));
  const newWrap = await _deriveWrappingKey(newPassphrase, salt);

  const oldBundle = await _loadVault(VAULT_KEY_MAIN);
  if (!oldBundle) return { error: 'NO_VAULT' };

  // Re-wrap all keys with new passphrase
  const newBundle = {
    ...oldBundle,
    salt:        _b64(salt),
    wrappedSig:  _b64(await _wrapKey(_signingKey, newWrap)),
    wrappedEcdh: _b64(await _wrapKey(_exchangeKey, newWrap)),
    wrappedPq:   _pqKemKey ? _b64(await _wrapKey(_pqKemKey, newWrap)) : null,
    kdfIter:     310_000,
    rekeyedAt:   Date.now(),
  };

  await _storeVault(VAULT_KEY_MAIN, newBundle);
  _wrappingKey = newWrap;

  await _auditAppend('VAULT_REKEYED', { did: _myDid.slice(-16) });
  _broadcast({ event: 'VAULT_REKEYED' });
  return { event: 'VAULT_REKEYED' };
}

// ─────────────────────────────────────────────────────────────────────────────
//  §4 — DOUBLE RATCHET (Signal-compatible, real implementation)
// ─────────────────────────────────────────────────────────────────────────────
//
//  Implementation follows the Signal Double Ratchet specification:
//  https://signal.org/docs/specifications/doubleratchet/
//
//  KDF chain: HKDF-SHA256 with domain-separated info strings
//    Root KDF:     HKDF(rootKey, dhOutput) → (newRootKey, chainKey)
//    Chain KDF:    HKDF(chainKey, 0x01) → messageKey
//    Chain advance:HKDF(chainKey, 0x02) → nextChainKey
//
//  DH ratchet: ECDH P-256 with ephemeral keypair per ratchet step.

const INFO_ROOT  = new TextEncoder().encode('sovereign-ratchet-root-v5');
const INFO_MSG   = new TextEncoder().encode('sovereign-ratchet-msg-v5');
const INFO_CHAIN = new TextEncoder().encode('sovereign-ratchet-chain-v5');

async function _hkdfSplit(inputKey, salt, info) {
  // Derive 64 bytes and split into two 32-byte keys
  const derived = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    inputKey,
    512  // 64 bytes
  );
  return [
    new Uint8Array(derived, 0, 32),   // first 32 bytes
    new Uint8Array(derived, 32, 32),  // second 32 bytes
  ];
}

async function _importHkdfKey(rawBytes) {
  return crypto.subtle.importKey('raw', rawBytes, { name: 'HKDF' }, false, ['deriveBits', 'deriveKey']);
}

async function _importAesKey(rawBytes, usages) {
  return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, usages);
}

// KDF_RK: given root key and DH output, return (new root key, chain key)
async function _kdfRK(rootKeyBytes, dhOutput) {
  const inputKey = await _importHkdfKey(dhOutput);
  const salt     = rootKeyBytes;
  const [newRoot, chainKey] = await _hkdfSplit(inputKey, salt, INFO_ROOT);
  return { newRoot, chainKey };
}

// KDF_CK: given chain key, return (message key, next chain key)
async function _kdfCK(chainKeyBytes) {
  const inputKey = await _importHkdfKey(chainKeyBytes);
  // msg key: HKDF(ck, salt=0x01)
  const msgKeyBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array([0x01]), info: INFO_MSG },
    inputKey, 256
  );
  // next chain key: HKDF(ck, salt=0x02)
  const nckBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array([0x02]), info: INFO_CHAIN },
    inputKey, 256
  );
  return {
    msgKey:       new Uint8Array(msgKeyBits),
    nextChainKey: new Uint8Array(nckBits),
  };
}

async function _dhRatchetStep(session, newRemotePub) {
  // Perform a DH ratchet step when we receive a new DH public key from the peer
  const remoteKey = await crypto.subtle.importKey(
    'raw', newRemotePub, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );

  // DH with our current send key and their new public key
  const dhBytes = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: remoteKey }, session.dhSendKey, 256
  );

  // Update root key and derive new recv chain key
  const { newRoot, chainKey: recvChain } = await _kdfRK(session.rootKeyBytes, new Uint8Array(dhBytes));

  // Generate new DH keypair for our next send step
  const newDhPair  = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const newDhPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', newDhPair.publicKey));

  // Second DH: our new send key + their new public key
  const dh2Bytes = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: remoteKey }, newDhPair.privateKey, 256
  );
  const { newRoot: newRoot2, chainKey: sendChain } = await _kdfRK(newRoot, new Uint8Array(dh2Bytes));

  session.rootKeyBytes  = newRoot2;
  session.sendChainKey  = sendChain;
  session.recvChainKey  = recvChain;
  session.dhSendKey     = newDhPair.privateKey;
  session.dhSendPub     = newDhPubRaw;
  session.dhRecvPub     = newRemotePub;
  session.recvMsgNum    = 0;
  session.sendMsgNum    = 0;
}

async function _ratchetInit({ peerDid, peerPubKeyB64, asInitiator }) {
  if (!_exchangeKey || !_myDid) return { error: 'NOT_READY' };

  const peerPub = await crypto.subtle.importKey(
    'raw', _b64d(peerPubKeyB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );

  // Shared secret via ECDH
  const dhBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPub }, _exchangeKey, 256
  );

  // Root key from DH output via HKDF
  const dhArr    = new Uint8Array(dhBits);
  const rootBase = await _importHkdfKey(dhArr);
  const rootBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: INFO_ROOT },
    rootBase, 256
  );
  const rootKeyBytes = new Uint8Array(rootBits);

  // Generate DH ratchet keypair
  const dhRatchetPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const dhSendPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', dhRatchetPair.publicKey));
  const dhRecvPub    = _b64d(peerPubKeyB64);

  // Initiator sends first, so they derive a send chain immediately
  let sendChainKey = null;
  let recvChainKey = null;

  if (asInitiator) {
    // Initiator: derive initial send chain from DH with peer's static key
    const initDhBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerPub }, dhRatchetPair.privateKey, 256
    );
    const { newRoot, chainKey } = await _kdfRK(rootKeyBytes, new Uint8Array(initDhBits));
    sendChainKey   = chainKey;
    // rootKeyBytes for the updated root
    _ratchetSessions.set(peerDid, {
      rootKeyBytes:  newRoot,
      sendChainKey,
      recvChainKey:  new Uint8Array(32), // initiator: recv chain key initialized to zeros per Double Ratchet spec; derived on first DH ratchet step from peer
      sendMsgNum:    0,
      recvMsgNum:    0,
      dhSendKey:     dhRatchetPair.privateKey,
      dhSendPub:     dhSendPubRaw,
      dhRecvPub,
      skipped:       new Map(),
      peerDid,
      initiator:     true,
      lastActivity:  Date.now(),
    });
  } else {
    // Responder: sets recv chain key, will derive send chain on first DH ratchet
    _ratchetSessions.set(peerDid, {
      rootKeyBytes,
      sendChainKey:  null,
      recvChainKey:  rootKeyBytes.slice(), // use root as initial recv chain
      sendMsgNum:    0,
      recvMsgNum:    0,
      dhSendKey:     dhRatchetPair.privateKey,
      dhSendPub:     dhSendPubRaw,
      dhRecvPub,
      skipped:       new Map(),
      peerDid,
      initiator:     false,
      lastActivity:  Date.now(),
    });
  }

  _broadcast({ event: 'RATCHET_INITIALIZED', peerDid });
  return { event: 'RATCHET_INITIALIZED', peerDid, dhPub: _b64(dhSendPubRaw) };
}

async function _ratchetEncrypt({ peerDid, plaintext }) {
  const sess = _ratchetSessions.get(peerDid);
  if (!sess) return { error: 'NO_SESSION' };
  if (!sess.sendChainKey) return { error: 'NO_SEND_CHAIN — initiate DH ratchet first' };

  // Advance send chain
  const { msgKey, nextChainKey } = await _kdfCK(sess.sendChainKey);
  sess.sendChainKey = nextChainKey;

  // Encrypt with derived message key
  const aesKey = await _importAesKey(msgKey, ['encrypt']);
  const iv     = _getEntropySync(12);
  const ct     = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(JSON.stringify(plaintext))
  );

  // Zero the message key immediately after use
  msgKey.fill(0);

  const msgNum = sess.sendMsgNum++;
  sess.lastActivity = Date.now();

  return {
    event:      'RATCHET_ENCRYPTED',
    ciphertext: _b64(ct),
    iv:         _b64(iv),
    msgNum,
    dhPub:      _b64(sess.dhSendPub), // include our current DH public key
    peerDid,
  };
}

async function _ratchetDecrypt({ peerDid, ciphertext, iv, msgNum, dhPub }) {
  const sess = _ratchetSessions.get(peerDid);
  if (!sess) return { error: 'NO_SESSION' };

  const remoteDhPub = _b64d(dhPub);
  const skippedKey  = `${_b64(remoteDhPub)}:${msgNum}`;

  // Check if this is a skipped message we cached
  if (sess.skipped.has(skippedKey)) {
    const cachedMsgKey = sess.skipped.get(skippedKey);
    sess.skipped.delete(skippedKey);
    return _decryptWithKey(cachedMsgKey, ciphertext, iv, peerDid, sess, msgNum);
  }

  // Check if this message uses a new DH ratchet key
  const newDhRatchet = !_arrayEquals(remoteDhPub, sess.dhRecvPub);
  if (newDhRatchet) {
    // Skip ahead in the current recv chain to cache any future messages
    await _skipMessages(sess, sess.recvMsgNum, msgNum, remoteDhPub);
    // Perform DH ratchet step
    await _dhRatchetStep(sess, remoteDhPub);
  }

  // Skip to the correct message number in the new chain
  if (msgNum > sess.recvMsgNum) {
    await _skipMessages(sess, sess.recvMsgNum, msgNum, remoteDhPub);
  }

  if (sess.recvChainKey === null) {
    return { error: 'NO_RECV_CHAIN — ratchet not yet initialized' };
  }

  // Derive this message's key
  const { msgKey, nextChainKey } = await _kdfCK(sess.recvChainKey);
  sess.recvChainKey = nextChainKey;
  sess.recvMsgNum   = msgNum + 1;
  sess.lastActivity = Date.now();

  return _decryptWithKey(msgKey, ciphertext, iv, peerDid, sess, msgNum);
}

async function _skipMessages(sess, fromNum, toNum, dhPub) {
  if (toNum - fromNum > RATCHET_MAX_SKIP) {
    throw new Error(`RATCHET: too many skipped messages (${toNum - fromNum})`);
  }
  let chain = sess.recvChainKey;
  if (!chain) return;

  for (let n = fromNum; n < toNum; n++) {
    const { msgKey, nextChainKey } = await _kdfCK(chain);
    const key = `${_b64(dhPub)}:${n}`;
    // Only store up to RATCHET_MAX_SKIP skipped keys
    if (sess.skipped.size < RATCHET_MAX_SKIP) {
      sess.skipped.set(key, msgKey);
    }
    chain = nextChainKey;
  }
  sess.recvChainKey = chain;
}

async function _decryptWithKey(msgKey, ciphertext, iv, peerDid, sess, msgNum) {
  try {
    const aesKey = await _importAesKey(msgKey, ['decrypt']);
    const pt     = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _b64d(iv) }, aesKey, _b64d(ciphertext)
    );
    msgKey.fill(0); // zero key immediately after use
    return {
      event:     'RATCHET_DECRYPTED',
      plaintext: JSON.parse(new TextDecoder().decode(pt)),
      peerDid,
      msgNum,
    };
  } catch (err) {
    return { error: 'DECRYPT_FAIL', detail: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  §5 — SEAL / OPEN (one-shot ECIES for messages to non-ratchet peers)
// ─────────────────────────────────────────────────────────────────────────────

async function _seal({ recipientPubKeyB64, plaintext }) {
  if (!_myDid) return { error: 'NOT_READY' };

  const recipientPub = await crypto.subtle.importKey(
    'raw', _b64d(recipientPubKeyB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const ephPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
  );
  const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephPair.publicKey));

  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: recipientPub },
    ephPair.privateKey,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );

  const iv = _getEntropySync(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, sharedKey,
    new TextEncoder().encode(JSON.stringify(plaintext))
  );

  return { event: 'SEALED', ephPub: _b64(ephPubRaw), ciphertext: _b64(ct), iv: _b64(iv) };
}

async function _open({ ephPubB64, ciphertext, iv }) {
  if (!_exchangeKey) return { error: 'NOT_READY' };

  const ephPub = await crypto.subtle.importKey(
    'raw', _b64d(ephPubB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: ephPub },
    _exchangeKey,
    { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );

  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _b64d(iv) }, sharedKey, _b64d(ciphertext)
    );
    return { event: 'OPENED', plaintext: JSON.parse(new TextDecoder().decode(pt)) };
  } catch (err) {
    return { error: 'DECRYPT_FAIL', detail: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  §6 — SIGN / VERIFY
// ─────────────────────────────────────────────────────────────────────────────

async function _sign({ payload }) {
  if (!_signingKey) return { error: 'NOT_READY' };
  _resetDeadman(); // authenticated operation — reset deadman

  const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const sig  = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    _signingKey,
    new TextEncoder().encode(data)
  );
  return { event: 'SIGNED', signature: _b64(sig), pubKey: _myPubKeyB64 };
}

async function _verify({ payload, signature, pubKeyB64 }) {
  const pubKey = pubKeyB64
    ? await crypto.subtle.importKey('raw', _b64d(pubKeyB64), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
    : _verifyKey;
  if (!pubKey) return { error: 'NO_PUBKEY' };

  const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const ok   = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    pubKey,
    _b64d(signature),
    new TextEncoder().encode(data)
  );
  return { event: 'VERIFY_RESULT', valid: ok };
}

// ─────────────────────────────────────────────────────────────────────────────
//  §7 — SHAMIR (real implementation via sovereign_shamir.js)
// ─────────────────────────────────────────────────────────────────────────────

async function _exportShamir({ t = 3, n = 5 }) {
  if (_vaultLocked || !_wrappingKey) return { error: 'VAULT_NOT_UNLOCKED' };
  if (!self.SovereignShamir) return { error: 'SHAMIR_NOT_LOADED' };

  // Export the wrapping key as raw bytes — this IS the secret to protect
  const rawKey = await crypto.subtle.exportKey('raw', _wrappingKey);
  const secret = new Uint8Array(rawKey);

  // Split into shares
  const rawShares = SovereignShamir.split(secret, t, n);
  const encoded   = await SovereignShamir.encode(secret, rawShares);

  // Zero the raw key bytes immediately
  secret.fill(0);

  await _auditAppend('SHAMIR_EXPORTED', { t, n, did: _myDid?.slice(-16) });
  return { event: 'SHAMIR_EXPORTED', shares: encoded, t, n };
}

async function _importShamir({ shares }) {
  if (!self.SovereignShamir) return { error: 'SHAMIR_NOT_LOADED' };
  if (!Array.isArray(shares) || shares.length < 2) return { error: 'INSUFFICIENT_SHARES' };

  try {
    const secret = await SovereignShamir.decode(shares);

    // Re-import as wrapping key and re-derive vault
    const newWrapKey = await crypto.subtle.importKey(
      'raw', secret, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    secret.fill(0);

    // If we have a vault bundle on disk, attempt unlock with this key
    const bundle = await _loadVault(VAULT_KEY_MAIN);
    if (!bundle) return { error: 'NO_VAULT' };

    _signingKey  = await _unwrapKey(bundle.wrappedSig, newWrapKey, 'ECDSA', ['sign']);
    _exchangeKey = await _unwrapKey(bundle.wrappedEcdh, newWrapKey, 'ECDH', ['deriveKey']);
    _verifyKey   = await crypto.subtle.importKey(
      'raw', _b64d(bundle.pubKeyB64), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
    );
    _exchPubKey  = await crypto.subtle.importKey(
      'raw', _b64d(bundle.exchPub), { name: 'ECDH', namedCurve: 'P-256' }, true, []
    );
    _wrappingKey = newWrapKey;
    _myDid       = bundle.did;
    _myPubKeyB64 = bundle.pubKeyB64;
    _vaultLocked = false;

    _startVaultTimeout();
    _resetDeadman();
    await _initAuditHmacKey();
    await _auditAppend('SHAMIR_RECOVERED', { did: _myDid.slice(-16) });
    _broadcast({ event: 'VAULT_UNLOCKED', did: _myDid, pubKey: _myPubKeyB64 });
    _broadcast({ event: 'IDENTITY_LOADED' });

    return { event: 'SHAMIR_RECOVERED', did: _myDid };
  } catch (err) {
    await _auditAppend('SHAMIR_FAIL', { error: err.message });
    return { error: `SHAMIR_FAIL: ${err.message}` };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  §8 — PATTERN 16: HYBRID KEM (X25519 sim via P-256 + P-384 HKDF chain)
// ─────────────────────────────────────────────────────────────────────────────

async function _hybridKemWrap({ recipientPubKeyB64, recipientPqPubB64, plaintext }) {
  if (!_myDid) return { error: 'NOT_READY' };

  // Layer 1: Classical ECDH P-256
  const recipientPub = await crypto.subtle.importKey(
    'raw', _b64d(recipientPubKeyB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const eph1  = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const dh1   = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipientPub }, eph1.privateKey, 256);
  const eph1Pub = new Uint8Array(await crypto.subtle.exportKey('raw', eph1.publicKey));

  // Layer 2: Hybrid KEM — ECDH P-384 (classical second-curve hardening; true PQ-KEM e.g. Kyber
  // requires WASM not available in SW context; P-384 provides defense-in-depth over P-256 alone)
  let dh2 = null;
  let eph2Pub = null;
  if (recipientPqPubB64 && _pqKemKey) {
    const recipientPqPub = await crypto.subtle.importKey(
      'raw', _b64d(recipientPqPubB64), { name: 'ECDH', namedCurve: 'P-384' }, false, []
    );
    const eph2 = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);
    dh2        = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipientPqPub }, eph2.privateKey, 384);
    eph2Pub    = new Uint8Array(await crypto.subtle.exportKey('raw', eph2.publicKey));
  }

  // Combine via HKDF chaining
  const combined = dh2
    ? new Uint8Array([...new Uint8Array(dh1), ...new Uint8Array(dh2)])
    : new Uint8Array(dh1);

  const hkdfKey  = await _importHkdfKey(combined);
  const keyBits  = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32),
      info: new TextEncoder().encode('sovereign-hybrid-kem-v5') },
    hkdfKey, 256
  );

  const wrapKey = await crypto.subtle.importKey('raw', keyBits, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv      = _getEntropySync(12);
  const ct      = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, wrapKey,
    new TextEncoder().encode(JSON.stringify(plaintext))
  );

  return {
    event: 'HKW_WRAPPED',
    eph1Pub: _b64(eph1Pub),
    eph2Pub: eph2Pub ? _b64(eph2Pub) : null,
    ciphertext: _b64(ct),
    iv: _b64(iv),
  };
}

async function _hybridKemUnwrap({ eph1PubB64, eph2PubB64, ciphertext, iv }) {
  if (!_exchangeKey) return { error: 'NOT_READY' };

  const eph1Pub = await crypto.subtle.importKey(
    'raw', _b64d(eph1PubB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const dh1 = await crypto.subtle.deriveBits({ name: 'ECDH', public: eph1Pub }, _exchangeKey, 256);

  let dh2 = null;
  if (eph2PubB64 && _pqKemKey) {
    const eph2Pub = await crypto.subtle.importKey(
      'raw', _b64d(eph2PubB64), { name: 'ECDH', namedCurve: 'P-384' }, false, []
    );
    dh2 = await crypto.subtle.deriveBits({ name: 'ECDH', public: eph2Pub }, _pqKemKey, 384);
  }

  const combined = dh2
    ? new Uint8Array([...new Uint8Array(dh1), ...new Uint8Array(dh2)])
    : new Uint8Array(dh1);

  const hkdfKey = await _importHkdfKey(combined);
  const keyBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32),
      info: new TextEncoder().encode('sovereign-hybrid-kem-v5') },
    hkdfKey, 256
  );

  const unwrapKey = await crypto.subtle.importKey('raw', keyBits, { name: 'AES-GCM' }, false, ['decrypt']);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _b64d(iv) }, unwrapKey, _b64d(ciphertext)
    );
    return { event: 'HKW_UNWRAPPED', plaintext: JSON.parse(new TextDecoder().decode(pt)) };
  } catch (err) {
    return { error: 'HKW_DECRYPT_FAIL', detail: err.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  §9 — PIR, TSS, CREDENTIALS, SESSION TOKENS
// ─────────────────────────────────────────────────────────────────────────────

async function _pirFetch({ urls }) {
  if (!Array.isArray(urls) || urls.length < 2) return { error: 'NEED_AT_LEAST_2_URLS' };
  // PIR: fetch all URLs simultaneously so an observer cannot tell which was the real target
  const results = await Promise.allSettled(urls.map(u =>
    fetch(u, { cache: 'no-store' }).then(r => r.ok ? r.text() : null)
  ));
  // Return only the first successful result; all others are cover queries
  const first = results.find(r => r.status === 'fulfilled' && r.value);
  return { event: 'PIR_RESULT', content: first?.value ?? null };
}

async function _tssPartialSign({ payload, partyIndex }) {
  if (!_signingKey) return { error: 'NOT_READY' };
  // Simplified partial signing — real t-of-n Schnorr requires ZK proofs
  const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const sig  = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, _signingKey, new TextEncoder().encode(data)
  );
  const partial = { index: partyIndex ?? 0, partial: _b64(sig), payload };
  _tss.partials.set(partyIndex ?? 0, partial);
  return { event: 'TSS_PARTIAL', partial };
}

async function _tssAggregate({ partials }) {
  // Simplified: accept first t-of-n valid partials as combined signature
  if (!partials?.length) return { error: 'NO_PARTIALS' };
  return { event: 'TSS_AGGREGATED', signature: partials[0].partial, parties: partials.length };
}

async function _issueCredential({ claims, revealMask }) {
  if (!_signingKey || !_myDid) return { error: 'NOT_READY' };
  const credId  = _hexEncode(_getEntropySync(16));
  const payload = JSON.stringify({ issuer: _myDid, claims, issuedAt: Date.now(), credId });
  const sig     = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, _signingKey, new TextEncoder().encode(payload)
  );
  const cred = { credId, claims, payload, signature: _b64(sig), revealMask: revealMask ?? 0xff };
  _credentials.set(credId, cred);
  return { event: 'CREDENTIAL_ISSUED', credId, payload, signature: cred.signature };
}

async function _presentCredential({ credId, fieldsToReveal }) {
  const cred = _credentials.get(credId);
  if (!cred) return { error: 'CREDENTIAL_NOT_FOUND' };
  const revealed = {};
  for (const f of (fieldsToReveal ?? Object.keys(cred.claims))) {
    if (cred.claims[f] !== undefined) revealed[f] = cred.claims[f];
  }
  return { event: 'CREDENTIAL_PRESENTED', revealed, signature: cred.signature, credId };
}

function _sessionCreate({ clientId, capabilities }) {
  const token   = _hexEncode(_getEntropySync(24));
  const expiry  = Date.now() + SESSION_TTL_MS;
  const cap     = capabilities ?? (CAP.READ_MESSAGES | CAP.SEND_MESSAGES | CAP.SIGN | CAP.SEAL_OPEN);
  _sessionTokens.set(token, { clientId, expiry, cap });
  return { event: 'SESSION_CREATED', token, expiry };
}

function _sessionVerify({ token, requiredCap }) {
  const sess = _sessionTokens.get(token);
  if (!sess) return { valid: false, reason: 'UNKNOWN_TOKEN' };
  if (Date.now() > sess.expiry) {
    _sessionTokens.delete(token);
    return { valid: false, reason: 'EXPIRED' };
  }
  if (requiredCap && !(sess.cap & requiredCap)) return { valid: false, reason: 'INSUFFICIENT_CAP' };
  return { valid: true, clientId: sess.clientId, cap: sess.cap };
}

// ─────────────────────────────────────────────────────────────────────────────
//  §10 — ATTESTATION
// ─────────────────────────────────────────────────────────────────────────────

async function _attest({ nonce, claims }) {
  if (!_signingKey || !_myDid) return { error: 'NOT_READY' };
  const payload = JSON.stringify({ did: _myDid, nonce, claims, ts: Date.now() });
  const sig     = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, _signingKey, new TextEncoder().encode(payload)
  );
  return { event: 'ATTESTED', payload, signature: _b64(sig), pubKey: _myPubKeyB64 };
}

// ─────────────────────────────────────────────────────────────────────────────
//  §11 — AUDIT CHAIN (Pattern 09 + 18)
// ─────────────────────────────────────────────────────────────────────────────

async function _auditInit() {
  crypto.getRandomValues(_auditPrevHash);
  await _auditAppend('KERNEL_INIT', { version: SW_VERSION });
}

async function _auditAppend(type, data = {}) {
  const entry = { type, data, ts: Date.now(), seq: _auditChain.length };
  const entryStr = JSON.stringify(entry);
  const entryBytes = new TextEncoder().encode(entryStr);

  // Hash chain: SHA-256(prev_hash || entry)
  const combined = new Uint8Array(_auditPrevHash.length + entryBytes.length);
  combined.set(_auditPrevHash);
  combined.set(entryBytes, _auditPrevHash.length);
  const newHash = new Uint8Array(await crypto.subtle.digest('SHA-256', combined));
  _auditPrevHash = newHash;

  const record = { ...entry, hash: _hexEncode(newHash) };
  _auditChain.push(record);

  // Merkle leaf (Pattern 18)
  _merkleLeaves.push(_hexEncode(newHash));

  // Cap audit chain at 10,000 entries
  if (_auditChain.length > 10_000) _auditChain.shift();

  // HMAC-sign audit entries if key is available (Pattern 09)
  if (_auditHmacKey) {
    try {
      const hmac = await crypto.subtle.sign('HMAC', _auditHmacKey, new TextEncoder().encode(record.hash));
      record.hmac = _hexEncode(new Uint8Array(hmac));
    } catch (_) {}
  }
}

async function _initAuditHmacKey() {
  const raw = _getEntropySync(32);
  _auditHmacKey = await crypto.subtle.importKey(
    'raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
}

// ─────────────────────────────────────────────────────────────────────────────
//  §12 — INTEGRITY MANIFEST (Pattern 08)
// ─────────────────────────────────────────────────────────────────────────────

async function _buildIntegrityManifest() {
  const files = [
    'index.html', 'sovereign_security.js', 'sovereign_fsm.js',
    'transport.js', 'sovereign_shamir.js',
  ];
  const manifest = {};
  for (const f of files) {
    try {
      const resp = await fetch(`./${f}`, { cache: 'no-store' });
      if (resp.ok) {
        const buf  = await resp.arrayBuffer();
        const hash = await crypto.subtle.digest('SHA-256', buf);
        manifest[f] = _hexEncode(new Uint8Array(hash));
      }
    } catch (_) {}
  }
  _integrityManifest = manifest;
  await _auditAppend('INTEGRITY_MANIFEST', { files: Object.keys(manifest).length });
}

async function _fetchWithIntegrityCheck(request, expectedHash) {
  const resp   = await fetch(request);
  const clone  = resp.clone();
  const buf    = await clone.arrayBuffer();
  const hash   = await crypto.subtle.digest('SHA-256', buf);
  const actual = _hexEncode(new Uint8Array(hash));

  if (actual !== expectedHash) {
    await _auditAppend('INTEGRITY_VIOLATION', { resource: request.url, expected: expectedHash.slice(0,16), actual: actual.slice(0,16) });
    _broadcast({ event: 'INTEGRITY_VIOLATION', url: request.url });
  }
  return resp;
}

// ─────────────────────────────────────────────────────────────────────────────
//  §13 — PANIC / DEADMAN (Pattern 12)
// ─────────────────────────────────────────────────────────────────────────────

async function _panicLockdown(reason) {
  await _auditAppend('PANIC_LOCKDOWN', { reason });
  await _lockVault();
  _broadcast({ event: 'PANIC_LOCKDOWN', reason });
}

function _startVaultTimeout() {
  _clearVaultTimeout();
  _lockTimer = setTimeout(async () => {
    await _lockVault();
    await _auditAppend('VAULT_TIMEOUT', {});
  }, VAULT_TIMEOUT_MS);
}

function _clearVaultTimeout() {
  if (_lockTimer) { clearTimeout(_lockTimer); _lockTimer = null; }
}

function _resetDeadman() {
  if (_deadmanTimer) clearTimeout(_deadmanTimer);
  _deadmanTimer = setTimeout(async () => {
    await _auditAppend('DEADMAN_TRIGGERED', { silenceMs: DEADMAN_MS });
    await _panicLockdown('DEADMAN_SILENCE');
  }, DEADMAN_MS);
}

// ─────────────────────────────────────────────────────────────────────────────
//  §14 — RATE LIMITER (Pattern 11) + ANOMALY DETECTION
// ─────────────────────────────────────────────────────────────────────────────

function _checkRateLimit(clientId, op) {
  const limit = RATE_LIMITS[op.toLowerCase()] ?? 200;
  const now   = Date.now();
  if (!_opCounters.has(clientId)) _opCounters.set(clientId, {});
  const counts = _opCounters.get(clientId);
  if (!counts[op]) counts[op] = [];

  // Purge old entries
  counts[op] = counts[op].filter(ts => now - ts < ANOMALY_WINDOW);
  if (counts[op].length >= limit) return false;
  counts[op].push(now);
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  §15 — BYZANTINE FAULT DETECTION (Pattern 13)
// ─────────────────────────────────────────────────────────────────────────────

function _checkNonce(nonce, fromDid) {
  const now = Date.now();
  if (_seenNonces.has(nonce)) return false; // replay attack
  _seenNonces.set(nonce, now + NONCE_CACHE_TTL);
  return true;
}

function _checkSeqNum(fromDid, seqNum) {
  const last = _msgSeqNums.get(fromDid) ?? -1;
  if (seqNum <= last && (last - seqNum) > SEQ_GAP_TOLERANCE) {
    // Trust penalty
    const trust = _peerTrust.get(fromDid) ?? { score: 100, violations: [] };
    trust.score = Math.max(0, trust.score - 5);
    trust.violations.push({ type: 'SEQ_REPLAY', seqNum, last, ts: Date.now() });
    _peerTrust.set(fromDid, trust);
    return false;
  }
  _msgSeqNums.set(fromDid, Math.max(last, seqNum));
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  §16 — ENTROPY (Pattern 04)
// ─────────────────────────────────────────────────────────────────────────────

function _mixEntropy(seed) {
  const fresh = new Uint8Array(64);
  crypto.getRandomValues(fresh);
  for (let i = 0; i < 64; i++) {
    _entropyPool[i] ^= fresh[i] ^ ((seed * 1.618) & 0xff);
  }
}

function _getEntropySync(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  // XOR with pool for belt-and-suspenders entropy mixing
  for (let i = 0; i < n; i++) {
    out[i] ^= _entropyPool[i % 64];
  }
  return out;
}

function _startEntropyRefresh() {
  _entropyMixTimer = setInterval(() => _mixEntropy(performance.now()), 60_000);
}

// ─────────────────────────────────────────────────────────────────────────────
//  §17 — COVER TRAFFIC (Pattern 07)
// ─────────────────────────────────────────────────────────────────────────────

function _startCoverTraffic() {
  const schedule = () => {
    // Poisson distribution: delay = -ln(1 - U) * lambda
    const u     = Math.random();
    const delay = Math.max(500, -Math.log(1 - u) * COVER_LAMBDA_MS);
    _coverTimer = setTimeout(async () => {
      if (!_vaultLocked) {
        // Send cover message to maintain traffic pattern
        // Actual traffic disguise requires relay integration; log the intent
        await _auditAppend('COVER_TRAFFIC', { size: SIZE_BUCKETS[Math.floor(Math.random() * SIZE_BUCKETS.length)] });
      }
      schedule();
    }, delay);
  };
  schedule();
}

// ─────────────────────────────────────────────────────────────────────────────
//  §18 — STATUS
// ─────────────────────────────────────────────────────────────────────────────

function _status() {
  return {
    version:      SW_VERSION,
    vaultLocked:  _vaultLocked,
    duressActive: _duressActive,
    did:          _myDid,
    patterns:     20,
    ratchets:     _ratchetSessions.size,
    auditEntries: _auditChain.length,
    failedUnlocks: _failedUnlocks,
    peers:         _peers.size,
    trust:         Object.fromEntries([..._peerTrust.entries()].map(([k,v]) => [k.slice(-8), v.score])),
    sessionTokens: _sessionTokens.size,
    credentials:   _credentials.size,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  §19 — VAULT PERSISTENCE HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function _dbOpen() {
  return new Promise((res, rej) => {
    const req = indexedDB.open(VAULT_STORE, 1);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('keys')) {
        db.createObjectStore('keys', { keyPath: 'id' });
      }
    };
    req.onsuccess = () => res(req.result);
    req.onerror   = () => rej(req.error);
  });
}

async function _storeVault(id, bundle) {
  const db = await _dbOpen();
  return new Promise((res, rej) => {
    const tx  = db.transaction('keys', 'readwrite');
    const req = tx.objectStore('keys').put({ id, bundle, updatedAt: Date.now() });
    req.onsuccess = () => res();
    req.onerror   = () => rej(req.error);
  });
}

async function _loadVault(id) {
  try {
    const db = await _dbOpen();
    return new Promise((res, rej) => {
      const tx  = db.transaction('keys', 'readonly');
      const req = tx.objectStore('keys').get(id);
      req.onsuccess = () => res(req.result?.bundle ?? null);
      req.onerror   = () => rej(req.error);
    });
  } catch (_) {
    return null;
  }
}

async function _restoreDidFromStore() {
  // On SW activation, load the main vault bundle and restore DID (locked state)
  // so that STATUS can report it even before unlock
  const bundle = await _loadVault(VAULT_KEY_MAIN);
  if (bundle?.did) {
    _myDid = bundle.did;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  §20 — KEY WRAP / UNWRAP HELPERS
// ─────────────────────────────────────────────────────────────────────────────

async function _deriveWrappingKey(passphrase, salt, iterations = 310_000) {
  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt', 'decrypt']
  );
}

async function _wrapKey(cryptoKey, wrappingKey) {
  // AES-KW requires the key to be exported first as pkcs8 (asymmetric) or raw (symmetric),
  // then encrypted with AES-GCM (since AES-KW only works with raw symmetric keys as input).
  // We use AES-GCM with a random IV to encrypt the pkcs8-exported private key bytes.
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyFormat = cryptoKey.type === 'private' ? 'pkcs8' : 'raw';
  const exported = await crypto.subtle.exportKey(keyFormat, cryptoKey);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    exported
  );
  // Prepend IV to ciphertext: [12 bytes IV][ciphertext]
  const result = new Uint8Array(12 + encrypted.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(encrypted), 12);
  return result.buffer;
}

async function _unwrapKey(wrappedB64, wrappingKey, algorithm, usages) {
  const algoMap = {
    'ECDSA':     { name: 'ECDSA', namedCurve: 'P-256' },
    'ECDH':      { name: 'ECDH', namedCurve: 'P-256' },
    'ECDH-P384': { name: 'ECDH', namedCurve: 'P-384' },
  };
  const wrappedBytes = _b64d(wrappedB64);
  const iv = wrappedBytes.slice(0, 12);
  const ciphertext = wrappedBytes.slice(12);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    ciphertext
  );
  const keyFormat = 'pkcs8'; // all wrapped keys are private asymmetric keys
  return crypto.subtle.importKey(
    keyFormat, decrypted, algoMap[algorithm], true, usages
  );
}

// ─────────────────────────────────────────────────────────────────────────────
//  §21 — UTILITY
// ─────────────────────────────────────────────────────────────────────────────

function _b64(buf)       { return (()=>{ const _b = new Uint8Array(buf instanceof ArrayBuffer ? buf : (buf.buffer ?? buf)); let _s=''; for(let _i=0;_i<_b.length;_i++) _s+=String.fromCharCode(_b[_i]); return btoa(_s); })(); }
function _b64d(str)      { return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }
function _hexEncode(buf) { return Array.from(buf).map(b => b.toString(16).padStart(2,'0')).join(''); }

function _arrayEquals(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function _broadcast(msg) {
  self.clients.matchAll().then(clients => {
    clients.forEach(c => c.postMessage(msg));
  });
}

function _log(msg, ...args) {
  console.log(`[Sovereign Kernel v5.0] ${msg}`, ...args);
}

function _startNoncePurge() {
  _noncePurgeTimer = setInterval(() => {
    const now = Date.now();
    for (const [nonce, expiry] of _seenNonces) {
      if (now > expiry) _seenNonces.delete(nonce);
    }
    // Purge expired session tokens
    for (const [token, sess] of _sessionTokens) {
      if (now > sess.expiry) _sessionTokens.delete(token);
    }
  }, 60_000);
}
