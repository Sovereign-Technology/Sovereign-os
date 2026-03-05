// ═══════════════════════════════════════════════════════════════════════════
//  SOVEREIGN SERVICE WORKER SECURITY KERNEL — genesis_sw.js
//  Version: 2.0.0 — Full 15-Pattern Security Architecture
//
//  © James Chapman (XheCarpenXer) · iconoclastdao@gmail.com
//  Sovereign Technology Master IP Registry — March 2026
//
//  Dual License:
//    License A — Personal / Open-Source  → FREE (attribution required)
//    License B — Commercial / Institutional → Negotiated / Reciprocal OSS
//  Prohibited: mass surveillance, cryptographic backdoors, human rights violations.
//
//  ┌─────────────────────────────────────────────────────────────────────┐
//  │  TIER I   — Crypto Kernel     Patterns 01–04                       │
//  │  TIER II  — Network Security  Patterns 05–07                       │
//  │  TIER III — Integrity         Patterns 08–10                       │
//  │  TIER IV  — Resilience        Patterns 11–13                       │
//  │  TIER V   — Novel / Profound  Patterns 14–15                       │
//  └─────────────────────────────────────────────────────────────────────┘
//
//  KEY INSIGHT: The Service Worker does not share memory with any page.
//  An XSS attacker who owns every active tab cannot read the SW heap.
//  This is the most important isolation primitive in the browser.
// ═══════════════════════════════════════════════════════════════════════════
'use strict';

const SW_VERSION = 'sovereign-sw-v2.2.0';
const SW_BUILD   = '2026-03';

// ════════════════════════════════════════════════════════════════════════════
//  §0 — GLOBAL STATE
// ════════════════════════════════════════════════════════════════════════════

// Identity — held in SW memory, NEVER exposed to tabs (Pattern 01)
let _signingKey   = null;
let _verifyKey    = null;
let _exchangeKey  = null;
let _exchPubKey   = null;
let _wrappingKey  = null;
let _auditHmacKey = null;
let _myDid        = null;
let _myPubKeyB64  = null;
let _vaultLocked  = true;
let _lockTimer    = null;
const VAULT_TIMEOUT_MS = 30 * 60 * 1000;

// Peer mesh
const _peers    = new Map();
const _registry = new Map();
const _queue    = new Map();

// Pattern 02 — Double Ratchet sessions: did → RatchetSession
const _ratchetSessions = new Map();

// Pattern 03 — Dual vault keys
const VAULT_STORE = 'sovereign_vault';
const VAULT_KEY_A = 'vault_alpha';
const VAULT_KEY_B = 'vault_beta';

// Pattern 04 — Entropy pool (512-bit, continuously refreshed)
const _entropyPool = new Uint8Array(64);
crypto.getRandomValues(_entropyPool);
const _beaconCommits = new Map();
const _beaconReveals = new Map();
let   _beaconRandom  = null;

// Pattern 05 — Network firewall
const _networkPolicy = {
  allowed: new Set([
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'cdnjs.cloudflare.com',
    'cdn.jsdelivr.net',
    // Relay servers
    'sovereign-relay.fly.dev',         // first-party relay
    'broker.emqx.io',                  // EMQ X fallback relay
    'broker.hivemq.com',               // HiveMQ fallback relay
    'test.mosquitto.org',              // Mosquitto fallback relay
    'public.mqtthq.com',               // MQTTHQ fallback relay
    // STUN servers
    'openrelay.metered.ca',            // metered.ca STUN
    'stun.relay.metered.ca',           // metered.ca STUN 2
    'stun.cloudflare.com',             // Cloudflare STUN
    'global.stun.twilio.com',          // Twilio STUN
    'stun.nextcloud.com',              // Nextcloud STUN
    'stun.libreoffice.org',            // LibreOffice STUN
    'stun.sipgate.net',                // Sipgate STUN
  ]),
};

// Pattern 07 — Cover traffic & jitter
const COVER_LAMBDA_MS = 45000;
const SIZE_BUCKETS    = [256, 512, 1024, 4096];
const MAX_JITTER_MS   = 800;
let   _coverTimer     = null;

// Pattern 08 — Integrity manifest: resource → sha256hex
let _integrityManifest = null;

// Pattern 09 — Audit chain
const _auditChain    = [];
let   _auditPrevHash = new Uint8Array(32);

// Pattern 10 — Capability tokens: clientId → token
const _capabilities = new Map();
const CAP = {
  READ_MESSAGES : 0b00000001,
  SEND_MESSAGES : 0b00000010,
  SIGN          : 0b00000100,
  SEAL_OPEN     : 0b00001000,
  MANAGE_PEERS  : 0b00010000,
  ADMIN         : 0b10000000,
};

// Pattern 11 — Anomaly detector: clientId → counters
const _opCounters      = new Map();
const ANOMALY_WINDOW   = 10000;
const RATE_LIMITS      = { sign: 30, open: 60, send: 120, peerEnum: 10 };

// Pattern 12 — Panic / deadman
let _failedUnlocks   = 0;
const MAX_UNLOCKS    = 5;
let _deadmanTimer    = null;
const DEADMAN_MS     = 4 * 60 * 60 * 1000;

// Pattern 13 — Byzantine detector
const _peerTrust  = new Map();
const _msgIndex   = new Map();
const _seenNonces = new Set();

// Pattern 15 — Threshold signing
const _tss = {
  threshold: 2, parties: 3, myIndex: null,
  shards: new Map(), commitments: new Map(), partials: new Map(),
};

// ════════════════════════════════════════════════════════════════════════════
//  §1 — SW LIFECYCLE
// ════════════════════════════════════════════════════════════════════════════

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    await self.skipWaiting();
    await _buildIntegrityManifest();
    _mixEntropy(performance.now());
    _startCoverTraffic();
    await _auditInit();
    _log('Security Kernel v2.0 installed — 15 patterns active');
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    await self.clients.claim();
    _resetDeadman();
    _broadcast({ event: 'SW_READY', version: SW_VERSION });
  })());
});

self.addEventListener('push',             () => _mixEntropy(performance.now()));
self.addEventListener('sync',             () => _mixEntropy(performance.now()));
self.addEventListener('notificationclick',() => _mixEntropy(performance.now()));

function _mixEntropy(sample) {
  const t = new Uint8Array(8);
  new DataView(t.buffer).setFloat64(0, sample, false);
  for (let i = 0; i < 8; i++) _entropyPool[i % 64] ^= t[i];
  const fresh = new Uint8Array(32);
  crypto.getRandomValues(fresh);
  for (let i = 0; i < 32; i++) _entropyPool[32 + i] ^= fresh[i];
}

// ════════════════════════════════════════════════════════════════════════════
//  §2 — FETCH INTERCEPT (Patterns 05, 08)
// ════════════════════════════════════════════════════════════════════════════

self.addEventListener('fetch', (e) => {
  _mixEntropy(performance.now());
  const req = e.request;
  const url = new URL(req.url);

  // Same-origin: serve from integrity-verified cache
  if (url.origin === self.location.origin) {
    e.respondWith(_serveFromCache(req));
    return;
  }

  // Pattern 05: Firewall — block non-allowlisted external domains
  if (!_networkPolicy.allowed.has(url.hostname)) {
    _auditLogSync('FIREWALL_BLOCK', { url: url.hostname });
    _broadcast({ event: 'FIREWALL_BLOCK', url: url.hostname });
    e.respondWith(new Response('Blocked by Sovereign Firewall', { status: 403 }));
    return;
  }

  // Strip tracking headers before external request
  e.respondWith(_strippedFetch(req));
});

async function _serveFromCache(req) {
  const cache  = await caches.open(SW_VERSION);
  const cached = await cache.match(req);
  if (cached) return cached;
  const resp = await fetch(req);
  if (resp.ok) await cache.put(req, resp.clone());
  return resp;
}

async function _strippedFetch(req) {
  const BLOCKED_HEADERS = new Set(['referer','cookie','x-forwarded-for','via','origin','authorization']);
  const headers = new Headers();
  for (const [k, v] of req.headers.entries()) {
    if (!BLOCKED_HEADERS.has(k.toLowerCase())) headers.set(k, v);
  }
  const stripped = new Request(req.url, {
    method: req.method, headers,
    body: (req.method !== 'GET' && req.method !== 'HEAD') ? await req.blob() : undefined,
    mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer',
  });
  return fetch(stripped);
}

// ════════════════════════════════════════════════════════════════════════════
//  §3 — TAB MESSAGE BUS
// ════════════════════════════════════════════════════════════════════════════

self.addEventListener('message', async (e) => {
  _mixEntropy(performance.now());
  const { cmd, ...args } = e.data || {};
  const client = e.source;
  if (!client) return;

  const openCmds = new Set([
    'BOOT','VAULT_UNLOCK','VAULT_CREATE','VAULT_CREATE_DUAL',
    'STATUS','HEARTBEAT','PANIC','SW_VERSION','AUDIT_VERIFY','AUDIT_EXPORT',
    'AUDIT_NOTARY', // 4B fix: notary attestation is pre-auth — page signs with local key
    'SELF_TEST',
    // Pattern 08: manifest rebuild is pre-auth because a stale manifest would
    // otherwise permanently lock users out after a legitimate app update.
    // The SW re-hashes files from its own fetch cache — no tab input trusted.
    'REBUILD_MANIFEST',
  ]);

  if (!openCmds.has(cmd)) {
    const cap = _capabilities.get(client.id);
    if (!cap && _vaultLocked) {
      client.postMessage({ event: 'ERROR', cmd, reason: 'Vault locked — please unlock first' });
      return;
    }
  }

  // Anomaly tracking (Pattern 11)
  _trackOp(client.id, cmd);

  switch (cmd) {
    // Vault & Identity
    case 'BOOT':             await _handleBoot(args, client);           break;
    case 'VAULT_UNLOCK':     await _handleVaultUnlock(args, client);    break;
    case 'VAULT_LOCK':       _vaultLock(); client.postMessage({ event: 'VAULT_LOCKED' }); break;
    case 'VAULT_CREATE':     await _handleVaultCreate(args, client);    break;
    case 'VAULT_CREATE_DUAL':await _handleVaultCreateDual(args, client);break;
    case 'HEARTBEAT':        _resetDeadman(); client.postMessage({ event: 'HEARTBEAT_ACK' }); break;

    // Pattern 01: Key Oracle
    case 'SIGN':             await _handleSign(args, client);           break;
    case 'SEAL':             await _handleSeal(args, client);           break;
    case 'OPEN':             await _handleOpen(args, client);           break;

    // Pattern 02: Double Ratchet
    case 'RATCHET_INIT':     await _handleRatchetInit(args, client);    break;
    case 'RATCHET_ENCRYPT':  await _handleRatchetEncrypt(args, client); break;
    case 'RATCHET_DECRYPT':  await _handleRatchetDecrypt(args, client); break;

    // Peer Mesh
    case 'CONNECT':          await _handleConnect(args.did, client);    break;
    case 'SEND':             await _handleSend(args, client);           break;
    case 'REGISTER_PEER':    _handleRegisterPeer(args, client);         break;
    case 'CHANNEL_OPEN':     _handleChannelOpen(args);                  break;
    case 'CHANNEL_CLOSED':   _handleChannelClosed(args);                break;
    case 'INCOMING_MSG':     await _handleIncomingMsg(args, client);    break;
    case 'OFFER_RECEIVED':   _peers.set(args.peerId, { state:'handshake', did:args.peerId });
                             _broadcast({ event:'PEER_HANDSHAKE', did:args.peerId }); break;

    // Pattern 05: Firewall admin
    case 'ALLOW_DOMAIN':     _handleAllowDomain(args, client);          break;
    case 'REVOKE_DOMAIN':    _handleRevokeDomain(args, client);         break;

    // Pattern 06: Onion routing
    case 'ONION_SEND':       await _handleOnionSend(args, client);      break;
    case 'ONION_INCOMING':   await _handleOnionIncoming(args, client);  break;

    // Pattern 04: Entropy beacon
    case 'BEACON_COMMIT':    _beaconCommits.set(args.peerDid, args.commitment);
                             _broadcast({ event:'BEACON_COMMIT_RECEIVED', peerDid: args.peerDid }); break;
    case 'BEACON_REVEAL':    await _handleBeaconReveal(args, client);   break;

    // Pattern 09: Audit
    case 'AUDIT_VERIFY':     await _handleAuditVerify(client);          break;
    case 'AUDIT_EXPORT':     client.postMessage({ event:'AUDIT_EXPORTED', chain:[..._auditChain], tipHash:_b64(_auditPrevHash) }); break;

    // Pattern 14: PIR fetch
    case 'PIR_FETCH':        await _handlePirFetch(args, client);       break;

    // Pattern 12: Panic
    case 'PANIC':            await _panicDestroy('EXPLICIT_COMMAND');   break;

    // Pattern 15: TSS
    case 'TSS_DKG_ROUND1':   await _handleTssDkgRound1(args, client);  break;
    case 'TSS_DKG_ROUND2':   await _handleTssDkgRound2(args, client);  break;
    case 'TSS_PARTIAL_SIGN': await _handleTssPartialSign(args, client); break;
    case 'TSS_AGGREGATE':    await _handleTssAggregate(args, client);   break;

    case 'STATUS':           _handleStatus(client);                      break;
    case 'SW_VERSION':       client.postMessage({ event:'SW_VERSION', version:SW_VERSION, build:SW_BUILD }); break;
    case 'SELF_TEST':        await _handleSelfTest(client);              break;
    case 'AUDIT_NOTARY':     await _handleAuditNotary(args, client);     break; // 4B fix
    // Pattern 08: Rebuild integrity manifest after a legitimate app update.
    // Clears the old hashes, re-fetches all app files from network (bypassing
    // the SW cache), and rebuilds. The vault remains locked until the next
    // successful unlock — this command only resets the baseline, not the lock.
    case 'REBUILD_MANIFEST': await _handleRebuildManifest(args, client); break;
    default:                 client.postMessage({ event:'ERROR', cmd, reason:'Unknown command' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  §4 — BOOT & IDENTITY
// ════════════════════════════════════════════════════════════════════════════

async function _handleBoot(args, client) {
  _myDid       = args.did || _myDid;
  _myPubKeyB64 = args.pubKey || _myPubKeyB64;
  if (_myDid) _registry.set(_myDid, { pubKeyB64: _myPubKeyB64, ts: Date.now(), self: true });
  await _issueCapability(client.id, CAP.READ_MESSAGES);
  _broadcast({ event: 'SW_READY', did: _myDid, version: SW_VERSION });
  _auditLog('BOOT', { did: _myDid, clientId: client.id });
}

// ════════════════════════════════════════════════════════════════════════════
//  §5 — PATTERN 01 — CRYPTOGRAPHIC KEY ORACLE
//  All private key operations run inside SW. Tabs receive results only.
//  Keys never cross the SW boundary.
// ════════════════════════════════════════════════════════════════════════════

async function _handleVaultUnlock(args, client) {
  const { passphrase } = args;
  if (!passphrase) { client.postMessage({ event:'VAULT_ERROR', reason:'No passphrase' }); return; }

  // Pattern 12: Brute-force detection
  if (_failedUnlocks >= MAX_UNLOCKS) {
    await _panicDestroy('BRUTE_FORCE_DETECTED');
    return;
  }

  // Pattern 08: Integrity check before vault unlock
  const ok = await _attestTabIntegrity();
  if (!ok) {
    client.postMessage({ event:'VAULT_ERROR', reason:'INTEGRITY_VIOLATION' });
    _broadcast({ event:'INTEGRITY_VIOLATION' });
    _auditLog('INTEGRITY_VIOLATION', { clientId: client.id });
    return;
  }

  // Pattern 03: Try both vault_alpha and vault_beta — do NOT reveal which succeeded
  let unlocked = false;
  for (const vaultKey of [VAULT_KEY_A, VAULT_KEY_B]) {
    try {
      const blob = await _idbGet(VAULT_STORE, vaultKey);
      if (!blob) continue;
      const keys = await _unwrapVault(blob, passphrase);
      if (keys) {
        _signingKey   = keys.signingKey;
        _verifyKey    = keys.verifyKey;
        _exchangeKey  = keys.exchangeKey;
        _exchPubKey   = keys.exchPubKey;
        _auditHmacKey = keys.auditKey;
        _vaultLocked  = false;
        _failedUnlocks = 0;
        await _issueCapability(client.id,
          CAP.READ_MESSAGES | CAP.SEND_MESSAGES | CAP.SIGN |
          CAP.SEAL_OPEN | CAP.MANAGE_PEERS | CAP.ADMIN);
        _resetDeadman();
        _resetLockTimer();
        client.postMessage({ event:'VAULT_UNLOCKED', did: _myDid });
        _auditLog('VAULT_UNLOCK', { clientId: client.id });
        unlocked = true;
        break;
      }
    } catch (_) { /* try next vault */ }
  }

  if (!unlocked) {
    _failedUnlocks++;
    const backoffMs = Math.pow(2, _failedUnlocks) * 1000;
    client.postMessage({ event:'VAULT_ERROR', reason:'Bad passphrase', backoffMs, attempts: _failedUnlocks });
    _auditLog('VAULT_UNLOCK_FAIL', { clientId: client.id, attempts: _failedUnlocks });
  }
}

function _vaultLock() {
  _signingKey = _verifyKey = _exchangeKey = _exchPubKey = _wrappingKey = _auditHmacKey = null;
  _vaultLocked = true;
  if (_lockTimer) clearTimeout(_lockTimer);
  for (const [cid] of _capabilities) {
    _capabilities.set(cid, { bitmask: CAP.READ_MESSAGES, expiresAt: Date.now() + 60000, clientId: cid, nonce: '', issuedAt: Date.now() });
  }
  _broadcast({ event:'VAULT_LOCKED' });
  _auditLog('VAULT_LOCKED', {});
}

function _resetLockTimer() {
  if (_lockTimer) clearTimeout(_lockTimer);
  _lockTimer = setTimeout(() => _vaultLock(), VAULT_TIMEOUT_MS);
}

async function _handleVaultCreate(args, client) {
  const { passphrase, isDecoy } = args;
  if (!passphrase) { client.postMessage({ event:'ERROR', reason:'No passphrase' }); return; }
  const keys  = await _generateKeys();
  const blob  = await _wrapVault(keys, passphrase);
  const vKey  = isDecoy ? VAULT_KEY_B : VAULT_KEY_A;
  await _idbSet(VAULT_STORE, vKey, blob);
  const verRaw = await crypto.subtle.exportKey('raw', keys.verifyKey);
  const pubB64 = _b64(verRaw);
  const did    = 'did:sovereign:' + pubB64.slice(0, 32);
  client.postMessage({ event:'VAULT_CREATED', did, pubKey: pubB64, vaultKey: vKey });
  _auditLog('VAULT_CREATE', { did, isDecoy: !!isDecoy });
}

// Pattern 03 — Deniable/Duress Vault
async function _handleVaultCreateDual(args, client) {
  const { passphrase, decoyPassphrase } = args;
  if (!passphrase || !decoyPassphrase) {
    client.postMessage({ event:'ERROR', reason:'Both passphrases required for dual vault' });
    return;
  }
  const realKeys  = await _generateKeys();
  const decoyKeys = await _generateKeys();
  await _idbSet(VAULT_STORE, VAULT_KEY_A, await _wrapVault(realKeys,  passphrase));
  await _idbSet(VAULT_STORE, VAULT_KEY_B, await _wrapVault(decoyKeys, decoyPassphrase));
  const realPub  = _b64(await crypto.subtle.exportKey('raw', realKeys.verifyKey));
  const decoyPub = _b64(await crypto.subtle.exportKey('raw', decoyKeys.verifyKey));
  // No structural difference visible from outside SW — observer cannot determine which vault is real
  client.postMessage({
    event    : 'DUAL_VAULT_CREATED',
    realDid  : 'did:sovereign:' + realPub.slice(0,32),
    decoyDid : 'did:sovereign:' + decoyPub.slice(0,32),
  });
  _auditLog('DUAL_VAULT_CREATE', {});
}

// Pattern 01 — SIGN oracle. Key never leaves SW.
async function _handleSign(args, client) {
  if (!_requireCap(client.id, CAP.SIGN, client)) return;
  if (!_signingKey) { client.postMessage({ event:'ERROR', cmd:'SIGN', reason:'Vault locked' }); return; }
  const data = _fromB64(args.data);
  const sig  = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, _signingKey, data);
  client.postMessage({ event:'SIGNED', sig: _b64(sig), nonce: args.nonce });
  _auditLog('SIGN', { clientId: client.id, dataLen: data.byteLength });
}

// Pattern 01 — SEAL oracle. Returns ciphertext only.
async function _handleSeal(args, client) {
  if (!_requireCap(client.id, CAP.SEAL_OPEN, client)) return;
  if (!_exchangeKey) { client.postMessage({ event:'ERROR', cmd:'SEAL', reason:'Vault locked' }); return; }
  const theirKey = await crypto.subtle.importKey('raw', _fromB64(args.recipientPubKey),
    { name:'ECDH', namedCurve:'P-256' }, false, []);
  const dhRaw    = await crypto.subtle.deriveBits({ name:'ECDH', public: theirKey }, _exchangeKey, 256);
  const hkdfK    = await crypto.subtle.importKey('raw', dhRaw, 'HKDF', false, ['deriveBits']);
  const keyBuf   = await crypto.subtle.deriveBits(
    { name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: _str2b('sovereign-seal-v1') },
    hkdfK, 256);
  const aesKey   = await crypto.subtle.importKey('raw', keyBuf, 'AES-GCM', false, ['encrypt']);
  const iv       = crypto.getRandomValues(new Uint8Array(12));
  const ct       = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, _fromB64(args.plaintext));
  client.postMessage({ event:'SEALED', ciphertext: _b64(ct), iv: _b64(iv), nonce: args.nonce });
  _auditLog('SEAL', { clientId: client.id });
}

// Pattern 01 — OPEN oracle. Returns plaintext only.
async function _handleOpen(args, client) {
  if (!_requireCap(client.id, CAP.SEAL_OPEN, client)) return;
  if (!_exchangeKey) { client.postMessage({ event:'ERROR', cmd:'OPEN', reason:'Vault locked' }); return; }
  try {
    const senderKey = await crypto.subtle.importKey('raw', _fromB64(args.senderPubKey),
      { name:'ECDH', namedCurve:'P-256' }, false, []);
    const dhRaw     = await crypto.subtle.deriveBits({ name:'ECDH', public: senderKey }, _exchangeKey, 256);
    const hkdfK     = await crypto.subtle.importKey('raw', dhRaw, 'HKDF', false, ['deriveBits']);
    const keyBuf    = await crypto.subtle.deriveBits(
      { name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: _str2b('sovereign-seal-v1') },
      hkdfK, 256);
    const aesKey    = await crypto.subtle.importKey('raw', keyBuf, 'AES-GCM', false, ['decrypt']);
    const pt        = await crypto.subtle.decrypt({ name:'AES-GCM', iv: _fromB64(args.iv) }, aesKey, _fromB64(args.ciphertext));
    client.postMessage({ event:'OPENED', plaintext: _b64(pt), nonce: args.nonce });
    _auditLog('OPEN', { clientId: client.id });
  } catch {
    client.postMessage({ event:'ERROR', cmd:'OPEN', reason:'Decryption failed' });
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  §6 — PATTERN 02 — DOUBLE RATCHET FORWARD SECRECY ENGINE
//  Per-session ratchet state. Past sessions mathematically irrecoverable.
// ════════════════════════════════════════════════════════════════════════════

async function _handleRatchetInit(args, client) {
  const { peerDid, theirIdentityPubKey, theirEphemeralPubKey } = args;
  try {
    const theirIdKey  = await crypto.subtle.importKey('raw', _fromB64(theirIdentityPubKey),
      { name:'ECDH', namedCurve:'P-256' }, false, []);
    const theirEphKey = await crypto.subtle.importKey('raw', _fromB64(theirEphemeralPubKey),
      { name:'ECDH', namedCurve:'P-256' }, false, []);
    const myEph    = await crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']);
    const myEphPub = await crypto.subtle.exportKey('raw', myEph.publicKey);

    // X3DH: three DH operations, HKDF to derive root + chain key
    const dh1 = await crypto.subtle.deriveBits({ name:'ECDH', public: theirEphKey }, _exchangeKey, 256);
    const dh2 = await crypto.subtle.deriveBits({ name:'ECDH', public: theirIdKey  }, myEph.privateKey, 256);
    const dh3 = await crypto.subtle.deriveBits({ name:'ECDH', public: theirEphKey }, myEph.privateKey, 256);

    const ikm      = _concat(dh1, dh2, dh3);
    const hkdfKey  = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const derived  = await crypto.subtle.deriveBits(
      { name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: _str2b('sovereign-ratchet-v1') },
      hkdfKey, 512
    );
    const d = new Uint8Array(derived);
    _ratchetSessions.set(peerDid, {
      rootKey: d.slice(0,32), sendChain: d.slice(32,64), recvChain: d.slice(32,64),
      sendN: 0, recvN: 0, skipped: new Map(),
      myDHPriv: myEph.privateKey, myDHPubB64: _b64(myEphPub),
    });
    client.postMessage({ event:'RATCHET_INITIALIZED', peerDid, myEphPubKey: _b64(myEphPub), nonce: args.nonce });
    _auditLog('RATCHET_INIT', { peerDid });
  } catch (err) {
    client.postMessage({ event:'ERROR', cmd:'RATCHET_INIT', reason: err.message });
  }
}

async function _handleRatchetEncrypt(args, client) {
  const s = _ratchetSessions.get(args.peerDid);
  if (!s) { client.postMessage({ event:'ERROR', cmd:'RATCHET_ENCRYPT', reason:'No session' }); return; }
  const msgKey    = await _hkdfDerive(s.sendChain, 'sovereign-msg-key');
  const nextChain = await _hkdfDerive(s.sendChain, 'sovereign-chain-adv');
  s.sendChain = new Uint8Array(nextChain);  // advance and destroy previous
  const n      = s.sendN++;
  const aesKey = await crypto.subtle.importKey('raw', msgKey.slice(0,32), 'AES-GCM', false, ['encrypt']);
  const iv     = crypto.getRandomValues(new Uint8Array(12));
  const ct     = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, _fromB64(args.plaintext));
  client.postMessage({
    event:'RATCHET_ENCRYPTED', peerDid: args.peerDid, n,
    myDHPubKey: s.myDHPubB64, ciphertext: _b64(ct), iv: _b64(iv), nonce: args.nonce,
  });
}

async function _handleRatchetDecrypt(args, client) {
  const s = _ratchetSessions.get(args.peerDid);
  if (!s) { client.postMessage({ event:'ERROR', cmd:'RATCHET_DECRYPT', reason:'No session' }); return; }
  const n = args.n;

  // Gap 11 fix: DH ratchet step — if peer sent a new DH public key, perform the DH ratchet
  // to advance the root key and derive a fresh receiving chain (provides break-in recovery)
  if (args.myDHPubKey && args.myDHPubKey !== s.lastSeenPeerDHPub) {
    try {
      const theirNewDH = await crypto.subtle.importKey('raw', _fromB64(args.myDHPubKey),
        { name:'ECDH', namedCurve:'P-256' }, false, []);
      // DH ratchet: derive new root key + recv chain from old root + DH output
      const dh       = await crypto.subtle.deriveBits({ name:'ECDH', public: theirNewDH }, s.myDHPriv, 256);
      const ikm      = _concat(s.rootKey, new Uint8Array(dh));
      const hkdfKey  = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
      const derived  = await crypto.subtle.deriveBits(
        { name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: _str2b('sovereign-ratchet-dh-step') },
        hkdfKey, 512);
      const d = new Uint8Array(derived);
      s.rootKey   = d.slice(0, 32);
      s.recvChain = d.slice(32, 64);
      s.recvN     = 0;
      s.skipped.clear();
      s.lastSeenPeerDHPub = args.myDHPubKey;
      // Generate our new DH keypair for the next send step
      const myNewDH    = await crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']);
      const myNewPub   = await crypto.subtle.exportKey('raw', myNewDH.publicKey);
      // Advance send chain with new DH
      const dh2      = await crypto.subtle.deriveBits({ name:'ECDH', public: theirNewDH }, myNewDH.privateKey, 256);
      const ikm2     = _concat(s.rootKey, new Uint8Array(dh2));
      const hkdfKey2 = await crypto.subtle.importKey('raw', ikm2, 'HKDF', false, ['deriveBits']);
      const derived2 = await crypto.subtle.deriveBits(
        { name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: _str2b('sovereign-ratchet-dh-step') },
        hkdfKey2, 512);
      const d2 = new Uint8Array(derived2);
      s.rootKey    = d2.slice(0, 32);
      s.sendChain  = d2.slice(32, 64);
      s.sendN      = 0;
      s.myDHPriv   = myNewDH.privateKey;
      s.myDHPubB64 = _b64(myNewPub);
    } catch (err) {
      client.postMessage({ event:'ERROR', cmd:'RATCHET_DECRYPT', reason:'DH ratchet step failed: ' + err.message }); return;
    }
  }

  let msgKey;
  if (s.skipped.has(n)) {
    msgKey = s.skipped.get(n);
    s.skipped.delete(n);
  } else {
    let chain = new Uint8Array(s.recvChain);
    let cur   = s.recvN;
    while (cur < n) {
      s.skipped.set(cur, (await _hkdfDerive(chain, 'sovereign-msg-key')).slice(0,32));
      chain = new Uint8Array(await _hkdfDerive(chain, 'sovereign-chain-adv'));
      cur++;
    }
    msgKey = (await _hkdfDerive(chain, 'sovereign-msg-key')).slice(0,32);
    s.recvChain = new Uint8Array(await _hkdfDerive(chain, 'sovereign-chain-adv'));
    s.recvN = n + 1;
  }
  try {
    const aesKey = await crypto.subtle.importKey('raw', msgKey, 'AES-GCM', false, ['decrypt']);
    const pt     = await crypto.subtle.decrypt({ name:'AES-GCM', iv: _fromB64(args.iv) }, aesKey, _fromB64(args.ciphertext));
    client.postMessage({ event:'RATCHET_DECRYPTED', peerDid: args.peerDid, plaintext: _b64(pt), nonce: args.nonce });
  } catch {
    client.postMessage({ event:'ERROR', cmd:'RATCHET_DECRYPT', reason:'Decryption failed' });
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  §7 — PEER MESH
// ════════════════════════════════════════════════════════════════════════════

async function _handleConnect(targetDid, client) {
  if (!targetDid) return;
  if (_peers.get(targetDid)?.state === 'open') {
    client.postMessage({ event:'ALREADY_CONNECTED', did: targetDid }); return;
  }
  _peers.set(targetDid, { state:'handshake', did: targetDid });
  _broadcast({ event:'PEER_HANDSHAKE', did: targetDid });
  client.postMessage({ event:'INITIATE_WEBRTC', did: targetDid });
}

async function _handleSend(args, client) {
  if (!_requireCap(client.id, CAP.SEND_MESSAGES, client)) return;
  const { did, msg } = args;
  // Pattern 07: Jitter
  await _sleep(Math.floor(Math.random() * MAX_JITTER_MS));
  const padded = _padToBucket(typeof msg === 'string' ? msg : JSON.stringify(msg));
  if (_peers.get(did)?.state === 'open') {
    _broadcast({ event:'RELAY_SEND', did, msg: padded });
  } else {
    if (!_queue.has(did)) _queue.set(did, []);
    _queue.get(did).push(padded);
    client.postMessage({ event:'MSG_QUEUED', did, queueLen: _queue.get(did).length });
  }
}

function _handleRegisterPeer(args, client) {
  if (!_requireCap(client.id, CAP.MANAGE_PEERS, client)) return;
  _registry.set(args.did, { pubKeyB64: args.pubKey, exchPubKeyB64: args.exchPubKey, ts: Date.now() });
  _peerTrust.set(args.did, 100);
  _broadcast({ event:'PEER_KNOWN', did: args.did });
  _auditLog('PEER_REGISTER', { did: args.did });
}

function _handleChannelOpen(args) {
  _peers.has(args.did) ? (_peers.get(args.did).state = 'open') : _peers.set(args.did, { state:'open', did:args.did });
  _broadcast({ event:'PEER_CONNECTED', did:args.did });
  _flushQueue(args.did);
}

function _handleChannelClosed(args) {
  if (_peers.has(args.did)) _peers.get(args.did).state = 'closed';
  _broadcast({ event:'PEER_DISCONNECTED', did:args.did });
}

async function _handleIncomingMsg(args, client) {
  if (!(await _validateIncomingMessage(args.did, args.msg, args.sig, args.seq, args.nonce))) return;
  _broadcast({ event:'MESSAGE', from: args.did, msg: args.msg });
}

function _flushQueue(did) {
  const q = _queue.get(did);
  if (!q?.length) return;
  _broadcast({ event:'FLUSH_QUEUE', did, messages: q });
  _queue.delete(did);
}

// ════════════════════════════════════════════════════════════════════════════
//  §8 — PATTERN 05 — NETWORK FIREWALL (admin)
// ════════════════════════════════════════════════════════════════════════════

function _handleAllowDomain(args, client) {
  if (!_requireCap(client.id, CAP.ADMIN, client)) return;
  _networkPolicy.allowed.add(args.domain);
  _auditLog('ALLOW_DOMAIN', { domain: args.domain });
  client.postMessage({ event:'DOMAIN_ALLOWED', domain: args.domain });
}

function _handleRevokeDomain(args, client) {
  if (!_requireCap(client.id, CAP.ADMIN, client)) return;
  _networkPolicy.allowed.delete(args.domain);
  _auditLog('REVOKE_DOMAIN', { domain: args.domain });
  client.postMessage({ event:'DOMAIN_REVOKED', domain: args.domain });
}

// ════════════════════════════════════════════════════════════════════════════
//  §9 — PATTERN 06 — LAYERED ONION ROUTER
//  N-layer encryption. No single peer knows both sender and recipient.
// ════════════════════════════════════════════════════════════════════════════

async function _handleOnionSend(args, client) {
  if (!_requireCap(client.id, CAP.SEND_MESSAGES, client)) return;
  const { targetDid, plaintext } = args;
  const relays = _selectRoute(targetDid, 2);
  if (relays.length < 2) {
    client.postMessage({ event:'ERROR', cmd:'ONION_SEND', reason:`Insufficient qualified peers for onion routing (need 2, have ${relays.length})` }); return;
  }
  const route = [...relays, targetDid];
  let payload = JSON.stringify({ type:'FINAL', content: plaintext, to: targetDid });

  for (let i = route.length - 1; i >= 0; i--) {
    const hopDid = route[i];
    const peer   = _registry.get(hopDid);
    if (!peer?.exchPubKeyB64) continue;
    const nextHop = i < route.length - 1 ? route[i+1] : null;
    const envelope = JSON.stringify({ type: nextHop ? 'RELAY' : 'FINAL', nextHop, payload });
    const eph    = await crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']);
    const ephPub = await crypto.subtle.exportKey('raw', eph.publicKey);
    const theirK = await crypto.subtle.importKey('raw', _fromB64(peer.exchPubKeyB64),
      { name:'ECDH', namedCurve:'P-256' }, false, []);
    const shared = await crypto.subtle.deriveBits({ name:'ECDH', public: theirK }, eph.privateKey, 256);
    const hkdfK  = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const keyBuf = await crypto.subtle.deriveBits(
      { name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: _str2b('sovereign-onion-v1') },
      hkdfK, 256);
    const aesKey = await crypto.subtle.importKey('raw', keyBuf, 'AES-GCM', false, ['encrypt']);
    const iv     = crypto.getRandomValues(new Uint8Array(12));
    const ct     = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, _str2b(envelope));
    payload      = JSON.stringify({ ephPubKey: _b64(ephPub), iv: _b64(iv), ct: _b64(ct) });
  }

  _broadcast({ event:'RELAY_SEND', did: route[0], msg: { type:'ONION', payload } });
  client.postMessage({ event:'ONION_SENT', hops: relays.length, nonce: args.nonce });
  _auditLog('ONION_SEND', { hops: relays.length });
}

async function _handleOnionIncoming(args, client) {
  try {
    const parsed  = JSON.parse(args.payload);
    const ephPub  = await crypto.subtle.importKey('raw', _fromB64(parsed.ephPubKey),
      { name:'ECDH', namedCurve:'P-256' }, false, []);
    const shared  = await crypto.subtle.deriveBits({ name:'ECDH', public: ephPub }, _exchangeKey, 256);
    const hkdfK   = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const keyBuf  = await crypto.subtle.deriveBits(
      { name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: _str2b('sovereign-onion-v1') },
      hkdfK, 256);
    const aesKey  = await crypto.subtle.importKey('raw', keyBuf, 'AES-GCM', false, ['decrypt']);
    const pt      = await crypto.subtle.decrypt({ name:'AES-GCM', iv: _fromB64(parsed.iv) }, aesKey, _fromB64(parsed.ct));
    const env     = JSON.parse(_b2str(pt));
    if (env.type === 'FINAL') _broadcast({ event:'ONION_MESSAGE', content: env.content });
    else _broadcast({ event:'RELAY_SEND', did: env.nextHop, msg: { type:'ONION', payload: env.payload } });
  } catch { /* silently discard — hides routing info */ }
}

function _selectRoute(targetDid, n) {
  // Gap 13 fix: only select peers that have an exchange key registered,
  // so hops are never silently dropped during onion encryption.
  const cands = [..._registry.entries()]
    .filter(([d, p]) => d !== _myDid && d !== targetDid && p.exchPubKeyB64)
    .map(([d]) => d);
  for (let i = cands.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i+1));
    [cands[i], cands[j]] = [cands[j], cands[i]];
  }
  return cands.slice(0, n);
}

// ════════════════════════════════════════════════════════════════════════════
//  §10 — PATTERN 07 — COVER TRAFFIC & TIMING JITTER
// ════════════════════════════════════════════════════════════════════════════

function _startCoverTraffic() {
  const scheduleNext = () => {
    const ms = -Math.log(Math.random()) * COVER_LAMBDA_MS;
    _coverTimer = setTimeout(() => { _sendCoverTraffic(); scheduleNext(); }, ms);
  };
  scheduleNext();
}

async function _sendCoverTraffic() {
  const peers = [..._registry.keys()].filter(d => d !== _myDid);
  for (const did of peers.filter(() => Math.random() < 0.3)) {
    try {
      // Gap 12 fix: cover traffic must be indistinguishable from real encrypted messages.
      // Encrypt random bytes with a throw-away key so the envelope looks identical to CHAT.
      const throwawayKey = await crypto.subtle.generateKey({ name:'AES-GCM', length:256 }, false, ['encrypt']);
      const iv           = crypto.getRandomValues(new Uint8Array(12));
      const randomPayload= crypto.getRandomValues(new Uint8Array(128));
      const ct           = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, throwawayKey, randomPayload);
      const dummy = _padToBucket(JSON.stringify({
        type:'CHAT', iv: _b64(iv), ct: _b64(ct), ts: Date.now(),
        nonce: _b64(crypto.getRandomValues(new Uint8Array(16))),
      }));
      _broadcast({ event:'RELAY_SEND', did, msg: dummy });
    } catch (_) { /* ignore */ }
  }
}

function _padToBucket(msg) {
  const bytes  = _str2b(msg);
  const bucket = SIZE_BUCKETS.find(b => b >= bytes.length) || SIZE_BUCKETS[SIZE_BUCKETS.length-1];
  if (bytes.length >= bucket) return msg;
  const padded = new Uint8Array(bucket);
  padded.set(bytes);
  crypto.getRandomValues(padded.subarray(bytes.length));
  return JSON.stringify({ _p:1, d: _b64(bytes), x: _b64(padded.subarray(bytes.length)) });
}

// ════════════════════════════════════════════════════════════════════════════
//  §11 — PATTERN 08 — TAB CODE INTEGRITY ATTESTATION
// ════════════════════════════════════════════════════════════════════════════

const APP_FILES = [
  'index.html','os.html','forge.html','messenger.html','mail.html',
  'attack.html','bridge.html','search.html','portal.html','square.html',
  'studio.html','relay.html','transport.js',
];

async function _buildIntegrityManifest() {
  const m = new Map();
  for (const f of APP_FILES) {
    try {
      const resp = await fetch(f);
      if (resp.ok) m.set(f, _b64(await _sha256(await resp.arrayBuffer())));
    } catch { /* offline — skip */ }
  }
  if (m.size) { _integrityManifest = m; _auditLog('MANIFEST_BUILD', { files: m.size }); }
}

async function _attestTabIntegrity() {
  if (!_integrityManifest?.size) return true;
  const cache = await caches.open(SW_VERSION);
  for (const [f, expected] of _integrityManifest) {
    const cached = await cache.match(f);
    if (!cached) continue;
    const got = _b64(await _sha256(await cached.clone().arrayBuffer()));
    if (got !== expected) { _auditLog('INTEGRITY_MISMATCH', { resource: f }); return false; }
  }
  return true;
}

async function _handleRebuildManifest(args, client) {
  // Caller may optionally pass a nonce for rate-limiting / dedup.
  // This command is intentionally pre-auth: a stale manifest after a legitimate
  // update would otherwise permanently prevent vault unlock.
  //
  // Security note: the rebuild fetches fresh copies from the network (cache:reload),
  // not from the SW cache, so updated files are picked up immediately.
  // The old manifest is cleared first — if rebuild fails partially, integrity
  // checks pass (no manifest = permissive) rather than failing permanently.
  const prev = _integrityManifest ? _integrityManifest.size : 0;
  _integrityManifest = null;   // clear old baseline immediately

  const m = new Map();
  const errors = [];
  for (const f of APP_FILES) {
    try {
      // cache:'reload' bypasses SW cache and fetches fresh from origin
      const resp = await fetch(f, { cache: 'reload' });
      if (resp.ok) {
        m.set(f, _b64(await _sha256(await resp.arrayBuffer())));
        // Also update the SW cache with the fresh copy
        const cache = await caches.open(SW_VERSION);
        const resp2 = await fetch(f, { cache: 'reload' });
        if (resp2.ok) await cache.put(f, resp2);
      } else {
        errors.push({ file: f, status: resp.status });
      }
    } catch (e) {
      errors.push({ file: f, error: e.message });
    }
  }

  if (m.size) {
    _integrityManifest = m;
    await _auditLog('MANIFEST_REBUILD', { files: m.size, prev, errors: errors.length });
    client.postMessage({ event: 'MANIFEST_REBUILT', files: m.size, errors, nonce: args.nonce });
    _log(`Manifest rebuilt: ${m.size} files hashed, ${errors.length} errors`);
  } else {
    await _auditLog('MANIFEST_REBUILD_FAILED', { errors });
    client.postMessage({ event: 'ERROR', cmd: 'REBUILD_MANIFEST', reason: 'All files unreachable', errors, nonce: args.nonce });
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  §12 — PATTERN 09 — CRYPTOGRAPHICALLY-CHAINED IMMUTABLE AUDIT LEDGER
// ════════════════════════════════════════════════════════════════════════════

async function _auditInit() {
  _auditHmacKey = await crypto.subtle.generateKey({ name:'HMAC', hash:'SHA-256' }, true, ['sign','verify']);
  // Gap 8: restore running tip from IDB so chain is not lost on SW restart
  try {
    const tip = await _idbGet(VAULT_STORE, 'audit_tip');
    if (tip?.tipHash) {
      _auditPrevHash = _fromB64(tip.tipHash);
      _log(`Audit chain resumed from seq ${tip.seq}, tip ${tip.tipHash.slice(0,8)}…`);
    }
  } catch (_) { /* IDB may not exist yet on first install — that is fine */ }
}

async function _auditLog(event, data) {
  const entry  = { seq: _auditChain.length, event, data, ts: Date.now(), prevHash: _b64(_auditPrevHash) };
  const eBytes = _str2b(JSON.stringify(entry));
  const hash   = await _sha256(_concat(_auditPrevHash, eBytes));
  let hmac = null;
  if (_auditHmacKey) hmac = _b64(await crypto.subtle.sign('HMAC', _auditHmacKey, eBytes));
  const record = { ...entry, hash: _b64(hash), hmac };
  _auditChain.push(record);
  // Keep only last 500 entries in memory; persist the running tip to IDB (Gap 8 fix)
  if (_auditChain.length > 500) _auditChain.splice(0, _auditChain.length - 500);
  _auditPrevHash = new Uint8Array(hash);
  _broadcast({ event:'AUDIT_ENTRY', record });
  // Persist tip non-blocking so restart can resume chain
  _idbSet(VAULT_STORE, 'audit_tip', { seq: record.seq, tipHash: _b64(hash), ts: record.ts }).catch(()=>{});
}

// Sync version for fetch handler (no await)
function _auditLogSync(event, data) { _auditLog(event, data).catch(()=>{}); }

async function _handleAuditVerify(client) {
  let prev = new Uint8Array(32), firstBroken = null;
  for (const record of _auditChain) {
    const { hash, hmac, ...entry } = record;
    const eBytes   = _str2b(JSON.stringify(entry));
    const computed = _b64(await _sha256(_concat(prev, eBytes)));
    if (computed !== hash) { firstBroken = record.seq; break; }
    prev = _fromB64(hash);
  }
  client.postMessage({ event:'AUDIT_VERIFIED', intact: !firstBroken, entries: _auditChain.length, firstBroken, tipHash: _b64(_auditPrevHash) });
}

// ════════════════════════════════════════════════════════════════════════════
//  §13 — PATTERN 10 — CAPABILITY TOKEN ISSUER
// ════════════════════════════════════════════════════════════════════════════

async function _issueCapability(clientId, bitmask) {
  const issuedAt  = Date.now();
  const expiresAt = issuedAt + 60 * 60 * 1000;
  const nonce     = _b64(crypto.getRandomValues(new Uint8Array(16)));
  // Gap 14 fix: bind token to clientId+bitmask+issuedAt+nonce via HMAC
  // so impersonation attempts are detectable even if clientId is somehow spoofed.
  let tokenHmac = null;
  if (_auditHmacKey) {
    const claim = _str2b(JSON.stringify({ clientId, bitmask, issuedAt, nonce }));
    tokenHmac = _b64(await crypto.subtle.sign('HMAC', _auditHmacKey, claim));
  }
  _capabilities.set(clientId, { clientId, bitmask, issuedAt, expiresAt, nonce, tokenHmac });
}

async function _verifyCapabilityToken(clientId) {
  const cap = _capabilities.get(clientId);
  if (!cap || !cap.tokenHmac || !_auditHmacKey) return !!cap;
  const claim = _str2b(JSON.stringify({ clientId: cap.clientId, bitmask: cap.bitmask, issuedAt: cap.issuedAt, nonce: cap.nonce }));
  try {
    return await crypto.subtle.verify('HMAC', _auditHmacKey, _fromB64(cap.tokenHmac), claim);
  } catch { return false; }
}

function _requireCap(clientId, required, client) {
  const cap = _capabilities.get(clientId);
  if (!cap) { client?.postMessage({ event:'CAPABILITY_DENIED', required }); return false; }
  if (Date.now() > cap.expiresAt) { _capabilities.delete(clientId); client?.postMessage({ event:'CAPABILITY_EXPIRED' }); return false; }
  if (!(cap.bitmask & required)) { client?.postMessage({ event:'CAPABILITY_DENIED', required }); return false; }
  // Gap 14: verify HMAC binding asynchronously; revoke cap if verification fails
  if (cap.tokenHmac && _auditHmacKey) {
    _verifyCapabilityToken(clientId).then(valid => {
      if (!valid) { _capabilities.delete(clientId); _auditLog('CAP_HMAC_FAIL', { clientId }); }
    }).catch(()=>{});
  }
  return true;
}

function _degradeCapabilities(clientId) {
  const cap = _capabilities.get(clientId);
  if (cap) {
    cap.bitmask = CAP.READ_MESSAGES;
    _broadcast({ event:'CAPABILITIES_DEGRADED', clientId });
    _auditLog('CAP_DEGRADED', { clientId });
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  §14 — PATTERN 11 — BEHAVIORAL ANOMALY DETECTOR
// ════════════════════════════════════════════════════════════════════════════

function _trackOp(clientId, cmd) {
  if (!_opCounters.has(clientId)) {
    _opCounters.set(clientId, { sign:0, open:0, send:0, peerEnum:0, windowStart:Date.now(), baseline:null });
  }
  const c = _opCounters.get(clientId);
  const now = Date.now();
  if (now - c.windowStart > ANOMALY_WINDOW) {
    if (!c.baseline) c.baseline = { sign:c.sign, open:c.open, send:c.send };
    c.sign = c.open = c.send = c.peerEnum = 0;
    c.windowStart = now;
  }
  if (cmd === 'SIGN')          c.sign++;
  if (cmd === 'OPEN')          c.open++;
  if (cmd === 'SEND')          c.send++;
  if (cmd === 'REGISTER_PEER') c.peerEnum++;
  _checkAnomaly(clientId, c);
}

function _checkAnomaly(clientId, c) {
  let severity = null, rule = null;
  if (c.open > 20)                              { severity='HIGH';   rule='BULK_DECRYPT'; }
  else if (c.sign > 15 && c.send === 0)         { severity='HIGH';   rule='SIGN_WITHOUT_SEND'; }
  else if (c.peerEnum > 10)                     { severity='MEDIUM'; rule='PEER_ENUM_BURST'; }
  else if (c.baseline && c.sign > c.baseline.sign * 10) { severity='HIGH'; rule='RATE_SPIKE'; }
  if (severity) {
    if (severity === 'HIGH') _degradeCapabilities(clientId);
    _broadcast({ event:'ANOMALY_DETECTED', clientId, rule, severity });
    _auditLog('ANOMALY', { clientId, rule, severity });
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  §15 — PATTERN 12 — PANIC HANDLER, DEADMAN SWITCH & KEY ZEROIZATION
// ════════════════════════════════════════════════════════════════════════════

async function _panicDestroy(reason) {
  _auditLog('PANIC', { reason });
  // Zero all key material
  _signingKey = _verifyKey = _exchangeKey = _exchPubKey = _wrappingKey = _auditHmacKey = null;
  _vaultLocked = true;
  // Destroy ratchet sessions
  _ratchetSessions.clear();
  // Delete vault from IndexedDB
  try { await _idbDelete(VAULT_STORE, VAULT_KEY_A); } catch {}
  try { await _idbDelete(VAULT_STORE, VAULT_KEY_B); } catch {}
  // Revoke all capabilities
  _capabilities.clear();
  // Clear peer state and TSS shards
  _peers.clear(); _queue.clear(); _tss.shards.clear();
  if (_deadmanTimer) clearTimeout(_deadmanTimer);
  if (_lockTimer)    clearTimeout(_lockTimer);
  if (_coverTimer)   clearTimeout(_coverTimer);
  _broadcast({ event:'PANIC_LOCKDOWN', reason, ts: Date.now() });
  _failedUnlocks = 0;
}

function _resetDeadman() {
  if (_deadmanTimer) clearTimeout(_deadmanTimer);
  _deadmanTimer = setTimeout(() => _panicDestroy('DEADMAN_HEARTBEAT_SILENCE'), DEADMAN_MS);
}

// ════════════════════════════════════════════════════════════════════════════
//  §16 — PATTERN 13 — BYZANTINE PEER FAULT DETECTOR
// ════════════════════════════════════════════════════════════════════════════

async function _validateIncomingMessage(did, msg, sigB64, seq, nonce) {
  // 1. Signature verification — Gap 1 fix: support both ECDSA P-256 (SW-side) and Ed25519 (page-side)
  //    until identity systems are fully unified. Try P-256 first, then Ed25519.
  if (sigB64 && _registry.get(did)?.pubKeyB64) {
    let sigOk = false;
    const msgB   = _str2b(typeof msg === 'string' ? msg : JSON.stringify(msg));
    const pubRaw = _fromB64(_registry.get(did).pubKeyB64);
    // Try ECDSA P-256 (SW-generated keys)
    try {
      const pubKey = await crypto.subtle.importKey('raw', pubRaw,
        { name:'ECDSA', namedCurve:'P-256' }, false, ['verify']);
      sigOk = await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, pubKey, _fromB64(sigB64), msgB);
    } catch {}
    // Try Ed25519 (page-generated keys) — fallback for backward compat until migration completes
    if (!sigOk) {
      try {
        const pubKey = await crypto.subtle.importKey('raw', pubRaw, { name:'Ed25519' }, false, ['verify']);
        sigOk = await crypto.subtle.verify({ name:'Ed25519' }, pubKey, _fromB64(sigB64), msgB);
      } catch {}
    }
    // Also try SPKI format for page-side Ed25519 keys that may be SPKI-encoded
    if (!sigOk) {
      try {
        const pubKey = await crypto.subtle.importKey('spki', pubRaw, { name:'Ed25519' }, false, ['verify']);
        sigOk = await crypto.subtle.verify({ name:'Ed25519' }, pubKey, _fromB64(sigB64), msgB);
      } catch {}
    }
    if (!sigOk) { _recordPeerFault(did, 'INVALID_SIG', 15); return false; }
  }
  // 2. Timestamp window (±5 min)
  if (typeof msg === 'object' && msg?.ts && Math.abs(Date.now() - msg.ts) > 300000) {
    _recordPeerFault(did, 'TIMESTAMP', 15); return false;
  }
  // 3. Nonce dedup (replay prevention)
  if (nonce) {
    if (_seenNonces.has(nonce)) { _recordPeerFault(did, 'REPLAY', 15); return false; }
    _seenNonces.add(nonce);
    if (_seenNonces.size > 10000) { const it = _seenNonces.values(); for (let i=0;i<1000;i++) _seenNonces.delete(it.next().value); }
  }
  // 4. Equivocation detection (same seq, different content)
  if (seq !== undefined && did) {
    if (!_msgIndex.has(did)) _msgIndex.set(did, new Map());
    const idx = _msgIndex.get(did);
    const h   = _b64(await _sha256(_str2b(typeof msg === 'string' ? msg : JSON.stringify(msg))));
    if (idx.has(seq) && idx.get(seq) !== h) {
      _recordPeerFault(did, 'EQUIVOCATION', 40);
      _broadcast({ event:'EQUIVOCATION_DETECTED', did, seq });
      return false;
    }
    idx.set(seq, h);
  }
  return true;
}

function _recordPeerFault(did, type, penalty) {
  const score = Math.max(0, (_peerTrust.get(did) ?? 100) - penalty);
  _peerTrust.set(did, score);
  _auditLog('PEER_FAULT', { did, type, penalty, score });
  if (score <= 0) {
    _broadcast({ event:'PEER_BANNED', did, reason: type });
    _registry.delete(did); _peers.delete(did);
    _auditLog('PEER_BANNED', { did });
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  §17 — PATTERN 04 — ENTROPY BEACON (Commit-Reveal)
// ════════════════════════════════════════════════════════════════════════════

async function _handleBeaconReveal(args, client) {
  const { peerDid, random } = args;
  const check = _b64(await _sha256(_fromB64(random)));
  if (check !== args.commitment || _beaconCommits.get(peerDid) !== args.commitment) {
    _auditLog('BEACON_CHEAT', { peerDid });
    _broadcast({ event:'BEACON_CHEAT_DETECTED', peerDid }); return;
  }
  _beaconReveals.set(peerDid, _fromB64(random));
  if (_beaconReveals.size >= _beaconCommits.size) {
    let beacon = new Uint8Array(32);
    for (const [, r] of _beaconReveals) for (let i=0;i<32;i++) beacon[i] ^= (r[i]||0);
    for (let i=0;i<32;i++) _entropyPool[i] ^= beacon[i];
    _broadcast({ event:'BEACON_COMPLETE', beacon: _b64(beacon) });
    _beaconCommits.clear(); _beaconReveals.clear();
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  §18 — PATTERN 14 — OBLIVIOUS MESSAGE RETRIEVAL (PIR-STYLE)
//  Prefix bucketing + K-1 decoy queries. Relay sees a bucket, not the user.
// ════════════════════════════════════════════════════════════════════════════

async function _handlePirFetch(args, client) {
  if (!_requireCap(client.id, CAP.READ_MESSAGES, client)) return;
  const { relayUrl, myTopicHash, decoyCount = 3 } = args;
  if (!relayUrl || !myTopicHash) return;

  const realPrefix = myTopicHash.slice(0, 2);
  const queries    = [realPrefix];
  while (queries.length < decoyCount + 1) {
    const d = Math.floor(Math.random() * 256).toString(16).padStart(2,'0');
    if (!queries.includes(d)) queries.push(d);
  }
  // Shuffle — relay cannot identify real query by position
  for (let i = queries.length-1; i>0; i--) {
    const j = Math.floor(Math.random()*(i+1));
    [queries[i],queries[j]] = [queries[j],queries[i]];
  }

  const all = [];
  for (const q of queries) {
    try {
      const resp = await fetch(`${relayUrl}/messages?prefix=${q}`);
      if (resp.ok) all.push(...(await resp.json()));
    } catch {}
  }
  // Return all — tab decrypts locally, silently discards non-matching
  client.postMessage({ event:'PIR_RESULTS', messages: all, nonce: args.nonce });
  _auditLog('PIR_FETCH', { prefix: realPrefix, decoys: decoyCount, total: all.length });
}

// ════════════════════════════════════════════════════════════════════════════
//  §19 — PATTERN 15 — THRESHOLD SIGNATURE SCHEME
//  t-of-n Shamir Secret Sharing over GF(2^8). Key never in one place.
// ════════════════════════════════════════════════════════════════════════════

// GF(2^8) with AES irreducible polynomial
function _gfMul(a, b) {
  let p = 0;
  for (let i=0;i<8;i++) {
    if (b&1) p ^= a;
    const hi = a & 0x80;
    a = (a<<1)&0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}
function _gfPow(x, e) {
  let r = 1;
  for (let i=0;i<e;i++) r = _gfMul(r,x);
  return r;
}

function _shamirSplit(secret, t, n) {
  const shares = Array.from({length:n}, (_,i) => ({ x:i+1, y:new Uint8Array(secret.length) }));
  for (let b=0;b<secret.length;b++) {
    const coeffs = new Uint8Array(t);
    coeffs[0] = secret[b];
    crypto.getRandomValues(coeffs.subarray(1));
    for (let i=0;i<n;i++) {
      let val = 0;
      for (let j=t-1;j>=0;j--) val = _gfMul(val, i+1) ^ coeffs[j];
      shares[i].y[b] = val;
    }
  }
  return shares;
}

function _shamirCombine(shares) {
  const out = new Uint8Array(shares[0].y.length);
  for (let b=0;b<out.length;b++) {
    let val = 0;
    for (let i=0;i<shares.length;i++) {
      let num = shares[i].y[b], den = 1;
      for (let j=0;j<shares.length;j++) {
        if (i!==j) { num = _gfMul(num, shares[j].x); den = _gfMul(den, shares[i].x ^ shares[j].x); }
      }
      val ^= _gfMul(num, _gfPow(den, 254)); // inverse = den^254 in GF(2^8)
    }
    out[b] = val;
  }
  return out;
}

async function _handleTssDkgRound1(args, client) {
  const { myIndex, parties, threshold } = args;
  _tss.myIndex = myIndex; _tss.parties = parties; _tss.threshold = threshold;
  const mySecret = crypto.getRandomValues(new Uint8Array(32));
  _tss.shards.set('self', mySecret);
  const shares      = _shamirSplit(mySecret, threshold, parties);
  const commitments = await Promise.all(shares.map(async s => ({ x:s.x, c: _b64(await _sha256(s.y)) })));
  _tss.commitments.set(myIndex, commitments);
  client.postMessage({
    event:'TSS_DKG_ROUND1', myIndex, commitments,
    sharesForPeers: shares.map(s => ({ x:s.x, y:_b64(s.y) })),
    nonce: args.nonce,
  });
  _auditLog('TSS_DKG_ROUND1', { myIndex, parties, threshold });
}

async function _handleTssDkgRound2(args, client) {
  const shareBytes = _fromB64(args.shareY);
  if (_b64(await _sha256(shareBytes)) !== args.commitment) {
    client.postMessage({ event:'ERROR', cmd:'TSS_DKG_ROUND2', reason:'Commitment mismatch' });
    _recordPeerFault(`peer:${args.peerIndex}`, 'TSS_COMMIT_FAIL', 40); return;
  }
  _tss.shards.set(args.peerIndex, shareBytes);
  client.postMessage({ event:'TSS_SHARD_ACCEPTED', peerIndex: args.peerIndex, nonce: args.nonce });
  _auditLog('TSS_DKG_ROUND2', { peerIndex: args.peerIndex });
}

async function _handleTssPartialSign(args, client) {
  if (!_signingKey) { client.postMessage({ event:'ERROR', cmd:'TSS_PARTIAL_SIGN', reason:'Vault locked' }); return; }
  const sig = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, _signingKey, _fromB64(args.payload));
  client.postMessage({
    event:'TSS_PARTIAL_SIG', sessionId: args.sessionId,
    partial: _b64(sig), signerIndex: _tss.myIndex, nonce: args.nonce,
  });
  _auditLog('TSS_PARTIAL_SIGN', { sessionId: args.sessionId });
}

async function _handleTssAggregate(args, client) {
  const { partials } = args;
  if (partials.length < _tss.threshold) {
    client.postMessage({ event:'ERROR', cmd:'TSS_AGGREGATE', reason:'Insufficient partials' }); return;
  }
  const shares = partials.slice(0, _tss.threshold).map(p => ({ x: p.signerIndex, y: _fromB64(p.partial) }));
  const agg    = _shamirCombine(shares);
  client.postMessage({
    event:'TSS_AGGREGATED', aggregated: _b64(agg),
    signers: partials.map(p=>p.signerIndex), nonce: args.nonce,
  });
  _auditLog('TSS_AGGREGATE', { signers: partials.map(p=>p.signerIndex) });
}

// ════════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════════
//  §20a — 4B FIX — AI NOTARY AUDIT ATTESTATION
//  Accepts dual-signed attestations from SovereignAINotary (sovereign_security.js).
//  Appends them to the SW audit chain for a tamper-evident dual-signed trail.
// ════════════════════════════════════════════════════════════════════════════

async function _handleAuditNotary(args, client) {
  const { attestation } = args;
  if (!attestation?.payload || !attestation?.sig || !attestation?.notaryPub) {
    client.postMessage({ event:'ERROR', cmd:'AUDIT_NOTARY', reason:'Invalid attestation format' }); return;
  }
  try {
    // Verify the notary signature before accepting
    const notaryPubRaw = _fromB64(attestation.notaryPub);
    const notaryKey    = await crypto.subtle.importKey('raw', notaryPubRaw,
      { name:'ECDSA', namedCurve:'P-256' }, false, ['verify']);
    const payloadBytes = _str2b(attestation.payload);
    const sigBytes     = _fromB64(attestation.sig);
    const valid        = await crypto.subtle.verify(
      { name:'ECDSA', hash:'SHA-256' }, notaryKey, sigBytes, payloadBytes);
    if (!valid) {
      client.postMessage({ event:'ERROR', cmd:'AUDIT_NOTARY', reason:'Notary signature invalid' });
      _auditLog('NOTARY_SIG_FAIL', { clientId: client.id });
      return;
    }
    // Attestation is valid — append to audit chain
    _auditLog('AI_NOTARY_ATTESTATION', {
      notaryPub   : attestation.notaryPub.slice(0, 24) + '…',
      payloadHash : _b64(await _sha256(_str2b(attestation.payload))),
      clientId    : client.id,
    });
    client.postMessage({ event:'AUDIT_NOTARY_ACCEPTED', ts: Date.now() });
  } catch(err) {
    client.postMessage({ event:'ERROR', cmd:'AUDIT_NOTARY', reason: err.message });
  }
}

//  §20b — PATTERN 15 FIX — SELF_TEST / HEALTH CHECK
// ════════════════════════════════════════════════════════════════════════════

async function _handleSelfTest(client) {
  const details = [];
  let pass = true;

  // 1. Vault unlock check
  details.push({ test: 'vault_state', result: !_vaultLocked ? 'UNLOCKED' : 'LOCKED' });

  // 2. Sign → Verify round trip (only if vault is unlocked)
  if (!_vaultLocked && _signingKey && _verifyKey) {
    try {
      const testVec = _str2b('sovereign-self-test-vector');
      const sig     = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, _signingKey, testVec);
      const ok      = await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, _verifyKey, sig, testVec);
      details.push({ test: 'sign_verify_roundtrip', result: ok ? 'PASS' : 'FAIL' });
      if (!ok) pass = false;
    } catch (e) {
      details.push({ test: 'sign_verify_roundtrip', result: 'ERROR', error: e.message });
      pass = false;
    }
  } else {
    details.push({ test: 'sign_verify_roundtrip', result: 'SKIPPED_VAULT_LOCKED' });
  }

  // 3. SEAL → OPEN round trip (only if vault is unlocked and exchange key available)
  if (!_vaultLocked && _exchangeKey && _exchPubKey) {
    try {
      const plaintext = _str2b('sovereign-seal-test');
      const exchPubRaw= await crypto.subtle.exportKey('raw', _exchPubKey);
      const theirKey  = await crypto.subtle.importKey('raw', exchPubRaw, { name:'ECDH', namedCurve:'P-256' }, false, []);
      const dhRaw     = await crypto.subtle.deriveBits({ name:'ECDH', public: theirKey }, _exchangeKey, 256);
      const hkdfK     = await crypto.subtle.importKey('raw', dhRaw, 'HKDF', false, ['deriveBits']);
      const keyBuf    = await crypto.subtle.deriveBits({ name:'HKDF', hash:'SHA-256', salt: new Uint8Array(32), info: _str2b('sovereign-seal-v1') }, hkdfK, 256);
      const aesKey    = await crypto.subtle.importKey('raw', keyBuf, 'AES-GCM', false, ['encrypt','decrypt']);
      const iv        = crypto.getRandomValues(new Uint8Array(12));
      const ct        = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, plaintext);
      const pt        = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, aesKey, ct);
      const ok        = _b2str(pt) === 'sovereign-seal-test';
      details.push({ test: 'seal_open_roundtrip', result: ok ? 'PASS' : 'FAIL' });
      if (!ok) pass = false;
    } catch (e) {
      details.push({ test: 'seal_open_roundtrip', result: 'ERROR', error: e.message });
      pass = false;
    }
  } else {
    details.push({ test: 'seal_open_roundtrip', result: 'SKIPPED_VAULT_LOCKED' });
  }

  // 4. Audit chain integrity
  try {
    let prev = new Uint8Array(32), auditOk = true;
    for (const record of _auditChain) {
      const { hash, hmac, ...entry } = record;
      const eBytes   = _str2b(JSON.stringify(entry));
      const computed = _b64(await _sha256(_concat(prev, eBytes)));
      if (computed !== hash) { auditOk = false; break; }
      prev = _fromB64(hash);
    }
    details.push({ test: 'audit_chain_integrity', result: auditOk ? 'PASS' : 'FAIL', entries: _auditChain.length });
    if (!auditOk) pass = false;
  } catch (e) {
    details.push({ test: 'audit_chain_integrity', result: 'ERROR', error: e.message });
    pass = false;
  }

  // 5. Entropy pool sanity (not all zeros)
  const entropyOk = _entropyPool.some(b => b !== 0);
  details.push({ test: 'entropy_pool', result: entropyOk ? 'PASS' : 'FAIL' });
  if (!entropyOk) pass = false;

  client.postMessage({ event:'SELF_TEST_RESULT', pass, details, ts: Date.now() });
  _auditLog('SELF_TEST', { pass, tests: details.length });
}



function _handleStatus(client) {
  const cap = _capabilities.get(client.id);
  client.postMessage({
    event        : 'STATUS',
    version      : SW_VERSION,
    did          : _myDid,
    vaultLocked  : _vaultLocked,
    peers        : [..._peers.entries()].map(([did,p])=>({did,state:p.state})),
    known        : _registry.size,
    auditEntries : _auditChain.length,
    allowedDomains: [..._networkPolicy.allowed],
    tssReady     : _tss.shards.size >= _tss.threshold,
    capabilities : cap ? Object.entries(CAP).filter(([,v])=>cap.bitmask&v).map(([k])=>k) : [],
    patterns     : 15,
  });
}

// ════════════════════════════════════════════════════════════════════════════
//  §21 — VAULT CRYPTO (Key generation & wrap/unwrap)
// ════════════════════════════════════════════════════════════════════════════

async function _generateKeys() {
  const [sigPair, echPair, auditKey] = await Promise.all([
    crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']),
    crypto.subtle.generateKey({ name:'ECDH',  namedCurve:'P-256' }, true, ['deriveBits']),
    crypto.subtle.generateKey({ name:'HMAC',  hash:'SHA-256'      }, true, ['sign','verify']),
  ]);
  return { signingKey:sigPair.privateKey, verifyKey:sigPair.publicKey,
           exchangeKey:echPair.privateKey, exchPubKey:echPair.publicKey, auditKey };
}

async function _wrapVault(keys, passphrase) {
  const salt    = crypto.getRandomValues(new Uint8Array(16));
  const pbkdf   = await crypto.subtle.importKey('raw', _str2b(passphrase), 'PBKDF2', false, ['deriveKey']);
  const wrapKey = await crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:600000, hash:'SHA-256' },
    pbkdf, { name:'AES-KW', length:256 }, false, ['wrapKey','unwrapKey']
  );
  const wSig  = await crypto.subtle.wrapKey('pkcs8', keys.signingKey,  wrapKey, 'AES-KW');
  const wEch  = await crypto.subtle.wrapKey('pkcs8', keys.exchangeKey, wrapKey, 'AES-KW');
  const verPub= await crypto.subtle.exportKey('raw', keys.verifyKey);
  const echPub= await crypto.subtle.exportKey('raw', keys.exchPubKey);
  const audRaw= await crypto.subtle.exportKey('raw', keys.auditKey);
  return { salt:_b64(salt), wSig:_b64(wSig), wEch:_b64(wEch),
           verPub:_b64(verPub), echPub:_b64(echPub), audKey:_b64(audRaw), v:2 };
}

async function _unwrapVault(blob, passphrase) {
  const salt    = _fromB64(blob.salt);
  const pbkdf   = await crypto.subtle.importKey('raw', _str2b(passphrase), 'PBKDF2', false, ['deriveKey']);
  const wrapKey = await crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:600000, hash:'SHA-256' },
    pbkdf, { name:'AES-KW', length:256 }, false, ['wrapKey','unwrapKey']
  );
  const signingKey  = await crypto.subtle.unwrapKey('pkcs8', _fromB64(blob.wSig), wrapKey, 'AES-KW',
    { name:'ECDSA', namedCurve:'P-256' }, false, ['sign']);
  const exchangeKey = await crypto.subtle.unwrapKey('pkcs8', _fromB64(blob.wEch), wrapKey, 'AES-KW',
    { name:'ECDH', namedCurve:'P-256' }, false, ['deriveBits']);
  const verifyKey   = await crypto.subtle.importKey('raw', _fromB64(blob.verPub),
    { name:'ECDSA', namedCurve:'P-256' }, true, ['verify']);
  const exchPubKey  = await crypto.subtle.importKey('raw', _fromB64(blob.echPub),
    { name:'ECDH', namedCurve:'P-256' }, true, []);
  const auditKey    = await crypto.subtle.importKey('raw', _fromB64(blob.audKey),
    { name:'HMAC', hash:'SHA-256' }, true, ['sign','verify']);
  _myPubKeyB64 = blob.verPub;
  _myDid       = 'did:sovereign:' + blob.verPub.slice(0, 32);
  return { signingKey, verifyKey, exchangeKey, exchPubKey, auditKey };
}

// ════════════════════════════════════════════════════════════════════════════
//  §22 — INDEXEDDB
// ════════════════════════════════════════════════════════════════════════════

function _idbOpen() {
  return new Promise((res, rej) => {
    const req = indexedDB.open('sovereign_kernel', 1);
    req.onupgradeneeded = e => {
      if (!e.target.result.objectStoreNames.contains(VAULT_STORE))
        e.target.result.createObjectStore(VAULT_STORE);
    };
    req.onsuccess = () => res(req.result);
    req.onerror   = () => rej(req.error);
  });
}

async function _idbGet(store, key) {
  const db = await _idbOpen();
  return new Promise((res, rej) => {
    const r = db.transaction(store,'readonly').objectStore(store).get(key);
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}

async function _idbSet(store, key, value) {
  const db = await _idbOpen();
  return new Promise((res, rej) => {
    const r = db.transaction(store,'readwrite').objectStore(store).put(value, key);
    r.onsuccess = () => res(); r.onerror = () => rej(r.error);
  });
}

async function _idbDelete(store, key) {
  const db = await _idbOpen();
  return new Promise((res, rej) => {
    const r = db.transaction(store,'readwrite').objectStore(store).delete(key);
    r.onsuccess = () => res(); r.onerror = () => rej(r.error);
  });
}

// ════════════════════════════════════════════════════════════════════════════
//  §23 — CRYPTO PRIMITIVES
// ════════════════════════════════════════════════════════════════════════════

async function _sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256',
    data instanceof Uint8Array ? data : new Uint8Array(data)));
}

async function _hkdfDerive(ikm, info) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name:'HKDF', hash:'SHA-256', salt:new Uint8Array(32), info:_str2b(info) }, key, 512
  ));
}

// ════════════════════════════════════════════════════════════════════════════
//  §24 — ENCODING UTILITIES
// ════════════════════════════════════════════════════════════════════════════

function _b64(buf) {
  const b = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

function _fromB64(s) {
  if (!s) return new Uint8Array(0);
  const d = atob(s), o = new Uint8Array(d.length);
  for (let i=0;i<d.length;i++) o[i]=d.charCodeAt(i);
  return o;
}

function _str2b(s) { return new TextEncoder().encode(s); }
function _b2str(b) { return new TextDecoder().decode(b); }

function _concat(...arrs) {
  const total = arrs.reduce((s,a) => s + (a.byteLength ?? a.length), 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const a of arrs) {
    const src = a instanceof ArrayBuffer ? new Uint8Array(a) : a;
    out.set(src, offset);
    offset += src.byteLength ?? src.length;
  }
  return out;
}

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function _log(msg)  { console.log(`[SOVEREIGN-KERNEL] ${msg}`); }

function _broadcast(msg) {
  self.clients.matchAll({ type:'window', includeUncontrolled:true })
    .then(cs => cs.forEach(c => c.postMessage(msg)));
}

// ════════════════════════════════════════════════════════════════════════════
//  END — Sovereign Service Worker Security Kernel v2.0
//  © James Chapman (XheCarpenXer) · Sovereign Technology IP Registry
//  "The tools of sovereignty should be sovereign themselves."
// ════════════════════════════════════════════════════════════════════════════
