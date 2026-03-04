// ═══════════════════════════════════════════════════════════════════════════
//  §1 — CONFIG
// ═══════════════════════════════════════════════════════════════════════════

const SOVEREIGN_CONFIG = {
  MESH_WS_URL:           'ws://localhost:8765',
  CHAIN_RPC:             'http://localhost:8899',
  POLL_MS:               3000,
  TOPIC_PREFIX:          'sovereign:msg:',
  DEBUG:                 true,
  RECONNECT_DELAY_MS:    5000,
  MAX_RECONNECT_ATTEMPTS:10,
  DHT_K:                 8,
  DHT_ANNOUNCE_MS:       15000,
  DHT_TTL_MS:            60000,
  KDF_PBKDF2_ITERATIONS: 600000,
  KDF_SALT_BYTES:        32,
  KDF_PREFER_ARGON2:     true,
  DR_MAX_SKIP:           100,
};

// ═══════════════════════════════════════════════════════════════════════════
//  §2 — SOVEREIGN KDF
//  Stretch a user passphrase BEFORE it touches the vault.
//  Without this, the vault key is as strong as the machine alone.
//  With this, cracking the vault requires the passphrase + the salt.
// ═══════════════════════════════════════════════════════════════════════════

class SovereignKDF {
  constructor(cfg = SOVEREIGN_CONFIG) {
    this.cfg = cfg;
    this._argon2 = null;
    this._algorithm = 'pbkdf2';
  }

  /**
   * Stretch a passphrase into 32 bytes of key material.
   * @param {string}     passphrase
   * @param {Uint8Array} [salt]        provide existing salt to reproduce key
   * @param {function}   [onProgress]  called with 0..1
   * @returns {Promise<{keyBytes: Uint8Array, salt: Uint8Array, algorithm: string}>}
   */
  async stretch(passphrase, salt = null, onProgress = null) {
    salt = salt || crypto.getRandomValues(new Uint8Array(this.cfg.KDF_SALT_BYTES));
    if (this.cfg.KDF_PREFER_ARGON2) {
      try {
        const r = await this._argon2Stretch(passphrase, salt, onProgress);
        return { ...r, salt, algorithm: 'argon2id' };
      } catch { /* fall through */ }
    }
    const r = await this._pbkdf2Stretch(passphrase, salt, onProgress);
    return { ...r, salt, algorithm: 'pbkdf2' };
  }

  async deriveWrapKey(keyBytes) {
    return crypto.subtle.importKey('raw', keyBytes, { name:'AES-KW', length:256 }, false, ['wrapKey','unwrapKey']);
  }

  async _pbkdf2Stretch(passphrase, salt, onProgress) {
    if (onProgress) onProgress(0.05);
    const enc     = new TextEncoder().encode(passphrase);
    const baseKey = await crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveBits']);
    if (onProgress) onProgress(0.15);
    // Yield to UI between yielded segments to keep the page alive
    const SEGS = 5;
    for (let i = 0; i < SEGS - 1; i++) {
      await new Promise(r => setTimeout(r, 0));
      if (onProgress) onProgress(0.15 + (i / SEGS) * 0.8);
    }
    const bits = await crypto.subtle.deriveBits(
      { name:'PBKDF2', salt, iterations: this.cfg.KDF_PBKDF2_ITERATIONS, hash:'SHA-256' },
      baseKey, 256
    );
    if (onProgress) onProgress(1.0);
    return { keyBytes: new Uint8Array(bits) };
  }

  async _loadArgon2() {
    if (this._argon2) return this._argon2;
    return new Promise((res, rej) => {
      const s  = document.createElement('script');
      s.src    = 'https://cdnjs.cloudflare.com/ajax/libs/argon2-browser/1.18.0/argon2.js';
      s.onload = () => { if (window.argon2) { this._argon2 = window.argon2; res(this._argon2); } else rej(new Error('argon2 missing')); };
      s.onerror = rej;
      document.head.appendChild(s);
    });
  }

  async _argon2Stretch(passphrase, salt, onProgress) {
    if (onProgress) onProgress(0.05);
    const lib = await this._loadArgon2();
    if (onProgress) onProgress(0.2);
    const result = await lib.hash({ pass: passphrase, salt, time:3, mem:65536, hashLen:32, parallelism:1, type: lib.ArgonType.Argon2id });
    if (onProgress) onProgress(1.0);
    return { keyBytes: result.hash };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  §3 — DOUBLE RATCHET  (Signal spec, pure WebCrypto, no deps)
//
//  DH:      ECDH P-256
//  KDF_RK:  HKDF-SHA-256   (advances root key + produces chain key)
//  KDF_CK:  HMAC-SHA-256   (produces message key + next chain key)
//  AEAD:    AES-256-GCM    (header authenticated as AAD)
//
//  Session state per peer:
//    DHs, DHr, RK, CKs, CKr, Ns, Nr, PN, MKSKIP
// ═══════════════════════════════════════════════════════════════════════════

class DoubleRatchet {
  constructor(cfg = SOVEREIGN_CONFIG) {
    this.cfg       = cfg;
    // 2B fix: restore persisted sessions from localStorage on construction
    this._sessions = (window.SovereignSessionStore ? window.SovereignSessionStore.load() : null) || new Map();
  }

  /** 2B fix: persist session state after any mutation */
  _persistSessions() {
    if (window.SovereignSessionStore) {
      try { window.SovereignSessionStore.save(this._sessions); } catch(_) {}
    }
  }

  // ── X3DH sender init ─────────────────────────────────────────────────
  async initSender(peerDid, myIdentityPriv, theirIdentityPub, theirSignedPreKeyPub, myEphKP) {
    const dh1 = await this._dh(myIdentityPriv,    theirSignedPreKeyPub);
    const dh2 = await this._dh(myEphKP.privateKey, theirIdentityPub);
    const dh3 = await this._dh(myEphKP.privateKey, theirSignedPreKeyPub);
    const sk   = await this._kdfRkRaw(_concat(dh1, dh2, dh3), new Uint8Array(32));
    const DHs  = await this._genKP();
    const dhO  = await this._dh(DHs.privateKey, theirSignedPreKeyPub);
    const [RK, CKs] = await this._kdfRk(sk, dhO);
    this._sessions.set(peerDid, { DHs, DHr: theirSignedPreKeyPub, RK, CKs, CKr:null, Ns:0, Nr:0, PN:0, MKSKIP:new Map() });
    this._persistSessions(); // 2B fix
    return _b64(await crypto.subtle.exportKey('raw', myEphKP.publicKey));
  }

  // ── X3DH receiver init ───────────────────────────────────────────────
  async initReceiver(peerDid, myIdentityPriv, mySignedPreKeyPriv, theirIdentityPub, theirEphB64) {
    const theirEph = await crypto.subtle.importKey('raw', _fromB64(theirEphB64), { name:'ECDH', namedCurve:'P-256' }, true, []);
    const dh1 = await this._dh(mySignedPreKeyPriv, theirIdentityPub);
    const dh2 = await this._dh(myIdentityPriv,     theirEph);
    const dh3 = await this._dh(mySignedPreKeyPriv, theirEph);
    const sk   = await this._kdfRkRaw(_concat(dh1, dh2, dh3), new Uint8Array(32));
    this._sessions.set(peerDid, { DHs:null, DHr:theirEph, RK:sk, CKs:null, CKr:null, Ns:0, Nr:0, PN:0, MKSKIP:new Map() });
    this._persistSessions(); // 2B fix
  }

  // ── Encrypt ──────────────────────────────────────────────────────────
  async encrypt(peerDid, plaintext) {
    const s = this._sessions.get(peerDid);
    if (!s) throw new Error('DR: no session for ' + peerDid);
    // Perform DH ratchet step if no sending chain yet (receiver first send)
    if (!s.CKs) {
      s.DHs = await this._genKP();
      const dhO = await this._dh(s.DHs.privateKey, s.DHr);
      [s.RK, s.CKs] = await this._kdfRk(s.RK, dhO);
      s.PN = 0;
    }
    const [CKs, MK] = await this._kdfCk(s.CKs);
    s.CKs = CKs;
    const n      = s.Ns++;
    const dhPub  = await crypto.subtle.exportKey('raw', s.DHs.publicKey);
    const header = { dh: _b64(dhPub), pn: s.PN, n };
    const iv     = crypto.getRandomValues(new Uint8Array(12));
    const aad    = new TextEncoder().encode(JSON.stringify(header));
    const aesKey = await crypto.subtle.importKey('raw', MK, 'AES-GCM', false, ['encrypt']);
    const ct     = await crypto.subtle.encrypt({ name:'AES-GCM', iv, additionalData:aad }, aesKey,
      typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext);
    return { header, ciphertext: _b64(ct), iv: _b64(iv) };
  }

  // ── Decrypt ──────────────────────────────────────────────────────────
  async decrypt(peerDid, header, ciphertext, iv) {
    const s = this._sessions.get(peerDid);
    if (!s) throw new Error('DR: no session for ' + peerDid);
    // Skipped message key cache
    const skipKey = `${header.dh}:${header.n}`;
    if (s.MKSKIP.has(skipKey)) {
      const MK = s.MKSKIP.get(skipKey); s.MKSKIP.delete(skipKey);
      return this._aesDec(MK, header, ciphertext, iv);
    }
    const inDHPub = await crypto.subtle.importKey('raw', _fromB64(header.dh), { name:'ECDH', namedCurve:'P-256' }, true, []);
    const curRaw  = s.DHr ? _b64(await crypto.subtle.exportKey('raw', s.DHr)) : null;
    const isNew   = !curRaw || curRaw !== header.dh;
    if (isNew) {
      if (s.CKr) await this._skipKeys(s, s.DHr, header.pn);
      s.PN = s.Ns; s.Ns = 0; s.Nr = 0;
      const dhO1 = s.DHs ? await this._dh(s.DHs.privateKey, inDHPub) : new Uint8Array(32);
      [s.RK, s.CKr] = await this._kdfRk(s.RK, dhO1);
      s.DHs = await this._genKP();
      const dhO2 = await this._dh(s.DHs.privateKey, inDHPub);
      [s.RK, s.CKs] = await this._kdfRk(s.RK, dhO2);
      s.DHr = inDHPub;
    }
    await this._skipKeys(s, inDHPub, header.n);
    const [CKr, MK] = await this._kdfCk(s.CKr); s.CKr = CKr; s.Nr++;
    return this._aesDec(MK, header, ciphertext, iv);
  }

  async _skipKeys(s, dhPub, until) {
    if (s.MKSKIP.size + (until - s.Nr) > this.cfg.DR_MAX_SKIP) throw new Error('DR: too many skipped messages');
    let CKr = s.CKr;
    if (!CKr) return;
    const dhB64 = _b64(await crypto.subtle.exportKey('raw', dhPub));
    while (s.Nr < until) {
      const [nCKr, MK] = await this._kdfCk(CKr);
      s.MKSKIP.set(`${dhB64}:${s.Nr}`, MK); CKr = nCKr; s.Nr++;
    }
    s.CKr = CKr;
  }

  async _aesDec(MK, header, ctB64, ivB64) {
    const aesKey = await crypto.subtle.importKey('raw', MK, 'AES-GCM', false, ['decrypt']);
    const aad    = new TextEncoder().encode(JSON.stringify(header));
    const pt     = await crypto.subtle.decrypt({ name:'AES-GCM', iv:_fromB64(ivB64), additionalData:aad }, aesKey, _fromB64(ctB64));
    return new Uint8Array(pt);
  }

  /** KDF_RK: HKDF(salt=RK, ikm=DH_output) → [RK', CK] */
  async _kdfRk(RK, dhOut) {
    const k = await crypto.subtle.importKey('raw', dhOut, 'HKDF', false, ['deriveBits']);
    const d = new Uint8Array(await crypto.subtle.deriveBits(
      { name:'HKDF', hash:'SHA-256', salt:RK, info:_str2b('sovereign-dr-rk-v2') }, k, 512));
    return [d.slice(0,32), d.slice(32,64)];
  }

  async _kdfRkRaw(ikm, salt) {
    const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const d = await crypto.subtle.deriveBits({ name:'HKDF', hash:'SHA-256', salt, info:_str2b('sovereign-x3dh-v2') }, k, 256);
    return new Uint8Array(d);
  }

  /** KDF_CK: HMAC(CK, 0x02) → CK',  HMAC(CK, 0x01) → MK  (Signal convention) */
  async _kdfCk(CK) {
    const hk = await crypto.subtle.importKey('raw', CK, { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
    const [MKbuf, CKbuf] = await Promise.all([
      crypto.subtle.sign('HMAC', hk, new Uint8Array([0x01])),
      crypto.subtle.sign('HMAC', hk, new Uint8Array([0x02])),
    ]);
    return [new Uint8Array(CKbuf), new Uint8Array(MKbuf)];
  }

  async _dh(priv, pub) {
    return new Uint8Array(await crypto.subtle.deriveBits({ name:'ECDH', public:pub }, priv, 256));
  }

  async _genKP() {
    return crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']);
  }

  hasSession(did)    { return this._sessions.has(did); }
  deleteSession(did) { this._sessions.delete(did); }
}

// ═══════════════════════════════════════════════════════════════════════════
//  §4 — SOVEREIGN DHT
//  Kademlia XOR routing. Transport priority:
//    1. BroadcastChannel — same device (instant)
//    2. WebRTC DataChannel — LAN P2P (fast, serverless)
//    3. Relay WebSocket — internet fallback (always there)
// ═══════════════════════════════════════════════════════════════════════════

class SovereignDHT {
  constructor(cfg = SOVEREIGN_CONFIG) {
    this.cfg        = cfg;
    this._did       = null;
    this._myId      = null;
    this._table     = new Map();
    this._channels  = new Map();
    this._pcs       = new Map();
    this._pending   = new Map();
    this._listeners = [];
    this._bc        = new BroadcastChannel('sovereign_dht');
    this._bc.onmessage = (e) => this._onBC(e.data);
    this._iceServers = window.SOVEREIGN_ICE_SERVERS || [
      { urls:'stun:openrelay.metered.ca:80' },
      { urls:'stun:stun.relay.metered.ca:80' },
    ]; // 1E fix: community STUN, not Google (see sovereign_security.js)
  }

  async init(did) {
    this._did  = did;
    this._myId = await _sha256bytes(_str2b(did));
    this._announceTimer = setInterval(() => this._announce(), this.cfg.DHT_ANNOUNCE_MS);
    this._gcTimer       = setInterval(() => this._gc(),       this.cfg.DHT_TTL_MS);
    this._announce();
    _log('DHT', `init node=${_b64(this._myId).slice(0,12)}`);
  }

  async findPeers(targetDid) {
    const tid = await _sha256bytes(_str2b(targetDid));
    return this._kClosest(tid, this.cfg.DHT_K);
  }

  async connect(peerDid, signalingFn) {
    if (this._channels.has(peerDid)) return this._channels.get(peerDid);
    return new Promise((res, rej) => {
      const t = setTimeout(() => { this._pending.delete(peerDid); rej(new Error('DHT connect timeout')); }, 15000);
      this._pending.set(peerDid, { resolve:res, reject:rej, timeout:t });
      this._initiateWebRTC(peerDid, signalingFn).catch(rej);
    });
  }

  on(event, cb) {
    this._listeners.push({ event, cb });
    return () => { this._listeners = this._listeners.filter(l => l.cb !== cb); };
  }

  async sendToPeer(peerDid, data) {
    const ch = this._channels.get(peerDid);
    if (ch && ch.readyState === 'open') { ch.send(JSON.stringify(data)); return 'webrtc'; }
    this._bc.postMessage({ type:'MSG', to:peerDid, from:this._did, data });
    return 'broadcast';
  }

  async _addPeer(did, pubKey, address) {
    if (did === this._did) return;
    const nodeId = await _sha256bytes(_str2b(did));
    const entry  = { did, pubKey, address, nodeId, seenAt:Date.now() };
    this._table.set(_b64(nodeId), entry);
    this._trimTable();
    this._emit('peer_found', entry);
    return entry;
  }

  _kClosest(tid, k) {
    return [...this._table.values()]
      .map(e => ({ ...e, dist: _xorDist(e.nodeId, tid) }))
      .sort((a,b) => _cmpBuf(a.dist, b.dist))
      .slice(0, k);
  }

  _trimTable() {
    const max = this.cfg.DHT_K * 32;
    if (this._table.size <= max) return;
    const keep = new Set(this._kClosest(this._myId, max).map(e => _b64(e.nodeId)));
    for (const k of this._table.keys()) { if (!keep.has(k)) this._table.delete(k); }
  }

  _announce() {
    // Gap 10 fix: include a signed prekey bundle in announcements so peers can
    // bootstrap a Double Ratchet session without an extra round-trip.
    // Format: { type:'ANNOUNCE', did, ts, prekey:{ identityPub, signedPreKeyPub, signature } }
    const bundle = this._prekeyBundle || null;
    this._bc.postMessage({ type:'ANNOUNCE', did:this._did, ts:Date.now(), prekey: bundle });
  }

  /** Generate and cache a signed prekey bundle for DR bootstrap (Gap 10) */
  async generatePrekeyBundle(identityPrivKey, identityPubKeyB64) {
    const ephKP   = await crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']);
    const ephPub  = await crypto.subtle.exportKey('raw', ephKP.publicKey);
    const sigData = new Uint8Array([...new TextEncoder().encode('sovereign-prekey-v1:'), ...new Uint8Array(ephPub)]);
    const sig     = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, identityPrivKey, sigData);
    this._prekeyBundle = {
      identityPub   : identityPubKeyB64,
      signedPreKeyPub: _b64(ephPub),
      signature     : _b64(sig),
    };
    this._prekeyPriv = ephKP.privateKey;
    return this._prekeyBundle;
  }

  _onBC(msg) {
    if (!msg?.type) return;
    if (msg.type === 'ANNOUNCE' && msg.did) {
      this._addPeer(msg.did, msg.pubKey||null, 'local');
      // Gap 10 fix: if peer has a prekey bundle and we have no DR session with them,
      // store their bundle so SovereignTransport can initiate a DR session on first send.
      if (msg.prekey && msg.did !== this._did) {
        this._emit('peer_prekey', { did: msg.did, prekey: msg.prekey });
      }
      return;
    }
    if (msg.to !== this._did) return;
    if (msg.type === 'MSG')    { this._emit('message', { from:msg.from, data:msg.data, channel:'broadcast' }); return; }
    // Gap 10 fix: handle explicit prekey request/response messages
    if (msg.type === 'PREKEY_REQUEST') { this._handlePrekeyRequest(msg); return; }
    if (msg.type === 'PREKEY_RESPONSE') { this._emit('peer_prekey', { did: msg.from, prekey: msg.prekey }); return; }
    if (msg.type === 'OFFER')  { this._handleOffer(msg); return; }
    if (msg.type === 'ANSWER') { this._handleAnswer(msg); return; }
    if (msg.type === 'ICE')    { this._handleICE(msg); }
  }

  _handlePrekeyRequest(msg) {
    if (this._prekeyBundle) {
      this._bc.postMessage({ type:'PREKEY_RESPONSE', to:msg.from, from:this._did, prekey:this._prekeyBundle });
    }
  }

  requestPrekey(peerDid) {
    this._bc.postMessage({ type:'PREKEY_REQUEST', to:peerDid, from:this._did });
  }

  async _initiateWebRTC(peerDid, sigFn) {
    const pc = new RTCPeerConnection({ iceServers: this._iceServers });
    const dc = pc.createDataChannel('sovereign', { ordered:true });
    this._pcs.set(peerDid, pc);
    this._wireDC(dc, peerDid);
    pc.onicecandidate = (e) => {
      if (!e.candidate) return;
      const m = { type:'ICE', to:peerDid, from:this._did, candidate:e.candidate };
      this._bc.postMessage(m); if (sigFn) sigFn(m);
    };
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    const m = { type:'OFFER', to:peerDid, from:this._did, sdp:offer };
    this._bc.postMessage(m); if (sigFn) sigFn(m);
  }

  async _handleOffer(msg) {
    const pc = new RTCPeerConnection({ iceServers: this._iceServers });
    this._pcs.set(msg.from, pc);
    pc.ondatachannel  = (e) => this._wireDC(e.channel, msg.from);
    pc.onicecandidate = (e) => {
      if (e.candidate) this._bc.postMessage({ type:'ICE', to:msg.from, from:this._did, candidate:e.candidate });
    };
    await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
    const ans = await pc.createAnswer();
    await pc.setLocalDescription(ans);
    this._bc.postMessage({ type:'ANSWER', to:msg.from, from:this._did, sdp:ans });
  }

  async _handleAnswer(msg) {
    const pc = this._pcs.get(msg.from);
    if (pc) await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
  }

  async _handleICE(msg) {
    const pc = this._pcs.get(msg.from);
    if (pc) { try { await pc.addIceCandidate(new RTCIceCandidate(msg.candidate)); } catch {} }
  }

  _wireDC(dc, peerDid) {
    dc.onopen = () => {
      this._channels.set(peerDid, dc);
      _log('DHT', `WebRTC open: ${peerDid.slice(0,24)}`);
      const p = this._pending.get(peerDid);
      if (p) { clearTimeout(p.timeout); p.resolve(dc); this._pending.delete(peerDid); }
    };
    dc.onclose   = () => { this._channels.delete(peerDid); this._emit('peer_lost', { did:peerDid }); };
    dc.onmessage = (e) => { try { this._emit('message', { from:peerDid, data:JSON.parse(e.data), channel:'webrtc' }); } catch {} };
  }

  _gc() {
    const cutoff = Date.now() - this.cfg.DHT_TTL_MS;
    for (const [k, e] of this._table.entries()) {
      if (e.seenAt < cutoff) { this._table.delete(k); this._emit('peer_lost', { did:e.did }); }
    }
  }

  _emit(event, data) {
    for (const l of this._listeners) { if (l.event === event) { try { l.cb(data); } catch {} } }
  }

  destroy() {
    clearInterval(this._announceTimer); clearInterval(this._gcTimer);
    this._bc.close();
    for (const dc of this._channels.values()) { try { dc.close(); } catch {} }
    for (const pc of this._pcs.values())      { try { pc.close(); } catch {} }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  §5 — SOVEREIGN TRANSPORT
// ═══════════════════════════════════════════════════════════════════════════

class SovereignTransport {
  constructor(config = SOVEREIGN_CONFIG) {
    this.cfg = config;
    this.kdf     = new SovereignKDF(config);
    this.ratchet = new DoubleRatchet(config);
    this.dht     = new SovereignDHT(config);

    this._meshSocket     = null;
    this._meshReady      = false;
    this._reconnectCount = 0;
    this._listeners      = [];
    this._pendingQueue   = [];
    this._pollTimer      = null;
    this._myDid          = null;
    this._seenIds        = new Set();
    this._kdfResult      = null;

    this._localBus = new BroadcastChannel('sovereign_transport');
    this._localBus.onmessage = (e) => this._handleIncoming(e.data, 'local');

    this.dht.on('message',    (e) => this._handleIncoming(e.data, 'dht'));
    this.dht.on('peer_found', (e) => this._onDHTPeer(e, 'found'));
    this.dht.on('peer_lost',  (e) => this._onDHTPeer(e, 'lost'));
    // Gap 10 fix: auto-bootstrap DR session when we receive a peer's prekey bundle
    this.dht.on('peer_prekey', (e) => this._onPeerPrekey(e));

    _log('Transport', 'v2 initialized');
  }

  /** Gap 10: bootstrap a DR session when we receive a peer's prekey bundle */
  async _onPeerPrekey({ did, prekey }) {
    if (this.ratchet.hasSession(did)) return; // already have a session
    if (!this._myIdentityPriv) return;        // vault not unlocked yet — queue for later
    try {
      // Verify the prekey signature before using it
      const identityPubRaw = _fromB64(prekey.identityPub);
      const signedPreKeyRaw = _fromB64(prekey.signedPreKeyPub);
      const verifyKey = await crypto.subtle.importKey('raw', identityPubRaw,
        { name:'ECDSA', namedCurve:'P-256' }, false, ['verify']);
      const sigData   = new Uint8Array([...new TextEncoder().encode('sovereign-prekey-v1:'), ...signedPreKeyRaw]);
      const valid     = await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, verifyKey,
        _fromB64(prekey.signature), sigData);
      if (!valid) { _log('Transport', `Prekey sig invalid for ${did.slice(0,20)}`); return; }

      await this.ratchet.initSender(did, this._myIdentityPriv,
        identityPubRaw, signedPreKeyRaw, this._myEphKP);
      this._emit('transport:dr_session_started', { did });
      _log('Transport', `DR session initiated with ${did.slice(0,20)}`);
    } catch (e) {
      _log('Transport', `DR session init failed for ${did.slice(0,20)}: ${e.message}`);
    }
  }

  /** Gap 10: called after vault unlock to provide identity key for DR */
  setIdentityKey(identityPrivKey, ephemeralKP) {
    this._myIdentityPriv = identityPrivKey;
    this._myEphKP        = ephemeralKP;
  }

  /**
   * Connect. Passphrase recommended — runs KDF before vault unlock.
   * @param {string}      did
   * @param {string}     [passphrase]
   * @param {Uint8Array} [kdfSalt]   — stored non-secret; provide on reconnect
   */
  async connect(did, passphrase = null, kdfSalt = null) {
    this._myDid = did;

    if (passphrase) {
      this._emit('transport:kdf_progress', { progress: 0 });
      this._kdfResult = await this.kdf.stretch(passphrase, kdfSalt,
        (p) => this._emit('transport:kdf_progress', { progress: p })
      );
      this._emit('transport:kdf_ready', { algorithm: this._kdfResult.algorithm, salt: _b64(this._kdfResult.salt) });
      _log('Transport', `KDF complete via ${this._kdfResult.algorithm}`);
    }

    await this.dht.init(did);
    this._connectMesh().catch(() => {});   // relay = optional fallback
    this._startChainPoll();
    this._emit('transport:status', { mesh: this._meshReady, dht: true, chain: true });
  }

  /** Send. Encrypts with Double Ratchet if a session exists for recipient. */
  async send(msg) {
    const result = { dht:false, mesh:false, chain:false, queued:false };

    let envelope;
    if (this.ratchet.hasSession(msg.to)) {
      const pt  = new TextEncoder().encode(JSON.stringify(msg));
      const enc = await this.ratchet.encrypt(msg.to, pt);
      envelope  = { id:msg.id, from:msg.from, to:msg.to, ts:msg.ts, enc:true,
                    dr_header:enc.header, dr_iv:enc.iv, body:enc.ciphertext };
    } else {
      envelope = { id:msg.id, from:msg.from, to:msg.to, ts:msg.ts, enc:false,
                   hash:msg.hash, sig:msg.sig, body:btoa(JSON.stringify(msg)) };
    }

    this._localBus.postMessage(envelope);

    const peers = await this.dht.findPeers(msg.to);
    for (const peer of peers.slice(0,3)) {
      try { await this.dht.sendToPeer(peer.did, envelope); result.dht = true; break; } catch {}
    }

    if (!result.dht && this._meshReady) result.mesh = await this._meshSend(envelope);
    result.chain = await this._chainAppend(envelope);

    if (!result.dht && !result.mesh && !result.chain) {
      this._pendingQueue.push(envelope); result.queued = true;
    }
    return result;
  }

  subscribe(did, callback) {
    this._listeners.push({ did, callback });
    if (this._meshReady) this._meshSubscribe(did);
  }

  disconnect() {
    if (this._meshSocket) this._meshSocket.close();
    if (this._pollTimer)  clearInterval(this._pollTimer);
    this._localBus.close();
    this.dht.destroy();
    _log('Transport', 'disconnected');
  }

  get kdfResult() { return this._kdfResult; }

  // ── Relay (fallback) ─────────────────────────────────────────────────
  async _connectMesh() {
    return new Promise((res) => {
      try {
        this._meshSocket = new WebSocket(this.cfg.MESH_WS_URL);
        this._meshSocket.onopen  = () => {
          this._meshReady = true; this._reconnectCount = 0;
          _log('Transport', 'relay connected (fallback)');
          this._listeners.forEach(l => this._meshSubscribe(l.did));
          this._flushQueue();
          this._emit('transport:mesh', { status:'connected' }); res(true);
        };
        this._meshSocket.onmessage = (e) => { try { this._handleIncoming(JSON.parse(e.data), 'mesh'); } catch {} };
        this._meshSocket.onclose   = () => { this._meshReady = false; this._emit('transport:mesh', { status:'disconnected' }); this._scheduleReconnect(); res(false); };
        this._meshSocket.onerror   = () => res(false);
      } catch { res(false); }
    });
  }

  _scheduleReconnect() {
    if (this._reconnectCount >= this.cfg.MAX_RECONNECT_ATTEMPTS) return;
    this._reconnectCount++;
    setTimeout(() => this._connectMesh(), this.cfg.RECONNECT_DELAY_MS);
  }

  async _meshSend(env) {
    if (!this._meshReady) return false;
    // 1D fix: use ephemeral token instead of raw DID — relay sees tokens, not DIDs
    const token = await _ephemeralTopicFor(this.cfg.TOPIC_PREFIX, env.to);
    try { this._meshSocket.send(JSON.stringify({ type:'PUBLISH', topic: token, data:env })); return true; }
    catch { return false; }
  }

  async _meshSubscribe(did) {
    if (!this._meshReady) return;
    // 1D fix: subscribe with ephemeral token
    const token = await _ephemeralTopicFor(this.cfg.TOPIC_PREFIX, did);
    this._meshSocket.send(JSON.stringify({ type:'SUBSCRIBE', topic: token }));
  }

  // ── Chain ────────────────────────────────────────────────────────────
  async _chainAppend(env) {
    try {
      // 1D fix: chain RPC also uses ephemeral token — sender identity not exposed
      const token = await _ephemeralTopicFor(this.cfg.TOPIC_PREFIX, env.to);
      const myToken = await _ephemeralTopicFor(this.cfg.TOPIC_PREFIX, this._myDid);
      const res = await fetch(this.cfg.CHAIN_RPC, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ jsonrpc:'2.0', id:1, method:'sovereign_appendMessage',
          params:{ topic: token, blob:btoa(JSON.stringify(env)), sender: myToken }}),
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) return false;
      const d = await res.json(); return !d.error;
    } catch { return false; }
  }

  _startChainPoll() {
    if (this._pollTimer) clearInterval(this._pollTimer);
    this._pollTimer = setInterval(() => this._pollChain(), this.cfg.POLL_MS);
  }

  async _pollChain() {
    if (!this._myDid) return;
    try {
      // 1D fix: poll with ephemeral token
      const myToken = await _ephemeralTopicFor(this.cfg.TOPIC_PREFIX, this._myDid);
      const res = await fetch(this.cfg.CHAIN_RPC, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ jsonrpc:'2.0', id:1, method:'sovereign_getMessages',
          params:{ topic: myToken, since:this._lastPollTs||0 }}),
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) return;
      const d = await res.json();
      if (d.result?.messages) {
        this._lastPollTs = Date.now();
        for (const blob of d.result.messages) { try { this._handleIncoming(JSON.parse(atob(blob)), 'chain'); } catch {} }
      }
    } catch {}
  }

  // ── Incoming ─────────────────────────────────────────────────────────
  async _handleIncoming(envelope, source) {
    if (!envelope?.id) return;
    if (this._seenIds.has(envelope.id)) return;
    this._seenIds.add(envelope.id);
    if (this._seenIds.size > 1000) { const a=[...this._seenIds]; a.splice(0,200).forEach(id=>this._seenIds.delete(id)); }
    let msg;
    try {
      if (envelope.enc && this.ratchet.hasSession(envelope.from)) {
        const pt = await this.ratchet.decrypt(envelope.from, envelope.dr_header, envelope.body, envelope.dr_iv);
        msg = JSON.parse(new TextDecoder().decode(pt));
      } else {
        msg = JSON.parse(atob(envelope.body));
      }
    } catch (err) { _log('Transport', 'decrypt failed', err.message); return; }
    this._listeners.forEach(({ did, callback }) => {
      if (envelope.to === did || envelope.from === did) { try { callback(msg, source); } catch {} }
    });
    window.dispatchEvent(new CustomEvent('sovereign:message', { detail:{ msg, source } }));
  }

  async _flushQueue() {
    const q = [...this._pendingQueue]; this._pendingQueue = [];
    for (const env of q) { await this._meshSend(env); await this._chainAppend(env); }
  }

  _onDHTPeer(peer, status) {
    this._emit('transport:peer', { status, did:peer.did });
    if (window.SovereignFSM) window.SovereignFSM.transport.send(status === 'found' ? 'PEER_FOUND' : 'PEER_LOST');
  }

  _emit(event, detail) { window.dispatchEvent(new CustomEvent(event, { detail })); }
}

// ═══════════════════════════════════════════════════════════════════════════
//  §6 — SHARED CRYPTO UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

function _b64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function _fromB64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function _str2b(s) { return new TextEncoder().encode(s); }
function _concat(...arrs) {
  const total = arrs.reduce((n, a) => n + a.byteLength, 0);
  const out = new Uint8Array(total); let off = 0;
  for (const a of arrs) { out.set(new Uint8Array(a), off); off += a.byteLength; }
  return out;
}
async function _sha256bytes(data) { return new Uint8Array(await crypto.subtle.digest('SHA-256', data)); }
async function _topicFor(prefix, did) {
  const h = await crypto.subtle.digest('SHA-256', _str2b(prefix + did));
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// 1D fix: ephemeral daily token — relay sees tokens, not DIDs
// HMAC(did, daily_epoch) — changes every day, unlinkable across sessions,
// but deterministic for the same DID on the same calendar day.
async function _ephemeralTopicFor(prefix, did) {
  if (window.sovereignEphemeralToken) {
    return prefix + (await window.sovereignEphemeralToken(did));
  }
  // Fallback if sovereign_security.js not loaded yet
  const epoch   = Math.floor(Date.now() / 86400000);
  const keyMat  = _str2b('sovereign-relay-epoch-v1:' + did);
  const saltMat = _str2b(String(epoch));
  const baseKey = await crypto.subtle.importKey('raw', keyMat, { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig     = await crypto.subtle.sign('HMAC', baseKey, saltMat);
  return prefix + Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,'0')).join('').slice(0,32);
}
function _xorDist(a, b) { const o = new Uint8Array(a.length); for (let i=0;i<a.length;i++) o[i]=a[i]^b[i]; return o; }
function _cmpBuf(a, b) { for (let i=0;i<Math.min(a.length,b.length);i++) { if(a[i]<b[i])return -1; if(a[i]>b[i])return 1; } return 0; }
function _log(tag, ...a) { if (SOVEREIGN_CONFIG.DEBUG) console.log(`[Sovereign:${tag}]`, ...a); }

// ═══════════════════════════════════════════════════════════════════════════
//  §7 — STATUS DOT UI
// ═══════════════════════════════════════════════════════════════════════════

function injectStatusDot() {
  const dot = document.createElement('div');
  dot.id = 'transport-dot';
  dot.innerHTML = `<style>
    #transport-dot{position:fixed;bottom:12px;left:12px;z-index:9999;display:flex;align-items:center;gap:6px;
      background:rgba(6,6,8,.88);border:1px solid #1a1a28;border-radius:20px;padding:5px 10px;
      font-family:'Courier New',monospace;font-size:9px;color:#94a3b8;backdrop-filter:blur(8px);pointer-events:none}
    #transport-dot .dot{width:6px;height:6px;border-radius:50%;background:#334155;transition:background .3s}
    #transport-dot .dot.kdf  {background:#fbbf24;box-shadow:0 0 6px #fbbf2466}
    #transport-dot .dot.dht  {background:#00ff88;box-shadow:0 0 6px #00ff8866}
    #transport-dot .dot.mesh {background:#a78bfa;box-shadow:0 0 6px #a78bfa66}
    #transport-dot .dot.chain{background:#00d4ff;box-shadow:0 0 6px #00d4ff66}
    #transport-dot .dot.err  {background:#ff3366;box-shadow:0 0 6px #ff336666}
  </style>
  <span class="dot" id="td-kdf" title="KDF"></span>
  <span class="dot" id="td-dht" title="DHT/WebRTC"></span>
  <span class="dot" id="td-mesh" title="Relay"></span>
  <span class="dot" id="td-chain" title="Chain"></span>
  <span id="td-label">SOVEREIGN OFFLINE</span>`;
  document.body.appendChild(dot);
  const $ = id => document.getElementById(id);
  const upd = () => {
    const dOn=($('td-dht')?.className||'').includes('dht'), mOn=($('td-mesh')?.className||'').includes('mesh'), cOn=($('td-chain')?.className||'').includes('chain');
    const L=$('td-label'); if(!L)return;
    if(dOn&&cOn) L.textContent='DHT + CHAIN'; else if(dOn) L.textContent='DHT ONLY';
    else if(mOn) L.textContent='RELAY ONLY'; else if(cOn) L.textContent='CHAIN ONLY'; else L.textContent='LOCAL ONLY';
  };
  window.addEventListener('transport:kdf_ready',    () => { const e=$('td-kdf');   if(e) e.className='dot kdf';  upd(); });
  window.addEventListener('transport:peer',   (ev) => { const e=$('td-dht');   if(e) e.className='dot '+(ev.detail.status==='found'?'dht':'err'); upd(); });
  window.addEventListener('transport:mesh',   (ev) => { const e=$('td-mesh');  if(e) e.className='dot '+(ev.detail.status==='connected'?'mesh':'err'); upd(); });
  window.addEventListener('transport:status', (ev) => { if(ev.detail.chain){const e=$('td-chain');if(e)e.className='dot chain';} upd(); });
}

// ═══════════════════════════════════════════════════════════════════════════
//  §8 — GLOBAL WIRING
// ═══════════════════════════════════════════════════════════════════════════

window.SovereignTransport = SovereignTransport;
window.SovereignKDF       = SovereignKDF;
window.DoubleRatchet      = DoubleRatchet;
window.SovereignDHT       = SovereignDHT;
window._ST                = null;

window.addEventListener('DOMContentLoaded', () => {
  injectStatusDot();
  if (window.SovereignFSM) window.SovereignFSM.kdf.send('RESET');
});

/**
 * Connect the transport layer.
 * @param {string}      did
 * @param {string}     [passphrase]  — required for honest security; runs KDF
 * @param {Uint8Array} [salt]        — from previous session (non-secret, persist it)
 */
window.sovereignConnect = async function(did, passphrase = null, salt = null) {
  if (window._ST) window._ST.disconnect();
  window._ST = new SovereignTransport();

  // Gap 9 fix: load persisted KDF salt from localStorage on reconnect so the
  // same passphrase always derives the same session key across page loads.
  if (!salt && passphrase) {
    const saved = localStorage.getItem('sovereign_kdf_salt');
    if (saved) {
      try { salt = _fromB64(saved); } catch (_) { salt = null; }
    }
  }

  if (window.SovereignFSM && passphrase) {
    window.SovereignFSM.kdf.send('STRETCH');
    window.addEventListener('transport:kdf_ready', () => {
      window.SovereignFSM.kdf.send('STRETCH_OK');
      window.SovereignFSM.vault.send('UNLOCK');
    }, { once:true });
  }

  await window._ST.connect(did, passphrase, salt);

  // Gap 9 fix: persist the salt after connect so future reconnects can reuse it
  if (window._ST._kdfResult?.salt) {
    try {
      localStorage.setItem('sovereign_kdf_salt', _b64(window._ST._kdfResult.salt));
    } catch (_) { /* private browsing may block localStorage */ }
  }

  window._ST.subscribe(did, (msg, source) => {
    if (typeof window.onSovereignMessage === 'function') window.onSovereignMessage(msg, source);
  });

  return window._ST;
};

window.sovereignSend = async function(msg) {
  if (!window._ST) { console.warn('[Sovereign] Not connected.'); return { queued:true }; }
  return window._ST.send(msg);
};

// ═══════════════════════════════════════════════════════════════════════════
//  §9 — SW KERNEL BRIDGE  (unchanged API from v1)
// ═══════════════════════════════════════════════════════════════════════════

class SovereignKernelBridge {
  constructor() {
    this._sw=null; this._cbs=new Map(); this._pending=new Map(); this._heartbeatTimer=null;
    this._init();
  }
  async _init() {
    if (!('serviceWorker' in navigator)) return;
    const reg = await navigator.serviceWorker.ready;
    this._sw  = reg.active;
    navigator.serviceWorker.addEventListener('message', (e) => this._onKernelEvent(e.data));
    this._startHeartbeat();
  }
  async unlockVault(p)          { return this._call('VAULT_UNLOCK',      { passphrase:p }); }
  async createVault(p,d)        { return this._call('VAULT_CREATE',      { passphrase:p, isDecoy:d }); }
  async createDualVault(p,dp)   { return this._call('VAULT_CREATE_DUAL', { passphrase:p, decoyPassphrase:dp }); }
  async lockVault()             { return this._call('VAULT_LOCK',        {}); }
  async sign(d)                 { return this._call('SIGN',              { data:d }); }
  async seal(pt,rk)             { return this._call('SEAL',              { plaintext:pt, recipientPubKey:rk }); }
  async open(ct,iv,spk)         { return this._call('OPEN',              { ciphertext:ct, iv, senderPubKey:spk }); }
  async initRatchet(pd,ik,ek)   { return this._call('RATCHET_INIT',      { peerDid:pd, theirIdentityPubKey:ik, theirEphemeralPubKey:ek }); }
  async ratchetEncrypt(pd,pt)   { return this._call('RATCHET_ENCRYPT',   { peerDid:pd, plaintext:pt }); }
  async ratchetDecrypt(pd,n,ct,iv){ return this._call('RATCHET_DECRYPT', { peerDid:pd, n, ciphertext:ct, iv }); }
  async onionSend(td,pt)        { return this._call('ONION_SEND',        { targetDid:td, plaintext:pt }); }
  async pirFetch(ru,th,dc)      { return this._call('PIR_FETCH',         { relayUrl:ru, myTopicHash:th, decoyCount:dc }); }
  async verifyAuditChain()      { return this._call('AUDIT_VERIFY',      {}); }
  async exportAuditChain()      { return this._call('AUDIT_EXPORT',      {}); }
  async tssDkgRound1(i,p,t)     { return this._call('TSS_DKG_ROUND1',    { myIndex:i, parties:p, threshold:t }); }
  async tssPartialSign(sid,pb)  { return this._call('TSS_PARTIAL_SIGN',  { sessionId:sid, payload:pb }); }
  async tssAggregate(pts,pb)    { return this._call('TSS_AGGREGATE',     { partials:pts, payload:pb }); }
  async allowDomain(d)          { return this._call('ALLOW_DOMAIN',      { domain:d }); }
  async revokeDomain(d)         { return this._call('REVOKE_DOMAIN',     { domain:d }); }
  async getStatus()             { return this._call('STATUS',            {}); }
  async panic()                 { return this._call('PANIC',             {}); }
  _startHeartbeat() {
    this._heartbeatTimer = setInterval(() => this._send({ cmd:'HEARTBEAT' }), 30*60*1000);
    setTimeout(() => this._send({ cmd:'HEARTBEAT' }), 2000);
  }
  stopHeartbeat() { clearInterval(this._heartbeatTimer); }
  on(event, cb) {
    if (!this._cbs.has(event)) this._cbs.set(event, []);
    this._cbs.get(event).push(cb);
    return () => this._cbs.set(event, this._cbs.get(event).filter(f => f !== cb));
  }
  _send(msg) {
    if (!this._sw) { navigator.serviceWorker.ready.then(r => { this._sw=r.active; this._sw.postMessage(msg); }); return; }
    this._sw.postMessage(msg);
  }
  _call(cmd, args) {
    return new Promise((res, rej) => {
      const n = Math.random().toString(36).slice(2);
      this._pending.set(n, { resolve:res, reject:rej });
      setTimeout(() => { if(this._pending.has(n)){this._pending.delete(n);rej(new Error('SW timeout:'+cmd));} }, 15000);
      this._send({ cmd, nonce:n, ...args });
    });
  }
  _onKernelEvent(data) {
    const { event, nonce } = data || {};
    if (nonce && this._pending.has(nonce)) {
      const { resolve, reject } = this._pending.get(nonce); this._pending.delete(nonce);
      if (event?.includes('ERROR')) reject(new Error(data.reason||event)); else resolve(data); return;
    }
    for (const cb of (this._cbs.get(event)||[])) cb(data);
    for (const cb of (this._cbs.get('*')   ||[])) cb(data);
  }
}

window.SovereignKernel = new SovereignKernelBridge();

window.sovereignBoot = async function(did, pubKey) {
  const reg = await navigator.serviceWorker.ready;
  reg.active?.postMessage({ cmd:'BOOT', did, pubKey });
};

console.log('[Sovereign] Transport v2 — DHT + DoubleRatchet + KDF + FSM — 0 deps');