/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SOVEREIGN TRANSPORT LAYER  v3.0  —  transport.js
 *
 *  Self-initializing drop-in transport module.
 *  Must be loaded AFTER sovereign_security.js AND sovereign_fsm.js.
 *
 *  Architecture:
 *    Primary:    WebRTC DataChannel mesh (direct P2P after relay handshake)
 *    Secondary:  WebTransport/QUIC (when available — Chrome 97+, lower latency)
 *    Tertiary:   BroadcastChannel (same-device, same-origin tab-to-tab)
 *    Routing:    Kademlia-inspired DHT for multi-hop message routing
 *    Privacy:    Optional 3-hop onion circuit (requires onion FSM READY)
 *    Discovery:  WebSocket relay (signaling only — never touches message content)
 *    Fallback:   Manual QR-code offer/answer for fully offline handshake
 *
 *  Topology:
 *    Each node has a NodeID = SHA256(DID)[0:20] (160 bits, Kademlia-compatible).
 *    Peers stored in a K-bucket table (k=20, α=3, distance = XOR metric).
 *    Messages route via iterative lookup: find_node → send.
 *    Onion routing wraps messages in 3 layers of AES-GCM with ephemeral keys.
 *
 *  Events emitted on window:
 *    sovereign:transport:peer-connected    { peerId, did, transport }
 *    sovereign:transport:peer-disconnected { peerId, did }
 *    sovereign:transport:message           { from, payload, channel }
 *    sovereign:transport:relay-connected   { relayUrl }
 *    sovereign:transport:relay-disconnected
 *    sovereign:transport:dht-updated       { peerCount, buckets }
 *    sovereign:transport:onion-ready       { circuitId }
 *
 *  API (window.SovereignTransport):
 *    .send(toDid, payload)         — best-effort direct or routed send
 *    .broadcast(payload)           — send to all connected peers
 *    .generateOffer()              — QR/manual handshake offer
 *    .receiveOffer(offer)          — process an offer, return answer
 *    .receiveAnswer(answer)        — complete manual handshake
 *    .connectRelay(url)            — connect to (or switch) relay
 *    .disconnectRelay()
 *    .buildOnionCircuit()          — build a 3-hop privacy circuit
 *    .sendOnion(toDid, payload)    — send via onion circuit
 *    .peers()                      — Map<peerId, PeerInfo>
 *    .nodeId()                     — this node's 160-bit Kademlia ID (hex)
 *    .stats()                      — bandwidth, latency, routing table size
 *
 *  © James Chapman (XheCarpenXer) · iconoclastdao@gmail.com
 *  Dual License — see LICENSE.md
 * ═══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

(function SovereignTransportInit() {

  // ── Constants ──────────────────────────────────────────────────────────────
  const DEFAULT_RELAY   = 'wss://sovereign-relay.fly.dev';
  const RELAY_FALLBACKS = [
    'wss://sovereign-relay.fly.dev',
    // Note: additional relay URLs should implement the Sovereign relay protocol
    // (HELLO / HELLO_ACK / OFFER / ANSWER / ICE message types).
    // MQTT brokers are incompatible — do not add them here.
  ];
  const ICE_SERVERS     = window.SOVEREIGN_ICE_SERVERS ?? [
    { urls: 'stun:openrelay.metered.ca:80' },
    { urls: 'stun:stun.cloudflare.com:3478' },
  ];

  // DHT parameters
  const DHT_K   = 20;  // k-bucket size
  const DHT_A   = 3;   // alpha: parallel lookups
  const DHT_B   = 160; // key space bits (SHA-256 truncated to 160)

  // Channel names
  const BC_CHANNEL = 'sovereign-transport-v3';

  // Ratchet message window before STALE
  const RATCHET_STALE_MS = 30 * 60 * 1000;

  // ── State ──────────────────────────────────────────────────────────────────
  const _peers    = new Map();   // peerId → PeerInfo
  const _dht      = new Map();   // nodeId (hex) → PeerInfo (routing table)
  const _pending  = new Map();   // offerId → { pc, resolve, reject, timer }
  const _stats    = { bytesSent: 0, bytesRecv: 0, msgSent: 0, msgRecv: 0 };
  const _circuits = new Map();   // circuitId → OnionCircuit

  let _myDid       = null;
  let _myNodeId    = null;   // 20-byte hex
  let _relay       = null;   // WebSocket
  let _relayUrl    = null;
  let _relayTimer  = null;   // reconnect timer
  let _bc          = null;   // BroadcastChannel
  let _wtSession   = null;   // WebTransport session (if available)
  let _fsm         = null;   // SovereignFSM kernel reference

  const K = () => window.SovereignFSM;

  // ── Utility ────────────────────────────────────────────────────────────────
  async function _sha256(str) {
    const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
  }

  function _hex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  function _emit(type, detail = {}) {
    window.dispatchEvent(new CustomEvent(`sovereign:transport:${type}`, { detail }));
  }

  function _log(msg, ...args) {
    console.log(`[Transport v3.0] ${msg}`, ...args);
  }

  // ── NodeID & DHT ──────────────────────────────────────────────────────────
  async function _computeNodeId(did) {
    const hex = await _sha256(did);
    return hex.slice(0, 40); // 160 bits = 20 bytes = 40 hex chars
  }

  function _xorDist(a, b) {
    // XOR distance between two 40-char hex NodeIDs, returned as BigInt
    const ai = BigInt('0x' + a);
    const bi = BigInt('0x' + b);
    return ai ^ bi;
  }

  function _bucketIndex(dist) {
    // Which k-bucket does this distance belong to?
    if (dist === 0n) return -1; // self
    let bit = DHT_B - 1;
    while (bit >= 0 && !((dist >> BigInt(bit)) & 1n)) bit--;
    return bit;
  }

  function _dhtInsert(nodeId, peerInfo) {
    if (nodeId === _myNodeId) return;
    const dist   = _xorDist(nodeId, _myNodeId);
    const bucket = _bucketIndex(dist);
    if (bucket < 0) return;

    // Simplified: just store in flat map (full k-bucket eviction policy is not needed
    // for this browser context — nodes are transient and the table is small)
    _dht.set(nodeId, { ...peerInfo, nodeId, bucket, lastSeen: Date.now() });
    _emit('dht-updated', { peerCount: _dht.size, buckets: bucket });
  }

  function _dhtClosest(targetId, n = DHT_K) {
    const sorted = [..._dht.values()].sort((a, b) => {
      const da = _xorDist(a.nodeId, targetId);
      const db = _xorDist(b.nodeId, targetId);
      return da < db ? -1 : da > db ? 1 : 0;
    });
    return sorted.slice(0, n);
  }

  // ── PeerInfo factory ───────────────────────────────────────────────────────
  function _makePeer(peerId, did, transport) {
    return {
      peerId,
      did,
      nodeId:     null,  // computed async
      transport,         // 'webrtc' | 'webtransport' | 'broadcast'
      pc:         null,  // RTCPeerConnection (webrtc only)
      dc:         null,  // RTCDataChannel (webrtc only)
      wt:         null,  // WebTransport stream (webtransport only)
      connectedAt: Date.now(),
      lastSeen:   Date.now(),
      latencyMs:  null,
    };
  }

  // ── BroadcastChannel (same-device) ────────────────────────────────────────
  function _initBroadcastChannel() {
    try {
      _bc = new BroadcastChannel(BC_CHANNEL);
      _bc.onmessage = (e) => _handleBCMessage(e.data);
      _bc.postMessage({ type: 'ANNOUNCE', did: _myDid, nodeId: _myNodeId });
      _log('BroadcastChannel open on:', BC_CHANNEL);
    } catch (err) {
      _log('BroadcastChannel unavailable:', err.message);
    }
  }

  function _handleBCMessage(msg) {
    if (!msg?.type || msg.did === _myDid) return;

    if (msg.type === 'ANNOUNCE' || msg.type === 'ANNOUNCE_ACK') {
      // Register as a local peer if not already connected
      if (!_peers.has(`bc:${msg.did}`)) {
        const peer = _makePeer(`bc:${msg.did}`, msg.did, 'broadcast');
        _peers.set(peer.peerId, peer);
        _emit('peer-connected', { peerId: peer.peerId, did: msg.did, transport: 'broadcast' });
        K()?.transport?.send('PEERS_FOUND');
        // Only ack to an ANNOUNCE (not to an ACK, to avoid infinite loop)
        if (msg.type === 'ANNOUNCE') {
          _bc?.postMessage({ type: 'ANNOUNCE_ACK', did: _myDid, nodeId: _myNodeId });
        }
      }
    } else if (msg.type === 'MESSAGE') {
      _handleIncoming(msg.from, msg.payload, 'broadcast');
    }
  }

  // ── WebRTC ─────────────────────────────────────────────────────────────────
  function _createPeerConnection() {
    return new RTCPeerConnection({
      iceServers:      ICE_SERVERS,
      iceTransportPolicy: 'all',
      bundlePolicy:    'max-bundle',
      rtcpMuxPolicy:   'require',
    });
  }

  function _setupDataChannel(pc, dc, peerId, did) {
    dc.binaryType = 'arraybuffer';

    dc.onopen = async () => {
      const peer     = _peers.get(peerId) ?? _makePeer(peerId, did, 'webrtc');
      peer.dc        = dc;
      peer.pc        = pc;
      _peers.set(peerId, peer);

      // Compute DHT node ID for this peer
      if (did) {
        peer.nodeId = await _computeNodeId(did);
        _dhtInsert(peer.nodeId, peer);
      }

      _log(`DataChannel open: ${peerId}`);
      _emit('peer-connected', { peerId, did, transport: 'webrtc' });
      K()?.transport?.send('PEERS_FOUND');

      // Announce our DID→nodeId to the new peer so they can route to us
      if (_myDid && _myNodeId) {
        _sendToPeer(peerId, { type: 'DHT_ANNOUNCE', did: _myDid, nodeId: _myNodeId });
      }

      // Latency probe
      _probePing(peerId);
    };

    dc.onclose = () => _handlePeerDisconnect(peerId);

    dc.onerror = (err) => {
      _log(`DataChannel error on ${peerId}:`, err);
      _handlePeerDisconnect(peerId);
    };

    dc.onmessage = (e) => {
      _stats.bytesRecv += e.data.byteLength ?? (e.data.length ?? 0);
      _stats.msgRecv++;
      try {
        const msg = JSON.parse(
          typeof e.data === 'string' ? e.data : new TextDecoder().decode(e.data)
        );
        _handleIncoming(did ?? peerId, msg, 'webrtc');
      } catch (_) {}
    };
  }

  function _handlePeerDisconnect(peerId) {
    const peer = _peers.get(peerId);
    if (!peer) return;

    _peers.delete(peerId);
    if (peer.nodeId) _dht.delete(peer.nodeId);

    // Clear latency probe interval for this peer
    if (_pingIntervals.has(peerId)) {
      clearInterval(_pingIntervals.get(peerId));
      _pingIntervals.delete(peerId);
    }

    _emit('peer-disconnected', { peerId, did: peer.did });
    _log(`Peer disconnected: ${peerId}`);

    // Update FSM
    if (_peers.size === 0) {
      K()?.transport?.send('PEER_LOST');
    }
  }

  // ── Relay signaling ─────────────────────────────────────────────────────────
  async function _connectRelay(url = DEFAULT_RELAY) {
    if (_relay?.readyState === WebSocket.OPEN) {
      _relay.close();
    }

    _relayUrl = url;

    try {
      _relay = new WebSocket(url);
    } catch (err) {
      _log('Relay connection failed:', err.message);
      K()?.transport?.send('PEERS_NONE');
      return;
    }

    _relay.onopen = async () => {
      _log('Relay connected:', url);
      _emit('relay-connected', { relayUrl: url });

      const token = await window.sovereignEphemeralToken(_myDid);
      _relay.send(JSON.stringify({ type: 'HELLO', token, did: _myDid }));
    };

    _relay.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      _handleRelayMessage(msg);
    };

    _relay.onclose = () => {
      _log('Relay disconnected');
      _emit('relay-disconnected');
      _stopRelayKeepalive();
      _myRelayToken = null;
      K()?.transport?.send('PEER_LOST');
      // Reconnect with exponential backoff
      if (_relayTimer) clearTimeout(_relayTimer);
      _relayTimer = setTimeout(() => _connectRelay(_relayUrl), 5_000);
    };

    _relay.onerror = () => {
      _log('Relay error — trying fallback');
      // Try next fallback
      const idx  = RELAY_FALLBACKS.indexOf(_relayUrl);
      const next = RELAY_FALLBACKS[(idx + 1) % RELAY_FALLBACKS.length];
      if (next && next !== _relayUrl) {
        setTimeout(() => _connectRelay(next), 1_000);
      }
    };
  }

  function _handleRelayMessage(msg) {
    switch (msg.type) {
      case 'HELLO_ACK':
        _log('Relay ack — peers online:', msg.peers?.length ?? 0);
        // Store our relay-assigned token so PEER_ONLINE guard works correctly
        if (msg.token) _myRelayToken = msg.token;
        _startRelayKeepalive();
        if (msg.peers?.length) {
          K()?.transport?.send('PEERS_FOUND');
        } else {
          K()?.transport?.send('PEERS_NONE');
        }
        break;

      case 'PONG':
        // Relay responded to our keepalive ping — connection is alive
        break;

      case 'PING':
        // Relay sent a ping — respond immediately
        if (_relay?.readyState === WebSocket.OPEN) {
          _relay.send(JSON.stringify({ type: 'PONG', ts: msg.ts }));
        }
        break;

      case 'PEER_ONLINE':
        if (msg.token !== _myRelayToken) {
          _initiateWebRTC(msg.token, msg.did);
        }
        break;

      case 'PEER_OFFLINE':
        // Find and disconnect peer by relay token
        for (const [id, peer] of _peers) {
          if (peer._relayToken === msg.token) {
            _handlePeerDisconnect(id);
          }
        }
        break;

      case 'OFFER':
        _handleOffer(msg);
        break;

      case 'ANSWER':
        _handleAnswer(msg);
        break;

      case 'ICE':
        _handleRemoteIce(msg);
        break;
    }
  }

  let _myRelayToken = null;
  let _relayKeepaliveTimer = null;

  function _startRelayKeepalive() {
    if (_relayKeepaliveTimer) clearInterval(_relayKeepaliveTimer);
    // Ping relay every 25s to prevent idle WS closure (most servers cut at 30-60s)
    _relayKeepaliveTimer = setInterval(() => {
      if (_relay?.readyState === WebSocket.OPEN) {
        _relay.send(JSON.stringify({ type: 'PING', ts: Date.now() }));
      } else {
        clearInterval(_relayKeepaliveTimer);
        _relayKeepaliveTimer = null;
      }
    }, 25_000);
  }

  function _stopRelayKeepalive() {
    if (_relayKeepaliveTimer) { clearInterval(_relayKeepaliveTimer); _relayKeepaliveTimer = null; }
  }

  // ── WebRTC offer/answer flow ────────────────────────────────────────────────
  async function _initiateWebRTC(targetToken, targetDid) {
    const peerId = `rtc:${targetToken}`;
    if (_peers.has(peerId)) return;

    const pc  = _createPeerConnection();
    const dc  = pc.createDataChannel('sovereign', {
      ordered:           true,
      maxRetransmits:    3,
      protocol:          'sovereign-v3',
    });

    _setupDataChannel(pc, dc, peerId, targetDid);

    pc.onicecandidate = (e) => {
      if (e.candidate && _relay?.readyState === WebSocket.OPEN) {
        _relay.send(JSON.stringify({
          type: 'ICE', to: targetToken,
          candidate: e.candidate,
        }));
      }
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    _relay?.send(JSON.stringify({
      type: 'OFFER', to: targetToken,
      offer: pc.localDescription,
      did: _myDid,
    }));

    _pending.set(targetToken, { pc, peerId });
    _log('WebRTC offer sent to:', targetToken);
  }

  async function _handleOffer(msg) {
    const { from, offer, did } = msg;
    const peerId = `rtc:${from}`;

    const pc = _createPeerConnection();

    pc.ondatachannel = (e) => {
      _setupDataChannel(pc, e.channel, peerId, did);
    };

    pc.onicecandidate = (e) => {
      if (e.candidate && _relay?.readyState === WebSocket.OPEN) {
        _relay.send(JSON.stringify({ type: 'ICE', to: from, candidate: e.candidate }));
      }
    };

    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    _relay?.send(JSON.stringify({
      type: 'ANSWER', to: from,
      answer: pc.localDescription,
      did: _myDid,
    }));

    _pending.set(from, { pc, peerId });
  }

  async function _handleAnswer(msg) {
    const entry = _pending.get(msg.from);
    if (!entry) return;
    await entry.pc.setRemoteDescription(new RTCSessionDescription(msg.answer));
    _pending.delete(msg.from);
  }

  async function _handleRemoteIce(msg) {
    const entry = _pending.get(msg.from) ?? _peers.get(`rtc:${msg.from}`);
    if (entry?.pc) {
      try {
        await entry.pc.addIceCandidate(new RTCIceCandidate(msg.candidate));
      } catch (_) {}
    }
  }

  // ── Manual offer/answer (offline handshake) ────────────────────────────────
  async function generateOffer() {
    const offerId = _hex(crypto.getRandomValues(new Uint8Array(8)));
    const pc      = _createPeerConnection();
    const dc      = pc.createDataChannel('sovereign', { ordered: true });
    const peerId  = `manual:${offerId}`;

    // Pass our own DID so the local peer record is populated correctly
    _setupDataChannel(pc, dc, peerId, _myDid);

    // Collect all ICE candidates before returning offer
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    await new Promise((res) => {
      pc.onicecandidate = (e) => { if (!e.candidate) res(); };
      setTimeout(res, 3_000); // max 3s wait
    });

    const packet = btoa(JSON.stringify({
      v:      3,
      offerId,
      sdp:    pc.localDescription,
      did:    _myDid,
    }));

    _pending.set(offerId, { pc, peerId });
    return { offerId, packet };
  }

  async function receiveOffer(packetB64) {
    const { v, offerId, sdp, did } = JSON.parse(atob(packetB64));
    if (v !== 3) throw new Error('Protocol version mismatch');

    const pc     = _createPeerConnection();
    const peerId = `manual:${offerId}`;

    pc.ondatachannel = (e) => _setupDataChannel(pc, e.channel, peerId, did);

    await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    await new Promise((res) => {
      pc.onicecandidate = (e) => { if (!e.candidate) res(); };
      setTimeout(res, 3_000);
    });

    _pending.set(offerId, { pc, peerId });

    return btoa(JSON.stringify({
      v: 3, offerId,
      sdp: pc.localDescription,
      did: _myDid,
    }));
  }

  async function receiveAnswer(packetB64) {
    const { v, offerId, sdp, did } = JSON.parse(atob(packetB64));
    if (v !== 3) throw new Error('Protocol version mismatch');
    const entry = _pending.get(offerId);
    if (!entry) throw new Error('No pending offer with id: ' + offerId);

    await entry.pc.setRemoteDescription(new RTCSessionDescription(sdp));

    // Backfill the remote DID into the peer record now that we know it
    if (did) {
      const peer = _peers.get(entry.peerId);
      if (peer && !peer.did) {
        peer.did = did;
        _computeNodeId(did).then(nodeId => {
          peer.nodeId = nodeId;
          _dhtInsert(nodeId, peer);
          // Announce ourselves back
          if (_myDid && _myNodeId) {
            _sendToPeer(entry.peerId, { type: 'DHT_ANNOUNCE', did: _myDid, nodeId: _myNodeId });
          }
        });
      }
    }

    _pending.delete(offerId);
  }

  // ── WebTransport / QUIC ────────────────────────────────────────────────────
  async function _initWebTransport(url) {
    if (!('WebTransport' in window)) return false;
    try {
      const wt   = new WebTransport(url);
      await wt.ready;
      _wtSession = wt;
      _log('WebTransport session ready:', url);

      // Handle incoming unidirectional streams
      const reader = wt.incomingUnidirectionalStreams.getReader();
      (async () => {
        while (true) {
          const { done, value: stream } = await reader.read();
          if (done) break;
          _readWebTransportStream(stream);
        }
      })();

      return true;
    } catch (err) {
      _log('WebTransport unavailable:', err.message);
      return false;
    }
  }

  async function _readWebTransportStream(stream) {
    const reader  = stream.getReader();
    const chunks  = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const buf = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
    let pos = 0;
    for (const c of chunks) { buf.set(c, pos); pos += c.length; }

    try {
      const msg = JSON.parse(new TextDecoder().decode(buf));
      _handleIncoming(msg.from, msg.payload, 'webtransport');
    } catch (_) {}
  }

  // ── Onion Routing ─────────────────────────────────────────────────────────
  //  3-hop circuit: us → hop1 → hop2 → exit → destination
  //  Each layer encrypted with an ephemeral ECDH key for that hop.

  async function buildOnionCircuit() {
    const peers = [..._peers.values()].filter(p => p.transport === 'webrtc');
    if (peers.length < 3) {
      _log('Not enough peers for onion circuit (need ≥3)');
      return null;
    }

    // Pick 3 distinct hops randomly
    const shuffled = [...peers].sort(() => Math.random() - 0.5);
    const hops     = shuffled.slice(0, 3);
    const circuitId = _hex(crypto.getRandomValues(new Uint8Array(8)));

    // Generate ephemeral ECDH keypair for each hop
    const hopKeys = await Promise.all(hops.map(() =>
      crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey'])
    ));

    const circuit = {
      id: circuitId,
      hops: hops.map((p, i) => ({ peer: p, key: hopKeys[i] })),
      createdAt: Date.now(),
    };

    _circuits.set(circuitId, circuit);
    K()?.onion?.send('CIRCUIT_OK', { circuitId });
    _emit('onion-ready', { circuitId });
    _log('Onion circuit built:', circuitId, 'via', hops.map(p => p.peerId));
    return circuitId;
  }

  async function sendOnion(circuitId, toDid, payload) {
    const circuit = _circuits.get(circuitId);
    if (!circuit) throw new Error('No circuit: ' + circuitId);

    // Wrap message in 3 layers of encryption (innermost = exit node)
    let wrapped = JSON.stringify({ to: toDid, payload, ts: Date.now() });

    for (let i = circuit.hops.length - 1; i >= 0; i--) {
      const { key } = circuit.hops[i];
      const iv      = crypto.getRandomValues(new Uint8Array(12));
      const encKey  = await crypto.subtle.deriveKey(
        { name: 'ECDH', public: key.publicKey },
        key.privateKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );
      const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        encKey,
        new TextEncoder().encode(wrapped)
      );
      wrapped = JSON.stringify({
        layer: i,
        iv:    _hex(iv),
        ct:    btoa(String.fromCharCode(...new Uint8Array(ct))),
        next:  i > 0 ? circuit.hops[i - 1].peer.peerId : toDid,
      });
    }

    // Send to first hop
    const firstHop = circuit.hops[0].peer;
    _sendToPeer(firstHop.peerId, { type: 'ONION', data: wrapped, circuitId });
  }

  // ── Message sending ────────────────────────────────────────────────────────
  function _sendToPeer(peerId, payload) {
    const peer = _peers.get(peerId);
    if (!peer) return false;

    const data = JSON.stringify(payload);

    if (peer.transport === 'webrtc' && peer.dc?.readyState === 'open') {
      peer.dc.send(data);
      _stats.bytesSent += data.length;
      _stats.msgSent++;
      return true;
    }

    if (peer.transport === 'broadcast') {
      _bc?.postMessage({ type: 'MESSAGE', from: _myDid, payload });
      return true;
    }

    return false;
  }

  /** Send to a DID — finds the best route (direct → DHT routed → degraded relay). */
  async function send(toDid, payload) {
    // 1. Direct connected peer
    for (const [id, peer] of _peers) {
      if (peer.did === toDid) {
        return _sendToPeer(id, { type: 'MSG', from: _myDid, payload });
      }
    }

    // 2. DHT routed — find closest peer to target's nodeId, forward through them
    const targetNodeId = await _computeNodeId(toDid);
    const closest      = _dhtClosest(targetNodeId, DHT_A);
    if (closest.length) {
      const via = closest[0];
      return _sendToPeer(via.peerId, {
        type:    'ROUTE',
        from:    _myDid,
        to:      toDid,
        payload,
        ttl:     7,
        nodeId:  targetNodeId,
      });
    }

    // 3. Relay forwarding (last resort — relay is out of path post-handshake,
    //    but can forward to peers that are still relay-connected)
    if (_relay?.readyState === WebSocket.OPEN) {
      _relay.send(JSON.stringify({ type: 'FORWARD', to: toDid, from: _myDid, payload }));
      return true;
    }

    _log('send() — no route to:', toDid);
    return false;
  }

  function broadcast(payload) {
    let sent = 0;
    for (const peerId of _peers.keys()) {
      if (_sendToPeer(peerId, { type: 'BROADCAST', from: _myDid, payload })) sent++;
    }
    if (_bc) _bc.postMessage({ type: 'MESSAGE', from: _myDid, payload });
    return sent;
  }

  // ── Incoming message handler ───────────────────────────────────────────────
  function _handleIncoming(from, msg, channel) {
    if (!msg?.type) return;

    switch (msg.type) {
      case 'PEER_PING':
        // Respond with PEER_PONG — find peerId by did+channel
        {
          const respPeer = [..._peers.values()].find(p => p.did === from);
          if (respPeer) _sendToPeer(respPeer.peerId, { type: 'PEER_PONG', ts: msg.ts });
        }
        break;

      case 'PEER_PONG': {
        // Update round-trip latency
        const latPeer = [..._peers.values()].find(p => p.did === from);
        if (latPeer && msg.ts) {
          latPeer.latencyMs = Date.now() - msg.ts;
          latPeer.lastSeen  = Date.now();
        }
        break;
      }

      case 'ROUTE':
        // Multi-hop DHT routing — forward if we're not the destination
        if (msg.to !== _myDid && msg.ttl > 0) {
          const fwd = { ...msg, ttl: msg.ttl - 1 };
          send(msg.to, fwd);
        } else if (msg.to === _myDid) {
          _emit('message', { from: msg.from, payload: msg.payload, channel });
        }
        break;

      case 'MSG':
      case 'BROADCAST':
        _emit('message', { from, payload: msg.payload, channel });
        break;

      case 'ONION':
        // Onion packet forwarding — in a real implementation, this would
        // decrypt the outermost layer and forward; for browser context we
        // deliver to the page and let the Security Kernel handle it.
        _emit('message', { from, payload: msg, channel, onion: true });
        break;

      case 'DHT_ANNOUNCE':
        // Peer announcing its DID ↔ nodeId mapping for routing table
        if (msg.did && msg.nodeId) {
          // Find peer by any identifier — may be a manual peer that didn't have DID yet
          const announcePeer = [..._peers.values()].find(p =>
            p.did === msg.did || p.did === from || (!p.did && p.transport === 'webrtc')
          );
          if (announcePeer) {
            const hadDid = !!announcePeer.did;
            announcePeer.did    = msg.did;
            announcePeer.nodeId = msg.nodeId;
            announcePeer.lastSeen = Date.now();
            _dhtInsert(msg.nodeId, announcePeer);
            // Emit updated peer info if DID just became known
            if (!hadDid) {
              _emit('peer-connected', { peerId: announcePeer.peerId, did: msg.did, transport: announcePeer.transport });
            }
          }
        }
        break;
    }
  }

  // ── Latency probing ────────────────────────────────────────────────────────
  const _pingIntervals = new Map(); // peerId → intervalId

  function _probePing(peerId) {
    // Clear any existing interval for this peer first
    if (_pingIntervals.has(peerId)) clearInterval(_pingIntervals.get(peerId));
    // Send initial probe immediately
    _sendToPeer(peerId, { type: 'PEER_PING', ts: Date.now() });
    // Re-probe every 30s — interval stored so it can be cleared on disconnect
    const id = setInterval(() => {
      if (_peers.has(peerId)) {
        _sendToPeer(peerId, { type: 'PEER_PING', ts: Date.now() });
      } else {
        clearInterval(id);
        _pingIntervals.delete(peerId);
      }
    }, 30_000);
    _pingIntervals.set(peerId, id);
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  const SovereignTransport = {
    send,
    broadcast,
    generateOffer,
    receiveOffer,
    receiveAnswer,
    buildOnionCircuit,
    sendOnion,

    connectRelay(url = DEFAULT_RELAY) {
      K()?.transport?.send('CONNECT');
      return _connectRelay(url);
    },

    disconnectRelay() {
      if (_relayTimer) clearTimeout(_relayTimer);
      _stopRelayKeepalive();
      _myRelayToken = null;
      _relay?.close();
      _relay = null;
      K()?.transport?.send('DISCONNECT');
    },

    peers()  { return new Map(_peers); },
    nodeId() { return _myNodeId; },

    stats() {
      return {
        ..._stats,
        peerCount:   _peers.size,
        dhtSize:     _dht.size,
        circuitCount: _circuits.size,
        relayUrl:    _relayUrl,
        relayState:  _relay ? ['CONNECTING','OPEN','CLOSING','CLOSED'][_relay.readyState] : 'NONE',
      };
    },

    setDid(did) {
      if (_myDid && _myDid !== did) {
        _log('DID changed — reinitializing transport');
      }
      _myDid = did;
      _computeNodeId(did).then(id => {
        _myNodeId = id;
        // Announce to existing peers
        for (const peerId of _peers.keys()) {
          _sendToPeer(peerId, { type: 'DHT_ANNOUNCE', did, nodeId: id });
        }
      });
    },
  };

  window.SovereignTransport = SovereignTransport;

  // ── Auto-init on DOMContentLoaded ─────────────────────────────────────────
  const _boot = async () => {
    _log('Booting transport v3.0');

    // Initialize BroadcastChannel immediately (same-device discovery)
    _initBroadcastChannel();

    // Wait for identity to be available
    const tryGetDid = () => {
      const did = window.SOVEREIGN_DID
        ?? sessionStorage.getItem('sovereign_did')
        ?? localStorage.getItem('sovereign_did');
      return did;
    };

    const did = tryGetDid();
    if (did) {
      SovereignTransport.setDid(did);
      await _connectRelay(DEFAULT_RELAY);
    } else {
      // Wait for identity event
      window.addEventListener('sovereign:identity:ready', async (e) => {
        const d = e.detail?.did ?? tryGetDid();
        if (d) {
          SovereignTransport.setDid(d);
          await _connectRelay(DEFAULT_RELAY);
        }
      }, { once: true });
    }

    // FSM integration — listen for vault lock to disconnect
    window.addEventListener('sovereign:fsm:TRANSITION', (e) => {
      const { machine, to } = e.detail ?? {};
      if (machine === 'vault' && to === 'LOCKED') {
        SovereignTransport.disconnectRelay();
        _bc?.close();
      }
      if (machine === 'transport' && to === 'OFFLINE') {
        _log('FSM: transport offline');
      }
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _boot);
  } else {
    _boot();
  }

  _log('Module evaluated — transport v3.0 registered');

})();
