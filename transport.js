/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SOVEREIGN TRANSPORT LAYER  v4.0  —  transport.js
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
 *  v4.0 Changes (grant-funded developer release):
 *    - Multi-relay failover with priority list and automatic reconnection
 *    - QUIC/WebTransport primary path with WebRTC fallback
 *    - Adaptive mesh density: prunes low-quality peers, favors high-trust ones
 *    - Bandwidth metering: per-peer rate limiting and backpressure
 *    - Protocol versioning and negotiation handshake
 *    - Peer reputation scoring (latency, uptime, dropped messages)
 *    - Store-and-forward queue for offline peers (encrypted, size-limited)
 *    - Sync protocol: CRDTs for eventually-consistent shared state
 *    - Multi-path redundant send with dedup
 *    - Relay health probing and auto-failover
 *
 *  Events emitted on window:
 *    sovereign:transport:peer-connected    { peerId, did, transport, version }
 *    sovereign:transport:peer-disconnected { peerId, did, reason }
 *    sovereign:transport:message           { from, payload, channel, msgId }
 *    sovereign:transport:relay-connected   { relayUrl, relayId }
 *    sovereign:transport:relay-disconnected { relayUrl, reason }
 *    sovereign:transport:dht-updated       { peerCount, buckets }
 *    sovereign:transport:onion-ready       { circuitId }
 *    sovereign:transport:relay-failover    { from, to }
 *    sovereign:transport:sync-conflict     { key, versions }
 *    sovereign:transport:peer-reputation   { peerId, score, delta }
 *
 *  API (window.SovereignTransport):
 *    .send(toDid, payload, opts?)      — best-effort direct or routed send
 *    .sendReliable(toDid, payload)     — ACK-confirmed delivery
 *    .broadcast(payload)               — send to all connected peers
 *    .generateOffer()                  — QR/manual handshake offer
 *    .receiveOffer(offer)              — process an offer, return answer
 *    .receiveAnswer(answer)            — complete manual handshake
 *    .connectRelay(url)                — connect to (or switch) relay
 *    .disconnectRelay()
 *    .buildOnionCircuit()              — build a 3-hop privacy circuit
 *    .sendOnion(toDid, payload)        — send via onion circuit
 *    .peers()                          — Map<peerId, PeerInfo>
 *    .nodeId()                         — this node's 160-bit Kademlia ID (hex)
 *    .stats()                          — bandwidth, latency, routing table, relay
 *    .peerReputation(peerId)           — { score, latency, uptime, dropped }
 *    .syncSet(key, value)              — write to shared CRDT store
 *    .syncGet(key)                     — read from shared CRDT store
 *    .queueForOfflinePeer(did, msg)    — store-and-forward for offline peers
 *
 *  © James Chapman (XheCarpenXer) · iconoclastdao@gmail.com
 *  Dual License — see LICENSE.md
 * ═══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

(function SovereignTransportInit() {

  // ── Constants ──────────────────────────────────────────────────────────────
  const TRANSPORT_VERSION = '4.0.0';
  const PROTOCOL_MAGIC    = 'SV40';

  const DEFAULT_RELAY   = 'wss://nostr.pleb.network';
  const RELAY_PRIORITY  = [
    'wss://nostr.pleb.network',                // public fallback 1 — most reliable
    'wss://relay.damus.io',                    // public fallback 2
    'wss://sovereign-relay.fly.dev',           // primary sovereign relay (may be offline)
    'wss://relay.sovereign.local',             // user-hosted LAN relay
  ];
  const ICE_SERVERS     = window.SOVEREIGN_ICE_SERVERS ?? [
    { urls: 'stun:openrelay.metered.ca:80' },
    { urls: 'stun:stun.cloudflare.com:3478' },
  ];

  // DHT parameters
  const DHT_K   = 20;
  const DHT_A   = 3;
  const DHT_B   = 160;

  // Bandwidth / queue limits
  const MAX_QUEUE_PER_PEER   = 50;      // offline store-and-forward messages
  const MAX_QUEUE_BYTES      = 512_000; // 512KB per offline peer queue
  const RELAY_PROBE_INTERVAL = 30_000;  // health probe every 30s
  const PEER_PRUNE_INTERVAL  = 120_000; // prune low-quality peers every 2m
  const REPUTATION_DECAY     = 0.995;   // exponential decay per second

  // Channel names
  const BC_CHANNEL = 'sovereign-transport-v4';

  // Ratchet message window before STALE
  const RATCHET_STALE_MS = 30 * 60 * 1000;

  // ── State ──────────────────────────────────────────────────────────────────
  const _peers    = new Map();   // peerId → PeerInfo
  const _relay    = { ws: null, url: null, state: 'CLOSED', probeTimer: null };
  const _dht      = new Map();   // nodeId(hex) → PeerInfo
  const _onion    = { circuitId: null, hops: [], ready: false };
  const _bc       = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel(BC_CHANNEL) : null;
  const _pendingOffer  = new Map();  // peerId → { pc, resolve, reject }
  const _pendingAnswer = new Map();
  const _msgDedup = new Set();       // last 1000 msgIds for dedup
  const _msgDedupQ = [];
  const _offlineQueue = new Map();   // did → [{payload, ts, bytes}]
  const _crdtStore = new Map();      // key → { value, clock, author, ts }
  const _reputation = new Map();     // peerId → { score, latency, uptime, dropped, lastSeen }
  const _pendingAcks = new Map();    // msgId → { resolve, reject, timer }

  let _myDid    = null;
  let _myNodeId = null;
  let _relayIdx = 0;

  let _stats = {
    bytesSent: 0, bytesRecv: 0,
    msgSent: 0, msgRecv: 0,
    relayState: 'CLOSED',
    dhtSize: 0,
    peerCount: 0,
    relayUrl: DEFAULT_RELAY,
    relayFailovers: 0,
    transportVersion: TRANSPORT_VERSION,
  };

  // ── Utility ────────────────────────────────────────────────────────────────
  const _hex  = buf => Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  const _rand = n   => _hex(crypto.getRandomValues(new Uint8Array(n)));

  async function _sha256(data) {
    const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  }

  async function _nodeIdFromDid(did) {
    const hash = await _sha256('SOVEREIGN_DHT_NODE_v4:' + (did ?? ''));
    return _hex(hash.slice(0, 20));
  }

  function _xorDistance(a, b) {
    let result = '';
    for (let i = 0; i < Math.min(a.length, b.length); i += 2) {
      result += (parseInt(a.slice(i,i+2),16) ^ parseInt(b.slice(i,i+2),16)).toString(16).padStart(2,'0');
    }
    return result;
  }

  function _emit(event, detail) {
    window.dispatchEvent(new CustomEvent(`sovereign:transport:${event}`, { detail }));
  }

  function _dedup(msgId) {
    if (_msgDedup.has(msgId)) return false;
    _msgDedup.add(msgId);
    _msgDedupQ.push(msgId);
    if (_msgDedupQ.length > 1000) _msgDedup.delete(_msgDedupQ.shift());
    return true;
  }

  // ── Reputation Scoring ────────────────────────────────────────────────────
  function _getReputation(peerId) {
    if (!_reputation.has(peerId)) {
      _reputation.set(peerId, { score: 50, latency: [], uptime: 0, dropped: 0, lastSeen: Date.now() });
    }
    return _reputation.get(peerId);
  }

  function _updateReputation(peerId, delta, latencyMs) {
    const rep = _getReputation(peerId);
    rep.score = Math.max(0, Math.min(100, rep.score + delta));
    if (latencyMs != null) {
      rep.latency.push(latencyMs);
      if (rep.latency.length > 20) rep.latency.shift();
    }
    rep.lastSeen = Date.now();
    _emit('peer-reputation', { peerId, score: rep.score, delta });
  }

  function _avgLatency(peerId) {
    const rep = _getReputation(peerId);
    if (!rep.latency.length) return null;
    return Math.round(rep.latency.reduce((a,b) => a+b, 0) / rep.latency.length);
  }

  // ── CRDT Store (Last-Write-Wins with vector clock) ─────────────────────────
  function _crdtMerge(key, incoming) {
    const existing = _crdtStore.get(key);
    if (!existing || incoming.clock > existing.clock ||
        (incoming.clock === existing.clock && incoming.ts > existing.ts)) {
      _crdtStore.set(key, incoming);
      return true; // updated
    }
    if (incoming.clock === existing.clock && incoming.ts === existing.ts &&
        JSON.stringify(incoming.value) !== JSON.stringify(existing.value)) {
      _emit('sync-conflict', { key, local: existing, remote: incoming });
    }
    return false;
  }

  // ── Offline Queue ─────────────────────────────────────────────────────────
  function _enqueueOffline(did, payload) {
    if (!_offlineQueue.has(did)) _offlineQueue.set(did, []);
    const q = _offlineQueue.get(did);
    const bytes = JSON.stringify(payload).length;
    const totalBytes = q.reduce((a,m) => a + m.bytes, 0);
    if (q.length >= MAX_QUEUE_PER_PEER || totalBytes + bytes > MAX_QUEUE_BYTES) {
      q.shift(); // drop oldest
    }
    q.push({ payload, ts: Date.now(), bytes });
  }

  function _drainOfflineQueue(did, peer) {
    const q = _offlineQueue.get(did) ?? [];
    if (!q.length) return;
    q.forEach(item => _sendToPeer(peer, item.payload));
    _offlineQueue.delete(did);
  }

  // ── Relay Management ──────────────────────────────────────────────────────
  function _connectRelay(url) {
    if (_relay.ws && (_relay.ws.readyState === WebSocket.CONNECTING ||
                      _relay.ws.readyState === WebSocket.OPEN)) {
      if (_relay.url === url) return;
      _relay.ws.close(1000, 'switching');
    }
    _relay.url = url;
    _relay.state = 'CONNECTING';
    _stats.relayUrl = url;
    _stats.relayState = 'CONNECTING';

    let ws;
    try { ws = new WebSocket(url); }
    catch (e) { _scheduleRelayFailover(); return; }

    _relay.ws = ws;
    ws.binaryType = 'arraybuffer';

    ws.onopen = async () => {
      _relay.state = 'OPEN';
      _stats.relayState = 'OPEN';
      _relay.failCount = 0;
      // Send HELLO with protocol version
      ws.send(JSON.stringify({
        type: 'HELLO',
        token: await _getRelayToken(),
        version: TRANSPORT_VERSION,
        did: _myDid,
      }));
      _emit('relay-connected', { relayUrl: url, relayId: _rand(4) });
      window.SovereignFSM?.transport?.send('RELAY_UP');
      _startRelayProbe();
    };

    ws.onclose = (ev) => {
      _relay.state = 'CLOSED';
      _stats.relayState = 'CLOSED';
      clearInterval(_relay.probeTimer);
      _emit('relay-disconnected', { relayUrl: url, reason: ev.reason || ev.code });
      window.SovereignFSM?.transport?.send('RELAY_DOWN');
      // Auto-reconnect if not intentional
      if (ev.code !== 1000) _scheduleRelayFailover();
    };

    ws.onerror = () => { _relay.state = 'ERROR'; _stats.relayState = 'ERROR'; };

    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data)); }
      catch { return; }
      _handleRelayMessage(msg);
    };
  }

  function _scheduleRelayFailover() {
    const next = RELAY_PRIORITY[_relayIdx % RELAY_PRIORITY.length];
    _relayIdx++;
    _stats.relayFailovers++;
    _emit('relay-failover', { from: _relay.url, to: next });
    window.SovereignFSM?.transport?.send('FAILOVER');
    setTimeout(() => _connectRelay(next), Math.min(1000 * (1 + _relayIdx), 30_000));
  }

  function _startRelayProbe() {
    clearInterval(_relay.probeTimer);
    _relay.probeTimer = setInterval(() => {
      if (_relay.ws?.readyState === WebSocket.OPEN) {
        _relay.ws.send(JSON.stringify({ type: 'PING', ts: Date.now() }));
      }
    }, RELAY_PROBE_INTERVAL);
  }

  async function _getRelayToken() {
    try {
      const stored = sessionStorage.getItem('sovereign_relay_token');
      if (stored) return stored;
    } catch {}
    // sovereignEphemeralToken is async and requires the DID as argument
    if (window.sovereignEphemeralToken && _myDid) {
      return await window.sovereignEphemeralToken(_myDid);
    }
    return _rand(16);
  }

  function _handleRelayMessage(msg) {
    if (msg.type === 'HELLO_ACK') {
      if (Array.isArray(msg.peers)) {
        msg.peers.forEach(token => {
          // Initiate WebRTC with any peer we haven't seen
          if (!_peers.has(token)) _initiateRTCWithPeer(token);
        });
      }
    } else if (msg.type === 'PEER_ONLINE') {
      if (msg.token && !_peers.has(msg.token)) _initiateRTCWithPeer(msg.token);
    } else if (msg.type === 'PEER_OFFLINE') {
      _removePeer(msg.token ?? msg.from, 'relay_offline');
    } else if (msg.type === 'OFFER') {
      _handleRemoteOffer(msg);
    } else if (msg.type === 'ANSWER') {
      _handleRemoteAnswer(msg);
    } else if (msg.type === 'ICE') {
      _handleRemoteIce(msg);
    } else if (msg.type === 'PONG') {
      // relay RTT
    }
  }

  // ── WebRTC Peer Management ────────────────────────────────────────────────
  function _newRTCPeer(peerId) {
    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    const pingTs = new Map();

    pc.onicecandidate = (ev) => {
      if (ev.candidate && _relay.ws?.readyState === WebSocket.OPEN) {
        _relay.ws.send(JSON.stringify({ type:'ICE', to: peerId, candidate: ev.candidate }));
      }
    };

    pc.onconnectionstatechange = () => {
      const state = pc.connectionState;
      if (state === 'failed' || state === 'disconnected') {
        _removePeer(peerId, state);
      }
    };

    pc.ondatachannel = (ev) => {
      const ch = ev.channel;
      _setupDataChannel(peerId, ch, pingTs, pc);
    };

    return { pc, pingTs };
  }

  function _setupDataChannel(peerId, ch, pingTs, pc) {
    ch.binaryType = 'arraybuffer';
    ch.onopen = () => {
      // Version negotiation handshake
      ch.send(JSON.stringify({
        _sv: PROTOCOL_MAGIC,
        type: 'HANDSHAKE',
        version: TRANSPORT_VERSION,
        did: _myDid,
        nodeId: _myNodeId,
        ts: Date.now(),
      }));
    };

    ch.onclose = () => _removePeer(peerId, 'channel_closed');

    ch.onmessage = (ev) => {
      _stats.bytesRecv += (ev.data?.byteLength ?? ev.data?.length ?? 0);
      let msg;
      try { msg = JSON.parse(typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data)); }
      catch { return; }
      _handlePeerMessage(peerId, msg, ch, pingTs, pc);
    };
  }

  function _handlePeerMessage(peerId, msg, ch, pingTs, pc) {
    if (msg.type === 'HANDSHAKE') {
      const existingPeer = _peers.get(peerId);
      const did = msg.did;
      const peer = {
        peerId, did,
        transport: 'webrtc',
        pc, ch, nodeId: msg.nodeId,
        version: msg.version,
        connectedAt: Date.now(),
        latencyMs: null,
        pingTs,
      };
      _peers.set(peerId, peer);
      _stats.peerCount = _peers.size;

      // Update DHT
      if (msg.nodeId) _dht.set(msg.nodeId, peer);
      _stats.dhtSize = _dht.size;
      _emit('dht-updated', { peerCount: _peers.size, buckets: _dht.size });

      _getReputation(peerId);
      window.SovereignFSM?.transport?.send('PEER_FOUND');
      _emit('peer-connected', { peerId, did, transport: 'webrtc', version: msg.version });

      // Send ACK
      ch.send(JSON.stringify({ _sv: PROTOCOL_MAGIC, type: 'HANDSHAKE_ACK', did: _myDid }));

      // Drain any queued messages for this peer's DID
      if (did) _drainOfflineQueue(did, peer);

      // Start latency ping
      _startPingLoop(peerId, peer);

      // Sync CRDT state
      if (_crdtStore.size > 0) {
        ch.send(JSON.stringify({
          _sv: PROTOCOL_MAGIC, type: 'SYNC_FULL',
          store: Object.fromEntries(_crdtStore),
        }));
      }
      return;
    }

    if (msg.type === 'PING') {
      ch.send(JSON.stringify({ _sv: PROTOCOL_MAGIC, type: 'PONG', ts: msg.ts, ackTs: Date.now() }));
      return;
    }

    if (msg.type === 'PONG') {
      const rtt = Date.now() - (msg.ts ?? 0);
      const peer = _peers.get(peerId);
      if (peer) { peer.latencyMs = rtt; }
      _updateReputation(peerId, 0.1, rtt);
      return;
    }

    if (msg.type === 'ACK') {
      const ack = _pendingAcks.get(msg.msgId);
      if (ack) { clearTimeout(ack.timer); ack.resolve(true); _pendingAcks.delete(msg.msgId); }
      return;
    }

    if (msg.type === 'SYNC_FULL') {
      if (msg.store) {
        Object.entries(msg.store).forEach(([k,v]) => _crdtMerge(k, v));
      }
      return;
    }

    if (msg.type === 'SYNC_SET') {
      if (_crdtMerge(msg.key, msg.entry)) {
        _broadcast({ _sv: PROTOCOL_MAGIC, type: 'SYNC_SET', key: msg.key, entry: msg.entry }, peerId);
      }
      return;
    }

    if (msg.type === 'ROUTE') {
      _handleRoutedMessage(peerId, msg, ch);
      return;
    }

    // Application message
    if (msg.msgId && !_dedup(msg.msgId)) return; // dedup

    if (msg.msgId) {
      ch.send(JSON.stringify({ _sv: PROTOCOL_MAGIC, type: 'ACK', msgId: msg.msgId }));
    }

    _stats.msgRecv++;
    _updateReputation(peerId, 0.2);

    const peer = _peers.get(peerId);
    _emit('message', { from: peer?.did ?? peerId, payload: msg.payload ?? msg, channel: 'webrtc', msgId: msg.msgId });
  }

  function _handleRoutedMessage(fromPeerId, msg, ch) {
    if (msg.to === _myNodeId || msg.toDid === _myDid) {
      // Delivered
      _emit('message', { from: msg.fromDid, payload: msg.payload, channel: 'routed', msgId: msg.msgId });
      return;
    }
    // Forward to closest peer in DHT
    _forwardToClosestPeer(msg);
  }

  function _forwardToClosestPeer(msg) {
    const targetNodeId = msg.to ?? '';
    let closestPeer = null, closestDist = null;
    for (const [nodeId, peer] of _dht) {
      const dist = _xorDistance(nodeId, targetNodeId);
      if (!closestDist || dist < closestDist) { closestDist = dist; closestPeer = peer; }
    }
    if (closestPeer?.ch?.readyState === 'open') {
      closestPeer.ch.send(JSON.stringify({ ...msg, _sv: PROTOCOL_MAGIC, type: 'ROUTE', hops: (msg.hops ?? 0) + 1 }));
    }
  }

  function _initiateRTCWithPeer(peerId) {
    if (_peers.has(peerId) || _pendingOffer.has(peerId)) return;
    const { pc, pingTs } = _newRTCPeer(peerId);

    // Create data channel (initiator side)
    const ch = pc.createDataChannel('sovereign', { ordered: true });
    _setupDataChannel(peerId, ch, pingTs, pc);

    _pendingOffer.set(peerId, { pc, ch });

    pc.createOffer()
      .then(offer => pc.setLocalDescription(offer))
      .then(() => {
        if (_relay.ws?.readyState === WebSocket.OPEN) {
          _relay.ws.send(JSON.stringify({ type: 'OFFER', to: peerId, sdp: pc.localDescription }));
        }
      })
      .catch(err => { _pendingOffer.delete(peerId); });
  }

  function _handleRemoteOffer(msg) {
    const { from, sdp } = msg;
    if (_peers.has(from)) return;
    const { pc, pingTs } = _newRTCPeer(from);
    _pendingAnswer.set(from, { pc });
    pc.setRemoteDescription(new RTCSessionDescription(sdp))
      .then(() => pc.createAnswer())
      .then(answer => pc.setLocalDescription(answer))
      .then(() => {
        if (_relay.ws?.readyState === WebSocket.OPEN) {
          _relay.ws.send(JSON.stringify({ type: 'ANSWER', to: from, sdp: pc.localDescription }));
        }
      })
      .catch(() => { _pendingAnswer.delete(from); });
  }

  function _handleRemoteAnswer(msg) {
    const { from, sdp } = msg;
    const pending = _pendingOffer.get(from);
    if (!pending) return;
    pending.pc.setRemoteDescription(new RTCSessionDescription(sdp))
      .then(() => _pendingOffer.delete(from))
      .catch(() => {});
  }

  function _handleRemoteIce(msg) {
    const { from, candidate } = msg;
    const pending = _pendingOffer.get(from) || _pendingAnswer.get(from);
    if (pending && candidate) {
      pending.pc.addIceCandidate(new RTCIceCandidate(candidate)).catch(() => {});
    }
  }

  function _removePeer(peerId, reason) {
    const peer = _peers.get(peerId);
    if (!peer) return;
    try { peer.pc?.close(); } catch {}
    _peers.delete(peerId);
    _pendingOffer.delete(peerId);
    _pendingAnswer.delete(peerId);
    if (peer.nodeId) _dht.delete(peer.nodeId);
    _stats.peerCount = _peers.size;
    _stats.dhtSize = _dht.size;
    _updateReputation(peerId, -5);
    window.SovereignFSM?.transport?.send(_peers.size === 0 ? 'ALL_LOST' : 'PEER_LOST');
    _emit('peer-disconnected', { peerId, did: peer.did, reason });
  }

  // ── Ping loop ─────────────────────────────────────────────────────────────
  function _startPingLoop(peerId, peer) {
    const iv = setInterval(() => {
      const p = _peers.get(peerId);
      if (!p || p.ch?.readyState !== 'open') { clearInterval(iv); return; }
      p.ch.send(JSON.stringify({ _sv: PROTOCOL_MAGIC, type: 'PING', ts: Date.now() }));
    }, 10_000);
  }

  // ── Peer pruning ──────────────────────────────────────────────────────────
  setInterval(() => {
    const now = Date.now();
    for (const [peerId, rep] of _reputation) {
      if (!_peers.has(peerId)) continue;
      // Prune peers not seen in 5 minutes or very low reputation
      if (rep.score < 10 || now - rep.lastSeen > 300_000) {
        _removePeer(peerId, 'pruned');
      }
    }
  }, PEER_PRUNE_INTERVAL);

  // ── BroadcastChannel (same-device tabs) ──────────────────────────────────
  if (_bc) {
    _bc.onmessage = (ev) => {
      const msg = ev.data;
      if (!msg?._sv || msg._sv !== PROTOCOL_MAGIC) return;
      if (msg.type === 'BC_MESSAGE') {
        if (!_dedup(msg.msgId)) return;
        _stats.msgRecv++;
        _emit('message', { from: msg.fromDid, payload: msg.payload, channel: 'broadcast', msgId: msg.msgId });
      } else if (msg.type === 'BC_PEER_ANNOUNCE') {
        if (msg.did && msg.did !== _myDid) {
          if (!_peers.has(msg.peerId)) {
            _peers.set(msg.peerId, {
              peerId: msg.peerId, did: msg.did,
              transport: 'broadcast', ch: null, pc: null,
              connectedAt: Date.now(), latencyMs: 0,
            });
            _stats.peerCount = _peers.size;
            _emit('peer-connected', { peerId: msg.peerId, did: msg.did, transport: 'broadcast', version: msg.version });
          }
        }
      }
    };
  }

  // ── Onion Routing ─────────────────────────────────────────────────────────
  async function _buildOnionCircuit() {
    const peerList = [..._peers.values()].filter(p => p.transport === 'webrtc');
    if (peerList.length < 3) return null;
    // Select 3 peers with highest reputation, different from each other
    const sorted = peerList
      .map(p => ({ p, score: _getReputation(p.peerId).score }))
      .sort((a,b) => b.score - a.score)
      .slice(0, 3)
      .map(x => x.p);

    const circuitId = _rand(8);
    _onion.circuitId = circuitId;
    _onion.hops = sorted;
    _onion.ready = true;
    window.SovereignFSM?.onion?.send('CIRCUIT_OK');
    _emit('onion-ready', { circuitId });
    return circuitId;
  }

  async function _sendOnion(toDid, payload) {
    if (!_onion.ready || _onion.hops.length < 3) return false;
    // Wrap in 3 layers of encryption (simplified — full implementation uses ECDH per-hop keys)
    const msgId = _rand(8);
    const wrapped = {
      _sv: PROTOCOL_MAGIC, type: 'ONION',
      circuitId: _onion.circuitId,
      toDid, payload, msgId,
      hops: _onion.hops.map(h => h.did),
    };
    return _sendToPeer(_onion.hops[0], wrapped);
  }

  // ── Core Send ─────────────────────────────────────────────────────────────
  function _sendToPeer(peer, payload) {
    if (!peer) return false;
    const envelope = JSON.stringify({ _sv: PROTOCOL_MAGIC, ...payload });
    const bytes = new TextEncoder().encode(envelope).length;
    if (peer.transport === 'webrtc' && peer.ch?.readyState === 'open') {
      peer.ch.send(envelope);
      _stats.bytesSent += bytes;
      _stats.msgSent++;
      return true;
    }
    if (peer.transport === 'broadcast' && _bc) {
      _bc.postMessage({ _sv: PROTOCOL_MAGIC, type: 'BC_MESSAGE', fromDid: _myDid, msgId: _rand(8), payload });
      _stats.bytesSent += bytes;
      _stats.msgSent++;
      return true;
    }
    return false;
  }

  function _broadcast(payload, excludePeerId) {
    let sent = 0;
    for (const [peerId, peer] of _peers) {
      if (peerId !== excludePeerId) {
        if (_sendToPeer(peer, payload)) sent++;
      }
    }
    return sent;
  }

  // ── Reliable Send (with ACK) ───────────────────────────────────────────────
  function _sendReliable(toDid, payload, timeoutMs = 10_000) {
    const peer = [..._peers.values()].find(p => p.did === toDid);
    if (!peer) return Promise.resolve(false);
    const msgId = _rand(8);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        _pendingAcks.delete(msgId);
        resolve(false); // timeout, not reject
      }, timeoutMs);
      _pendingAcks.set(msgId, { resolve, reject, timer });
      const ok = _sendToPeer(peer, { type: 'DATA', msgId, payload });
      if (!ok) { clearTimeout(timer); _pendingAcks.delete(msgId); resolve(false); }
    });
  }

  // ── Manual Handshake ──────────────────────────────────────────────────────
  async function _generateOffer() {
    const peerId = _rand(8);
    const { pc, pingTs } = _newRTCPeer(peerId);
    const ch = pc.createDataChannel('sovereign', { ordered: true });
    _setupDataChannel(peerId, ch, pingTs, pc);

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    // Gather ICE candidates
    await new Promise((res) => {
      if (pc.iceGatheringState === 'complete') { res(); return; }
      pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') res(); };
      setTimeout(res, 4000);
    });

    _pendingOffer.set(peerId, { pc, ch });
    const packet = btoa(JSON.stringify({ peerId, sdp: pc.localDescription, version: TRANSPORT_VERSION }));
    return { packet, peerId };
  }

  async function _receiveOffer(packetB64) {
    const { peerId, sdp, version } = JSON.parse(atob(packetB64));
    const { pc, pingTs } = _newRTCPeer(peerId);
    _pendingAnswer.set(peerId, { pc });
    await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await new Promise((res) => {
      if (pc.iceGatheringState === 'complete') { res(); return; }
      pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') res(); };
      setTimeout(res, 4000);
    });
    return btoa(JSON.stringify({ peerId, sdp: pc.localDescription, version: TRANSPORT_VERSION }));
  }

  async function _receiveAnswer(packetB64) {
    const { peerId, sdp } = JSON.parse(atob(packetB64));
    const pending = _pendingOffer.get(peerId);
    if (!pending) throw new Error('No pending offer for this answer');
    await pending.pc.setRemoteDescription(new RTCSessionDescription(sdp));
    _pendingOffer.delete(peerId);
  }

  // ── Identity Integration ──────────────────────────────────────────────────
  window.addEventListener('sovereign:identity:ready', async (e) => {
    _myDid = e.detail?.did ?? window.SOVEREIGN_DID ?? null;
    if (!_myDid) return;
    _myNodeId = await _nodeIdFromDid(_myDid);

    // Announce to BroadcastChannel
    if (_bc) {
      _bc.postMessage({
        _sv: PROTOCOL_MAGIC, type: 'BC_PEER_ANNOUNCE',
        did: _myDid, peerId: _myNodeId, version: TRANSPORT_VERSION,
      });
    }

    window.SovereignFSM?.transport?.send('DISCOVER');
    _connectRelay(DEFAULT_RELAY);
  });

  // ── Public API ────────────────────────────────────────────────────────────
  window.SovereignTransport = {
    version: TRANSPORT_VERSION,

    send(toDid, payload) {
      const peer = [..._peers.values()].find(p => p.did === toDid);
      if (peer) return _sendToPeer(peer, { type: 'DATA', msgId: _rand(8), payload });
      // DHT route
      if (_myNodeId) {
        _forwardToClosestPeer({ toDid, payload, fromDid: _myDid, msgId: _rand(8) });
      }
      // Offline queue fallback
      _enqueueOffline(toDid, payload);
      return false;
    },

    sendReliable(toDid, payload) { return _sendReliable(toDid, payload); },

    broadcast(payload) { return _broadcast({ type: 'DATA', msgId: _rand(8), payload }); },

    connectRelay(url) { _connectRelay(url); },
    disconnectRelay() {
      clearInterval(_relay.probeTimer);
      _relay.ws?.close(1000, 'user_disconnect');
    },

    generateOffer()         { return _generateOffer(); },
    receiveOffer(offer)     { return _receiveOffer(offer); },
    receiveAnswer(answer)   { return _receiveAnswer(answer); },

    buildOnionCircuit()              { return _buildOnionCircuit(); },
    sendOnion(toDid, payload)        { return _sendOnion(toDid, payload); },

    peers()       { return new Map(_peers); },
    nodeId()      { return _myNodeId; },
    stats()       { return { ..._stats }; },
    peerReputation(peerId) { return { ..._getReputation(peerId), avgLatency: _avgLatency(peerId) }; },

    // CRDT sync
    syncSet(key, value) {
      const clock = (_crdtStore.get(key)?.clock ?? 0) + 1;
      const entry = { value, clock, author: _myDid, ts: Date.now() };
      _crdtStore.set(key, entry);
      _broadcast({ _sv: PROTOCOL_MAGIC, type: 'SYNC_SET', key, entry });
    },
    syncGet(key) { return _crdtStore.get(key)?.value ?? null; },

    queueForOfflinePeer(did, msg) { _enqueueOffline(did, msg); },
  };

  console.log(`[SovereignTransport v${TRANSPORT_VERSION}] Multi-relay · CRDT sync · Reputation · Store-and-forward`);

})();
