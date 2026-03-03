// ═══════════════════════════════════════════════════════════════════
//  SOVEREIGN SERVICE WORKER — genesis_sw.js
//  This is the always-on daemon. It persists even when all tabs close.
//
//  Responsibilities:
//    1. Hold all peer WebRTC connections across tab lifecycle
//    2. Maintain DID → address registry (in-memory + chain-synced)
//    3. Expose Sovereign.connect(did) to all tabs via postMessage
//    4. Route incoming messages to the correct tab
//    5. Queue messages for offline tabs, flush on wake
//
//  Message protocol (tab ↔ SW):
//    Tab → SW:  { cmd: 'CONNECT'|'SEND'|'REGISTER'|'STATUS', ...args }
//    SW → Tab:  { event: 'CONNECTED'|'MESSAGE'|'STATUS'|'ERROR', ...data }
// ═══════════════════════════════════════════════════════════════════

const SW_VERSION = 'sovereign-sw-v1';

// ── State ────────────────────────────────────────────────────────
const _peers    = new Map();   // did → PeerState
const _registry = new Map();   // did → { meshAddr, pubKey, ts }
const _queue    = new Map();   // did → [pending messages]
let   _myDid    = null;
let   _myPubKey = null;
let   _clients  = new Set();   // connected tabs

// ── SW Lifecycle ─────────────────────────────────────────────────
self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', e  => e.waitUntil(self.clients.claim()));

// ── Tab Message Bus ───────────────────────────────────────────────
self.addEventListener('message', async (e) => {
  const { cmd, ...args } = e.data || {};
  const client = e.source;

  switch (cmd) {

    case 'BOOT':
      // Tab registers identity with the SW daemon
      _myDid    = args.did;
      _myPubKey = args.pubKey;
      _registry.set(args.did, { meshAddr: args.did, pubKey: args.pubKey, ts: Date.now(), self: true });
      _broadcast({ event: 'SW_READY', did: _myDid, version: SW_VERSION });
      break;

    case 'CONNECT':
      // Tab requests connection to a DID
      await _handleConnect(args.did, client);
      break;

    case 'SEND':
      // Tab wants to send a message to a DID
      await _handleSend(args.did, args.msg, client);
      break;

    case 'REGISTER_PEER':
      // Tab learned about a peer (from chain scan or manual handshake)
      _registry.set(args.did, { meshAddr: args.did, pubKey: args.pubKey, ts: Date.now() });
      _broadcast({ event: 'PEER_KNOWN', did: args.did });
      break;

    case 'STATUS':
      client.postMessage({
        event:   'STATUS',
        did:     _myDid,
        peers:   [..._peers.entries()].map(([did, p]) => ({ did, state: p.state })),
        known:   _registry.size,
        version: SW_VERSION,
      });
      break;

    case 'OFFER_RECEIVED':
      // Joiner side: tab received an offer, SW tracks the pending connection
      _peers.set(args.peerId, { state: 'handshake', channel: null, did: args.peerId });
      _broadcast({ event: 'PEER_HANDSHAKE', did: args.peerId });
      break;

    case 'CHANNEL_OPEN':
      // Tab reports a DataChannel is now open
      if (_peers.has(args.did)) {
        _peers.get(args.did).state = 'open';
      } else {
        _peers.set(args.did, { state: 'open', did: args.did });
      }
      _broadcast({ event: 'PEER_CONNECTED', did: args.did });
      // Flush queued messages for this peer
      _flushQueue(args.did);
      break;

    case 'CHANNEL_CLOSED':
      if (_peers.has(args.did)) _peers.get(args.did).state = 'closed';
      _broadcast({ event: 'PEER_DISCONNECTED', did: args.did });
      break;

    case 'INCOMING_MSG':
      // Tab received a message on a DataChannel, route to all tabs
      _broadcast({ event: 'MESSAGE', from: args.did, msg: args.msg });
      break;
  }
});

async function _handleConnect(targetDid, requestingClient) {
  if (!targetDid) return;

  // Already open?
  const existing = _peers.get(targetDid);
  if (existing?.state === 'open') {
    requestingClient.postMessage({ event: 'ALREADY_CONNECTED', did: targetDid });
    return;
  }

  // Mark as handshake in progress
  _peers.set(targetDid, { state: 'handshake', did: targetDid });
  _broadcast({ event: 'PEER_HANDSHAKE', did: targetDid });

  // Tell the tab to initiate WebRTC offer
  // (SW can't do WebRTC directly — only tabs can create RTCPeerConnection)
  requestingClient.postMessage({ event: 'INITIATE_WEBRTC', did: targetDid });
}

async function _handleSend(targetDid, msg, fromClient) {
  const peer = _peers.get(targetDid);

  if (peer?.state === 'open') {
    // Tell the tab that owns this connection to send
    _broadcast({ event: 'RELAY_SEND', did: targetDid, msg });
  } else {
    // Queue for when they come online
    if (!_queue.has(targetDid)) _queue.set(targetDid, []);
    _queue.get(targetDid).push(msg);
    fromClient.postMessage({ event: 'MSG_QUEUED', did: targetDid, queueLen: _queue.get(targetDid).length });
  }
}

function _flushQueue(did) {
  const q = _queue.get(did);
  if (!q || !q.length) return;
  _broadcast({ event: 'FLUSH_QUEUE', did, messages: q });
  _queue.delete(did);
}

function _broadcast(msg) {
  self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    .then(clients => clients.forEach(c => c.postMessage(msg)));
}
