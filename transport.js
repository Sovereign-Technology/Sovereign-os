/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║          SOVEREIGN TRANSPORT LAYER  v1.0                ║
 * ║  Bridges your UI to: Blockchain Ledger + Mesh Network   ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * DROP THIS SCRIPT INTO ANY SOVEREIGN HTML FILE.
 * It wires itself in automatically on DOMContentLoaded.
 *
 * ARCHITECTURE:
 *   Browser UI
 *       │
 *       ▼
 *   SovereignTransport  ◄── YOU ARE HERE
 *      ├── MeshChannel    (WebSocket → local mesh node)
 *      ├── ChainChannel   (HTTP RPC → blockchain node)
 *      └── BroadcastChannel (tab-to-tab, offline fallback)
 *
 * CONFIGURATION (edit the CONFIG block below):
 *   MESH_WS_URL  → your libp2p/gossipsub node WebSocket
 *   CHAIN_RPC    → your blockchain RPC endpoint
 *   POLL_MS      → how often to check chain for incoming msgs
 */

// ─────────────────────────────────────────────
//  CONFIG — edit these to match your nodes
// ─────────────────────────────────────────────
const SOVEREIGN_CONFIG = {
  // Your local mesh node WebSocket (libp2p, gossipsub, etc.)
  // Run: npx @libp2p/daemon or your custom node
  MESH_WS_URL: 'ws://localhost:8765',

  // Your blockchain RPC (Solana, custom chain, etc.)
  // Replace with your actual RPC endpoint
  CHAIN_RPC: 'http://localhost:8899',

  // Polling interval for incoming chain messages (ms)
  POLL_MS: 3000,

  // Topic prefix for DHT routing
  // Messages land at: sha256(TOPIC_PREFIX + recipient_did)
  TOPIC_PREFIX: 'sovereign:msg:',

  // Enable debug logs in console
  DEBUG: true,

  // Retry config
  RECONNECT_DELAY_MS: 5000,
  MAX_RECONNECT_ATTEMPTS: 10,
};

// ─────────────────────────────────────────────
//  SOVEREIGN TRANSPORT — core class
// ─────────────────────────────────────────────
class SovereignTransport {
  constructor(config = SOVEREIGN_CONFIG) {
    this.cfg = config;
    this._meshSocket = null;
    this._meshReady = false;
    this._reconnectCount = 0;
    this._listeners = [];          // { did, callback }
    this._pendingQueue = [];       // messages queued while offline
    this._pollTimer = null;
    this._myDid = null;
    this._seenIds = new Set();     // dedup incoming

    // Tab-to-tab fallback (works even with no network)
    this._localBus = new BroadcastChannel('sovereign_transport');
    this._localBus.onmessage = (e) => this._handleIncoming(e.data, 'local');

    this.log('SovereignTransport initialized');
  }

  // ── PUBLIC API ─────────────────────────────

  /**
   * Call this once your identity is loaded.
   * @param {string} did - your DID string
   */
  async connect(did) {
    this._myDid = did;
    this.log(`Connecting as ${did}`);

    // Start mesh WebSocket
    await this._connectMesh();

    // Start chain polling for incoming messages
    this._startChainPoll();

    // Emit status
    this._emit('transport:status', { mesh: this._meshReady, chain: true });
  }

  /**
   * Send a message. Call this after your local dbPut().
   * @param {object} msg - the signed message object from sendMsg()
   * @returns {object} { mesh: bool, chain: bool, queued: bool }
   */
  async send(msg) {
    const envelope = this._wrap(msg);
    const result = { mesh: false, chain: false, queued: false };

    // 1. Always broadcast to local tabs (instant, zero latency)
    this._localBus.postMessage(envelope);
    this.log(`[LOCAL BUS] broadcasted msg ${msg.id}`);

    // 2. Send via mesh (fast propagation)
    if (this._meshReady) {
      result.mesh = await this._meshSend(envelope);
    }

    // 3. Anchor to chain (permanent record)
    result.chain = await this._chainAppend(envelope);

    // 4. If both failed, queue for retry
    if (!result.mesh && !result.chain) {
      this._pendingQueue.push(envelope);
      result.queued = true;
      this.log(`[QUEUE] msg ${msg.id} queued (${this._pendingQueue.length} pending)`);
    }

    return result;
  }

  /**
   * Register a callback for incoming messages addressed to a DID.
   * @param {string} did - DID to listen for
   * @param {function} callback - called with (msg, source)
   */
  subscribe(did, callback) {
    this._listeners.push({ did, callback });
    this.log(`Subscribed to messages for ${did}`);

    // Subscribe on mesh topic
    if (this._meshReady) {
      this._meshSubscribe(did);
    }
  }

  /**
   * Graceful shutdown.
   */
  disconnect() {
    if (this._meshSocket) this._meshSocket.close();
    if (this._pollTimer) clearInterval(this._pollTimer);
    this._localBus.close();
    this.log('Transport disconnected');
  }

  // ── MESH (WebSocket) ───────────────────────

  async _connectMesh() {
    return new Promise((resolve) => {
      try {
        this._meshSocket = new WebSocket(this.cfg.MESH_WS_URL);

        this._meshSocket.onopen = () => {
          this._meshReady = true;
          this._reconnectCount = 0;
          this.log(`[MESH] Connected to ${this.cfg.MESH_WS_URL}`);

          // Re-subscribe all listeners after reconnect
          this._listeners.forEach(l => this._meshSubscribe(l.did));

          // Flush pending queue
          this._flushQueue();

          this._emit('transport:mesh', { status: 'connected' });
          resolve(true);
        };

        this._meshSocket.onmessage = (e) => {
          try {
            const envelope = JSON.parse(e.data);
            this._handleIncoming(envelope, 'mesh');
          } catch (err) {
            this.log('[MESH] Bad message format', err);
          }
        };

        this._meshSocket.onclose = () => {
          this._meshReady = false;
          this.log('[MESH] Disconnected. Reconnecting...');
          this._emit('transport:mesh', { status: 'disconnected' });
          this._scheduleReconnect();
          resolve(false);
        };

        this._meshSocket.onerror = (e) => {
          this.log('[MESH] Error:', e.message || 'connection refused');
          // Don't crash — fall back to chain-only
          resolve(false);
        };
      } catch (err) {
        this.log('[MESH] Could not connect:', err.message);
        resolve(false);
      }
    });
  }

  _scheduleReconnect() {
    if (this._reconnectCount >= this.cfg.MAX_RECONNECT_ATTEMPTS) {
      this.log('[MESH] Max reconnect attempts reached. Running chain-only.');
      return;
    }
    this._reconnectCount++;
    setTimeout(() => this._connectMesh(), this.cfg.RECONNECT_DELAY_MS);
  }

  async _meshSend(envelope) {
    if (!this._meshReady) return false;
    try {
      const topic = await this._topicFor(envelope.to);
      this._meshSocket.send(JSON.stringify({
        type: 'PUBLISH',
        topic,
        data: envelope,
      }));
      this.log(`[MESH] Sent to topic ${topic.slice(0, 16)}…`);
      return true;
    } catch (err) {
      this.log('[MESH] Send failed:', err.message);
      return false;
    }
  }

  async _meshSubscribe(did) {
    if (!this._meshReady) return;
    const topic = await this._topicFor(did);
    this._meshSocket.send(JSON.stringify({
      type: 'SUBSCRIBE',
      topic,
    }));
    this.log(`[MESH] Subscribed to topic for ${did.slice(0, 20)}…`);
  }

  // ── CHAIN (HTTP RPC) ───────────────────────

  async _chainAppend(envelope) {
    try {
      const topic = await this._topicFor(envelope.to);

      // ── ADAPT THIS TO YOUR CHAIN ──────────────────────────────
      // This calls a generic JSON-RPC endpoint.
      // Replace with your chain's actual method.
      //
      // Solana example:
      //   method: 'sendTransaction', with memo instruction containing envelope
      //
      // Custom chain example:
      //   method: 'sovereign_appendMessage'
      //
      // Ethereum example:
      //   method: 'eth_sendRawTransaction'
      // ─────────────────────────────────────────────────────────

      const payload = {
        jsonrpc: '2.0',
        id: 1,
        method: 'sovereign_appendMessage',   // ← change to your chain method
        params: {
          topic,
          blob: btoa(JSON.stringify(envelope)),  // base64 encoded encrypted blob
          sender: this._myDid,
        },
      };

      const res = await fetch(this.cfg.CHAIN_RPC, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(8000),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      if (data.error) throw new Error(data.error.message);

      this.log(`[CHAIN] Appended: txid=${data.result?.txid || 'ok'}`);
      return true;
    } catch (err) {
      this.log('[CHAIN] Append failed:', err.message);
      return false;
    }
  }

  _startChainPoll() {
    if (this._pollTimer) clearInterval(this._pollTimer);
    this._pollTimer = setInterval(() => this._pollChain(), this.cfg.POLL_MS);
    this.log(`[CHAIN] Polling every ${this.cfg.POLL_MS}ms`);
  }

  async _pollChain() {
    if (!this._myDid) return;
    try {
      const topic = await this._topicFor(this._myDid);

      // ── ADAPT THIS TO YOUR CHAIN ──────────────────────────────
      // Replace 'sovereign_getMessages' with your chain's read method
      // ─────────────────────────────────────────────────────────

      const res = await fetch(this.cfg.CHAIN_RPC, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'sovereign_getMessages',   // ← change to your chain method
          params: { topic, since: this._lastPollTs || 0 },
        }),
        signal: AbortSignal.timeout(5000),
      });

      if (!res.ok) return;
      const data = await res.json();
      if (data.result?.messages) {
        this._lastPollTs = Date.now();
        data.result.messages.forEach(blob => {
          try {
            const envelope = JSON.parse(atob(blob));
            this._handleIncoming(envelope, 'chain');
          } catch {}
        });
      }
    } catch (err) {
      this.log('[CHAIN POLL] Error:', err.message);
    }
  }

  // ── INCOMING MESSAGE HANDLER ───────────────

  _handleIncoming(envelope, source) {
    if (!envelope?.id) return;

    // Dedup — same message can arrive via mesh + chain
    if (this._seenIds.has(envelope.id)) return;
    this._seenIds.add(envelope.id);
    if (this._seenIds.size > 1000) {
      // Prune oldest
      const arr = [...this._seenIds];
      arr.splice(0, 200).forEach(id => this._seenIds.delete(id));
    }

    this.log(`[INCOMING] msg ${envelope.id} via ${source}`);

    // Notify matching listeners
    this._listeners.forEach(({ did, callback }) => {
      if (envelope.to === did || envelope.from === did) {
        try { callback(this._unwrap(envelope), source); }
        catch (err) { this.log('Listener error:', err); }
      }
    });

    // Also fire a DOM event so any page can listen
    window.dispatchEvent(new CustomEvent('sovereign:message', {
      detail: { msg: this._unwrap(envelope), source },
    }));
  }

  // ── HELPERS ────────────────────────────────

  _wrap(msg) {
    // In production: encrypt msg body with recipient pubkey before wrapping
    // For now: structure the envelope
    return {
      id: msg.id,
      from: msg.from,
      to: msg.to,
      ts: msg.ts,
      hash: msg.hash,
      sig: msg.sig,
      // Production: replace body with encrypt(JSON.stringify(msg), recipientPubKey)
      body: btoa(JSON.stringify(msg)),
    };
  }

  _unwrap(envelope) {
    // Production: decrypt body with your private key
    try { return JSON.parse(atob(envelope.body)); }
    catch { return envelope; }
  }

  async _topicFor(did) {
    // Deterministic topic: sha256(PREFIX + DID)
    const raw = new TextEncoder().encode(this.cfg.TOPIC_PREFIX + did);
    const hashBuf = await crypto.subtle.digest('SHA-256', raw);
    return Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async _flushQueue() {
    if (!this._pendingQueue.length) return;
    this.log(`[QUEUE] Flushing ${this._pendingQueue.length} queued messages`);
    const queue = [...this._pendingQueue];
    this._pendingQueue = [];
    for (const envelope of queue) {
      await this._meshSend(envelope);
      await this._chainAppend(envelope);
    }
  }

  _emit(event, detail) {
    window.dispatchEvent(new CustomEvent(event, { detail }));
  }

  log(...args) {
    if (this.cfg.DEBUG) console.log('[SovereignTransport]', ...args);
  }
}

// ─────────────────────────────────────────────
//  STATUS INDICATOR UI
//  Injects a small status dot into any Sovereign page
// ─────────────────────────────────────────────
function injectStatusDot() {
  const dot = document.createElement('div');
  dot.id = 'transport-dot';
  dot.innerHTML = `
    <style>
      #transport-dot {
        position: fixed; bottom: 12px; left: 12px; z-index: 9999;
        display: flex; align-items: center; gap: 6px;
        background: rgba(6,6,8,0.85); border: 1px solid #1a1a28;
        border-radius: 20px; padding: 5px 10px;
        font-family: 'Courier New', monospace; font-size: 9px;
        color: #94a3b8; backdrop-filter: blur(8px);
        transition: all 0.3s;
        pointer-events: none;
      }
      #transport-dot .dot {
        width: 6px; height: 6px; border-radius: 50%;
        background: #334155;
        transition: background 0.3s;
      }
      #transport-dot .dot.mesh  { background: #00ff88; box-shadow: 0 0 6px #00ff8866; }
      #transport-dot .dot.chain { background: #00d4ff; box-shadow: 0 0 6px #00d4ff66; }
      #transport-dot .dot.error { background: #ff3366; box-shadow: 0 0 6px #ff336666; }
    </style>
    <span class="dot" id="td-mesh" title="Mesh"></span>
    <span class="dot" id="td-chain" title="Chain"></span>
    <span id="td-label">TRANSPORT OFFLINE</span>
  `;
  document.body.appendChild(dot);

  window.addEventListener('transport:mesh', (e) => {
    const el = document.getElementById('td-mesh');
    if (!el) return;
    el.className = 'dot ' + (e.detail.status === 'connected' ? 'mesh' : 'error');
    updateLabel();
  });

  window.addEventListener('transport:status', (e) => {
    const chainEl = document.getElementById('td-chain');
    if (chainEl) chainEl.className = 'dot chain';
    updateLabel();
  });

  function updateLabel() {
    const meshOn  = document.getElementById('td-mesh')?.classList.contains('mesh');
    const chainOn = document.getElementById('td-chain')?.classList.contains('chain');
    const label   = document.getElementById('td-label');
    if (!label) return;
    if (meshOn && chainOn) label.textContent = 'MESH + CHAIN';
    else if (meshOn)       label.textContent = 'MESH ONLY';
    else if (chainOn)      label.textContent = 'CHAIN ONLY';
    else                   label.textContent = 'LOCAL ONLY';
  }
}

// ─────────────────────────────────────────────
//  AUTO-WIRE — patches sendMsg() and boots connect()
//  Works if this script is loaded AFTER the page JS
// ─────────────────────────────────────────────
window.SovereignTransport = SovereignTransport;
window._ST = null; // global transport instance

window.addEventListener('DOMContentLoaded', () => {
  injectStatusDot();
});

// Called by your page after identity loads:
// await window.sovereignConnect(myDID);
window.sovereignConnect = async function(did) {
  if (window._ST) window._ST.disconnect();
  window._ST = new SovereignTransport();
  await window._ST.connect(did);

  // Subscribe to incoming messages for this DID
  window._ST.subscribe(did, (msg, source) => {
    console.log(`[Sovereign] Incoming from ${source}:`, msg);
    // If the page has a receive handler, call it
    if (typeof window.onSovereignMessage === 'function') {
      window.onSovereignMessage(msg, source);
    }
  });

  return window._ST;
};

// Patch to call after sendMsg() saves to local DB:
// await window.sovereignSend(msg);
window.sovereignSend = async function(msg) {
  if (!window._ST) {
    console.warn('[Sovereign] Transport not connected. Call sovereignConnect(did) first.');
    return { queued: true };
  }
  return window._ST.send(msg);
};
