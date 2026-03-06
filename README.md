# ⬡ SOVEREIGN OS

**A self-sovereign, peer-to-peer operating environment that runs entirely in your browser.**

No servers. No accounts. No surveillance. Every key, every message, every file — stored on your device, yours alone.

---

## What Is Sovereign?

Sovereign is a decentralized identity and communication stack built as a suite of standalone HTML files. There is no backend, no cloud, no login system. Open a file in a browser and it runs.

Your cryptographic identity is generated locally and protected by a passphrase-encrypted vault. Your private key lives inside the Security Kernel — a Service Worker that is isolated from every tab, including from XSS — and never surfaces to page memory. Your messages travel peer-to-peer with Double Ratchet forward secrecy. Your sessions are signed by keys only you hold.

It is designed for people who refuse to rent their digital life from corporations, platforms, or governments. Every node is equal. Every connection is direct.

The name is not branding. It is a statement of intent.

---

## Quick Start

**No install. No build. No server.**

```
1. Download and unzip the package
2. Serve the folder over HTTP (required — Service Worker does not run on file://)
3. Open index.html in Chrome, Brave, Firefox, or Edge
4. Identity tab → set a passphrase → Generate Identity
5. Connect tab → the public relay connects automatically
6. Share your DID or use the QR code to invite a peer
```

The included public relay (`wss://sovereign-relay.fly.dev`) connects automatically.
No configuration needed for same-network or cross-internet peer discovery.

### Serving locally

```bash
npx serve .
# or
python3 -m http.server 8080
# or
php -S localhost:8080
```

> **Service Worker note:** `genesis_sw.js` (the Security Kernel) requires HTTP — not `file://`. All local server options above work. Opening `index.html` directly from a file manager will run the UI but skip key isolation.

---

## File Structure

```
sovereign/
├── index.html          ← Genesis Node        Identity, peers, messages, network map
├── os.html             ← Sovereign OS        Kernel, governance, trust graph, asset layer
├── forge.html          ← Forge Platform      Social feed, AI Studio, marketplace, app builder
├── square.html         ← Forge Square        Community hub, DMs, channels
├── studio.html         ← Forge Studio        Build, publish, and monetize sovereign apps
├── mail.html           ← Sovereign Mail      Layered encrypted mail — inbox, feed, archive
├── messenger.html      ← Messenger           Real-time P2P encrypted chat
├── attack.html         ← Attack Command      Adversarial security and audit platform
├── search.html         ← Sovereign Search    Network-wide distributed search
├── portal.html         ← Sovereign Portal    Onboarding gateway and personal profile hub
├── relay.html          ← Sovereign Relay     WebSocket relay with live admin UI
├── finance.html        ← Sovereign Finance   AI-governed payments, P2P wallet, Merkle audit ledger
├── bridge.html         ← Protocol Bridge     Nostr, Matrix, RSS, ActivityPub gateway
├── transport.js        ← Transport Layer     WebRTC + mesh + blockchain RPC module
├── sovereign_fsm.js    ← FSM Kernel          State machine — 5 machines, 5 invariants
├── sovereign_security.js ← Security Utils    Sanitize, persist, self-hash, Worker keygen
└── genesis_sw.js       ← Security Kernel     15-pattern cryptographic service worker
```

Everything starts at `index.html`. All other apps share the same identity layer.

---

## Connecting to Other Peers

### Same device, multiple tabs
Automatic via BroadcastChannel. Open any two Sovereign pages — they find each other instantly. No configuration.

### Different devices, same local network
WebRTC handshake. Both nodes connect to the same relay and exchange credentials, then go direct:
1. Both peers open `index.html`
2. Both enter the same relay URL in **Connect → Relay** (default: `wss://sovereign-relay.fly.dev`)
3. Connection opens; relay exits the path after handshake

### Different networks (internet peers)
Same as above — the public relay at `wss://sovereign-relay.fly.dev` handles cross-network discovery automatically. Once the WebRTC connection is established, all traffic is direct P2P.

### Manual handshake (fully offline, no relay)
1. Connect → Generate Offer → copy packet or show QR
2. Send to peer by any means (text, email, airdrop, printed paper)
3. Peer pastes into Receive Handshake → copies back the Answer
4. Paste the Answer → connection opens

No server ever touched the exchange.

### Public Space
The default public relay is:
```
wss://sovereign-relay.fly.dev
```
All Sovereign nodes using this relay can discover and connect to each other. The relay **does not read, store, or log message content** — it only brokers the WebRTC handshake. Once two peers connect, they go direct and the relay is out of the path.

To use your own relay instead, enter its WSS URL in **Connect → Relay** and press Connect.

---

## The Apps

### ⬡ Genesis Node — `index.html`

The root of the system. Handles:

- **Identity** — ECDSA P-256 keypair generation, passphrase-encrypted vault, DID management
- **Network map** — Animated canvas showing all apps and their relationships in the mesh
- **Peer connect** — WebRTC offer/answer handshake, relay discovery, QR code connect
- **Messages** — P2P encrypted messaging with all connected peers
- **Search** — Cross-network search across messages, peers, and apps
- **Apps** — Launcher for the full application suite

### ⬡ Sovereign OS — `os.html`

The system kernel and control plane:

- **Birth Certificate** — On-chain identity anchoring and sovereign record
- **Stack** — Full layer view of running system components
- **Event Runtime** — Real-time event log and system signal monitor
- **Trust Graph** — Visualize and manage your web of trusted peers
- **Identity Vault** — Key management, Shamir recovery share generation, export, and verification
- **Governance** — Proposal, vote, and ratification flows for DAO-style decisions
- **Asset Valuation** — Token and asset tracking layer
- **AI Witness** — Local Ollama integration for identity notarization

### ⬡ Forge — `forge.html`

The decentralized social and creative platform: Square, AI Studio, Marketplace, App Builder, Docs, Credits.

### ⬡ Forge Square — `square.html`

Community hub: public feed, direct messages, topic channels, file sharing, contacts.

### ⬡ Forge Studio — `studio.html`

Creative workspace for building and shipping sovereign apps: editor, app manager, publish, and monetization flows.

### ⬡ Sovereign Mail — `mail.html`

Layered encrypted message system: Inbox, Feed, Frozen Archive, Drafts/Sent.

### ⬡ Messenger — `messenger.html`

Minimal, fast, real-time P2P encrypted chat. Messages are signed and delivered over WebRTC DataChannels with Double Ratchet forward secrecy and BroadcastChannel fallback for same-device tabs.

### ⬡ Attack Command — `attack.html`

Adversarial security and audit platform: Overview, Solidity Analyzer, RRTK, Fuzzer, Invariant Checker, Benchmark, Modules, Log.

### ⬡ Sovereign Search — `search.html`

Distributed search across your entire sovereign network — messages, peers, apps, and content. All assembled locally. No query leaves your device.

### ⬡ Sovereign Portal — `portal.html`

First-run onboarding flow and personal profile hub. Loads `sovereign_fsm.js` + `transport.js` for full identity state management.

### ⬡ Sovereign Relay — `relay.html`

Optional WebSocket relay with live admin UI. Sections: **Peers · Channel · Signal · Graph**

To self-host a relay, see the **Self-Hosting** section below.

### ⬡ Protocol Bridge — `bridge.html`

Gateway to the open protocol ecosystem: Nostr, Matrix, RSS/Atom, WebFinger/ActivityPub.

### ⬡ Transport Layer — `transport.js`

Drop-in module. Self-initializes on `DOMContentLoaded`. Wires up:

- WebRTC mesh transport (default: `wss://sovereign-relay.fly.dev`)
- DHT-based message routing via `sha256(TOPIC_PREFIX + recipient_did)`
- BroadcastChannel tab-to-tab fallback
- Blockchain RPC polling (configurable; disabled by default)

Include with `<script src="transport.js"></script>` **after** `sovereign_fsm.js`.

---

## Security Architecture

### The Security Kernel

`genesis_sw.js` implements 15 security patterns across 5 tiers:

| Tier | Patterns | What it does |
|---|---|---|
| I — Crypto Kernel | 01–04 | Key oracle, Double Ratchet sessions, dual vault keys, 512-bit entropy pool |
| II — Network Security | 05–07 | Network firewall, domain allowlist, onion routing, cover traffic & jitter |
| III — Integrity | 08–10 | Integrity manifest (SHA-256 per resource), hash-chained audit log, capability tokens |
| IV — Resilience | 11–13 | Anomaly detector, panic / deadman switch, Byzantine fault detector |
| V — Novel | 14–15 | PIR (Private Information Retrieval) fetch, threshold signing |

**Critical isolation:** The Service Worker does not share memory with any page. An XSS attacker who fully controls every active tab cannot read the Security Kernel heap.

### The FSM Kernel — `sovereign_fsm.js`

Five state machines enforce system invariants at runtime:

| Machine | States |
|---|---|
| `vault` | LOCKED → UNLOCKING → UNLOCKED (+ CREATING, REKEYING, PANICKED) |
| `identity` | NONE → GENERATING → READY → DESTROYED |
| `transport` | OFFLINE → DISCOVERING → CONNECTED → DEGRADED |
| `kdf` | IDLE → STRETCHING → READY → CONSUMED |
| `ratchet` (per peer) | UNINIT → KEYED → ACTIVE → STALE |

Five invariants are checked after every transition. Any violation emits `sovereign:fsm:INVARIANT_VIOLATION` and logs to the audit chain.

### Identity

ECDSA P-256 keypair (signing) + ECDH P-256 (key exchange), Web Crypto API, entirely in-browser. Private key protected by passphrase (PBKDF2-derived AES-KW-256, 600,000 iterations), held exclusively in the Service Worker. Never in tab memory.

**Key recovery:** Shamir 3-of-5 — any 3 of 5 shares reconstruct the key. Below 3 shares, information-theoretic security applies.

**Deniable vault:** Two passphrases open different key material (Pattern 03).

### Messaging transport priority

| Layer | Scope | Security |
|---|---|---|
| BroadcastChannel | Same device | Instant, zero config |
| WebRTC DataChannel | Cross-device direct | DTLS + Double Ratchet forward secrecy |
| WebSocket Relay | Cross-network | Relay sees session tokens only, not content |

---

## Self-Hosting Guide

Sovereign is pure static HTML — no application server, no database, no runtime dependencies.

### Option 1 — Local Machine

```bash
npx serve .
python3 -m http.server 8080
php -S localhost:8080
caddy file-server --browse
```

### Option 2 — Static File Host (GitHub Pages, Netlify, Cloudflare Pages)

No build step. No configuration. Drag and drop or connect your repo.

- **GitHub Pages:** Settings → Pages → select branch and root folder
- **Netlify:** Drop the folder at netlify.com/drop. Build command: leave blank
- **Cloudflare Pages:** Connect repo. Build command: blank. Output directory: `/`

### Option 3 — VPS / Dedicated Server (Nginx)

```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /var/www/sovereign;
    index index.html;

    location / { try_files $uri $uri/ /index.html; }

    add_header Cross-Origin-Opener-Policy same-origin;
    add_header Cross-Origin-Embedder-Policy require-corp;

    location ~* \.(js|css|png|ico|woff2)$ { expires 1y; add_header Cache-Control "public, immutable"; }
    location ~* \.html$ { add_header Cache-Control "no-cache"; }
}
```

Add HTTPS: `certbot --nginx -d your-domain.com`

### Option 4 — Self-Hosting the Relay

`relay.html` is the admin UI. The actual relay is a WebSocket server process.

**Minimal Node.js relay:**

```javascript
const { WebSocketServer } = require('ws');
const PORT = process.env.PORT || 8765;
const wss  = new WebSocketServer({ port: PORT });
const peers = new Map();

wss.on('connection', (ws) => {
  let myToken = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'HELLO' && msg.token) {
      myToken = msg.token;
      peers.set(myToken, ws);
      ws.send(JSON.stringify({ type: 'HELLO_ACK', peers: [...peers.keys()] }));
      broadcast({ type: 'PEER_ONLINE', token: myToken }, myToken);
      return;
    }

    if (msg.to && peers.has(msg.to)) {
      peers.get(msg.to).send(JSON.stringify({ ...msg, from: myToken }));
    }
  });

  ws.on('close', () => {
    if (myToken) {
      peers.delete(myToken);
      broadcast({ type: 'PEER_OFFLINE', token: myToken }, myToken);
    }
  });

  function broadcast(msg, except) {
    const payload = JSON.stringify(msg);
    for (const [token, sock] of peers) {
      if (token !== except && sock.readyState === 1) sock.send(payload);
    }
  }
});

console.log(`Sovereign relay listening on ws://0.0.0.0:${PORT}`);
```

```bash
npm install ws && node relay-server.js

# Keep alive with pm2:
npm install -g pm2
pm2 start relay-server.js --name sovereign-relay && pm2 save && pm2 startup
```

**Nginx WebSocket proxy (for HTTPS/WSS):**

```nginx
location /relay {
    proxy_pass http://localhost:8765;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;
}
```

Relay URL: `wss://your-domain.com/relay`

### Option 5 — LAN / Intranet Node

```bash
npx serve --listen 0.0.0.0 --port 8080 .
```

Other devices open `http://192.168.x.x:8080/index.html`. Run the relay on the same machine for peer discovery.

---

## STUN / TURN Configuration

Default STUN servers (privacy-respecting community servers, not Google):

```
stun:openrelay.metered.ca:80
stun:stun.relay.metered.ca:80
```

For symmetric NAT (common in corporate networks), add a TURN server to `SOVEREIGN_ICE_SERVERS` in `sovereign_security.js`:

```javascript
window.SOVEREIGN_ICE_SERVERS = [
  { urls: 'stun:openrelay.metered.ca:80' },
  { urls: 'turn:your-domain.com:3478', username: 'sovereign', credential: 'your-password' }
];
```

Or set `sovereign_custom_stun` in localStorage at runtime — `sovereign_security.js` reads it automatically on load.

---

## Correct Script Loading Order

Every HTML file that uses transport or FSM features must load scripts in this order:

```html
<script src="sovereign_security.js"></script>  <!-- must be first -->
<script src="sovereign_fsm.js"></script>        <!-- must come before transport.js -->
<script src="transport.js"></script>            <!-- initializes on DOMContentLoaded -->
```

`sovereign_security.js` must be loaded first — it defines `sanitize()`, `sovereignEphemeralToken()`, `SOVEREIGN_ICE_SERVERS`, and `SovereignSessionStore`, all of which `transport.js` and `sovereign_fsm.js` depend on.

---

## Browser Compatibility

| Browser | Status |
|---|---|
| Chrome / Chromium | ✅ Full support |
| Brave | ✅ Full support |
| Firefox | ✅ Full support |
| Edge | ✅ Full support |
| Safari | ⚠️ Partial — WebRTC may require flags |
| Mobile Chrome / Firefox | ✅ Supported |

**Required APIs:** Web Crypto · IndexedDB · WebRTC · BroadcastChannel · Service Worker
**Optional:** BarcodeDetector (QR scanning — Chrome/Chromium only)

---

## Running Offline

`genesis_sw.js` registers a service worker that caches all assets on first load. After that, the full identity and local data stack runs without a network connection. Peer connections still require the network, but all UI, key management, and stored data work fully offline.

---

## Security Model Summary

| Property | Status |
|---|---|
| Private key never in tab memory | ✅ Enforced — Service Worker heap only |
| Key encrypted at rest | ✅ AES-256-GCM, PBKDF2 600k iterations |
| Key recovery without single point of failure | ✅ Shamir 3-of-5 |
| Deniable vault under duress | ✅ Dual vault keys (Pattern 03) |
| Forward secrecy for messaging | ✅ Double Ratchet per peer (Pattern 02) |
| No external network requests | ✅ CSP + Security Kernel firewall (Pattern 05) |
| XSS isolation for key material | ✅ Service Worker memory inaccessible from page |
| Entropy quality gate | ✅ 512-bit pool, generation blocked below threshold |
| Hash-chained audit log | ✅ Pattern 09 — tamper-evident |
| FSM invariants enforced at runtime | ✅ 5 machines, 5 invariants checked every transition |
| Relay privacy | ✅ Ephemeral daily HMAC tokens — relay sees tokens, not DIDs |
| No account database to leak | ✅ No server, no database |

---

## Threat Model

A full formal threat model is published with this repository: `sovereign_os_threat_model_v7.docx`

---

## Changelog

### v2.1 — Bug Fixes

- **FSM ratchet transitions added** — `sovereign_fsm.js` TABLE was missing all per-peer ratchet machine transitions (UNINIT → KEYED → ACTIVE → STALE). Every `ratchet.send()` call was silently returning `false`. Transitions and FSM machine name resolution for `ratchet:*` prefixed machines are now correct.
- **Public relay default** — `transport.js` and `index.html` inline transport both now default to `wss://sovereign-relay.fly.dev` instead of `ws://localhost:8765`. Nodes connect to the public space automatically out of the box.
- **portal.html script order fixed** — `sovereign_fsm.js` was missing from `portal.html`'s script tags; `transport.js` depends on `window.SovereignFSM`. Load order is now: `sovereign_security.js` → `sovereign_fsm.js` → `transport.js`.

---

## Author

**James Chapman** — XheCarpenXer
iconoclastdao@gmail.com
An Iconoclast DAO project. Built by hand. Owned by no one except its creator and the people who use it.

---

## License

Sovereign is dual-licensed. See `LICENSE.md` for full terms.

**License A — Personal & Open-Source (free):** For individuals, researchers, students, and open-source projects.

**License B — Commercial & Institutional (paid or reciprocal):** Required for corporations, governments, military, law enforcement, and revenue-generating organizations.

Sovereign may not be used for mass surveillance, cryptographic backdooring, or targeting individuals based on protected characteristics.

Contact **iconoclastdao@gmail.com** for commercial licensing.

---

*"The tools of sovereignty should be sovereign themselves."*
