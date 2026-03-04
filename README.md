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
2. Open index.html in Chrome, Brave, Firefox, or Edge
3. Identity tab → set a passphrase → Generate Identity
4. Connect tab → share a handshake packet with a peer
5. You're on the network
```

For connections across different networks, both peers enter the same relay URL in the Connect tab. You can self-host a relay using `relay.html`.

> **Service Worker note:** The Security Kernel (`genesis_sw.js`) requires HTTP — not `file://`. Run a local server for full functionality:
> ```bash
> npx serve .
> # or
> python3 -m http.server 8080
> ```

---

## File Structure

```
sovereign/
├── index.html       ← Genesis Node        Identity, peers, messages, network map
├── os.html          ← Sovereign OS        Kernel, governance, trust graph, asset layer
├── forge.html       ← Forge Platform      Social feed, AI Studio, marketplace, app builder
├── square.html      ← Forge Square        Community hub, DMs, channels
├── studio.html      ← Forge Studio        Build, publish, and monetize sovereign apps
├── mail.html        ← Sovereign Mail      Layered encrypted mail — inbox, feed, archive
├── messenger.html   ← Messenger           Real-time P2P encrypted chat
├── attack.html      ← Attack Command      Adversarial security and audit platform
├── search.html      ← Sovereign Search    Network-wide distributed search
├── portal.html      ← Sovereign Portal    Onboarding gateway and personal profile hub
├── relay.html       ← Sovereign Relay     WebSocket relay with live admin UI
├── bridge.html      ← Protocol Bridge     Nostr, Matrix, RSS, ActivityPub gateway
├── transport.js     ← Transport Layer     WebRTC + mesh + blockchain RPC module
└── genesis_sw.js    ← Security Kernel     15-pattern cryptographic service worker
```

Everything starts at `index.html`. All other apps share the same identity layer.

---

## The Apps

### ⬡ Genesis Node — `index.html`

The root of the system. Handles:

- **Identity** — Ed25519 keypair generation, passphrase-encrypted vault, DID management
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

The decentralized social and creative platform:

- **Square** — Community feed, posts, reactions, discovery
- **AI Studio** — Local Ollama and compatible API integration
- **Marketplace** — Peer-to-peer exchange for apps, assets, and services
- **App Builder** — In-browser application construction
- **Docs** — Integrated documentation and knowledge base
- **Credits** — Reputation and contribution tracking

### ⬡ Forge Square — `square.html`

Focused community hub: public feed, direct messages, topic channels, file sharing, contacts.

### ⬡ Forge Studio — `studio.html`

Creative workspace for building and shipping sovereign apps: editor, app manager, publish, and monetization flows.

### ⬡ Sovereign Mail — `mail.html`

Layered encrypted message system:

- **Inbox** — Received messages across all connected peers
- **Feed** — Subscribed network updates and announcements
- **Frozen Archive** — Cryptographically sealed, tamper-evident message archive
- **Drafts / Sent** — Full message lifecycle management

### ⬡ Messenger — `messenger.html`

Minimal, fast, real-time P2P encrypted chat. Messages are signed and delivered over WebRTC DataChannels with Double Ratchet forward secrecy and BroadcastChannel fallback for same-device tabs.

### ⬡ Attack Command — `attack.html`

Adversarial security and audit platform:

- **Overview** — System threat surface and audit dashboard
- **Solidity Analyzer** — Static analysis for smart contracts
- **RRTK** — Rapid Response Toolkit for live simulation and incident response
- **Fuzzer** — Input fuzzing for contracts and protocol endpoints
- **Invariant Checker** — Formal property verification
- **Benchmark** — Performance and gas profiling
- **Modules** — Pluggable security analysis extensions
- **Log** — Full audit trail and event record

### ⬡ Sovereign Search — `search.html`

Distributed search across your entire sovereign network — messages, peers, apps, and content. All assembled locally. No query leaves your device.

### ⬡ Sovereign Portal — `portal.html`

First-run onboarding flow: username, keypair generation, Shamir share distribution, DID confirmation. After setup: personal profile hub, network status, peer directory, DMs, and settings.

### ⬡ Sovereign Relay — `relay.html`

Optional WebSocket relay with live admin UI. Brokers WebRTC handshakes across networks — once two peers connect, the relay exits the path. It does not read, store, or log message content.

Sections: **Peers** · **Channel** · **Signal** · **Graph**

### ⬡ Protocol Bridge — `bridge.html`

Gateway to the open protocol ecosystem:

- **Nostr** — Subscribe to relays, publish notes, read feeds, send encrypted DMs (NIP-04)
- **Matrix** — Join rooms and send messages against any Matrix homeserver
- **RSS / Atom** — Subscribe to any feed, with optional CORS proxy support
- **WebFinger / ActivityPub** — Resolve any Fediverse handle to its full identity record

The Bridge derives a Nostr (secp256k1) keypair deterministically from your Sovereign Ed25519 identity, maintaining cryptographic continuity across protocols.

### ⬡ Transport Layer — `transport.js`

Drop-in module for any Sovereign HTML file. Self-initializes on `DOMContentLoaded`, wiring up:

- WebRTC mesh transport
- libp2p / gossipsub mesh node bridge (configurable)
- Blockchain RPC polling (Solana-compatible, configurable)
- DHT-based message routing via `sha256(TOPIC_PREFIX + recipient_did)`
- BroadcastChannel tab-to-tab fallback

Include with a single `<script>` tag. Configure the top-level constants for your mesh node and RPC endpoint.

---

## Security Architecture

### The Security Kernel

`genesis_sw.js` is not a standard service worker — it is the cryptographic heart of the system. It implements 15 security patterns across 5 tiers:

| Tier | Patterns | What it does |
|---|---|---|
| I — Crypto Kernel | 01–04 | Key oracle, Double Ratchet sessions, dual vault keys, 512-bit entropy pool |
| II — Network Security | 05–07 | Network firewall, domain allowlist, onion routing, cover traffic & jitter |
| III — Integrity | 08–10 | Integrity manifest (SHA-256 per resource), hash-chained audit log, capability tokens |
| IV — Resilience | 11–13 | Anomaly detector, panic / deadman switch, Byzantine fault detector |
| V — Novel | 14–15 | PIR (Private Information Retrieval) fetch, threshold signing |

**The critical isolation property:** The Service Worker does not share memory with any page. An XSS attacker who fully controls every active tab cannot read the Security Kernel heap. This is the most important isolation primitive in the browser, and the reason private keys never appear in tab memory.

### Identity

Each user generates an **Ed25519 keypair** using the Web Crypto API — entirely in-browser. The private key is protected by a user-chosen passphrase (PBKDF2-derived AES-256-GCM) and held exclusively in the Security Kernel Service Worker. It never surfaces to page memory.

Your public identity is a **DID** (`did:sovereign:<pubkey-hex>`) derived deterministically from your public key. Share it like a username. Anyone can verify your signatures without trusting any third party.

**Key recovery** uses **Shamir 3-of-5 secret sharing** — your private key is split into 5 shares, any 3 of which reconstruct it. Distribute shares physically to trusted parties or storage locations. Below the 3-share threshold, information-theoretic security applies: an attacker with fewer than 3 shares learns nothing about the key.

The dual vault (Pattern 03) supports a **deniable/duress vault** — two passphrases open different key material, providing plausible deniability under coercion.

### Messaging

Messages are delivered over three transport layers in priority order:

| Layer | Scope | Security |
|---|---|---|
| BroadcastChannel | Same device, multiple tabs | Instant, zero configuration |
| WebRTC DataChannel | Cross-device, direct P2P | DTLS + Double Ratchet forward secrecy |
| WebSocket Relay | Cross-network, assisted discovery | Relay sees session tokens only, not content |

**Double Ratchet** (Pattern 02) provides forward secrecy: each message uses a new ephemeral key derived from a ratcheting chain. Compromise of any session key does not expose past or future messages.

### Entropy

Key generation seeds from `crypto.getRandomValues()` combined with a continuously-refreshed 512-bit entropy pool (Pattern 04) that mixes high-resolution timing samples and optional mouse-movement entropy. Key generation is blocked until the pool reaches sufficient variance.

### Storage

All persistent data lives in **IndexedDB** — never `localStorage`:

| Store | Contents |
|---|---|
| `identity` | Username, public key, DID, creation timestamp |
| `keyvault` | Encrypted private key (AES-256-GCM, passphrase-derived key) |
| `peers` | Known peer records — DID, name, last seen |
| `messages` | Message history per peer DID |
| `settings` | Relay URL, preferences, configuration |

Nothing is sent to any external service unless you initiate a peer connection.

> **Key responsibility:** Your identity lives in IndexedDB. Clearing browser site data deletes your keys permanently. Use **Identity → Backup** and keep your Shamir recovery shares before clearing browser data or switching devices.

---

## Connecting Peers

**Same device, multiple tabs** — automatic via BroadcastChannel. No configuration needed.

**Different devices, same network** — WebRTC handshake, exchange packet by any channel.

**Different devices, different networks:**
1. Both peers enter the same relay URL in **Connect → Relay**
2. Relay brokers the WebRTC negotiation
3. Once connected, all traffic is direct — relay exits the path

**Manual handshake (no relay, fully offline):**
1. Connect → Generate Offer → copy packet or show QR
2. Send to peer by any means (text, email, airdrop, printed paper)
3. Peer pastes into Receive Handshake → copies back the Answer
4. Paste the Answer → connection opens
5. No server ever touched the exchange

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

**Required browser APIs:** Web Crypto API · IndexedDB · WebRTC · BroadcastChannel · Service Worker  
**Optional:** BarcodeDetector (QR scanning — Chrome/Chromium only)

---

## Running Offline

`genesis_sw.js` registers a service worker that caches all assets on first load. After that, the full identity and local data stack runs without a network connection. Peer connections still require the network, but all UI, key management, and stored data work fully offline.

The service worker requires HTTP (not `file://`). Any local server works:

```bash
npx serve .
# or
python3 -m http.server 8080
```

---

## Self-Hosting Guide

Sovereign is pure static HTML — no application server, no database, no runtime dependencies.

### Option 1 — Local Machine

```bash
npx serve .                     # Node
python3 -m http.server 8080     # Python
php -S localhost:8080            # PHP
caddy file-server --browse       # Caddy (zero-config HTTPS)
```

### Option 2 — Static File Host (GitHub Pages, Netlify, Cloudflare Pages)

No build step. No configuration. Drag and drop or connect your repo.

- **GitHub Pages:** Settings → Pages → select branch and root folder
- **Netlify:** Drop the folder at netlify.com/drop. Build command: leave blank
- **Cloudflare Pages:** Connect repo. Build command: blank. Output directory: `/`

### Option 3 — VPS / Dedicated Server

**Nginx:**

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

**Caddy:**

```
your-domain.com {
    root * /var/www/sovereign
    file_server
    header Cross-Origin-Opener-Policy same-origin
    header Cross-Origin-Embedder-Policy require-corp
}
```

### Option 4 — Self-Hosting the Relay

The relay needs a persistent network presence. `relay.html` is an admin interface — the actual relay is a WebSocket server process.

**Minimal Node.js relay:**

```javascript
const { WebSocketServer } = require('ws');
const PORT = process.env.PORT || 8765;
const wss  = new WebSocketServer({ port: PORT });
const peers = new Map(); // sessionToken → socket

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

# Keep alive:
npm install -g pm2
pm2 start relay-server.js --name sovereign-relay && pm2 save && pm2 startup
```

**For HTTPS-served nodes, proxy the relay through Nginx (`wss://`):**

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

Default STUN servers:

```
stun:stun.l.google.com:19302
stun:stun1.l.google.com:19302
stun:stun.cloudflare.com:3478
```

For symmetric NAT (common in corporate networks), add a TURN server to `ICE_SERVERS` in `index.html`:

```javascript
const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'turn:your-domain.com:3478', username: 'sovereign', credential: 'your-password' }
];
```

Self-host with coturn: `apt install coturn` — see full config in the coturn documentation.

---

## Content Security Policy

Inline CSP on all files:

```
default-src 'none';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
connect-src 'self' http://localhost:11434 ws: wss: https:;
img-src 'self' data: blob:;
worker-src blob:;
```

`http://localhost:11434` is the local Ollama AI endpoint. Remove it if unused. Tighten `connect-src` to specific relay domains in production.

---

## Security Model Summary

| Property | Status |
|---|---|
| Private key never in tab memory | ✅ Enforced — lives in Service Worker heap only |
| Key encrypted at rest | ✅ AES-256-GCM, passphrase-derived key (PBKDF2) |
| Key recovery without single point of failure | ✅ Shamir 3-of-5 secret sharing |
| Deniable vault under duress | ✅ Dual vault keys (Pattern 03) |
| Forward secrecy for messaging | ✅ Double Ratchet per peer session (Pattern 02) |
| No external network requests | ✅ CSP enforced + Security Kernel firewall (Pattern 05) |
| XSS isolation for key material | ✅ Service Worker memory inaccessible from page context |
| Entropy quality gate | ✅ 512-bit pool, generation blocked below variance threshold |
| Hash-chained audit log | ✅ Pattern 09 — tamper-evident audit chain |
| Supply chain integrity | ⚠️ SHA-256 self-hash at load time planned — verify file hash against published releases |
| No account database to leak | ✅ No server, no database |

**Accepted limitations:** A browser extension with JavaScript execution access can read page memory (not the Service Worker). An active browser session is accessible to anyone with physical device access. The OS layer is below this application's trust boundary.

---

## Threat Model

A full formal threat model is published with this repository: `sovereign_os_threat_model_v7.docx`

It covers all protected assets, adversary classes (including relay operator and passive network observer), trust boundaries, formal security guarantees, accepted limitations, and the complete v7 design directive set. Read it before deploying in a high-risk context.

---

## Author

**James Chapman** — XheCarpenXer  
iconoclastdao@gmail.com  
An Iconoclast DAO project. Built by hand. Owned by no one except its creator and the people who use it.

---

## License

Sovereign is dual-licensed. See `LICENSE.md` for full terms.

**License A — Personal & Open-Source (free):** For individuals, researchers, students, and open-source projects. Use it, fork it, build on it, share it. Attribution required.

**License B — Commercial & Institutional (paid or reciprocal):** Required for corporations, governments, military, law enforcement, and revenue-generating organizations. Two paths: pay for a commercial license, or open-source all code built on Sovereign under the same terms.

Regardless of license tier, Sovereign may not be used for mass surveillance, cryptographic backdooring, or targeting individuals based on protected characteristics.

Contact **iconoclastdao@gmail.com** for commercial licensing.

---

*"The tools of sovereignty should be sovereign themselves."*
