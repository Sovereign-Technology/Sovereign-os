# ⬡ SOVEREIGN

**A self-sovereign, peer-to-peer operating environment that runs entirely in your browser.**

No servers. No accounts. No surveillance. Every key, every message, every file — stored on your device and yours alone.

---

## What Is Sovereign?

Sovereign is a decentralized identity and communication stack built as a suite of standalone HTML files. There is no backend, no cloud, no login system. Open a file in a browser and it runs. Your cryptographic identity is generated locally, encrypted at rest, and never transmitted without your explicit action. Your messages travel peer-to-peer or through a relay you choose and control.

It is designed for people who refuse to rent their digital life from corporations, platforms, or governments. Every node is equal. Every connection is direct. Every message is signed with keys only you hold.

The name is not branding. It is a statement of intent.

---

## Quick Start

**No install. No build. No server.**

1. Download and unzip the package
2. Open `index.html` in Chrome, Brave, Firefox, or Edge
3. Go to **Identity** → generate your sovereign keypair
4. Go to **Connect** → share a handshake packet with a peer
5. You're on the network

For connections across different networks or devices, both peers connect to a shared WebSocket relay URL in the Connect tab. You can self-host one using `relay.html`.

---

## File Structure

```
sovereign/
├── index.html        ← Genesis Node         Start here. Identity, network map, peer connect, messages
├── os.html           ← Sovereign OS          System kernel, governance, trust graph, asset valuation
├── forge.html        ← Forge Platform        Social feed, AI Studio, marketplace, app builder
├── square.html       ← Forge Square          Public square and direct messaging community hub
├── studio.html       ← Forge Studio          Creative workspace — build, publish, and monetize apps
├── mail.html         ← Sovereign Mail        Encrypted layered mail — inbox, feed, frozen archive
├── messenger.html    ← Messenger             Real-time P2P encrypted chat
├── attack.html       ← Attack Command        Security and adversarial audit platform
├── search.html       ← Sovereign Search      Network-wide distributed search index
├── portal.html       ← Sovereign Portal      Onboarding gateway and personal profile space
├── relay.html        ← Sovereign Relay       Optional WebSocket relay server with live admin UI
├── bridge.html       ← Protocol Bridge       Nostr, Matrix, RSS feeds, and WebFinger/ActivityPub
├── transport.js      ← Transport Layer       WebRTC + blockchain RPC abstraction, drop-in module
└── genesis_sw.js     ← Service Worker        Offline caching and local-first asset serving
```

Everything starts at `index.html`. All other apps link back to it and share the same identity layer.

---

## The Apps

### ⬡ Genesis Node — `index.html`

The root of the system. Handles:

- **Identity** — Ed25519 keypair generation, encrypted storage, DID management
- **Network map** — Live animated canvas showing all apps and their relationships in the mesh
- **Peer connect** — WebRTC handshake (offer/answer), relay discovery, QR code connect
- **Messages** — P2P encrypted messaging with all connected peers
- **Search** — Cross-network search across messages, peers, and apps
- **Apps launcher** — Entry point to the full application suite

### ⬡ Sovereign OS — `os.html`

The system kernel and control plane. Includes:

- **Birth Certificate** — On-chain identity anchoring and sovereign record
- **Stack** — Full layer view of your running system components
- **Event Runtime** — Real-time event log and system signal monitor
- **Trust Graph** — Visualize and manage your web of trusted peers
- **Identity Vault** — Full key management, export, and verification tools
- **Governance** — Proposal, vote, and ratification flows for DAO-style decisions
- **Asset Valuation** — Token and asset tracking layer

### ⬡ Forge — `forge.html`

The decentralized social and creative platform. Sections:

- **Square** — Community feed, posts, reactions, and discovery
- **AI Studio** — Local and remote AI model integration (Ollama / compatible APIs)
- **Marketplace** — Peer-to-peer exchange for apps, assets, and services
- **App Builder** — In-browser application construction tools
- **Docs** — Integrated documentation and knowledge base
- **Credits** — Reputation and contribution tracking

### ⬡ Forge Square — `square.html`

A focused community hub. Provides:

- Public square feed with post, reply, and reaction
- Direct Messages with any connected peer
- Channels for topic-focused group conversations
- File sharing and contacts

### ⬡ Forge Studio — `studio.html`

Creative workspace for building and shipping sovereign apps:

- **Studio** — Main creative canvas and editor
- **My Apps** — Manage all apps you've built or installed
- **Publish** — Deploy apps to the peer network
- **Monetize** — Attach payment flows, subscriptions, or credits to your work

### ⬡ Sovereign Mail — `mail.html`

A layered encrypted message system:

- **Inbox** — Received messages across all connected peers
- **Feed** — Subscribed network updates and announcements
- **Frozen Archive** — Cryptographically sealed, tamper-evident message archive
- **Drafts / Sent** — Full message lifecycle management

### ⬡ Messenger — `messenger.html`

Minimal, fast, real-time P2P encrypted chat. One screen, one purpose. Messages are signed and delivered over WebRTC DataChannels with BroadcastChannel fallback for same-device tabs.

### ⬡ Attack Command — `attack.html`

Adversarial security and audit platform:

- **Overview** — System threat surface and audit dashboard
- **Solidity Analyzer** — Static analysis for smart contracts
- **RRTK** — Rapid Response Toolkit for live simulation and incident response
- **Modules** — Pluggable security analysis extensions
- **Fuzzer** — Input fuzzing for contracts and protocol endpoints
- **Invariant Checker** — Formal property verification
- **Benchmark** — Performance and gas profiling
- **Log** — Full audit trail and event record

### ⬡ Sovereign Search — `search.html`

Distributed search across your entire sovereign network — messages, peers, apps, and content. All scoped and assembled locally. No query leaves your device.

### ⬡ Sovereign Portal — `portal.html`

First-run onboarding flow walking through name selection, keypair generation, and DID confirmation. After setup, becomes your personal profile hub — identity management, network status, and peer directory.

### ⬡ Sovereign Relay — `relay.html`

An optional WebSocket relay with a live admin interface. Used for peer discovery across networks where direct WebRTC negotiation isn't possible. The relay brokers the handshake and then exits the path — it does not read, store, or log message content. Self-host anywhere that supports WebSockets.

### ⬡ Protocol Bridge — `bridge.html`

Gateway to the broader open protocol ecosystem:

- **Nostr** — Subscribe to relays, publish notes, read feeds, send encrypted DMs (NIP-04)
- **Matrix** — Join rooms and send messages against any Matrix homeserver
- **RSS / Atom** — Subscribe to any feed, with optional CORS proxy support
- **WebFinger / ActivityPub** — Resolve any Fediverse handle to its full identity record

The Bridge derives a Nostr (secp256k1) keypair deterministically from your Sovereign Ed25519 identity, maintaining cryptographic continuity across protocols.

### ⬡ Transport Layer — `transport.js`

A drop-in module for any Sovereign HTML file. Include it with a script tag and it self-initializes on DOMContentLoaded, wiring up WebRTC mesh transport and blockchain RPC simultaneously.

---

## Core Technology

### Identity

Each user generates an **Ed25519 keypair** using the Web Crypto API — entirely in-browser. The private key is encrypted with **AES-256-GCM** and stored in **IndexedDB**. It never leaves your device.

Your public identity is a **DID** (`did:sovereign:<pubkey-hex>`) derived deterministically from your public key. Share it like a username. Anyone can verify your signatures against it without trusting any third party.

### Peer Connections

Three transport layers, used in priority order:

| Layer | Scope | Notes |
|---|---|---|
| BroadcastChannel | Same device, multiple tabs | Instant, zero configuration |
| WebRTC DataChannel | Cross-device, direct | DTLS encrypted, NAT-traversing |
| WebSocket Relay | Cross-network, assisted | Relay introduces peers, then exits |

WebRTC handshake packets can be exchanged by any means — copy/paste, email, QR code — with no dependency on a central server. Once connected, the relay is no longer in the path.

### Entropy

Key generation is seeded from `crypto.getRandomValues()` combined with high-resolution `performance.now()` timing samples collected at boot. Additional mouse-movement entropy can be added via the Identity panel's entropy zone, but is not required — the auto-seed produces sufficient randomness for production-grade keys.

### Storage

All persistent data lives in **IndexedDB**:

| Store | Contents |
|---|---|
| `identity` | Username, public key, DID, creation timestamp |
| `keyvault` | Encrypted private key material |
| `peers` | Known peer records — DID, name, last seen |
| `messages` | Message history per peer DID |
| `settings` | Relay URL, preferences, configuration |

Nothing is sent to any external service unless you initiate a peer connection or relay link.

---

## Connecting Peers

**Same device, multiple tabs** — works automatically via BroadcastChannel. No configuration.

**Different devices, same network** — use the WebRTC handshake and exchange the packet over any channel.

**Different devices, different networks:**
1. Both peers enter the same relay URL in Connect → Relay
2. The relay brokers the WebRTC negotiation
3. Once connected, all traffic is direct — relay is out of the path

**Manual handshake (no relay, fully offline):**
1. Genesis Node → Connect → Generate Offer → copy packet or show QR
2. Send to peer by any means (text, email, airdrop, hand)
3. Peer pastes into Step 2 → Process Packet → copies back the Answer
4. Paste the Answer → connection opens

---

## Security Model

- Private keys are generated locally and **never transmitted**
- Keys at rest are encrypted with AES-256-GCM using a locally-generated wrapping key
- WebRTC DataChannels carry built-in **DTLS encryption** — the relay sees only handshake metadata, never content
- There is no central server that can be seized, subpoenaed, or breached
- There is no account database to leak

**Key responsibility:** Your identity lives in IndexedDB. Clearing browser site data deletes your keys permanently. Use **Identity → Backup** before clearing browser data or switching devices.

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

**Required browser APIs:** Web Crypto API · IndexedDB · WebRTC · BroadcastChannel  
**Optional:** BarcodeDetector (for QR scanning — Chrome/Chromium only)

---

## Running Offline

`genesis_sw.js` registers a service worker that caches all assets on first load. After that, the full system runs without a network connection. Peer connections still require the network, but all UI, identity management, and local data work fully offline.

The service worker requires HTTP (not `file://`). A simple local server works:

```bash
npx serve .
# or
python3 -m http.server 8080
```

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

Contact **iconoclastdao@gmail.com** for commercial licensing inquiries.

---

*"The tools of sovereignty should be sovereign themselves."*

---

## Self-Hosting Guide

Sovereign is designed to run as static files — no application server, no database, no runtime dependencies. Hosting it means putting the files somewhere a browser can reach them over HTTP/HTTPS and optionally running the relay as a persistent WebSocket service.

### Option 1 — Local Machine (Simplest)

The fastest way to run the full stack locally. Pick any static file server:

```bash
# Node (one-liner, no config)
npx serve .

# Python (built-in, no install)
python3 -m http.server 8080

# PHP (built-in)
php -S localhost:8080

# Caddy (zero-config HTTPS on localhost)
caddy file-server --browse
```

Then open `http://localhost:8080/index.html` in your browser. The service worker will register and cache all assets on first load, enabling full offline use after that.

> **Note:** The service worker will not register over a bare `file://` URL. You must use HTTP, even locally.

---

### Option 2 — Static File Host (GitHub Pages, Netlify, Cloudflare Pages)

Because Sovereign is pure static HTML, any static host works with zero configuration. There is no build step.

**GitHub Pages**

1. Push your Sovereign folder to a GitHub repository
2. Go to Settings → Pages → Source → select your branch and root folder
3. Your node is live at `https://yourusername.github.io/your-repo/`

**Netlify**

1. Drag and drop the folder into [netlify.com/drop](https://netlify.com/drop)
2. Or connect your GitHub repo and set publish directory to `/`
3. No build command needed — leave it blank

**Cloudflare Pages**

1. Connect your repo in the Cloudflare dashboard
2. Set build command: *(leave empty)*
3. Set output directory: `/`
4. Deploy

All three give you HTTPS automatically. The service worker will register and all features work.

---

### Option 3 — VPS / Dedicated Server

For a permanent, accessible node — useful if you want a relay that is always reachable or want to share your Sovereign instance with others.

**Nginx**

Create `/etc/nginx/sites-available/sovereign`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    root /var/www/sovereign;
    index index.html;

    # Required for service worker scope
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Required headers for SharedArrayBuffer (if used) and service worker
    add_header Cross-Origin-Opener-Policy same-origin;
    add_header Cross-Origin-Embedder-Policy require-corp;

    # Cache static assets, never cache HTML
    location ~* \.(js|css|png|ico|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    location ~* \.html$ {
        add_header Cache-Control "no-cache";
    }
}
```

Enable and reload:

```bash
ln -s /etc/nginx/sites-available/sovereign /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

Add HTTPS with Certbot:

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d your-domain.com
```

**Caddy** (HTTPS automatic, config minimal)

Create a `Caddyfile` in your Sovereign directory:

```
your-domain.com {
    root * /var/www/sovereign
    file_server
    header Cross-Origin-Opener-Policy same-origin
    header Cross-Origin-Embedder-Policy require-corp
}
```

Run:

```bash
caddy run
```

Caddy handles HTTPS certificate issuance and renewal automatically.

---

### Option 4 — Self-Hosting the Relay (`relay.html`)

The relay is the only component that needs a persistent network presence. It is a WebSocket server that brokers WebRTC handshakes — once two peers connect, the relay is no longer in the communication path.

The relay UI (`relay.html`) is a browser-based admin interface, not the relay server itself. To self-host a relay, you need a WebSocket server running on a machine with a public IP.

**Minimal Node.js relay server**

Create `relay-server.js`:

```javascript
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8765;
const wss  = new WebSocketServer({ port: PORT });
const peers = new Map(); // did → socket

wss.on('connection', (ws) => {
  let myDid = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // Register identity
    if (msg.type === 'HELLO' && msg.did) {
      myDid = msg.did;
      peers.set(myDid, ws);
      ws.send(JSON.stringify({ type: 'HELLO_ACK', peers: [...peers.keys()] }));
      broadcast({ type: 'PEER_ONLINE', did: myDid }, myDid);
      return;
    }

    // Route to target peer
    if (msg.to && peers.has(msg.to)) {
      peers.get(msg.to).send(JSON.stringify({ ...msg, from: myDid }));
    }
  });

  ws.on('close', () => {
    if (myDid) {
      peers.delete(myDid);
      broadcast({ type: 'PEER_OFFLINE', did: myDid }, myDid);
    }
  });

  function broadcast(msg, exceptDid) {
    const payload = JSON.stringify(msg);
    for (const [did, sock] of peers) {
      if (did !== exceptDid && sock.readyState === 1) sock.send(payload);
    }
  }
});

console.log(`Sovereign relay listening on ws://0.0.0.0:${PORT}`);
```

Run it:

```bash
npm install ws
node relay-server.js
```

**Keep it running with PM2:**

```bash
npm install -g pm2
pm2 start relay-server.js --name sovereign-relay
pm2 save
pm2 startup
```

**Expose it over WSS (required for HTTPS-served nodes)**

If your Sovereign files are served over HTTPS, the relay must use `wss://` — browsers block mixed content. Proxy the relay through Nginx:

```nginx
# Add inside your server block:
location /relay {
    proxy_pass http://localhost:8765;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
```

Your relay URL becomes: `wss://your-domain.com/relay`

Enter this in Genesis Node → **Connect → Relay** on both devices.

---

### Option 5 — LAN / Intranet Node

For use within a local network (home lab, organization, air-gapped environment):

1. Run any static file server on one machine:
   ```bash
   npx serve --listen 0.0.0.0 --port 8080 .
   ```
2. Other devices on the network open `http://192.168.x.x:8080/index.html`
3. For the relay, run `relay-server.js` on the same or a dedicated machine and point all nodes at `ws://192.168.x.x:8765`

Within a LAN, WebRTC connections often succeed without STUN servers because peers are on the same subnet. The relay is still useful for initial discovery.

---

### STUN / TURN Configuration

WebRTC uses STUN to discover public IP addresses for NAT traversal. Sovereign ships with Google's and Cloudflare's free STUN servers:

```
stun:stun.l.google.com:19302
stun:stun1.l.google.com:19302
stun:stun2.l.google.com:19302
stun:stun.cloudflare.com:3478
```

These work for most home and office networks. If peers are behind symmetric NAT (common in some corporate networks), STUN alone will not be enough — you will need a TURN server, which relays media traffic.

**Self-hosting a TURN server with coturn:**

```bash
apt install coturn

# /etc/turnserver.conf
listening-port=3478
tls-listening-port=5349
realm=your-domain.com
user=sovereign:your-secret-password
lt-cred-mech
fingerprint
no-multicast-peers
```

Then add your TURN server to the `ICE_SERVERS` constant in `index.html`:

```javascript
const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  {
    urls: 'turn:your-domain.com:3478',
    username: 'sovereign',
    credential: 'your-secret-password'
  }
];
```

---

### Content Security Policy

The HTML files ship with a strict CSP:

```
default-src 'none';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
connect-src 'self' http://localhost:11434 ws: wss: https:;
img-src 'self' data: blob:;
worker-src blob:;
```

`http://localhost:11434` is the Ollama local AI endpoint. If you are not using Ollama, you can remove it. All WebSocket and HTTPS connections are permitted under `ws: wss: https:` — tighten this to specific domains in a production deployment if you want a narrower surface:

```
connect-src 'self' wss://your-relay.com https://your-relay.com;
```

---

### Connecting the Relay Admin UI

Once your relay server is running, open `relay.html` in a browser and enter your relay's WebSocket URL. The admin UI shows:

- Connected peers and their DIDs
- Message routing activity
- Live connection graph
- Uptime and throughput stats

The relay server itself does not depend on `relay.html` being open — the Node.js process runs independently. The HTML file is purely an observation and management interface.

---

### Hosting Checklist

| Task | Required | Notes |
|---|---|---|
| Serve files over HTTP or HTTPS | ✅ | `file://` breaks service worker |
| HTTPS for public nodes | Recommended | Required for `wss://` relay, geolocation, camera (QR scan) |
| Relay server running | Optional | Needed for cross-network peer discovery |
| Relay behind WSS proxy | If HTTPS | Mixed content blocks `ws://` from HTTPS pages |
| TURN server | Optional | Only needed for symmetric NAT environments |
| PM2 or systemd for relay | Recommended | Keeps relay alive after reboot |
