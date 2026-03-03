# SOVEREIGN — Genesis Node

**A self-sovereign, peer-to-peer operating environment built entirely in the browser.**
No servers. No accounts. No surveillance. You own everything.

---

## What Is Sovereign?

Sovereign is a decentralized, cryptographic identity and communication stack that runs entirely as local HTML files. There is no backend. There is no cloud. Your identity, your keys, your messages, and your data live only on your device — encrypted, signed, and yours.

It is designed for people who refuse to rent their digital life from corporations and governments. Every node is equal. Every connection is direct. Every message is signed with keys that only you control.

---

## System Architecture

The stack is flat, simple, and readable. Open any file in a browser and it runs.

```
sovereign/
├── index.html       ← Genesis Node — boots the system, network map, identity hub
├── os.html          ← Sovereign OS — kernel services, control plane, AI layer
├── forge.html       ← Forge — decentralized social and creative platform
├── square.html      ← Forge Square — the public square, community feed
├── studio.html      ← Forge Studio — creative workspace and full toolchain
├── mail.html        ← Sovereign Mail — encrypted, serverless communication
├── messenger.html   ← Sovereign Messenger — real-time P2P encrypted chat
├── attack.html      ← Attack Command — adversarial security and audit platform
├── search.html      ← Sovereign Search — network-wide distributed search
├── portal.html      ← Sovereign Portal — gateway and routing layer
├── relay.html       ← Sovereign Relay — optional WebSocket relay server bridge
├── transport.js     ← Transport layer — WebRTC and relay abstraction
└── genesis_sw.js    ← Service Worker — offline support and local caching
```

Start at `index.html`. Everything else launches from there.

---

## How To Run

**No install. No build. No server.**

1. Download and unzip the package
2. Open `index.html` in any modern browser (Chrome, Firefox, Brave, Edge)
3. Go to the **Identity** tab and generate your sovereign keypair
4. That's it — you're on the network

For cross-device connections, point both nodes at the same WebSocket relay URL in the **Connect** tab. You can self-host `relay.html` or use any compatible relay.

---

## Core Technology

**Identity**
Each user generates an Ed25519 keypair entirely in-browser using the Web Crypto API. Your private key is encrypted with AES-256-GCM and stored in IndexedDB. It never leaves your device. Your identity is a DID (`did:sovereign:...`) derived from your public key — share it like a username.

**Messaging**
Messages are transmitted over three layers in priority order:
- **BroadcastChannel** — instant delivery between tabs on the same device
- **WebRTC DataChannel** — direct peer-to-peer, end-to-end encrypted
- **WebSocket Relay** — optional bridge for cross-network discovery

**Entropy**
Key generation is seeded from `crypto.getRandomValues()` combined with high-resolution performance timing. Mouse movement over the entropy zone enriches the pool further but is not required — the system is ready to generate immediately on load.

**Storage**
All data lives in **IndexedDB** — identity records, keyvault, contacts, messages, and settings. Nothing is sent anywhere unless you initiate a connection.

---

## The Philosophy

Sovereign is built on a simple premise: your digital identity should belong to you the way your thoughts do. Not to a platform. Not to a service agreement. Not to a jurisdiction.

This system does not track you. It does not phone home. It does not have a business model that requires your attention or your data. It is a tool, not a product.

The name is not branding. It is a statement of intent.

---

## Connecting Peers

**Same device, multiple tabs:** works automatically via BroadcastChannel — no configuration needed.

**Different devices, same network:** use WebRTC after a manual handshake exchange.

**Different devices, different networks:**
1. Both peers connect to a shared relay URL in the **Connect** tab
2. The relay introduces you — after that, connection is direct
3. You can self-host a relay using `relay.html` or any WebSocket server

**Manual (offline) handshake:**
1. Go to **Connect** → copy your handshake packet
2. Send it to your peer via any channel (text, email, etc.)
3. They paste it in **Receive Handshake** and click Connect
4. You're now linked — no server ever touched the exchange

---

## Browser Compatibility

| Browser | Status |
|---------|--------|
| Chrome / Chromium | ✅ Full support |
| Brave | ✅ Full support |
| Firefox | ✅ Full support |
| Edge | ✅ Full support |
| Safari | ⚠️ Partial (WebRTC may require flag) |
| Mobile (Chrome/Firefox) | ✅ Supported |

Requires a browser with: Web Crypto API, IndexedDB, WebRTC, BroadcastChannel.

---

## Security Model

- Private keys are generated locally and **never transmitted**
- Keys at rest are encrypted with AES-256-GCM using a locally generated AES key
- Messages over WebRTC use the built-in DTLS encryption of the DataChannel
- There is no central server that can be seized, subpoenaed, or breached
- There is no account database to leak

**Important:** Your identity is stored in your browser's IndexedDB. Clearing site data will delete your keys. Export or back up your DID and key vault before clearing browser data.

---

## Author & Ownership

**James Chapman**
Handle: XheCarpenXer
Contact: iconoclastdao@gmail.com

Sovereign is an Iconoclast DAO project. Built by hand. Owned by no one except its creator and the people who use it.

---

## License

Sovereign is dual-licensed. See `LICENSE.md` for full terms.

**Personal and open-source use:** Free. Use it, fork it, build on it, share it.

**Commercial and government use:** Requires a paid license OR complete open-sourcing of all code built on or integrated with Sovereign under the same terms.

Contact **iconoclastdao@gmail.com** to discuss commercial licensing.

---

*"The tools of sovereignty should be sovereign themselves."*
