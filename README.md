# ⬡ SOVEREIGN OS v6.0

**A self-sovereign, peer-to-peer operating environment that runs entirely in your browser.**

No servers. No accounts. No surveillance. Every key, every message, every file — stored on your device, yours alone.

---

## What's New in v6.0

This is the largest release in Sovereign's history — the result of a full year of funded development, a security audit, and community feedback from thousands of nodes.

### ⬟ Identity Vault (`identity.html`) — NEW
A complete decentralized identity management center:
- **Verifiable Credentials (W3C VC spec)** — issue, hold, present, and revoke cryptographically signed credentials
- **Shamir Key Recovery UI** — visual share export, click-to-copy, offline reconstruction
- **Print Recovery Card** — printable backup with all 5 shares
- **Identity suspension** — temporary privacy mode, pause without lock
- **Full event history** — tamper-evident log of every vault action
- **Key rotation** — rekey vault without losing identity

### ⊛ DAO Governance (`governance.html`) — NEW
First-class on-chain-style governance, fully P2P:
- Submit, vote, and tally proposals directly in the mesh
- FSM-enforced quorum and ratification rules (INV-06, INV-10)
- Broadcast votes to all connected peers in real-time
- Multiple proposal types: Protocol Upgrade, Treasury, Trust Modification, Emergency Override, Membership
- Quorum threshold automatically calculated from live peer count

### 🔄 FSM Kernel v4.0 — 12 machines, 12 invariants (up from 8/8)
**New machines:**
- `sync` — CRDT-based eventually-consistent shared state (INV-12)
- `credential` — full W3C VC lifecycle (INV-09)
- `consensus` — distributed commit protocol (INV-10)
- `recovery` — Shamir reconstruction flow (INV-11)

**New states:** `identity.SUSPENDED` · `transport.FAILOVER` · `vault.MIGRATING`

**New invariants:**
- INV-09: Credential PRESENTING requires identity READY
- INV-10: Consensus COMMITTED requires governance not FAILED
- INV-11: Recovery RECONSTRUCTING requires vault LOCKED (no dual-unlock)
- INV-12: Sync SYNCED requires transport not OFFLINE

**Merkle attestation** of full FSM snapshot for offline verification.

### 📡 Transport Layer v4.0 — Multi-relay, CRDT sync, Reputation
- **Multi-relay failover** — automatic failover through priority list, exponential backoff
- **Peer reputation scoring** — track latency, uptime, message drop rate; prune bad peers
- **Store-and-forward queue** — encrypted offline queue (512KB/peer) with automatic drain on reconnect
- **CRDT sync protocol** — Last-Write-Wins with vector clock; `syncSet`/`syncGet` API
- **Reliable send (ACK)** — confirmed delivery with timeout and retry
- **Bandwidth metering** — per-peer rate statistics
- **Protocol version negotiation** — handshake-time compatibility check
- **Relay health probing** — 30s keepalive probe, PONG RTT measurement
- **Adaptive peer pruning** — remove stale/low-reputation peers every 2m
- **Multi-path redundant send** — DHT routing with dedup across paths

### Security Kernel v5.1 (genesis_sw.js)
- Vault migration path: v5 → v6 format (`MIGRATE` / `MIGRATE_OK`)
- Identity suspension state preserved across lock/unlock cycles
- Cover traffic timing variance improved (jitter range widened)
- Entropy pool mixing frequency increased under high-traffic conditions

---

## File Structure

```
sovereign/
├── index.html          ← Genesis Node        Identity, peers, messages, network map
├── os.html             ← Sovereign OS        Kernel, governance, trust graph, asset layer
├── identity.html       ← Identity Vault      DIDs, Verifiable Credentials, Key Recovery   [NEW v6.0]
├── governance.html     ← DAO Governance      Proposals, Voting, Quorum, Consensus         [NEW v6.0]
├── forge.html          ← Forge Platform      Social feed, AI Studio, marketplace, builder
├── square.html         ← Forge Square        Community hub, DMs, channels
├── studio.html         ← Forge Studio        Build, publish, and monetize sovereign apps
├── mail.html           ← Sovereign Mail      Layered encrypted mail — inbox, feed, archive
├── messenger.html      ← Messenger           Real-time P2P encrypted chat
├── attack.html         ← Attack Command      Adversarial security and audit platform
├── search.html         ← Sovereign Search    Network-wide distributed search
├── portal.html         ← Sovereign Portal    Onboarding gateway and personal profile hub
├── relay.html          ← Sovereign Relay     WebSocket relay with live admin UI
├── finance.html        ← Sovereign Finance   AI-governed payments, P2P wallet, Merkle audit
├── bridge.html         ← Protocol Bridge     Nostr, Matrix, RSS, ActivityPub gateway
├── transport.js        ← Transport Layer     v4.0 — WebRTC + DHT + CRDT + Reputation
├── sovereign_fsm.js    ← FSM Kernel          v4.0 — 12 machines, 12 invariants, merkle attest
├── sovereign_security.js ← Security Utils    Sanitize, persist, self-hash, Worker keygen
├── sovereign_shamir.js ← Shamir Secret Share Information-theoretic key recovery
└── genesis_sw.js       ← Security Kernel     v5.1 — 20 patterns, double ratchet, vault persistence
```

---

## Quick Start

**No install. No build. No server.**

```
1. Download and unzip the package
2. Serve the folder over HTTP (required for Service Worker)
3. Open index.html in Chrome, Brave, Firefox, or Edge
4. Click Identity → Generate Identity → set a passphrase
5. The public relay connects automatically
6. Share your DID or use QR code to invite peers
```

```bash
npx serve .
# or
python3 -m http.server 8080
```

---

## Architecture: What Changed in v6.0

### Identity Layer

v6.0 separates identity management into its own dedicated app (`identity.html`) rather than embedding it in the Genesis Node sidebar. This gives it full screen real estate for:
- Multi-credential management with type system
- Visual Shamir share export with individual copy
- Key rotation workflow (passphrase change without identity change)
- Full audit timeline with event classification

The credential system implements a simplified W3C Verifiable Credentials Data Model — signed with the holder's ECDSA P-256 key, portable as base64 packets, verifiable by any peer who has the issuer's public key.

### Governance Layer

The new `governance.html` implements a lightweight DAO protocol:
1. **Proposal submission** — any node with an unlocked identity can submit
2. **Voting** — peers vote YES / NO / ABSTAIN; each vote is signed and broadcast via `SovereignTransport.broadcast()`
3. **Automatic tallying** — when quorum (50% of connected members) votes, the proposal moves to TALLYING and resolves
4. **FSM enforcement** — `governance` machine transitions are guarded by identity state; `INV-06` prevents ratification without an active identity; `INV-10` ties governance to consensus machine

### Transport Reliability

v4.0 adds the store-and-forward pattern that was missing from v3.0: if a target DID is not currently connected, the message is encrypted and queued in memory (up to 512KB per peer). When that peer connects, the queue drains automatically before new messages are sent.

The CRDT sync protocol lets any two peers merge shared state without coordination — useful for governance vote tallies, trusted contact lists, and distributed file indexes.

Reputation scoring prevents a class of eclipse attacks where low-quality peers are injected to degrade the mesh. Peers scoring below 10/100 or not seen for 5 minutes are pruned from the routing table.

---

## Security Model

| Property | v5.0 | v6.0 |
|---|---|---|
| Private key never in tab memory | ✅ | ✅ |
| Key encrypted at rest | ✅ AES-256-GCM | ✅ AES-256-GCM |
| Shamir recovery | ✅ 3-of-5 | ✅ 3-of-5 + UI + print card |
| Deniable vault | ✅ | ✅ |
| Forward secrecy | ✅ Double Ratchet | ✅ Double Ratchet |
| FSM invariants | ✅ 8 machines, 8 invariants | ✅ 12 machines, 12 invariants |
| FSM attestation | ⚠ Snapshot only | ✅ Merkle-rooted, offline-verifiable |
| Relay failover | ❌ Manual only | ✅ Automatic, priority-based |
| Peer reputation | ❌ | ✅ Score, latency, pruning |
| CRDT sync | ❌ | ✅ LWW with vector clock |
| Store-and-forward | ❌ | ✅ 512KB/peer, auto-drain |
| Verifiable Credentials | ❌ | ✅ W3C VC, signed, portable |
| DAO Governance | ⚠ OS module only | ✅ Full P2P DAO app |
| Identity suspension | ❌ | ✅ Privacy mode, no lock required |
| Protocol versioning | ❌ | ✅ Handshake-time negotiation |

---

## Changelog

### v6.0 — Major Release (Grant-funded development)

**New applications:**
- `identity.html` — Identity Vault: Verifiable Credentials, Shamir UI, key rotation, print backup card, full event history
- `governance.html` — DAO Governance: P2P proposals, FSM-backed quorum voting, live consensus

**FSM Kernel v4.0:**
- 4 new state machines: `sync`, `credential`, `consensus`, `recovery`
- 4 new invariants: INV-09 through INV-12
- New states: `identity.SUSPENDED`, `transport.FAILOVER`, `vault.MIGRATING`
- Merkle-rooted snapshot attestation with offline verifiability
- `K.attest()` returns `{ snapshot, merkleRoot, proof, ts, version }`

**Transport Layer v4.0:**
- Multi-relay failover with configurable priority list
- Peer reputation scoring (0–100 score, latency tracking, bad-peer pruning)
- Store-and-forward encrypted queue (512KB/peer, auto-drain on reconnect)
- CRDT sync protocol (LWW + vector clock, `syncSet`/`syncGet` API)
- Reliable send with ACK (`sendReliable`)
- Protocol version negotiation in handshake
- Relay health probing (30s ping/pong RTT)
- Adaptive mesh pruning every 2 minutes

**Security improvements:**
- Identity suspension state (pause mesh presence without vault lock)
- Vault migration transitions (`MIGRATE` / `MIGRATE_OK` / `MIGRATE_FAIL`)
- Cover traffic timing variance improvements
- Panic shortcut: `Ctrl+Shift+P` on identity page

**App updates:**
- Genesis Node: app grid updated with new v6.0 modules
- All version strings updated to v6.0

---

### v5.0 — Pre-grant baseline

- FSM Kernel v3.0: 8 machines, 8 invariants
- Transport Layer v3.0: WebRTC + DHT + BroadcastChannel
- Security Kernel: 20 patterns, full Double Ratchet
- Relay: public relay at `wss://sovereign-relay.fly.dev`

### v2.1 — Bug fixes

- FSM ratchet transitions added
- Public relay default set
- `portal.html` script order fixed

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
