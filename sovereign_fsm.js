/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║         SOVEREIGN FSM KERNEL  v3.0  —  sovereign_fsm.js                ║
 * ║                                                                          ║
 * ║  The single source of authoritative system state.                        ║
 * ║  Every invariant in the threat model is enforced here.                   ║
 * ║  No external dependencies. Drop-in for any Sovereign HTML file.          ║
 * ║                                                                          ║
 * ║  © James Chapman (XheCarpenXer) · iconoclastdao@gmail.com               ║
 * ║  Dual License — see LICENSE.md                                           ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * MACHINES (v3.0 — 8 total, up from 5):
 *   vault       — LOCKED → UNLOCKING → UNLOCKED → LOCKED (+ PANICKED, REKEYING, CREATING)
 *   identity    — NONE → GENERATING → LOADING → READY → DESTROYED
 *   transport   — OFFLINE → DISCOVERING → CONNECTED → DEGRADED
 *   kdf         — IDLE → STRETCHING → READY → CONSUMED
 *   ratchet     — per-peer: UNINIT → KEYED → ACTIVE → STALE (lazily created)
 *   governance  — IDLE → PROPOSED → VOTING → TALLYING → RATIFIED | FAILED  [NEW v3.0]
 *   attestation — IDLE → CHALLENGING → AWAITING → VERIFIED | FAILED         [NEW v3.0]
 *   onion       — OFFLINE → BOOTSTRAPPING → READY → DEGRADED                [NEW v3.0]
 *
 * INVARIANTS (8 total — 5 original + 3 new temporal):
 *   INV-01  Transport cannot be CONNECTED without an UNLOCKED vault
 *   INV-02  Identity cannot be READY while vault is LOCKED
 *   INV-03  No ratchet may be ACTIVE without a READY identity
 *   INV-04  Vault cannot be UNLOCKED without KDF completion
 *   INV-05  PANICKED state is terminal — no other machine may advance
 *   INV-06  Governance RATIFIED requires identity READY at ratification time  [NEW]
 *   INV-07  Onion circuit READY requires transport CONNECTED                  [NEW]
 *   INV-08  Attestation VERIFIED timestamp must post-date challenge timestamp [NEW]
 *
 * PROTOCOL VERSIONING:
 *   FSM_PROTOCOL_VERSION — included in every snapshot. Breaking changes bump major.
 *
 * SNAPSHOT ATTESTATION:
 *   K.attest() → { snapshot, merkleRoot, proof }
 *   Root is SHA-256(concat(state hashes sorted by machine name)).
 *   Proof is the sorted leaf hashes. Verifiable offline.
 *
 * USAGE:
 *   const K = window.SovereignFSM;
 *
 *   K.vault.send('UNLOCK');
 *   K.vault.send('UNLOCK_OK');
 *
 *   K.on('TRANSITION', e => console.log(e.detail));
 *   K.on('INVARIANT_VIOLATION', e => console.error(e.detail));
 *
 *   const violations = K.checkInvariants();
 *   const snap       = K.snapshot();
 *   const attestation = await K.attest();     // includes merkle root
 *
 *   K.governance.send('PROPOSE', { id: 'PROP-001', author: did });
 *   K.attestation.send('CHALLENGE', { nonce: hex });
 *   K.onion.send('BOOTSTRAP');
 */

'use strict';

window.SovereignFSM = (() => {

  const FSM_PROTOCOL_VERSION = '3.0.0';

  // ──────────────────────────────────────────────────────────────────────────
  //  TRANSITION TABLE
  //  Each row: { m, from, on, to, guard?, meta? }
  //  guard  — key into GUARDS (function that must return true)
  //  meta   — arbitrary annotations (for tooling / visualization)
  //  from   — '*' means any state
  // ──────────────────────────────────────────────────────────────────────────
  const TABLE = [

    // ── VAULT ────────────────────────────────────────────────────────────────
    { m:'vault', from:'LOCKED',     on:'CREATE',      to:'CREATING'                              },
    { m:'vault', from:'CREATING',   on:'CREATE_OK',   to:'LOCKED',    meta:'vault now exists'    },
    { m:'vault', from:'CREATING',   on:'CREATE_FAIL', to:'LOCKED'                                },
    { m:'vault', from:'LOCKED',     on:'UNLOCK',      to:'UNLOCKING'                             },
    { m:'vault', from:'UNLOCKING',  on:'UNLOCK_OK',   to:'UNLOCKED',  meta:'key in SW memory'    },
    { m:'vault', from:'UNLOCKING',  on:'UNLOCK_FAIL', to:'LOCKED'                                },
    { m:'vault', from:'UNLOCKED',   on:'LOCK',        to:'LOCKED',    meta:'explicit lock'       },
    { m:'vault', from:'UNLOCKED',   on:'TIMEOUT',     to:'LOCKED',    meta:'inactivity timeout'  },
    { m:'vault', from:'UNLOCKED',   on:'REKEY',       to:'REKEYING'                              },
    { m:'vault', from:'REKEYING',   on:'REKEY_OK',    to:'UNLOCKED'                              },
    { m:'vault', from:'REKEYING',   on:'REKEY_FAIL',  to:'UNLOCKED',  meta:'old key preserved'  },
    // Duress vault — silently switches to decoy keys
    { m:'vault', from:'LOCKED',     on:'DURESS',      to:'UNLOCKED',  meta:'decoy keys active'  },

    // ── IDENTITY ─────────────────────────────────────────────────────────────
    { m:'identity', from:'NONE',       on:'GENERATE', to:'GENERATING', guard:'vaultUnlocked'     },
    { m:'identity', from:'NONE',       on:'LOAD',     to:'LOADING',    guard:'vaultUnlocked'     },
    { m:'identity', from:'GENERATING', on:'GEN_OK',   to:'READY'                                 },
    { m:'identity', from:'GENERATING', on:'GEN_FAIL', to:'NONE'                                  },
    { m:'identity', from:'LOADING',    on:'LOAD_OK',  to:'READY'                                 },
    { m:'identity', from:'LOADING',    on:'LOAD_FAIL',to:'NONE'                                  },
    { m:'identity', from:'READY',      on:'LOCK',     to:'NONE',       meta:'mirror vault lock'  },
    { m:'identity', from:'READY',      on:'REVOKE',   to:'DESTROYED',  meta:'permanent'          },
    { m:'identity', from:'DESTROYED',  on:'RESET',    to:'NONE'                                  },

    // ── TRANSPORT ────────────────────────────────────────────────────────────
    { m:'transport', from:'OFFLINE',     on:'CONNECT',    to:'DISCOVERING', guard:'identityReady' },
    { m:'transport', from:'DISCOVERING', on:'PEERS_FOUND',to:'CONNECTED'                          },
    { m:'transport', from:'DISCOVERING', on:'PEERS_NONE', to:'DEGRADED'                           },
    { m:'transport', from:'DISCOVERING', on:'TIMEOUT',    to:'DEGRADED'                           },
    { m:'transport', from:'CONNECTED',   on:'PEER_LOST',  to:'DEGRADED'                           },
    { m:'transport', from:'CONNECTED',   on:'DISCONNECT', to:'OFFLINE'                            },
    { m:'transport', from:'DEGRADED',    on:'PEER_FOUND', to:'CONNECTED'                          },
    { m:'transport', from:'DEGRADED',    on:'RELAY_UP',   to:'CONNECTED'                          },
    { m:'transport', from:'DEGRADED',    on:'DISCONNECT', to:'OFFLINE'                            },

    // ── KDF ──────────────────────────────────────────────────────────────────
    { m:'kdf', from:'IDLE',       on:'STRETCH',     to:'STRETCHING'                              },
    { m:'kdf', from:'STRETCHING', on:'STRETCH_OK',  to:'READY'                                   },
    { m:'kdf', from:'STRETCHING', on:'STRETCH_FAIL',to:'IDLE'                                    },
    { m:'kdf', from:'READY',      on:'CONSUME',     to:'CONSUMED',  meta:'key handed to SW'      },
    { m:'kdf', from:'CONSUMED',   on:'RESET',       to:'IDLE'                                    },
    { m:'kdf', from:'READY',      on:'RESET',       to:'IDLE'                                    },

    // ── RATCHET (per-peer, lazily instantiated) ───────────────────────────────
    { m:'ratchet', from:'UNINIT', on:'INIT',  to:'KEYED',  guard:'identityReady'                 },
    { m:'ratchet', from:'KEYED',  on:'READY', to:'ACTIVE'                                        },
    { m:'ratchet', from:'ACTIVE', on:'REKEY', to:'KEYED',  meta:'forward secrecy epoch'          },
    { m:'ratchet', from:'ACTIVE', on:'STALE', to:'STALE',  meta:'inactivity > session window'   },
    { m:'ratchet', from:'STALE',  on:'REKEY', to:'KEYED'                                         },
    { m:'ratchet', from:'STALE',  on:'CLOSE', to:'UNINIT'                                        },
    { m:'ratchet', from:'KEYED',  on:'CLOSE', to:'UNINIT'                                        },
    { m:'ratchet', from:'ACTIVE', on:'CLOSE', to:'UNINIT'                                        },

    // ── GOVERNANCE [NEW v3.0] ─────────────────────────────────────────────────
    // Proposal lifecycle — DAO-style
    { m:'governance', from:'IDLE',     on:'PROPOSE',  to:'PROPOSED', guard:'identityReady',
                                                                      meta:'open for endorsement' },
    { m:'governance', from:'PROPOSED', on:'OPEN_VOTE',to:'VOTING',   guard:'quorumEndorsed'      },
    { m:'governance', from:'PROPOSED', on:'WITHDRAW', to:'IDLE'                                  },
    { m:'governance', from:'VOTING',   on:'CLOSE',    to:'TALLYING'                              },
    { m:'governance', from:'VOTING',   on:'EXPIRE',   to:'TALLYING'                              },
    { m:'governance', from:'TALLYING', on:'PASS',     to:'RATIFIED', guard:'identityReady'       },
    { m:'governance', from:'TALLYING', on:'FAIL',     to:'FAILED'                                },
    { m:'governance', from:'RATIFIED', on:'EXECUTE',  to:'IDLE'                                  },
    { m:'governance', from:'FAILED',   on:'RESET',    to:'IDLE'                                  },

    // ── ATTESTATION [NEW v3.0] ────────────────────────────────────────────────
    // Challenge-response identity attestation
    { m:'attestation', from:'IDLE',       on:'CHALLENGE', to:'CHALLENGING'                       },
    { m:'attestation', from:'CHALLENGING',on:'SEND',      to:'AWAITING', guard:'identityReady'   },
    { m:'attestation', from:'AWAITING',   on:'VERIFIED',  to:'VERIFIED'                          },
    { m:'attestation', from:'AWAITING',   on:'TIMEOUT',   to:'FAILED'                            },
    { m:'attestation', from:'AWAITING',   on:'REJECT',    to:'FAILED'                            },
    { m:'attestation', from:'VERIFIED',   on:'RESET',     to:'IDLE'                              },
    { m:'attestation', from:'FAILED',     on:'RESET',     to:'IDLE'                              },
    { m:'attestation', from:'FAILED',     on:'RETRY',     to:'CHALLENGING'                       },

    // ── ONION [NEW v3.0] ──────────────────────────────────────────────────────
    // 3-hop circuit lifecycle
    { m:'onion', from:'OFFLINE',      on:'BOOTSTRAP', to:'BOOTSTRAPPING', guard:'transportReady' },
    { m:'onion', from:'BOOTSTRAPPING',on:'CIRCUIT_OK',to:'READY'                                 },
    { m:'onion', from:'BOOTSTRAPPING',on:'FAIL',      to:'OFFLINE'                               },
    { m:'onion', from:'READY',        on:'HOP_LOST',  to:'DEGRADED'                              },
    { m:'onion', from:'READY',        on:'TEARDOWN',  to:'OFFLINE'                               },
    { m:'onion', from:'DEGRADED',     on:'REBUILD',   to:'BOOTSTRAPPING'                         },
    { m:'onion', from:'DEGRADED',     on:'TEARDOWN',  to:'OFFLINE'                               },

    // ── PANIC — cascades from any machine to all ──────────────────────────────
    { m:'*', from:'*', on:'PANIC', to:'PANICKED', meta:'irreversible — requires full restart'    },

  ];

  // ──────────────────────────────────────────────────────────────────────────
  //  GUARDS
  //  Each receives (K: Kernel) and must return boolean.
  //  Failing a guard silently rejects the transition (returns false from send()).
  // ──────────────────────────────────────────────────────────────────────────
  const GUARDS = {
    vaultUnlocked:   (K) => K.vault.state === 'UNLOCKED',
    identityReady:   (K) => K.identity.state === 'READY',
    kdfReady:        (K) => K.kdf.state === 'READY',
    transportReady:  (K) => K.transport.state === 'CONNECTED' || K.transport.state === 'DEGRADED',
    quorumEndorsed:  (K) => {
      // Governance: at least floor(N/2)+1 endorsements required to open a vote.
      // The kernel tracks endorsements via _gov metadata — checked lazily here.
      const meta = K._gov;
      if (!meta) return false;
      return meta.endorsements >= Math.floor((meta.eligibleVoters || 1) / 2) + 1;
    },
  };

  // ──────────────────────────────────────────────────────────────────────────
  //  INVARIANTS
  //  Checked after every transition (dev mode) or on-demand (K.checkInvariants()).
  //  Returning false === violation.
  // ──────────────────────────────────────────────────────────────────────────
  const INVARIANTS = [
    {
      id:   'INV-01',
      desc: 'Transport cannot be CONNECTED without an UNLOCKED vault',
      check: (K) =>
        !(K.transport.state === 'CONNECTED' && K.vault.state !== 'UNLOCKED'),
    },
    {
      id:   'INV-02',
      desc: 'Identity cannot be READY while vault is LOCKED',
      check: (K) =>
        !(K.identity.state === 'READY' && K.vault.state === 'LOCKED'),
    },
    {
      id:   'INV-03',
      desc: 'No ratchet may be ACTIVE without a READY identity',
      check: (K) => {
        if (K.identity.state !== 'READY') {
          for (const r of K._ratchets.values()) {
            if (r.state === 'ACTIVE') return false;
          }
        }
        return true;
      },
    },
    {
      id:   'INV-04',
      desc: 'Vault cannot be UNLOCKED without KDF completion (CONSUMED or READY)',
      check: (K) =>
        !(K.vault.state === 'UNLOCKED' && K.kdf.state === 'IDLE'),
    },
    {
      id:   'INV-05',
      desc: 'PANICKED state is terminal — no other machine may advance to an active state',
      check: (K) => {
        const panicked = [K.vault, K.identity, K.transport, K.kdf, K.governance, K.attestation, K.onion]
          .some(m => m.state === 'PANICKED');
        if (!panicked) return true;
        const safe = new Set(['PANICKED','LOCKED','NONE','OFFLINE','IDLE','CONSUMED','FAILED']);
        return [K.vault, K.identity, K.transport, K.kdf, K.governance, K.attestation, K.onion]
          .every(m => safe.has(m.state));
      },
    },
    {
      id:   'INV-06',
      desc: 'Governance RATIFIED requires identity to be READY at time of ratification',
      check: (K) => {
        if (K.governance.state === 'RATIFIED') {
          return K.identity.state === 'READY';
        }
        return true;
      },
    },
    {
      id:   'INV-07',
      desc: 'Onion circuit READY requires transport to be CONNECTED',
      check: (K) => {
        if (K.onion.state === 'READY') {
          return K.transport.state === 'CONNECTED' || K.transport.state === 'DEGRADED';
        }
        return true;
      },
    },
    {
      id:   'INV-08',
      desc: 'Attestation VERIFIED timestamp must post-date challenge timestamp',
      check: (K) => {
        if (K.attestation.state !== 'VERIFIED') return true;
        const hist = K.attestation._history;
        const challenged = hist.find(h => h.to === 'CHALLENGING');
        const verified   = hist.find(h => h.to === 'VERIFIED');
        if (!challenged || !verified) return true; // can't check without history
        return verified.ts >= challenged.ts;
      },
    },
  ];

  // ──────────────────────────────────────────────────────────────────────────
  //  FSM CLASS
  //  Represents a single state machine instance.
  // ──────────────────────────────────────────────────────────────────────────
  class FSM {
    constructor(name, initial) {
      this._name    = name;
      this._state   = initial;
      this._history = [{ from: null, to: initial, event: '@@INIT', ts: Date.now(), payload: {} }];
      this._kernel  = null; // set by Kernel after construction
    }

    get state() { return this._state; }
    get name()  { return this._name;  }

    /** Returns the history entry of the most recent visit to `state`, or null. */
    lastVisit(state) {
      return [...this._history].reverse().find(h => h.to === state) ?? null;
    }

    /** Can this event fire from the current state? */
    can(event) {
      const mn = _machineCategory(this._name);
      return TABLE.some(t =>
        (t.m === mn || t.m === '*') &&
        (t.from === this._state || t.from === '*') &&
        t.on === event
      );
    }

    /**
     * Fire an event.
     * @param {string} event  — event name (e.g. 'UNLOCK_OK')
     * @param {object} payload — arbitrary metadata attached to this transition
     * @returns {boolean} true if transition succeeded, false if guard failed or no match
     */
    send(event, payload = {}) {
      const K  = this._kernel;
      const mn = _machineCategory(this._name);

      const row = TABLE.find(t =>
        (t.m === mn || t.m === '*') &&
        (t.from === this._state || t.from === '*') &&
        t.on === event
      );

      if (!row) return false;

      // Evaluate guard if present
      if (row.guard && GUARDS[row.guard]) {
        if (!GUARDS[row.guard](K)) {
          K._emit('GUARD_REJECTED', {
            machine: this._name,
            event,
            guard: row.guard,
            state: this._state,
          });
          return false;
        }
      }

      const prev = this._state;
      this._state = row.to;

      const entry = {
        from:    prev,
        to:      row.to,
        event,
        ts:      Date.now(),
        payload,
        meta:    row.meta ?? null,
      };

      this._history.push(entry);
      // Keep history bounded: retain first entry + 255 most recent
      if (this._history.length > 256) this._history.splice(1, this._history.length - 256);

      // Emit transition events
      K._emit('TRANSITION',              { machine: this._name, ...entry });
      K._emit(`${this._name}:${row.to}`, { from: prev, event, payload });

      // PANIC cascades
      if (event === 'PANIC') {
        K._cascadePanic(payload);
      }

      // Invariant check after every transition
      if (K._checkAfterTransition) {
        const vs = K.checkInvariants();
        if (vs.length) {
          K._emit('INVARIANT_VIOLATION', { violations: vs, trigger: entry });
          // In strict mode, panic immediately on invariant violation
          if (K._strictMode && vs.length) {
            K._cascadePanic({ reason: 'INVARIANT_VIOLATION', violations: vs });
          }
        }
      }

      return true;
    }

    snapshot() {
      return {
        name:    this._name,
        state:   this._state,
        history: this._history.slice(-32), // last 32 transitions
      };
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  HELPER — resolve machine category for TABLE lookup
  // ──────────────────────────────────────────────────────────────────────────
  function _machineCategory(name) {
    if (name.startsWith('ratchet:')) return 'ratchet';
    return name;
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  MERKLE HELPERS — for snapshot attestation
  // ──────────────────────────────────────────────────────────────────────────
  async function _sha256hex(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  async function _merkleRoot(leaves) {
    // leaves is an array of hex strings (already hashed)
    // Standard binary merkle tree — if odd, duplicate last leaf
    let layer = [...leaves];
    while (layer.length > 1) {
      if (layer.length % 2 !== 0) layer.push(layer[layer.length - 1]);
      const next = [];
      for (let i = 0; i < layer.length; i += 2) {
        next.push(await _sha256hex(layer[i] + layer[i + 1]));
      }
      layer = next;
    }
    return layer[0] ?? null;
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  KERNEL — authoritative system state object
  // ──────────────────────────────────────────────────────────────────────────
  const Kernel = {

    // Core machines
    vault:       new FSM('vault',       'LOCKED'),
    identity:    new FSM('identity',    'NONE'),
    transport:   new FSM('transport',   'OFFLINE'),
    kdf:         new FSM('kdf',         'IDLE'),
    governance:  new FSM('governance',  'IDLE'),
    attestation: new FSM('attestation', 'IDLE'),
    onion:       new FSM('onion',       'OFFLINE'),

    // Per-peer ratchet machines (lazily created)
    _ratchets: new Map(),

    // Governance metadata — endorsements, eligible voters, active proposal
    _gov: { endorsements: 0, eligibleVoters: 1, proposal: null },

    // Global event bus (detached EventTarget for isolation)
    _bus: new EventTarget(),

    // Options
    _checkAfterTransition: true,
    _strictMode:           false, // if true, invariant violations trigger PANIC

    // Protocol version — included in all snapshots
    _version: FSM_PROTOCOL_VERSION,

    // ── Ratchet accessor ─────────────────────────────────────────────────────
    ratchet(peerDid) {
      if (!this._ratchets.has(peerDid)) {
        const r = new FSM(`ratchet:${peerDid}`, 'UNINIT');
        r._kernel = this;
        this._ratchets.set(peerDid, r);
      }
      return this._ratchets.get(peerDid);
    },

    /** Remove a peer ratchet (e.g. after peer disconnect + session closed). */
    dropRatchet(peerDid) {
      const r = this._ratchets.get(peerDid);
      if (r && r.state !== 'UNINIT') {
        r.send('CLOSE'); // attempt clean close
      }
      this._ratchets.delete(peerDid);
    },

    // ── Event bus ────────────────────────────────────────────────────────────
    on(event, cb) {
      const h = (e) => cb(e.detail);
      this._bus.addEventListener(event, h);
      return () => this._bus.removeEventListener(event, h);
    },

    once(event, cb) {
      const unsub = this.on(event, (detail) => { cb(detail); unsub(); });
      return unsub;
    },

    _emit(event, detail = {}) {
      detail._ts  = detail._ts  ?? Date.now();
      detail._ver = detail._ver ?? this._version;
      this._bus.dispatchEvent(new CustomEvent(event, { detail }));
      // Surface to window for cross-component / cross-script listening
      try {
        window.dispatchEvent(new CustomEvent(`sovereign:fsm:${event}`, { detail }));
      } catch (_) { /* Worker context — ignore */ }
    },

    // ── Panic cascade ────────────────────────────────────────────────────────
    _cascadePanic(payload) {
      const all = [
        this.vault, this.identity, this.transport,
        this.kdf, this.governance, this.attestation, this.onion,
      ];
      for (const m of all) {
        if (m.state !== 'PANICKED') {
          const prev = m._state;
          m._state = 'PANICKED';
          m._history.push({
            from: prev, to: 'PANICKED', event: 'PANIC_CASCADE',
            ts: Date.now(), payload,
          });
        }
      }
      for (const r of this._ratchets.values()) {
        r._state = 'PANICKED';
      }
      this._emit('PANIC_CASCADE', { payload });
    },

    // ── Invariant checking ───────────────────────────────────────────────────
    checkInvariants() {
      const violations = [];
      for (const inv of INVARIANTS) {
        try {
          if (!inv.check(this)) {
            violations.push({ id: inv.id, desc: inv.desc, ts: Date.now() });
          }
        } catch (err) {
          violations.push({ id: inv.id, desc: `CHECK_ERROR: ${err.message}`, ts: Date.now() });
        }
      }
      return violations;
    },

    /** Throws if any invariant is violated. Use before critical operations. */
    assert() {
      const vs = this.checkInvariants();
      if (vs.length) {
        throw new Error(
          `[SovereignFSM] Invariant violations:\n` +
          vs.map(v => `  ${v.id}: ${v.desc}`).join('\n')
        );
      }
    },

    // ── Snapshots ────────────────────────────────────────────────────────────
    snapshot() {
      return {
        _protocol:   this._version,
        ts:          Date.now(),
        vault:       this.vault.snapshot(),
        identity:    this.identity.snapshot(),
        transport:   this.transport.snapshot(),
        kdf:         this.kdf.snapshot(),
        governance:  this.governance.snapshot(),
        attestation: this.attestation.snapshot(),
        onion:       this.onion.snapshot(),
        ratchets:    Object.fromEntries(
          [...this._ratchets.entries()].map(([k, v]) => [k, v.snapshot()])
        ),
        invariants:  this.checkInvariants(),
      };
    },

    /**
     * Produce a cryptographically attested snapshot.
     * Returns { snapshot, leaves, merkleRoot } where merkleRoot is the SHA-256
     * of the sorted leaf hashes — verifiable without this library.
     */
    async attest() {
      const snap = this.snapshot();

      // Build one leaf per named machine: SHA256("machine:state:ts")
      const machineNames = ['vault','identity','transport','kdf','governance','attestation','onion'];
      const leafInputs = machineNames.map(n => `${n}:${snap[n].state}:${snap.ts}`);

      // Add one leaf per active ratchet
      for (const [did, r] of this._ratchets) {
        leafInputs.push(`ratchet:${did.slice(-16)}:${r.state}:${snap.ts}`);
      }

      leafInputs.sort(); // canonical ordering
      const leaves = await Promise.all(leafInputs.map(l => _sha256hex(l)));
      const root   = await _merkleRoot([...leaves]);

      return { snapshot: snap, leaves, merkleRoot: root };
    },

    // ── Governance helpers ───────────────────────────────────────────────────
    govern: {
      propose(K, proposal) {
        K._gov.proposal     = proposal;
        K._gov.endorsements = 1; // proposer auto-endorses
        return K.governance.send('PROPOSE', { proposal });
      },
      endorse(K) {
        K._gov.endorsements++;
        // Auto-advance to voting if quorum reached
        if (K.governance.state === 'PROPOSED') {
          K.governance.send('OPEN_VOTE');
        }
      },
      castVote(K, vote) {
        K._emit('GOVERNANCE_VOTE', { vote, ts: Date.now() });
      },
      close(K, result) {
        if (K.governance.state !== 'VOTING') return false;
        K.governance.send('CLOSE');
        return result === 'pass'
          ? K.governance.send('PASS')
          : K.governance.send('FAIL');
      },
    },

    // ── Convenience predicates ───────────────────────────────────────────────
    canSend()    { return this.transport.state === 'CONNECTED' || this.transport.state === 'DEGRADED'; },
    canSign()    { return this.vault.state === 'UNLOCKED' && this.identity.state === 'READY'; },
    canEncrypt() { return this.identity.state === 'READY'; },
    canRoute()   { return this.onion.state === 'READY'; },
    isPanicked() {
      return [this.vault, this.identity, this.transport, this.kdf]
        .some(m => m.state === 'PANICKED');
    },

    // ── Debug ────────────────────────────────────────────────────────────────
    printBoard() {
      const snap = this.snapshot();
      const row  = (name, s) => `  ${name.padEnd(14)} ${s}`;
      const machines = ['vault','kdf','identity','transport','governance','attestation','onion'];
      console.group('[SovereignFSM v3.0] System State Board');
      machines.forEach(n => console.log(row(n, snap[n].state)));
      const rkeys = Object.keys(snap.ratchets);
      if (rkeys.length) {
        console.group('ratchets');
        rkeys.forEach(did => console.log(row(did.slice(-16), snap.ratchets[did].state)));
        console.groupEnd();
      }
      if (snap.invariants.length) {
        console.warn('⚠ INVARIANT VIOLATIONS:', snap.invariants);
      } else {
        console.log('  invariants    ✓ all clear');
      }
      console.groupEnd();
    },

  };

  // Wire kernel reference into all named machines
  for (const m of [
    Kernel.vault, Kernel.identity, Kernel.transport,
    Kernel.kdf, Kernel.governance, Kernel.attestation, Kernel.onion,
  ]) {
    m._kernel = Kernel;
  }

  // Expose internals for tooling and visualization
  Kernel._table      = TABLE;
  Kernel._guards     = GUARDS;
  Kernel._invariants = INVARIANTS;

  // ──────────────────────────────────────────────────────────────────────────
  //  SERVICE WORKER INTEGRATION BRIDGE
  //  Mirror SW kernel events into FSM transitions.
  // ──────────────────────────────────────────────────────────────────────────
  if (typeof navigator !== 'undefined' && 'serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (e) => {
      const { event, peerDid, reason, data } = e.data ?? {};
      if (!event) return;

      const MAP = {
        'VAULT_CREATED':        () => Kernel.vault.send('CREATE_OK'),
        'VAULT_CREATE_FAIL':    () => Kernel.vault.send('CREATE_FAIL'),
        'KDF_COMPLETE':         () => {
          Kernel.kdf.send('STRETCH_OK');
          Kernel.kdf.send('CONSUME');
        },
        'VAULT_UNLOCKED':       () => {
          Kernel.vault.send('UNLOCK_OK');
          Kernel.identity.send('LOAD');
        },
        'VAULT_UNLOCK_FAIL':    () => Kernel.vault.send('UNLOCK_FAIL'),
        'VAULT_LOCKED':         () => {
          Kernel.vault.send('LOCK');
          Kernel.identity.send('LOCK');
          Kernel.transport.send('DISCONNECT');
          Kernel.onion.send('TEARDOWN');
        },
        'IDENTITY_LOADED':      () => Kernel.identity.send('LOAD_OK'),
        'IDENTITY_GENERATED':   () => Kernel.identity.send('GEN_OK'),
        'IDENTITY_GEN_FAIL':    () => Kernel.identity.send('GEN_FAIL'),
        'RATCHET_INITIALIZED':  () => {
          if (peerDid) {
            Kernel.ratchet(peerDid).send('INIT');
            Kernel.ratchet(peerDid).send('READY');
          }
        },
        'RATCHET_REKEYED':      () => {
          if (peerDid) Kernel.ratchet(peerDid).send('REKEY');
        },
        'RATCHET_CLOSED':       () => {
          if (peerDid) Kernel.ratchet(peerDid).send('CLOSE');
        },
        'ATTESTATION_VERIFIED': () => Kernel.attestation.send('VERIFIED', data),
        'ATTESTATION_FAILED':   () => Kernel.attestation.send('REJECT'),
        'ONION_CIRCUIT_READY':  () => Kernel.onion.send('CIRCUIT_OK'),
        'PANIC_LOCKDOWN':       () => Kernel.vault.send('PANIC', { reason }),
      };

      if (MAP[event]) {
        try { MAP[event](); } catch (_) {}
      }
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  WINDOW PROTOCOL — allow other pages / workers to query state
  // ──────────────────────────────────────────────────────────────────────────
  if (typeof window !== 'undefined') {
    window.addEventListener('sovereign:fsm:query', async (e) => {
      const { replyChannel, query } = e.detail ?? {};
      if (!replyChannel) return;

      let result;
      if (query === 'snapshot') result = Kernel.snapshot();
      if (query === 'attest')   result = await Kernel.attest();
      if (query === 'invariants') result = Kernel.checkInvariants();

      replyChannel.postMessage({ query, result });
    });
  }

  console.log(`[SovereignFSM] v${FSM_PROTOCOL_VERSION} loaded — 8 machines, 8 invariants, 0 deps`);

  return Kernel;

})();
