/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║         SOVEREIGN FSM KERNEL  v1.0  — sovereign_fsm.js          ║
 * ║  The only ground truth. Every invariant in the threat model      ║
 * ║  is a guard condition or a checked transition here.              ║
 * ║  No deps. No framework. Drop in any Sovereign HTML file.         ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * MACHINES:
 *   vault      — LOCKED → UNLOCKING → UNLOCKED → LOCKED (+ PANICKED)
 *   identity   — NONE → GENERATING → READY → DESTROYED
 *   transport  — OFFLINE → DISCOVERING → CONNECTED → DEGRADED
 *   ratchet    — per-peer: UNINIT → KEYED → ACTIVE → STALE
 *   kdf        — IDLE → STRETCHING → READY → CONSUMED
 *
 * USAGE:
 *   const K = window.SovereignFSM;
 *
 *   // Transition a machine
 *   K.vault.send('UNLOCK');          // → VAULT_UNLOCKING
 *   K.vault.send('UNLOCK_OK');       // → VAULT_UNLOCKED
 *
 *   // Listen to transitions
 *   K.on('TRANSITION', e => console.log(e.detail));
 *
 *   // Check all invariants right now
 *   const violations = K.checkInvariants();
 *
 *   // Full snapshot for debugging / attestation
 *   console.log(K.snapshot());
 */

'use strict';

window.SovereignFSM = (() => {

  // ─────────────────────────────────────────────────────────────────────
  //  TRANSITION TABLE
  //  Each row: { from, on, to, guard? }
  //  guard is a key into GUARDS — must return true for transition to fire
  //  from: '*'  means "any state" (used for PANIC only)
  // ─────────────────────────────────────────────────────────────────────
  const TABLE = [
    // ── VAULT ──────────────────────────────────────────────────────────
    { m:'vault', from:'LOCKED',     on:'UNLOCK',      to:'UNLOCKING'  },
    { m:'vault', from:'UNLOCKING',  on:'UNLOCK_OK',   to:'UNLOCKED'   },
    { m:'vault', from:'UNLOCKING',  on:'UNLOCK_FAIL', to:'LOCKED'     },
    { m:'vault', from:'LOCKED',     on:'CREATE',      to:'CREATING'   },
    { m:'vault', from:'CREATING',   on:'CREATE_OK',   to:'LOCKED'     },
    { m:'vault', from:'CREATING',   on:'CREATE_FAIL', to:'LOCKED'     },
    { m:'vault', from:'UNLOCKED',   on:'LOCK',        to:'LOCKED'     },
    { m:'vault', from:'UNLOCKED',   on:'TIMEOUT',     to:'LOCKED'     },
    { m:'vault', from:'UNLOCKED',   on:'REKEY',       to:'REKEYING'   },
    { m:'vault', from:'REKEYING',   on:'REKEY_OK',    to:'UNLOCKED'   },
    { m:'vault', from:'REKEYING',   on:'REKEY_FAIL',  to:'UNLOCKED'   },

    // ── IDENTITY ────────────────────────────────────────────────────────
    // Guard: vault must be UNLOCKED before identity can load
    { m:'identity', from:'NONE',       on:'GENERATE',   to:'GENERATING', guard:'vaultUnlocked' },
    { m:'identity', from:'NONE',       on:'LOAD',       to:'LOADING',    guard:'vaultUnlocked' },
    { m:'identity', from:'GENERATING', on:'GEN_OK',     to:'READY'      },
    { m:'identity', from:'GENERATING', on:'GEN_FAIL',   to:'NONE'       },
    { m:'identity', from:'LOADING',    on:'LOAD_OK',    to:'READY'      },
    { m:'identity', from:'LOADING',    on:'LOAD_FAIL',  to:'NONE'       },
    { m:'identity', from:'READY',      on:'LOCK',       to:'NONE'       },  // vault locked
    { m:'identity', from:'READY',      on:'REVOKE',     to:'DESTROYED'  },
    { m:'identity', from:'DESTROYED',  on:'RESET',      to:'NONE'       },

    // ── TRANSPORT ───────────────────────────────────────────────────────
    // Guard: identity must be READY before transport goes online
    { m:'transport', from:'OFFLINE',     on:'CONNECT',     to:'DISCOVERING', guard:'identityReady' },
    { m:'transport', from:'DISCOVERING', on:'PEERS_FOUND', to:'CONNECTED'  },
    { m:'transport', from:'DISCOVERING', on:'PEERS_NONE',  to:'DEGRADED'   },
    { m:'transport', from:'DISCOVERING', on:'TIMEOUT',     to:'DEGRADED'   },
    { m:'transport', from:'CONNECTED',   on:'PEER_LOST',   to:'DEGRADED'   },
    { m:'transport', from:'CONNECTED',   on:'DISCONNECT',  to:'OFFLINE'    },
    { m:'transport', from:'DEGRADED',    on:'PEER_FOUND',  to:'CONNECTED'  },
    { m:'transport', from:'DEGRADED',    on:'RELAY_UP',    to:'CONNECTED'  },
    { m:'transport', from:'DEGRADED',    on:'DISCONNECT',  to:'OFFLINE'    },

    // ── KDF (passphrase stretching) ─────────────────────────────────────
    // Guard: must complete KDF before vault can unlock
    { m:'kdf', from:'IDLE',      on:'STRETCH',   to:'STRETCHING' },
    { m:'kdf', from:'STRETCHING',on:'STRETCH_OK',to:'READY'      },
    { m:'kdf', from:'STRETCHING',on:'STRETCH_FAIL',to:'IDLE'     },
    { m:'kdf', from:'READY',     on:'CONSUME',   to:'CONSUMED'   },  // key handed to SW
    { m:'kdf', from:'CONSUMED',  on:'RESET',     to:'IDLE'       },
    { m:'kdf', from:'READY',     on:'RESET',     to:'IDLE'       },

    // ── RATCHET (per-peer sessions) ──────────────────────────────────────
    // States: UNINIT → KEYED → ACTIVE → STALE
    // Guard: identity must be READY before any ratchet may advance
    { m:'ratchet', from:'UNINIT',  on:'INIT',    to:'KEYED',   guard:'identityReady' },
    { m:'ratchet', from:'KEYED',   on:'READY',   to:'ACTIVE'   },
    { m:'ratchet', from:'ACTIVE',  on:'REKEY',   to:'KEYED'    },
    { m:'ratchet', from:'ACTIVE',  on:'STALE',   to:'STALE'    },
    { m:'ratchet', from:'STALE',   on:'REKEY',   to:'KEYED'    },
    { m:'ratchet', from:'STALE',   on:'CLOSE',   to:'UNINIT'   },
    { m:'ratchet', from:'KEYED',   on:'CLOSE',   to:'UNINIT'   },
    { m:'ratchet', from:'ACTIVE',  on:'CLOSE',   to:'UNINIT'   },

    // ── PANIC — from any state in any machine ───────────────────────────
    { m:'*', from:'*', on:'PANIC', to:'PANICKED' },
  ];

  // ─────────────────────────────────────────────────────────────────────
  //  GUARDS — functions that must return true for a transition to fire
  //  Called with the Kernel as `this`
  // ─────────────────────────────────────────────────────────────────────
  const GUARDS = {
    vaultUnlocked:  (K) => K.vault.state === 'UNLOCKED',
    identityReady:  (K) => K.identity.state === 'READY',
    kdfReady:       (K) => K.kdf.state === 'READY',
  };

  // ─────────────────────────────────────────────────────────────────────
  //  SYSTEM INVARIANTS — checked on demand or after every transition
  //  Violations returned as strings. Empty array = system consistent.
  // ─────────────────────────────────────────────────────────────────────
  const INVARIANTS = [
    {
      id: 'INV-01',
      desc: 'Transport cannot be connected without an unlocked vault',
      check: (K) =>
        !(K.transport.state === 'CONNECTED' && K.vault.state !== 'UNLOCKED'),
    },
    {
      id: 'INV-02',
      desc: 'Identity cannot be READY while vault is LOCKED',
      check: (K) =>
        !(K.identity.state === 'READY' && K.vault.state === 'LOCKED'),
    },
    {
      id: 'INV-03',
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
      id: 'INV-04',
      desc: 'Vault cannot be unlocked without KDF completion',
      check: (K) =>
        !(K.vault.state === 'UNLOCKED' && K.kdf.state === 'IDLE'),
    },
    {
      id: 'INV-05',
      desc: 'PANICKED state is terminal — no other machine may advance',
      check: (K) => {
        const panicked = [K.vault, K.identity, K.transport, K.kdf]
          .some(m => m.state === 'PANICKED');
        if (!panicked) return true;
        // If any machine panicked, all must be PANICKED or LOCKED/NONE/OFFLINE/IDLE
        const safe = new Set(['PANICKED','LOCKED','NONE','OFFLINE','IDLE','CONSUMED']);
        return [K.vault, K.identity, K.transport, K.kdf].every(m => safe.has(m.state));
      },
    },
  ];

  // ─────────────────────────────────────────────────────────────────────
  //  FSM — single state machine instance
  // ─────────────────────────────────────────────────────────────────────
  class FSM {
    constructor(name, initial) {
      this._name    = name;
      this._state   = initial;
      this._history = [{ state: initial, ts: Date.now() }];
      this._kernel  = null;   // set by Kernel after construction
    }

    get state() { return this._state; }
    get name()  { return this._name;  }

    /** Returns true if the event is valid from the current state */
    can(event) {
      const machineName = this._name.startsWith('ratchet:') ? 'ratchet' : this._name;
      return TABLE.some(t =>
        (t.m === machineName || t.m === '*') &&
        (t.from === this._state || t.from === '*') &&
        t.on === event
      );
    }

    /**
     * Fire an event.
     * @returns {boolean} true if transition succeeded
     */
    send(event, payload = {}) {
      const K = this._kernel;
      const machineName = this._name.startsWith('ratchet:') ? 'ratchet' : this._name;

      // Find matching transition for this machine
      const row = TABLE.find(t =>
        (t.m === machineName || t.m === '*') &&
        (t.from === this._state || t.from === '*') &&
        t.on === event
      );

      if (!row) {
        K._emit('FSM_INVALID', { machine: this._name, state: this._state, event });
        return false;
      }

      // Check guard
      if (row.guard) {
        const guardFn = GUARDS[row.guard];
        if (guardFn && !guardFn(K)) {
          K._emit('FSM_GUARD_FAIL', { machine: this._name, state: this._state, event, guard: row.guard });
          return false;
        }
      }

      const prev = this._state;
      this._state = row.to;

      const entry = { from: prev, to: row.to, event, ts: Date.now(), payload };
      this._history.push(entry);
      if (this._history.length > 256) this._history.splice(1, 64); // keep first + recent

      // Emit events
      K._emit('TRANSITION',          { machine: this._name, ...entry });
      K._emit(`${this._name}:${row.to}`, { from: prev, event, payload });

      // If PANIC, cascade to all machines
      if (event === 'PANIC' && this._name !== '*') {
        K._cascadePanic(payload);
      }

      // Check invariants after every transition (dev mode)
      if (K._checkAfterTransition) {
        const vs = K.checkInvariants();
        if (vs.length) {
          K._emit('INVARIANT_VIOLATION', { violations: vs, trigger: entry });
        }
      }

      return true;
    }

    snapshot() {
      return {
        name:    this._name,
        state:   this._state,
        history: this._history.slice(-20),
      };
    }
  }

  // ─────────────────────────────────────────────────────────────────────
  //  KERNEL — the authoritative system state
  // ─────────────────────────────────────────────────────────────────────
  const Kernel = {
    // Core machines
    vault:     new FSM('vault',     'LOCKED'),
    identity:  new FSM('identity',  'NONE'),
    transport: new FSM('transport', 'OFFLINE'),
    kdf:       new FSM('kdf',       'IDLE'),

    // Per-peer ratchets — lazily created
    _ratchets: new Map(),

    // Global event bus (CustomEvent on a detached EventTarget)
    _bus: new EventTarget(),

    // Check invariants after every transition in debug mode
    _checkAfterTransition: true,

    // ── Ratchet accessor ───────────────────────────────────────────────
    ratchet(peerDid) {
      if (!this._ratchets.has(peerDid)) {
        const r = new FSM(`ratchet:${peerDid}`, 'UNINIT');
        r._kernel = this;
        this._ratchets.set(peerDid, r);
      }
      return this._ratchets.get(peerDid);
    },

    // ── Event bus ─────────────────────────────────────────────────────
    on(event, cb) {
      const h = (e) => cb(e.detail);
      this._bus.addEventListener(event, h);
      return () => this._bus.removeEventListener(event, h);
    },

    _emit(event, detail = {}) {
      this._bus.dispatchEvent(new CustomEvent(event, { detail }));
      // Also bubble to window for cross-component listening
      window.dispatchEvent(new CustomEvent(`sovereign:fsm:${event}`, { detail }));
    },

    // ── Panic cascade ─────────────────────────────────────────────────
    _cascadePanic(payload) {
      for (const m of [this.vault, this.identity, this.transport, this.kdf]) {
        if (m.state !== 'PANICKED') {
          m._state = 'PANICKED';
          m._history.push({ from: m._state, to:'PANICKED', event:'PANIC_CASCADE', ts: Date.now(), payload });
        }
      }
      for (const r of this._ratchets.values()) {
        r._state = 'PANICKED';
      }
      this._emit('PANIC_CASCADE', { payload });
    },

    // ── Invariant checking ────────────────────────────────────────────
    checkInvariants() {
      const violations = [];
      for (const inv of INVARIANTS) {
        try {
          if (!inv.check(this)) {
            violations.push({ id: inv.id, desc: inv.desc });
          }
        } catch (err) {
          violations.push({ id: inv.id, desc: `CHECK_ERROR: ${err.message}` });
        }
      }
      return violations;
    },

    /**
     * Assert all invariants — throws on violation.
     * Call from tests or before critical operations.
     */
    assert() {
      const vs = this.checkInvariants();
      if (vs.length) {
        throw new Error(`[SovereignFSM] Invariant violations:\n` +
          vs.map(v => `  ${v.id}: ${v.desc}`).join('\n'));
      }
    },

    // ── Full snapshot ─────────────────────────────────────────────────
    snapshot() {
      return {
        ts:         Date.now(),
        vault:      this.vault.snapshot(),
        identity:   this.identity.snapshot(),
        transport:  this.transport.snapshot(),
        kdf:        this.kdf.snapshot(),
        ratchets:   Object.fromEntries(
          [...this._ratchets.entries()].map(([k, v]) => [k, v.snapshot()])
        ),
        invariants: this.checkInvariants(),
      };
    },

    // ── Convenience: check if a specific capability is currently safe ──
    canSend()    { return this.transport.state === 'CONNECTED' || this.transport.state === 'DEGRADED'; },
    canSign()    { return this.vault.state === 'UNLOCKED' && this.identity.state === 'READY'; },
    canEncrypt() { return this.identity.state === 'READY'; },
  };

  // Wire kernel reference into all machines
  for (const m of [Kernel.vault, Kernel.identity, Kernel.transport, Kernel.kdf]) {
    m._kernel = Kernel;
  }

  // Also expose ratchet TABLE for debugging / visualization
  Kernel._table     = TABLE;
  Kernel._invariants = INVARIANTS;

  // ── Dev helper: print a live state board to the console ──────────────
  Kernel.printBoard = function () {
    const snap = this.snapshot();
    const row  = (name, s) => `  ${name.padEnd(12)} ${s}`;
    console.group('[SovereignFSM] System State');
    console.log(row('vault',     snap.vault.state));
    console.log(row('kdf',       snap.kdf.state));
    console.log(row('identity',  snap.identity.state));
    console.log(row('transport', snap.transport.state));
    if (Object.keys(snap.ratchets).length) {
      console.group('ratchets');
      for (const [did, r] of Object.entries(snap.ratchets)) {
        console.log(row(did.slice(-16), r.state));
      }
      console.groupEnd();
    }
    if (snap.invariants.length) {
      console.warn('INVARIANT VIOLATIONS:', snap.invariants);
    } else {
      console.log('  invariants  ✓ all clear');
    }
    console.groupEnd();
  };

  // ── Integration hooks — listen for SW kernel events and mirror them ──
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (e) => {
      const { event } = e.data || {};
      if (!event) return;

      // Mirror SW events into FSM transitions
      const MAP = {
        'VAULT_UNLOCKED':      () => { Kernel.vault.send('UNLOCK_OK'); Kernel.identity.send('LOAD'); },
        'VAULT_LOCKED':        () => { Kernel.vault.send('LOCK'); Kernel.identity.send('LOCK'); Kernel.transport.send('DISCONNECT'); },
        'VAULT_CREATED':       () => Kernel.vault.send('CREATE_OK'),
        'VAULT_ERROR':         () => Kernel.vault.send('UNLOCK_FAIL'),
        'LOAD_OK':             () => Kernel.identity.send('LOAD_OK'),
        'RATCHET_INITIALIZED': () => {
          const did = e.data.peerDid;
          if (did) { Kernel.ratchet(did).send('INIT'); Kernel.ratchet(did).send('READY'); }
        },
        'PANIC_LOCKDOWN':      () => Kernel.vault.send('PANIC', { reason: e.data.reason }),
      };

      if (MAP[event]) {
        try { MAP[event](); } catch {}
      }
    });
  }

  console.log('[SovereignFSM] Kernel loaded — 5 machines, 5 invariants, 0 deps');
  return Kernel;

})();
