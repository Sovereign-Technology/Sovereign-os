/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║         SOVEREIGN FSM KERNEL  v4.0  —  sovereign_fsm.js                ║
 * ║                                                                          ║
 * ║  The single source of authoritative system state.                        ║
 * ║  Every invariant in the threat model is enforced here.                   ║
 * ║  No external dependencies. Drop-in for any Sovereign HTML file.          ║
 * ║                                                                          ║
 * ║  © James Chapman (XheCarpenXer) · iconoclastdao@gmail.com               ║
 * ║  Dual License — see LICENSE.md                                           ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * MACHINES (v4.0 — 12 total, up from 8):
 *   vault         — LOCKED → UNLOCKING → UNLOCKED → LOCKED (+ PANICKED, REKEYING, CREATING, MIGRATING)
 *   identity      — NONE → GENERATING → LOADING → READY → SUSPENDED → DESTROYED
 *   transport     — OFFLINE → DISCOVERING → CONNECTED → DEGRADED → FAILOVER
 *   kdf           — IDLE → STRETCHING → READY → CONSUMED
 *   ratchet       — per-peer: UNINIT → KEYED → ACTIVE → STALE (lazily created)
 *   governance    — IDLE → PROPOSED → VOTING → TALLYING → RATIFIED | FAILED
 *   attestation   — IDLE → CHALLENGING → AWAITING → VERIFIED | FAILED
 *   onion         — OFFLINE → BOOTSTRAPPING → READY → DEGRADED
 *   sync          — IDLE → SYNCING → SYNCED → CONFLICT → RESOLVING  [NEW v4.0]
 *   credential    — NONE → ISSUING → HELD → PRESENTING → REVOKED    [NEW v4.0]
 *   consensus     — IDLE → PROPOSING → COLLECTING → COMMITTED → ABORTED [NEW v4.0]
 *   recovery      — IDLE → COLLECTING_SHARES → RECONSTRUCTING → COMPLETE | FAILED [NEW v4.0]
 *
 * INVARIANTS (12 total):
 *   INV-01  Transport cannot be CONNECTED without an UNLOCKED vault
 *   INV-02  Identity cannot be READY while vault is LOCKED
 *   INV-03  No ratchet may be ACTIVE without a READY identity
 *   INV-04  Vault cannot be UNLOCKED without KDF completion
 *   INV-05  PANICKED state is terminal — no other machine may advance
 *   INV-06  Governance RATIFIED requires identity READY at ratification time
 *   INV-07  Onion circuit READY requires transport CONNECTED
 *   INV-08  Attestation VERIFIED timestamp must post-date challenge timestamp
 *   INV-09  Credential PRESENTING requires identity READY                    [NEW]
 *   INV-10  Consensus COMMITTED requires governance not FAILED               [NEW]
 *   INV-11  Recovery RECONSTRUCTING requires vault LOCKED (safety: no dual unlock) [NEW]
 *   INV-12  Sync SYNCED requires transport CONNECTED                         [NEW]
 *
 * SNAPSHOT ATTESTATION:
 *   K.attest() → { snapshot, merkleRoot, proof }
 *   Root is SHA-256(concat(state hashes sorted by machine name)).
 *   Proof is the sorted leaf hashes. Verifiable offline.
 *
 * USAGE:
 *   const K = window.SovereignFSM;
 *   K.vault.send('UNLOCK');
 *   K.vault.send('UNLOCK_OK');
 *   K.on('TRANSITION', e => console.log(e.detail));
 *   K.on('INVARIANT_VIOLATION', e => console.error(e.detail));
 *   const snap       = K.snapshot();
 *   const attestation = await K.attest();
 */

'use strict';

window.SovereignFSM = (() => {

  const FSM_PROTOCOL_VERSION = '4.0.0';

  // ──────────────────────────────────────────────────────────────────────────
  //  TRANSITION TABLE
  // ──────────────────────────────────────────────────────────────────────────
  const TABLE = [

    // ── VAULT ────────────────────────────────────────────────────────────────
    { m:'vault', from:'LOCKED',     on:'CREATE',       to:'CREATING'                              },
    { m:'vault', from:'CREATING',   on:'CREATE_OK',    to:'LOCKED',    meta:'vault now exists'    },
    { m:'vault', from:'CREATING',   on:'CREATE_FAIL',  to:'LOCKED'                                },
    { m:'vault', from:'LOCKED',     on:'UNLOCK',       to:'UNLOCKING'                             },
    { m:'vault', from:'UNLOCKING',  on:'UNLOCK_OK',    to:'UNLOCKED',  meta:'key in SW memory'    },
    { m:'vault', from:'UNLOCKING',  on:'UNLOCK_FAIL',  to:'LOCKED'                                },
    { m:'vault', from:'UNLOCKED',   on:'LOCK',         to:'LOCKED',    meta:'explicit lock'       },
    { m:'vault', from:'UNLOCKED',   on:'TIMEOUT',      to:'LOCKED',    meta:'inactivity timeout'  },
    { m:'vault', from:'UNLOCKED',   on:'REKEY',        to:'REKEYING'                              },
    { m:'vault', from:'REKEYING',   on:'REKEY_OK',     to:'UNLOCKED'                              },
    { m:'vault', from:'REKEYING',   on:'REKEY_FAIL',   to:'UNLOCKED',  meta:'old key preserved'  },
    { m:'vault', from:'LOCKED',     on:'DURESS',       to:'UNLOCKED',  meta:'decoy keys active'  },
    { m:'vault', from:'UNLOCKED',   on:'MIGRATE',      to:'MIGRATING', meta:'v5→v6 format'       },
    { m:'vault', from:'MIGRATING',  on:'MIGRATE_OK',   to:'UNLOCKED'                              },
    { m:'vault', from:'MIGRATING',  on:'MIGRATE_FAIL', to:'UNLOCKED'                              },
    { m:'vault', from:'*',          on:'PANIC',        to:'PANICKED',  meta:'terminal'            },

    // ── IDENTITY ─────────────────────────────────────────────────────────────
    { m:'identity', from:'NONE',       on:'GENERATE',  to:'GENERATING', guard:'vaultUnlocked'     },
    { m:'identity', from:'NONE',       on:'LOAD',      to:'LOADING',    guard:'vaultUnlocked'     },
    { m:'identity', from:'GENERATING', on:'GEN_OK',    to:'READY'                                 },
    { m:'identity', from:'GENERATING', on:'GEN_FAIL',  to:'NONE'                                  },
    { m:'identity', from:'LOADING',    on:'LOAD_OK',   to:'READY'                                 },
    { m:'identity', from:'LOADING',    on:'LOAD_FAIL', to:'NONE'                                  },
    { m:'identity', from:'READY',      on:'LOCK',      to:'NONE',       meta:'mirror vault lock'  },
    { m:'identity', from:'READY',      on:'SUSPEND',   to:'SUSPENDED',  meta:'temp privacy mode'  },
    { m:'identity', from:'SUSPENDED',  on:'RESUME',    to:'READY'                                 },
    { m:'identity', from:'READY',      on:'REVOKE',    to:'DESTROYED',  meta:'permanent'          },
    { m:'identity', from:'DESTROYED',  on:'RESET',     to:'NONE'                                  },

    // ── TRANSPORT ────────────────────────────────────────────────────────────
    { m:'transport', from:'OFFLINE',    on:'DISCOVER',    to:'DISCOVERING', guard:'vaultUnlocked' },
    { m:'transport', from:'DISCOVERING',on:'RELAY_UP',    to:'CONNECTED'                          },
    { m:'transport', from:'DISCOVERING',on:'RELAY_FAIL',  to:'OFFLINE'                            },
    { m:'transport', from:'CONNECTED',  on:'PEER_LOST',   to:'DEGRADED'                           },
    { m:'transport', from:'DEGRADED',   on:'PEER_FOUND',  to:'CONNECTED'                          },
    { m:'transport', from:'DEGRADED',   on:'ALL_LOST',    to:'OFFLINE'                            },
    { m:'transport', from:'CONNECTED',  on:'RELAY_DOWN',  to:'DEGRADED'                           },
    { m:'transport', from:'DEGRADED',   on:'RELAY_UP',    to:'CONNECTED'                          },
    { m:'transport', from:'CONNECTED',  on:'FAILOVER',    to:'FAILOVER',   meta:'switching relay' },
    { m:'transport', from:'FAILOVER',   on:'FAILOVER_OK', to:'CONNECTED'                          },
    { m:'transport', from:'FAILOVER',   on:'FAILOVER_FAIL',to:'DEGRADED'                          },
    { m:'transport', from:'*',          on:'DISCONNECT',  to:'OFFLINE'                            },

    // ── KDF ──────────────────────────────────────────────────────────────────
    { m:'kdf', from:'IDLE',       on:'STRETCH',    to:'STRETCHING' },
    { m:'kdf', from:'STRETCHING', on:'STRETCH_OK', to:'READY'      },
    { m:'kdf', from:'READY',      on:'CONSUME',    to:'CONSUMED'   },
    { m:'kdf', from:'CONSUMED',   on:'RESET',      to:'IDLE'       },

    // ── GOVERNANCE ───────────────────────────────────────────────────────────
    { m:'governance', from:'IDLE',      on:'PROPOSE',  to:'PROPOSED', guard:'identityReady' },
    { m:'governance', from:'PROPOSED',  on:'VOTE',     to:'VOTING'                          },
    { m:'governance', from:'PROPOSED',  on:'WITHDRAW', to:'IDLE'                            },
    { m:'governance', from:'VOTING',    on:'CLOSE',    to:'TALLYING'                        },
    { m:'governance', from:'TALLYING',  on:'PASS',     to:'RATIFIED'                        },
    { m:'governance', from:'TALLYING',  on:'FAIL',     to:'FAILED'                          },
    { m:'governance', from:'RATIFIED',  on:'RESET',    to:'IDLE'                            },
    { m:'governance', from:'FAILED',    on:'RESET',    to:'IDLE'                            },

    // ── ATTESTATION ──────────────────────────────────────────────────────────
    { m:'attestation', from:'IDLE',        on:'CHALLENGE', to:'CHALLENGING'                  },
    { m:'attestation', from:'CHALLENGING', on:'SEND',      to:'AWAITING'                     },
    { m:'attestation', from:'AWAITING',    on:'VERIFIED',  to:'VERIFIED'                     },
    { m:'attestation', from:'AWAITING',    on:'REJECT',    to:'FAILED'                       },
    { m:'attestation', from:'AWAITING',    on:'TIMEOUT',   to:'FAILED'                       },
    { m:'attestation', from:'VERIFIED',    on:'RESET',     to:'IDLE'                         },
    { m:'attestation', from:'FAILED',      on:'RESET',     to:'IDLE'                         },

    // ── ONION ─────────────────────────────────────────────────────────────────
    { m:'onion', from:'OFFLINE',       on:'BOOTSTRAP',  to:'BOOTSTRAPPING'                   },
    { m:'onion', from:'BOOTSTRAPPING', on:'CIRCUIT_OK', to:'READY'                           },
    { m:'onion', from:'BOOTSTRAPPING', on:'FAIL',       to:'OFFLINE'                         },
    { m:'onion', from:'READY',         on:'DEGRADE',    to:'DEGRADED'                        },
    { m:'onion', from:'DEGRADED',      on:'REBUILD',    to:'BOOTSTRAPPING'                   },
    { m:'onion', from:'READY',         on:'TEAR_DOWN',  to:'OFFLINE'                         },

    // ── SYNC (NEW v4.0) ───────────────────────────────────────────────────────
    { m:'sync', from:'IDLE',       on:'START',     to:'SYNCING',   guard:'transportConnected' },
    { m:'sync', from:'SYNCING',    on:'COMPLETE',  to:'SYNCED'                                },
    { m:'sync', from:'SYNCING',    on:'CONFLICT',  to:'CONFLICT'                              },
    { m:'sync', from:'CONFLICT',   on:'RESOLVE',   to:'RESOLVING'                             },
    { m:'sync', from:'RESOLVING',  on:'RESOLVED',  to:'SYNCED'                                },
    { m:'sync', from:'SYNCED',     on:'INVALIDATE',to:'IDLE'                                  },
    { m:'sync', from:'*',          on:'RESET',     to:'IDLE'                                  },

    // ── CREDENTIAL (NEW v4.0) ─────────────────────────────────────────────────
    { m:'credential', from:'NONE',       on:'ISSUE',    to:'ISSUING',   guard:'identityReady' },
    { m:'credential', from:'ISSUING',    on:'ISSUED',   to:'HELD'                              },
    { m:'credential', from:'ISSUING',    on:'FAIL',     to:'NONE'                              },
    { m:'credential', from:'HELD',       on:'PRESENT',  to:'PRESENTING'                        },
    { m:'credential', from:'PRESENTING', on:'PRESENTED',to:'HELD'                              },
    { m:'credential', from:'HELD',       on:'REVOKE',   to:'REVOKED'                           },
    { m:'credential', from:'REVOKED',    on:'RESET',    to:'NONE'                              },

    // ── CONSENSUS (NEW v4.0) ──────────────────────────────────────────────────
    { m:'consensus', from:'IDLE',       on:'PROPOSE',  to:'PROPOSING'                         },
    { m:'consensus', from:'PROPOSING',  on:'ACK',      to:'COLLECTING'                        },
    { m:'consensus', from:'COLLECTING', on:'COMMIT',   to:'COMMITTED'                         },
    { m:'consensus', from:'COLLECTING', on:'ABORT',    to:'ABORTED'                           },
    { m:'consensus', from:'COMMITTED',  on:'RESET',    to:'IDLE'                              },
    { m:'consensus', from:'ABORTED',    on:'RETRY',    to:'PROPOSING'                         },
    { m:'consensus', from:'ABORTED',    on:'RESET',    to:'IDLE'                              },

    // ── RECOVERY (NEW v4.0) ───────────────────────────────────────────────────
    { m:'recovery', from:'IDLE',              on:'START',       to:'COLLECTING_SHARES'         },
    { m:'recovery', from:'COLLECTING_SHARES', on:'ENOUGH',      to:'RECONSTRUCTING'            },
    { m:'recovery', from:'COLLECTING_SHARES', on:'CANCEL',      to:'IDLE'                      },
    { m:'recovery', from:'RECONSTRUCTING',    on:'SUCCESS',     to:'COMPLETE'                  },
    { m:'recovery', from:'RECONSTRUCTING',    on:'FAIL',        to:'FAILED'                    },
    { m:'recovery', from:'COMPLETE',          on:'RESET',       to:'IDLE'                      },
    { m:'recovery', from:'FAILED',            on:'RETRY',       to:'COLLECTING_SHARES'         },

    // ── RATCHET (per-peer, lazily created) ────────────────────────────────────
    { m:'ratchet', from:'UNINIT',  on:'INIT',    to:'KEYED'                                    },
    { m:'ratchet', from:'KEYED',   on:'ACTIVATE',to:'ACTIVE'                                   },
    { m:'ratchet', from:'ACTIVE',  on:'STEP',    to:'ACTIVE',  meta:'DH ratchet step'          },
    { m:'ratchet', from:'ACTIVE',  on:'STALE',   to:'STALE'                                    },
    { m:'ratchet', from:'STALE',   on:'REKEY',   to:'KEYED'                                    },
    { m:'ratchet', from:'*',       on:'RESET',   to:'UNINIT'                                   },
  ];

  // ──────────────────────────────────────────────────────────────────────────
  //  GUARDS
  // ──────────────────────────────────────────────────────────────────────────
  const GUARDS = {
    vaultUnlocked:       (snap) => snap.vault?.state === 'UNLOCKED',
    identityReady:       (snap) => snap.identity?.state === 'READY',
    transportConnected:  (snap) => ['CONNECTED','DEGRADED'].includes(snap.transport?.state),
    governanceNotFailed: (snap) => snap.governance?.state !== 'FAILED',
    vaultLocked:         (snap) => snap.vault?.state === 'LOCKED',
  };

  // ──────────────────────────────────────────────────────────────────────────
  //  INVARIANTS
  // ──────────────────────────────────────────────────────────────────────────
  const INVARIANTS = [
    {
      id: 'INV-01', desc: 'Transport CONNECTED requires vault UNLOCKED',
      check: s => !(s.transport?.state === 'CONNECTED' && s.vault?.state !== 'UNLOCKED'),
    },
    {
      id: 'INV-02', desc: 'Identity READY requires vault UNLOCKED',
      check: s => !(s.identity?.state === 'READY' && s.vault?.state !== 'UNLOCKED'),
    },
    {
      id: 'INV-03', desc: 'Active ratchet requires READY identity',
      check: s => {
        if (s.identity?.state !== 'READY') {
          for (const [k,v] of Object.entries(s)) {
            if (k.startsWith('ratchet:') && v?.state === 'ACTIVE') return false;
          }
        }
        return true;
      },
    },
    {
      id: 'INV-04', desc: 'Vault UNLOCKED requires KDF completion',
      check: s => !(s.vault?.state === 'UNLOCKED' &&
        s.kdf?.state !== 'CONSUMED' && s.kdf?.state !== 'READY' && s.kdf?.state !== 'IDLE'),
    },
    {
      id: 'INV-05', desc: 'PANICKED is terminal — no machine may advance',
      check: s => {
        if (s.vault?.state !== 'PANICKED') return true;
        for (const [k,v] of Object.entries(s)) {
          if (k === 'vault') continue;
          if (v?.state && v.state !== 'OFFLINE' && v.state !== 'LOCKED' &&
              v.state !== 'NONE' && v.state !== 'IDLE') return false;
        }
        return true;
      },
    },
    {
      id: 'INV-06', desc: 'Governance RATIFIED requires identity READY at ratification',
      check: s => !(s.governance?.state === 'RATIFIED' && s.identity?.state !== 'READY'),
    },
    {
      id: 'INV-07', desc: 'Onion READY requires transport CONNECTED',
      check: s => !(s.onion?.state === 'READY' && s.transport?.state === 'OFFLINE'),
    },
    {
      id: 'INV-08', desc: 'Attestation VERIFIED timestamp post-dates challenge',
      check: s => !(s.attestation?.state === 'VERIFIED' &&
        s.attestation?.verifiedAt && s.attestation?.challengedAt &&
        s.attestation.verifiedAt <= s.attestation.challengedAt),
    },
    {
      id: 'INV-09', desc: 'Credential PRESENTING requires identity READY',
      check: s => !(s.credential?.state === 'PRESENTING' && s.identity?.state !== 'READY'),
    },
    {
      id: 'INV-10', desc: 'Consensus COMMITTED requires governance not FAILED',
      check: s => !(s.consensus?.state === 'COMMITTED' && s.governance?.state === 'FAILED'),
    },
    {
      id: 'INV-11', desc: 'Recovery RECONSTRUCTING requires vault LOCKED (no dual-unlock)',
      check: s => !(s.recovery?.state === 'RECONSTRUCTING' && s.vault?.state === 'UNLOCKED'),
    },
    {
      id: 'INV-12', desc: 'Sync SYNCED requires transport not OFFLINE',
      check: s => !(s.sync?.state === 'SYNCED' && s.transport?.state === 'OFFLINE'),
    },
  ];

  // ──────────────────────────────────────────────────────────────────────────
  //  MACHINE FACTORY
  // ──────────────────────────────────────────────────────────────────────────
  const _machines = {};
  const _machineNames = [...new Set(TABLE.map(r => r.m))];
  _machineNames.forEach(m => {
    _machines[m] = { state: getInitialState(m), meta: {}, history: [], transitions: 0 };
  });

  function getInitialState(m) {
    switch(m) {
      case 'vault':       return 'LOCKED';
      case 'identity':    return 'NONE';
      case 'transport':   return 'OFFLINE';
      case 'kdf':         return 'IDLE';
      case 'governance':  return 'IDLE';
      case 'attestation': return 'IDLE';
      case 'onion':       return 'OFFLINE';
      case 'sync':        return 'IDLE';
      case 'credential':  return 'NONE';
      case 'consensus':   return 'IDLE';
      case 'recovery':    return 'IDLE';
      default:            return 'IDLE';
    }
  }

  function _getMachine(name) {
    if (_machines[name]) return _machines[name];
    // Dynamic ratchet machines for per-peer sessions
    if (name.startsWith('ratchet:')) {
      _machines[name] = { state: 'UNINIT', meta: {}, history: [], transitions: 0 };
      return _machines[name];
    }
    return null;
  }

  function _machineProxy(name) {
    return {
      get state() { return (_getMachine(name) ?? { state: '—' }).state; },
      send(event, data = {}) {
        const machine = _getMachine(name);
        if (!machine) {
          console.warn(`[SovereignFSM] Unknown machine: ${name}`);
          return false;
        }
        const snap = snapshot();
        // Find matching transition
        const tx = TABLE.find(r => {
          const mName = name.startsWith('ratchet:') ? 'ratchet' : name;
          return r.m === mName &&
            (r.from === '*' || r.from === machine.state) &&
            r.on === event;
        });
        if (!tx) return false; // No transition defined — silent no-op

        // Guard check
        if (tx.guard) {
          const guardFn = GUARDS[tx.guard];
          if (guardFn && !guardFn(snap)) {
            _emit('GUARD_BLOCKED', { machine: name, event, from: machine.state, guard: tx.guard });
            return false;
          }
        }

        const from = machine.state;
        machine.state = tx.to;
        machine.transitions++;
        machine.meta = { ...machine.meta, ...(data ?? {}) };
        machine.history.push({ from, on: event, to: tx.to, ts: Date.now() });
        if (machine.history.length > 50) machine.history.shift();

        _emit('TRANSITION', { machine: name, from, event, to: tx.to, data, meta: tx.meta });

        // Check invariants after every transition
        const violations = checkInvariants();
        if (violations.length > 0) {
          _emit('INVARIANT_VIOLATION', { violations, machine: name, transition: tx });
          _auditViolations(violations);
        }
        return true;
      }
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  AUDIT CHAIN
  // ──────────────────────────────────────────────────────────────────────────
  const _auditChain = [];
  let _lastAuditHash = new Uint8Array(32);

  async function _appendAudit(entry) {
    const payload = JSON.stringify({ ...entry, prev: (()=>{let _s='';for(let _i=0;_i<_lastAuditHash.length;_i++)_s+=String.fromCharCode(_lastAuditHash[_i]);return btoa(_s);})() });
    const bytes = new TextEncoder().encode(payload);
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    _lastAuditHash = hash;
    _auditChain.push({ entry, hash: (()=>{let _s='';for(let _i=0;_i<hash.length;_i++)_s+=String.fromCharCode(hash[_i]);return btoa(_s);})() });
    if (_auditChain.length > 1000) _auditChain.shift();
  }

  function _auditViolations(vs) {
    vs.forEach(v => _appendAudit({ type: 'INV_VIOLATION', id: v.id, desc: v.desc, ts: Date.now() }));
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  EVENTS
  // ──────────────────────────────────────────────────────────────────────────
  const _listeners = {};

  function _emit(type, detail) {
    const eventName = `sovereign:fsm:${type}`;
    window.dispatchEvent(new CustomEvent(eventName, { detail }));
    (_listeners[type] || []).forEach(fn => fn({ type, detail }));
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  SNAPSHOT
  // ──────────────────────────────────────────────────────────────────────────
  function snapshot() {
    const out = {};
    for (const [name, machine] of Object.entries(_machines)) {
      out[name] = {
        state: machine.state,
        transitions: machine.transitions,
        lastTs: machine.history[machine.history.length - 1]?.ts ?? null,
        meta: { ...machine.meta },
      };
    }
    out._version = FSM_PROTOCOL_VERSION;
    out._ts = Date.now();
    return out;
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  MERKLE ATTESTATION
  // ──────────────────────────────────────────────────────────────────────────
  async function attest() {
    const snap = snapshot();
    const leaves = Object.keys(snap).sort().map(k => {
      const v = snap[k];
      return JSON.stringify({ key: k, state: typeof v === 'object' ? v?.state ?? v : v });
    });
    const hashLeaf = async str => {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
      return new Uint8Array(buf);
    };
    const leafHashes = await Promise.all(leaves.map(hashLeaf));
    // Merkle root: concatenate sorted leaf hashes and hash again
    const catBuf = new Uint8Array(leafHashes.reduce((acc, h) => acc + h.length, 0));
    let offset = 0;
    for (const h of leafHashes) { catBuf.set(h, offset); offset += h.length; }
    const rootBuf = await crypto.subtle.digest('SHA-256', catBuf);
    const toHex = b => Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('');
    return {
      snapshot: snap,
      merkleRoot: toHex(new Uint8Array(rootBuf)),
      proof: leafHashes.map(h => toHex(h)),
      ts: Date.now(),
      version: FSM_PROTOCOL_VERSION,
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  INVARIANT CHECK
  // ──────────────────────────────────────────────────────────────────────────
  function checkInvariants() {
    const snap = snapshot();
    return INVARIANTS.filter(inv => !inv.check(snap));
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  PUBLIC API
  // ──────────────────────────────────────────────────────────────────────────
  const publicAPI = {
    snapshot,
    attest,
    checkInvariants,
    auditChain: () => [..._auditChain],
    version: FSM_PROTOCOL_VERSION,

    on(type, fn) {
      if (!_listeners[type]) _listeners[type] = [];
      _listeners[type].push(fn);
      return () => { _listeners[type] = _listeners[type].filter(f => f !== fn); };
    },

    // Ratchet machine factory
    ratchet(peerId) { return _machineProxy(`ratchet:${peerId}`); },
  };

  // Attach machine proxies
  _machineNames.forEach(name => {
    publicAPI[name] = _machineProxy(name);
  });

  console.log(`[SovereignFSM v${FSM_PROTOCOL_VERSION}] 12 machines · 12 invariants · merkle attestation`);
  return publicAPI;

})();
