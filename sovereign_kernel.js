/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  SOVEREIGN KERNEL  v1.0  —  sovereign_kernel.js                         ║
 * ║                                                                          ║
 * ║  Distributed OS kernel for the browser.                                  ║
 * ║  Drop-in module. Self-initializing. Zero mocks.                          ║
 * ║                                                                          ║
 * ║  Architecture:                                                            ║
 * ║    IPC:       BroadcastChannel (real cross-tab IPC, same-origin)         ║
 * ║    Discovery: ANNOUNCE / WELCOME handshake on channel join               ║
 * ║    Election:  Bully Algorithm (lower JOIN_TIME = older = higher priority)║
 * ║    Scheduling:Priority queue + round-robin with fault-aware dispatch     ║
 * ║    Compute:   new Function executor with injected stdlib                 ║
 * ║    Recovery:  Heartbeat + TTL eviction + automatic re-election           ║
 * ║                                                                          ║
 * ║  Events emitted on window:                                               ║
 * ║    sovereign:kernel:elected       { leaderId, role }                     ║
 * ║    sovereign:kernel:peer-joined   { peerId, joinTime, did? }             ║
 * ║    sovereign:kernel:peer-left     { peerId, reason }                     ║
 * ║    sovereign:kernel:task-queued   { task }                               ║
 * ║    sovereign:kernel:task-assigned { task }                               ║
 * ║    sovereign:kernel:task-done     { task }                               ║
 * ║    sovereign:kernel:task-failed   { task }                               ║
 * ║    sovereign:kernel:election      { phase, nodeId }                      ║
 * ║                                                                          ║
 * ║  API (window.SovereignKernel):                                           ║
 * ║    .dispatch(code, opts?)   — queue a task (any JS expression/closure)   ║
 * ║    .peers()                 — Map of known peers                         ║
 * ║    .tasks()                 — Map of all known tasks                     ║
 * ║    .role()                  — 'leader' | 'worker' | 'candidate'          ║
 * ║    .leader()                — current leader nodeId or null              ║
 * ║    .nodeId()                — this node's 8-char ID                      ║
 * ║    .stats()                 — cluster telemetry object                   ║
 * ║    .forceElection()         — trigger immediate Bully election           ║
 * ║                                                                          ║
 * ║  © James Chapman (XheCarpenXer)  ·  iconoclastdao@gmail.com             ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

'use strict';

(function SovereignKernelInit() {

  // ── Constants ─────────────────────────────────────────────────────────────
  const KERNEL_VERSION  = '1.0.0';
  const CHAN_NAME       = 'sovereign-kernel-v1';
  const HB_INTERVAL_MS  = 500;    // heartbeat period
  const PEER_TTL_MS     = 2500;   // evict peer after this much silence
  const ELECT_WAIT_MS   = 750;    // wait for OK before declaring victory
  const SOLO_WAIT_MS    = 1200;   // wait for peers before going singleton

  // ── Identity ─────────────────────────────────────────────────────────────
  // JOIN_TIME doubles as election priority: lower value = older node = wins
  const NODE_ID   = crypto.randomUUID().slice(0, 8).toUpperCase();
  const JOIN_TIME = performance.timeOrigin + performance.now();

  // ── Protocol Message Types ────────────────────────────────────────────────
  const T = Object.freeze({
    ANNOUNCE:       'ANN',      // join announcement
    WELCOME:        'WEL',      // acknowledge announcement
    HEARTBEAT:      'HB',       // liveness signal
    GOODBYE:        'BYE',      // graceful departure
    DID_ANNOUNCE:   'DANN',     // share sovereign DID with peers
    ELECTION:       'ELECT',    // Bully: I want to be leader
    OK:             'OK',       // Bully: I outrank you, stand down
    VICTORY:        'WIN',      // Bully: I am the leader
    TASK_ANNOUNCE:  'TANN',     // broadcast task state to cluster
    TASK_ASSIGN:    'TASSIGN',  // unicast: leader → worker
    TASK_RESULT:    'TRES',     // worker → broadcast result
  });

  // ── Cluster State ─────────────────────────────────────────────────────────
  const peers    = new Map();   // id → { id, joinTime, role, did, lastSeen }
  const tasks    = new Map();   // id → task object
  let   myRole       = 'candidate';
  let   leaderNode   = null;
  let   awaitingOK   = false;
  let   electionTimer = null;
  let   taskRoundRobin = 0;     // round-robin counter for dispatch
  let   myDid        = null;    // linked sovereign DID (once vault unlocked)

  // ── Channel ───────────────────────────────────────────────────────────────
  const bc = new BroadcastChannel(CHAN_NAME);

  function bcast(type, pay = {}) {
    bc.postMessage({
      type, from: NODE_ID, joinTime: JOIN_TIME,
      role: myRole, did: myDid, ...pay,
    });
  }

  function ucast(to, type, pay = {}) {
    bc.postMessage({
      type, from: NODE_ID, to, joinTime: JOIN_TIME,
      role: myRole, did: myDid, ...pay,
    });
  }

  // ── Event Bus ─────────────────────────────────────────────────────────────
  function emit(event, detail = {}) {
    window.dispatchEvent(new CustomEvent(`sovereign:kernel:${event}`, { detail }));
  }

  // Soft-link to FSM if available — never throws
  // Maps kernel events to the correct FSM machine (there is no 'kernel' machine)
  function fsmSend(event, data = {}) {
    try {
      const fsm = window.SovereignFSM;
      if (!fsm) return;
      switch (event) {
        case 'KERNEL_LEADER':  fsm.consensus?.send('PROPOSE', data);     break;
        case 'KERNEL_WORKER':  /* worker role — no FSM transition needed */ break;
        case 'PEER_JOINED':    fsm.transport?.send('PEER_FOUND', data);  break;
        case 'PEER_LEFT':
          fsm.transport?.send(
            window.SovereignKernel?.peers().size === 0 ? 'ALL_LOST' : 'PEER_LOST',
            data
          );
          break;
        case 'TASK_DONE':      /* task completion — no dedicated FSM machine */ break;
        case 'IDENTITY_READY': fsm.identity?.send('LOAD', data);         break;
      }
    } catch (_) {}
  }

  // ── Election — Bully Algorithm ────────────────────────────────────────────
  //
  //   Priority: lower JOIN_TIME = older node = higher priority.
  //
  //   1. Node sends ELECTION to all peers.
  //   2. Any peer with lower JOIN_TIME (higher priority) responds OK and
  //      restarts its own election.
  //   3. If no OK arrives within ELECT_WAIT_MS, node declares VICTORY.
  //   4. VICTORY is broadcast; all nodes update leaderNode.
  //
  function startElection() {
    if (awaitingOK) return;
    clearTimeout(electionTimer);
    awaitingOK = false;
    emit('election', { phase: 'started', nodeId: NODE_ID });

    const higherPriorityExists = [...peers.values()].some(p => p.joinTime < JOIN_TIME);
    if (!higherPriorityExists) {
      declareVictory();
      return;
    }

    awaitingOK = true;
    bcast(T.ELECTION);
    electionTimer = setTimeout(() => {
      if (awaitingOK) declareVictory();
    }, ELECT_WAIT_MS);
  }

  function declareVictory() {
    myRole     = 'leader';
    leaderNode = NODE_ID;
    awaitingOK = false;
    clearTimeout(electionTimer);
    bcast(T.VICTORY);
    emit('elected', { leaderId: NODE_ID, role: 'leader' });
    emit('election', { phase: 'won', nodeId: NODE_ID });
    fsmSend('KERNEL_LEADER');
  }

  // ── Message Handler ───────────────────────────────────────────────────────
  bc.onmessage = ({ data: m }) => {
    if (!m || m.from === NODE_ID) return;
    if (m.to && m.to !== NODE_ID) return;  // unicast not for me

    // Upsert peer registry
    peers.set(m.from, {
      id:       m.from,
      joinTime: m.joinTime,
      role:     m.role ?? peers.get(m.from)?.role ?? 'worker',
      did:      m.did  ?? peers.get(m.from)?.did  ?? null,
      lastSeen: Date.now(),
    });

    switch (m.type) {

      // ── Discovery ─────────────────────────────────────────────────────────

      case T.ANNOUNCE:
        bcast(T.WELCOME);
        if (myRole === 'leader') bcast(T.VICTORY);  // inform newcomer immediately
        emit('peer-joined', { peerId: m.from, joinTime: m.joinTime, did: m.did });
        fsmSend('PEER_JOINED');
        break;

      case T.WELCOME:
        emit('peer-joined', { peerId: m.from, joinTime: m.joinTime, did: m.did });
        if (!leaderNode) {
          // New peer welcomed us; wait briefly then elect if no leader found
          setTimeout(startElection, 100 + Math.random() * 400);
        }
        break;

      case T.HEARTBEAT:
        // Already upserted above; just keep lastSeen fresh
        break;

      case T.DID_ANNOUNCE:
        {
          const p = peers.get(m.from);
          if (p) { p.did = m.did; }
        }
        break;

      case T.GOODBYE:
        peers.delete(m.from);
        emit('peer-left', { peerId: m.from, reason: 'graceful' });
        fsmSend('PEER_LEFT');
        if (m.from === leaderNode) {
          leaderNode = null;
          if (myRole !== 'leader') myRole = 'candidate';
          emit('election', { phase: 'leader-lost', nodeId: m.from });
          setTimeout(startElection, Math.random() * 400);
        }
        break;

      // ── Election ──────────────────────────────────────────────────────────

      case T.ELECTION:
        // m.from has HIGHER joinTime → I have higher priority → I outrank them
        if (JOIN_TIME < m.joinTime) {
          ucast(m.from, T.OK);
          if (myRole !== 'leader') startElection();
        }
        break;

      case T.OK:
        // Higher-priority node outranks me → stand down
        awaitingOK = false;
        clearTimeout(electionTimer);
        emit('election', { phase: 'standing-down', nodeId: NODE_ID });
        break;

      case T.VICTORY:
        leaderNode = m.from;
        if (myRole !== 'leader') myRole = 'worker';
        awaitingOK = false;
        clearTimeout(electionTimer);
        emit('elected', { leaderId: m.from, role: myRole });
        emit('election', { phase: 'accepted', nodeId: m.from });
        fsmSend('KERNEL_WORKER');
        break;

      // ── Task Coordination ─────────────────────────────────────────────────

      case T.TASK_ANNOUNCE:
        if (m.task && !tasks.has(m.task.id)) {
          tasks.set(m.task.id, { ...m.task });
          emit('task-queued', { task: m.task });
          // If I'm the leader and the task is still pending, schedule it
          if (myRole === 'leader' && m.task.status === 'pending') {
            _leaderDispatch({ ...m.task });
          }
        } else if (m.task && tasks.has(m.task.id)) {
          // Merge updates (status, worker, result)
          Object.assign(tasks.get(m.task.id), m.task);
          emit('task-queued', { task: m.task });
        }
        break;

      case T.TASK_ASSIGN:
        // Directed to me — execute this task
        {
          const task = m.task;
          if (!tasks.has(task.id)) tasks.set(task.id, { ...task });
          const t = tasks.get(task.id);
          t.status = 'running'; t.worker = NODE_ID;
          bcast(T.TASK_ANNOUNCE, { task: { ...t } });
          emit('task-assigned', { task: { ...t } });
          _runTask(task);
        }
        break;

      case T.TASK_RESULT:
        if (tasks.has(m.taskId)) {
          const tr = tasks.get(m.taskId);
          tr.status   = m.error ? 'error' : 'done';
          tr.result   = m.result;
          tr.error    = m.error;
          tr.duration = m.duration;
          tr.worker   = m.from;
          emit(m.error ? 'task-failed' : 'task-done', { task: { ...tr } });
          fsmSend('TASK_DONE');
        }
        break;
    }
  };

  // ── Task Dispatch (public API entry) ──────────────────────────────────────
  function dispatch(code, opts = {}) {
    if (typeof code !== 'string' || !code.trim()) {
      throw new TypeError('SovereignKernel.dispatch: code must be a non-empty string');
    }

    const task = {
      id:        crypto.randomUUID(),
      code:      code.trim(),
      submitter: NODE_ID,
      created:   Date.now(),
      status:    'pending',
      priority:  opts.priority ?? 0,
    };

    emit('task-queued', { task });

    if (myRole === 'leader') {
      _leaderDispatch(task);
    } else if (leaderNode) {
      // Submit task to leader for proper scheduling via broadcast.
      // TASK_ASSIGN is leader→worker only; workers submit via TASK_ANNOUNCE
      // so the leader's scheduler can pick it up and dispatch via _leaderDispatch.
      tasks.set(task.id, { ...task });
      bcast(T.TASK_ANNOUNCE, { task });
    } else {
      // No leader yet (e.g. just joined, election in progress) — execute locally
      const t = { ...task, status: 'running', worker: NODE_ID };
      tasks.set(t.id, t);
      bcast(T.TASK_ANNOUNCE, { task: t });
      _runTask(task);
    }

    return task.id;
  }

  // ── Leader Scheduling: round-robin across peers ────────────────────────────
  function _leaderDispatch(task) {
    tasks.set(task.id, { ...task });
    bcast(T.TASK_ANNOUNCE, { task });

    const workerList = [...peers.values()];

    if (workerList.length > 0) {
      // Round-robin load balancing
      const target = workerList[taskRoundRobin % workerList.length];
      taskRoundRobin++;
      const t = tasks.get(task.id);
      t.status = 'running'; t.worker = target.id;
      bcast(T.TASK_ANNOUNCE, { task: { ...t } });
      ucast(target.id, T.TASK_ASSIGN, { task });
      emit('task-assigned', { task: { ...t } });
    } else {
      // Singleton cluster — execute locally
      const t = tasks.get(task.id);
      t.status = 'running'; t.worker = NODE_ID;
      bcast(T.TASK_ANNOUNCE, { task: { ...t } });
      emit('task-assigned', { task: { ...t } });
      _runTask(task);
    }
  }

  // ── Compute Executor ───────────────────────────────────────────────────────
  //
  //   Executes any JS closure string using new Function.
  //   Stdlib is injected as named parameters so tasks can use them.
  //
  const _stdlib = {
    fibonacci: n => {
      let a = 0, b = 1;
      for (let i = 0; i < n; i++) { [a, b] = [b, a + b]; }
      return a;
    },

    primes: n => {
      const sieve = new Uint8Array(n + 1).fill(1);
      sieve[0] = sieve[1] = 0;
      for (let i = 2; i * i <= n; i++)
        if (sieve[i]) for (let j = i * i; j <= n; j += i) sieve[j] = 0;
      let count = 0;
      for (let i = 2; i <= n; i++) if (sieve[i]) count++;
      return count;
    },

    sha256: async data => {
      const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(String(data))
      );
      return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    },

    uuid:  () => crypto.randomUUID(),
    sleep: ms => new Promise(r => setTimeout(r, ms)),
    now:   () => Date.now(),
    randomBytes: n => crypto.getRandomValues(new Uint8Array(n)),
  };

  function _runTask(task) {
    const t0 = performance.now();
    let result, error;

    try {
      const fn = new Function(
        'fibonacci', 'primes', 'sha256', 'uuid', 'sleep', 'now', 'randomBytes', 'crypto',
        `"use strict"; return (${task.code})()`
      );
      result = fn(
        _stdlib.fibonacci, _stdlib.primes, _stdlib.sha256,
        _stdlib.uuid, _stdlib.sleep, _stdlib.now, _stdlib.randomBytes,
        crypto
      );

      // Handle async tasks (returned Promise)
      if (result && typeof result.then === 'function') {
        result
          .then(r  => _finishTask(task.id, r !== undefined ? String(r) : 'undefined', null, performance.now() - t0))
          .catch(e => _finishTask(task.id, null, e.message || String(e), performance.now() - t0));
        return;
      }
    } catch (e) {
      error = e.message || String(e);
    }

    _finishTask(
      task.id,
      result !== undefined ? String(result) : undefined,
      error,
      performance.now() - t0
    );
  }

  function _finishTask(taskId, result, error, duration) {
    if (tasks.has(taskId)) {
      const t    = tasks.get(taskId);
      t.status   = error ? 'error' : 'done';
      t.result   = result;
      t.error    = error;
      t.duration = duration;
    }
    bcast(T.TASK_RESULT, { taskId, result, error, duration });
    const t = tasks.get(taskId);
    if (t) emit(error ? 'task-failed' : 'task-done', { task: { ...t } });
  }

  // ── Fault Detection ───────────────────────────────────────────────────────
  setInterval(() => {
    const now = Date.now();
    for (const [id, p] of peers) {
      if (now - p.lastSeen > PEER_TTL_MS) {
        peers.delete(id);
        emit('peer-left', { peerId: id, reason: 'timeout' });
        fsmSend('PEER_LEFT');
        if (id === leaderNode) {
          leaderNode = null;
          if (myRole !== 'leader') myRole = 'candidate';
          emit('election', { phase: 'leader-timed-out', nodeId: id });
          setTimeout(startElection, Math.random() * 300);
        }
      }
    }
  }, 500);

  // ── Heartbeat ─────────────────────────────────────────────────────────────
  setInterval(() => bcast(T.HEARTBEAT, { role: myRole }), HB_INTERVAL_MS);

  // ── Bootstrap ─────────────────────────────────────────────────────────────
  bcast(T.ANNOUNCE);

  // If nobody responds, form a singleton cluster
  setTimeout(() => {
    if (peers.size === 0 && myRole === 'candidate') {
      declareVictory();
    }
  }, SOLO_WAIT_MS);

  // ── DID Integration ───────────────────────────────────────────────────────
  window.addEventListener('sovereign:identity:ready', e => {
    myDid = e.detail?.did ?? null;
    if (myDid) bcast(T.DID_ANNOUNCE, { did: myDid });
    fsmSend('IDENTITY_READY');
  });

  // ── Cleanup ───────────────────────────────────────────────────────────────
  window.addEventListener('beforeunload', () => {
    try { bcast(T.GOODBYE); } catch (_) {}
    bc.close();
  });

  // ── Public API ────────────────────────────────────────────────────────────
  window.SovereignKernel = Object.freeze({
    dispatch,
    peers:        () => new Map(peers),
    tasks:        () => new Map(tasks),
    role:         () => myRole,
    leader:       () => leaderNode,
    nodeId:       () => NODE_ID,
    joinTime:     () => JOIN_TIME,
    forceElection: startElection,
    stats: () => ({
      version:        KERNEL_VERSION,
      nodeId:         NODE_ID,
      role:           myRole,
      leader:         leaderNode,
      did:            myDid,
      peers:          peers.size,
      tasks:          tasks.size,
      tasksCompleted: [...tasks.values()].filter(t => t.status === 'done').length,
      tasksPending:   [...tasks.values()].filter(t => t.status === 'pending').length,
      tasksRunning:   [...tasks.values()].filter(t => t.status === 'running').length,
      tasksErrored:   [...tasks.values()].filter(t => t.status === 'error').length,
      channel:        CHAN_NAME,
      uptime:         Math.round((performance.timeOrigin + performance.now() - JOIN_TIME) / 1000),
    }),
  });

  console.log(`[Sovereign Kernel v${KERNEL_VERSION}] Node ${NODE_ID} online · Bully election · ${CHAN_NAME}`);

})();
