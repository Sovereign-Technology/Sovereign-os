/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SOVEREIGN SHAMIR SECRET SHARING  v1.0  —  sovereign_shamir.js
 *
 *  Real t-of-n Shamir Secret Sharing over GF(256) with Lagrange interpolation.
 *  No external dependencies. Works in browser and Service Worker contexts.
 *
 *  Referenced from genesis_sw.js EXPORT_SHAMIR / IMPORT_SHAMIR commands.
 *
 *  Algorithm:
 *    - Field: GF(2^8) with irreducible polynomial x^8+x^4+x^3+x^2+1 (0x11d)
 *    - Split: evaluate a random degree-(t-1) polynomial at n distinct x-values
 *    - Combine: Lagrange interpolation at x=0 using t shares
 *    - Share format: { x: uint8, y: Uint8Array, checksum: hex }
 *      where y[i] = polynomial(x) for byte i of the secret
 *
 *  Security properties:
 *    - Information-theoretic: <t shares reveal zero information about the secret
 *    - Any t shares reconstruct the secret exactly
 *    - Checksum (SHA-256 of reconstructed secret) catches corrupt shares
 *
 *  © James Chapman (XheCarpenXer) · iconoclastdao@gmail.com
 *  Dual License — see LICENSE.md
 * ═══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

const SovereignShamir = (() => {

  // ── GF(256) arithmetic ─────────────────────────────────────────────────────
  // Precomputed log/exp tables for the field GF(2^8) with polynomial 0x11d
  const _exp = new Uint8Array(512);
  const _log = new Uint8Array(256);

  (() => {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      _exp[i] = x;
      _log[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) {
      _exp[i] = _exp[i - 255];
    }
    _log[0] = 0; // log(0) is undefined; set to 0 as sentinel
  })();

  function _gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return _exp[_log[a] + _log[b]];
  }

  function _gfDiv(a, b) {
    if (b === 0) throw new RangeError('GF division by zero');
    if (a === 0) return 0;
    return _exp[(_log[a] - _log[b] + 255) % 255];
  }

  function _gfPow(x, n) {
    if (n === 0) return 1;
    return _exp[(_log[x] * n) % 255];
  }

  // ── Polynomial evaluation ─────────────────────────────────────────────────
  // Evaluate polynomial with given coefficients at point x over GF(256)
  // coefficients[0] is the constant term (the secret byte)
  function _polyEval(coeffs, x) {
    let result = 0;
    let xPow   = 1;
    for (let i = 0; i < coeffs.length; i++) {
      result ^= _gfMul(coeffs[i], xPow);
      xPow    = _gfMul(xPow, x);
    }
    return result;
  }

  // ── Split ─────────────────────────────────────────────────────────────────
  /**
   * Split a secret (Uint8Array) into n shares, any t of which reconstruct it.
   *
   * @param {Uint8Array} secret  — the secret bytes to split
   * @param {number}     t       — threshold (minimum shares to reconstruct)
   * @param {number}     n       — total shares to produce
   * @returns {Array<{x: number, y: Uint8Array}>}
   */
  function split(secret, t, n) {
    if (!(secret instanceof Uint8Array)) throw new TypeError('secret must be Uint8Array');
    if (t < 2 || t > n) throw new RangeError(`invalid t=${t}, n=${n}`);
    if (n > 255)         throw new RangeError('n must be ≤ 255 (GF(256) limit)');
    if (secret.length === 0) throw new RangeError('secret must be non-empty');

    const L = secret.length;
    // For each byte of the secret, build a random degree-(t-1) polynomial
    // with secret[i] as the constant term
    const coeffMatrix = new Uint8Array(L * t);
    for (let i = 0; i < L; i++) {
      coeffMatrix[i * t] = secret[i]; // constant term = secret byte
      // Random coefficients for terms 1 through t-1
      const rand = new Uint8Array(t - 1);
      crypto.getRandomValues(rand);
      for (let j = 1; j < t; j++) {
        coeffMatrix[i * t + j] = rand[j - 1];
      }
    }

    // x-values 1..n (never 0, which is the secret point)
    const shares = [];
    for (let xi = 1; xi <= n; xi++) {
      const y = new Uint8Array(L);
      for (let i = 0; i < L; i++) {
        const coeffs = coeffMatrix.subarray(i * t, i * t + t);
        y[i] = _polyEval(coeffs, xi);
      }
      shares.push({ x: xi, y });
    }

    return shares;
  }

  // ── Combine ───────────────────────────────────────────────────────────────
  /**
   * Reconstruct a secret from t or more shares using Lagrange interpolation.
   *
   * @param {Array<{x: number, y: Uint8Array}>} shares — at least t shares
   * @returns {Uint8Array} the reconstructed secret
   */
  function combine(shares) {
    if (!Array.isArray(shares) || shares.length < 2) {
      throw new RangeError('Need at least 2 shares');
    }
    const L = shares[0].y.length;
    for (const s of shares) {
      if (s.x < 1 || s.x > 255) throw new RangeError(`invalid share x=${s.x}`);
      if (!(s.y instanceof Uint8Array) || s.y.length !== L) {
        throw new TypeError('malformed share');
      }
    }

    // Check for duplicate x-values
    const xs = shares.map(s => s.x);
    if (new Set(xs).size !== xs.length) throw new RangeError('duplicate x-values in shares');

    // Lagrange interpolation at x=0 for each byte position
    const secret = new Uint8Array(L);
    for (let i = 0; i < L; i++) {
      let acc = 0;
      for (let j = 0; j < shares.length; j++) {
        // Lagrange basis polynomial l_j(0) = ∏_{k≠j} (0 - x_k) / (x_j - x_k)
        // In GF(256): subtraction = XOR = addition
        let num = 1;
        let den = 1;
        for (let k = 0; k < shares.length; k++) {
          if (k === j) continue;
          num = _gfMul(num, shares[k].x);        // 0 XOR x_k = x_k
          den = _gfMul(den, shares[j].x ^ shares[k].x);
        }
        const lagrange = _gfDiv(num, den);
        acc ^= _gfMul(shares[j].y[i], lagrange);
      }
      secret[i] = acc;
    }

    return secret;
  }

  // ── Encoding / decoding ───────────────────────────────────────────────────
  // Encode shares as base64url strings for safe transmission
  // Format: "v1:<x_hex>:<y_b64>:<checksum_16>"

  async function _sha256hex(buf) {
    const hashBuf = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  function _b64url(buf) {
    return (()=>{ const _b = new Uint8Array(buf instanceof ArrayBuffer ? buf : (buf.buffer ?? buf)); let _s=''; for(let _i=0;_i<_b.length;_i++) _s+=String.fromCharCode(_b[_i]); return btoa(_s); })()
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function _b64urlDecode(s) {
    const padded = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad    = (4 - padded.length % 4) % 4;
    const b64    = padded + '='.repeat(pad);
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  /**
   * Encode shares with a checksum of the original secret embedded.
   * @param {Uint8Array} secret   — original secret (for checksum)
   * @param {Array}      shares   — output of split()
   * @returns {Promise<string[]>} — array of encoded share strings
   */
  async function encode(secret, shares) {
    const checksum = (await _sha256hex(secret)).slice(0, 16);
    return shares.map(s =>
      `v1:${s.x.toString(16).padStart(2,'0')}:${_b64url(s.y)}:${checksum}`
    );
  }

  /**
   * Decode share strings and reconstruct the secret.
   * Verifies checksum and throws if reconstruction is corrupt.
   * @param {string[]} encodedShares
   * @returns {Promise<Uint8Array>}
   */
  async function decode(encodedShares) {
    const parsed = [];
    let expectedChecksum = null;

    for (const raw of encodedShares) {
      const parts = raw.split(':');
      if (parts.length !== 4 || parts[0] !== 'v1') {
        throw new Error('Invalid share format: expected v1:<x>:<y>:<checksum>');
      }
      const x        = parseInt(parts[1], 16);
      const y        = _b64urlDecode(parts[2]);
      const checksum = parts[3];

      if (expectedChecksum && expectedChecksum !== checksum) {
        throw new Error('Share checksum mismatch — shares are from different secrets');
      }
      expectedChecksum = checksum;
      parsed.push({ x, y });
    }

    const secret    = combine(parsed);
    const actualSum = (await _sha256hex(secret)).slice(0, 16);

    if (actualSum !== expectedChecksum) {
      throw new Error('Reconstruction failed — incorrect or corrupted shares');
    }

    return secret;
  }

  return { split, combine, encode, decode, _gfMul, _gfDiv }; // export internals for tests

})();

// Make available in both browser and SW contexts
if (typeof self !== 'undefined') self.SovereignShamir = SovereignShamir;
if (typeof window !== 'undefined') window.SovereignShamir = SovereignShamir;

// Backward-compat alias — supports both window.Shamir and window.SovereignShamir
if (typeof window !== "undefined") window.Shamir = window.Shamir || window.SovereignShamir;
if (typeof self !== "undefined") self.Shamir = self.Shamir || self.SovereignShamir;
