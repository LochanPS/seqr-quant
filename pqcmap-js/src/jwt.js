/**
 * PQC-signed JWTs — port of Python `pqcmap.jwt`.
 *
 * {@link PQCToken} is the low-level class; the module also exports a **PyJWT-shaped**
 * surface (`encode` / `decode` / `getUnverifiedHeader` and PyJWT-named errors) so a
 * codebase migrates from an RS256 JWT to ML-DSA by changing the import:
 *
 *   import * as jwt from '@seqr/pqc/jwt';           // was: import jwt from 'jsonwebtoken'
 *   const token  = jwt.encode({ sub: '123' }, secretKey, 'ML-DSA-65');
 *   const claims = jwt.decode(token, publicKey, { algorithms: ['ML-DSA-65'] });
 *
 * Wire format matches the Python SDK (compact JOSE: base64url(header).base64url(payload).
 * base64url(signature); canonical sorted-key JSON), so a token signed by one SDK verifies
 * in the other. Keys are raw ML-DSA bytes (Uint8Array), not PEM objects. This is drop-in
 * at the *code* level; the token's `alg` is ML-DSA, not RS256-wire-compatible.
 */
import { DEFAULT_SIGN, SIGN_ALGORITHMS } from './algorithms.js';
import { Signature } from './sign.js';
import { b64u, b64uToBytes, canonicalJSON } from './_encoding.js';
import {
  PQCTokenExpiredError,
  PQCTokenInvalidError,
  PQCTokenSignatureError,
} from './errors.js';

const TYP = 'PQC-JWT';
const enc = new TextEncoder();

export class PQCToken {
  /**
   * Sign `payload` and return a compact token string.
   * @param {object} payload
   * @param {Uint8Array} secretKey
   * @param {string} [algorithm]
   * @param {object|null} [headers] extra JOSE headers (`alg`/`typ` are set by pqcmap and win)
   * @returns {string}
   */
  static encode(payload, secretKey, algorithm = DEFAULT_SIGN, headers = null) {
    const header = { ...(headers || {}), alg: algorithm, typ: TYP };
    const signingInput = `${b64u(enc.encode(canonicalJSON(header)))}.${b64u(enc.encode(canonicalJSON(payload)))}`;
    const signature = new Signature(algorithm).sign(enc.encode(signingInput), secretKey);
    return `${signingInput}.${b64u(signature)}`;
  }

  /**
   * Verify `token` against `publicKey` and return its claims.
   * @param {string} token
   * @param {Uint8Array} publicKey
   * @param {{ verifyExp?: boolean, leeway?: number }} [opts]
   * @returns {object}
   */
  static decode(token, publicKey, { verifyExp = true, leeway = 0 } = {}) {
    const parts = String(token).split('.');
    if (parts.length !== 3) throw new PQCTokenInvalidError('Token must have three dot-separated segments.');
    const [headerB64, payloadB64, sigB64] = parts;

    let header, payload, signature;
    try {
      header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf-8'));
      payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
      signature = b64uToBytes(sigB64);
    } catch (e) {
      throw new PQCTokenInvalidError(`Malformed token: ${e.message}`);
    }

    const algorithm = header.alg;
    if (!SIGN_ALGORITHMS.includes(algorithm)) {
      throw new PQCTokenInvalidError(`Unsupported token alg ${JSON.stringify(algorithm)}.`);
    }

    const signingInput = enc.encode(`${headerB64}.${payloadB64}`);
    let ok;
    try {
      ok = new Signature(algorithm).verify(signingInput, signature, publicKey);
    } catch (e) {
      throw new PQCTokenInvalidError(`Could not verify token: ${e.message}`);
    }
    if (!ok) throw new PQCTokenSignatureError('Signature verification failed.');

    if (verifyExp && Object.prototype.hasOwnProperty.call(payload, 'exp')) {
      const exp = Number(payload.exp);
      if (!Number.isFinite(exp)) throw new PQCTokenInvalidError("Invalid 'exp' claim.");
      if (Date.now() / 1000 > exp + leeway) throw new PQCTokenExpiredError('Token has expired.');
    }
    return payload;
  }

  /** Read the JOSE header WITHOUT verifying (as PyJWT's `get_unverified_header`). */
  static getUnverifiedHeader(token) {
    const parts = String(token).split('.');
    if (parts.length !== 3) throw new PQCTokenInvalidError('Token must have three dot-separated segments.');
    try {
      return JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf-8'));
    } catch (e) {
      throw new PQCTokenInvalidError(`Malformed token header: ${e.message}`);
    }
  }
}

// --- PyJWT-shaped surface + PyJWT-named errors -------------------------------

/** A token's `exp` has passed. */
export class ExpiredSignatureError extends PQCTokenExpiredError {}
/** A token's signature did not verify. */
export class InvalidSignatureError extends PQCTokenSignatureError {}
/** A token is malformed / undecodable. */
export class DecodeError extends PQCTokenInvalidError {}
/** The token's `alg` is not in the caller's allow-list. */
export class InvalidAlgorithmError extends PQCTokenInvalidError {}

/**
 * PyJWT-shaped `encode(payload, key, algorithm?, headers?)`.
 * @returns {string}
 */
export function encode(payload, key, algorithm = DEFAULT_SIGN, headers = null) {
  return PQCToken.encode(payload, key, algorithm, headers);
}

/**
 * PyJWT-shaped `decode(token, key, { algorithms, verifyExp?, leeway? })`. The `algorithms`
 * allow-list is REQUIRED (as in PyJWT >= 2) and maps failures to PyJWT-named errors.
 * @param {string} token
 * @param {Uint8Array} key
 * @param {{ algorithms: string[], verifyExp?: boolean, leeway?: number }} opts
 * @returns {object}
 */
export function decode(token, key, opts = {}) {
  const { algorithms, verifyExp = true, leeway = 0 } = opts;
  if (!Array.isArray(algorithms) || algorithms.length === 0) {
    throw new DecodeError("decode() requires a non-empty 'algorithms' allow-list.");
  }
  let header;
  try {
    header = PQCToken.getUnverifiedHeader(token);
  } catch (e) {
    throw new DecodeError(e.message);
  }
  if (!algorithms.includes(header.alg)) {
    throw new InvalidAlgorithmError(`Token alg ${JSON.stringify(header.alg)} not in allowed ${JSON.stringify(algorithms)}.`);
  }
  try {
    return PQCToken.decode(token, key, { verifyExp, leeway });
  } catch (e) {
    if (e instanceof PQCTokenExpiredError) throw new ExpiredSignatureError(e.message);
    if (e instanceof PQCTokenSignatureError) throw new InvalidSignatureError(e.message);
    if (e instanceof PQCTokenInvalidError) throw new DecodeError(e.message);
    throw e;
  }
}

/** PyJWT-shaped `get_unverified_header`. */
export function getUnverifiedHeader(token) {
  return PQCToken.getUnverifiedHeader(token);
}

/** Default export bundles the PyJWT-shaped surface, so `import jwt from '@seqr/pqc/jwt'` works. */
export default {
  encode,
  decode,
  getUnverifiedHeader,
  PQCToken,
  ExpiredSignatureError,
  InvalidSignatureError,
  DecodeError,
  InvalidAlgorithmError,
};
