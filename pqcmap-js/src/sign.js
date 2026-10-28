/**
 * Digital signatures — the drop-in replacement for RSA-sign and ECDSA.
 * Default: ML-DSA-65 (FIPS 204, NIST Level 3). Port of Python `pqcmap.core.sign`.
 *
 *   const sig = new Signature();                       // ML-DSA-65 by default
 *   const kp = sig.generateKeypair();
 *   const signature = sig.sign(message, kp.secretKey);
 *   sig.verify(message, signature, kp.publicKey);      // -> boolean
 *
 * Stateless: keys are passed in per call, so a key from a store can be used directly.
 */
import { DEFAULT_SIGN, SIGN_ALGORITHMS, meta } from './algorithms.js';
import { requireBackend } from './backend.js';
import { KeySizeError, UnsupportedAlgorithmError } from './errors.js';
import { KeyPair } from './keypair.js';

export class Signature {
  /** @param {string} [algorithm] one of the ML-DSA / SLH-DSA names (default ML-DSA-65). */
  constructor(algorithm = DEFAULT_SIGN) {
    if (!SIGN_ALGORITHMS.includes(algorithm)) {
      throw new UnsupportedAlgorithmError(
        `${JSON.stringify(algorithm)} is not a signature algorithm. Choose one of: ${[...SIGN_ALGORITHMS].sort().join(', ')}.`,
      );
    }
    this.algorithm = algorithm;
    this._meta = meta(algorithm);
  }

  /** @returns {KeyPair} */
  generateKeypair() {
    const { publicKey, secretKey } = requireBackend().signKeypair(this.algorithm);
    return new KeyPair(publicKey, secretKey);
  }

  /**
   * Sign `message` with `secretKey`, returning raw signature bytes.
   * @param {Uint8Array} message
   * @param {Uint8Array} secretKey
   * @returns {Uint8Array}
   */
  sign(message, secretKey) {
    this._checkLen('secret key', secretKey, this._meta.secretKeyBytes);
    return requireBackend().sign(this.algorithm, secretKey, message);
  }

  /**
   * Return true iff `signature` is a valid signature of `message`. Returns `false`
   * (never throws) on a bad signature, so callers branch on the boolean.
   * @param {Uint8Array} message
   * @param {Uint8Array} signature
   * @param {Uint8Array} publicKey
   * @returns {boolean}
   */
  verify(message, signature, publicKey) {
    this._checkLen('public key', publicKey, this._meta.publicKeyBytes);
    return requireBackend().verify(this.algorithm, publicKey, signature, message);
  }

  _checkLen(label, value, expected) {
    if (!value || value.length !== expected) {
      throw new KeySizeError(`${label} for ${this.algorithm} must be ${expected} bytes, got ${value ? value.length : 0}.`);
    }
  }
}
