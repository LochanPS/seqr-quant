/**
 * Key Encapsulation Mechanism (KEM) — the drop-in replacement for RSA/ECDH key exchange.
 * Default: ML-KEM-768 (FIPS 203, NIST Level 3). Port of Python `pqcmap.core.kem`.
 *
 *   const kem = new KeyEncapsulation();               // ML-KEM-768 by default
 *   const kp = kem.generateKeypair();
 *   const { ciphertext, sharedSecret } = kem.encapsulate(kp.publicKey);
 *   const sharedSecret2 = kem.decapsulate(kp.secretKey, ciphertext);
 *   // Buffer.from(sharedSecret).equals(Buffer.from(sharedSecret2)) === true
 *
 * Stateless/functional: keys are passed in per call rather than held on the instance, so it
 * composes cleanly with a key store and with hybrid mode.
 */
import { DEFAULT_KEM, KEM_ALGORITHMS, meta } from './algorithms.js';
import { requireBackend } from './backend.js';
import { KeySizeError, UnsupportedAlgorithmError } from './errors.js';
import { KeyPair } from './keypair.js';

export class KeyEncapsulation {
  /** @param {string} [algorithm] one of the ML-KEM names (default ML-KEM-768). */
  constructor(algorithm = DEFAULT_KEM) {
    if (!KEM_ALGORITHMS.includes(algorithm)) {
      throw new UnsupportedAlgorithmError(
        `${JSON.stringify(algorithm)} is not a KEM algorithm. Choose one of: ${[...KEM_ALGORITHMS].sort().join(', ')}.`,
      );
    }
    this.algorithm = algorithm;
    this._meta = meta(algorithm);
  }

  /** Generate a fresh keypair; the secret key never touches instance state. @returns {KeyPair} */
  generateKeypair() {
    const { publicKey, secretKey } = requireBackend().kemKeypair(this.algorithm);
    return new KeyPair(publicKey, secretKey);
  }

  /**
   * Return `{ ciphertext, sharedSecret }` for the recipient's `publicKey`.
   * Send `ciphertext` to the recipient; use `sharedSecret` (32 bytes) as an AES-256 key.
   * @param {Uint8Array} publicKey
   */
  encapsulate(publicKey) {
    this._checkLen('public key', publicKey, this._meta.publicKeyBytes);
    return requireBackend().kemEncaps(this.algorithm, publicKey);
  }

  /**
   * Recover the shared secret from `ciphertext` using your `secretKey`.
   * @param {Uint8Array} secretKey
   * @param {Uint8Array} ciphertext
   * @returns {Uint8Array}
   */
  decapsulate(secretKey, ciphertext) {
    this._checkLen('secret key', secretKey, this._meta.secretKeyBytes);
    this._checkLen('ciphertext', ciphertext, this._meta.outputBytes);
    return requireBackend().kemDecaps(this.algorithm, secretKey, ciphertext);
  }

  _checkLen(label, value, expected) {
    if (!value || value.length !== expected) {
      throw new KeySizeError(`${label} for ${this.algorithm} must be ${expected} bytes, got ${value ? value.length : 0}.`);
    }
  }
}
