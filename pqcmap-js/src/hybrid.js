/**
 * Hybrid KEM: X25519 (classical) + ML-KEM-768 (PQC), combined via HKDF-SHA256.
 * Port of Python `pqcmap.core.hybrid` — **the wire format and KDF match exactly**, so a
 * value produced here interoperates with the Python SDK (see test/core.test.js parity vector).
 *
 * Recommended for the 2026-2030 transition: if either primitive is broken, the other still
 * protects the shared secret — the same posture TLS 1.3's X25519MLKEM768 standardises.
 *
 * Wire format (concatenated, fixed offsets):
 *   publicKey  = x25519_public(32)          || mlkem768_public(1184)
 *   secretKey  = x25519_secret(32)          || mlkem768_secret(2400)
 *   ciphertext = x25519_ephemeral_public(32) || mlkem768_ciphertext(1088)
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { KEMAlgorithm } from './algorithms.js';
import { KeyEncapsulation } from './kem.js';
import { KeySizeError } from './errors.js';
import { KeyPair } from './keypair.js';

const X25519_LEN = 32;
const HKDF_SALT = new TextEncoder().encode('seqr-hybrid-v1');
const HKDF_INFO = new TextEncoder().encode('pqcmap hybrid kem X25519+ML-KEM-768');
const SHARED_SECRET_LEN = 32; // 256-bit combined secret, ready as an AES-256 key

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Derive the final 32-byte shared secret from both halves via HKDF-SHA256.
 * Order (classical then PQC) is part of the wire contract and must match on both sides.
 * Deterministic and backend-free — unit-tested directly against the Python vector.
 * @param {Uint8Array} classicalSecret
 * @param {Uint8Array} pqcSecret
 * @returns {Uint8Array}
 */
export function combineSecrets(classicalSecret, pqcSecret) {
  return hkdf(sha256, concatBytes(classicalSecret, pqcSecret), HKDF_SALT, HKDF_INFO, SHARED_SECRET_LEN);
}

export class HybridKEM {
  /** @param {string} [pqcAlgorithm] the PQC half (default ML-KEM-768). */
  constructor(pqcAlgorithm = KEMAlgorithm.ML_KEM_768) {
    this._kem = new KeyEncapsulation(pqcAlgorithm);
    this._pqcPubLen = this._kem._meta.publicKeyBytes;
    this._pqcSecLen = this._kem._meta.secretKeyBytes;
    this._pqcCtLen = this._kem._meta.outputBytes;
  }

  /** @returns {KeyPair} */
  generateKeypair() {
    const xPriv = x25519.utils.randomSecretKey();
    const xPub = x25519.getPublicKey(xPriv);
    const pqc = this._kem.generateKeypair();
    return new KeyPair(concatBytes(xPub, pqc.publicKey), concatBytes(xPriv, pqc.secretKey));
  }

  /**
   * @param {Uint8Array} publicKey
   * @returns {{ ciphertext: Uint8Array, sharedSecret: Uint8Array }}
   */
  encapsulate(publicKey) {
    const [xPeerPub, pqcPeerPub] = this._splitPublic(publicKey);

    // Classical: ephemeral X25519 ECDH against the peer's static X25519 key.
    const eph = x25519.utils.randomSecretKey();
    const ephPub = x25519.getPublicKey(eph);
    const classicalSecret = x25519.getSharedSecret(eph, xPeerPub);

    // PQC: ML-KEM encapsulation against the peer's static ML-KEM key.
    const { ciphertext: pqcCt, sharedSecret: pqcSecret } = this._kem.encapsulate(pqcPeerPub);

    const shared = combineSecrets(classicalSecret, pqcSecret);
    return { ciphertext: concatBytes(ephPub, pqcCt), sharedSecret: shared };
  }

  /**
   * @param {Uint8Array} secretKey
   * @param {Uint8Array} ciphertext
   * @returns {Uint8Array}
   */
  decapsulate(secretKey, ciphertext) {
    const [xPriv, pqcPriv] = this._splitSecret(secretKey);
    const [ephPub, pqcCt] = this._splitCiphertext(ciphertext);

    const classicalSecret = x25519.getSharedSecret(xPriv, ephPub);
    const pqcSecret = this._kem.decapsulate(pqcPriv, pqcCt);

    return combineSecrets(classicalSecret, pqcSecret);
  }

  _splitPublic(blob) {
    this._checkLen('hybrid public key', blob, X25519_LEN + this._pqcPubLen);
    return [blob.subarray(0, X25519_LEN), blob.subarray(X25519_LEN)];
  }
  _splitSecret(blob) {
    this._checkLen('hybrid secret key', blob, X25519_LEN + this._pqcSecLen);
    return [blob.subarray(0, X25519_LEN), blob.subarray(X25519_LEN)];
  }
  _splitCiphertext(blob) {
    this._checkLen('hybrid ciphertext', blob, X25519_LEN + this._pqcCtLen);
    return [blob.subarray(0, X25519_LEN), blob.subarray(X25519_LEN)];
  }
  _checkLen(label, value, expected) {
    if (!value || value.length !== expected) {
      throw new KeySizeError(`${label} must be ${expected} bytes, got ${value ? value.length : 0}.`);
    }
  }
}
