/**
 * Crypto backend — real NIST PQC via the audited, pure-JS
 * [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) library
 * (ML-KEM / FIPS 203, ML-DSA / FIPS 204, SLH-DSA / FIPS 205).
 *
 * Like the Python SDK, there is **no mock in the product path**: every KEM / signature
 * operation runs genuine FIPS crypto. noble is pure JavaScript, so it works everywhere
 * Node runs (and in browsers/bundlers) with no native build step. `available()` is
 * therefore always true and {@link backendName} is `"noble"`. (A native liboqs binding
 * could be added later as a faster optional backend, mirroring the Python design.)
 */
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128f } from '@noble/post-quantum/slh-dsa.js';

import { PQCUnavailableError, UnsupportedAlgorithmError } from './errors.js';

const KEM_IMPL = {
  'ML-KEM-512': ml_kem512,
  'ML-KEM-768': ml_kem768,
  'ML-KEM-1024': ml_kem1024,
};

const SIGN_IMPL = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87,
  'SLH-DSA-SHA2-128f': slh_dsa_sha2_128f,
};

function kemImpl(alg) {
  const impl = KEM_IMPL[alg];
  if (!impl) throw new UnsupportedAlgorithmError(`${JSON.stringify(alg)} is not a supported KEM algorithm.`);
  return impl;
}

function signImpl(alg) {
  const impl = SIGN_IMPL[alg];
  if (!impl) throw new UnsupportedAlgorithmError(`${JSON.stringify(alg)} is not a supported signature algorithm.`);
  return impl;
}

/** Adapter the wrappers call, so they never touch a specific library directly. */
export const backend = {
  name: 'noble',

  kemKeypair(alg) {
    const { publicKey, secretKey } = kemImpl(alg).keygen();
    return { publicKey, secretKey };
  },
  kemEncaps(alg, publicKey) {
    const { cipherText, sharedSecret } = kemImpl(alg).encapsulate(publicKey);
    return { ciphertext: cipherText, sharedSecret };
  },
  kemDecaps(alg, secretKey, ciphertext) {
    return kemImpl(alg).decapsulate(ciphertext, secretKey);
  },

  signKeypair(alg) {
    const { publicKey, secretKey } = signImpl(alg).keygen();
    return { publicKey, secretKey };
  },
  sign(alg, secretKey, message) {
    // noble's sign is (msg, secretKey); pqcmap's public API is (message, secretKey).
    return signImpl(alg).sign(message, secretKey);
  },
  verify(alg, publicKey, signature, message) {
    return signImpl(alg).verify(signature, message, publicKey);
  },
};

/** Return the active backend (always present — noble is a hard dependency). */
export function getBackend() {
  return backend;
}

/** Return the active backend or throw {@link PQCUnavailableError}. */
export function requireBackend() {
  const b = getBackend();
  if (!b) throw new PQCUnavailableError('No PQC backend available.');
  return b;
}

/** True iff a real PQC backend is usable — effectively always. */
export function available() {
  return getBackend() !== undefined;
}

/** Name of the active backend: `"noble"`. */
export function backendName() {
  return getBackend()?.name;
}
