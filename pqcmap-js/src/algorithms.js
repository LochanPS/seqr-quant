/**
 * Algorithm constants + metadata for the NIST FIPS 203/204/205 PQC standards.
 *
 * Names match the FIPS strings (`ML-KEM-768`, `ML-DSA-65`, …). `ALGORITHM_META` carries
 * the FIPS reference, NIST security level, and on-the-wire sizes — a straight port of the
 * Python `pqcmap.algorithms` table (identical values), useful for MTU / storage planning
 * without touching the crypto backend.
 */
import { UnsupportedAlgorithmError } from './errors.js';

/** Key-encapsulation (KEM) algorithm names — replace RSA/ECDH key exchange. */
export const KEMAlgorithm = Object.freeze({
  ML_KEM_512: 'ML-KEM-512', // FIPS 203, NIST Level 1
  ML_KEM_768: 'ML-KEM-768', // FIPS 203, NIST Level 3 — DEFAULT
  ML_KEM_1024: 'ML-KEM-1024', // FIPS 203, NIST Level 5
});

/** Digital-signature algorithm names — replace RSA-sign and ECDSA. */
export const SignAlgorithm = Object.freeze({
  ML_DSA_44: 'ML-DSA-44', // FIPS 204, NIST Level 2
  ML_DSA_65: 'ML-DSA-65', // FIPS 204, NIST Level 3 — DEFAULT
  ML_DSA_87: 'ML-DSA-87', // FIPS 204, NIST Level 5
  SLH_DSA_SHA2_128F: 'SLH-DSA-SHA2-128f', // FIPS 205, hash-based backup
});

/** Sensible defaults — NIST Level 3, the recommended baseline for new systems. */
export const DEFAULT_KEM = KEMAlgorithm.ML_KEM_768;
export const DEFAULT_SIGN = SignAlgorithm.ML_DSA_65;

/**
 * @typedef {Object} AlgorithmMeta
 * @property {string} name
 * @property {'kem'|'sign'} kind
 * @property {string} fips        e.g. "FIPS 203"
 * @property {number} nistLevel   1..5
 * @property {number} publicKeyBytes
 * @property {number} secretKeyBytes
 * @property {number} outputBytes  ciphertext (KEM) or signature (sign) size in bytes
 */

/** Standard FIPS 203/204/205 parameter-set sizes (bytes) — identical to the Python table. */
export const ALGORITHM_META = Object.freeze({
  'ML-KEM-512': { name: 'ML-KEM-512', kind: 'kem', fips: 'FIPS 203', nistLevel: 1, publicKeyBytes: 800, secretKeyBytes: 1632, outputBytes: 768 },
  'ML-KEM-768': { name: 'ML-KEM-768', kind: 'kem', fips: 'FIPS 203', nistLevel: 3, publicKeyBytes: 1184, secretKeyBytes: 2400, outputBytes: 1088 },
  'ML-KEM-1024': { name: 'ML-KEM-1024', kind: 'kem', fips: 'FIPS 203', nistLevel: 5, publicKeyBytes: 1568, secretKeyBytes: 3168, outputBytes: 1568 },
  'ML-DSA-44': { name: 'ML-DSA-44', kind: 'sign', fips: 'FIPS 204', nistLevel: 2, publicKeyBytes: 1312, secretKeyBytes: 2560, outputBytes: 2420 },
  'ML-DSA-65': { name: 'ML-DSA-65', kind: 'sign', fips: 'FIPS 204', nistLevel: 3, publicKeyBytes: 1952, secretKeyBytes: 4032, outputBytes: 3309 },
  'ML-DSA-87': { name: 'ML-DSA-87', kind: 'sign', fips: 'FIPS 204', nistLevel: 5, publicKeyBytes: 2592, secretKeyBytes: 4896, outputBytes: 4627 },
  'SLH-DSA-SHA2-128f': { name: 'SLH-DSA-SHA2-128f', kind: 'sign', fips: 'FIPS 205', nistLevel: 1, publicKeyBytes: 32, secretKeyBytes: 64, outputBytes: 17088 },
});

export const KEM_ALGORITHMS = Object.freeze(
  Object.values(ALGORITHM_META).filter((m) => m.kind === 'kem').map((m) => m.name),
);
export const SIGN_ALGORITHMS = Object.freeze(
  Object.values(ALGORITHM_META).filter((m) => m.kind === 'sign').map((m) => m.name),
);

/**
 * Return metadata for `algorithm`, or throw {@link UnsupportedAlgorithmError}.
 * @param {string} algorithm
 * @returns {AlgorithmMeta}
 */
export function meta(algorithm) {
  const m = ALGORITHM_META[algorithm];
  if (!m) {
    throw new UnsupportedAlgorithmError(
      `Unknown algorithm ${JSON.stringify(algorithm)}. Known: ${Object.keys(ALGORITHM_META).join(', ')}.`,
    );
  }
  return m;
}

/** Umbrella namespace so `Algorithm.KEM.ML_KEM_768` works, mirroring the Python re-export. */
export const Algorithm = Object.freeze({
  KEM: KEMAlgorithm,
  Sign: SignAlgorithm,
  DEFAULT_KEM,
  DEFAULT_SIGN,
});
