/**
 * @seqr/pqc — post-quantum cryptography for JavaScript/TypeScript developers.
 *
 * Drop-in NIST PQC (ML-KEM / ML-DSA) primitives that replace RSA / ECDH / ECDSA in
 * application code. The npm port of the Python `pqcmap` SDK — same public API shape and
 * the same real-backend + policy model. Crypto is genuine FIPS 203/204/205 via the
 * audited, pure-JS `@noble/post-quantum`; there is no mock in the product path.
 *
 *   import { KeyEncapsulation, Signature, HybridKEM, PQCToken } from '@seqr/pqc';
 */
export { KeyEncapsulation } from './src/kem.js';
export { Signature } from './src/sign.js';
export { HybridKEM, combineSecrets } from './src/hybrid.js';
export { KeyPair } from './src/keypair.js';
export { PQCToken } from './src/jwt.js';
export {
  Algorithm,
  KEMAlgorithm,
  SignAlgorithm,
  DEFAULT_KEM,
  DEFAULT_SIGN,
  ALGORITHM_META,
  KEM_ALGORITHMS,
  SIGN_ALGORITHMS,
  meta,
} from './src/algorithms.js';
export {
  CryptoPolicy,
  assertCompliant,
  isCompliant,
  violations,
  requiresPqc,
  loadPolicy,
  getActivePolicy,
  setActivePolicy,
  familyOf,
  resolve,
  DEFAULT_POLICY_BODY,
} from './src/policy.js';
export * as compliant from './src/compliant.js';
export { LocalKeyStore, RotationPolicy } from './src/kms/local.js';
export { HostedKMS } from './src/kms/hosted.js';
export * as tls from './src/tls.js';
export {
  PQCError,
  PQCUnavailableError,
  UnsupportedAlgorithmError,
  KeySizeError,
  SignatureVerificationError,
  PolicyViolationError,
  PQCTokenExpiredError,
  PQCTokenInvalidError,
  PQCTokenSignatureError,
  KMSError,
  KMSKeyNotFoundError,
  KMSAuthError,
} from './src/errors.js';

export { available, backendName as backend } from './src/backend.js';

export const version = '0.2.0';
