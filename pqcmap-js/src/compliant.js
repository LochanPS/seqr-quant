/**
 * Policy-checked drop-in primitives — port of Python `pqcmap.compliant`.
 *
 * Same API as {@link module:src/kem.KeyEncapsulation} / {@link module:src/sign.Signature},
 * but the algorithm is validated against the active crypto policy **at construction**,
 * before any key is minted — a below-policy algorithm throws `PolicyViolationError`.
 *
 *   import { compliant } from '@seqr/pqc';
 *   new compliant.KeyEncapsulation();              // ML-KEM-768 — allowed
 *   new compliant.KeyEncapsulation('ML-KEM-512');  // throws (below NIST Level 3)
 */
import { DEFAULT_KEM, DEFAULT_SIGN } from './algorithms.js';
import { KeyEncapsulation as BaseKEM } from './kem.js';
import { Signature as BaseSignature } from './sign.js';
import { assertCompliant } from './policy.js';

/** {@link BaseKEM} that refuses a below-policy algorithm at construction. */
export class KeyEncapsulation extends BaseKEM {
  /** @param {string} [algorithm] @param {{ policy?: any }} [opts] */
  constructor(algorithm = DEFAULT_KEM, { policy } = {}) {
    assertCompliant(algorithm, { kind: 'kem', policy });
    super(algorithm);
  }
}

/** {@link BaseSignature} that refuses a below-policy algorithm at construction. */
export class Signature extends BaseSignature {
  /** @param {string} [algorithm] @param {{ policy?: any }} [opts] */
  constructor(algorithm = DEFAULT_SIGN, { policy } = {}) {
    assertCompliant(algorithm, { kind: 'sign', policy });
    super(algorithm);
  }
}
