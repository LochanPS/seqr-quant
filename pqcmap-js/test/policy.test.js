import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  assertCompliant,
  isCompliant,
  violations,
  requiresPqc,
  setActivePolicy,
  CryptoPolicy,
  PolicyViolationError,
  compliant,
} from '../index.js';

test('default policy: allows ML-KEM-768 / ML-DSA-65', () => {
  assert.doesNotThrow(() => assertCompliant('ML-KEM-768', { kind: 'kem' }));
  assert.doesNotThrow(() => assertCompliant('ML-DSA-65', { kind: 'sign' }));
  assert.equal(isCompliant('ML-KEM-768', { kind: 'kem' }), true);
});

test('default policy: forbids quantum-vulnerable families', () => {
  assert.throws(() => assertCompliant('RSA-2048'), PolicyViolationError);
  assert.throws(() => assertCompliant('ECDSA-P256'), PolicyViolationError);
  const vs = violations('RSA-2048');
  assert.ok(vs.length >= 1);
  assert.equal(vs[0].severity, 'immediate');
});

test('default policy: rejects below NIST Level 3 PQC', () => {
  assert.throws(() => assertCompliant('ML-KEM-512', { kind: 'kem' }), PolicyViolationError);
  assert.throws(() => assertCompliant('ML-DSA-44', { kind: 'sign' }), PolicyViolationError);
});

test('PolicyViolationError carries algorithm + violations', () => {
  try {
    assertCompliant('RSA-2048');
    assert.fail('expected throw');
  } catch (e) {
    assert.ok(e instanceof PolicyViolationError);
    assert.equal(e.algorithm, 'RSA-2048');
    assert.ok(Array.isArray(e.violations) && e.violations.length >= 1);
  }
});

test('policy-checked constructors refuse below-policy algorithms', () => {
  assert.doesNotThrow(() => new compliant.KeyEncapsulation());
  assert.throws(() => new compliant.KeyEncapsulation('ML-KEM-512'), PolicyViolationError);
  assert.doesNotThrow(() => new compliant.Signature());
  assert.throws(() => new compliant.Signature('ML-DSA-44'), PolicyViolationError);
});

test('requiresPqc guards a key-minting function', () => {
  const mint = requiresPqc((alg = 'ML-KEM-768') => `minted:${alg}`, { kind: 'kem' });
  assert.equal(mint('ML-KEM-768'), 'minted:ML-KEM-768');
  assert.throws(() => mint('ML-KEM-512'), PolicyViolationError);
});

test('custom policy body (spine shape) loads and enforces', () => {
  const body = {
    name: 'strict L5',
    rules: [{ key: 'l5', type: 'min_nist_level', min: 5, severity: 'urgent', target: 'Level 5' }],
  };
  const policy = CryptoPolicy.fromBody(body);
  assert.throws(() => assertCompliant('ML-KEM-768', { kind: 'kem', policy }), PolicyViolationError);
  assert.doesNotThrow(() => assertCompliant('ML-KEM-1024', { kind: 'kem', policy }));
});

test('setActivePolicy swaps the process-wide policy, null resets to default', () => {
  try {
    setActivePolicy({ name: 'allow-all', rules: [] });
    assert.equal(isCompliant('RSA-2048'), true); // no rules => nothing forbidden
  } finally {
    setActivePolicy(null);
  }
  assert.equal(isCompliant('RSA-2048'), false); // default restored
});
