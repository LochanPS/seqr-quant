import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  KeyEncapsulation,
  Signature,
  HybridKEM,
  combineSecrets,
  KEMAlgorithm,
  SignAlgorithm,
  meta,
  available,
  backend,
  KeySizeError,
  UnsupportedAlgorithmError,
} from '../index.js';

test('backend is real and always available (no mock)', () => {
  assert.equal(available(), true);
  assert.equal(backend(), 'noble');
});

test('algorithm metadata matches the FIPS parameter sizes', () => {
  const m = meta('ML-KEM-768');
  assert.equal(m.publicKeyBytes, 1184);
  assert.equal(m.secretKeyBytes, 2400);
  assert.equal(m.outputBytes, 1088);
  assert.equal(m.nistLevel, 3);
  assert.equal(meta('ML-DSA-65').outputBytes, 3309);
  assert.throws(() => meta('RSA-2048'), UnsupportedAlgorithmError);
});

for (const alg of Object.values(KEMAlgorithm)) {
  test(`KEM round-trip: ${alg}`, () => {
    const kem = new KeyEncapsulation(alg);
    const kp = kem.generateKeypair();
    assert.equal(kp.publicKey.length, meta(alg).publicKeyBytes);
    assert.equal(kp.secretKey.length, meta(alg).secretKeyBytes);
    const { ciphertext, sharedSecret } = kem.encapsulate(kp.publicKey);
    assert.equal(ciphertext.length, meta(alg).outputBytes);
    assert.equal(sharedSecret.length, 32);
    const recovered = kem.decapsulate(kp.secretKey, ciphertext);
    assert.deepEqual(Buffer.from(recovered), Buffer.from(sharedSecret));
  });
}

test('KEM rejects a wrong-size public key', () => {
  const kem = new KeyEncapsulation('ML-KEM-768');
  assert.throws(() => kem.encapsulate(new Uint8Array(10)), KeySizeError);
});

test('KEM constructor rejects a non-KEM algorithm', () => {
  assert.throws(() => new KeyEncapsulation('ML-DSA-65'), UnsupportedAlgorithmError);
});

for (const alg of Object.values(SignAlgorithm)) {
  test(`signature round-trip + tamper: ${alg}`, () => {
    const sig = new Signature(alg);
    const kp = sig.generateKeypair();
    assert.equal(kp.publicKey.length, meta(alg).publicKeyBytes);
    const message = new TextEncoder().encode('authorize transfer');
    const signature = sig.sign(message, kp.secretKey);
    assert.equal(sig.verify(message, signature, kp.publicKey), true);
    assert.equal(sig.verify(new TextEncoder().encode('tampered'), signature, kp.publicKey), false);
  });
}

test('signature constructor rejects a non-signature algorithm', () => {
  assert.throws(() => new Signature('ML-KEM-768'), UnsupportedAlgorithmError);
});

test('hybrid KEM round-trip (X25519 + ML-KEM-768)', () => {
  const kem = new HybridKEM();
  const kp = kem.generateKeypair();
  assert.equal(kp.publicKey.length, 32 + 1184);
  assert.equal(kp.secretKey.length, 32 + 2400);
  const { ciphertext, sharedSecret } = kem.encapsulate(kp.publicKey);
  assert.equal(ciphertext.length, 32 + 1088);
  const recovered = kem.decapsulate(kp.secretKey, ciphertext);
  assert.deepEqual(Buffer.from(recovered), Buffer.from(sharedSecret));
  assert.equal(sharedSecret.length, 32);
});

test('combineSecrets matches the Python pqcmap KDF vector (cross-language interop)', () => {
  const classical = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
  const pqc = new Uint8Array(Array.from({ length: 32 }, (_, i) => 100 + i));
  const out = Buffer.from(combineSecrets(classical, pqc)).toString('hex');
  // Produced by python pqcmap.core.hybrid.combine_secrets on the same input.
  assert.equal(out, '11b9f197bb60fe68e66aeb5986a8f9df5fe9dfdf318a41f23366334429b5e4d1');
});
