import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { PQCToken, Signature } from '../index.js';
import jwt, { encode, decode, ExpiredSignatureError, InvalidSignatureError, InvalidAlgorithmError, DecodeError } from '../src/jwt.js';

const enc = new TextEncoder();

test('PQCToken round-trips claims', () => {
  const kp = new Signature('ML-DSA-65').generateKeypair();
  const token = PQCToken.encode({ sub: '123', role: 'admin' }, kp.secretKey);
  const claims = PQCToken.decode(token, kp.publicKey);
  assert.equal(claims.sub, '123');
  assert.equal(claims.role, 'admin');
});

test('PQCToken rejects the wrong key with a signature error', () => {
  const kp = new Signature('ML-DSA-65').generateKeypair();
  const other = new Signature('ML-DSA-65').generateKeypair();
  const token = PQCToken.encode({ sub: '123' }, kp.secretKey);
  assert.throws(() => PQCToken.decode(token, other.publicKey), (e) => e.name === 'PQCTokenSignatureError');
});

test('PQCToken honours exp', () => {
  const kp = new Signature('ML-DSA-65').generateKeypair();
  const expired = PQCToken.encode({ sub: '123', exp: Math.floor(Date.now() / 1000) - 10 }, kp.secretKey);
  assert.throws(() => PQCToken.decode(expired, kp.publicKey), (e) => e.name === 'PQCTokenExpiredError');
  // still decodable when exp verification is off
  assert.equal(PQCToken.decode(expired, kp.publicKey, { verifyExp: false }).sub, '123');
});

test('PyJWT-shaped surface: encode/decode + algorithms allow-list', () => {
  const kp = new Signature('ML-DSA-65').generateKeypair();
  const token = encode({ sub: 'abc' }, kp.secretKey, 'ML-DSA-65');
  const claims = decode(token, kp.publicKey, { algorithms: ['ML-DSA-65'] });
  assert.equal(claims.sub, 'abc');

  // missing allow-list -> DecodeError (PyJWT >= 2 semantics)
  assert.throws(() => decode(token, kp.publicKey, {}), DecodeError);
  // alg not allowed -> InvalidAlgorithmError
  assert.throws(() => decode(token, kp.publicKey, { algorithms: ['ML-DSA-87'] }), InvalidAlgorithmError);
});

test('PyJWT-shaped errors map correctly', () => {
  const kp = new Signature('ML-DSA-65').generateKeypair();
  const other = new Signature('ML-DSA-65').generateKeypair();
  const token = encode({ sub: 'x' }, kp.secretKey);
  assert.throws(() => decode(token, other.publicKey, { algorithms: ['ML-DSA-65'] }), InvalidSignatureError);
  const expired = encode({ sub: 'x', exp: 1 }, kp.secretKey);
  assert.throws(() => decode(expired, kp.publicKey, { algorithms: ['ML-DSA-65'] }), ExpiredSignatureError);
});

test('default export is the PyJWT-shaped bundle', () => {
  assert.equal(typeof jwt.encode, 'function');
  assert.equal(typeof jwt.decode, 'function');
  assert.equal(typeof jwt.getUnverifiedHeader, 'function');
});

test('cross-language interop: verifies a token signed by the Python pqcmap SDK', () => {
  const fixture = JSON.parse(
    readFileSync(fileURLToPath(new URL('./fixtures/py_token.json', import.meta.url)), 'utf-8'),
  );
  const publicKey = new Uint8Array(Buffer.from(fixture.publicKeyHex, 'hex'));
  const claims = PQCToken.decode(fixture.token, publicKey);
  assert.deepEqual(claims, fixture.payload);
});
