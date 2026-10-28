import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  LocalKeyStore,
  RotationPolicy,
  HostedKMS,
  Signature,
  KMSAuthError,
  KMSKeyNotFoundError,
  KMSError,
} from '../index.js';

function tmpStore() {
  const p = path.join(os.tmpdir(), `pqcmap-js-ks-${crypto.randomBytes(6).toString('hex')}.enc`);
  const cleanup = () => {
    for (const f of [p, p + '.audit.log', p + '.tmp']) if (fs.existsSync(f)) fs.unlinkSync(f);
  };
  return { p, cleanup };
}

test('LocalKeyStore: generate, sign with stored key, verify', () => {
  const { p, cleanup } = tmpStore();
  try {
    const ks = new LocalKeyStore('secret', p);
    const kid = ks.generateAndStore('ML-DSA-65', { purpose: 'jwt' });
    const sig = new Signature('ML-DSA-65');
    const msg = new TextEncoder().encode('hello');
    const signature = sig.sign(msg, ks.getPrivateKey(kid));
    assert.equal(sig.verify(msg, signature, ks.getPublicKey(kid)), true);
    assert.equal(ks.getMetadata(kid).uses, 1); // getPrivateKey counted a use
  } finally {
    cleanup();
  }
});

test('LocalKeyStore: persists across reopen, wrong passphrase throws', () => {
  const { p, cleanup } = tmpStore();
  try {
    const ks = new LocalKeyStore('right', p);
    const kid = ks.generateAndStore('ML-KEM-768');
    const pub = Buffer.from(ks.getPublicKey(kid)).toString('hex');

    const reopened = new LocalKeyStore('right', p);
    assert.equal(Buffer.from(reopened.getPublicKey(kid)).toString('hex'), pub);

    assert.throws(() => new LocalKeyStore('wrong', p), KMSAuthError);
  } finally {
    cleanup();
  }
});

test('LocalKeyStore: rotation policy by uses', () => {
  const { p, cleanup } = tmpStore();
  try {
    const ks = new LocalKeyStore('secret', p, { rotationPolicy: new RotationPolicy({ maxUses: 2 }) });
    const kid = ks.generateAndStore('ML-DSA-65');
    ks.getPrivateKey(kid);
    assert.equal(ks.needsRotation(kid), false);
    ks.getPrivateKey(kid); // second use hits the limit
    assert.equal(ks.needsRotation(kid), true);
    const newId = ks.rotateIfNeeded(kid);
    assert.ok(newId && newId !== kid);
    assert.equal(ks.getMetadata(kid).status, 'rotated');
    assert.equal(ks.getMetadata(kid).rotated_to, newId);
  } finally {
    cleanup();
  }
});

test('LocalKeyStore: export/import a single key with an independent passphrase', () => {
  const a = tmpStore();
  const b = tmpStore();
  try {
    const ks = new LocalKeyStore('store-a-pass', a.p);
    const kid = ks.generateAndStore('ML-DSA-65');
    const pub = Buffer.from(ks.getPublicKey(kid)).toString('hex');
    const blob = ks.exportKey(kid, 'transfer-pass');

    const other = new LocalKeyStore('store-b-pass', b.p);
    const importedId = other.importKey(blob, 'transfer-pass');
    assert.equal(Buffer.from(other.getPublicKey(importedId)).toString('hex'), pub);

    assert.throws(() => other.importKey(blob, 'wrong'), KMSAuthError);
  } finally {
    a.cleanup();
    b.cleanup();
  }
});

test('LocalKeyStore: audit log is hash-chained and tamper-evident', () => {
  const { p, cleanup } = tmpStore();
  try {
    const ks = new LocalKeyStore('secret', p);
    ks.generateAndStore('ML-DSA-65');
    assert.equal(ks.verifyAuditLog(), true);
    assert.ok(ks.readAuditLog().length >= 1);

    // tamper: rewrite an op field
    const lines = fs.readFileSync(p + '.audit.log', 'utf-8').trim().split('\n');
    const first = JSON.parse(lines[0]);
    first.op = 'forged';
    lines[0] = JSON.stringify(first);
    fs.writeFileSync(p + '.audit.log', lines.join('\n') + '\n');

    const reopened = new LocalKeyStore('secret', p);
    assert.throws(() => reopened.verifyAuditLog(), KMSError);
  } finally {
    cleanup();
  }
});

test('LocalKeyStore: unknown key id throws KMSKeyNotFoundError', () => {
  const { p, cleanup } = tmpStore();
  try {
    const ks = new LocalKeyStore('secret', p);
    assert.throws(() => ks.getPublicKey('key_nope'), KMSKeyNotFoundError);
  } finally {
    cleanup();
  }
});

// --- HostedKMS with an in-memory mock transport ------------------------------

function mockKmsTransport(masterKey, { apiKey = 'sq_live_test' } = {}) {
  const aesWrap = (nonce, pt) => {
    const c = crypto.createCipheriv('aes-256-gcm', masterKey, nonce);
    return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  };
  const aesUnwrap = (nonce, blob) => {
    const body = blob.subarray(0, blob.length - 16);
    const tag = blob.subarray(blob.length - 16);
    const d = crypto.createDecipheriv('aes-256-gcm', masterKey, nonce);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(body), d.final()]);
  };
  const b64u = (b) => Buffer.from(b).toString('base64url');
  const fromB64u = (s) => Buffer.from(s, 'base64url');

  return async (method, url, headers, body) => {
    const json = (status, obj) => ({ status, body: Buffer.from(JSON.stringify(obj)) });
    if (headers.Authorization !== `Bearer ${apiKey}`) return json(401, { error: 'bad key' });
    const u = new URL(url);
    if (method === 'GET' && u.pathname === '/v1/health') return json(200, { status: 'ok' });
    if (method === 'POST' && u.pathname.endsWith('/data-key')) {
      const mkid = u.pathname.split('/')[3];
      const dk = crypto.randomBytes(32);
      const nonce = crypto.randomBytes(12);
      // wrapped = nonce || aesgcm(masterKey, nonce, dk)
      const wrapped = Buffer.concat([nonce, aesWrap(nonce, dk)]);
      return json(200, { plaintext: b64u(dk), ciphertext: b64u(wrapped), master_key_id: mkid });
    }
    if (method === 'POST' && u.pathname === '/v1/decrypt') {
      const payload = JSON.parse(body.toString('utf-8'));
      const wrapped = fromB64u(payload.ciphertext);
      const nonce = wrapped.subarray(0, 12);
      const dk = aesUnwrap(nonce, wrapped.subarray(12));
      return json(200, { plaintext: b64u(dk) });
    }
    return json(404, { error: 'not found' });
  };
}

test('HostedKMS: envelope encrypt/decrypt round-trip through a mock KMS', async () => {
  const masterKey = crypto.randomBytes(32);
  const kms = new HostedKMS({
    endpoint: 'https://kms.example',
    apiKey: 'sq_live_test',
    transport: mockKmsTransport(masterKey),
  });
  const secret = Buffer.from('card number 4111 1111 1111 1111');
  const blob = await kms.encrypt(secret, { masterKeyId: 'mk-prod-1' });
  const recovered = await kms.decrypt(blob);
  assert.ok(recovered.equals(secret));
  assert.deepEqual(await kms.health(), { status: 'ok' });
});

test('HostedKMS: bad API key maps to KMSAuthError', async () => {
  const kms = new HostedKMS({
    endpoint: 'https://kms.example',
    apiKey: 'sq_live_wrong',
    transport: mockKmsTransport(crypto.randomBytes(32), { apiKey: 'sq_live_right' }),
  });
  await assert.rejects(() => kms.encrypt(Buffer.from('x'), { masterKeyId: 'mk' }), KMSAuthError);
});

test('HostedKMS: constructor validates endpoint + api key', () => {
  assert.throws(() => new HostedKMS({ endpoint: '', apiKey: 'k' }), KMSError);
  assert.throws(() => new HostedKMS({ endpoint: 'https://x', apiKey: '' }), KMSAuthError);
});
