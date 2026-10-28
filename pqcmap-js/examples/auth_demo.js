#!/usr/bin/env node
/**
 * Minimal ML-DSA JWT auth demo: a LocalKeyStore holds the signing key, login mints a
 * token, a "protected route" verifies it. Framework-agnostic — the same two calls drop
 * into Express/Fastify/Koa. Run: `node examples/auth_demo.js`
 */
import os from 'node:os';
import path from 'node:path';

import jwt from '../src/jwt.js'; // PyJWT-shaped
import { LocalKeyStore } from '../index.js';

const ALG = 'ML-DSA-65';
const store = path.join(os.tmpdir(), 'pqcmap-auth-demo.enc');
const ks = new LocalKeyStore('demo-passphrase', store);
const keyId = ks.generateAndStore(ALG, { purpose: 'session-jwt' });

// --- login: issue a token ---
function login(username) {
  const payload = { sub: username, role: 'admin', iat: Math.floor(Date.now() / 1000) };
  return jwt.encode(payload, ks.getPrivateKey(keyId), ALG);
}

// --- protected route: verify a token ---
function requireAuth(token) {
  return jwt.decode(token, ks.getPublicKey(keyId), { algorithms: [ALG] });
}

const token = login('alice');
console.log('issued token:', token.slice(0, 48) + '…');
console.log('verified claims:', requireAuth(token));

try {
  requireAuth(token.slice(0, -4) + 'AAAA'); // tamper the signature
} catch (e) {
  console.log('tampered token rejected:', e.name);
}
