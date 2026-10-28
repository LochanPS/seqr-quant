/**
 * Encrypted local key store — AES-256-GCM at rest, key derived from a passphrase.
 * Port of Python `pqcmap.kms.local`, with the same on-disk format (interoperable stores).
 *
 *   const ks = new LocalKeyStore('my-secret');
 *   const keyId = ks.generateAndStore('ML-DSA-65', { purpose: 'jwt' });
 *   const pub = ks.getPublicKey(keyId);
 *   const priv = ks.getPrivateKey(keyId);          // counts as one "use"
 *   const newId = ks.rotate(keyId);                 // new keypair; old marked "rotated"
 *
 * On-disk layout (default ~/.seqr/keys.enc):
 *   salt(16) || nonce(12) || AES-256-GCM(ciphertext || tag)
 * Plaintext is a JSON document; the master key is PBKDF2-HMAC-SHA256(passphrase, salt,
 * 100000, 32). A wrong passphrase surfaces as KMSAuthError (GCM tag mismatch).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { ALGORITHM_META, KEM_ALGORITHMS, SIGN_ALGORITHMS } from '../algorithms.js';
import { KeyEncapsulation } from '../kem.js';
import { Signature } from '../sign.js';
import { b64u, b64uToBytes, canonicalJSON } from '../_encoding.js';
import { KMSAuthError, KMSError, KMSKeyNotFoundError, UnsupportedAlgorithmError } from '../errors.js';

const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const PBKDF2_ITERATIONS = 100_000;
const MASTER_KEY_LEN = 32; // AES-256
const SCHEMA_VERSION = 2;
const EXPORT_MAGIC = Buffer.from('PQCKEXP1');
const AUDIT_GENESIS = '0'.repeat(64);

const DEFAULT_STORE_PATH = path.join(os.homedir(), '.seqr', 'keys.enc');

function now() {
  return new Date().toISOString();
}

function derive(passphrase, salt) {
  return crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, MASTER_KEY_LEN, 'sha256');
}

/** AES-256-GCM encrypt → ciphertext||tag (matches Python cryptography's AESGCM output). */
function aesEncrypt(key, nonce, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

function aesDecrypt(key, nonce, blob) {
  if (blob.length < TAG_LEN) throw new KMSError('Ciphertext too short.');
  const body = blob.subarray(0, blob.length - TAG_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

function auditHash(prev, entry) {
  const material = {
    seq: entry.seq, ts: entry.ts, op: entry.op,
    key_id: entry.key_id, algorithm: entry.algorithm, detail: entry.detail,
  };
  return crypto.createHash('sha256').update(prev + canonicalJSON(material)).digest('hex');
}

/** When a key should be rotated. `null` disables that dimension. */
export class RotationPolicy {
  constructor({ maxAgeDays = null, maxUses = null } = {}) {
    this.maxAgeDays = maxAgeDays;
    this.maxUses = maxUses;
  }
  toDict() {
    return { max_age_days: this.maxAgeDays, max_uses: this.maxUses };
  }
  static fromDict(d) {
    d = d || {};
    return new RotationPolicy({ maxAgeDays: d.max_age_days ?? null, maxUses: d.max_uses ?? null });
  }
}

export class LocalKeyStore {
  /**
   * @param {string} passphrase
   * @param {string} [storePath]
   * @param {{ rotationPolicy?: RotationPolicy, audit?: boolean }} [opts]
   */
  constructor(passphrase, storePath = null, { rotationPolicy = null, audit = true } = {}) {
    if (!passphrase) throw new KMSAuthError('A non-empty passphrase is required.');
    this._passphrase = Buffer.from(passphrase, 'utf-8');
    this.path = storePath ? String(storePath) : DEFAULT_STORE_PATH;
    this.auditPath = this.path + '.audit.log';
    this._auditEnabled = audit;
    this._records = {};
    this._policy = rotationPolicy || new RotationPolicy();

    if (fs.existsSync(this.path)) {
      this._load();
      if (rotationPolicy !== null) {
        this._policy = rotationPolicy;
        this._save();
      }
    } else {
      this._salt = crypto.randomBytes(SALT_LEN);
      if (rotationPolicy !== null) this._save();
    }
    this._lastAuditHash = this._readLastAuditHash();
  }

  get rotationPolicy() {
    return this._policy;
  }
  setRotationPolicy(policy) {
    this._policy = policy;
    this._save();
  }

  /** Store an existing keypair (raw bytes); return its generated key id. */
  store(algorithm, publicKey, secretKey, metadata = null) {
    if (!ALGORITHM_META[algorithm]) throw new UnsupportedAlgorithmError(`Unknown algorithm ${JSON.stringify(algorithm)}.`);
    const keyId = 'key_' + crypto.randomBytes(8).toString('hex');
    this._records[keyId] = {
      algorithm,
      public_key: b64u(publicKey),
      secret_key: b64u(secretKey),
      metadata: metadata || {},
      created_at: now(),
      status: 'active',
      rotated_to: null,
      uses: 0,
      last_used_at: null,
    };
    this._save();
    this._audit('store', keyId, algorithm);
    return keyId;
  }

  /** Generate a fresh keypair for `algorithm` and store it. */
  generateAndStore(algorithm, metadata = null) {
    const kp = this._generate(algorithm);
    const keyId = this.store(algorithm, kp.publicKey, kp.secretKey, metadata);
    this._audit('generate', keyId, algorithm);
    return keyId;
  }

  getPublicKey(keyId) {
    return b64uToBytes(this._record(keyId).public_key);
  }

  /** Return the secret key. Counts as one "use" unless `recordUse` is false. */
  getPrivateKey(keyId, { recordUse = true } = {}) {
    const rec = this._record(keyId);
    if (recordUse) {
      rec.uses = (rec.uses | 0) + 1;
      rec.last_used_at = now();
      this._save();
      this._audit('access', keyId, rec.algorithm, { uses: rec.uses });
    }
    return b64uToBytes(rec.secret_key);
  }

  getMetadata(keyId) {
    const rec = this._record(keyId);
    return {
      algorithm: rec.algorithm,
      metadata: rec.metadata,
      created_at: rec.created_at,
      status: rec.status,
      rotated_to: rec.rotated_to,
      uses: rec.uses | 0,
      last_used_at: rec.last_used_at,
    };
  }

  /** Generate a new keypair (same algorithm), mark the old one rotated; return new id. */
  rotate(keyId) {
    const rec = this._record(keyId);
    const newId = this.generateAndStore(rec.algorithm, rec.metadata);
    rec.status = 'rotated';
    rec.rotated_to = newId;
    this._save();
    this._audit('rotate', keyId, rec.algorithm, { rotated_to: newId });
    return newId;
  }

  needsRotation(keyId, policy = null) {
    const rec = this._record(keyId);
    if (rec.status !== 'active') return false;
    const pol = policy || this._policy;
    if (pol.maxUses != null && (rec.uses | 0) >= pol.maxUses) return true;
    if (pol.maxAgeDays != null) {
      const ageDays = (Date.now() - Date.parse(rec.created_at)) / 86_400_000;
      if (ageDays >= pol.maxAgeDays) return true;
    }
    return false;
  }

  rotateIfNeeded(keyId, policy = null) {
    return this.needsRotation(keyId, policy) ? this.rotate(keyId) : null;
  }

  listKeys() {
    return Object.keys(this._records).map((kid) => ({ key_id: kid, ...this.getMetadata(kid) }));
  }

  // -- export / import --------------------------------------------------------

  /** Export a single key as a portable, passphrase-encrypted blob (Uint8Array). */
  exportKey(keyId, passphrase) {
    if (!passphrase) throw new KMSAuthError('A non-empty export passphrase is required.');
    const rec = this._record(keyId);
    const doc = Buffer.from(JSON.stringify({ key_id: keyId, record: rec }), 'utf-8');
    const salt = crypto.randomBytes(SALT_LEN);
    const nonce = crypto.randomBytes(NONCE_LEN);
    const ciphertext = aesEncrypt(derive(Buffer.from(passphrase, 'utf-8'), salt), nonce, doc);
    this._audit('export', keyId, rec.algorithm);
    return new Uint8Array(Buffer.concat([EXPORT_MAGIC, salt, nonce, ciphertext]));
  }

  /** Import a key produced by {@link exportKey}; return its id in this store. */
  importKey(blob, passphrase) {
    const buf = Buffer.from(blob);
    if (!buf.subarray(0, EXPORT_MAGIC.length).equals(EXPORT_MAGIC)) {
      throw new KMSError('Not a pqcmap key export (bad magic).');
    }
    const body = buf.subarray(EXPORT_MAGIC.length);
    if (body.length < SALT_LEN + NONCE_LEN) throw new KMSError('Truncated key export.');
    const salt = body.subarray(0, SALT_LEN);
    const nonce = body.subarray(SALT_LEN, SALT_LEN + NONCE_LEN);
    const ciphertext = body.subarray(SALT_LEN + NONCE_LEN);
    let doc;
    try {
      doc = JSON.parse(aesDecrypt(derive(Buffer.from(passphrase, 'utf-8'), salt), nonce, ciphertext).toString('utf-8'));
    } catch {
      throw new KMSAuthError('Wrong export passphrase or corrupt export blob.');
    }
    let keyId = doc.key_id || '';
    if (!keyId || this._records[keyId]) keyId = 'key_' + crypto.randomBytes(8).toString('hex');
    this._records[keyId] = doc.record;
    this._save();
    this._audit('import', keyId, doc.record?.algorithm ?? '?');
    return keyId;
  }

  // -- audit log --------------------------------------------------------------

  readAuditLog() {
    if (!fs.existsSync(this.auditPath)) return [];
    return fs.readFileSync(this.auditPath, 'utf-8')
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  }

  /** Re-walk the hash chain; return true, or throw KMSError on tamper. */
  verifyAuditLog() {
    let prev = AUDIT_GENESIS;
    for (const entry of this.readAuditLog()) {
      const expected = auditHash(prev, entry);
      if (entry.hash !== expected || entry.prev !== prev) {
        throw new KMSError(`Audit log tamper detected at seq ${JSON.stringify(entry.seq)}.`);
      }
      prev = entry.hash;
    }
    return true;
  }

  // -- internals --------------------------------------------------------------

  _record(keyId) {
    const rec = this._records[keyId];
    if (!rec) throw new KMSKeyNotFoundError(`No key with id ${JSON.stringify(keyId)}.`);
    return rec;
  }

  _generate(algorithm) {
    if (KEM_ALGORITHMS.includes(algorithm)) return new KeyEncapsulation(algorithm).generateKeypair();
    if (SIGN_ALGORITHMS.includes(algorithm)) return new Signature(algorithm).generateKeypair();
    throw new UnsupportedAlgorithmError(`Cannot generate for ${JSON.stringify(algorithm)}.`);
  }

  _load() {
    const raw = fs.readFileSync(this.path);
    if (raw.length < SALT_LEN + NONCE_LEN) throw new KMSAuthError('Key store file is truncated or corrupt.');
    this._salt = raw.subarray(0, SALT_LEN);
    const nonce = raw.subarray(SALT_LEN, SALT_LEN + NONCE_LEN);
    const ciphertext = raw.subarray(SALT_LEN + NONCE_LEN);
    let plaintext;
    try {
      plaintext = aesDecrypt(derive(this._passphrase, this._salt), nonce, ciphertext);
    } catch {
      throw new KMSAuthError('Could not decrypt key store — wrong passphrase or corrupt file.');
    }
    const doc = JSON.parse(plaintext.toString('utf-8'));
    if (doc && doc.version === SCHEMA_VERSION) {
      this._records = doc.keys || {};
      this._policy = RotationPolicy.fromDict(doc.policy);
    } else {
      this._records = doc; // legacy v1: flat {key_id: record}
      this._policy = new RotationPolicy();
    }
  }

  _save() {
    const doc = { version: SCHEMA_VERSION, keys: this._records, policy: this._policy.toDict() };
    const nonce = crypto.randomBytes(NONCE_LEN);
    const ciphertext = aesEncrypt(derive(this._passphrase, this._salt), nonce, Buffer.from(JSON.stringify(doc), 'utf-8'));
    fs.mkdirSync(path.dirname(this.path), { recursive: true });
    const tmp = this.path + '.tmp';
    fs.writeFileSync(tmp, Buffer.concat([this._salt, nonce, ciphertext]), { mode: 0o600 });
    fs.renameSync(tmp, this.path);
  }

  _readLastAuditHash() {
    if (!this._auditEnabled || !fs.existsSync(this.auditPath)) return AUDIT_GENESIS;
    let last = AUDIT_GENESIS;
    for (const line of fs.readFileSync(this.auditPath, 'utf-8').split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        last = JSON.parse(t).hash;
      } catch {
        /* skip */
      }
    }
    return last;
  }

  _audit(op, keyId, algorithm, detail = null) {
    if (!this._auditEnabled) return;
    const entry = {
      seq: this.readAuditLog().length,
      ts: now(),
      op,
      key_id: keyId,
      algorithm,
      detail: detail || {},
      prev: this._lastAuditHash,
    };
    entry.hash = auditHash(this._lastAuditHash, entry);
    fs.mkdirSync(path.dirname(this.auditPath), { recursive: true });
    fs.appendFileSync(this.auditPath, JSON.stringify(entry) + '\n', 'utf-8');
    this._lastAuditHash = entry.hash;
  }
}
