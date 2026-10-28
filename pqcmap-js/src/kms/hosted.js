/**
 * HostedKMS — client for the SeQr hosted Key Management Service. Port of Python
 * `pqcmap.kms.hosted`, with the same envelope wire format (interoperable blobs).
 *
 * The master key never leaves the KMS. Envelope encryption: the KMS mints a data key
 * (returned once in plaintext plus a copy wrapped under the master key); the client
 * encrypts locally under it and stores only the wrapped form. Decryption asks the KMS to
 * unwrap the data key.
 *
 *   const kms = new HostedKMS({ endpoint: 'https://kms.seqrlabs.com', apiKey: 'sq_live_…' });
 *   const blob = await kms.encrypt(Buffer.from('card number'), { masterKeyId: 'mk-prod-1' });
 *   (await kms.decrypt(blob)).equals(Buffer.from('card number'));   // true
 *
 * Bearer `sq_live_` auth; HTTP status maps to the error family (401/403 → KMSAuthError,
 * 404 → KMSKeyNotFoundError, else KMSError). The network layer is a pluggable async
 * `transport(method, url, headers, body) -> { status, body }`, so tests mock the HTTP
 * while the local envelope crypto stays real. Default transport uses global `fetch`.
 */
import crypto from 'node:crypto';

import { b64u, b64uToBytes } from '../_encoding.js';
import { KMSAuthError, KMSError, KMSKeyNotFoundError } from '../errors.js';

const MAGIC = Buffer.from('PQCKMS1');
const NONCE_LEN = 12;
const TAG_LEN = 16;
const DEFAULT_DATA_KEY_BYTES = 32; // AES-256

function aesEncrypt(key, nonce, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}
function aesDecrypt(key, nonce, blob) {
  const body = blob.subarray(0, blob.length - TAG_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

export class HostedKMS {
  /**
   * @param {{ endpoint: string, apiKey: string, timeout?: number,
   *           transport?: (method: string, url: string, headers: object, body: Buffer|null) => Promise<{status:number, body:Buffer}> }} opts
   */
  constructor({ endpoint, apiKey, timeout = 10_000, transport = null } = {}) {
    if (!endpoint) throw new KMSError('A KMS endpoint URL is required.');
    if (!apiKey) throw new KMSAuthError('A KMS API key is required.');
    this.endpoint = endpoint.replace(/\/+$/, '');
    this._apiKey = apiKey;
    this._timeout = timeout;
    this._transport = transport || fetchTransport(timeout);
  }

  /** Ask the KMS to mint a data key under `masterKeyId` (envelope pattern). */
  async generateDataKey(masterKeyId, { keyBytes = DEFAULT_DATA_KEY_BYTES } = {}) {
    const body = await this._request('POST', `/v1/keys/${masterKeyId}/data-key`, { key_bytes: keyBytes });
    return {
      plaintext: this._b64(body, 'plaintext'),
      wrapped: this._b64(body, 'ciphertext'),
      masterKeyId: body.master_key_id ?? masterKeyId,
    };
  }

  /** Ask the KMS to unwrap a previously wrapped data key. */
  async decryptDataKey(wrapped, { masterKeyId = null } = {}) {
    const payload = { ciphertext: b64u(wrapped) };
    if (masterKeyId != null) payload.master_key_id = masterKeyId;
    const body = await this._request('POST', '/v1/decrypt', payload);
    return this._b64(body, 'plaintext');
  }

  /** Envelope-encrypt `plaintext` and return a self-describing Buffer. */
  async encrypt(plaintext, { masterKeyId }) {
    const dk = await this.generateDataKey(masterKeyId);
    const nonce = crypto.randomBytes(NONCE_LEN);
    const ciphertext = aesEncrypt(Buffer.from(dk.plaintext), nonce, Buffer.from(plaintext));
    return pack(dk.masterKeyId, Buffer.from(dk.wrapped), nonce, ciphertext);
  }

  /** Decrypt a blob produced by {@link encrypt}. */
  async decrypt(envelope) {
    const { masterKeyId, wrapped, nonce, ciphertext } = unpack(Buffer.from(envelope));
    const dataKey = await this.decryptDataKey(wrapped, { masterKeyId: masterKeyId || null });
    try {
      return aesDecrypt(Buffer.from(dataKey), nonce, ciphertext);
    } catch (e) {
      throw new KMSError(`Envelope decryption failed: ${e.message}`);
    }
  }

  /** KMS health/status document (a cheap connectivity check). */
  async health() {
    return this._request('GET', '/v1/health');
  }

  // -- HTTP plumbing ----------------------------------------------------------

  async _request(method, urlPath, payload = null) {
    const url = `${this.endpoint}${urlPath}`;
    const headers = {
      Authorization: `Bearer ${this._apiKey}`,
      Accept: 'application/json',
      'User-Agent': 'pqcmap-hosted-kms',
    };
    let body = null;
    if (payload != null) {
      body = Buffer.from(JSON.stringify(payload), 'utf-8');
      headers['Content-Type'] = 'application/json';
    }
    let resp;
    try {
      resp = await this._transport(method, url, headers, body);
    } catch (e) {
      if (e instanceof KMSError) throw e;
      throw new KMSError(`KMS request to ${urlPath} failed: ${e.message}`);
    }
    return handleStatus(urlPath, resp);
  }

  _b64(body, field) {
    if (!(field in body)) throw new KMSError(`KMS response missing ${JSON.stringify(field)}.`);
    try {
      return b64uToBytes(body[field]);
    } catch (e) {
      throw new KMSError(`KMS response ${JSON.stringify(field)} was not valid base64: ${e.message}`);
    }
  }
}

// --- status handling + envelope (de)serialisation ----------------------------

function handleStatus(urlPath, resp) {
  const bodyBuf = Buffer.from(resp.body || Buffer.alloc(0));
  if (resp.status >= 200 && resp.status < 300) {
    if (bodyBuf.length === 0) return {};
    try {
      return JSON.parse(bodyBuf.toString('utf-8'));
    } catch (e) {
      throw new KMSError(`KMS returned invalid JSON from ${urlPath}: ${e.message}`);
    }
  }
  const detail = errorDetail(bodyBuf);
  if (resp.status === 401 || resp.status === 403) throw new KMSAuthError(`KMS rejected the API key (${resp.status}): ${detail}`);
  if (resp.status === 404) throw new KMSKeyNotFoundError(`KMS key not found (404): ${detail}`);
  throw new KMSError(`KMS error ${resp.status} from ${urlPath}: ${detail}`);
}

function errorDetail(bodyBuf) {
  try {
    const data = JSON.parse(bodyBuf.toString('utf-8'));
    return String(data.error ?? data.message ?? JSON.stringify(data));
  } catch {
    return bodyBuf.length ? bodyBuf.subarray(0, 200).toString('utf-8') : '(no body)';
  }
}

function pack(masterKeyId, wrapped, nonce, ciphertext) {
  const mkid = Buffer.from(masterKeyId, 'utf-8');
  const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n);
    return b;
  };
  return Buffer.concat([MAGIC, u16(mkid.length), mkid, u16(wrapped.length), wrapped, nonce, ciphertext]);
}

function unpack(blob) {
  try {
    if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) throw new KMSError('Not a pqcmap KMS envelope (bad magic).');
    let pos = MAGIC.length;
    const mkidLen = blob.readUInt16BE(pos); pos += 2;
    const masterKeyId = blob.subarray(pos, pos + mkidLen).toString('utf-8'); pos += mkidLen;
    const wrappedLen = blob.readUInt16BE(pos); pos += 2;
    const wrapped = blob.subarray(pos, pos + wrappedLen); pos += wrappedLen;
    const nonce = blob.subarray(pos, pos + NONCE_LEN); pos += NONCE_LEN;
    const ciphertext = blob.subarray(pos);
    if (nonce.length !== NONCE_LEN || wrapped.length !== wrappedLen) throw new KMSError('Truncated KMS envelope.');
    return { masterKeyId, wrapped, nonce, ciphertext };
  } catch (e) {
    if (e instanceof KMSError) throw e;
    throw new KMSError(`Malformed KMS envelope: ${e.message}`);
  }
}

/** Default transport: global fetch (Node 18+), over the platform's TLS. */
function fetchTransport(timeout) {
  return async (method, url, headers, body) => {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, { method, headers, body, signal: controller.signal });
      const buf = Buffer.from(await res.arrayBuffer());
      return { status: res.status, body: buf };
    } finally {
      clearTimeout(t);
    }
  };
}
