/**
 * Small serialisation helpers shared across the SDK — base64url and canonical JSON.
 * Kept in one place so the JWT signing input and the keystore audit hash use identical
 * byte encodings (and match the Python SDK's `pqcmap.utils.encoding`).
 */

/** URL-safe base64 without padding (the JOSE/JWT convention). */
export function b64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

/** Inverse of {@link b64u} — tolerates missing padding. */
export function b64uToBytes(text) {
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

/**
 * Canonical JSON: recursively sorted object keys, no whitespace. Matches Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"))` for ASCII content, so signed
 * bytes / audit hashes are identical across the SDKs. (Python escapes non-ASCII via
 * ensure_ascii; keep string values ASCII for guaranteed cross-language parity.)
 */
export function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJSON(value[k])}`).join(',')}}`;
}
