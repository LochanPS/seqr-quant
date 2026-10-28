# pqcmap ports — Node (`@seqr/pqc`) & Go (`pqcmap-go`)

Session SDK-6 scope + status. Both ports mirror the Python `pqcmap` **public API** and its
two invariants: a **real crypto backend** (no mock in the product path) and the **same
policy model** (the SeQr platform-spine `{ "rules": [...] }` shape). Wire formats (hybrid
KDF, JWT) are kept **byte-identical to Python** so the three SDKs interoperate.

## Backend choices (real FIPS crypto per language)

| Port | Backend | Why |
|---|---|---|
| Python `pqcmap` | `kyber-py` + `dilithium-py` (pure-Python), optional `liboqs` | ships today |
| Node `@seqr/pqc` | [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) (audited pure-JS) | zero native build, runs in Node + browsers/bundlers |
| Go `pqcmap-go` | [`cloudflare/circl`](https://github.com/cloudflare/circl) (`kem/mlkem`, `sign/mldsa`) | audited, pure-Go, the de-facto Go PQC library |

All three run genuine FIPS 203/204 (ML-KEM / ML-DSA); noble and circl also carry
FIPS 205 (SLH-DSA). `available()` is always true; the backend name identifies the library.

## Status

### `@seqr/pqc` (npm) — built + verified ✅ (42 node:test pass, real crypto)
- **Primitives + framework:** `KeyEncapsulation`, `Signature`, `HybridKEM` +
  `combineSecrets`, `KeyPair`, algorithm constants + `meta()` (identical FIPS sizes), the
  full `PQCError` family; `PQCToken` + the PyJWT-shaped `@seqr/pqc/jwt`; the policy engine
  (`CryptoPolicy`, `assertCompliant`, `requiresPqc`, `compliant.*`, active policy +
  `PQCMAP_POLICY`); hand-authored `index.d.ts`.
- **Key management + TLS:** `LocalKeyStore` (AES-256-GCM at rest, PBKDF2, rotation policy,
  export/import, hash-chained audit log — **on-disk format interoperable with Python**);
  `HostedKMS` (envelope encryption, pluggable transport, same wire format); best-effort
  PQC-hybrid TLS (`@seqr/pqc/tls` — configures X25519MLKEM768 on OpenSSL 3.5+, honest report).
- **Cross-language interop verified:** hybrid KDF matches Python byte-for-byte; a
  Python-signed ML-DSA JWT verifies in JS; a Python-written `LocalKeyStore` reads in JS
  (same key id / public key / audit chain). On the build machine (Node 22 / OpenSSL 3.5.2)
  the TLS helper genuinely negotiates X25519MLKEM768.
- **Proof:** `benchmarks/benchmark.js` (live noble + RSA-2048 baseline) → `docs/BENCHMARKS.md`;
  runnable `examples/{auth_demo,tls_report}.js`.
- **Pending:** publish to npm (gated on founder). LocalKeyStore/HostedKMS parity complete.

### `pqcmap-go` — built + verified ✅ full parity (Go 1.27 / circl v1.6.1, `go test ./...` 24 tests)
- **Done:** module + metadata + error family (sentinels wrapping `ErrPQC`, `errors.Is`-based);
  `KeyEncapsulation` (ML-KEM) and `Signature` (ML-DSA) via circl `kem.Scheme` / `sign.Scheme`;
  `HybridKEM` (stdlib `crypto/ecdh` X25519 + ML-KEM-768, `crypto/hkdf`); `EncodeToken` /
  `DecodeToken` (ML-DSA JWT, canonical JSON); the policy engine (`CryptoPolicy`,
  `AssertCompliant`, `NewCompliant{KeyEncapsulation,Signature}`, active policy + `PQCMAP_POLICY`);
  `LocalKeyStore` (AES-256-GCM, PBKDF2, rotation, export/import, hash-chained audit — on-disk
  format interoperable with Python); `HostedKMS` (envelope, pluggable transport, same wire
  format); best-effort PQC-hybrid TLS (`X25519MLKEM768` via stdlib `crypto/tls`, Go 1.24+).
- **Cross-language interop verified:** the hybrid KDF matches Python/JS byte-for-byte; a
  Go-signed ML-DSA JWT verifies in **both Python and JS** (`examples/jwt_demo`); a Go-written
  `LocalKeyStore` reads in Python (`examples/ks_demo`).
- **Pending:** publish (tag → pkg.go.dev).

## API parity approach

Names and concepts are identical across ports; each uses its language's idiom:

- **Python:** `snake_case` methods, tuples, keyword args.
- **Node:** `camelCase` methods, `{ ciphertext, sharedSecret }` objects, `{ options }` args.
- **Go:** exported `PascalCase` methods, multiple returns, `(value, error)` where fallible.

The one deliberate divergence is `requires_pqc`: Python introspects parameter names; JS reads
the first call argument (override with `getAlgorithm`); Go will take an explicit algorithm.

## Interop contracts (must stay byte-identical)

1. **Hybrid KDF** — `HKDF-SHA256`, salt `"seqr-hybrid-v1"`, info
   `"pqcmap hybrid kem X25519+ML-KEM-768"`, input `classical || pqc`, 32-byte output.
2. **Hybrid wire format** — `x25519(32) || ml-kem-768(…)` for public key / secret key /
   ciphertext, in that order.
3. **JWT** — compact JOSE `b64url(header).b64url(payload).b64url(signature)`; canonical JSON
   with **sorted keys**, `","`/`":"` separators; `typ` = `"PQC-JWT"`; ML-DSA over the exact
   `header.payload` signing input. (Keep payload values ASCII for guaranteed parity — Python
   emits `ensure_ascii` JSON.)
4. **Policy** — the spine `{ "rules": [...] }` body with rule types `family_in` /
   `family_not_in` / `min_key_size` / `min_nist_level`; default forbids RSA/ECDSA/EdDSA/
   ECDH/DSA/DH and requires NIST Level 3+.
