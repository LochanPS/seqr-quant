# @seqr/pqc

**Post-quantum cryptography for JavaScript / TypeScript developers.** Drop-in NIST PQC
primitives (ML-KEM / ML-DSA) that replace RSA, ECDH, and ECDSA in application code — the
npm port of the Python [`pqcmap`](https://pypi.org/project/pqcmap/) SDK, with the same
public API shape, the same real-backend model, and the same policy engine.

@seqr/pqc is the **code-level arm of the [SeQr](https://seqrlabs.com) migration
lifecycle**: the SeQr scanner *finds* quantum-vulnerable crypto, pqcmap is how you *fix* it.

> **Status:** v0.1 (alpha). Core primitives, hybrid mode, PQC-signed JWTs (PyJWT-shaped
> drop-in), the policy engine, the encrypted `LocalKeyStore`, the `HostedKMS` client, and
> the best-effort PQC-hybrid TLS helper are all implemented and tested (42 tests). See
> [`../PORTS.md`](../PORTS.md) for cross-language status.

## Install

```bash
npm install @seqr/pqc
```

Real FIPS 203/204/205 crypto works out of the box on every platform — no native build.
The backend is the audited, pure-JS [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum);
there is **no mock in the product path**. `available()` is always true and `backend()`
returns `"noble"`.

## Quick start

```js
import { KeyEncapsulation, Signature, HybridKEM } from '@seqr/pqc';

// KEM — replaces RSA/ECDH key exchange (ML-KEM-768, FIPS 203, Level 3)
const kem = new KeyEncapsulation();
const kp = kem.generateKeypair();
const { ciphertext, sharedSecret } = kem.encapsulate(kp.publicKey);       // sender
const sharedSecret2 = kem.decapsulate(kp.secretKey, ciphertext);          // receiver
// Buffer.from(sharedSecret).equals(Buffer.from(sharedSecret2)) === true

// Signatures — replaces RSA-sign / ECDSA (ML-DSA-65, FIPS 204, Level 3)
const sig = new Signature();
const sk = sig.generateKeypair();
const signature = sig.sign(new TextEncoder().encode('authorize'), sk.secretKey);
sig.verify(new TextEncoder().encode('authorize'), signature, sk.publicKey);  // true

// Hybrid — X25519 + ML-KEM-768, recommended for the 2026–2030 transition
const h = new HybridKEM();
const hk = h.generateKeypair();
const enc = h.encapsulate(hk.publicKey);
h.decapsulate(hk.secretKey, enc.ciphertext);   // === enc.sharedSecret
```

### PQC-signed JWTs (drop-in for RS256)

```js
import * as jwt from '@seqr/pqc/jwt';           // PyJWT-shaped surface
import { Signature } from '@seqr/pqc';

const kp = new Signature('ML-DSA-65').generateKeypair();
const token  = jwt.encode({ sub: '123' }, kp.secretKey, 'ML-DSA-65');
const claims = jwt.decode(token, kp.publicKey, { algorithms: ['ML-DSA-65'] });
```

`decode` requires the `algorithms` allow-list (as PyJWT ≥ 2) and throws PyJWT-named errors
(`ExpiredSignatureError`, `InvalidSignatureError`, `DecodeError`, `InvalidAlgorithmError`),
each also a `PQCError`. The wire format matches the Python SDK, so **a token signed by one
SDK verifies in the other** (see the cross-language interop test).

### Policy enforcement

Refuse below-policy crypto in code, using the **same `{ rules: [...] }` policy shape as the
SeQr platform spine** (a spine policy body loads as-is):

```js
import { assertCompliant, compliant, PolicyViolationError } from '@seqr/pqc';

assertCompliant('ML-KEM-768', { kind: 'kem' });   // ok
assertCompliant('RSA-2048');                       // throws PolicyViolationError
new compliant.KeyEncapsulation('ML-KEM-512');      // throws — below NIST Level 3
```

Default policy (from PCI DSS 12.3.3 + SEBI CSCRF intent): no quantum-vulnerable families,
PQC at NIST Level 3+. Swap it with `setActivePolicy(bodyOrPath)` or `PQCMAP_POLICY`.

### Encrypted local key store

`LocalKeyStore` keeps keys AES-256-GCM-encrypted at rest (master key from PBKDF2-HMAC-SHA256),
with rotation policy, single-key export/import, and a hash-chained tamper-evident audit log.
The on-disk format matches the Python SDK — **a store written by one reads in the other**.

```js
import { LocalKeyStore, RotationPolicy } from '@seqr/pqc';

const ks = new LocalKeyStore('passphrase', undefined, { rotationPolicy: new RotationPolicy({ maxAgeDays: 90 }) });
const keyId = ks.generateAndStore('ML-DSA-65', { purpose: 'jwt' });
const pub = ks.getPublicKey(keyId);
ks.rotateIfNeeded(keyId);          // rotates only if the policy says so
ks.verifyAuditLog();               // true, or throws on tamper
```

### Hosted KMS

`HostedKMS` keeps the master key server-side and uses envelope encryption (same wire format
as the Python SDK). The transport is pluggable, so it mocks cleanly in tests.

```js
import { HostedKMS } from '@seqr/pqc';

const kms = new HostedKMS({ endpoint: 'https://kms.seqrlabs.com', apiKey: 'sq_live_…' });
const blob = await kms.encrypt(Buffer.from('card number'), { masterKeyId: 'mk-prod-1' });
(await kms.decrypt(blob)).equals(Buffer.from('card number'));   // true
```

### Best-effort PQC-hybrid TLS

```js
import * as tls from '@seqr/pqc/tls';

console.log(tls.report());          // honest capability line
const agent = tls.pqcHttpsAgent();  // https.Agent; negotiates X25519MLKEM768 on OpenSSL 3.5+
```

Node exposes group selection via `ecdhCurve`; because OpenSSL rejects an unknown group name,
the helper only configures the PQC group when the linked OpenSSL (3.5+) knows it — otherwise
it configures a hardened classical list and says so. It never breaks a connection to try for
PQC. (MTU caveat: an ML-KEM ClientHello ~1.2 KB fragments — test real handshakes first.)

### Benchmark

```bash
node benchmarks/benchmark.js                     # live per-op timings (noble + RSA baseline)
node benchmarks/benchmark.js --markdown out.md
```

A snapshot is in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## API parity with Python `pqcmap`

Same concepts and names; JavaScript idiom (camelCase methods, `{ options }` objects):

| Python `pqcmap` | `@seqr/pqc` |
|---|---|
| `KeyEncapsulation().generate_keypair()` | `new KeyEncapsulation().generateKeypair()` |
| `kem.encapsulate(pk)` → `(ct, ss)` tuple | `kem.encapsulate(pk)` → `{ ciphertext, sharedSecret }` |
| `Signature().sign(msg, sk)` / `.verify(msg, sig, pk)` | same, camelCase |
| `HybridKEM`, `combine_secrets` | `HybridKEM`, `combineSecrets` |
| `PQCToken` / `pqcmap.jwt` | `PQCToken` / `@seqr/pqc/jwt` |
| `assert_compliant`, `requires_pqc`, `pqcmap.compliant.*` | `assertCompliant`, `requiresPqc`, `compliant.*` |
| `LocalKeyStore`, `RotationPolicy` | same (interoperable on-disk format) |
| `HostedKMS` (sync) | `HostedKMS` (async — `await` encrypt/decrypt) |
| `pqcmap.tls` | `@seqr/pqc/tls` |
| `KEMAlgorithm`, `SignAlgorithm`, `meta()` | same (identical FIPS sizes) |

`requiresPqc` differs by necessity: JS has no parameter-name introspection, so the guarded
algorithm is read from the call's first argument (override with `getAlgorithm`).

## Test

```bash
npm test        # node --test — real crypto, no mock; includes cross-language interop
```

## License

MIT.
