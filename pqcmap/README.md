# pqcmap

**Post-quantum cryptography for Python developers.** Drop-in NIST PQC primitives
(ML-KEM / ML-DSA) that replace RSA, ECDH, and ECDSA in application code — without
needing to understand lattices.

pqcmap is the **code-level arm of the [SeQr](https://seqrlabs.com) migration
lifecycle**: the SeQr scanner *finds* quantum-vulnerable crypto, pqcmap is how you
*fix* it. `seqr explain` / `seqr migrate` reference these same patterns.

> **Status:** v0.1 (alpha). Core primitives, hybrid mode, PQC-signed JWTs (with a
> PyJWT-shaped drop-in), a best-effort PQC-hybrid TLS context builder, httpx/requests
> helpers, an encrypted local key store (rotation policy, export/import, audit log), and
> the hosted KMS client are implemented and tested.

**Documentation & proof**

- 📕 [**Migration cookbook**](docs/COOKBOOK.md) — before→after recipes for RS256/ES256 JWT,
  RSA-sign, ECDSA, ECDH/X25519, RSA-OAEP → pqcmap. Every snippet is [run for real](examples/cookbook_recipes.py).
- 🧪 [**Worked example**](examples/worked_migration/) — the full loop: `seqr scan code` finds
  the vulns, pqcmap fixes them, a re-scan comes back clean.
- ⏱️ [**Benchmarks**](docs/BENCHMARKS.md) — real keygen/encap/sign/verify timings on this
  machine, from [`benchmarks/benchmark.py`](benchmarks/benchmark.py) (no invented numbers).

---

## Install

```bash
pip install pqcmap
```

**Real crypto works out of the box on every platform, including Windows** — no C
toolchain. pqcmap runs one of two interchangeable backends:

| Backend | What | When |
|---|---|---|
| `pure-python` | [`kyber-py`](https://pypi.org/project/kyber-py/) (ML-KEM / FIPS 203) + [`dilithium-py`](https://pypi.org/project/dilithium-py/) (ML-DSA / FIPS 204) | **Default.** Hard dependencies, pure Python, install everywhere. |
| `liboqs` | [liboqs](https://github.com/open-quantum-safe/liboqs) via `oqs` | Optional (`pip install pqcmap[liboqs]`). Faster; adds algorithms like SLH-DSA. |

pqcmap prefers liboqs for speed and falls back to the pure-Python backend, so real
ML-KEM / ML-DSA always run — there is no mock in the product path.

```python
import pqcmap
pqcmap.available()   # True (pure-python is always installed)
pqcmap.backend()     # "pure-python" or "liboqs"
```

> The pure-Python backend is a reference implementation: correct and portable, but
> slower than liboqs. For high-throughput production, install `pqcmap[liboqs]`.

---

## Quick start

### Key encapsulation (replaces RSA/ECDH key exchange)

```python
from pqcmap import KeyEncapsulation

kem = KeyEncapsulation()                       # ML-KEM-768 (FIPS 203, Level 3) by default
keypair = kem.generate_keypair()

ciphertext, shared_secret = kem.encapsulate(keypair.public_key)   # sender
shared_secret2 = kem.decapsulate(keypair.secret_key, ciphertext)  # receiver
assert shared_secret == shared_secret2         # use as an AES-256 key
```

### Signatures (replaces RSA-sign / ECDSA)

```python
from pqcmap import Signature

sig = Signature()                              # ML-DSA-65 (FIPS 204, Level 3) by default
keypair = sig.generate_keypair()
signature = sig.sign(b"authorize transfer", keypair.secret_key)
assert sig.verify(b"authorize transfer", signature, keypair.public_key)
```

### Hybrid mode (recommended for the 2026–2030 transition)

X25519 (classical) **+** ML-KEM-768 (PQC), combined with HKDF-SHA256. If either
primitive is broken, the other still protects the shared secret — the same posture
TLS 1.3 deployments are standardising on (`X25519MLKEM768`).

```python
from pqcmap import HybridKEM

kem = HybridKEM()
keypair = kem.generate_keypair()
ciphertext, secret = kem.encapsulate(keypair.public_key)
secret2 = kem.decapsulate(keypair.secret_key, ciphertext)
assert secret == secret2
```

### PQC-signed JWTs (drop-in for PyJWT RS256)

```python
from pqcmap.jwt import PQCToken
from pqcmap.kms.local import LocalKeyStore

ks = LocalKeyStore(passphrase="…")
key_id = ks.generate_and_store("ML-DSA-65", metadata={"purpose": "jwt"})

token = PQCToken.encode({"user_id": "123", "exp": 1_800_000_000}, ks.get_private_key(key_id))
claims = PQCToken.decode(token, ks.get_public_key(key_id))   # verifies signature + exp
```

### Encrypted local key store

`LocalKeyStore` keeps keys AES-256-GCM-encrypted at rest, with the master key derived
from a passphrase via PBKDF2-HMAC-SHA256 (100,000 iterations). Default location:
`~/.seqr/keys.enc`.

```python
ks = LocalKeyStore(passphrase="my-secret")
key_id = ks.generate_and_store("ML-DSA-65", metadata={"purpose": "jwt"})
pub = ks.get_public_key(key_id)
new_id = ks.rotate(key_id)      # new keypair; old one retained, marked "rotated"
```

**Rotation policy** (by age and/or usage — `get_private_key` counts a use):

```python
from pqcmap.kms.local import RotationPolicy

ks = LocalKeyStore(passphrase="…", rotation_policy=RotationPolicy(max_age_days=90, max_uses=100_000))
ks.rotate_if_needed(key_id)     # rotates only if the policy says so; returns new id or None
```

**Export / import** a single key as a portable, passphrase-encrypted blob (independent
of the store passphrase):

```python
blob = ks.export_key(key_id, passphrase="transfer-pass")
other = LocalKeyStore(passphrase="…", path="/other/keys.enc")
other.import_key(blob, passphrase="transfer-pass")
```

**Audit log** — every key operation is appended, hash-chained and tamper-evident, to
`<store>.audit.log` (operational metadata only, never key material):

```python
ks.read_audit_log()      # [{seq, ts, op, key_id, algorithm, detail, prev, hash}, …]
ks.verify_audit_log()    # True, or raises KMSError on tamper
```

### Hosted KMS

`HostedKMS` keeps the **master key server-side** and uses envelope encryption — the KMS
mints a data key (returned once in plaintext plus a copy wrapped under the master key),
you encrypt locally under it, and store only the wrapped form.

```python
from pqcmap import HostedKMS

kms = HostedKMS(endpoint="https://kms.seqrlabs.com", api_key="sq_live_…")
blob = kms.encrypt(b"card number", master_key_id="mk-prod-1")   # self-describing bytes
assert kms.decrypt(blob) == b"card number"
```

Authentication is a bearer `sq_live_` API key; HTTP status maps to the pqcmap error
family (401/403 → `KMSAuthError`, 404 → `KMSKeyNotFoundError`, else `KMSError`). The
network layer is a pluggable `transport`, so it is easy to mock in tests.

---

## Migrating existing code

```python
# Before — PyJWT with RS256 (RSA, quantum-vulnerable)
import jwt
token = jwt.encode({"user_id": "123"}, rsa_private_key, algorithm="RS256")

# After — pqcmap with ML-DSA-65
from pqcmap.jwt import PQCToken
from pqcmap.kms.local import LocalKeyStore
ks = LocalKeyStore(passphrase="…")
key_id = ks.generate_and_store("ML-DSA-65")
token = PQCToken.encode({"user_id": "123"}, ks.get_private_key(key_id))
```

Find what to migrate first:

```bash
pip install seqr
seqr scan code ./src --output json --save findings.json
```

Then apply the matching recipe from the [**migration cookbook**](docs/COOKBOOK.md) — it covers
RS256/ES256 JWT, RSA-sign, ECDSA, ECDH/X25519, and RSA-OAEP, each keyed to the scanner's
finding ids. For the whole find→fix→re-scan loop on a real service, see the
[**worked example**](examples/worked_migration/).

---

## Policy enforcement

pqcmap can **refuse below-policy crypto in code**, so an app can't silently fall back to
a quantum-vulnerable algorithm. This is the SDK's role in the SeQr lifecycle: the scanner
*measures* against a crypto policy, the migration engine *converges* to it, and pqcmap
*enforces* it. Policies use the **same `{"rules": [...]}` shape as the SeQr platform
spine** (`app/spine/policy.py`) — a spine policy body loads here directly.

The built-in default derives from PCI DSS 12.3.3 + SEBI CSCRF intent: no quantum-vulnerable
families, and PQC at NIST Level 3 or above.

```python
from pqcmap import assert_compliant, requires_pqc, PolicyViolationError

assert_compliant("ML-KEM-768", kind="kem")     # ok — returns None
assert_compliant("RSA-2048")                    # raises PolicyViolationError
assert_compliant("ML-KEM-512", kind="kem")      # raises — below NIST Level 3
```

### Policy-checked constructors

Drop-in primitives that validate the algorithm at construction, before any key is minted:

```python
from pqcmap.compliant import KeyEncapsulation, Signature

KeyEncapsulation()                 # ML-KEM-768 — allowed
KeyEncapsulation("ML-KEM-512")     # raises PolicyViolationError (below Level 3)
```

### Guard a key-minting / signing function

```python
@requires_pqc(kind="sign")
def issue_token(algorithm="ML-DSA-65"):
    ...        # a below-policy `algorithm` raises before the body runs
```

### Choosing the policy

```python
from pqcmap import set_active_policy, CryptoPolicy

set_active_policy("crypto-policy.json")     # JSON file (spine shape)
set_active_policy({"rules": [...]})         # inline body
# or export PQCMAP_POLICY=/path/to/policy.json
```

Precedence: an explicit `policy=` argument > `set_active_policy(...)` > the `PQCMAP_POLICY`
env var > the built-in default. Rule types match the spine's vocabulary — `family_in`,
`family_not_in`, `min_key_size` — plus `min_nist_level` for code-level algorithm selection.

---

## Framework drop-ins

Migrating the most common cases should be a few-line change, not a rewrite.

### JWT — change the import, keep the call shape

`pqcmap.jwt` exposes a **PyJWT-shaped** surface (`encode` / `decode` /
`get_unverified_header` and PyJWT-named exceptions), so a codebase migrates by swapping
the import:

```python
import pqcmap.jwt as jwt                 # was: import jwt

token  = jwt.encode({"sub": "123"}, mldsa_secret_key, algorithm="ML-DSA-65")
claims = jwt.decode(token, mldsa_public_key, algorithms=["ML-DSA-65"])
```

`decode()` requires the `algorithms` allow-list (as in PyJWT ≥ 2) and raises the
familiar `jwt.ExpiredSignatureError` / `jwt.InvalidSignatureError` / `jwt.DecodeError` /
`jwt.InvalidAlgorithmError` — each of which also subclasses `pqcmap.PQCError`. Keys are
raw ML-DSA bytes (from a `LocalKeyStore` or `Signature().generate_keypair()`), not PEM
objects. This is drop-in at the *code* level; the token is ML-DSA, not RS256-wire-compatible.

A runnable **FastAPI** service — login issues an ML-DSA JWT, a dependency verifies it —
is in [`examples/fastapi_auth.py`](examples/fastapi_auth.py).

### TLS — best-effort PQC-hybrid context, with an honest capability report

```python
from pqcmap import tls

ctx, caps = tls.build_client_context()
print(caps.summary())
# e.g. "PQC-hybrid TLS: configured (group X25519MLKEM768); OpenSSL 3.5.x; …"
#  or  "PQC-hybrid TLS: unavailable (group -); OpenSSL 3.0.x; Python ssl set_groups=no"
```

`build_client_context()` returns a hardened client `SSLContext` that negotiates
**X25519MLKEM768** when the runtime supports it — **OpenSSL 3.5+** (native ML-KEM groups)
or the liboqs **oqs-provider**, plus **Python 3.13+** for `ssl.SSLContext.set_groups` —
and **degrades cleanly to secure classical TLS 1.3 otherwise**. It never raises for lack
of PQC support; `capabilities()` tells you exactly what the runtime can do so you can log
or gate on it.

### HTTP — httpx / requests over that context

```python
from pqcmap.tls import http

with http.pqc_httpx_client() as client:
    r = client.get("https://example.com")
    print(client.pqc_capabilities.summary())

session = http.pqc_requests_session()   # requests.Session with the same TLS posture
```

Both carry a `pqc_capabilities` attribute; `httpx` / `requests` stay optional. See
[`examples/tls_client.py`](examples/tls_client.py).

> **MTU / fragmentation caveat** (per `docs/02_SDK_PRD.md`): an ML-KEM share (~1.2 KB)
> makes the TLS ClientHello span multiple packets. Mainstream stacks cope, but some
> middleboxes and DTLS paths choke on a fragmented ClientHello — **test a real handshake
> against your endpoints before a production rollout.**

---

## Algorithms

| Constant | Name | FIPS | NIST level | Notes |
|---|---|---|---|---|
| `KEMAlgorithm.ML_KEM_512` | ML-KEM-512 | 203 | 1 | |
| `KEMAlgorithm.ML_KEM_768` | ML-KEM-768 | 203 | 3 | **KEM default** |
| `KEMAlgorithm.ML_KEM_1024` | ML-KEM-1024 | 203 | 5 | |
| `SignAlgorithm.ML_DSA_44` | ML-DSA-44 | 204 | 2 | |
| `SignAlgorithm.ML_DSA_65` | ML-DSA-65 | 204 | 3 | **Signature default** |
| `SignAlgorithm.ML_DSA_87` | ML-DSA-87 | 204 | 5 | |
| `SignAlgorithm.SLH_DSA_SHA2_128F` | SLH-DSA-SHA2-128f | 205 | 1 | hash-based backup |

`pqcmap.algorithms.meta(name)` returns FIPS reference, NIST level, and on-the-wire
sizes (useful for MTU / storage planning) without instantiating the crypto backend.

> **MTU note:** ML-KEM public keys (1,184 bytes) are larger than RSA and may cause TLS
> handshake fragmentation. Test with a large ClientHello before production rollout.

---

## Performance

Run the benchmark to get **real** per-operation timings for every installed backend
(pure-python always; liboqs when present) plus a classical RSA-2048 baseline, all measured
live on your machine — nothing is looked-up or invented:

```bash
python benchmarks/benchmark.py                        # human table
python benchmarks/benchmark.py --markdown out.md      # + Markdown results
```

A committed snapshot from one machine is in [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Headline
shape: PQC **keygen** is faster than RSA-2048 keygen even in pure Python; PQC sign/verify look
slower under the pure-Python reference backend and get orders of magnitude faster with
`pqcmap[liboqs]`. Sizes are fixed by the FIPS parameter set (table above).

---

## Errors

Every error derives from `pqcmap.PQCError`, so one `except PQCError` catches the
family: `PQCUnavailableError`, `UnsupportedAlgorithmError`, `KeySizeError`,
`SignatureVerificationError`, `PQCTokenExpiredError`, `PQCTokenInvalidError`
(`PQCTokenSignatureError`), `KMSError` (`KMSKeyNotFoundError`, `KMSAuthError`). The
PyJWT-shaped errors from `pqcmap.jwt` (`ExpiredSignatureError`, `InvalidSignatureError`,
`DecodeError`, `InvalidAlgorithmError`) subclass these too.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

The suite runs against the **real** backend — pure-Python here, liboqs where it is
installed (one liboqs-only test skips otherwise). No mock: every KEM / signature /
JWT / keystore test performs genuine FIPS 203/204 operations.

## License

MIT.
