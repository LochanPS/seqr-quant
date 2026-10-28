# pqcmap migration cookbook

Practical **before → after** recipes for replacing quantum-vulnerable crypto with
post-quantum equivalents. Each recipe is a small, self-contained change you can paste
into a real codebase. Every "after" snippet in this document is exercised by
[`examples/cookbook_recipes.py`](../examples/cookbook_recipes.py) — run it to see them all
pass end-to-end.

**How to use this doc:** find the classical primitive you have on the left, jump to that
recipe, apply the change. If you don't yet know *where* your quantum-vulnerable crypto is,
find it first:

```bash
pip install seqr
seqr scan code ./src --output json --save findings.json
```

Then fix each finding with the matching recipe below. The scanner's `recommended_replacement`
field points at the same ML-KEM / ML-DSA targets these recipes use.

| You have (classical) | Finding id (typical) | Replace with | Recipe |
|---|---|---|---|
| PyJWT `RS256` / `ES256` | `PY-JWT-RS256` | `pqcmap.jwt` (ML-DSA-65) | [1](#1-rs256--es256-jwt--ml-dsa-jwt) |
| RSA signatures | `PY-RSA-001` | `Signature` (ML-DSA-65) | [2](#2-rsa-signatures--ml-dsa) |
| ECDSA signatures | `PY-ECC-001` | `Signature` (ML-DSA-65) | [3](#3-ecdsa-signatures--ml-dsa) |
| ECDH / X25519 key agreement | `PY-ECC-001` | `KeyEncapsulation` (ML-KEM-768) | [4](#4-ecdh--x25519-key-agreement--ml-kem) |
| RSA-OAEP encryption | `PY-RSA-001` | KEM + AES-GCM (KEM-DEM) | [5](#5-rsa-oaep-encryption--kem--aes-gcm-kem-dem) |
| any of the above, transition-safe | — | `HybridKEM` (X25519 + ML-KEM-768) | [6](#6-hybrid-mode-for-the-20262030-transition) |

> **Naming:** ML-KEM (FIPS 203) is the standardised name for Kyber; ML-DSA (FIPS 204) for
> Dilithium. pqcmap defaults to **NIST Level 3** everywhere (ML-KEM-768, ML-DSA-65) — the
> recommended baseline for new systems. Bump to `-1024` / `-87` for Level 5.

---

## 1. RS256 / ES256 JWT → ML-DSA JWT

The single most common finding. PyJWT signs tokens with RSA (`RS256`) or ECDSA (`ES256`);
both are broken by a cryptographically-relevant quantum computer. `pqcmap.jwt` is
**PyJWT-shaped** — same `encode` / `decode` call signatures and the same exception names —
so the migration is mostly a changed import.

**Before** (PyJWT, RS256):

```python
import jwt   # PyJWT

token  = jwt.encode({"sub": "123", "exp": exp}, rsa_private_key, algorithm="RS256")
claims = jwt.decode(token, rsa_public_key, algorithms=["RS256"])
```

**After** (pqcmap, ML-DSA-65):

```python
import pqcmap.jwt as jwt                       # was: import jwt
from pqcmap import Signature

kp = Signature("ML-DSA-65").generate_keypair()  # or load from a LocalKeyStore

token  = jwt.encode({"sub": "123", "exp": exp}, kp.secret_key, algorithm="ML-DSA-65")
claims = jwt.decode(token, kp.public_key, algorithms=["ML-DSA-65"])
```

What changed and what didn't:

- **Same call shape.** `encode(payload, key, algorithm=...)` and
  `decode(token, key, algorithms=[...])` are unchanged. `decode` still enforces the
  `algorithms` allow-list (as PyJWT ≥ 2 requires) and still checks `exp`.
- **Same exceptions.** `jwt.ExpiredSignatureError`, `jwt.InvalidSignatureError`,
  `jwt.DecodeError`, `jwt.InvalidAlgorithmError` all exist — and each also subclasses
  `pqcmap.PQCError`, so `except PQCError` catches the whole family.
- **Keys are raw ML-DSA bytes**, not PEM/`cryptography` key objects. Get them from a
  `Signature().generate_keypair()` or a `LocalKeyStore` (recipe 7 below).
- **Not wire-compatible with RS256.** The token's `alg` is `ML-DSA-65`; old RS256 verifiers
  won't accept it and vice-versa. Roll issuers and verifiers together, or dual-issue during
  a cutover.

Production keys belong in a key store, not a module global:

```python
from pqcmap.kms.local import LocalKeyStore
import pqcmap.jwt as jwt

ks     = LocalKeyStore(passphrase="…")                 # AES-256-GCM at rest
key_id = ks.generate_and_store("ML-DSA-65", metadata={"purpose": "jwt"})

token  = jwt.encode({"sub": "123"}, ks.get_private_key(key_id), algorithm="ML-DSA-65")
claims = jwt.decode(token, ks.get_public_key(key_id), algorithms=["ML-DSA-65"])
```

A runnable FastAPI service (login issues an ML-DSA JWT, a dependency verifies it) is in
[`examples/fastapi_auth.py`](../examples/fastapi_auth.py).

---

## 2. RSA signatures → ML-DSA

**Before** (PyCA `cryptography`, RSA-PSS):

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

signature = key.sign(message, pss, hashes.SHA256())
key.public_key().verify(signature, message, pss, hashes.SHA256())   # raises on failure
```

**After** (pqcmap, ML-DSA-65):

```python
from pqcmap import Signature

sig = Signature("ML-DSA-65")            # FIPS 204, NIST Level 3
kp  = sig.generate_keypair()

signature = sig.sign(message, kp.secret_key)
is_valid  = sig.verify(message, signature, kp.public_key)   # returns bool, never raises
```

Notes:

- ML-DSA folds the hash into the signature scheme — **no separate `hashes.SHA256()` / padding
  choice** to get wrong. One algorithm string picks the whole scheme.
- `verify` **returns a bool** rather than raising on a bad signature. If your old code relied
  on `verify()` raising, branch on the return value instead: `if not sig.verify(...): reject()`.
- `message` is raw `bytes`. For large payloads, sign a hash/digest of the content exactly as
  you would have with RSA.

---

## 3. ECDSA signatures → ML-DSA

**Before** (PyCA `cryptography`, ECDSA P-256):

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1())
signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
key.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))   # raises on failure
```

**After** (pqcmap, ML-DSA-65):

```python
from pqcmap import Signature

sig = Signature("ML-DSA-65")
kp  = sig.generate_keypair()

signature = sig.sign(message, kp.secret_key)
is_valid  = sig.verify(message, signature, kp.public_key)
```

Same target as RSA signatures — ML-DSA replaces **both** RSA-sign and ECDSA; you don't pick a
curve or a hash. Trade-off to plan for: an ML-DSA-65 signature is ~3.3 KB versus ~64–72 bytes
for ECDSA P-256 (see the sizes table at the end). That matters for anything that stores or
transmits many signatures — budget for it, but it does not change the code shape.

---

## 4. ECDH / X25519 key agreement → ML-KEM

Diffie-Hellman (ECDH, X25519) lets two parties derive a shared secret. Post-quantum, the
equivalent primitive is a **KEM**: one side publishes a public key, the other *encapsulates*
to it, producing a ciphertext plus a shared secret; the first side *decapsulates* the
ciphertext to recover the same secret.

**Before** (X25519 ECDH):

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

alice = X25519PrivateKey.generate()
bob   = X25519PrivateKey.generate()

alice_shared = alice.exchange(bob.public_key())
bob_shared   = bob.exchange(alice.public_key())
assert alice_shared == bob_shared          # feed through HKDF → AES key
```

**After** (pqcmap ML-KEM-768):

```python
from pqcmap import KeyEncapsulation

kem = KeyEncapsulation("ML-KEM-768")       # FIPS 203, NIST Level 3
kp  = kem.generate_keypair()               # receiver publishes kp.public_key

# sender: encapsulate to the receiver's public key
ciphertext, shared_secret = kem.encapsulate(kp.public_key)

# receiver: recover the same secret from the ciphertext
shared_secret2 = kem.decapsulate(kp.secret_key, ciphertext)
assert shared_secret == shared_secret2     # 32-byte secret, use directly as an AES-256 key
```

Mental-model shift: DH is symmetric (both sides send a public key); a KEM is **directional**
(one static public key + one ciphertext). Whoever initiates *encapsulates*; the key owner
*decapsulates*. The resulting `shared_secret` is 32 bytes — use it straight as an AES-256-GCM
key, no extra KDF required (ML-KEM already applies one internally). For the belt-and-suspenders
option during the transition, use `HybridKEM` (recipe 6).

---

## 5. RSA-OAEP encryption → KEM + AES-GCM (KEM-DEM)

"Encrypt this blob to a public key" (RSA-OAEP, and ECIES) becomes the standard **KEM-DEM**
construction: use the KEM to agree a symmetric key, then encrypt the payload with AES-GCM under
it. This is also how you handle payloads larger than an RSA modulus — the KEM never touches the
plaintext.

**Before** (RSA-OAEP — also limited to ~190 bytes of plaintext at 2048-bit):

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

ciphertext = key.public_key().encrypt(plaintext, oaep)
recovered  = key.decrypt(ciphertext, oaep)
```

**After** (ML-KEM-768 + AES-256-GCM):

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcmap import KeyEncapsulation

kem = KeyEncapsulation("ML-KEM-768")
kp  = kem.generate_keypair()               # recipient's long-term keypair

def encrypt_to(public_key, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    kem_ct, secret = kem.encapsulate(public_key)   # secret is a 32-byte AES key
    nonce = os.urandom(12)
    dem_ct = AESGCM(secret).encrypt(nonce, plaintext, None)
    return kem_ct, nonce, dem_ct                   # ship all three to the recipient

def decrypt_with(secret_key, kem_ct, nonce, dem_ct) -> bytes:
    secret = kem.decapsulate(secret_key, kem_ct)   # same 32-byte key
    return AESGCM(secret).decrypt(nonce, dem_ct, None)
```

Notes:

- **No plaintext-size limit.** AES-GCM handles arbitrarily large payloads; the KEM only ever
  protects a 32-byte key. (RSA-OAEP could not encrypt more than a couple hundred bytes anyway.)
- **Wire format** is `kem_ct || nonce || dem_ct`. For ML-KEM-768, `kem_ct` is 1,088 bytes and
  the nonce is 12 — prepend them with fixed offsets or length prefixes.
- Use each encapsulation **once** (fresh `kem_ct` + nonce per message); never reuse a nonce
  under the same key.

---

## 6. Hybrid mode for the 2026–2030 transition

Standards bodies and TLS 1.3 deployments are rolling out **hybrids** — classical + PQC combined
— so that a break in *either* primitive still leaves the secret protected. pqcmap's `HybridKEM`
is X25519 **+** ML-KEM-768, combined with HKDF-SHA256 (the same `X25519MLKEM768` posture TLS is
standardising).

```python
from pqcmap import HybridKEM

kem = HybridKEM()                          # X25519 + ML-KEM-768
kp  = kem.generate_keypair()

ciphertext, secret  = kem.encapsulate(kp.public_key)   # sender
secret2             = kem.decapsulate(kp.secret_key, ciphertext)
assert secret == secret2                   # 32-byte AES-256 key
```

Identical call shape to the plain KEM (recipe 4) — just swap the class. The keys and ciphertext
are larger (both halves concatenated), but you get a secret that stays safe unless *both* X25519
and ML-KEM are broken. **This is the recommended default for new production key exchange today.**

---

## 7. Where keys live: `LocalKeyStore`

None of the recipes above should keep private keys in module globals in production. The
`LocalKeyStore` keeps them AES-256-GCM-encrypted at rest (master key from a passphrase via
PBKDF2-HMAC-SHA256), with rotation policy, single-key export/import, and a tamper-evident audit
log:

```python
from pqcmap.kms.local import LocalKeyStore, RotationPolicy

ks = LocalKeyStore(passphrase="…", rotation_policy=RotationPolicy(max_age_days=90))
kid = ks.generate_and_store("ML-DSA-65", metadata={"purpose": "jwt"})

priv = ks.get_private_key(kid)     # use with Signature / pqcmap.jwt
pub  = ks.get_public_key(kid)
ks.rotate_if_needed(kid)           # rotates only if the policy says so
```

For a server-held master key (envelope encryption), see `HostedKMS` in the README.

---

## Enforce the migration so it can't regress

Fixing the code once isn't enough if the next commit reintroduces RSA. pqcmap can **refuse
below-policy algorithms at construction time**, using the same policy shape as the SeQr platform
spine and CI gate:

```python
from pqcmap.compliant import KeyEncapsulation, Signature   # policy-checked constructors

Signature()                    # ML-DSA-65 — allowed
Signature("ML-DSA-44")         # raises PolicyViolationError (below NIST Level 3)
```

Pair that with `seqr ci` in your pipeline (gates on drift from the org crypto policy) so a
regression fails the build rather than shipping. Find → fix → **keep fixed**.

---

## Algorithm sizes (plan for these)

Post-quantum keys and signatures are larger than classical ones. This never changes the code,
but it matters for storage, tokens, and packet sizes. All values in bytes (FIPS parameter sets):

| Algorithm | Role | Public key | Secret key | Ciphertext / Signature | NIST level |
|---|---|---:|---:|---:|:--:|
| ML-KEM-512 | KEM | 800 | 1,632 | 768 | 1 |
| **ML-KEM-768** | KEM | 1,184 | 2,400 | 1,088 | **3** |
| ML-KEM-1024 | KEM | 1,568 | 3,168 | 1,568 | 5 |
| ML-DSA-44 | Sign | 1,312 | 2,560 | 2,420 | 2 |
| **ML-DSA-65** | Sign | 1,952 | 4,032 | 3,309 | **3** |
| ML-DSA-87 | Sign | 2,592 | 4,896 | 4,627 | 5 |
| _RSA-2048 (ref)_ | both | ~294 (PEM) | ~1,679 (PEM) | 256 | — |
| _X25519 (ref)_ | KEM/DH | 32 | 32 | 32 | — |

Read live from `pqcmap.algorithms.meta("ML-KEM-768")`. For real per-operation *timings* on your
own hardware, run [`benchmarks/benchmark.py`](../benchmarks/benchmark.py) — see
[BENCHMARKS.md](BENCHMARKS.md).

> **MTU / fragmentation caveat:** an ML-KEM share (~1.2 KB) makes a TLS ClientHello span
> multiple packets. Mainstream stacks cope; some middleboxes and DTLS paths choke on a
> fragmented ClientHello. Test a real handshake against your endpoints before rollout.
