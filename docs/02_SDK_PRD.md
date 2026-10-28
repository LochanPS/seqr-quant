# SeQr SDK — Engineering PRD v1.1
### pqcmap · Open Source Post-Quantum Cryptography Library
**Status: v0 BUILT 2026-08-20 (`pqcmap/`); SDK-1 + SDK-2 done 2026-08-21.** The SDK is the
*code-level* arm of the lifecycle — it **enforces the crypto policy** (see `docs/13`) inside
application code, for crypto the infra migration engine can't reach. Discovery of code crypto
belongs to the SDK/CI, not the infra discovery agent. v0 ships KEM / Signature / HybridKEM /
PQCToken / LocalKeyStore + algorithm metadata, with a runtime liboqs capability probe.
- **SDK-1:** PyPI-ready packaging (`py.typed`, MIT LICENSE, full metadata) + release workflow
  (test matrix + tag-gated OIDC trusted publish, TestPyPI dry-run). Publish gated on a tag.
- **SDK-2:** `pqcmap.policy` — loads the spine policy shape and enforces it (`assert_compliant`,
  `@requires_pqc`, `pqcmap.compliant.*` checked constructors, `PolicyViolationError`).
- 99 tests. Hosted KMS client and the best-effort TLS context builder remain deferred (SDK-3/4).
- **SDK-3 (2026-08-21):** framework drop-ins — `pqcmap.jwt` PyJWT-shaped `encode`/`decode`
  (+ PyJWT-named errors) with a runnable FastAPI auth example; `pqcmap.tls` best-effort
  PQC-hybrid TLS context builder (X25519MLKEM768 when supported, honest capability report,
  clean classical fallback); `pqcmap.tls.http` httpx/requests helpers. MTU caveat documented.
- **SDK-4 (2026-08-21):** key management — `pqcmap.kms.hosted.HostedKMS` (envelope
  encryption under a KMS-held master key, key-id addressing, bearer auth, mockable
  transport) + LocalKeyStore hardening (rotation policy, single-key export/import,
  hash-chained append-only audit log).
- 152 tests (1 real-liboqs test skips when native lib absent).
The sections below are the original spec — kept as the design reference.

---

## Deferral Rationale

pqcmap is the developer-layer migration tool that lets engineers fix code-level
quantum vulnerabilities found by the SeQr scanner. It is the "prescribe" layer
in the Audit → SDK → Gateway migration stack.

Current priority: audit backend + frontend + research paper + first customer.
pqcmap enables `seqr migrate` commands and provides the migration code snippets
shown in `seqr explain` output. Build it when the first customer asks "how do I fix this."

---

## Product Summary

pqcmap is a developer-first Python library (with Node.js and Go ports later) that
wraps the Open Quantum Safe liboqs library. Developers use simple function calls to
implement NIST PQC algorithms without understanding lattice mathematics.

**Open source (MIT license)** — core library is free. Revenue from:
- Hosted Key Management Service (₹8,000–25,000/month)
- Enterprise support SLA (₹30,000+/month)
- Compliance audit log export (bundled with SeQr Audit)

**Package names:**
- Python: `pqcmap` on PyPI (`pip install pqcmap`)
- Node.js: `@seqr/pqc` on npm (port after Python stable)
- Go: `github.com/seqrlabs/pqcmap-go` (port after 500 PyPI installs)

**Relationship to SeQr CLI:**
`seqr explain <finding-id>` uses offline static lookup from pqcmap migration patterns.
`seqr migrate --finding <id>` generates migration code using pqcmap API.
pqcmap is the fix layer; seqr-scanner is the find layer.

---

## Project Structure

```
pqcmap/
├── pqcmap/
│   ├── __init__.py            # Public API exports
│   ├── core/
│   │   ├── kem.py             # Key Encapsulation (ML-KEM-768 default)
│   │   ├── sign.py            # Digital Signatures (ML-DSA-65 default)
│   │   ├── hybrid.py          # Hybrid X25519+ML-KEM-768
│   │   └── exceptions.py
│   ├── algorithms.py          # Algorithm constants and metadata
│   ├── jwt/
│   │   └── token.py           # Drop-in PyJWT replacement (ML-DSA)
│   ├── tls/
│   │   └── context.py         # TLS context builder (best-effort PQC)
│   ├── kms/
│   │   ├── local.py           # AES-256-GCM encrypted local key store
│   │   └── hosted.py          # SeQr hosted KMS client
│   └── utils/
│       ├── encoding.py        # PEM/DER/base64 serialisation
│       └── random.py          # OS entropy secure random
├── tests/
├── pyproject.toml
└── README.md
```

---

## Public API

```python
# pqcmap/__init__.py

from pqcmap.core.kem import KeyEncapsulation
from pqcmap.core.sign import Signature
from pqcmap.core.hybrid import HybridKEM, HybridSignature
from pqcmap.jwt.token import PQCToken
from pqcmap.algorithms import Algorithm, KEMAlgorithm, SignAlgorithm
from pqcmap.kms.local import LocalKeyStore
from pqcmap.kms.hosted import HostedKMS
```

---

## Algorithm Constants

```python
class KEMAlgorithm:
    ML_KEM_512 = 'ML-KEM-512'   # FIPS 203, Level 1
    ML_KEM_768 = 'ML-KEM-768'   # FIPS 203, Level 3 — DEFAULT
    ML_KEM_1024 = 'ML-KEM-1024' # FIPS 203, Level 5

class SignAlgorithm:
    ML_DSA_44 = 'ML-DSA-44'    # FIPS 204, Level 2
    ML_DSA_65 = 'ML-DSA-65'    # FIPS 204, Level 3 — DEFAULT
    ML_DSA_87 = 'ML-DSA-87'    # FIPS 204, Level 5
    SLH_DSA_SHA2_128F = 'SLH-DSA-SHA2-128f'  # FIPS 205, backup
```

---

## Core Implementation Specs

### Key Encapsulation (kem.py)
```python
"""
Replaces RSA/ECDH key exchange.
Default: ML-KEM-768 (FIPS 203, Level 3)

API:
  kem = KeyEncapsulation('ML-KEM-768')
  keypair = kem.generate_keypair()           # → KeyPair(public_key, private_key)
  ciphertext, shared_secret = kem.encapsulate(keypair.public_key)
  shared_secret = kem.decapsulate(keypair.private_key, ciphertext)
  # Both parties now have shared_secret → use as AES-256 key
"""
```

### Digital Signatures (sign.py)
```python
"""
Replaces RSA-sign and ECDSA.
Default: ML-DSA-65 (FIPS 204, Level 3)

API:
  sig = Signature('ML-DSA-65')
  keypair = sig.generate_keypair()
  signature = sig.sign(message, keypair.private_key)
  is_valid = sig.verify(message, signature, keypair.public_key)
"""
```

### Hybrid Mode (hybrid.py)
```python
"""
X25519 (classical) + ML-KEM-768 (PQC) combined.
Recommended for production during 2026-2030 transition.
If either is broken, the other protects you.

Combined secret = HKDF(classical_secret + pqc_secret, salt='seqr-hybrid-v1')
"""
```

### JWT Integration (jwt/token.py)
```python
"""
Drop-in PyJWT replacement. Same interface, ML-DSA underneath.

MIGRATION:
  # Before
  import jwt
  token = jwt.encode(payload, rsa_private_key, algorithm='RS256')

  # After
  from pqcmap.jwt import PQCToken
  token = PQCToken.encode(payload, mldsa_private_key)
  data = PQCToken.decode(token, mldsa_public_key)
"""
```

---

## Local Key Store

```python
"""
pqcmap/kms/local.py
AES-256-GCM encrypted on-disk key storage.
Master key derived from passphrase via PBKDF2-HMAC-SHA256 (100,000 iterations).
Default location: ~/.seqr/keys.enc

API:
  ks = LocalKeyStore(passphrase="my-secret")
  key_id = ks.generate_and_store('ML-DSA-65', metadata={"purpose": "jwt"})
  pub_key = ks.get_public_key(key_id)
  priv_key = ks.get_private_key(key_id)
  new_id = ks.rotate(key_id)   # generates new keypair, marks old as rotated
"""
```

---

## pyproject.toml

```toml
[project]
name = "pqcmap"
version = "0.1.0"
description = "Post-quantum cryptography for Python developers. Drop-in PQC algorithms."
license = {text = "MIT"}
authors = [{name = "Lochan", email = "lochan@seqrlabs.com"}]
keywords = ["post-quantum", "cryptography", "PQC", "ML-KEM", "ML-DSA", "NIST", "quantum-safe"]
requires-python = ">=3.10"
dependencies = [
    "liboqs-python>=0.11.0",
    "cryptography>=43.0.0",
    "PyJWT>=2.8.0",
]

[project.urls]
Homepage = "https://seqrlabs.com/sdk"
Repository = "https://github.com/seqrlabs/pqcmap"
Documentation = "https://docs.seqrlabs.com/sdk"
```

---

## Migration Guide (What Docs Must Include)

### Step 1: Find vulnerabilities
```bash
pip install seqr
seqr scan code ./src --output json --save findings.json
```

### Step 2: Install pqcmap
```bash
pip install pqcmap
```

### Step 3: Replace JWT signing (most common)
```python
# Before (PyJWT RS256)
import jwt
token = jwt.encode({'user_id': '123'}, rsa_private_key, algorithm='RS256')

# After (pqcmap ML-DSA-65)
from pqcmap.jwt import PQCToken
from pqcmap.kms.local import LocalKeyStore
ks = LocalKeyStore()
key_id = ks.generate_and_store('ML-DSA-65', metadata={"purpose": "jwt"})
token = PQCToken.encode({'user_id': '123'}, ks.get_private_key(key_id))
data = PQCToken.decode(token, ks.get_public_key(key_id))
```

### Hybrid mode (recommended for 2026-2030 transition)
```python
from pqcmap import HybridKEM
kem = HybridKEM()   # X25519 + ML-KEM-768 combined
keypair = kem.generate_keypair()
ciphertext, secret = kem.encapsulate(keypair.public_key)
```

---

## Performance Benchmarks (Expected)

| Operation | ML-KEM-768 | ML-DSA-65 | RSA-2048 comparison |
|---|---|---|---|
| Key generation | ~0.1ms | ~0.1ms | RSA: ~100ms (1000x slower) |
| Sign/Encap | ~0.1ms | ~0.1ms | RSA sign: ~2ms |
| Verify/Decap | ~0.1ms | ~0.05ms | RSA verify: ~0.05ms (similar) |

| Size | ML-KEM-768 | ML-DSA-65 | RSA-2048 comparison |
|---|---|---|---|
| Public key | 1,184 bytes | 1,952 bytes | RSA: 294 bytes PEM |
| Private key | 2,400 bytes | 4,000 bytes | RSA: 1,679 bytes PEM |
| Ciphertext/Signature | 1,088 bytes | 3,309 bytes | RSA: 256 bytes |

**MTU note:** ML-KEM public keys (1,184 bytes) may cause TLS handshake fragmentation.
Add note to docs: "Test with large ClientHello before production rollout."

---

## Error Class Hierarchy

```python
class PQCError(Exception): pass
class UnsupportedAlgorithmError(PQCError): pass
class KeySizeError(PQCError): pass
class SignatureVerificationError(PQCError): pass
class PQCTokenExpiredError(PQCError): pass
class PQCTokenInvalidError(PQCError): pass
class KMSError(PQCError): pass
class KMSKeyNotFoundError(KMSError): pass
class KMSAuthError(KMSError): pass
```

---

## Build Prerequisites

Before building pqcmap:
```bash
# Verify liboqs-python installs correctly
python -c "import oqs; kem = oqs.KeyEncapsulation('ML-KEM-768'); print('liboqs OK')"
```

If this fails: liboqs C library not installed. Use pre-built wheels from PyPI
or install via: `brew install liboqs` (macOS) / `apt install liboqs-dev` (Ubuntu).
