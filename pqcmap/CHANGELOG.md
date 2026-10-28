# Changelog

All notable changes to **pqcmap** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-20

### Added
- **Docs, benchmarks & worked example (SDK-5).**
  - `docs/COOKBOOK.md` — a migration cookbook with before→after recipes for RS256/ES256
    JWT, RSA signatures, ECDSA, ECDH/X25519 key agreement, and RSA-OAEP encryption, each
    keyed to the SeQr scanner's finding ids. Every "after" snippet is executed for real by
    `examples/cookbook_recipes.py` and guarded by `tests/test_cookbook_recipes.py`.
  - `benchmarks/benchmark.py` — real, live-timed keygen/encap/decap/sign/verify for every
    installed backend (pure-python always; liboqs when present) plus a classical RSA-2048
    baseline. Human table, JSON, and Markdown output; a committed snapshot in
    `docs/BENCHMARKS.md`.
  - `examples/worked_migration/` — the end-to-end loop: `seqr scan code` flags a small
    RS256/RSA auth service, pqcmap migrates it to ML-DSA-65, and a re-scan comes back clean
    (guarded by `tests/test_worked_migration.py`).
- **Key management (`pqcmap.kms`).**
  - `pqcmap.kms.hosted.HostedKMS` — the hosted KMS client: bearer-authenticated calls to
    a SeQr KMS, envelope encryption of data keys under a KMS-held master key, key-id
    addressing, self-describing `encrypt()`/`decrypt()` blobs, and status→error mapping
    (401/403 → `KMSAuthError`, 404 → `KMSKeyNotFoundError`, else `KMSError`). Pluggable
    transport (default: urllib over pqcmap's PQC-hybrid TLS) so tests mock the HTTP.
  - `LocalKeyStore` hardening: `RotationPolicy` (age/usage, persisted); `get_private_key`
    usage counting + `needs_rotation` / `rotate_if_needed`; `export_key` / `import_key`
    (single-key portable passphrase-encrypted blob); an append-only, hash-chained,
    tamper-evident audit log (`read_audit_log` / `verify_audit_log`). On-disk schema v2
    (legacy v1 files still load).
- **Framework drop-ins (JWT / TLS / HTTP).**
  - `pqcmap.jwt` PyJWT-shaped surface: `encode` / `decode` / `get_unverified_header` and
    PyJWT-named exceptions (`ExpiredSignatureError`, `InvalidSignatureError`,
    `DecodeError`, `InvalidAlgorithmError`, all also `PQCTokenError`), so an RS256 JWT
    migrates to ML-DSA by changing only the import. `decode()` enforces the `algorithms`
    allow-list. Runnable `examples/fastapi_auth.py`.
  - `pqcmap.tls` best-effort PQC-hybrid TLS: `build_client_context()` negotiates
    X25519MLKEM768 when the runtime supports it (OpenSSL 3.5+ / liboqs oqs-provider,
    Python 3.13+ `set_groups`) and degrades cleanly to classical TLS 1.3 otherwise;
    `capabilities()` / `report()` give an honest runtime probe.
  - `pqcmap.tls.http` helpers `pqc_httpx_client()` / `pqc_requests_session()` build HTTP
    clients on that context (httpx / requests optional). Documents the ML-KEM ClientHello
    MTU/fragmentation caveat. Runnable `examples/tls_client.py`.
  - Core: `PQCToken.encode(headers=…)` and a narrower `PQCTokenSignatureError`.
- **Policy enforcement (`pqcmap.policy` + `pqcmap.compliant`).** Load a crypto policy in
  the SeQr platform-spine `{"rules": [...]}` shape and enforce it in application code:
  `assert_compliant(algorithm)`, the `@requires_pqc` guard for key-minting / signing
  functions, and policy-checked constructors `pqcmap.compliant.KeyEncapsulation` /
  `Signature` that raise `PolicyViolationError` for a below-policy algorithm. Ships an
  opinionated default (no quantum-vulnerable families; NIST Level 3+). Reuses the spine's
  `family_in` / `family_not_in` / `min_key_size` rule vocabulary and adds `min_nist_level`.
- `py.typed` marker — pqcmap now ships PEP 561 inline type information.
- MIT `LICENSE` file and full PyPI metadata (classifiers, project URLs).
- GitHub Actions release pipeline: test matrix (Linux/macOS/Windows × Python
  3.10–3.12 on the real PQC backend) plus a tag-gated build → TestPyPI dry-run →
  PyPI trusted-publishing (OIDC, no stored token) flow.

## [0.1.0] - 2026-08-20

### Added
- Core primitives: `KeyEncapsulation` (ML-KEM), `Signature` (ML-DSA), `HybridKEM`
  (X25519 + ML-KEM-768), `PQCToken` (ML-DSA-signed JWTs), and `LocalKeyStore`
  (AES-256-GCM at rest, PBKDF2-HMAC-SHA256).
- Real FIPS 203/204 crypto via the pure-Python `kyber-py` + `dilithium-py` backend,
  with an optional faster `liboqs` backend (`pip install pqcmap[liboqs]`).
- Runtime backend probe: `pqcmap.available()` / `pqcmap.backend()`.
- Algorithm metadata (`pqcmap.algorithms`) with FIPS reference, NIST level, and
  on-the-wire sizes.
