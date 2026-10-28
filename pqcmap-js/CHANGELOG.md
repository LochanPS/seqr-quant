# Changelog

All notable changes to **@seqr/pqc** (the npm port of `pqcmap`) are documented
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-20

First public release. Full parity with the Python `pqcmap` 0.2.0 surface,
backed by real NIST PQC via `@noble/post-quantum`.

### Added
- Core primitives: `KeyEncapsulation` (ML-KEM), `Signature` (ML-DSA),
  `HybridKEM` (X25519 + ML-KEM-768), `PQCToken` (ML-DSA-signed JWTs), and
  `LocalKeyStore` (AES-256-GCM at rest, interoperable on-disk format).
- `@seqr/pqc/jwt` — PyJWT-shaped `encode` / `decode` surface so an RS256 JWT
  migrates to ML-DSA by changing only the import.
- `@seqr/pqc/tls` — best-effort PQC-hybrid TLS (X25519MLKEM768 on OpenSSL 3.5+),
  with an honest runtime capability probe.
- Policy engine (`compliant.KeyEncapsulation` / `Signature`) that loads the SeQr
  platform-spine `{"rules": [...]}` shape and rejects below-policy algorithms.
- `HostedKMS` client, algorithm metadata, and TypeScript types (`index.d.ts`).
- Cross-language interop with the Python and Go ports: shared KDF, and ML-DSA
  JWTs / keystores that verify across all three languages.
