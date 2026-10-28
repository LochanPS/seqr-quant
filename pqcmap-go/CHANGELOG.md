# Changelog

All notable changes to **pqcmap-go** (the Go port of `pqcmap`) are documented
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Module path: `github.com/LochanPS/SeQr-Labs/pqcmap-go`.

## [Unreleased]

## [0.2.0] - 2026-09-20

First public release. Full parity with the Python `pqcmap` 0.2.0 surface,
backed by real NIST PQC via `github.com/cloudflare/circl`.

### Added
- Core primitives: KEM (ML-KEM), Signature (ML-DSA), HybridKEM
  (X25519 + ML-KEM-768), ML-DSA-signed JWTs, and `LocalKeyStore` (AES-256-GCM
  at rest, interoperable on-disk format).
- Policy engine that loads the SeQr platform-spine `{"rules": [...]}` shape and
  rejects below-policy algorithms.
- `HostedKMS` client and a PQC-hybrid TLS context builder.
- Cross-language interop with the Python and JS ports: shared KDF, and ML-DSA
  JWTs / keystores that verify across all three languages.
