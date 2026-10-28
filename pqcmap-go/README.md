# pqcmap-go

**Post-quantum cryptography for Go developers.** Drop-in NIST PQC (ML-KEM / ML-DSA) that
replaces RSA, ECDH, and ECDSA — the Go port of the Python [`pqcmap`](https://pypi.org/project/pqcmap/)
SDK, with the same public API shape, the same real-backend model, and (once complete) the
same policy engine. The code-level arm of the [SeQr](https://seqrlabs.com) migration
lifecycle: the scanner *finds* quantum-vulnerable crypto, pqcmap is how you *fix* it.

Crypto is genuine FIPS 203/204 via [`cloudflare/circl`](https://github.com/cloudflare/circl).

> **Status: v0.1 — built + verified** (Go 1.27 / circl v1.6.1). `go test ./...` passes.
> Cross-language interop verified: the hybrid KDF matches the Python/JS SDKs byte-for-byte,
> and a Go-signed ML-DSA JWT verifies in both Python and JS.
>
> ```bash
> cd pqcmap-go
> go test ./...
> go run ./examples/jwt_demo    # prints a token the Python/JS SDKs can verify
> ```

## What's here

| File | Status |
|---|---|
| `algorithms.go` | ✅ algorithm constants + `Meta()` (identical FIPS sizes) |
| `errors.go` | ✅ sentinel error family, all wrapping `ErrPQC` (use `errors.Is`) |
| `kem.go` | ✅ `KeyEncapsulation` (ML-KEM) via circl `kem.Scheme` |
| `sign.go` | ✅ `Signature` (ML-DSA) via circl `sign.Scheme` |
| `hybrid.go` | ✅ `HybridKEM` — X25519 (stdlib `crypto/ecdh`) + ML-KEM-768, HKDF-SHA256 |
| `jwt.go` | ✅ `EncodeToken` / `DecodeToken` (ML-DSA JWT, canonical JSON) |
| `policy.go` | ✅ `CryptoPolicy`, `AssertCompliant`, `NewCompliant{KeyEncapsulation,Signature}` |
| `keystore.go` | ✅ `LocalKeyStore` — AES-256-GCM at rest, rotation, export/import, audit log (interoperable with Python) |
| `hosted.go` | ✅ `HostedKMS` — envelope encryption, pluggable transport (same wire format) |
| `tls.go` | ✅ best-effort PQC-hybrid TLS (`X25519MLKEM768` via stdlib crypto/tls, Go 1.24+) |

## Intended usage

```go
import pqcmap "github.com/LochanPS/SeQr-Labs/pqcmap-go"

kem, _ := pqcmap.NewKeyEncapsulation("")     // ML-KEM-768 by default
pk, sk, _ := kem.GenerateKeypair()
ct, ss, _ := kem.Encapsulate(pk)             // sender
ss2, _ := kem.Decapsulate(sk, ct)            // receiver; bytes.Equal(ss, ss2)

sig, _ := pqcmap.NewSignature("")            // ML-DSA-65 by default
spk, ssk, _ := sig.GenerateKeypair()
signature, _ := sig.Sign([]byte("authorize"), ssk)
ok, _ := sig.Verify([]byte("authorize"), signature, spk)
```

## API parity

Same concepts as Python/Node, in Go idiom: exported `PascalCase` methods, multiple returns,
`(value, error)` where fallible. The error family maps the Python exception hierarchy to
Go sentinels (`errors.Is(err, pqcmap.ErrPQC)` catches the whole family, the analogue of
`except PQCError`). See [`../PORTS.md`](../PORTS.md) for the full mapping and the byte-level
interop contracts (hybrid KDF, JWT wire format, policy shape).

## License

MIT.
