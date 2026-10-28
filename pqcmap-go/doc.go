// Package pqcmap is the Go port of the pqcmap SDK — drop-in NIST post-quantum
// cryptography (ML-KEM / ML-DSA) that replaces RSA, ECDH, and ECDSA in application
// code. It is the code-level arm of the SeQr migration lifecycle: the SeQr scanner
// finds quantum-vulnerable crypto, pqcmap is how you fix it.
//
// The port mirrors the Python pqcmap public API and its invariants: a real crypto
// backend (no mock in the product path) and the same policy model. Crypto is genuine
// FIPS 203/204 via cloudflare/circl.
//
//	kem, _ := pqcmap.NewKeyEncapsulation("")          // ML-KEM-768 by default
//	pk, sk, _ := kem.GenerateKeypair()
//	ct, ss, _ := kem.Encapsulate(pk)
//	ss2, _ := kem.Decapsulate(sk, ct)                 // bytes.Equal(ss, ss2)
//
//	sig, _ := pqcmap.NewSignature("")                 // ML-DSA-65 by default
//	spk, ssk, _ := sig.GenerateKeypair()
//	signature, _ := sig.Sign([]byte("authorize"), ssk)
//	ok, _ := sig.Verify([]byte("authorize"), signature, spk)
//
// STATUS — v0.1, built + verified (SDK-6, Go 1.27 / circl v1.6.1): full parity with the
// Python/JS SDKs — KEM, Signature, HybridKEM, PQCToken (JWT), the policy engine,
// LocalKeyStore, HostedKMS, and the best-effort PQC-hybrid TLS helper are implemented and
// pass `go test ./...`. Cross-language interop is verified end-to-end: the hybrid KDF
// matches the Python/JS SDKs byte-for-byte, a Go-signed ML-DSA JWT verifies in both Python
// and JS, and a Go-written LocalKeyStore reads in Python. See ../PORTS.md.
package pqcmap
