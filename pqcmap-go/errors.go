package pqcmap

import (
	"errors"
	"fmt"
)

// Error family — the Go-idiomatic mapping of the Python pqcmap exception hierarchy.
// Go favours sentinel errors + wrapping over class inheritance, so callers use
// errors.Is(err, ErrUnsupportedAlgorithm) rather than type assertions. Every error here
// wraps ErrPQC, so errors.Is(err, ErrPQC) catches the whole family (the analogue of
// `except PQCError`).
var (
	// ErrPQC is the root of the family; every other pqcmap error wraps it.
	ErrPQC = errors.New("pqcmap error")

	// ErrUnavailable — no usable PQC backend (should not happen; circl is compiled in).
	ErrUnavailable = wrap("no PQC backend available")
	// ErrUnsupportedAlgorithm — unknown algorithm, or wrong family for the operation.
	ErrUnsupportedAlgorithm = wrap("unsupported algorithm")
	// ErrKeySize — a key / ciphertext / signature has the wrong length for its algorithm.
	ErrKeySize = wrap("wrong key/ciphertext/signature size")
	// ErrSignatureVerification — a signature failed to verify.
	ErrSignatureVerification = wrap("signature verification failed")
	// ErrPolicyViolation — an algorithm is below the active crypto policy.
	ErrPolicyViolation = wrap("crypto policy violation")
	// ErrTokenExpired — a token has a valid signature but a passed exp.
	ErrTokenExpired = wrap("token has expired")
	// ErrTokenInvalid — a token is malformed or its signature did not verify.
	ErrTokenInvalid = wrap("invalid token")
	// ErrKMS — a hosted-KMS operation failed.
	ErrKMS = wrap("kms error")
	// ErrKMSKeyNotFound — the KMS could not find the referenced key.
	ErrKMSKeyNotFound = wrap("kms key not found")
	// ErrKMSAuth — the KMS rejected the credentials.
	ErrKMSAuth = wrap("kms authentication failed")
)

// wrap builds a family error that reports as ErrPQC under errors.Is.
func wrap(msg string) error {
	return fmt.Errorf("%w: %s", ErrPQC, msg)
}
