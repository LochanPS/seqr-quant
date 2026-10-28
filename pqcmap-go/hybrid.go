package pqcmap

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// Hybrid KEM: X25519 (classical) + ML-KEM-768 (PQC), combined via HKDF-SHA256.
// Port of the Python/JS pqcmap hybrid — the wire format and KDF match exactly, so a value
// produced here interoperates with the other SDKs (see the parity vector in hybrid_test.go).
//
// Wire format (concatenated, fixed offsets):
//
//	publicKey  = x25519_public(32)           || mlkem768_public(1184)
//	secretKey  = x25519_secret(32)           || mlkem768_secret(2400)
//	ciphertext = x25519_ephemeral_public(32) || mlkem768_ciphertext(1088)
const (
	x25519Len       = 32
	sharedSecretLen = 32 // 256-bit combined secret, ready as an AES-256 key
)

var (
	hkdfSalt = []byte("seqr-hybrid-v1")
	hkdfInfo = "pqcmap hybrid kem X25519+ML-KEM-768"
)

// CombineSecrets derives the final 32-byte shared secret from both halves via HKDF-SHA256.
// Order (classical then PQC) is part of the wire contract and must match on both sides.
func CombineSecrets(classicalSecret, pqcSecret []byte) ([]byte, error) {
	ikm := append(append([]byte{}, classicalSecret...), pqcSecret...)
	return hkdf.Key(sha256.New, ikm, hkdfSalt, hkdfInfo, sharedSecretLen)
}

// HybridKEM is X25519 + ML-KEM-768. Recommended for the 2026-2030 transition: if either
// primitive is broken, the other still protects the shared secret.
type HybridKEM struct {
	kem      *KeyEncapsulation
	curve    ecdh.Curve
	pqcPub   int
	pqcSec   int
	pqcCt    int
}

// NewHybridKEM builds a hybrid KEM (empty pqcAlgorithm == ML-KEM-768).
func NewHybridKEM(pqcAlgorithm string) (*HybridKEM, error) {
	if pqcAlgorithm == "" {
		pqcAlgorithm = MLKEM768
	}
	kem, err := NewKeyEncapsulation(pqcAlgorithm)
	if err != nil {
		return nil, err
	}
	return &HybridKEM{
		kem:    kem,
		curve:  ecdh.X25519(),
		pqcPub: kem.meta.PublicKeyBytes,
		pqcSec: kem.meta.SecretKeyBytes,
		pqcCt:  kem.meta.OutputBytes,
	}, nil
}

// GenerateKeypair returns concatenated (publicKey, secretKey).
func (h *HybridKEM) GenerateKeypair() (publicKey, secretKey []byte, err error) {
	xPriv, err := h.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPQC, err)
	}
	pqcPub, pqcSec, err := h.kem.GenerateKeypair()
	if err != nil {
		return nil, nil, err
	}
	publicKey = append(append([]byte{}, xPriv.PublicKey().Bytes()...), pqcPub...)
	secretKey = append(append([]byte{}, xPriv.Bytes()...), pqcSec...)
	return publicKey, secretKey, nil
}

// Encapsulate returns (ciphertext, sharedSecret) for the peer's hybrid publicKey.
func (h *HybridKEM) Encapsulate(publicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(publicKey) != x25519Len+h.pqcPub {
		return nil, nil, fmt.Errorf("%w: hybrid public key must be %d bytes, got %d", ErrKeySize, x25519Len+h.pqcPub, len(publicKey))
	}
	xPeerBytes, pqcPeer := publicKey[:x25519Len], publicKey[x25519Len:]

	xPeer, err := h.curve.NewPublicKey(xPeerBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	eph, err := h.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPQC, err)
	}
	classicalSecret, err := eph.ECDH(xPeer)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPQC, err)
	}
	pqcCt, pqcSecret, err := h.kem.Encapsulate(pqcPeer)
	if err != nil {
		return nil, nil, err
	}
	shared, err := CombineSecrets(classicalSecret, pqcSecret)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = append(append([]byte{}, eph.PublicKey().Bytes()...), pqcCt...)
	return ciphertext, shared, nil
}

// Decapsulate recovers the shared secret from a hybrid ciphertext.
func (h *HybridKEM) Decapsulate(secretKey, ciphertext []byte) ([]byte, error) {
	if len(secretKey) != x25519Len+h.pqcSec {
		return nil, fmt.Errorf("%w: hybrid secret key must be %d bytes, got %d", ErrKeySize, x25519Len+h.pqcSec, len(secretKey))
	}
	if len(ciphertext) != x25519Len+h.pqcCt {
		return nil, fmt.Errorf("%w: hybrid ciphertext must be %d bytes, got %d", ErrKeySize, x25519Len+h.pqcCt, len(ciphertext))
	}
	xPrivBytes, pqcPriv := secretKey[:x25519Len], secretKey[x25519Len:]
	ephPubBytes, pqcCt := ciphertext[:x25519Len], ciphertext[x25519Len:]

	xPriv, err := h.curve.NewPrivateKey(xPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	ephPub, err := h.curve.NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	classicalSecret, err := xPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPQC, err)
	}
	pqcSecret, err := h.kem.Decapsulate(pqcPriv, pqcCt)
	if err != nil {
		return nil, err
	}
	return CombineSecrets(classicalSecret, pqcSecret)
}
