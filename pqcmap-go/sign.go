package pqcmap

import (
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// signSchemes maps an algorithm name to its circl signature scheme.
var signSchemes = map[string]sign.Scheme{
	MLDSA44: mldsa44.Scheme(),
	MLDSA65: mldsa65.Scheme(),
	MLDSA87: mldsa87.Scheme(),
}

// Signature is the drop-in replacement for RSA-sign and ECDSA (default ML-DSA-65).
// Mirrors the Python pqcmap.core.sign.Signature.
type Signature struct {
	Algorithm string
	scheme    sign.Scheme
	meta      AlgorithmMeta
}

// NewSignature builds a signer for algorithm (empty string == ML-DSA-65).
func NewSignature(algorithm string) (*Signature, error) {
	if algorithm == "" {
		algorithm = DefaultSign
	}
	scheme, ok := signSchemes[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a signature algorithm", ErrUnsupportedAlgorithm, algorithm)
	}
	m, _ := Meta(algorithm)
	return &Signature{Algorithm: algorithm, scheme: scheme, meta: m}, nil
}

// GenerateKeypair returns fresh (publicKey, secretKey) as raw bytes.
func (s *Signature) GenerateKeypair() (publicKey, secretKey []byte, err error) {
	pk, sk, err := s.scheme.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPQC, err)
	}
	publicKey, err = pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPQC, err)
	}
	secretKey, err = sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPQC, err)
	}
	return publicKey, secretKey, nil
}

// Sign returns the raw signature of message under secretKey.
func (s *Signature) Sign(message, secretKey []byte) ([]byte, error) {
	if len(secretKey) != s.meta.SecretKeyBytes {
		return nil, fmt.Errorf("%w: secret key for %s must be %d bytes, got %d",
			ErrKeySize, s.Algorithm, s.meta.SecretKeyBytes, len(secretKey))
	}
	sk, err := s.scheme.UnmarshalBinaryPrivateKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	return s.scheme.Sign(sk, message, nil), nil
}

// Verify reports whether signature is a valid signature of message under publicKey.
// It returns false (not an error) for a bad signature, matching the Python/JS API.
func (s *Signature) Verify(message, signature, publicKey []byte) (bool, error) {
	if len(publicKey) != s.meta.PublicKeyBytes {
		return false, fmt.Errorf("%w: public key for %s must be %d bytes, got %d",
			ErrKeySize, s.Algorithm, s.meta.PublicKeyBytes, len(publicKey))
	}
	pk, err := s.scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	return s.scheme.Verify(pk, message, signature, nil), nil
}
