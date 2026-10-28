package pqcmap

import (
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// kemSchemes maps an algorithm name to its circl KEM scheme.
var kemSchemes = map[string]kem.Scheme{
	MLKEM512:  mlkem512.Scheme(),
	MLKEM768:  mlkem768.Scheme(),
	MLKEM1024: mlkem1024.Scheme(),
}

// KeyEncapsulation is the drop-in replacement for RSA/ECDH key exchange (default
// ML-KEM-768). Stateless: keys are passed in per call, so it composes with a key store.
// Mirrors the Python pqcmap.core.kem.KeyEncapsulation.
type KeyEncapsulation struct {
	Algorithm string
	scheme    kem.Scheme
	meta      AlgorithmMeta
}

// NewKeyEncapsulation builds a KEM for algorithm (empty string == ML-KEM-768).
func NewKeyEncapsulation(algorithm string) (*KeyEncapsulation, error) {
	if algorithm == "" {
		algorithm = DefaultKEM
	}
	scheme, ok := kemSchemes[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a KEM algorithm", ErrUnsupportedAlgorithm, algorithm)
	}
	m, _ := Meta(algorithm)
	return &KeyEncapsulation{Algorithm: algorithm, scheme: scheme, meta: m}, nil
}

// GenerateKeypair returns fresh (publicKey, secretKey) as raw bytes.
func (k *KeyEncapsulation) GenerateKeypair() (publicKey, secretKey []byte, err error) {
	pk, sk, err := k.scheme.GenerateKeyPair()
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

// Encapsulate returns (ciphertext, sharedSecret) for the recipient's publicKey. Send
// ciphertext to the recipient; use sharedSecret (32 bytes) as an AES-256 key.
func (k *KeyEncapsulation) Encapsulate(publicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(publicKey) != k.meta.PublicKeyBytes {
		return nil, nil, fmt.Errorf("%w: public key for %s must be %d bytes, got %d",
			ErrKeySize, k.Algorithm, k.meta.PublicKeyBytes, len(publicKey))
	}
	pk, err := k.scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	ciphertext, sharedSecret, err = k.scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPQC, err)
	}
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext using secretKey.
func (k *KeyEncapsulation) Decapsulate(secretKey, ciphertext []byte) ([]byte, error) {
	if len(secretKey) != k.meta.SecretKeyBytes {
		return nil, fmt.Errorf("%w: secret key for %s must be %d bytes, got %d",
			ErrKeySize, k.Algorithm, k.meta.SecretKeyBytes, len(secretKey))
	}
	if len(ciphertext) != k.meta.OutputBytes {
		return nil, fmt.Errorf("%w: ciphertext for %s must be %d bytes, got %d",
			ErrKeySize, k.Algorithm, k.meta.OutputBytes, len(ciphertext))
	}
	sk, err := k.scheme.UnmarshalBinaryPrivateKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	ss, err := k.scheme.Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPQC, err)
	}
	return ss, nil
}
