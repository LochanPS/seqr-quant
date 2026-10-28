package pqcmap

import "fmt"

// KEM algorithm names — replace RSA/ECDH key exchange. Values match the FIPS strings.
const (
	MLKEM512  = "ML-KEM-512"  // FIPS 203, NIST Level 1
	MLKEM768  = "ML-KEM-768"  // FIPS 203, NIST Level 3 — DEFAULT
	MLKEM1024 = "ML-KEM-1024" // FIPS 203, NIST Level 5
)

// Signature algorithm names — replace RSA-sign and ECDSA.
const (
	MLDSA44 = "ML-DSA-44" // FIPS 204, NIST Level 2
	MLDSA65 = "ML-DSA-65" // FIPS 204, NIST Level 3 — DEFAULT
	MLDSA87 = "ML-DSA-87" // FIPS 204, NIST Level 5
)

// Defaults — NIST Level 3, the recommended baseline for new systems.
const (
	DefaultKEM  = MLKEM768
	DefaultSign = MLDSA65
)

// AlgorithmMeta carries the FIPS reference, NIST level, and on-the-wire sizes — a pure-data
// port of the Python pqcmap table (identical values), for MTU / storage planning.
type AlgorithmMeta struct {
	Name           string
	Kind           string // "kem" | "sign"
	FIPS           string
	NISTLevel      int
	PublicKeyBytes int
	SecretKeyBytes int
	OutputBytes    int // ciphertext (KEM) or signature (sign)
}

// algorithmMeta holds the standard FIPS 203/204 parameter-set sizes (bytes).
var algorithmMeta = map[string]AlgorithmMeta{
	MLKEM512:  {MLKEM512, "kem", "FIPS 203", 1, 800, 1632, 768},
	MLKEM768:  {MLKEM768, "kem", "FIPS 203", 3, 1184, 2400, 1088},
	MLKEM1024: {MLKEM1024, "kem", "FIPS 203", 5, 1568, 3168, 1568},
	MLDSA44:   {MLDSA44, "sign", "FIPS 204", 2, 1312, 2560, 2420},
	MLDSA65:   {MLDSA65, "sign", "FIPS 204", 3, 1952, 4032, 3309},
	MLDSA87:   {MLDSA87, "sign", "FIPS 204", 5, 2592, 4896, 4627},
}

// Meta returns metadata for algorithm, or an error wrapping ErrUnsupportedAlgorithm.
func Meta(algorithm string) (AlgorithmMeta, error) {
	m, ok := algorithmMeta[algorithm]
	if !ok {
		return AlgorithmMeta{}, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algorithm)
	}
	return m, nil
}

// Available reports whether a real PQC backend is usable. circl is a compiled-in
// dependency, so this is effectively always true — it exists for API parity with the
// Python/Node SDKs.
func Available() bool { return true }

// Backend returns the active backend name.
func Backend() string { return "circl" }
