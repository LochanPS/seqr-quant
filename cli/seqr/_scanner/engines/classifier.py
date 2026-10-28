"""
Algorithm → vulnerability classification engine.
Single source of truth for quantum risk scoring used by network scanner,
code scanner, and risk engine.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class AlgorithmClassification:
    quantum_status: str       # vulnerable | safe | deprecated | unknown
    algorithm_risk: int       # 0-10
    algorithm_family: str     # RSA | ECC | AES | DH | ML-KEM | ML-DSA | SLH-DSA | SHA | TLS
    hndl_candidate: bool      # True = used for key exchange or long-term encryption
    notes: str = ""


# ---------------------------------------------------------------------------
# Classification table — exact scores from PRD
# ---------------------------------------------------------------------------

_CERT_ALGORITHM_TABLE: dict[str, AlgorithmClassification] = {
    # RSA
    "rsa-512":   AlgorithmClassification("deprecated", 10, "RSA", True, "Classically broken"),
    "rsa-768":   AlgorithmClassification("deprecated", 10, "RSA", True, "Classically broken"),
    "rsa-1024":  AlgorithmClassification("deprecated",  9, "RSA", True, "Classically weak"),
    "rsa-2048":  AlgorithmClassification("vulnerable",  8, "RSA", True),
    "rsa-3072":  AlgorithmClassification("vulnerable",  7, "RSA", True),
    "rsa-4096":  AlgorithmClassification("vulnerable",  7, "RSA", True),
    "rsa":       AlgorithmClassification("vulnerable",  8, "RSA", True, "Unknown key size → assume 2048"),

    # ECC / ECDSA / ECDH
    "ecdsa-p256":      AlgorithmClassification("vulnerable", 7, "ECC", True),
    "ecdsa-p384":      AlgorithmClassification("vulnerable", 6, "ECC", True),
    "ecdsa-p521":      AlgorithmClassification("vulnerable", 6, "ECC", True),
    "ecdsa-secp256k1": AlgorithmClassification("vulnerable", 7, "ECC", True),
    "ecdsa":           AlgorithmClassification("vulnerable", 7, "ECC", True, "Unknown curve"),
    "ecdh":            AlgorithmClassification("vulnerable", 7, "ECC", True),
    "ecdh-p256":       AlgorithmClassification("vulnerable", 7, "ECC", True),
    "ecdh-p384":       AlgorithmClassification("vulnerable", 6, "ECC", True),

    # DH / DHE / ECDHE
    "dh":       AlgorithmClassification("vulnerable", 8, "DH",  True),
    "dhe":      AlgorithmClassification("vulnerable", 8, "DH",  True),
    "dh-1024":  AlgorithmClassification("deprecated", 9, "DH",  True, "Too small"),
    "dh-2048":  AlgorithmClassification("vulnerable", 7, "DH",  True),
    "ecdhe":    AlgorithmClassification("vulnerable", 7, "ECC", True, "Ephemeral ECDH — quantum vulnerable"),
    "ecdhe-rsa":   AlgorithmClassification("vulnerable", 7, "ECC", True),
    "ecdhe-ecdsa": AlgorithmClassification("vulnerable", 7, "ECC", True),
    "tls1.3-hkdf": AlgorithmClassification("safe",      0, "TLS", False,
                                             "TLS 1.3 HKDF — safe if key exchange is PQC"),

    # Ed25519 / Ed448 — quantum vulnerable but NOT classically broken
    "ed25519": AlgorithmClassification("vulnerable", 5, "ECC", False,
                                       "Quantum vulnerable via Shor, not classically broken"),
    "ed448":   AlgorithmClassification("vulnerable", 5, "ECC", False,
                                       "Quantum vulnerable via Shor, not classically broken"),
    "x25519":  AlgorithmClassification("vulnerable", 5, "ECC", True),

    # AES
    "aes-128": AlgorithmClassification("vulnerable", 2, "AES", False,
                                       "Grover halves effective key; 64-bit quantum security"),
    "aes-192": AlgorithmClassification("safe",       0, "AES", False),
    "aes-256": AlgorithmClassification("safe",       0, "AES", False),

    # SHA
    "sha-1":   AlgorithmClassification("deprecated", 10, "SHA", False, "Classically broken"),
    "sha-256": AlgorithmClassification("safe",        0, "SHA", False),
    "sha-384": AlgorithmClassification("safe",        0, "SHA", False),
    "sha-512": AlgorithmClassification("safe",        0, "SHA", False),
    "sha3-256": AlgorithmClassification("safe",       0, "SHA", False),
    "sha3-384": AlgorithmClassification("safe",       0, "SHA", False),
    "sha3-512": AlgorithmClassification("safe",       0, "SHA", False),

    # NIST PQC — SAFE
    "ml-kem-512":  AlgorithmClassification("safe", 0, "ML-KEM", True,  "FIPS 203 Level 1"),
    "ml-kem-768":  AlgorithmClassification("safe", 0, "ML-KEM", True,  "FIPS 203 Level 3"),
    "ml-kem-1024": AlgorithmClassification("safe", 0, "ML-KEM", True,  "FIPS 203 Level 5"),
    "ml-dsa-44":   AlgorithmClassification("safe", 0, "ML-DSA", False, "FIPS 204 Level 2"),
    "ml-dsa-65":   AlgorithmClassification("safe", 0, "ML-DSA", False, "FIPS 204 Level 3"),
    "ml-dsa-87":   AlgorithmClassification("safe", 0, "ML-DSA", False, "FIPS 204 Level 5"),
    "slh-dsa":     AlgorithmClassification("safe", 0, "SLH-DSA", False, "FIPS 205"),
    "slh-dsa-sha2-128f": AlgorithmClassification("safe", 0, "SLH-DSA", False, "FIPS 205"),
    "slh-dsa-sha2-256f": AlgorithmClassification("safe", 0, "SLH-DSA", False, "FIPS 205"),

    # Hybrid PQC — X25519 based
    "x25519kyber768":   AlgorithmClassification("safe", 0, "ML-KEM", True,  "Hybrid X25519+ML-KEM-768"),
    "x25519mlkem768":   AlgorithmClassification("safe", 0, "ML-KEM", True,  "Hybrid X25519+ML-KEM-768"),
    "mlkem768x25519":   AlgorithmClassification("safe", 0, "ML-KEM", True,  "Hybrid ML-KEM-768+X25519"),
    "x25519kyber512":   AlgorithmClassification("safe", 0, "ML-KEM", True,  "Hybrid X25519+ML-KEM-512"),
    # Hybrid PQC — NIST P-curve based (AWS, OpenSSL provider, BoringSSL use these)
    "secp256r1mlkem768":  AlgorithmClassification("safe", 0, "ML-KEM", True, "Hybrid P-256+ML-KEM-768"),
    "p256mlkem768":       AlgorithmClassification("safe", 0, "ML-KEM", True, "Hybrid P-256+ML-KEM-768"),
    "secp256r1kyber768":  AlgorithmClassification("safe", 0, "ML-KEM", True, "Hybrid P-256+ML-KEM-768"),
    "secp384r1mlkem1024": AlgorithmClassification("safe", 0, "ML-KEM", True, "Hybrid P-384+ML-KEM-1024"),
    "p384mlkem1024":      AlgorithmClassification("safe", 0, "ML-KEM", True, "Hybrid P-384+ML-KEM-1024"),
    "secp521r1mlkem1024": AlgorithmClassification("safe", 0, "ML-KEM", True, "Hybrid P-521+ML-KEM-1024"),
    # Pure / pre-standard Kyber (ML-KEM)
    "kyber512":         AlgorithmClassification("safe", 0, "ML-KEM", True,  "Pre-standard Kyber (ML-KEM)"),
    "kyber768":         AlgorithmClassification("safe", 0, "ML-KEM", True,  "Pre-standard Kyber (ML-KEM)"),
    "kyber1024":        AlgorithmClassification("safe", 0, "ML-KEM", True,  "Pre-standard Kyber (ML-KEM)"),
}

_TLS_VERSION_TABLE: dict[str, AlgorithmClassification] = {
    "tls_1_0": AlgorithmClassification("deprecated", 9, "TLS", False, "Deprecated by RFC 8996"),
    "tls_1_1": AlgorithmClassification("deprecated", 9, "TLS", False, "Deprecated by RFC 8996"),
    "tls_1_2": AlgorithmClassification("vulnerable", 4, "TLS", False,
                                        "Safe when combined with good cipher suite"),
    "tls_1_3": AlgorithmClassification("safe", 0, "TLS", False,
                                        "Check key exchange algorithm specifically"),
    "ssl_2_0": AlgorithmClassification("deprecated", 10, "TLS", False, "Classically broken"),
    "ssl_3_0": AlgorithmClassification("deprecated", 10, "TLS", False, "POODLE attack"),
}


def _normalise_algorithm_name(algorithm: str) -> str:
    """Normalise to lowercase key matching the classification table."""
    a = algorithm.lower().strip()
    # Strip spaces and dashes inconsistency
    a = a.replace(" ", "-")
    # Handle OpenSSL / sslyze naming conventions
    replacements = {
        "ec":            "ecdsa",
        "ecpublickey":   "ecdsa",
        "prime256v1":    "ecdsa-p256",
        "secp384r1":     "ecdsa-p384",
        "secp521r1":     "ecdsa-p521",
        "secp256k1":     "ecdsa-secp256k1",
        "nistp256":      "ecdsa-p256",
        "nistp384":      "ecdsa-p384",
        "nistp521":      "ecdsa-p521",
        "rsaencryption": "rsa",
        "rsa-pss":       "rsa",
    }
    return replacements.get(a, a)


def _normalise_rsa_key_size(key_size: Optional[int]) -> str:
    """Return canonical rsa-NNNN key for lookup."""
    if key_size is None:
        return "rsa"
    if key_size <= 512:
        return "rsa-512"
    if key_size <= 768:
        return "rsa-768"
    if key_size <= 1024:
        return "rsa-1024"
    if key_size <= 2048:
        return "rsa-2048"
    if key_size <= 3072:
        return "rsa-3072"
    return "rsa-4096"


def classify_algorithm(
    algorithm: str,
    key_size: Optional[int] = None,
) -> AlgorithmClassification:
    """
    Map an algorithm name (as returned by sslyze / cryptography library) to
    an AlgorithmClassification.

    Args:
        algorithm: Algorithm name string. Case-insensitive.
        key_size:  Key size in bits (important for RSA and DH classification).

    Returns:
        AlgorithmClassification with quantum_status, algorithm_risk, etc.
    """
    normalised = _normalise_algorithm_name(algorithm)

    # RSA: score depends on key size
    if normalised in ("rsa", "rsaencryption", "rsa-pss") or normalised.startswith("rsa-"):
        key = _normalise_rsa_key_size(key_size)
        return _CERT_ALGORITHM_TABLE.get(key, _CERT_ALGORITHM_TABLE["rsa"])

    # DH with key size
    if normalised in ("dh", "dhe") and key_size is not None:
        if key_size < 2048:
            return _CERT_ALGORITHM_TABLE["dh-1024"]
        return _CERT_ALGORITHM_TABLE["dh-2048"]

    result = _CERT_ALGORITHM_TABLE.get(normalised)
    if result is not None:
        return result

    # Unknown algorithm
    return AlgorithmClassification(
        quantum_status="unknown",
        algorithm_risk=5,
        algorithm_family="UNKNOWN",
        hndl_candidate=False,
        notes=f"Unrecognised algorithm: {algorithm}",
    )


def classify_tls_version(tls_version: str) -> AlgorithmClassification:
    """
    Classify a TLS version string.

    Args:
        tls_version: e.g. "TLS_1_2", "TLS_1_3", "TLS 1.0"

    Returns:
        AlgorithmClassification
    """
    normalised = (
        tls_version.lower()
        .strip()
        .replace(".", "_")
        .replace(" ", "_")
        .replace("-", "_")
    )
    # Handle variants like "tls1_2" → "tls_1_2"
    if normalised.startswith("tls") and not normalised.startswith("tls_"):
        normalised = "tls_" + normalised[3:].lstrip("_")

    result = _TLS_VERSION_TABLE.get(normalised)
    if result is not None:
        return result

    return AlgorithmClassification(
        quantum_status="unknown",
        algorithm_risk=5,
        algorithm_family="TLS",
        hndl_candidate=False,
        notes=f"Unrecognised TLS version: {tls_version}",
    )


def recommended_algorithm(algorithm: str) -> tuple[str, str]:
    """
    Return (recommended_algorithm, recommended_fips) for a vulnerable algorithm.

    The PQC target is tiered to the *strength* of the algorithm being replaced,
    so a 4096-bit RSA / P-384 key (NIST security category 5) maps to ML-KEM-1024
    / ML-DSA-87, while a 2048-bit RSA / P-256 key (category 1-3) maps to
    ML-KEM-768 / ML-DSA-65. Recommending the same Level-3 target for everything
    would silently downgrade high-assurance keys.

    Returns:
        (recommended_algorithm_name, fips_standard)
    """
    normalised = _normalise_algorithm_name(algorithm)

    # --- security-category-5 (high assurance) sources → ML-KEM-1024 / ML-DSA-87
    high_assurance = (
        normalised in ("ecdsa-p384", "ecdsa-p521", "ecdh-p384", "ecdh-p521",
                       "ed448", "rsa-4096")
        or normalised.startswith("rsa-3072")
        or normalised.startswith("rsa-4096")
    )

    if normalised.startswith("rsa"):
        # RSA used for signing → ML-DSA; for key exchange → ML-KEM.
        if high_assurance:
            return ("ML-DSA-87 (signing) / ML-KEM-1024 (key exchange)", "FIPS 204 / FIPS 203")
        return ("ML-DSA-65 (signing) / ML-KEM-768 (key exchange)", "FIPS 204 / FIPS 203")

    if normalised in ("ecdsa", "ecdsa-p256", "ecdsa-secp256k1", "ed25519"):
        return ("ML-DSA-65", "FIPS 204")

    if normalised in ("ecdsa-p384", "ecdsa-p521", "ed448"):
        return ("ML-DSA-87", "FIPS 204")

    if normalised in ("ecdh-p384", "ecdh-p521"):
        return ("ML-KEM-1024", "FIPS 203")

    if normalised in ("ecdh", "ecdh-p256", "x25519", "dh", "dhe",
                      "dh-1024", "dh-2048"):
        return ("ML-KEM-768", "FIPS 203")

    if normalised in ("aes-128",):
        return ("AES-256", "NIST SP 800-131A")

    if normalised in ("sha-1",):
        return ("SHA-256", "NIST SP 800-131A")

    if normalised in ("tls_1_0", "tls_1_1"):
        return ("TLS 1.3 with ML-KEM-768 key exchange", "NIST SP 800-131A")

    return ("Consult NIST PQC standards", "FIPS 203/204/205")
