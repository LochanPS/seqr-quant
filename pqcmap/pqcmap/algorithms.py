"""Algorithm constants and metadata for the NIST FIPS 203/204/205 PQC standards.

These names match the strings liboqs expects (``ML-KEM-768``, ``ML-DSA-65`` …), so
they can be passed straight through to the backend. ``ALGORITHM_META`` carries the
FIPS reference, NIST security level, and on-the-wire sizes documented in
``docs/02_SDK_PRD.md`` — useful for MTU / storage planning without instantiating the
crypto backend.
"""
from __future__ import annotations

from dataclasses import dataclass


class KEMAlgorithm:
    """Key-encapsulation (KEM) algorithm names — replace RSA/ECDH key exchange."""

    ML_KEM_512 = "ML-KEM-512"   # FIPS 203, NIST Level 1
    ML_KEM_768 = "ML-KEM-768"   # FIPS 203, NIST Level 3 — DEFAULT
    ML_KEM_1024 = "ML-KEM-1024"  # FIPS 203, NIST Level 5


class SignAlgorithm:
    """Digital-signature algorithm names — replace RSA-sign and ECDSA."""

    ML_DSA_44 = "ML-DSA-44"    # FIPS 204, NIST Level 2
    ML_DSA_65 = "ML-DSA-65"    # FIPS 204, NIST Level 3 — DEFAULT
    ML_DSA_87 = "ML-DSA-87"    # FIPS 204, NIST Level 5
    SLH_DSA_SHA2_128F = "SLH-DSA-SHA2-128f"  # FIPS 205, hash-based backup


# Sensible defaults — NIST Level 3, the recommended baseline for new systems.
DEFAULT_KEM = KEMAlgorithm.ML_KEM_768
DEFAULT_SIGN = SignAlgorithm.ML_DSA_65


@dataclass(frozen=True)
class AlgorithmMeta:
    name: str
    kind: str            # "kem" | "sign"
    fips: str            # e.g. "FIPS 203"
    nist_level: int      # 1..5
    public_key_bytes: int
    secret_key_bytes: int
    # ciphertext (KEM) or signature (sign) size in bytes
    output_bytes: int


# Sizes are the standard FIPS 203/204/205 parameter-set sizes (bytes).
ALGORITHM_META: dict[str, AlgorithmMeta] = {
    KEMAlgorithm.ML_KEM_512: AlgorithmMeta("ML-KEM-512", "kem", "FIPS 203", 1, 800, 1632, 768),
    KEMAlgorithm.ML_KEM_768: AlgorithmMeta("ML-KEM-768", "kem", "FIPS 203", 3, 1184, 2400, 1088),
    KEMAlgorithm.ML_KEM_1024: AlgorithmMeta("ML-KEM-1024", "kem", "FIPS 203", 5, 1568, 3168, 1568),
    SignAlgorithm.ML_DSA_44: AlgorithmMeta("ML-DSA-44", "sign", "FIPS 204", 2, 1312, 2560, 2420),
    SignAlgorithm.ML_DSA_65: AlgorithmMeta("ML-DSA-65", "sign", "FIPS 204", 3, 1952, 4032, 3309),
    SignAlgorithm.ML_DSA_87: AlgorithmMeta("ML-DSA-87", "sign", "FIPS 204", 5, 2592, 4896, 4627),
    SignAlgorithm.SLH_DSA_SHA2_128F: AlgorithmMeta(
        "SLH-DSA-SHA2-128f", "sign", "FIPS 205", 1, 32, 64, 17088
    ),
}

KEM_ALGORITHMS = frozenset(
    a for a, m in ALGORITHM_META.items() if m.kind == "kem"
)
SIGN_ALGORITHMS = frozenset(
    a for a, m in ALGORITHM_META.items() if m.kind == "sign"
)


def meta(algorithm: str) -> AlgorithmMeta:
    """Return metadata for ``algorithm`` or raise :class:`UnsupportedAlgorithmError`."""
    from pqcmap.core.exceptions import UnsupportedAlgorithmError

    try:
        return ALGORITHM_META[algorithm]
    except KeyError as exc:
        raise UnsupportedAlgorithmError(
            f"Unknown algorithm {algorithm!r}. "
            f"Known: {', '.join(sorted(ALGORITHM_META))}."
        ) from exc


# Backwards-friendly umbrella accessor used in the PRD's public API sketch.
class Algorithm:
    """Namespace re-export so ``from pqcmap import Algorithm`` reaches both families."""

    KEM = KEMAlgorithm
    Sign = SignAlgorithm
    DEFAULT_KEM = DEFAULT_KEM
    DEFAULT_SIGN = DEFAULT_SIGN
