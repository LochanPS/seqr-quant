"""pqcmap — post-quantum cryptography for Python developers.

Drop-in NIST PQC (ML-KEM / ML-DSA) primitives that replace RSA / ECDH / ECDSA in
application code. The code-level arm of the SeQr migration lifecycle: the SeQr
scanner *finds* quantum-vulnerable crypto, pqcmap is how you *fix* it.

    from pqcmap import KeyEncapsulation, Signature, HybridKEM, PQCToken, LocalKeyStore

The PQC primitives are backed by liboqs; call :func:`available` to check the backend
is usable in the current environment before relying on it.
"""
from __future__ import annotations

from pqcmap.algorithms import Algorithm, KEMAlgorithm, SignAlgorithm
from pqcmap.core.exceptions import (
    KMSAuthError,
    KMSError,
    KMSKeyNotFoundError,
    KeySizeError,
    PolicyViolationError,
    PQCError,
    PQCTokenExpiredError,
    PQCTokenInvalidError,
    PQCTokenSignatureError,
    PQCUnavailableError,
    SignatureVerificationError,
    UnsupportedAlgorithmError,
)
from pqcmap.core.hybrid import HybridKEM, combine_secrets
from pqcmap.core.kem import KeyEncapsulation
from pqcmap.core.keypair import KeyPair
from pqcmap.core.sign import Signature
from pqcmap.jwt.token import PQCToken
from pqcmap.kms.hosted import HostedKMS
from pqcmap.kms.local import LocalKeyStore
from pqcmap.policy import (
    CryptoPolicy,
    assert_compliant,
    get_active_policy,
    load_policy,
    requires_pqc,
    set_active_policy,
)

__version__ = "0.2.0"


def available() -> bool:
    """True iff a real PQC backend is usable — effectively always.

    pqcmap ships the pure-Python backend (kyber-py + dilithium-py) as a hard
    dependency, so ML-KEM / ML-DSA operations run everywhere with real FIPS crypto.
    Returns False only if those dependencies were forcibly removed.
    """
    from pqcmap._backend import backend_available

    return backend_available()


def backend() -> str | None:
    """Name of the active PQC backend: ``"liboqs"`` (fast, optional) or ``"pure-python"``."""
    from pqcmap._backend import backend_name

    return backend_name()


__all__ = [
    "__version__",
    "available",
    "backend",
    # primitives
    "KeyEncapsulation",
    "Signature",
    "HybridKEM",
    "combine_secrets",
    "KeyPair",
    "PQCToken",
    "LocalKeyStore",
    "HostedKMS",
    # algorithm constants
    "Algorithm",
    "KEMAlgorithm",
    "SignAlgorithm",
    # policy enforcement
    "CryptoPolicy",
    "assert_compliant",
    "requires_pqc",
    "load_policy",
    "get_active_policy",
    "set_active_policy",
    # errors
    "PQCError",
    "PQCUnavailableError",
    "UnsupportedAlgorithmError",
    "KeySizeError",
    "SignatureVerificationError",
    "PolicyViolationError",
    "PQCTokenExpiredError",
    "PQCTokenInvalidError",
    "PQCTokenSignatureError",
    "KMSError",
    "KMSKeyNotFoundError",
    "KMSAuthError",
]
