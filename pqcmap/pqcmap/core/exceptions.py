"""pqcmap exception hierarchy.

Every error pqcmap raises derives from :class:`PQCError`, so callers can catch the
whole family with a single ``except PQCError``.
"""
from __future__ import annotations


class PQCError(Exception):
    """Base class for every pqcmap error."""


class PQCUnavailableError(PQCError):
    """The liboqs post-quantum backend is not usable in this environment.

    Raised when the ``oqs`` module cannot be imported, or when its native shared
    library failed to load (e.g. liboqs was never built for this platform). The
    message carries install guidance. Pure-classical helpers (LocalKeyStore, the
    X25519 half of hybrid mode, encoding utilities) do not raise this.
    """


class UnsupportedAlgorithmError(PQCError):
    """An algorithm name was passed that pqcmap / liboqs does not support."""


class KeySizeError(PQCError):
    """A key or ciphertext had an unexpected length for the chosen algorithm."""


class SignatureVerificationError(PQCError):
    """A signature failed verification."""


class PQCTokenError(PQCError):
    """Base for token (JWT) errors."""


class PQCTokenExpiredError(PQCTokenError):
    """The token's ``exp`` claim is in the past."""


class PQCTokenInvalidError(PQCTokenError):
    """The token is malformed or its signature does not verify."""


class PQCTokenSignatureError(PQCTokenInvalidError):
    """The token is well-formed but its signature does not verify.

    A narrower :class:`PQCTokenInvalidError` (still caught by ``except
    PQCTokenInvalidError``) that lets the PyJWT-shaped adapter distinguish a bad
    signature from a merely malformed token.
    """


class PolicyViolationError(PQCError):
    """An algorithm (or key) is below the active crypto policy.

    Raised by :func:`pqcmap.policy.assert_compliant`, the ``@requires_pqc`` guard, and
    the policy-checked constructors in :mod:`pqcmap.compliant` when application code
    would otherwise use crypto weaker than the policy allows (e.g. a quantum-vulnerable
    family, or a PQC parameter set below the required NIST level).

    Carries the offending ``algorithm`` and the ranked list of :class:`Violation`
    objects on ``.violations`` so callers can inspect exactly which rules failed.
    """

    def __init__(self, message: str, *, algorithm: str = "", violations=()):
        super().__init__(message)
        self.algorithm = algorithm
        self.violations = list(violations)


class KMSError(PQCError):
    """Base for key-store / KMS errors."""


class KMSKeyNotFoundError(KMSError):
    """No key with the requested id exists in the store."""


class KMSAuthError(KMSError):
    """The passphrase (or hosted-KMS credential) was rejected."""
