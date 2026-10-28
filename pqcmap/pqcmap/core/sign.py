"""Digital signatures — the drop-in replacement for RSA-sign and ECDSA.

Default: ML-DSA-65 (FIPS 204, NIST Level 3).

    sig = Signature()                              # ML-DSA-65 by default
    keypair = sig.generate_keypair()
    signature = sig.sign(b"message", keypair.secret_key)
    assert sig.verify(b"message", signature, keypair.public_key)

Like the KEM wrapper, this is stateless: keys are passed in per call, so a signing
key held in a :class:`~pqcmap.kms.local.LocalKeyStore` can be used directly.
"""
from __future__ import annotations

from pqcmap import algorithms
from pqcmap._backend import require_backend
from pqcmap.core.exceptions import KeySizeError, UnsupportedAlgorithmError
from pqcmap.core.keypair import KeyPair


class Signature:
    def __init__(self, algorithm: str = algorithms.DEFAULT_SIGN):
        if algorithm not in algorithms.SIGN_ALGORITHMS:
            raise UnsupportedAlgorithmError(
                f"{algorithm!r} is not a signature algorithm. "
                f"Choose one of: {', '.join(sorted(algorithms.SIGN_ALGORITHMS))}."
            )
        self.algorithm = algorithm
        self._meta = algorithms.meta(algorithm)

    def generate_keypair(self) -> KeyPair:
        public_key, secret_key = require_backend().sign_keypair(self.algorithm)
        return KeyPair(public_key, secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign ``message`` with ``secret_key``, returning the raw signature bytes."""
        self._check_len("secret key", secret_key, self._meta.secret_key_bytes)
        return require_backend().sign(self.algorithm, secret_key, message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Return True iff ``signature`` is a valid signature of ``message``.

        Returns ``False`` (never raises) on a bad signature, so callers branch on the
        boolean. Both backends verify in constant time internally.
        """
        self._check_len("public key", public_key, self._meta.public_key_bytes)
        return require_backend().verify(self.algorithm, public_key, signature, message)

    def _check_len(self, label: str, value: bytes, expected: int) -> None:
        if len(value) != expected:
            raise KeySizeError(
                f"{label} for {self.algorithm} must be {expected} bytes, got {len(value)}."
            )
