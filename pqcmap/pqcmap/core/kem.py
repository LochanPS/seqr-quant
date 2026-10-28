"""Key Encapsulation Mechanism (KEM) — the drop-in replacement for RSA/ECDH key exchange.

Default: ML-KEM-768 (FIPS 203, NIST Level 3).

    kem = KeyEncapsulation()                       # ML-KEM-768 by default
    keypair = kem.generate_keypair()
    ciphertext, shared_secret = kem.encapsulate(keypair.public_key)
    shared_secret2 = kem.decapsulate(keypair.secret_key, ciphertext)
    assert shared_secret == shared_secret2         # both sides now share a key

The wrapper is intentionally *stateless / functional*: keys are passed in explicitly
rather than held inside the object, so it composes cleanly with a key store and with
hybrid mode. Each call opens a short-lived liboqs object (a context manager) so no
secret material lingers on the instance.
"""
from __future__ import annotations

from pqcmap import algorithms
from pqcmap._backend import require_backend
from pqcmap.core.exceptions import KeySizeError, UnsupportedAlgorithmError
from pqcmap.core.keypair import KeyPair


class KeyEncapsulation:
    def __init__(self, algorithm: str = algorithms.DEFAULT_KEM):
        if algorithm not in algorithms.KEM_ALGORITHMS:
            raise UnsupportedAlgorithmError(
                f"{algorithm!r} is not a KEM algorithm. "
                f"Choose one of: {', '.join(sorted(algorithms.KEM_ALGORITHMS))}."
            )
        self.algorithm = algorithm
        self._meta = algorithms.meta(algorithm)

    def generate_keypair(self) -> KeyPair:
        """Generate a fresh keypair. The secret key never touches the instance state."""
        public_key, secret_key = require_backend().kem_keypair(self.algorithm)
        return KeyPair(public_key, secret_key)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return ``(ciphertext, shared_secret)`` for the recipient's ``public_key``.

        Send ``ciphertext`` to the recipient; use ``shared_secret`` as an AES-256 key.
        """
        self._check_len("public key", public_key, self._meta.public_key_bytes)
        return require_backend().kem_encaps(self.algorithm, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Recover the shared secret from ``ciphertext`` using your ``secret_key``."""
        self._check_len("secret key", secret_key, self._meta.secret_key_bytes)
        self._check_len("ciphertext", ciphertext, self._meta.output_bytes)
        return require_backend().kem_decaps(self.algorithm, secret_key, ciphertext)

    def _check_len(self, label: str, value: bytes, expected: int) -> None:
        if len(value) != expected:
            raise KeySizeError(
                f"{label} for {self.algorithm} must be {expected} bytes, got {len(value)}."
            )
