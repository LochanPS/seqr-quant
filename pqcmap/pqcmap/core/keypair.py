"""Immutable keypair container shared by the KEM and signature wrappers."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KeyPair:
    """A raw public/secret key pair (bytes, as liboqs emits them).

    ``public_key`` is safe to distribute; ``secret_key`` must be protected — store it
    via :class:`pqcmap.kms.local.LocalKeyStore`, never in plaintext at rest.
    """

    public_key: bytes
    secret_key: bytes

    def __repr__(self) -> str:  # never leak secret bytes in logs / tracebacks
        return (
            f"KeyPair(public_key=<{len(self.public_key)} bytes>, "
            f"secret_key=<{len(self.secret_key)} bytes redacted>)"
        )
