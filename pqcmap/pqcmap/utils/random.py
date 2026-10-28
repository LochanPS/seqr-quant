"""Secure random helpers backed by the OS CSPRNG (``os.urandom`` / ``secrets``)."""
from __future__ import annotations

import secrets


def random_bytes(n: int) -> bytes:
    """Return ``n`` cryptographically secure random bytes from the OS CSPRNG."""
    if n < 0:
        raise ValueError("n must be non-negative")
    return secrets.token_bytes(n)


def random_token(n_bytes: int = 32) -> str:
    """Return a URL-safe random token (e.g. for key ids / nonces)."""
    return secrets.token_urlsafe(n_bytes)
