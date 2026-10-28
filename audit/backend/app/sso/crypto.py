"""Symmetric encryption for OIDC client secrets at rest (A5 SSO).

An IdP client secret is a bearer credential — storing it plaintext in the DB fails any
regulated buyer's review. Encrypt it with a Fernet key derived from ``SECRET_KEY`` (the
same value already trusted to sign every JWT). Rotating SECRET_KEY invalidates stored
secrets, which is acceptable — an admin re-enters the IdP secret, exactly as they would
after any key-compromise rotation.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def _fernet() -> Fernet:
    # Fernet needs a url-safe base64 32-byte key; derive one deterministically from SECRET_KEY.
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest())
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    if plaintext is None:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:  # wrong/rotated key or tampered ciphertext
        raise ValueError("Cannot decrypt OIDC client secret (SECRET_KEY changed?)") from e
