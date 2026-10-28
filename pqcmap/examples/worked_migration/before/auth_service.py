"""A small auth service — BEFORE migration (quantum-vulnerable).

Issues session tokens as RS256 JWTs signed with an RSA-2048 key. Both the RSA key
and the RS256 algorithm are broken by a cryptographically-relevant quantum computer,
so `seqr scan code` flags this file. See ../run_migration.py for the full walkthrough.
"""
import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_signing_key():
    """RSA-2048 signing key — quantum-vulnerable (Shor's algorithm)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def issue_token(payload: dict, private_key) -> str:
    """Sign a session token with RS256 (RSA) — quantum-vulnerable."""
    return jwt.encode(payload, private_key, algorithm="RS256")


def verify_token(token: str, public_key) -> dict:
    return jwt.decode(token, public_key, algorithms=["RS256"])


if __name__ == "__main__":
    key = generate_signing_key()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token = issue_token({"sub": "user-123", "role": "admin"}, key)
    print("issued RS256 token:", token[:40], "...")
