"""ACME Bank — settlement signing keys (RSA)."""

from Crypto.PublicKey import RSA


def generate_settlement_signing_key():
    """RSA-2048 key used to sign the nightly settlement batch."""
    key = RSA.generate(2048)
    return key
