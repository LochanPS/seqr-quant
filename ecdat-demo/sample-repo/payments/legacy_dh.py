"""ACME Bank — legacy partner gateway key agreement (Diffie-Hellman)."""

from cryptography.hazmat.primitives.asymmetric import dh


def generate_dh_parameters():
    """Classic Diffie-Hellman parameters for the legacy partner gateway."""
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters
