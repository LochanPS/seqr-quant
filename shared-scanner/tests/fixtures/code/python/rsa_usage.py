"""Fixture: Python file with RSA and ECDSA usage. Scanner must find both."""
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

# RSA key generation — should be flagged as vulnerable, risk=8
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)

# ECDSA — ECC is also quantum-vulnerable but lower risk=7
ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

# RSA-OAEP encryption
encrypted = private_key.public_key().encrypt(
    b"secret",
    padding.OAEP(
        mgf=padding.MGF1(algorithm=None),
        algorithm=None,
        label=None,
    ),
)
