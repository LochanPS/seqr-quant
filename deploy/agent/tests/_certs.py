"""Test helper — mint self-signed certs (RSA/EC) as PEM/DER for the cert_store tests."""
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def _cert(priv, cn: str):
    pub = priv.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(pub).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )


def rsa_pem(cn="rsa-leaf.internal", bits=2048) -> bytes:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return _cert(priv, cn).public_bytes(Encoding.PEM)


def ec_der(cn="ec-leaf.internal") -> bytes:
    priv = ec.generate_private_key(ec.SECP256R1())
    return _cert(priv, cn).public_bytes(Encoding.DER)
