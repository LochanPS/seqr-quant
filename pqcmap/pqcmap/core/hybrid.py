"""Hybrid KEM: X25519 (classical) + ML-KEM-768 (PQC), combined via HKDF-SHA256.

Recommended for production during the 2026-2030 transition: if *either* primitive is
broken, the other still protects the shared secret. This mirrors the hybrid key
exchange that TLS 1.3 deployments (X25519MLKEM768) are standardising on.

    kem = HybridKEM()
    keypair = kem.generate_keypair()
    ciphertext, secret = kem.encapsulate(keypair.public_key)
    secret2 = kem.decapsulate(keypair.secret_key, ciphertext)
    assert secret == secret2

Wire format (concatenated, fixed offsets):
    public_key = x25519_public(32) || mlkem768_public(1184)
    secret_key = x25519_secret(32) || mlkem768_secret(2400)
    ciphertext = x25519_ephemeral_public(32) || mlkem768_ciphertext(1088)

Only the ML-KEM half needs liboqs; the X25519 half and the HKDF combine use PyCA
``cryptography`` and work everywhere.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from pqcmap import algorithms
from pqcmap.core.exceptions import KeySizeError
from pqcmap.core.kem import KeyEncapsulation
from pqcmap.core.keypair import KeyPair

_X25519_LEN = 32
_HKDF_SALT = b"seqr-hybrid-v1"
_HKDF_INFO = b"pqcmap hybrid kem X25519+ML-KEM-768"
_SHARED_SECRET_LEN = 32  # 256-bit combined secret, ready as an AES-256 key


def combine_secrets(classical_secret: bytes, pqc_secret: bytes) -> bytes:
    """Derive the final 32-byte shared secret from both halves via HKDF-SHA256.

    Order (classical then PQC) is part of the wire contract and must match on both
    sides. Deterministic and backend-free, so it is unit-tested directly.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_SHARED_SECRET_LEN,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(classical_secret + pqc_secret)


class HybridKEM:
    def __init__(self, pqc_algorithm: str = algorithms.KEMAlgorithm.ML_KEM_768):
        self._kem = KeyEncapsulation(pqc_algorithm)
        self._pqc_pub_len = self._kem._meta.public_key_bytes
        self._pqc_sec_len = self._kem._meta.secret_key_bytes
        self._pqc_ct_len = self._kem._meta.output_bytes

    def generate_keypair(self) -> KeyPair:
        x_priv = X25519PrivateKey.generate()
        x_pub_bytes = x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        x_priv_bytes = x_priv.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        pqc = self._kem.generate_keypair()
        return KeyPair(
            public_key=x_pub_bytes + pqc.public_key,
            secret_key=x_priv_bytes + pqc.secret_key,
        )

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        x_peer_pub, pqc_peer_pub = self._split_public(public_key)

        # Classical: ephemeral X25519 ECDH against the peer's static X25519 key.
        eph = X25519PrivateKey.generate()
        eph_pub_bytes = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        classical_secret = eph.exchange(X25519PublicKey.from_public_bytes(x_peer_pub))

        # PQC: ML-KEM encapsulation against the peer's static ML-KEM key.
        pqc_ct, pqc_secret = self._kem.encapsulate(pqc_peer_pub)

        shared = combine_secrets(classical_secret, pqc_secret)
        return eph_pub_bytes + pqc_ct, shared

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        x_priv_bytes, pqc_priv = self._split_secret(secret_key)
        eph_pub, pqc_ct = self._split_ciphertext(ciphertext)

        x_priv = X25519PrivateKey.from_private_bytes(x_priv_bytes)
        classical_secret = x_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        pqc_secret = self._kem.decapsulate(pqc_priv, pqc_ct)

        return combine_secrets(classical_secret, pqc_secret)

    # -- wire-format splitting (with length validation) ---------------------------

    def _split_public(self, blob: bytes) -> tuple[bytes, bytes]:
        expected = _X25519_LEN + self._pqc_pub_len
        self._check_len("hybrid public key", blob, expected)
        return blob[:_X25519_LEN], blob[_X25519_LEN:]

    def _split_secret(self, blob: bytes) -> tuple[bytes, bytes]:
        expected = _X25519_LEN + self._pqc_sec_len
        self._check_len("hybrid secret key", blob, expected)
        return blob[:_X25519_LEN], blob[_X25519_LEN:]

    def _split_ciphertext(self, blob: bytes) -> tuple[bytes, bytes]:
        expected = _X25519_LEN + self._pqc_ct_len
        self._check_len("hybrid ciphertext", blob, expected)
        return blob[:_X25519_LEN], blob[_X25519_LEN:]

    @staticmethod
    def _check_len(label: str, value: bytes, expected: int) -> None:
        if len(value) != expected:
            raise KeySizeError(f"{label} must be {expected} bytes, got {len(value)}.")
