"""Hybrid KEM: the HKDF combine (backend-free) + full roundtrip via the fake backend."""
import pytest

from pqcmap import HybridKEM, combine_secrets
from pqcmap.algorithms import meta
from pqcmap.core.exceptions import KeySizeError


# -- combine_secrets: deterministic, no backend --------------------------------

def test_combine_is_deterministic_and_32_bytes():
    a, b = b"classical-secret", b"pqc-secret"
    out = combine_secrets(a, b)
    assert len(out) == 32
    assert combine_secrets(a, b) == out


def test_combine_is_order_sensitive():
    assert combine_secrets(b"A", b"B") != combine_secrets(b"B", b"A")


def test_combine_changes_if_either_half_changes():
    base = combine_secrets(b"c", b"p")
    assert combine_secrets(b"c2", b"p") != base
    assert combine_secrets(b"c", b"p2") != base


# -- full hybrid roundtrip (real X25519 + real ML-KEM-768) --------------------

def test_hybrid_roundtrip(pqc_backend):
    kem = HybridKEM()
    kp = kem.generate_keypair()
    x = 32
    assert len(kp.public_key) == x + meta("ML-KEM-768").public_key_bytes
    assert len(kp.secret_key) == x + meta("ML-KEM-768").secret_key_bytes

    ct, secret_sender = kem.encapsulate(kp.public_key)
    assert len(ct) == x + meta("ML-KEM-768").output_bytes
    secret_receiver = kem.decapsulate(kp.secret_key, ct)
    assert secret_sender == secret_receiver
    assert len(secret_sender) == 32


def test_hybrid_two_encapsulations_differ(pqc_backend):
    # Ephemeral X25519 => a fresh shared secret each time, even to the same key.
    kem = HybridKEM()
    kp = kem.generate_keypair()
    _, s1 = kem.encapsulate(kp.public_key)
    _, s2 = kem.encapsulate(kp.public_key)
    assert s1 != s2


def test_hybrid_rejects_malformed_lengths(pqc_backend):
    kem = HybridKEM()
    kp = kem.generate_keypair()
    with pytest.raises(KeySizeError):
        kem.encapsulate(kp.public_key[:-1])
    ct, _ = kem.encapsulate(kp.public_key)
    with pytest.raises(KeySizeError):
        kem.decapsulate(kp.secret_key, ct[:-1])
