"""KEM + signature wrapper logic, exercised through the fake liboqs backend."""
import pytest

from pqcmap import KEMAlgorithm, KeyEncapsulation, Signature, SignAlgorithm
from pqcmap.algorithms import meta
from pqcmap.core.exceptions import KeySizeError, UnsupportedAlgorithmError


# -- KEM ----------------------------------------------------------------------

def test_kem_roundtrip(pqc_backend):
    kem = KeyEncapsulation()  # ML-KEM-768
    kp = kem.generate_keypair()
    assert len(kp.public_key) == meta("ML-KEM-768").public_key_bytes
    assert len(kp.secret_key) == meta("ML-KEM-768").secret_key_bytes

    ct, ss_sender = kem.encapsulate(kp.public_key)
    assert len(ct) == meta("ML-KEM-768").output_bytes
    ss_receiver = kem.decapsulate(kp.secret_key, ct)
    assert ss_sender == ss_receiver
    assert len(ss_sender) == 32


@pytest.mark.parametrize("alg", [KEMAlgorithm.ML_KEM_512, KEMAlgorithm.ML_KEM_1024])
def test_kem_other_levels(pqc_backend, alg):
    kem = KeyEncapsulation(alg)
    kp = kem.generate_keypair()
    ct, ss = kem.encapsulate(kp.public_key)
    assert kem.decapsulate(kp.secret_key, ct) == ss


def test_kem_rejects_sign_algorithm():
    with pytest.raises(UnsupportedAlgorithmError):
        KeyEncapsulation("ML-DSA-65")


def test_kem_length_validation(pqc_backend):
    kem = KeyEncapsulation()
    with pytest.raises(KeySizeError):
        kem.encapsulate(b"too short")
    kp = kem.generate_keypair()
    ct, _ = kem.encapsulate(kp.public_key)
    with pytest.raises(KeySizeError):
        kem.decapsulate(b"short", ct)
    with pytest.raises(KeySizeError):
        kem.decapsulate(kp.secret_key, b"short-ct")


def test_keypair_repr_redacts_secret(pqc_backend):
    kp = KeyEncapsulation().generate_keypair()
    assert "redacted" in repr(kp)
    assert kp.secret_key.hex() not in repr(kp)


# -- Signatures ---------------------------------------------------------------

def test_sign_verify_roundtrip(pqc_backend):
    sig = Signature()  # ML-DSA-65
    kp = sig.generate_keypair()
    signature = sig.sign(b"authorize transfer", kp.secret_key)
    assert len(signature) == meta("ML-DSA-65").output_bytes
    assert sig.verify(b"authorize transfer", signature, kp.public_key) is True


def test_verify_rejects_tampered_message(pqc_backend):
    sig = Signature()
    kp = sig.generate_keypair()
    signature = sig.sign(b"amount=100", kp.secret_key)
    assert sig.verify(b"amount=999", signature, kp.public_key) is False


def test_verify_rejects_wrong_key(pqc_backend):
    sig = Signature()
    kp1 = sig.generate_keypair()
    kp2 = sig.generate_keypair()
    signature = sig.sign(b"msg", kp1.secret_key)
    assert sig.verify(b"msg", signature, kp2.public_key) is False


def test_sign_rejects_kem_algorithm():
    with pytest.raises(UnsupportedAlgorithmError):
        Signature("ML-KEM-768")


@pytest.mark.parametrize("alg", [SignAlgorithm.ML_DSA_44, SignAlgorithm.ML_DSA_87])
def test_sign_other_levels(pqc_backend, alg):
    sig = Signature(alg)
    kp = sig.generate_keypair()
    s = sig.sign(b"x", kp.secret_key)
    assert sig.verify(b"x", s, kp.public_key)
