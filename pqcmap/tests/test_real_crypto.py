"""End-to-end tests against the REAL PQC backend (pure-python here, liboqs in CI).

No mock anywhere: these exercise genuine FIPS 203 / 204 operations through pqcmap's
public API, and prove cross-object interop (sign with the key store, verify a JWT,
combine a hybrid secret)."""
import pqcmap
from pqcmap import HybridKEM, KeyEncapsulation, LocalKeyStore, PQCToken, Signature


def test_backend_is_real_and_named():
    assert pqcmap.available() is True
    assert pqcmap.backend() in {"pure-python", "liboqs"}


def test_real_kem_roundtrip(pqc_backend):
    kem = KeyEncapsulation()
    kp = kem.generate_keypair()
    ct, ss1 = kem.encapsulate(kp.public_key)
    ss2 = kem.decapsulate(kp.secret_key, ct)
    assert ss1 == ss2 and len(ss1) == 32


def test_real_sign_verify_and_tamper(pqc_backend):
    sig = Signature()
    kp = sig.generate_keypair()
    s = sig.sign(b"real message", kp.secret_key)
    assert sig.verify(b"real message", s, kp.public_key)
    assert not sig.verify(b"tampered", s, kp.public_key)


def test_real_hybrid_roundtrip(pqc_backend):
    kem = HybridKEM()
    kp = kem.generate_keypair()
    ct, s1 = kem.encapsulate(kp.public_key)
    assert kem.decapsulate(kp.secret_key, ct) == s1


def test_real_jwt_over_keystore(tmp_path, pqc_backend):
    ks = LocalKeyStore(passphrase="pw", path=tmp_path / "k.enc")
    kid = ks.generate_and_store("ML-DSA-65", metadata={"purpose": "jwt"})
    token = PQCToken.encode({"user_id": "42"}, ks.get_private_key(kid))
    assert PQCToken.decode(token, ks.get_public_key(kid))["user_id"] == "42"
