"""LocalKeyStore — AES-GCM at rest, PBKDF2 key derivation, rotation, wrong passphrase."""
import pytest

from pqcmap import LocalKeyStore
from pqcmap.core.exceptions import (
    KMSAuthError,
    KMSKeyNotFoundError,
    UnsupportedAlgorithmError,
)


def _store(tmp_path, passphrase="correct horse"):
    return LocalKeyStore(passphrase=passphrase, path=tmp_path / "keys.enc")


def test_store_and_retrieve_roundtrip(tmp_path):
    ks = _store(tmp_path)
    kid = ks.store("ML-DSA-65", b"pub-bytes", b"sec-bytes", metadata={"purpose": "jwt"})
    assert ks.get_public_key(kid) == b"pub-bytes"
    assert ks.get_private_key(kid) == b"sec-bytes"
    assert ks.get_metadata(kid)["metadata"] == {"purpose": "jwt"}
    assert ks.get_metadata(kid)["status"] == "active"


def test_persists_across_instances(tmp_path):
    ks = _store(tmp_path)
    kid = ks.store("ML-KEM-768", b"pk", b"sk")
    reopened = _store(tmp_path)
    assert reopened.get_public_key(kid) == b"pk"
    assert reopened.get_private_key(kid) == b"sk"


def test_wrong_passphrase_rejected(tmp_path):
    ks = _store(tmp_path)
    ks.store("ML-KEM-768", b"pk", b"sk")
    with pytest.raises(KMSAuthError):
        _store(tmp_path, passphrase="wrong passphrase")


def test_empty_passphrase_rejected(tmp_path):
    with pytest.raises(KMSAuthError):
        LocalKeyStore(passphrase="", path=tmp_path / "k.enc")


def test_file_is_encrypted_at_rest(tmp_path):
    ks = _store(tmp_path)
    ks.store("ML-KEM-768", b"SUPER_SECRET_PUBLIC", b"SUPER_SECRET_PRIVATE")
    raw = (tmp_path / "keys.enc").read_bytes()
    assert b"SUPER_SECRET_PRIVATE" not in raw
    assert b"ML-KEM-768" not in raw


def test_missing_key_raises(tmp_path):
    ks = _store(tmp_path)
    with pytest.raises(KMSKeyNotFoundError):
        ks.get_public_key("key_deadbeef")


def test_unknown_algorithm_rejected(tmp_path):
    ks = _store(tmp_path)
    with pytest.raises(UnsupportedAlgorithmError):
        ks.store("RSA-2048", b"pk", b"sk")


def test_generate_and_store_needs_backend(tmp_path, pqc_backend):
    ks = _store(tmp_path)
    kid = ks.generate_and_store("ML-DSA-65", metadata={"purpose": "signing"})
    pub = ks.get_public_key(kid)
    assert len(pub) == 1952  # ML-DSA-65 public key size


def test_rotate_marks_old_and_creates_new(tmp_path, pqc_backend):
    ks = _store(tmp_path)
    old = ks.generate_and_store("ML-KEM-768")
    new = ks.rotate(old)
    assert new != old
    assert ks.get_metadata(old)["status"] == "rotated"
    assert ks.get_metadata(old)["rotated_to"] == new
    assert ks.get_metadata(new)["status"] == "active"
    # old key material is retained so prior artifacts still verify
    assert ks.get_public_key(old)
    assert len(ks.list_keys()) == 2
