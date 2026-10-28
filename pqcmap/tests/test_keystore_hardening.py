"""LocalKeyStore SDK-4 hardening — rotation policy, export/import, audit log."""
import pytest

from pqcmap import LocalKeyStore
from pqcmap.core.exceptions import KMSAuthError, KMSError
from pqcmap.kms.local import RotationPolicy


def _store(tmp_path, name="keys.enc", passphrase="correct horse", **kw):
    return LocalKeyStore(passphrase=passphrase, path=tmp_path / name, **kw)


# -- rotation policy -------------------------------------------------------------

def test_usage_counter_increments_on_private_key_access(tmp_path):
    ks = _store(tmp_path)
    kid = ks.store("ML-DSA-65", b"pk", b"sk")
    assert ks.get_metadata(kid)["uses"] == 0
    ks.get_private_key(kid)
    ks.get_private_key(kid)
    assert ks.get_metadata(kid)["uses"] == 2
    # peeking without recording a use leaves the counter untouched
    ks.get_private_key(kid, record_use=False)
    assert ks.get_metadata(kid)["uses"] == 2


def test_needs_rotation_by_usage(tmp_path):
    ks = _store(tmp_path, rotation_policy=RotationPolicy(max_uses=2))
    kid = ks.store("ML-DSA-65", b"pk", b"sk")
    ks.get_private_key(kid)
    assert ks.needs_rotation(kid) is False
    ks.get_private_key(kid)
    assert ks.needs_rotation(kid) is True


def test_needs_rotation_by_age(tmp_path):
    ks = _store(tmp_path, rotation_policy=RotationPolicy(max_age_days=7))
    kid = ks.store("ML-DSA-65", b"pk", b"sk")
    assert ks.needs_rotation(kid) is False
    # backdate creation past the age limit
    ks._records[kid]["created_at"] = "2000-01-01T00:00:00+00:00"
    assert ks.needs_rotation(kid) is True


def test_rotate_if_needed_rotates_and_returns_new_id(tmp_path, pqc_backend):
    ks = _store(tmp_path, rotation_policy=RotationPolicy(max_uses=1))
    kid = ks.generate_and_store("ML-DSA-65")
    ks.get_private_key(kid)  # hits the limit
    new_id = ks.rotate_if_needed(kid)
    assert new_id is not None and new_id != kid
    assert ks.get_metadata(kid)["status"] == "rotated"
    # a rotated key no longer needs rotation
    assert ks.rotate_if_needed(kid) is None


def test_rotation_policy_persists_across_instances(tmp_path):
    _store(tmp_path, rotation_policy=RotationPolicy(max_age_days=30, max_uses=100))
    reopened = _store(tmp_path)
    assert reopened.rotation_policy.max_age_days == 30
    assert reopened.rotation_policy.max_uses == 100


# -- export / import -------------------------------------------------------------

def test_export_import_roundtrip_between_stores(tmp_path):
    src = _store(tmp_path, name="src.enc")
    kid = src.store("ML-DSA-65", b"public-material", b"secret-material", {"purpose": "jwt"})
    blob = src.export_key(kid, passphrase="transfer-pass")

    dst = _store(tmp_path, name="dst.enc", passphrase="a-different-store-pass")
    imported = dst.import_key(blob, passphrase="transfer-pass")
    assert dst.get_public_key(imported) == b"public-material"
    assert dst.get_private_key(imported, record_use=False) == b"secret-material"
    assert dst.get_metadata(imported)["metadata"] == {"purpose": "jwt"}


def test_import_wrong_passphrase_rejected(tmp_path):
    src = _store(tmp_path, name="src.enc")
    kid = src.store("ML-KEM-768", b"pk", b"sk")
    blob = src.export_key(kid, passphrase="right")
    dst = _store(tmp_path, name="dst.enc")
    with pytest.raises(KMSAuthError):
        dst.import_key(blob, passphrase="wrong")


def test_import_rejects_non_export_blob(tmp_path):
    ks = _store(tmp_path)
    with pytest.raises(KMSError):
        ks.import_key(b"garbage-not-an-export", passphrase="x")


def test_import_assigns_new_id_on_collision(tmp_path):
    src = _store(tmp_path, name="src.enc")
    kid = src.store("ML-KEM-768", b"pk", b"sk")
    blob = src.export_key(kid, passphrase="p")
    # import back into the SAME store — original id is taken, so a new one is assigned
    new_id = src.import_key(blob, passphrase="p")
    assert new_id != kid
    assert src.get_public_key(new_id) == b"pk"


# -- audit log -------------------------------------------------------------------

def test_audit_log_records_operations(tmp_path, pqc_backend):
    ks = _store(tmp_path)
    kid = ks.generate_and_store("ML-DSA-65")
    ks.get_private_key(kid)
    ks.rotate(kid)
    ops = [e["op"] for e in ks.read_audit_log()]
    assert "store" in ops and "generate" in ops and "access" in ops and "rotate" in ops


def test_audit_log_is_append_only_and_chain_verifies(tmp_path):
    ks = _store(tmp_path)
    ks.store("ML-DSA-65", b"pk", b"sk")
    ks.store("ML-KEM-768", b"pk2", b"sk2")
    assert ks.verify_audit_log() is True
    # sequence numbers are monotonic and the chain links prev -> hash
    entries = ks.read_audit_log()
    assert [e["seq"] for e in entries] == list(range(len(entries)))
    for a, b in zip(entries, entries[1:]):
        assert b["prev"] == a["hash"]


def test_audit_log_tamper_is_detected(tmp_path):
    ks = _store(tmp_path)
    ks.store("ML-DSA-65", b"pk", b"sk")
    ks.store("ML-KEM-768", b"pk2", b"sk2")
    # tamper: rewrite one entry's algorithm without fixing the chain hash
    lines = ks.audit_path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("ML-DSA-65", "ML-KEM-512")
    ks.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(KMSError):
        ks.verify_audit_log()


def test_audit_chain_survives_reopen(tmp_path):
    ks = _store(tmp_path)
    ks.store("ML-DSA-65", b"pk", b"sk")
    reopened = _store(tmp_path)  # continues the same chain
    reopened.store("ML-KEM-768", b"pk2", b"sk2")
    assert reopened.verify_audit_log() is True
    assert len(reopened.read_audit_log()) == 2


def test_audit_can_be_disabled(tmp_path):
    ks = _store(tmp_path, audit=False)
    ks.store("ML-DSA-65", b"pk", b"sk")
    assert ks.read_audit_log() == []
