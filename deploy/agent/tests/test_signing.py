"""Signing must be byte-identical to the platform verifier, and round-trip correctly."""
import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from seqr_agent import signing


def test_canonical_bytes_match_platform_contract():
    # The platform uses json.dumps(obs, sort_keys=True, separators=(",",":")).
    obs = [{"b": 2, "a": 1, "z": "x"}]
    expected = json.dumps(obs, sort_keys=True, separators=(",", ":")).encode()
    assert signing.canonical_bytes(obs) == expected


def test_load_or_create_and_persist(tmp_path):
    kf = str(tmp_path / "k.pem")
    priv1, created1 = signing.load_or_create_key(kf)
    assert created1 is True
    priv2, created2 = signing.load_or_create_key(kf)
    assert created2 is False
    # Same key reloaded -> same public bytes.
    assert signing.public_key_b64(priv1) == signing.public_key_b64(priv2)


def test_sign_verify_roundtrip_raw_and_pem(tmp_path):
    priv, _ = signing.load_or_create_key(str(tmp_path / "k.pem"))
    obs = [{"asset_key": "lb-01", "algorithm": "RSA-2048"}]
    sig = signing.sign(priv, obs)
    assert signing.verify(signing.public_key_b64(priv), sig, obs) is True
    assert signing.verify(signing.public_key_pem(priv), sig, obs) is True


def test_verify_rejects_tamper(tmp_path):
    priv, _ = signing.load_or_create_key(str(tmp_path / "k.pem"))
    sig = signing.sign(priv, [{"a": 1}])
    assert signing.verify(signing.public_key_b64(priv), sig, [{"a": 2}]) is False
    assert signing.verify(signing.public_key_b64(priv), "not-b64!!", [{"a": 1}]) is False


def test_public_key_b64_is_raw_32_bytes(tmp_path):
    priv, _ = signing.load_or_create_key(str(tmp_path / "k.pem"))
    raw = base64.b64decode(signing.public_key_b64(priv))
    assert len(raw) == 32
    # Loads as a valid Ed25519 key.
    Ed25519PublicKey.from_public_bytes(raw)
