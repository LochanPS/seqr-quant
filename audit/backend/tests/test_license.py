from app.license.validator import (
    generate_dev_keypair,
    generate_license,
    validate_license,
)
from datetime import datetime, timedelta, timezone


def test_generate_keypair():
    private_pem, public_pem = generate_dev_keypair()
    assert "PRIVATE KEY" in private_pem
    assert "PUBLIC KEY" in public_pem


def test_generate_and_validate_license():
    priv, pub = generate_dev_keypair()
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    key = generate_license(
        private_key_pem=priv,
        org_id="test-org",
        org_name="Test Org",
        tier="mid",
        asset_limit=100,
        expires_at=expires,
    )
    assert key.startswith("SQ-MID-")
    info = validate_license(key, pub)
    assert info.valid is True
    assert info.tier == "mid"
    assert info.asset_limit == 100
    assert info.expired is False
    assert info.org_name == "Test Org"


def test_expired_license_in_grace_period():
    priv, pub = generate_dev_keypair()
    expires = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    key = generate_license(priv, "org", "Org", "small", 25, expires)
    info = validate_license(key, pub)
    assert info.valid is True
    assert info.expired is True
    assert info.grace_period is True


def test_expired_license_outside_grace():
    priv, pub = generate_dev_keypair()
    expires = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    key = generate_license(priv, "org", "Org", "small", 25, expires)
    info = validate_license(key, pub)
    assert info.expired is True
    assert info.grace_period is False


def test_tampered_license_invalid():
    priv, pub = generate_dev_keypair()
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    key = generate_license(priv, "org", "Org", "trial", 5, expires)
    tampered = key[:-5] + "XXXXX"
    info = validate_license(tampered, pub)
    assert info.valid is False
    assert info.error is not None


def test_wrong_public_key_rejected():
    priv1, pub1 = generate_dev_keypair()
    _, pub2 = generate_dev_keypair()
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    key = generate_license(priv1, "org", "Org", "mid", 50, expires)
    info = validate_license(key, pub2)
    assert info.valid is False


def test_invalid_format_rejected():
    _, pub = generate_dev_keypair()
    info = validate_license("not-a-license", pub)
    assert info.valid is False
