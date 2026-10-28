import base64
import json
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


@dataclass
class LicenseInfo:
    valid: bool
    org_id: str
    org_name: str
    tier: str
    asset_limit: int
    issued_at: datetime
    expires_at: datetime
    features: list[str]
    expired: bool
    grace_period: bool
    error: Optional[str] = None


def generate_dev_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption
    )
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    public_pem = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_pem, public_pem


def generate_license(
    private_key_pem: str,
    org_id: str,
    org_name: str,
    tier: str,
    asset_limit: int,
    expires_at: str,
    features: list[str] = None,
) -> str:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if features is None:
        features = ["network", "code", "reports", "api"]

    payload = {
        "org_id": org_id,
        "org_name": org_name,
        "tier": tier,
        "asset_limit": asset_limit,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
        "features": features,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode()

    private_key = load_pem_private_key(private_key_pem.encode(), password=None)
    signature = private_key.sign(payload_bytes)
    sig_b64 = base64.urlsafe_b64encode(signature).decode()

    # Use '.' as payload/sig separator — base64url uses '-' so '-' is ambiguous
    return f"SQ-{tier.upper()}-{payload_b64}.{sig_b64}"


def validate_license(license_key: str, public_key_pem: str) -> LicenseInfo:
    try:
        if not license_key.startswith("SQ-"):
            return _invalid("License key format invalid")

        parts = license_key.split("-", 2)
        if len(parts) < 3:
            return _invalid("License key format invalid")

        remainder = parts[2]
        dot_pos = remainder.rfind(".")
        if dot_pos == -1:
            return _invalid("License key format invalid")

        payload_b64 = remainder[:dot_pos]
        sig_b64 = remainder[dot_pos + 1:]

        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        signature = base64.urlsafe_b64decode(sig_b64)

        public_key = load_pem_public_key(public_key_pem.encode())
        public_key.verify(signature, payload_bytes)

        payload = json.loads(payload_bytes)
        now = datetime.now(timezone.utc)
        expires = datetime.fromisoformat(payload["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        expired = now > expires
        grace = False
        if expired:
            from datetime import timedelta
            grace = (now - expires).days <= 30

        return LicenseInfo(
            valid=True,
            org_id=payload["org_id"],
            org_name=payload["org_name"],
            tier=payload["tier"],
            asset_limit=payload["asset_limit"],
            issued_at=datetime.fromisoformat(payload["issued_at"]),
            expires_at=expires,
            features=payload.get("features", ["network", "code"]),
            expired=expired,
            grace_period=grace,
        )

    except InvalidSignature:
        return _invalid("License signature invalid")
    except Exception as e:
        return _invalid(f"License validation error: {e}")


def _invalid(error: str) -> LicenseInfo:
    now = datetime.now(timezone.utc)
    return LicenseInfo(
        valid=False,
        org_id="",
        org_name="",
        tier="none",
        asset_limit=0,
        issued_at=now,
        expires_at=now,
        features=[],
        expired=True,
        grace_period=False,
        error=error,
    )
