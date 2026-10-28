"""
Run once to generate SeQr Labs keypair and create a development license.

Usage:
  python scripts/generate_license.py

Outputs:
  - private key (save securely, never commit)
  - public key (embed in validator.py)
  - a dev license key for testing
"""
import sys
sys.path.insert(0, ".")

from app.license.validator import generate_dev_keypair, generate_license
from datetime import datetime, timedelta, timezone

print("Generating SeQr Labs Ed25519 keypair...")
private_pem, public_pem = generate_dev_keypair()

print("\n=== PRIVATE KEY (store securely, never commit) ===")
print(private_pem)

print("\n=== PUBLIC KEY (embed in validator.py) ===")
print(public_pem)

expires = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
license_key = generate_license(
    private_key_pem=private_pem,
    org_id="dev-org-001",
    org_name="SeQr Labs Dev",
    tier="mid",
    asset_limit=100,
    expires_at=expires,
    features=["network", "code", "reports", "api", "agent"],
)

print("\n=== DEV LICENSE KEY ===")
print(license_key)

print("\n=== NEXT STEPS ===")
print("1. Copy the PUBLIC KEY into app/license/validator.py as DEV_PUBLIC_KEY_PEM")
print("2. Store the PRIVATE KEY securely (not in repo)")
print("3. Set LICENSE_KEY=<license key> in .env")
