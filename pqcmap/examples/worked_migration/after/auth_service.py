"""The same auth service — AFTER migration (quantum-safe).

Session tokens are now ML-DSA-65 JWTs (FIPS 204, NIST Level 3) via pqcmap. The signing
key lives in an encrypted LocalKeyStore instead of a module global. `seqr scan code`
reports this file clean (0 findings). Functionally identical: issue a token, verify it.

Migration applied (see ../../docs/COOKBOOK.md recipes 1 + 7):
    import jwt                       ->  import pqcmap.jwt as jwt
    rsa.generate_private_key(...)    ->  LocalKeyStore.generate_and_store("ML-DSA-65")
    algorithm="RS256"                ->  algorithm="ML-DSA-65"
"""
import pqcmap.jwt as jwt  # PyJWT-shaped, ML-DSA underneath
from pqcmap.kms.local import LocalKeyStore

ALGORITHM = "ML-DSA-65"  # FIPS 204, NIST Level 3


def open_keystore(passphrase: str, path: str) -> LocalKeyStore:
    """Encrypted at-rest key storage (AES-256-GCM, PBKDF2) — replaces the RSA global."""
    return LocalKeyStore(passphrase=passphrase, path=path)


def issue_token(payload: dict, private_key: bytes) -> str:
    """Sign a session token with ML-DSA-65 — quantum-safe."""
    return jwt.encode(payload, private_key, algorithm=ALGORITHM)


def verify_token(token: str, public_key: bytes) -> dict:
    return jwt.decode(token, public_key, algorithms=[ALGORITHM])


if __name__ == "__main__":
    import os
    import tempfile

    store_path = os.path.join(tempfile.gettempdir(), "worked_migration_keys.enc")
    ks = open_keystore(passphrase="demo-passphrase", path=store_path)
    key_id = ks.generate_and_store(ALGORITHM, metadata={"purpose": "session-jwt"})

    token = issue_token({"sub": "user-123", "role": "admin"}, ks.get_private_key(key_id))
    claims = verify_token(token, ks.get_public_key(key_id))
    print("issued ML-DSA-65 token:", token[:40], "...")
    print("verified claims:", claims)
