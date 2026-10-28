#!/usr/bin/env python3
"""Runnable proof for every "after" recipe in docs/COOKBOOK.md.

Each function is the exact post-quantum replacement shown in the cookbook, executed
against the real pqcmap backend. Run it directly to see them all pass:

    python examples/cookbook_recipes.py

It doubles as a regression guard: if the public API drifts from what the cookbook
documents, this script fails. `tests/test_cookbook_recipes.py` imports and runs it too.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

import pqcmap.jwt as jwt  # noqa: E402  (PyJWT-shaped)
from pqcmap import HybridKEM, KeyEncapsulation, Signature  # noqa: E402
from pqcmap.kms.local import LocalKeyStore, RotationPolicy  # noqa: E402


def recipe_1_jwt() -> None:
    """RS256 JWT -> ML-DSA JWT (PyJWT-shaped)."""
    kp = Signature("ML-DSA-65").generate_keypair()
    token = jwt.encode({"sub": "123", "role": "admin"}, kp.secret_key, algorithm="ML-DSA-65")
    claims = jwt.decode(token, kp.public_key, algorithms=["ML-DSA-65"])
    assert claims["sub"] == "123" and claims["role"] == "admin"

    # A token verified against the wrong key is rejected with the familiar PyJWT error.
    other = Signature("ML-DSA-65").generate_keypair()
    try:
        jwt.decode(token, other.public_key, algorithms=["ML-DSA-65"])
    except jwt.InvalidSignatureError:
        pass
    else:  # pragma: no cover - would signal a real regression
        raise AssertionError("token verified under the wrong key was accepted")


def recipe_2_rsa_signatures() -> None:
    """RSA signatures -> ML-DSA."""
    sig = Signature("ML-DSA-65")
    kp = sig.generate_keypair()
    message = b"authorize transfer of 50000 to account 998"
    signature = sig.sign(message, kp.secret_key)
    assert sig.verify(message, signature, kp.public_key) is True
    assert sig.verify(b"tampered", signature, kp.public_key) is False


def recipe_3_ecdsa_signatures() -> None:
    """ECDSA signatures -> ML-DSA (same target as RSA-sign)."""
    sig = Signature("ML-DSA-65")
    kp = sig.generate_keypair()
    message = b"session=abc123;issued=2026-08-21"
    signature = sig.sign(message, kp.secret_key)
    assert sig.verify(message, signature, kp.public_key) is True


def recipe_4_ecdh_to_kem() -> None:
    """ECDH / X25519 key agreement -> ML-KEM."""
    kem = KeyEncapsulation("ML-KEM-768")
    kp = kem.generate_keypair()
    ciphertext, shared_secret = kem.encapsulate(kp.public_key)
    shared_secret2 = kem.decapsulate(kp.secret_key, ciphertext)
    assert shared_secret == shared_secret2
    assert len(shared_secret) == 32  # ready as an AES-256 key


def recipe_5_kem_dem_encryption() -> None:
    """RSA-OAEP encryption -> KEM + AES-GCM (KEM-DEM)."""
    kem = KeyEncapsulation("ML-KEM-768")
    kp = kem.generate_keypair()
    plaintext = b"card number 4111 1111 1111 1111" * 100  # far larger than an RSA modulus

    def encrypt_to(public_key, data):
        kem_ct, secret = kem.encapsulate(public_key)
        nonce = os.urandom(12)
        return kem_ct, nonce, AESGCM(secret).encrypt(nonce, data, None)

    def decrypt_with(secret_key, kem_ct, nonce, dem_ct):
        secret = kem.decapsulate(secret_key, kem_ct)
        return AESGCM(secret).decrypt(nonce, dem_ct, None)

    kem_ct, nonce, dem_ct = encrypt_to(kp.public_key, plaintext)
    assert decrypt_with(kp.secret_key, kem_ct, nonce, dem_ct) == plaintext


def recipe_6_hybrid() -> None:
    """Hybrid X25519 + ML-KEM-768 for the transition."""
    kem = HybridKEM()
    kp = kem.generate_keypair()
    ciphertext, secret = kem.encapsulate(kp.public_key)
    secret2 = kem.decapsulate(kp.secret_key, ciphertext)
    assert secret == secret2 and len(secret) == 32


def recipe_7_keystore(tmp_path: Path | None = None) -> None:
    """Keys in a LocalKeyStore, used by pqcmap.jwt."""
    base = tmp_path or Path(os.environ.get("TEMP", "/tmp"))
    store_path = base / "cookbook_keys.enc"
    if store_path.exists():
        store_path.unlink()
    audit = base / "cookbook_keys.enc.audit.log"
    if audit.exists():
        audit.unlink()

    ks = LocalKeyStore(passphrase="cookbook-demo",
                       path=str(store_path),
                       rotation_policy=RotationPolicy(max_age_days=90))
    kid = ks.generate_and_store("ML-DSA-65", metadata={"purpose": "jwt"})
    token = jwt.encode({"sub": "123"}, ks.get_private_key(kid), algorithm="ML-DSA-65")
    claims = jwt.decode(token, ks.get_public_key(kid), algorithms=["ML-DSA-65"])
    assert claims["sub"] == "123"

    store_path.unlink(missing_ok=True)
    audit.unlink(missing_ok=True)


RECIPES = [
    ("1  RS256 JWT      -> ML-DSA JWT", recipe_1_jwt),
    ("2  RSA signatures -> ML-DSA", recipe_2_rsa_signatures),
    ("3  ECDSA          -> ML-DSA", recipe_3_ecdsa_signatures),
    ("4  ECDH/X25519    -> ML-KEM", recipe_4_ecdh_to_kem),
    ("5  RSA-OAEP       -> KEM + AES-GCM", recipe_5_kem_dem_encryption),
    ("6  Hybrid         X25519 + ML-KEM-768", recipe_6_hybrid),
    ("7  LocalKeyStore  -> pqcmap.jwt", recipe_7_keystore),
]


def main() -> int:
    import pqcmap

    print(f"pqcmap {pqcmap.__version__}  backend={pqcmap.backend()}\n")
    failures = 0
    for label, fn in RECIPES:
        try:
            fn()
        except Exception as exc:  # pragma: no cover - surfaces a real break
            failures += 1
            print(f"  FAIL  {label}: {exc!r}")
        else:
            print(f"  ok    {label}")
    print()
    if failures:
        print(f"{failures} recipe(s) FAILED")
        return 1
    print("all cookbook recipes verified against the real backend")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
