"""Agent-side Ed25519 signing — the exact mirror of the platform's verifier.

The platform (`app/spine/agent_sig.py`) verifies a signature over the *canonical* JSON
encoding of the observation list:

    canonical_bytes(observations) = json.dumps(observations, sort_keys=True,
                                               separators=(",", ":")).encode()

`sort_keys` makes the bytes independent of key order, so this must produce byte-identical
output to the server. Observations MUST already be JSON-native (dates as ISO strings, no
datetime objects) so the agent's canonical bytes match the bytes the server re-derives from
the wire body. The signing key is a per-agent Ed25519 key, generated once and persisted; its
public half is bound to the credential trust-on-first-use.
"""

import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)


def canonical_bytes(observations) -> bytes:
    """Deterministic byte encoding of an observation batch — what the agent signs.

    Byte-for-byte identical to the platform's ``agent_sig.canonical_bytes``.
    """
    return json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()


def load_or_create_key(keyfile: str) -> tuple[Ed25519PrivateKey, bool]:
    """Load the agent's Ed25519 private key from ``keyfile`` (PEM/PKCS8), or generate and
    persist a fresh one. Returns ``(private_key, created)``. The key file is written with
    owner-only permissions where the platform supports it (best effort on Windows)."""
    if os.path.exists(keyfile):
        with open(keyfile, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{keyfile} is not an Ed25519 private key")
        return key, False

    priv = Ed25519PrivateKey.generate()
    parent = os.path.dirname(os.path.abspath(keyfile))
    if parent:
        os.makedirs(parent, exist_ok=True)
    pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    # Create restrictively where possible, then write.
    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    try:
        os.chmod(keyfile, 0o600)
    except OSError:
        pass  # Windows / restricted FS — best effort.
    return priv, True


def public_key_b64(priv: Ed25519PrivateKey) -> str:
    """Raw 32-byte public key, base64 — the trust-on-first-use ``X-Agent-Public-Key`` value."""
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def public_key_pem(priv: Ed25519PrivateKey) -> str:
    """SubjectPublicKeyInfo PEM — the form air-gap operators paste when enrolling a key."""
    return priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()


def sign(priv: Ed25519PrivateKey, observations) -> str:
    """Ed25519-sign the canonical encoding of ``observations``; return base64 signature."""
    return base64.b64encode(priv.sign(canonical_bytes(observations))).decode()


def verify(pubkey_b64_or_pem: str, signature_b64: str, observations) -> bool:
    """Self-check a signature the way the platform will (used by tests + `verify-envelope`).

    Accepts the public key as raw-32-byte base64 or SubjectPublicKeyInfo PEM. Never raises.
    """
    if not pubkey_b64_or_pem or not signature_b64:
        return False
    try:
        text = pubkey_b64_or_pem.strip()
        if "-----BEGIN" in text:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            key = load_pem_public_key(text.encode())
            if not isinstance(key, Ed25519PublicKey):
                return False
        else:
            key = Ed25519PublicKey.from_public_bytes(_b64decode(text))
        key.verify(_b64decode(signature_b64), canonical_bytes(observations))
        return True
    except Exception:
        return False


def _b64decode(data: str) -> bytes:
    s = (data or "").strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s + pad)
    except Exception:
        return base64.urlsafe_b64decode(s + pad)
