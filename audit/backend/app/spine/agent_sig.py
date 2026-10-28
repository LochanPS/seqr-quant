"""Discovery-agent signature verification (PRD 15 §5/§6/§8).

Ed25519 signatures over an observation batch, mirroring the offline license validator
(`app/license/validator.py`) — same primitive, no new dependency.

The agent (offline) signs the *canonical* JSON encoding of its observation list:

    canonical_bytes(observations) = json.dumps(observations, sort_keys=True,
                                               separators=(",", ":")).encode()

`sort_keys` makes the encoding independent of key order, so an agent in any language can
reproduce the exact bytes. The signature travels as base64 (standard or URL-safe) either in
the ``X-Agent-Signature`` header (live upload) or the ``signature`` field of an air-gap
envelope. The public key is bound to the credential as PEM or base64 raw 32-byte key.
"""

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def canonical_bytes(observations) -> bytes:
    """Deterministic byte encoding of an observation batch — what the agent signs."""
    return json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()


def _b64decode(data: str) -> bytes:
    """Decode base64, accepting both standard and URL-safe alphabets and missing padding."""
    s = (data or "").strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s + pad)
    except Exception:
        return base64.urlsafe_b64decode(s + pad)


def load_public_key(pubkey: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM document or base64-encoded raw 32-byte key."""
    text = (pubkey or "").strip()
    if "-----BEGIN" in text:
        key = load_pem_public_key(text.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("agent public key is not Ed25519")
        return key
    return Ed25519PublicKey.from_public_bytes(_b64decode(text))


def verify(pubkey: str, signature_b64: str, observations) -> bool:
    """Return True iff `signature_b64` is a valid Ed25519 signature by `pubkey` over the
    canonical encoding of `observations`. Never raises — any malformed key/signature is False."""
    if not pubkey or not signature_b64:
        return False
    try:
        key = load_public_key(pubkey)
        key.verify(_b64decode(signature_b64), canonical_bytes(observations))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
