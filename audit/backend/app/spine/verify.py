"""Offline attestation verifier (PRD 13, §6, fork C).

Self-contained: verifies an attestation artifact using only the artifact itself — no database,
no network, no call back to SeQr. Recomputes the canonical payload and checks the Ed25519
signature against the embedded public key, then confirms key_id is consistent with that key.

Trust: matching key_id to the appliance's PUBLISHED public key is an out-of-band step the
auditor performs; this verifier proves the artifact is internally authentic and untampered.

Usage: python -m app.spine.verify path/to/attestation.json
"""

import base64
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.spine.attest import canonical_payload, key_id_for


def verify_artifact(artifact: dict) -> bool:
    try:
        public_raw = base64.b64decode(artifact["public_key"])
        if artifact.get("key_id") != key_id_for(public_raw):
            return False
        payload = canonical_payload(artifact)
        signature = base64.b64decode(artifact["signature"])
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, payload)
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m app.spine.verify <attestation.json>")
        return 2
    with open(argv[1]) as fh:
        artifact = json.load(fh)
    ok = verify_artifact(artifact)
    print("VALID" if ok else "INVALID")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
