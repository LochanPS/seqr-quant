"""Attestation signing (PRD 13, §6, fork C).

A signed, reproducible statement of crypto posture at a point in time. Uses a dedicated
Ed25519 attestation key — separate from the licensing key. The signing key is pluggable:
local key now (env/file), swappable to a KMS/HSM later without touching callers.

The signature covers a canonical (deterministic) JSON payload of the pinned fields, so any
tamper invalidates it, and the same inputs always produce the same bytes. Verification is
offline and self-contained (see verify.py) — the artifact carries its own public key; trust
is established by matching key_id against the appliance's published key out-of-band.
"""

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session

from app.graph_schema import GRAPH_SCHEMA_VERSION
from app.models.attestation import Attestation
from app.models.policy import Policy, PolicyEvaluation
from app.spine.ingest import record_event

# Fields covered by the signature, in a fixed set. Serialized sorted + compact so signer and
# verifier compute identical bytes.
CANON_FIELDS = [
    "org_id", "policy_id", "policy_version", "policy_content_hash",
    "evaluation_id", "evaluation_result_hash", "covered_asset_set",
    "scanner_version", "migration_engine_version", "graph_schema_version",
    "key_id", "created_at",
]


def canonical_payload(d: dict) -> bytes:
    return json.dumps({k: d[k] for k in CANON_FIELDS}, sort_keys=True, separators=(",", ":")).encode()


def key_id_for(public_raw: bytes) -> str:
    return "att_" + hashlib.sha256(public_raw).hexdigest()[:16]


class AttestationSigner:
    """Wraps an Ed25519 private key. `key_id` is derived from the public key (rotation-safe)."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self._pk = private_key.public_key()
        self.public_raw = self._pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_id = key_id_for(self.public_raw)

    @classmethod
    def generate(cls) -> "AttestationSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> "AttestationSigner":
        return cls(serialization.load_pem_private_key(pem, password=password))

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(self._sk.sign(payload)).decode()

    def public_b64(self) -> str:
        return base64.b64encode(self.public_raw).decode()

    def private_pem(self) -> bytes:
        return self._sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def get_signer() -> AttestationSigner:
    """Load the deployment's attestation signer.

    Order: ATTESTATION_PRIVATE_KEY_PEM env -> ATTESTATION_KEY_PATH file -> generate+persist
    (dev/on-prem first boot). A SaaS deployment overrides this to fetch from KMS.
    """
    pem = os.environ.get("ATTESTATION_PRIVATE_KEY_PEM")
    if pem:
        return AttestationSigner.from_pem(pem.encode())
    path = os.environ.get("ATTESTATION_KEY_PATH")
    if path and os.path.exists(path):
        with open(path, "rb") as fh:
            return AttestationSigner.from_pem(fh.read())
    signer = AttestationSigner.generate()
    if path:
        with open(path, "wb") as fh:
            fh.write(signer.private_pem())
    return signer


def create_attestation(
    db: Session,
    org_id,
    evaluation: PolicyEvaluation,
    signer: AttestationSigner,
    scanner_version: str | None = None,
    migration_engine_version: str | None = None,
    actor: str = "system",
) -> tuple[Attestation, dict]:
    """Build, sign, and persist an attestation over a policy evaluation. Returns (row, artifact)."""
    org_id = evaluation.org_id
    policy = db.get(Policy, evaluation.policy_id)
    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    fields = {
        "org_id": str(org_id),
        "policy_id": str(evaluation.policy_id),
        "policy_version": policy.version if policy else "",
        "policy_content_hash": evaluation.policy_content_hash,
        "evaluation_id": str(evaluation.id),
        "evaluation_result_hash": evaluation.result_hash,
        "covered_asset_set": list(evaluation.covered_asset_set or []),
        "scanner_version": scanner_version,
        "migration_engine_version": migration_engine_version,
        "graph_schema_version": GRAPH_SCHEMA_VERSION,
        "key_id": signer.key_id,
        "created_at": created_at,
    }
    signature = signer.sign(canonical_payload(fields))
    artifact = {**fields, "signature": signature, "public_key": signer.public_b64(),
                "algorithm": "ed25519"}

    row = Attestation(
        org_id=org_id,
        policy_id=evaluation.policy_id,
        policy_version=fields["policy_version"],
        policy_content_hash=evaluation.policy_content_hash,
        evaluation_id=evaluation.id,
        evaluation_result_hash=evaluation.result_hash,
        covered_asset_set=fields["covered_asset_set"],
        scanner_version=scanner_version,
        migration_engine_version=migration_engine_version,
        graph_schema_version=GRAPH_SCHEMA_VERSION,
        key_id=signer.key_id,
        signature=signature,
        artifact_json=artifact,
    )
    db.add(row)
    db.flush()

    record_event(db, org_id, "attested", actor, None,
                 {"attestation_id": str(row.id), "evaluation_id": str(evaluation.id)})
    return row, artifact
