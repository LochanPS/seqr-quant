"""Attestation signing + offline verification (PRD 13, Slice 4)."""

import os
import uuid
from datetime import datetime

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
import app.models  # noqa: F401
from app.models.asset import Asset
from app.models.crypto_component import CryptoComponent
from app.spine.attest import AttestationSigner, create_attestation
from app.spine.ingest import project_component_state
from app.spine.policy import evaluate_policy
from app.spine.sources import DiscoverySource, precedence_for
from app.spine.verify import verify_artifact


def _evaluation(s: Session, org):
    asset = Asset(org_id=org, type="domain", identifier="bank.in", name="bank.in", provenance="user_declared")
    s.add(asset); s.flush()
    s.add(CryptoComponent(
        org_id=org, scan_id=uuid.uuid4(), asset_id=asset.id, location_type="tls_kex",
        location_detail="kex", algorithm="X25519", algorithm_family="ECC", quantum_status="vulnerable",
        source=DiscoverySource.EXTERNAL_SCANNER, precedence=precedence_for(DiscoverySource.EXTERNAL_SCANNER),
        observed_at=datetime(2026, 1, 1),
    ))
    s.commit()
    project_component_state(s, org, asset.id); s.commit()
    ev = evaluate_policy(s, org); s.commit()
    return ev


def _session() -> Session:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def test_sign_and_offline_verify():
    s = _session(); org = uuid.uuid4()
    ev = _evaluation(s, org)
    signer = AttestationSigner.generate()
    row, artifact = create_attestation(s, org, ev, signer, scanner_version="0.1.1"); s.commit()

    # offline: verification uses ONLY the artifact (no db, no network)
    assert verify_artifact(artifact) is True
    assert artifact["evaluation_result_hash"] == ev.result_hash
    assert artifact["key_id"] == signer.key_id


def test_artifact_persisted_on_row_and_verifies():
    # The exact signed certificate must be stored on the row so download-later reproduces
    # it byte-for-byte and still verifies offline (the signed created_at differs from the
    # row's default created_at, so reconstructing from columns would break the signature).
    s = _session(); org = uuid.uuid4()
    ev = _evaluation(s, org)
    row, artifact = create_attestation(s, org, ev, AttestationSigner.generate()); s.commit()

    assert row.artifact_json is not None
    assert row.artifact_json == artifact
    assert verify_artifact(row.artifact_json) is True


def test_tampering_invalidates_signature():
    s = _session(); org = uuid.uuid4()
    ev = _evaluation(s, org)
    _, artifact = create_attestation(s, org, ev, AttestationSigner.generate()); s.commit()

    assert verify_artifact({**artifact, "evaluation_result_hash": "deadbeef"}) is False
    assert verify_artifact({**artifact, "covered_asset_set": []}) is False
    assert verify_artifact({**artifact, "org_id": str(uuid.uuid4())}) is False


def test_same_inputs_same_evaluation_hash():
    s = _session(); org = uuid.uuid4()
    ev = _evaluation(s, org)
    # re-evaluating the same graph yields the same result hash -> reproducible attestation
    ev2 = evaluate_policy(s, org); s.commit()
    assert ev2.result_hash == ev.result_hash


def test_rotation_and_historical_verifiability():
    s = _session(); org = uuid.uuid4()
    ev = _evaluation(s, org)
    signer1 = AttestationSigner.generate()
    _, artifact1 = create_attestation(s, org, ev, signer1); s.commit()

    # rotate to a new key
    signer2 = AttestationSigner.generate()
    assert signer1.key_id != signer2.key_id

    # a later evaluation / policy change does not break the old attestation
    evaluate_policy(s, org); s.commit()
    assert verify_artifact(artifact1) is True  # still verifiable with its embedded key
