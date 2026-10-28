"""Migration bundle engine (PRD 14, Slice 3)."""

import io
import json
import os
import tarfile
import uuid
from datetime import datetime

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
import app.models  # noqa: F401
from app.migration.bundle import MigrationSigner, build_bundle, verify_bundle, _deterministic_tar
from app.migration.planner import build_plan
from app.models.asset import Asset
from app.models.crypto_component import CryptoComponent
from app.models.migration import MigrationBundle
from app.spine.ingest import project_component_state
from app.spine.policy import evaluate_policy
from app.spine.sources import DiscoverySource, precedence_for


def _plan(s: Session, org):
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
    return build_plan(s, org, ev)


def _session() -> Session:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def _repack(tar_bytes: bytes, mutate) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        files = {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}
    mutate(files)
    return _deterministic_tar(files)


def test_build_and_offline_verify():
    s = _session(); org = uuid.uuid4()
    plan = _plan(s, org)
    row, tar_bytes, manifest = build_bundle(s, plan, MigrationSigner.generate()); s.commit()

    assert verify_bundle(tar_bytes) is True
    assert plan.status == "bundled"
    assert s.query(MigrationBundle).filter_by(plan_id=plan.id).count() == 1
    assert manifest["bundle"]["key_id"].startswith("mig_")  # dedicated migration key, not att_


def test_tampered_artifact_fails_verification():
    s = _session(); org = uuid.uuid4()
    _, tar_bytes, _ = build_bundle(s, _plan(s, org), MigrationSigner.generate()); s.commit()

    def _corrupt(files):
        name = next(n for n in files if n.startswith("artifacts/"))
        files[name] = files[name] + b"tampered"
    assert verify_bundle(_repack(tar_bytes, _corrupt)) is False


def test_tampered_manifest_fails_verification():
    s = _session(); org = uuid.uuid4()
    _, tar_bytes, _ = build_bundle(s, _plan(s, org), MigrationSigner.generate()); s.commit()

    def _corrupt(files):
        m = json.loads(files["manifest.json"])
        m["bundle"]["plan_id"] = str(uuid.uuid4())  # change signed content -> signature invalid
        files["manifest.json"] = json.dumps(m).encode()
    assert verify_bundle(_repack(tar_bytes, _corrupt)) is False


def test_bundle_signed_portion_is_deterministic():
    s = _session(); org = uuid.uuid4()
    plan = _plan(s, org)
    signer = MigrationSigner.generate()
    _, _, m1 = build_bundle(s, plan, signer)
    _, _, m2 = build_bundle(s, plan, signer)
    # signed portion + signature are a pure function of plan + key (created_at is unsigned)
    assert m1["bundle"] == m2["bundle"]
    assert m1["signature"] == m2["signature"]
