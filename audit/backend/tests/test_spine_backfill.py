"""Backfill of historical scans into the spine graph (PRD 13, Phase 1 final)."""

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
from app.models.asset_edge import AssetEdge
from app.models.asset_identity import AssetIdentity
from app.models.component_state import ComponentState
from app.models.crypto_component import CryptoComponent
from app.models.policy import PolicyEvaluation, Violation
from app.models.scan import Scan
from app.spine.backfill import backfill


def _session() -> Session:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def _legacy_scan(s: Session, org):
    """A pre-spine scan: a Scan + crypto_components with none of the graph wiring."""
    asset = Asset(org_id=org, type="domain", identifier="bank.in", name="bank.in", provenance="user_declared")
    s.add(asset); s.flush()
    scan = Scan(org_id=org, asset_id=asset.id, type="domain", status="complete",
                completed_at=datetime(2026, 1, 1), transport_summary={
                    "scan_target": "edge", "origin_candidates": ["origin.bank.in"]})
    s.add(scan); s.flush()
    for loc, algo, fam in [("tls_kex", "X25519", "ECC"), ("tls_cert", "RSA-2048", "RSA")]:
        s.add(CryptoComponent(org_id=org, scan_id=scan.id, asset_id=asset.id, location_type=loc,
                              location_detail=loc, algorithm=algo, algorithm_family=fam,
                              quantum_status="vulnerable"))
    s.commit()
    return asset


def test_backfill_builds_graph_and_is_idempotent():
    s = _session(); org = uuid.uuid4()
    _legacy_scan(s, org)

    summary = backfill(s)
    assert summary["scans"] == 1 and summary["assets"] == 1

    # graph wired up
    assert s.query(AssetIdentity).filter_by(org_id=org).count() >= 1
    assert s.query(ComponentState).filter_by(org_id=org).count() == 2  # tls:kex + tls:cert
    # discovered origin + edge
    assert s.query(Asset).filter_by(identifier="origin.bank.in").count() == 1
    assert s.query(AssetEdge).filter_by(org_id=org, relation="origin_of").count() == 1
    # deterministic evaluation with violations, no attestation created
    ev = s.query(PolicyEvaluation).filter_by(org_id=org).order_by(PolicyEvaluation.ran_at.desc()).first()
    assert ev is not None and ev.violations_count >= 1
    assert {v.rule_key for v in s.query(Violation).filter_by(evaluation_id=ev.id)} >= {
        "kex_must_be_hybrid", "cert_min_rsa", "no_exposed_classical_origin"}

    # observations were enriched to the scan's real time, not duplicated
    obs = s.query(CryptoComponent).filter_by(org_id=org).all()
    assert len(obs) == 2
    assert all(o.observed_at == datetime(2026, 1, 1) for o in obs)

    # idempotent: re-run does not duplicate assets/identities/edges/state
    counts_before = (
        s.query(Asset).count(), s.query(AssetIdentity).count(),
        s.query(AssetEdge).count(), s.query(ComponentState).count(),
        s.query(CryptoComponent).count(),
    )
    backfill(s)
    counts_after = (
        s.query(Asset).count(), s.query(AssetIdentity).count(),
        s.query(AssetEdge).count(), s.query(ComponentState).count(),
        s.query(CryptoComponent).count(),
    )
    assert counts_before == counts_after
