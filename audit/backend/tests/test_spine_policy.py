"""Policy engine validation (PRD 13, Slice 3)."""

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
from app.models.component_state import ComponentState
from app.models.crypto_component import CryptoComponent
from app.models.policy import Violation
from app.spine.ingest import project_component_state
from app.spine.policy import evaluate_policy
from app.spine.sources import DiscoverySource, precedence_for


def _session() -> Session:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def _obs(org, asset_id, loc, algo, fam, status):
    return CryptoComponent(
        org_id=org, scan_id=uuid.uuid4(), asset_id=asset_id, location_type=loc,
        location_detail=f"{loc}", algorithm=algo, algorithm_family=fam, quantum_status=status,
        source=DiscoverySource.EXTERNAL_SCANNER, precedence=precedence_for(DiscoverySource.EXTERNAL_SCANNER),
        observed_at=datetime(2026, 1, 1),
    )


def test_classical_graph_trips_kex_cert_and_origin_rules():
    s = _session()
    org = uuid.uuid4()
    asset = Asset(org_id=org, type="domain", identifier="bank.in", name="bank.in", provenance="user_declared")
    origin = Asset(org_id=org, type="origin", identifier="origin.bank.in", name="origin.bank.in", provenance="discovered")
    s.add_all([asset, origin]); s.flush()

    s.add(_obs(org, asset.id, "tls_kex", "X25519", "ECC", "vulnerable"))
    s.add(_obs(org, asset.id, "tls_cert", "RSA-2048", "RSA", "vulnerable"))
    s.add(AssetEdge(org_id=org, src_asset_id=asset.id, dst_asset_id=origin.id,
                    relation="origin_of", discovered_by=DiscoverySource.EXTERNAL_SCANNER, confidence=0.6))
    s.commit()
    project_component_state(s, org, asset.id); s.commit()

    ev = evaluate_policy(s, org); s.commit()
    keys = {v.rule_key for v in s.query(Violation).filter_by(evaluation_id=ev.id).all()}
    assert keys == {"kex_must_be_hybrid", "cert_min_rsa", "no_exposed_classical_origin"}
    assert ev.violations_count == 3

    # component_state now references this evaluation (compliance computed from it, not stored)
    states = s.query(ComponentState).filter_by(org_id=org).all()
    assert states and all(st.latest_policy_evaluation_id == ev.id for st in states)

    # reproducible: same graph -> same result hash
    ev2 = evaluate_policy(s, org); s.commit()
    assert ev2.result_hash == ev.result_hash


def test_hybrid_kex_passes_the_kex_rule():
    s = _session()
    org = uuid.uuid4()
    asset = Asset(org_id=org, type="domain", identifier="ok.in", name="ok.in", provenance="user_declared")
    s.add(asset); s.flush()
    s.add(_obs(org, asset.id, "tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid"))
    s.commit()
    project_component_state(s, org, asset.id); s.commit()

    ev = evaluate_policy(s, org); s.commit()
    keys = {v.rule_key for v in s.query(Violation).filter_by(evaluation_id=ev.id).all()}
    assert "kex_must_be_hybrid" not in keys
