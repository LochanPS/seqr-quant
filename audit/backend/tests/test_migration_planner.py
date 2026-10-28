"""Migration engine Slice 1 — plan builder + graph-ordered ChangeItems (PRD 14)."""

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
from app.models.crypto_component import CryptoComponent
from app.models.migration import ChangeItem, MigrationPlan
from app.migration.planner import build_plan
from app.spine.ingest import project_component_state
from app.spine.policy import evaluate_policy
from app.spine.sources import DiscoverySource, precedence_for


def _session() -> Session:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def _kex(org, asset_id):
    return CryptoComponent(
        org_id=org, scan_id=uuid.uuid4(), asset_id=asset_id, location_type="tls_kex",
        location_detail="kex", algorithm="X25519", algorithm_family="ECC", quantum_status="vulnerable",
        source=DiscoverySource.EXTERNAL_SCANNER, precedence=precedence_for(DiscoverySource.EXTERNAL_SCANNER),
        observed_at=datetime(2026, 1, 1),
    )


def test_build_plan_from_violations_with_graph_ordering():
    s = _session(); org = uuid.uuid4()
    edge = Asset(org_id=org, type="domain", identifier="bank.in", name="bank.in", provenance="user_declared")
    origin = Asset(org_id=org, type="origin", identifier="origin.bank.in", name="origin", provenance="discovered")
    s.add_all([edge, origin]); s.flush()

    s.add(_kex(org, edge.id))
    s.add(CryptoComponent(
        org_id=org, scan_id=uuid.uuid4(), asset_id=edge.id, location_type="tls_cert",
        location_detail="cert", algorithm="RSA-2048", algorithm_family="RSA", quantum_status="vulnerable",
        source=DiscoverySource.EXTERNAL_SCANNER, precedence=precedence_for(DiscoverySource.EXTERNAL_SCANNER),
        observed_at=datetime(2026, 1, 1),
    ))
    s.add(_kex(org, origin.id))
    s.add(AssetEdge(org_id=org, src_asset_id=edge.id, dst_asset_id=origin.id, relation="origin_of",
                    discovered_by=DiscoverySource.EXTERNAL_SCANNER, confidence=0.6))
    s.commit()
    project_component_state(s, org, edge.id)
    project_component_state(s, org, origin.id)
    s.commit()

    ev = evaluate_policy(s, org); s.commit()
    plan = build_plan(s, org, ev); s.commit()

    assert isinstance(plan, MigrationPlan) and plan.status == "draft"
    items = s.query(ChangeItem).filter_by(plan_id=plan.id).all()
    # one change item per violation
    assert len(items) == ev.violations_count
    actions = {i.action for i in items}
    assert {"enable_hybrid_kex", "reissue_cert_stronger", "harden_origin"} <= actions

    # graph ordering: the edge asset's change items depend on the origin asset's kex change item
    origin_items = [str(i.id) for i in items if i.asset_id == origin.id]
    edge_items = [i for i in items if i.asset_id == edge.id]
    assert origin_items, "origin must have a change item"
    assert any(set(origin_items) <= set(i.depends_on or []) for i in edge_items), \
        "edge changes must depend on origin changes"
