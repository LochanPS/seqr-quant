"""Platform-spine ingest validation (PRD 13, Slice 2).

Guards the Slice-2 acceptance gate:
  - rescans do not duplicate assets or component_state rows
  - identity resolution is deterministic
  - current state is reproducible from the append-only observations alone
  - source precedence beats recency; disagreeing sources flag a conflict
Self-contained: builds its own in-memory SQLite, no app fixtures required.
"""

import os
import uuid
from datetime import datetime, timedelta

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
import app.models  # noqa: F401 — register models
from app.models.asset import Asset
from app.models.component_state import ComponentState
from app.models.crypto_component import CryptoComponent
from app.spine.ingest import project_component_state, resolve_asset
from app.spine.sources import DiscoverySource, precedence_for


def _session() -> Session:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def _obs(org, asset_id, source, algo, status, when):
    return CryptoComponent(
        org_id=org, scan_id=uuid.uuid4(), asset_id=asset_id,
        location_type="tls_kex", location_detail="bank.in:443 (kex)", algorithm=algo,
        algorithm_family="ML-KEM" if status == "hybrid" else "ECC", quantum_status=status,
        source=source, precedence=precedence_for(source), observed_at=when,
    )


def test_projection_precedence_conflict_and_reproducibility():
    s = _session()
    org = uuid.uuid4()
    asset = Asset(org_id=org, type="domain", identifier="bank.in", name="bank.in", provenance="user_declared")
    s.add(asset); s.flush()
    t0 = datetime(2026, 1, 1)

    # 1) external passive classical
    s.add(_obs(org, asset.id, DiscoverySource.EXTERNAL_SCANNER, "X25519", "vulnerable", t0)); s.commit()
    project_component_state(s, org, asset.id); s.commit()
    cs = s.query(ComponentState).filter_by(asset_id=asset.id, slot_key="tls:kex").all()
    assert len(cs) == 1
    assert s.get(CryptoComponent, cs[0].winning_observation_id).source == DiscoverySource.EXTERNAL_SCANNER

    # 2) active probe hybrid, later + higher precedence -> wins, conflict flagged
    s.add(_obs(org, asset.id, DiscoverySource.ACTIVE_PROBE, "X25519MLKEM768", "hybrid", t0 + timedelta(days=1))); s.commit()
    project_component_state(s, org, asset.id); s.commit()
    cs = s.query(ComponentState).filter_by(asset_id=asset.id, slot_key="tls:kex").all()
    assert len(cs) == 1, "rescan must not duplicate component_state"
    assert s.get(CryptoComponent, cs[0].winning_observation_id).source == DiscoverySource.ACTIVE_PROBE
    assert cs[0].conflict is True

    # 3) external passive again LATER but LOWER precedence -> must not win
    s.add(_obs(org, asset.id, DiscoverySource.EXTERNAL_SCANNER, "X25519", "vulnerable", t0 + timedelta(days=2))); s.commit()
    project_component_state(s, org, asset.id); s.commit()
    cs = s.query(ComponentState).filter_by(asset_id=asset.id, slot_key="tls:kex").one()
    assert s.get(CryptoComponent, cs.winning_observation_id).source == DiscoverySource.ACTIVE_PROBE, "precedence beats recency"

    # append-only: all three observations retained
    assert s.query(CryptoComponent).filter_by(asset_id=asset.id).count() == 3

    # reproducible from observations alone
    s.query(ComponentState).delete(); s.commit()
    project_component_state(s, org, asset.id); s.commit()
    cs2 = s.query(ComponentState).filter_by(asset_id=asset.id, slot_key="tls:kex").one()
    assert s.get(CryptoComponent, cs2.winning_observation_id).source == DiscoverySource.ACTIVE_PROBE


def test_identity_resolver_is_deterministic():
    s = _session()
    org = uuid.uuid4()
    a1 = resolve_asset(s, org, "host", "origin.bank.in", asset_type="origin"); s.flush()
    a2 = resolve_asset(s, org, "host", "origin.bank.in", asset_type="origin")
    assert a1 == a2
    assert s.query(Asset).filter_by(identifier="origin.bank.in").count() == 1
