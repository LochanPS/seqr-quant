"""Migration engine Slices 4-5 — dry-run, rollback, verify-by-rescan (PRD 14)."""

import os
import uuid
from datetime import datetime, timedelta

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
import app.models  # noqa: F401
from app.migration.bundle import MigrationSigner, build_bundle
from app.migration.dryrun import dry_run
from app.migration.planner import build_plan
from app.migration.verify import verify_plan
from app.models.asset import Asset
from app.models.crypto_component import CryptoComponent
from app.models.migration import ChangeItem, MigrationPlan, RollbackPlan
from app.spine.ingest import project_component_state
from app.spine.policy import evaluate_policy
from app.spine.sources import DiscoverySource, precedence_for


def _session() -> Session:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return Session(eng)


def _kex(org, asset_id, source, algo, fam, status, when):
    return CryptoComponent(
        org_id=org, scan_id=uuid.uuid4(), asset_id=asset_id, location_type="tls_kex",
        location_detail="kex", algorithm=algo, algorithm_family=fam, quantum_status=status,
        source=source, precedence=precedence_for(source), observed_at=when,
    )


def _classical_kex_asset(s, org):
    a = Asset(org_id=org, type="domain", identifier="bank.in", name="bank.in", provenance="user_declared")
    s.add(a); s.flush()
    s.add(_kex(org, a.id, DiscoverySource.EXTERNAL_SCANNER, "X25519", "ECC", "vulnerable", datetime(2026, 1, 1)))
    s.commit()
    project_component_state(s, org, a.id); s.commit()
    return a


def test_dry_run_previews_without_persisting():
    s = _session(); org = uuid.uuid4()
    _classical_kex_asset(s, org)
    ev = evaluate_policy(s, org); s.commit()

    preview = dry_run(s, org, ev)
    assert preview["change_count"] >= 1 and preview["persisted"] is False
    assert preview["changes"][0]["action"] == "enable_hybrid_kex"
    # nothing was written
    assert s.query(MigrationPlan).count() == 0
    assert s.query(ChangeItem).count() == 0


def test_bundle_captures_rollback_per_change_item():
    s = _session(); org = uuid.uuid4()
    _classical_kex_asset(s, org)
    ev = evaluate_policy(s, org); s.commit()
    plan = build_plan(s, org, ev); s.commit()
    build_bundle(s, plan, MigrationSigner.generate()); s.commit()

    items = s.query(ChangeItem).filter_by(plan_id=plan.id).count()
    rbs = s.query(RollbackPlan).filter_by(org_id=org).all()
    assert len(rbs) == items and all(r.inverse_artifact for r in rbs)


def test_verify_converges_after_fix_reobserved():
    s = _session(); org = uuid.uuid4()
    asset = _classical_kex_asset(s, org)
    ev = evaluate_policy(s, org); s.commit()
    plan = build_plan(s, org, ev); s.commit()

    # customer applies the fix; a re-scan observes hybrid PQC (higher-precedence active probe)
    s.add(_kex(org, asset.id, DiscoverySource.ACTIVE_PROBE, "X25519MLKEM768", "ML-KEM", "hybrid",
               datetime(2026, 1, 2)))
    s.commit()
    project_component_state(s, org, asset.id); s.commit()

    report = verify_plan(s, plan); s.commit()
    assert report["converged"] is True
    assert report["cleared"] and not report["remaining"]
    assert plan.status == "verified"
