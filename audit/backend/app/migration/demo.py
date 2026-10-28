"""End-to-end pipeline demo (Phase 2 checkpoint — "see it work").

Runs the entire lifecycle against a throwaway in-memory database and narrates every stage:
scan observation -> graph -> state -> policy -> violations -> plan -> synthesis -> dry-run ->
bundle -> verify -> convergence. No external services.

Usage: python -m app.migration.demo
"""

import os
import uuid
from datetime import datetime

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
import app.models  # noqa: F401
from app.migration.bundle import MigrationSigner, build_bundle, verify_bundle
from app.migration.dryrun import dry_run
from app.migration.pipeline import pipeline_status
from app.migration.planner import build_plan
from app.migration.verify import verify_plan
from app.models.asset import Asset
from app.models.asset_edge import AssetEdge
from app.models.crypto_component import CryptoComponent
from app.models.migration import ChangeItem
from app.models.policy import Violation
from app.spine.ingest import ingest_scan_graph, project_component_state
from app.spine.policy import evaluate_policy
from app.spine.sources import DiscoverySource, precedence_for


def _h(title):
    print(f"\n=== {title} ===")


def _obs(org, asset_id, loc, algo, fam, status, source, when):
    return CryptoComponent(
        org_id=org, scan_id=uuid.uuid4(), asset_id=asset_id, location_type=loc, location_detail=loc,
        algorithm=algo, algorithm_family=fam, quantum_status=status,
        source=source, precedence=precedence_for(source), observed_at=when,
    )


def run_demo() -> dict:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    s = Session(eng)
    org = uuid.uuid4()

    _h("1. Scan observations (edge asset + exposed origin, all classical)")
    edge = Asset(org_id=org, type="domain", identifier="bank.in", name="bank.in", provenance="user_declared")
    origin = Asset(org_id=org, type="origin", identifier="origin.bank.in", name="origin", provenance="discovered")
    s.add_all([edge, origin]); s.flush()
    s.add(_obs(org, edge.id, "tls_kex", "X25519", "ECC", "vulnerable", DiscoverySource.EXTERNAL_SCANNER, datetime(2026, 1, 1)))
    s.add(_obs(org, edge.id, "tls_cert", "RSA-2048", "RSA", "vulnerable", DiscoverySource.EXTERNAL_SCANNER, datetime(2026, 1, 1)))
    s.add(_obs(org, origin.id, "tls_kex", "X25519", "ECC", "vulnerable", DiscoverySource.EXTERNAL_SCANNER, datetime(2026, 1, 1)))
    s.add(AssetEdge(org_id=org, src_asset_id=edge.id, dst_asset_id=origin.id, relation="origin_of",
                    discovered_by=DiscoverySource.EXTERNAL_SCANNER, confidence=0.6))
    s.commit()
    print(f"  assets=2 (1 edge, 1 discovered origin), 3 observations, 1 origin_of edge")

    _h("2. Project current state")
    project_component_state(s, org, edge.id)
    project_component_state(s, org, origin.id)
    s.commit()
    print(f"  component_states = {s.query(__import__('app.models.component_state', fromlist=['ComponentState']).ComponentState).filter_by(org_id=org).count()}")

    _h("3. Policy evaluation -> violations")
    ev = evaluate_policy(s, org); s.commit()
    for v in s.query(Violation).filter_by(evaluation_id=ev.id).all():
        print(f"  [{v.severity}] {v.rule_key}  actual={v.actual}  -> {v.target_state}")

    _h("4. Migration plan (graph-ordered change items)")
    plan = build_plan(s, org, ev); s.commit()
    for ci in s.query(ChangeItem).filter_by(plan_id=plan.id).all():
        dep = f"  depends_on={ci.depends_on}" if ci.depends_on else ""
        print(f"  {ci.provider}: {ci.action} on {ci.slot_key or '-'}{dep}")

    _h("5. Dry-run preview (no writes)")
    preview = dry_run(s, org, ev)
    print(f"  changes={preview['change_count']} by_platform={preview['by_platform']} persisted={preview['persisted']}")

    _h("6. Bundle + offline verify")
    row, tar_bytes, manifest = build_bundle(s, plan, MigrationSigner.generate()); s.commit()
    print(f"  bundle key_id={manifest['bundle']['key_id']} artifacts={len(manifest['bundle']['artifacts'])} "
          f"verify={verify_bundle(tar_bytes)}")

    _h("7. Customer applies fix -> re-scan observes hybrid -> verify convergence")
    s.add(_obs(org, edge.id, "tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", DiscoverySource.ACTIVE_PROBE, datetime(2026, 1, 2)))
    s.add(_obs(org, origin.id, "tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", DiscoverySource.ACTIVE_PROBE, datetime(2026, 1, 2)))
    # close the origin bypass edge (hardened) so the origin rule clears too
    edge_row = s.query(AssetEdge).filter_by(org_id=org, relation="origin_of").first()
    edge_row.valid_to = datetime(2026, 1, 2)
    # reissue cert stronger
    s.add(_obs(org, edge.id, "tls_cert", "RSA-3072", "RSA", "vulnerable", DiscoverySource.EXTERNAL_SCANNER, datetime(2026, 1, 2)))
    s.commit()
    project_component_state(s, org, edge.id); project_component_state(s, org, origin.id); s.commit()
    report = verify_plan(s, plan); s.commit()
    print(f"  converged={report['converged']} cleared={len(report['cleared'])} remaining={len(report['remaining'])} "
          f"plan.status={plan.status}")

    _h("8. Pipeline status")
    status = pipeline_status(s, org)
    for k in ("assets", "edges", "component_states", "open_violations", "plans", "bundles", "converged"):
        print(f"  {k}: {status[k]}")

    s.close()
    return status


if __name__ == "__main__":
    run_demo()
