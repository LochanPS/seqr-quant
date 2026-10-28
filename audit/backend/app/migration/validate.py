"""Internal validation harness (Phase 2 checkpoint).

Seeds a realistic enterprise, runs the whole pipeline, and inspects EVERY stage — asset
discovery, graph, identity, observations, policy, violations, plan, synthesis, bundle, bundle
verification, re-scan, convergence, attestation, offline verification, REST surface, and the
audit trail. Prints a checklist and returns a structured report so every intermediate object
is observable.

Usage: python -m app.migration.validate
"""

import os
from collections import Counter

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
import app.models  # noqa: F401
from app.migration.templates import TEMPLATES, build
from app.migration.synthesis import synthesize_plan
from app.migration.verify import verify_plan
from app.models.asset import Asset
from app.models.asset_edge import AssetEdge
from app.models.asset_identity import AssetIdentity
from app.models.attestation import Attestation
from app.models.component_state import ComponentState
from app.models.crypto_component import CryptoComponent
from app.models.event import Event
from app.models.migration import ChangeItem, MigrationBundle, MigrationPlan
from app.models.policy import PolicyEvaluation, Violation
from app.spine.ingest import project_component_state
from app.spine.sources import DiscoverySource, precedence_for


def _remediate_everything(s: Session, org, ev_id):
    """Simulate the customer applying every fix, then a re-scan re-observing compliant crypto."""
    import uuid
    from datetime import datetime

    for v in s.query(Violation).filter_by(evaluation_id=ev_id).all():
        st = s.query(ComponentState).filter_by(asset_id=v.asset_id).all()
        slots = {c.slot_key for c in st}
        # Operator-confirmed remediation: MANUAL_OVERRIDE is highest precedence, so it dominates
        # even agent-observed slots (a re-scan by the same source would too — this keeps it simple).
        fix = DiscoverySource.MANUAL_OVERRIDE
        if "tls:kex" in slots:
            s.add(CryptoComponent(org_id=org, scan_id=uuid.uuid4(), asset_id=v.asset_id,
                  location_type="tls_kex", location_detail="kex", algorithm="X25519MLKEM768",
                  algorithm_family="ML-KEM", quantum_status="hybrid", source=fix,
                  precedence=precedence_for(fix), observed_at=datetime(2026, 7, 1)))
        if "tls:cert" in slots:
            s.add(CryptoComponent(org_id=org, scan_id=uuid.uuid4(), asset_id=v.asset_id,
                  location_type="tls_cert", location_detail="cert", algorithm="RSA-3072",
                  algorithm_family="RSA", quantum_status="vulnerable", key_size=3072,
                  source=fix, precedence=precedence_for(fix), observed_at=datetime(2026, 7, 1)))
    # close every exposed-origin edge (hardened)
    for e in s.query(AssetEdge).filter_by(org_id=org, relation="origin_of").all():
        e.valid_to = datetime(2026, 7, 1)
    s.commit()
    for a in s.query(Asset).filter_by(org_id=org).all():
        project_component_state(s, org, a.id)
    s.commit()


def run_internal_validation(template: str = "banking") -> dict:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    s = Session(eng)

    seeded = build(s, TEMPLATES[template])
    org = seeded["org_id"]
    ev_id = seeded["evaluation_id"]
    plan_id = seeded["plan_id"]

    stages: list[dict] = []

    def stage(name, ok, detail):
        stages.append({"stage": name, "ok": ok if ok is None else bool(ok), "detail": detail})

    assets = s.query(Asset).filter_by(org_id=org).all()
    stage("Asset discovery", len(assets) >= 4,
          {"total": len(assets), "by_type": dict(Counter(a.type for a in assets)),
           "by_provenance": dict(Counter(a.provenance for a in assets))})

    edges = s.query(AssetEdge).filter_by(org_id=org).all()
    stage("Crypto-asset graph", len(edges) >= 1,
          {"edges": len(edges), "relations": dict(Counter(e.relation for e in edges))})

    idents = s.query(AssetIdentity).filter_by(org_id=org).count()
    stage("Identity resolution", idents == len(assets), {"identities": idents, "assets": len(assets)})

    obs = s.query(CryptoComponent).filter_by(org_id=org).all()
    stage("Temporal observations", len(obs) >= 6,
          {"observations": len(obs), "by_source": dict(Counter(o.source for o in obs))})

    states = s.query(ComponentState).filter_by(org_id=org).all()
    stage("State projection", len(states) >= 4,
          {"component_states": len(states), "conflicts": sum(1 for x in states if x.conflict)})

    ev = s.get(PolicyEvaluation, ev_id)
    stage("Policy evaluation", ev is not None and bool(ev.result_hash),
          {"result_hash": ev.result_hash[:16] + "...", "violations": ev.violations_count})

    viols = s.query(Violation).filter_by(evaluation_id=ev_id).all()
    stage("Violation generation", len(viols) >= 2,
          {"count": len(viols), "by_rule": dict(Counter(v.rule_key for v in viols))})

    items = s.query(ChangeItem).filter_by(plan_id=plan_id).all()
    stage("Migration planning", len(items) >= 2,
          {"change_items": len(items), "actions": dict(Counter(i.action for i in items)),
           "ordered": sum(1 for i in items if i.depends_on)})

    plan = s.get(MigrationPlan, plan_id)
    artifacts = synthesize_plan(s, plan)
    stage("Configuration synthesis", all(a.snippets or a.action.startswith(("no_action", "manual")) for a in artifacts),
          {"artifacts": len(artifacts), "platforms": dict(Counter(a.target_platform for a in artifacts))})

    bundle = s.query(MigrationBundle).filter_by(plan_id=plan_id).first()
    stage("Bundle generation", bundle is not None and bool(bundle.signature),
          {"key_id": bundle.key_id, "artifacts": len(seeded["bundle_manifest"]["bundle"]["artifacts"])})

    stage("Bundle offline verification", seeded["bundle_offline_verify"] is True,
          {"verified": seeded["bundle_offline_verify"]})

    # re-scan + convergence
    _remediate_everything(s, org, ev_id)
    report = verify_plan(s, plan); s.commit()
    stage("Re-scan + policy convergence", report["converged"] is True,
          {"converged": report["converged"], "cleared": len(report["cleared"]),
           "remaining": len(report["remaining"]), "plan_status": plan.status})

    att = s.get(Attestation, seeded["attestation_id"])
    stage("Attestation generation", att is not None and bool(att.signature),
          {"key_id": att.key_id, "graph_schema_version": att.graph_schema_version})

    stage("Attestation offline verification", seeded["attestation_offline_verify"] is True,
          {"verified": seeded["attestation_offline_verify"]})

    from app.main import app
    paths = {r.path for r in app.routes}
    need = {"/api/v1/graph/assets", "/api/v1/migration/pipeline", "/api/v1/graph/attestations"}
    stage("REST API surface", need <= paths, {"present": sorted(need & paths)})

    events = s.query(Event).filter_by(org_id=org).all()
    etypes = set(e.type for e in events)
    expected = {"measured", "policy_evaluated", "migration_planned", "migration_bundled", "attested", "migration_verified"}
    stage("Complete audit trail", expected <= etypes,
          {"events": len(events), "types": sorted(etypes)})

    stage("Dashboard visualization", None,  # not built yet - next milestone, not a failure
          {"status": "pending - next milestone (renders /migration/pipeline + /graph/*)"})

    s.close()
    passed = sum(1 for st in stages if st["ok"] is True)
    checkable = sum(1 for st in stages if st["ok"] is not None)
    return {"stages": stages, "passed": passed, "checkable": checkable,
            "all_ok": passed == checkable}


def run_all_templates() -> dict:
    """Validate every sector template end-to-end. Returns {template: all_ok}."""
    return {key: run_internal_validation(key)["all_ok"] for key in TEMPLATES}


def main() -> int:
    r = run_internal_validation("banking")
    print("\nSeQr - internal validation checklist (banking)\n" + "=" * 46)
    for st in r["stages"]:
        mark = ".." if st["ok"] is None else ("OK" if st["ok"] else "XX")
        print(f"[{mark}] {st['stage']}")
        print(f"      {st['detail']}")
    print("=" * 46)
    print(f"{r['passed']}/{r['checkable']} checkable stages passed; all_ok={r['all_ok']}")

    print("\nAll sector templates:")
    allt = run_all_templates()
    for key, ok in allt.items():
        print(f"  [{'OK' if ok else 'XX'}] {key}")
    return 0 if r["all_ok"] and all(allt.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
