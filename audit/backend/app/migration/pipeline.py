"""Pipeline observability (PRD 14 / Phase 2 checkpoint).

A single read that summarizes every stage of the lifecycle for one org, so the whole pipeline
is visible end-to-end: assets -> graph -> state -> evaluation -> violations -> plans -> bundles
-> attestations -> convergence. Pure read; safe to call anytime.
"""

from collections import Counter

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_edge import AssetEdge
from app.models.attestation import Attestation
from app.models.component_state import ComponentState
from app.models.event import Event
from app.models.migration import MigrationBundle, MigrationPlan
from app.models.policy import PolicyEvaluation, Violation


def pipeline_status(db: Session, org_id) -> dict:
    assets = db.query(Asset).filter(Asset.org_id == org_id).all()
    states = db.query(ComponentState).filter(ComponentState.org_id == org_id).all()
    latest = (db.query(PolicyEvaluation).filter(PolicyEvaluation.org_id == org_id)
              .order_by(PolicyEvaluation.ran_at.desc()).first())

    latest_block = None
    open_violations = 0
    if latest:
        open_violations = db.query(Violation).filter(Violation.evaluation_id == latest.id).count()
        latest_block = {
            "id": str(latest.id),
            "ran_at": latest.ran_at.isoformat() if latest.ran_at else None,
            "result_hash": latest.result_hash,
            "violations_count": latest.violations_count,
        }

    plans = db.query(MigrationPlan).filter(MigrationPlan.org_id == org_id).all()
    recent = (db.query(Event).filter(Event.org_id == org_id)
              .order_by(Event.at.desc()).limit(10).all())

    return {
        "org_id": str(org_id),
        "assets": {"total": len(assets), "by_provenance": dict(Counter(a.provenance for a in assets))},
        "edges": db.query(AssetEdge).filter(AssetEdge.org_id == org_id).count(),
        "component_states": {"total": len(states), "conflicts": sum(1 for s in states if s.conflict)},
        "latest_evaluation": latest_block,
        "open_violations": open_violations,
        "plans": {"total": len(plans), "by_status": dict(Counter(p.status for p in plans))},
        "bundles": db.query(MigrationBundle).filter(MigrationBundle.org_id == org_id).count(),
        "attestations": db.query(Attestation).filter(Attestation.org_id == org_id).count(),
        "converged": latest is not None and open_violations == 0,
        "recent_events": [{"type": e.type, "at": e.at.isoformat() if e.at else None} for e in recent],
    }
