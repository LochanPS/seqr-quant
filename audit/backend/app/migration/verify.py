"""Verify-by-rescan + convergence (PRD 14, Slice 5).

After the customer applies a bundle and a re-scan flows fresh observations into the spine,
verification re-evaluates policy and checks whether the violations the plan targeted have
cleared. Convergence = none of the targeted (asset, rule) violations remain. The engine never
self-asserts success — only a fresh measurement (through the spine) clears a finding.
"""

from sqlalchemy.orm import Session

from app.models.migration import ChangeItem
from app.models.policy import Violation
from app.spine.ingest import record_event
from app.spine.policy import evaluate_policy


def verify_plan(db: Session, plan, actor: str = "system") -> dict:
    org_id = plan.org_id

    # What this plan set out to fix: (asset, rule) pairs from its change items' violations.
    targeted: set[tuple] = set()
    for ci in db.query(ChangeItem).filter(ChangeItem.plan_id == plan.id).all():
        rule = None
        if ci.violation_id:
            v = db.get(Violation, ci.violation_id)
            if v:
                rule = v.rule_key
        targeted.add((str(ci.asset_id), rule))

    # Re-evaluate against the current (post-rescan) state.
    new_ev = evaluate_policy(db, org_id)
    db.flush()
    current = {
        (str(v.asset_id), v.rule_key)
        for v in db.query(Violation).filter(Violation.evaluation_id == new_ev.id).all()
    }

    remaining = sorted(f"{a}:{r}" for (a, r) in (targeted & current))
    cleared = sorted(f"{a}:{r}" for (a, r) in (targeted - current))
    converged = not remaining
    plan.status = "verified" if converged else "applied"

    record_event(db, org_id, "migration_verified", actor, None, {
        "plan_id": str(plan.id), "converged": converged,
        "cleared": len(cleared), "remaining": len(remaining),
    })
    return {
        "plan_id": str(plan.id),
        "new_evaluation_id": str(new_ev.id),
        "converged": converged,
        "cleared": cleared,
        "remaining": remaining,
    }
