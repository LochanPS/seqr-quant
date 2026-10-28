"""Dry-run (PRD 14, Slice 4).

Render the full set of changes + synthesized snippets for an evaluation WITHOUT persisting a
plan, bundle, or any row. Pure preview so a customer can review before anything becomes real.
"""

from sqlalchemy.orm import Session

from app.migration.planner import plan_specs
from app.migration.synthesis import synthesize
from app.models.policy import PolicyEvaluation


def dry_run(db: Session, org_id, evaluation: PolicyEvaluation) -> dict:
    specs = plan_specs(db, org_id, evaluation)
    changes = []
    by_platform: dict[str, int] = {}
    for sp in specs:
        art = synthesize(sp["provider"], sp["action"], to_state=sp["to_state"],
                         from_state=sp["from_state"], target_component=sp["slot_key"])
        by_platform[art.target_platform] = by_platform.get(art.target_platform, 0) + 1
        changes.append({
            "asset_id": str(sp["asset_id"]),
            "rule_key": sp["rule_key"],
            "provider": sp["provider"],
            "action": art.action,
            "slot": sp["slot_key"],
            "from": sp["from_state"],
            "to": sp["to_state"],
            "snippets": [s.content for s in art.snippets],
            "validation": art.validation_checklist,
            "rollback": art.rollback,
            "manual": art.action == "manual_review",
        })
    return {
        "evaluation_id": str(evaluation.id),
        "change_count": len(specs),
        "by_platform": by_platform,
        "affected_assets": sorted({str(sp["asset_id"]) for sp in specs}),
        "changes": changes,
        "persisted": False,
    }
