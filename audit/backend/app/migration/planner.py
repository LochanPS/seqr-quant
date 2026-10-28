"""Plan builder (PRD 14, Slice 1).

Turns the violations of one policy evaluation into a MigrationPlan of ChangeItems, ordered by
the asset graph. No config synthesis, no signing, no execution — those are later slices.
"""

import uuid

from sqlalchemy.orm import Session

from app.models.asset_edge import AssetEdge
from app.models.migration import ChangeItem, MigrationPlan
from app.models.policy import PolicyEvaluation, Violation
from app.models.scan import Scan
from app.spine.ingest import record_event

# rule_key -> (change action, affected slot)
_RULE_ACTION = {
    "kex_must_be_hybrid": ("enable_hybrid_kex", "tls:kex"),
    "no_static_rsa_kex": ("enable_forward_secrecy_kex", "tls:kex"),
    "cert_min_rsa": ("reissue_cert_stronger", "tls:cert"),
    "no_exposed_classical_origin": ("harden_origin", None),
}


def _u(v) -> uuid.UUID:
    return v if isinstance(v, uuid.UUID) else uuid.UUID(str(v))


def _infer_provider(db: Session, org_id, asset_id) -> str:
    """Best-effort provider from the asset's latest scan transport summary. Synthesis refines."""
    scan = (
        db.query(Scan)
        .filter(Scan.org_id == org_id, Scan.asset_id == asset_id, Scan.transport_summary.isnot(None))
        .order_by(Scan.created_at.desc())
        .first()
    )
    cdn = ((scan.transport_summary or {}).get("cdn_provider") or "").lower() if scan else ""
    if "cloudflare" in cdn:
        return "cloudflare"
    if "cloudfront" in cdn:
        return "cloudfront"
    return "nginx"


def plan_specs(db: Session, org_id, evaluation: PolicyEvaluation) -> list[dict]:
    """Pure (read-only) compute of the change specs for an evaluation's violations.

    Shared by build_plan (which persists) and dry_run (which does not). No writes.
    """
    org_id = _u(org_id)
    violations = (
        db.query(Violation)
        .filter(Violation.org_id == org_id, Violation.evaluation_id == evaluation.id)
        .all()
    )
    specs = []
    for v in violations:
        action, slot = _RULE_ACTION.get(v.rule_key, ("review", v.rule_key))
        specs.append({
            "asset_id": v.asset_id, "violation_id": v.id, "slot_key": slot,
            "provider": _infer_provider(db, org_id, v.asset_id), "action": action,
            "from_state": v.actual, "to_state": v.target_state, "rule_key": v.rule_key,
        })
    return specs


def build_plan(db: Session, org_id, evaluation: PolicyEvaluation, actor: str = "system") -> MigrationPlan:
    org_id = _u(org_id)
    plan = MigrationPlan(org_id=org_id, policy_evaluation_id=evaluation.id, status="draft")
    db.add(plan)
    db.flush()

    items_by_asset: dict[uuid.UUID, list[ChangeItem]] = {}
    for spec in plan_specs(db, org_id, evaluation):
        ci = ChangeItem(
            org_id=org_id, plan_id=plan.id, asset_id=spec["asset_id"], violation_id=spec["violation_id"],
            slot_key=spec["slot_key"], provider=spec["provider"], action=spec["action"],
            from_state=spec["from_state"], to_state=spec["to_state"],
        )
        db.add(ci)
        db.flush()
        items_by_asset.setdefault(spec["asset_id"], []).append(ci)

    # Graph-aware ordering: for an origin_of edge (edge --fronts--> origin), the edge's changes
    # depend on the origin's changes (harden the origin before altering the edge that routes to it).
    edges = (
        db.query(AssetEdge)
        .filter(AssetEdge.org_id == org_id, AssetEdge.relation == "origin_of",
                AssetEdge.valid_to.is_(None))
        .all()
    )
    for e in edges:
        dst_items = items_by_asset.get(e.dst_asset_id, [])
        if not dst_items:
            continue
        dep_ids = [str(d.id) for d in dst_items]
        for si in items_by_asset.get(e.src_asset_id, []):
            si.depends_on = (si.depends_on or []) + dep_ids

    db.flush()
    record_event(db, org_id, "migration_planned", actor, None,
                 {"plan_id": str(plan.id), "items": sum(len(v) for v in items_by_asset.values())})
    return plan
