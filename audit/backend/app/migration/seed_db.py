"""Persist a demo enterprise template into the real database, behind a login (dev/demo enabler).

Lets the dashboard render a full, realistic pipeline for customer demonstrations. Creates (or
reuses) a demo org + user, then materializes a sector template under that org and runs the whole
pipeline so the graph, violations, plan, bundle, attestation, and audit trail all exist.

Usage:
    python -m app.migration.seed_db                 # banking, demo@seqrlabs.com / demodemo123
    python -m app.migration.seed_db healthcare demo2@seqrlabs.com hunter2hunter2
"""

import sys


def seed(template: str = "banking", email: str = "demo@seqrlabs.com", password: str = "demodemo123") -> dict:
    from app.database import SyncSessionLocal
    from app.migration.templates import TEMPLATES, build
    from app.models.organisation import Organisation
    from app.models.user import User
    from app.security import hash_password

    if template not in TEMPLATES:
        raise SystemExit(f"unknown template '{template}'. options: {sorted(TEMPLATES)}")

    db = SyncSessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            org_id = user.org_id
        else:
            org = Organisation(name=TEMPLATES[template]["name"], sector=template, plan="enterprise")
            db.add(org); db.flush()
            user = User(org_id=org.id, email=email, password_hash=hash_password(password),
                        name="Demo Operator", role="admin")
            db.add(user); db.commit()
            org_id = org.id

        res = build(db, TEMPLATES[template], org=org_id)
        db.commit()
        print(f"seeded template={template} org={org_id}")
        print(f"login: {email} / {password}")
        print(f"evaluation={res['evaluation_id']} plan={res['plan_id']} "
              f"bundle_verify={res['bundle_offline_verify']} att_verify={res['attestation_offline_verify']}")
        return {"org_id": str(org_id), "email": email, **{k: str(res[k]) for k in ("evaluation_id", "plan_id")}}
    finally:
        db.close()


def seed_if_empty(template: str = "banking", email: str = "demo@seqrlabs.com",
                  password: str = "demodemo123") -> bool:
    """Idempotent boot-seed for shell-less hosts (e.g. Render free tier).

    Seeds the demo org + template ONLY if it isn't already populated (demo user exists AND has
    assets). Returns True if it seeded this call, False if it was already present. Safe to run
    on every startup; also self-heals if a free-tier database is wiped.
    """
    from app.database import SyncSessionLocal
    from app.models.asset import Asset
    from app.models.user import User

    db = SyncSessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user and db.query(Asset).filter(Asset.org_id == user.org_id).first() is not None:
            return False  # already seeded
    finally:
        db.close()

    seed(template, email, password)  # creates org/user if needed + builds the template
    return True


def reseed_org(db, org_id, template: str) -> dict:
    """Wipe an org's spine/migration data and load a different template into it (dev/demo only).

    Leaves the global default policy + asset-type registry intact. Used by the dashboard's
    template switcher so a reviewer can flip sectors without touching the database by hand.
    Uses ORM deletes (not raw SQL) so UUID columns bind in the DB's stored format.
    """
    from app.migration.templates import TEMPLATES, build
    from app.models.asset import Asset
    from app.models.asset_edge import AssetEdge
    from app.models.asset_identity import AssetIdentity
    from app.models.attestation import Attestation
    from app.models.component_state import ComponentState
    from app.models.crypto_component import CryptoComponent
    from app.models.event import Event
    from app.models.migration import ChangeItem, MigrationBundle, MigrationPlan, RollbackPlan
    from app.models.policy import PolicyEvaluation, Violation
    from app.models.scan import Scan

    if template not in TEMPLATES:
        raise ValueError(f"unknown template '{template}'")

    # FK-safe order: children first.
    for model in (RollbackPlan, MigrationBundle, ChangeItem, MigrationPlan, Attestation,
                  Violation, PolicyEvaluation, ComponentState, AssetEdge, AssetIdentity,
                  Event, CryptoComponent, Scan, Asset):
        db.query(model).filter(model.org_id == org_id).delete(synchronize_session=False)
    db.flush()

    res = build(db, TEMPLATES[template], org=org_id)
    db.commit()
    return {"org_id": str(org_id), "template": template,
            "evaluation_id": str(res["evaluation_id"]), "plan_id": str(res["plan_id"])}


if __name__ == "__main__":
    args = sys.argv[1:]
    seed(*(args[:3]))
