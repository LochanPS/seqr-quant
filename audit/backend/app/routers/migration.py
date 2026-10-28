"""Migration engine REST API (PRD 14 / Phase 2 checkpoint) — org-scoped.

Reads use the async session; the mutating spine/engine operations run in a dedicated sync
session (the planner/synthesis/bundle/verify modules are sync), mirroring the attestation
endpoint. Nothing here executes customer infrastructure — the API stops at a verified bundle.
"""

import base64
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import require_permission, verify_plan_belongs_to_org
from app.models.migration import MigrationPlan
from app.models.user import User
from app.rbac import MIGRATION_WRITE, ORG_MANAGE
from app.security import get_current_user

router = APIRouter()


class PlanOut(BaseModel):
    id: uuid.UUID
    policy_evaluation_id: uuid.UUID
    status: str
    model_config = {"from_attributes": True}


def _latest_evaluation(db, org_id):
    from app.models.policy import PolicyEvaluation
    return (db.query(PolicyEvaluation).filter(PolicyEvaluation.org_id == org_id)
            .order_by(PolicyEvaluation.ran_at.desc()).first())


# --------------------------------------------------------------- observability
@router.get("/pipeline")
async def pipeline(current_user: Annotated[User, Depends(get_current_user)]):
    """Full end-to-end pipeline status for the org (assets -> ... -> convergence)."""
    from app.database import SyncSessionLocal
    from app.migration.pipeline import pipeline_status

    db = SyncSessionLocal()
    try:
        return pipeline_status(db, current_user.org_id)
    finally:
        db.close()


@router.post("/demo/reseed")
async def demo_reseed(
    current_user: Annotated[User, Depends(require_permission(ORG_MANAGE))],
    template: str = Query(...),
):
    """Dev/demo only: reload a sector template into the caller's org (template switcher).

    Guarded: org:manage (admin) + non-SaaS deployment. Wipes only the caller's org
    spine/migration data.
    """
    from app.config import settings
    from app.database import SyncSessionLocal
    from app.migration.seed_db import reseed_org

    if getattr(settings, "DEPLOYMENT_MODE", "dev") == "saas" and not getattr(
        settings, "ALLOW_DEMO_RESEED", False
    ):
        raise HTTPException(status_code=403, detail="Demo reseed disabled in SaaS deployment")

    db = SyncSessionLocal()
    try:
        return reseed_org(db, current_user.org_id, template)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()


@router.post("/dry-run")
async def dry_run_latest(current_user: Annotated[User, Depends(require_permission(MIGRATION_WRITE))]):
    """Preview the changes for the latest evaluation without persisting anything."""
    from app.database import SyncSessionLocal
    from app.migration.dryrun import dry_run

    db = SyncSessionLocal()
    try:
        ev = _latest_evaluation(db, current_user.org_id)
        if not ev:
            raise HTTPException(status_code=404, detail="No evaluation yet. Run a scan first.")
        return dry_run(db, current_user.org_id, ev)
    finally:
        db.close()


# ---------------------------------------------------------------------- plans
@router.get("/plans", response_model=list[PlanOut])
async def list_plans(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    q = (select(MigrationPlan).where(MigrationPlan.org_id == current_user.org_id)
         .order_by(MigrationPlan.created_at.desc()).limit(limit).offset(offset))
    return (await db.execute(q)).scalars().all()


@router.post("/plans", response_model=PlanOut)
async def create_plan(current_user: Annotated[User, Depends(require_permission(MIGRATION_WRITE))]):
    """Build a migration plan from the org's latest evaluation."""
    from app.database import SyncSessionLocal
    from app.migration.planner import build_plan

    db = SyncSessionLocal()
    try:
        ev = _latest_evaluation(db, current_user.org_id)
        if not ev:
            raise HTTPException(status_code=404, detail="No evaluation yet. Run a scan first.")
        plan = build_plan(db, current_user.org_id, ev, actor=str(current_user.id))
        db.commit()
        return PlanOut(id=plan.id, policy_evaluation_id=plan.policy_evaluation_id, status=plan.status)
    finally:
        db.close()


@router.get("/plans/{plan_id}", response_model=PlanOut)
async def get_plan(plan: Annotated[MigrationPlan, Depends(verify_plan_belongs_to_org)]):
    return plan


@router.post("/plans/{plan_id}/bundle")
async def bundle_plan(
    plan: Annotated[MigrationPlan, Depends(verify_plan_belongs_to_org)],
    current_user: Annotated[User, Depends(require_permission(MIGRATION_WRITE))],
):
    """Synthesize + sign the bundle for a plan. Returns the manifest + base64 tar (offline-verifiable)."""
    from app.database import SyncSessionLocal
    from app.migration.bundle import build_bundle

    db = SyncSessionLocal()
    try:
        p = db.get(MigrationPlan, plan.id)
        row, tar_bytes, manifest = build_bundle(db, p, actor=str(current_user.id))
        db.commit()
        return {"bundle_id": str(row.id), "manifest": manifest,
                "tar_base64": base64.b64encode(tar_bytes).decode()}
    finally:
        db.close()


@router.post("/plans/{plan_id}/verify")
async def verify_plan_endpoint(
    plan: Annotated[MigrationPlan, Depends(verify_plan_belongs_to_org)],
    current_user: Annotated[User, Depends(require_permission(MIGRATION_WRITE))],
):
    """Re-evaluate policy against current (post-rescan) state and report convergence."""
    from app.database import SyncSessionLocal
    from app.migration.verify import verify_plan

    db = SyncSessionLocal()
    try:
        p = db.get(MigrationPlan, plan.id)
        report = verify_plan(db, p, actor=str(current_user.id))
        db.commit()
        return report
    finally:
        db.close()
