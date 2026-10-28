"""
Reusable FastAPI dependencies for multi-tenant org boundary enforcement.

Every endpoint that accepts an asset_id, scan_id, component_id, or
report_id MUST use one of these dependencies to ensure the resource
belongs to the caller's org.  A missing or wrong org returns 404
(not 403) to avoid leaking resource existence.
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.asset import Asset
from app.models.attestation import Attestation
from app.models.crypto_component import CryptoComponent
from app.models.migration import MigrationPlan
from app.models.policy import PolicyEvaluation
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.rbac import has_permission
from app.security import get_current_user


def require_permission(permission: str):
    """Dependency factory: allow the request only if the user's role grants ``permission``.

    Enforces the org RBAC matrix (:mod:`app.rbac`) on top of authentication. Returns the
    user on success so a handler can still ``Depends`` on it. 403 (not 404) here — the
    resource may exist and be in the caller's org; they simply lack the capability. Cross-
    org resource hiding stays the job of the ``verify_*_belongs_to_org`` deps (which 404).
    """

    async def _dep(
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        if not has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Your role ('{current_user.role}') lacks the required permission: {permission}",
            )
        return current_user

    return _dep


async def verify_asset_belongs_to_org(
    asset_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> Asset:
    """Return the Asset if it belongs to the current user's org, else 404."""
    asset = await db.get(Asset, asset_id)
    if not asset or asset.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


async def verify_scan_belongs_to_org(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> Scan:
    """Return the Scan if it belongs to the current user's org, else 404."""
    scan = await db.get(Scan, scan_id)
    if not scan or scan.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


async def verify_component_belongs_to_org(
    component_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> CryptoComponent:
    """Return the CryptoComponent if it belongs to the current user's org, else 404."""
    component = await db.get(CryptoComponent, component_id)
    if not component or component.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Component not found")
    return component


async def verify_report_belongs_to_org(
    report_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> Report:
    """Return the Report if it belongs to the current user's org, else 404."""
    report = await db.get(Report, report_id)
    if not report or report.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


async def verify_evaluation_belongs_to_org(
    evaluation_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> PolicyEvaluation:
    """Return the PolicyEvaluation if it belongs to the current user's org, else 404."""
    ev = await db.get(PolicyEvaluation, evaluation_id)
    if not ev or ev.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    return ev


async def verify_attestation_belongs_to_org(
    attestation_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> Attestation:
    """Return the Attestation if it belongs to the current user's org, else 404."""
    att = await db.get(Attestation, attestation_id)
    if not att or att.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return att


async def verify_plan_belongs_to_org(
    plan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> MigrationPlan:
    """Return the MigrationPlan if it belongs to the current user's org, else 404."""
    plan = await db.get(MigrationPlan, plan_id)
    if not plan or plan.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Plan not found")
    return plan
