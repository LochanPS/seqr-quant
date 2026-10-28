"""
Audit-log read API (A5) — org-scoped.

Exposes the append-only :class:`app.models.audit_event.AuditEvent` log for the caller's
own org, gated by the ``audit:read`` permission (admin + auditor roles). This is the
*tenant-facing* audit view; it is deliberately NOT under ``/api/v1/admin`` (that router is
the cross-tenant platform-operator console). Read-only: there is no write/delete route —
rows are written by the audit middleware.
"""
import uuid
from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import require_permission
from app.models.audit_event import AuditEvent
from app.models.user import User
from app.rbac import AUDIT_READ

router = APIRouter()


class AuditEventOut(BaseModel):
    id: uuid.UUID
    org_id: Optional[uuid.UUID]
    actor: Optional[str]
    actor_type: str
    action: str
    method: Optional[str]
    path: Optional[str]
    status_code: Optional[int]
    target: Optional[str]
    ip: Optional[str]
    detail: Optional[dict]
    at: datetime

    model_config = {"from_attributes": True}


@router.get("", response_model=list[AuditEventOut])
async def list_audit_events(
    current_user: Annotated[User, Depends(require_permission(AUDIT_READ))],
    db: AsyncSession = Depends(get_db),
    actor: Optional[str] = Query(None, description="Filter by actor (exact)"),
    action: Optional[str] = Query(None, description="Filter by action substring"),
    since: Optional[datetime] = Query(None, description="Only events at or after this time (UTC)"),
    until: Optional[datetime] = Query(None, description="Only events at or before this time (UTC)"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List this org's audit events, newest first. Tenant-scoped and filterable."""
    q = select(AuditEvent).where(AuditEvent.org_id == current_user.org_id)
    if actor:
        q = q.where(AuditEvent.actor == actor)
    if action:
        q = q.where(AuditEvent.action.ilike(f"%{action}%"))
    if since:
        q = q.where(AuditEvent.at >= since)
    if until:
        q = q.where(AuditEvent.at <= until)
    q = q.order_by(AuditEvent.at.desc()).limit(limit).offset(offset)
    return (await db.execute(q)).scalars().all()
