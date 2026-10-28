import uuid
from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import verify_scan_belongs_to_org
from app.models.scan import Scan
from app.models.user import User
from app.security import get_current_user

router = APIRouter()


class ScanOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    asset_id: Optional[uuid.UUID]
    type: str
    status: str
    trigger: str
    celery_task_id: Optional[str]
    components_found: int
    vulnerable_found: int
    transport_summary: Optional[dict] = None
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("", response_model=list[ScanOut])
async def list_scans(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    result = await db.execute(
        select(Scan)
        .where(Scan.org_id == current_user.org_id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan: Annotated[Scan, Depends(verify_scan_belongs_to_org)],
):
    return scan
