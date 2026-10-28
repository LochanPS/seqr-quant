import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.deps import require_permission, verify_asset_belongs_to_org
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.user import User
from app.rbac import ASSETS_WRITE, SCANS_RUN
from app.security import get_current_user
from app.tasks.scan_tasks import run_network_scan

router = APIRouter()

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Asset types → the scanner protocol used for them. "domain" is direct HTTPS;
# smtp/imap/pop3/postgres are STARTTLS/wrapped-protocol scans; ssh is a KEXINIT
# scan; mongodb/amqp/grpc are direct-TLS services (whole connection is TLS);
# mysql negotiates TLS mid-handshake (its own STARTTLS-upgrade probe).
_ASSET_TYPES = {
    "domain", "smtp", "imap", "pop3", "postgres", "ssh",
    "mongodb", "amqp", "grpc", "mysql",
}


class AssetCreate(BaseModel):
    type: str
    name: Optional[str] = None
    identifier: str
    data_sensitivity: str = "internal"


class AssetOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    type: str
    name: Optional[str]
    identifier: str
    data_sensitivity: str
    status: str
    scan_schedule: str
    last_scanned_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AssetWithLastScan(AssetOut):
    last_scan_id: Optional[uuid.UUID] = None
    last_scan_status: Optional[str] = None


@router.post("", response_model=AssetOut)
async def create_asset(
    body: AssetCreate,
    current_user: Annotated[User, Depends(require_permission(ASSETS_WRITE))],
    db: AsyncSession = Depends(get_db),
):
    if body.type not in _ASSET_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"type must be one of {sorted(_ASSET_TYPES)}",
        )
    if not _DOMAIN_RE.match(body.identifier):
        raise HTTPException(status_code=400, detail="Invalid host identifier")

    asset = Asset(
        org_id=current_user.org_id,
        type=body.type,
        name=body.name,
        identifier=body.identifier,
        data_sensitivity=body.data_sensitivity,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset


@router.get("", response_model=list[AssetWithLastScan])
async def list_assets(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Asset).where(Asset.org_id == current_user.org_id))
    assets = result.scalars().all()

    out = []
    for asset in assets:
        scan_result = await db.execute(
            select(Scan)
            .where(Scan.asset_id == asset.id)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        last_scan = scan_result.scalar_one_or_none()
        row = AssetWithLastScan.model_validate(asset)
        if last_scan:
            row.last_scan_id = last_scan.id
            row.last_scan_status = last_scan.status
        out.append(row)
    return out


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset: Annotated[Asset, Depends(verify_asset_belongs_to_org)],
):
    return asset


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset: Annotated[Asset, Depends(verify_asset_belongs_to_org)],
    _perm: Annotated[User, Depends(require_permission(ASSETS_WRITE))],
    db: AsyncSession = Depends(get_db),
):
    await db.delete(asset)
    await db.commit()


@router.post("/{asset_id}/scan")
async def trigger_scan(
    asset: Annotated[Asset, Depends(verify_asset_belongs_to_org)],
    current_user: Annotated[User, Depends(require_permission(SCANS_RUN))],
    db: AsyncSession = Depends(get_db),
):
    asset_id = asset.id

    scan = Scan(
        org_id=current_user.org_id,
        asset_id=asset_id,
        type=asset.type,
        status="queued",
        trigger="manual",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    run_network_scan.delay(
        str(scan.id),
        str(asset_id),
        str(current_user.org_id),
        asset.identifier,
        asset.type,
    )

    if settings.USE_FAKE_REDIS:
        await db.refresh(scan)

    return {"scan_id": str(scan.id), "status": scan.status}


@router.post("/scan-all")
async def scan_all_assets(
    current_user: Annotated[User, Depends(require_permission(SCANS_RUN))],
    db: AsyncSession = Depends(get_db),
):
    """Enqueue a scan for every asset in the caller's org (batch scan).

    Returns immediately with one queued job per asset; the worker pool runs them
    concurrently, bounded by the per-org fairness cap (MAX_CONCURRENT_SCANS_PER_ORG)
    so a large batch cannot starve other tenants. Excess tasks wait in the queue.
    """
    result = await db.execute(select(Asset).where(Asset.org_id == current_user.org_id))
    assets = result.scalars().all()
    if not assets:
        return {"queued": 0, "scans": []}

    scans = [
        Scan(
            org_id=current_user.org_id,
            asset_id=asset.id,
            type=asset.type,
            status="queued",
            trigger="batch",
        )
        for asset in assets
    ]
    db.add_all(scans)
    await db.commit()
    for s in scans:
        await db.refresh(s)

    out = []
    for scan, asset in zip(scans, assets):
        run_network_scan.delay(
            str(scan.id),
            str(asset.id),
            str(current_user.org_id),
            asset.identifier,
            asset.type,
        )
        out.append({"scan_id": str(scan.id), "asset_id": str(asset.id), "status": scan.status})

    return {"queued": len(out), "scans": out}
