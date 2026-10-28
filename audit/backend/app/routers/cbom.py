import csv
import io
import uuid
from datetime import date, datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import verify_component_belongs_to_org
from app.models.crypto_component import CryptoComponent
from app.models.organisation import Organisation
from app.models.user import User
from app.security import get_current_user

router = APIRouter()


class ComponentOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    scan_id: uuid.UUID
    asset_id: Optional[uuid.UUID] = None
    location_type: str
    location_detail: str
    algorithm: str
    algorithm_family: str
    key_size: Optional[int] = None
    quantum_status: str
    pqc_migration_priority: Optional[float] = None
    estimated_hndl_exposure: Optional[str] = None
    deployment_level: Optional[int] = None
    crypto_agility_score: Optional[float] = None
    threat_timeline: Optional[str] = None
    confidence: Optional[str] = None
    cert_expiry_date: Optional[date] = None
    cert_issuer: Optional[str] = None
    migration_status: str
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = {"from_attributes": True}


class ComponentListOut(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[ComponentOut]


class ComponentPatch(BaseModel):
    migration_status: Optional[str] = None
    data_sensitivity: Optional[str] = None


_CSV_FIELDS = [
    "id", "org_id", "scan_id", "asset_id", "location_type", "location_detail",
    "algorithm", "algorithm_family", "key_size", "quantum_status",
    "pqc_migration_priority", "estimated_hndl_exposure", "deployment_level",
    "crypto_agility_score", "threat_timeline", "confidence",
    "cert_expiry_date", "cert_issuer", "migration_status",
    "first_seen_at", "last_seen_at",
]


@router.get("", response_model=ComponentListOut)
async def list_cbom(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    quantum_status: Optional[str] = Query(None),
    threat_timeline: Optional[str] = Query(None),
    algorithm_family: Optional[str] = Query(None),
    migration_status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    filters = [CryptoComponent.org_id == current_user.org_id]
    if quantum_status:
        filters.append(CryptoComponent.quantum_status == quantum_status)
    if threat_timeline:
        filters.append(CryptoComponent.threat_timeline == threat_timeline)
    if algorithm_family:
        filters.append(CryptoComponent.algorithm_family == algorithm_family)
    if migration_status:
        filters.append(CryptoComponent.migration_status == migration_status)

    total = (await db.execute(
        select(func.count()).select_from(CryptoComponent).where(*filters)
    )).scalar()

    items = (await db.execute(
        select(CryptoComponent).where(*filters)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )).scalars().all()

    return ComponentListOut(total=total, page=page, page_size=page_size, items=list(items))


@router.get("/summary")
async def cbom_summary(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    components = (await db.execute(
        select(CryptoComponent).where(CryptoComponent.org_id == current_user.org_id)
    )).scalars().all()

    by_family: dict[str, int] = {}
    by_timeline: dict[str, int] = {"IMMEDIATE": 0, "URGENT": 0, "PLANNED": 0, "ROADMAP": 0}
    by_level: dict[str, int] = {}
    agility_scores: list[float] = []
    counts = {"vulnerable": 0, "safe": 0, "hybrid": 0, "hndl_high": 0}

    for c in components:
        qs = c.quantum_status or "unknown"
        if qs in counts:
            counts[qs] += 1

        if c.estimated_hndl_exposure == "high":
            counts["hndl_high"] += 1

        fam = c.algorithm_family or "other"
        by_family[fam] = by_family.get(fam, 0) + 1

        if c.threat_timeline in by_timeline:
            by_timeline[c.threat_timeline] += 1

        lvl = str(c.deployment_level) if c.deployment_level is not None else "unknown"
        by_level[lvl] = by_level.get(lvl, 0) + 1

        if c.crypto_agility_score is not None:
            agility_scores.append(c.crypto_agility_score)

    avg_agility = sum(agility_scores) / len(agility_scores) if agility_scores else 0.0

    return {
        "total_components": len(components),
        "vulnerable": counts["vulnerable"],
        "safe": counts["safe"],
        "hybrid": counts["hybrid"],
        "hndl_high": counts["hndl_high"],
        "by_algorithm_family": by_family,
        "by_threat_timeline": by_timeline,
        "by_deployment_level": by_level,
        "avg_crypto_agility_score": round(avg_agility, 2),
    }


@router.get("/export")
async def export_cbom(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    format: str = Query("json"),
):
    if format not in ("json", "csv", "cyclonedx"):
        raise HTTPException(status_code=400, detail="format must be json, csv, or cyclonedx")

    components = (await db.execute(
        select(CryptoComponent).where(CryptoComponent.org_id == current_user.org_id)
    )).scalars().all()

    if format == "json":
        data = []
        for c in components:
            row = {f: str(getattr(c, f)) if getattr(c, f) is not None else None for f in _CSV_FIELDS}
            data.append(row)
        return JSONResponse(content=data)

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        for c in components:
            row = {f: str(getattr(c, f)) if getattr(c, f) is not None else "" for f in _CSV_FIELDS}
            writer.writerow(row)
        return Response(
            content=output.getvalue().encode("utf-8"),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=cbom.csv"},
        )

    # cyclonedx
    org = await db.get(Organisation, current_user.org_id)
    org_name = org.name if org else str(current_user.org_id)

    cdx_components = [
        {
            "type": "cryptographic-asset",
            "name": c.algorithm,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": c.algorithm_family,
                    "parameterSetIdentifier": str(c.key_size) if c.key_size else "",
                },
            },
            "evidence": {"occurrences": [{"location": c.location_detail}]},
        }
        for c in components
    ]

    return JSONResponse(content={
        "bomFormat": "CycloneDX",
        # 1.6 introduced cryptographic-asset / cryptoProperties (used below).
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{current_user.org_id}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "tools": [{"name": "SeQr", "version": "0.1.0"}],
            "component": {"name": org_name, "type": "library"},
        },
        "components": cdx_components,
    })


@router.patch("/{component_id}", response_model=ComponentOut)
async def patch_component(
    body: ComponentPatch,
    component: Annotated[CryptoComponent, Depends(verify_component_belongs_to_org)],
    db: AsyncSession = Depends(get_db),
):
    if body.migration_status is not None:
        component.migration_status = body.migration_status
    await db.commit()
    await db.refresh(component)
    return component
