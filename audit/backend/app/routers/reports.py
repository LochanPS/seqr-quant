import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.crypto_component import CryptoComponent
from app.models.organisation import Organisation
from app.models.report import Report
from app.models.user import User
from app.reports.generator import build_executive_summary, build_technical_audit
from app.routers.risk import compute_org_risk_score, _score_label
from app.security import get_current_user

router = APIRouter()

VALID_TYPES = {"executive_summary", "technical_audit", "compliance"}


class _OrgUser:
    """Minimal stand-in for User when calling risk helpers directly."""
    def __init__(self, org_id: uuid.UUID):
        self.org_id = org_id


async def _fetch_compliance(org_id: uuid.UUID, db: AsyncSession) -> dict:
    from app.routers.risk import compliance_status
    return await compliance_status(current_user=_OrgUser(org_id), db=db)


async def _fetch_roadmap(org_id: uuid.UUID, db: AsyncSession) -> dict:
    from app.routers.risk import migration_roadmap
    return await migration_roadmap(current_user=_OrgUser(org_id), db=db)


@router.post("/generate")
async def generate_report(
    body: dict,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    report_type = body.get("type", "")
    if report_type not in VALID_TYPES:
        raise HTTPException(status_code=422, detail=f"type must be one of {sorted(VALID_TYPES)}")

    org_id_str = str(current_user.org_id)

    org = (await db.execute(
        select(Organisation).where(Organisation.id == current_user.org_id)
    )).scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")

    components = (await db.execute(
        select(CryptoComponent).where(CryptoComponent.org_id == current_user.org_id)
    )).scalars().all()

    report = Report(
        org_id=current_user.org_id,
        type=report_type,
        status="generating",
    )
    db.add(report)
    await db.flush()
    report_id = report.id

    try:
        score = await compute_org_risk_score(org_id_str, db)
        risk_data = {"score": score, "label": _score_label(score)}
        compliance_data = await _fetch_compliance(current_user.org_id, db)
        roadmap_data = await _fetch_roadmap(current_user.org_id, db)

        if report_type == "executive_summary":
            pdf_bytes = await build_executive_summary(
                org, components, risk_data, compliance_data, roadmap_data
            )
        elif report_type == "technical_audit":
            pdf_bytes = await build_technical_audit(org, components, roadmap_data)
        else:
            # compliance — use executive summary layout
            pdf_bytes = await build_executive_summary(
                org, components, risk_data, compliance_data, roadmap_data
            )

        out_dir = Path(__file__).parent.parent.parent / "reports" / org_id_str
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{report_id}.pdf"
        out_path.write_bytes(pdf_bytes)

        report.status = "complete"
        report.storage_path = str(out_path)
        report.component_count = len(components)
        report.vulnerable_count = sum(1 for c in components if c.quantum_status == "vulnerable")
        report.risk_score_at_generation = score
        report.generated_at = datetime.utcnow()

    except Exception as exc:
        report.status = "failed"
        report.error_message = str(exc)
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")

    await db.commit()
    await db.refresh(report)
    return _report_dict(report)


@router.get("")
async def list_reports(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(
        select(Report)
        .where(Report.org_id == current_user.org_id)
        .order_by(Report.created_at.desc())
    )).scalars().all()
    return [_report_dict(r) for r in rows]


@router.get("/{report_id}")
async def get_report(
    report_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    report = await _get_report_or_404(report_id, current_user.org_id, db)
    return _report_dict(report)


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    report = await _get_report_or_404(report_id, current_user.org_id, db)
    if report.status != "complete":
        raise HTTPException(status_code=409, detail=f"Report not ready (status: {report.status})")

    path = Path(report.storage_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="PDF file not found on disk")

    date_str = (report.generated_at or report.created_at).strftime("%Y%m%d")
    filename = f"seqr-report-{report.type}-{date_str}.pdf"
    return FileResponse(
        path=str(path),
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_report_or_404(report_id: str, org_id: uuid.UUID, db: AsyncSession) -> Report:
    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid report ID")
    report = (await db.execute(
        select(Report).where(Report.id == rid, Report.org_id == org_id)
    )).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def _report_dict(r: Report) -> dict:
    return {
        "id": str(r.id),
        "org_id": str(r.org_id),
        "type": r.type,
        "status": r.status,
        "storage_path": r.storage_path,
        "component_count": r.component_count,
        "vulnerable_count": r.vulnerable_count,
        "risk_score_at_generation": r.risk_score_at_generation,
        "error_message": r.error_message,
        "generated_at": r.generated_at.isoformat() if r.generated_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }
