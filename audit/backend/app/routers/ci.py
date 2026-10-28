"""SeQr CI → dashboard sync (PRD 07, CI-2).

The `seqr ci` GitHub Action can push a pull request's PQC findings here so the org's crypto
posture reflects application code, not only infra scans. Endpoints are authenticated
(JWT or an `sq_live_` API key — the CI use case) and strictly org-scoped; ingestion is
feature-flagged (`CI_INGEST_ENABLED`) so a deployment opts in before accepting pushes.
"""
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.ci_report import CIReport
from app.models.user import User
from app.security import get_current_user

router = APIRouter()

# Cap the stored payload so a runaway push can't bloat the row.
_MAX_FINDINGS = 5000


class CIFindingsIn(BaseModel):
    repo: str = Field(..., min_length=1, max_length=255)
    pr_number: int | None = None
    commit_sha: str | None = Field(None, max_length=64)
    branch: str | None = Field(None, max_length=255)
    source: str = "github"
    summary: dict[str, Any] | None = None
    gate: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)


class CIReportOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    repo: str
    pr_number: int | None
    commit_sha: str | None
    branch: str | None
    source: str
    findings_count: int
    summary: dict[str, Any] | None
    created_at: datetime


class CIReportDetail(CIReportOut):
    findings: list[dict[str, Any]]


def _actor(user: User) -> str:
    return str(user.id)


@router.post("/findings", response_model=CIReportOut, status_code=201)
async def push_findings(
    body: CIFindingsIn,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Record a PR's PQC findings against the caller's org (feature-flagged)."""
    if not settings.CI_INGEST_ENABLED:
        raise HTTPException(status_code=403, detail="CI ingestion is disabled on this deployment")
    if len(body.findings) > _MAX_FINDINGS:
        raise HTTPException(status_code=413, detail=f"too many findings (max {_MAX_FINDINGS})")

    summary = dict(body.summary or {})
    if body.gate:
        summary["gate"] = body.gate

    report = CIReport(
        org_id=current_user.org_id,
        actor=_actor(current_user),
        repo=body.repo,
        pr_number=body.pr_number,
        commit_sha=body.commit_sha,
        branch=body.branch,
        source=body.source or "github",
        findings_count=len(body.findings),
        summary=summary or None,
        findings=body.findings,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


@router.get("/reports", response_model=list[CIReportOut])
async def list_reports(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
    repo: str | None = None,
):
    """List the org's CI reports, newest first (dashboard list view)."""
    q = select(CIReport).where(CIReport.org_id == current_user.org_id)
    if repo:
        q = q.where(CIReport.repo == repo)
    q = q.order_by(CIReport.created_at.desc()).limit(max(1, min(limit, 200)))
    rows = (await db.execute(q)).scalars().all()
    return rows


@router.get("/reports/{report_id}", response_model=CIReportDetail)
async def get_report(
    report_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """One CI report with its findings. 404 (not 403) on a cross-tenant id."""
    report = await db.get(CIReport, report_id)
    if not report or report.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="CI report not found")
    return report
