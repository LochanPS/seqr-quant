import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CIReport(Base):
    """A pull-request PQC scan pushed from `seqr ci` (CI-2, docs/07).

    The application-code arm of the CBOM: when the CI gate runs on a PR it can push the
    findings here so the org's crypto posture reflects code, not just infra scans. Stored
    org-scoped and append-only — one row per push (repo + PR + commit). The findings list
    is kept as JSON (the CLI's `--output json` `findings` array); the dashboard reads the
    summary for the list view and the payload for drill-down.
    """

    __tablename__ = "ci_reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    actor: Mapped[str | None] = mapped_column(String, nullable=True)  # api-key prefix / user id

    repo: Mapped[str] = mapped_column(String, nullable=False)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String, nullable=True)
    branch: Mapped[str | None] = mapped_column(String, nullable=True)
    source: Mapped[str] = mapped_column(String, default="github")

    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    findings: Mapped[list | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
