import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id"), nullable=False
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    type: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, default="queued")
    trigger: Mapped[str] = mapped_column(String, default="manual")
    celery_task_id: Mapped[str | None] = mapped_column(String, nullable=True)
    components_found: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_found: Mapped[int] = mapped_column(Integer, default=0)
    # Scan-level transport posture (TLS version, cert, key exchange, active PQC group,
    # CDN, edge/origin) for the scan-detail header + edge/origin honesty card. Null for
    # code scans. See app/tasks/scan_tasks.py.
    transport_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
