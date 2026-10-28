import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Event(Base):
    """Append-only history + access audit for the spine (PRD 13, forks B + E).

    Two jobs, one log: (1) the temporal event stream (measured, policy_changed, migrated,
    drifted, attested) that lets us reconstruct the graph at any time, and (2) the security
    access-audit — every read of crypto weakness detail records who/when/which-assets here.
    Never updated or deleted.
    """

    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(String, nullable=False)  # measured|policy_changed|migrated|drift|attested|posture_read
    actor: Mapped[str | None] = mapped_column(String, nullable=True)  # user id / api-key prefix / "system"
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # never store raw weakness detail here
    at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
