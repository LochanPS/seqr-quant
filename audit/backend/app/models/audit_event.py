import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Uuid, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AuditEvent(Base):
    """Append-only security audit log — who did what, when (A5, enterprise table-stakes).

    Distinct from :class:`app.models.event.Event`, which is the *domain* history of the
    spine graph (measured/migrated/attested…). This log answers the compliance question:
    "who mutated state in this org, and when?" A row is written for every authenticated
    mutating request (see the audit middleware in ``app.main``). Never updated or deleted —
    there is no route or ORM path that mutates a row once written.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_org_at", "org_id", "at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Nullable so a pre-org mutation (none today) can still be recorded rather than lost.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # Stable actor string — never a raw secret. user id, api-key prefix (sq_live_ab12cd34),
    # or "system". Mirrors the Event.actor convention.
    actor: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    actor_type: Mapped[str] = mapped_column(String, default="user", nullable=False)  # user|api_key|agent|system
    # Semantic action when known ("user.role_changed"), else the HTTP verb+route.
    action: Mapped[str] = mapped_column(String, nullable=False, index=True)
    method: Mapped[str | None] = mapped_column(String, nullable=True)
    path: Mapped[str | None] = mapped_column(String, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Target resource id (path param) when resolvable, for filtering.
    target: Mapped[str | None] = mapped_column(String, nullable=True)
    ip: Mapped[str | None] = mapped_column(String, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
