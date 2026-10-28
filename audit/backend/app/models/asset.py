import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    # `type` is validated against the AssetType registry (asset_types.key) so new asset
    # classes can be added without a schema change. Kept as a plain string for back-compat.
    type: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str | None] = mapped_column(String, nullable=True)
    identifier: Mapped[str] = mapped_column(String, nullable=False)
    data_sensitivity: Mapped[str] = mapped_column(String, default="internal")
    # How this asset entered the graph: "user_declared" (created via the UI/API) or
    # "discovered" (found by a scan / the discovery agent — e.g. an origin or certificate).
    provenance: Mapped[str] = mapped_column(String, default="user_declared")
    status: Mapped[str] = mapped_column(String, default="pending")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    scan_schedule: Mapped[str] = mapped_column(String, default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
