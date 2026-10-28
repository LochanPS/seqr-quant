import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AssetType(Base):
    """Extensible asset-type registry (PRD 13, fork #8).

    New asset classes (tls_endpoint, certificate, host, hsm, cdn_edge, origin, ssh_host,
    mail_server, internal_ca, load_balancer, reverse_proxy, ...) are added as rows, not by
    changing the graph schema. `org_id` is nullable: NULL = system-provided type available
    to every tenant; set = a tenant-specific custom type.
    """

    __tablename__ = "asset_types"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    key: Mapped[str] = mapped_column(String, nullable=False)  # e.g. "tls_endpoint"
    label: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str | None] = mapped_column(String, nullable=True)  # network|host|pki|key-store
    meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
