import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AssetIdentity(Base):
    """Natural-key -> Asset UUID resolver (PRD 13, fork A).

    The permanent Asset UUID is trivial; the hard part is deciding *which* asset a fresh
    observation belongs to. Each stable natural key (a domain, an IP, a certificate
    fingerprint, an internal host, an HSM serial) maps here to an asset, with a confidence
    and a record of how it was resolved — so rescans reattach to the same asset instead of
    duplicating, and merges/splits are explicit and auditable.
    """

    __tablename__ = "asset_identities"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )

    key_type: Mapped[str] = mapped_column(String, nullable=False)  # domain|ip|cert_fp|host|hsm_serial
    key_value: Mapped[str] = mapped_column(String, nullable=False)

    # Probabilistic resolution support: how sure we are, and which resolver decided.
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    resolver: Mapped[str] = mapped_column(String, default="exact")  # exact|dns|ct_log|heuristic|manual
    resolved_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Set when this identity was merged into another asset (split/merge history, never deleted).
    merged_into: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
