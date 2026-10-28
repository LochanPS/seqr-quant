import uuid
from datetime import date, datetime

from sqlalchemy import Date, DateTime, Float, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CryptoComponent(Base):
    """One measured crypto observation on an asset at a point in time.

    This is the append-only *observation* record of the platform spine (PRD 13, fork B):
    every scan inserts new rows; nothing is mutated in place. The current, authoritative
    posture per crypto slot is projected into ComponentState. Kept the name CryptoComponent
    for back-compat with the existing scan write-path, CBOM router, and tests.
    """

    __tablename__ = "crypto_components"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    location_type: Mapped[str] = mapped_column(String, nullable=False)
    location_detail: Mapped[str] = mapped_column(String, nullable=False)

    algorithm: Mapped[str] = mapped_column(String, nullable=False)
    algorithm_family: Mapped[str] = mapped_column(String, nullable=False)
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)

    quantum_status: Mapped[str] = mapped_column(String, nullable=False)
    pqc_migration_priority: Mapped[float | None] = mapped_column(Float, nullable=True)
    estimated_hndl_exposure: Mapped[str | None] = mapped_column(String, nullable=True)
    deployment_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    crypto_agility_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    threat_timeline: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[str | None] = mapped_column(String, nullable=True)

    cert_expiry_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    cert_issuer: Mapped[str | None] = mapped_column(String, nullable=True)

    migration_status: Mapped[str] = mapped_column(String, default="open")

    # --- Observation provenance (PRD 13, forks B + D) -------------------------------------
    # Structured discovery source, not a free-form string (fork #7). One of DiscoverySource
    # in app/spine/sources.py: external_scanner, discovery_agent, active_probe, cloudflare_api,
    # aws_api, azure_api, manual_import, ... Drives precedence + is kept raw so precedence can
    # later become attribute-aware without a migration.
    source: Mapped[str] = mapped_column(String, default="external_scanner")
    # Higher wins when projecting current state (inside beats outside). Derived from `source`.
    precedence: Mapped[int] = mapped_column(Integer, default=10)
    # Numeric confidence 0..1 for probabilistic resolution (distinct from the legacy string
    # `confidence` field above, which is the scanner's own qualitative note).
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
