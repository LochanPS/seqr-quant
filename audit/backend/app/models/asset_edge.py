import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AssetEdge(Base):
    """A temporal relationship between two assets (PRD 13, fork A + temporal refinement).

    The graph edges: an edge terminates for an origin, a load balancer fronts an upstream,
    an endpoint serves a certificate, a host holds an HSM. Relationships change over time,
    so edges are temporal (valid_from/valid_to) and never mutated in place — an edge that
    stops being true is closed with valid_to, not deleted. This is what powers the
    edge-vs-origin bypass analysis and point-in-time reconstruction.
    """

    __tablename__ = "asset_edges"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    src_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    dst_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    # edge_terminates | origin_of | serves_cert | upstream_of | hosted_on_hsm | fronts
    relation: Mapped[str] = mapped_column(String, nullable=False)

    discovered_by: Mapped[str] = mapped_column(String, default="external_scanner")  # DiscoverySource
    confidence: Mapped[float] = mapped_column(Float, default=1.0)

    valid_from: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # NULL = still valid
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
