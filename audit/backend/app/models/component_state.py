import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ComponentState(Base):
    """Current-state projection over the append-only observations (PRD 13, forks B + D).

    One row per (asset, crypto slot) — e.g. the TLS key exchange on an endpoint, the
    certificate it serves, its cipher policy. It holds only *observed reality by reference*:

      - winning_observation_id      -> the CryptoComponent observation that currently wins
                                       (highest source precedence, then most recent)
      - latest_policy_evaluation_id -> the evaluation that last judged this slot

    It deliberately stores NO `desired` and NO cached compliance `status`: desired state lives
    only in the immutable Policy, and compliance is computed from the referenced evaluation.
    `conflict` flags that sources disagreed on this slot (a data-quality signal, not dropped).
    """

    __tablename__ = "component_states"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    # Identifies the crypto slot on the asset, e.g. "tls:kex", "tls:cert", "tls:cipher".
    slot_key: Mapped[str] = mapped_column(String, nullable=False)

    winning_observation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("crypto_components.id", ondelete="CASCADE"), nullable=False
    )
    latest_policy_evaluation_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("policy_evaluations.id", ondelete="SET NULL"), nullable=True
    )
    conflict: Mapped[bool] = mapped_column(Boolean, default=False)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
