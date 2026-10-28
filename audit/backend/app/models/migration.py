import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class MigrationPlan(Base):
    """A remediation plan targeting the violations of one policy evaluation (PRD 14).

    Reproducible from its evaluation. The engine never executes — a plan becomes a signed
    bundle the customer applies, after which a re-scan verifies convergence.
    """

    __tablename__ = "migration_plans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    policy_evaluation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("policy_evaluations.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String, default="draft")  # draft|bundled|applied|verified|superseded
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ChangeItem(Base):
    """One remediation step: bring a slot on an asset from its actual state to the policy target.

    `depends_on` holds ChangeItem ids that must be applied first (graph-ordered, e.g. harden an
    origin before touching the edge that fronts it). Synthesis fills the concrete artifact later.
    """

    __tablename__ = "change_items"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("migration_plans.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    violation_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("violations.id", ondelete="SET NULL"), nullable=True
    )
    slot_key: Mapped[str | None] = mapped_column(String, nullable=True)
    provider: Mapped[str] = mapped_column(String, default="nginx")  # nginx|cloudflare|cloudfront|...
    action: Mapped[str] = mapped_column(String, nullable=False)  # enable_hybrid_kex|harden_origin|...
    from_state: Mapped[str | None] = mapped_column(String, nullable=True)
    to_state: Mapped[str | None] = mapped_column(String, nullable=True)
    depends_on: Mapped[list | None] = mapped_column(JSON, nullable=True)  # list[str(change_item.id)]
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class MigrationBundle(Base):
    """Signed, applyable artifact assembled from a plan (metadata only in Slice 1).

    Populated by later slices: tar manifest + per-artifact SHA-256, rendered runbook, and an
    Ed25519 signature from a DEDICATED migration key (separate from attestation/licensing keys).
    """

    __tablename__ = "migration_bundles"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("migration_plans.id", ondelete="CASCADE"), nullable=False
    )
    manifest: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    runbook: Mapped[str | None] = mapped_column(Text, nullable=True)
    migration_engine_version: Mapped[str | None] = mapped_column(String, nullable=True)
    graph_schema_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    key_id: Mapped[str | None] = mapped_column(String, nullable=True)
    signature: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RollbackPlan(Base):
    """Per-ChangeItem revert: captured pre-state + the inverse artifact (filled by synthesis)."""

    __tablename__ = "rollback_plans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    change_item_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("change_items.id", ondelete="CASCADE"), nullable=False
    )
    pre_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    inverse_artifact: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
