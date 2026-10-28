import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Policy(Base):
    """An immutable, versioned crypto policy — the single home of *desired* state (PRD 13, §4).

    Policy-as-code: `body` is the declarative rule set (YAML/JSON), `content_hash` is its
    stable fingerprint. A policy version is never edited in place — a change produces a new
    row/version — so any attestation that references (version + content_hash) stays
    reproducible. `org_id` NULL + is_default = the system baseline derived from PCI DSS + SEBI.
    """

    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    version: Mapped[str] = mapped_column(String, nullable=False)
    content_hash: Mapped[str] = mapped_column(String, nullable=False)
    body: Mapped[dict] = mapped_column(JSON, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PolicyEvaluation(Base):
    """A single run of a policy over a set of assets. Reproducible via result_hash."""

    __tablename__ = "policy_evaluations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    policy_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    policy_content_hash: Mapped[str] = mapped_column(String, nullable=False)
    covered_asset_set: Mapped[list | None] = mapped_column(JSON, nullable=True)  # asset UUIDs judged
    result_hash: Mapped[str] = mapped_column(String, nullable=False)
    violations_count: Mapped[int] = mapped_column(Integer, default=0)
    ran_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Violation(Base):
    """A single policy rule failing on a single asset/slot in an evaluation."""

    __tablename__ = "violations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    evaluation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("policy_evaluations.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    observation_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("crypto_components.id", ondelete="SET NULL"), nullable=True
    )
    rule_key: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)  # from engines/risk.py
    actual: Mapped[str | None] = mapped_column(String, nullable=True)
    target_state: Mapped[str | None] = mapped_column(String, nullable=True)  # migration engine input
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
