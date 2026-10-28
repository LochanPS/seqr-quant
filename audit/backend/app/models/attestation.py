import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Attestation(Base):
    """A signed, reproducible statement of crypto posture at a point in time (PRD 13, §6).

    The artifact auditors trust and the enterprise price is built on. It pins everything
    needed to reproduce and verify the claim offline: the exact policy (version + content
    hash), the evaluation (result hash + covered asset set), the tool versions, the graph
    schema version, and an Ed25519 signature with the key id used (separate attestation key,
    on-prem self-held / SaaS KMS-held; rotated with old public keys retained forever).

    Verified by a standalone `seqr verify-attestation` with no callback to SeQr.
    """

    __tablename__ = "attestations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("policies.id", ondelete="RESTRICT"), nullable=False
    )
    policy_version: Mapped[str] = mapped_column(String, nullable=False)
    policy_content_hash: Mapped[str] = mapped_column(String, nullable=False)

    evaluation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("policy_evaluations.id", ondelete="RESTRICT"), nullable=False
    )
    evaluation_result_hash: Mapped[str] = mapped_column(String, nullable=False)
    covered_asset_set: Mapped[list | None] = mapped_column(JSON, nullable=True)

    scanner_version: Mapped[str | None] = mapped_column(String, nullable=True)
    migration_engine_version: Mapped[str | None] = mapped_column(String, nullable=True)
    graph_schema_version: Mapped[int] = mapped_column(Integer, nullable=False)

    key_id: Mapped[str] = mapped_column(String, nullable=False)
    signature: Mapped[str] = mapped_column(String, nullable=False)  # Ed25519 over the canonical payload

    # The exact signed artifact (canonical fields + signature + public_key + algorithm), stored
    # verbatim so the downloadable certificate is byte-reproducible and verifies offline later.
    # The signed created_at lives INSIDE this JSON; the row's created_at below is only for ordering.
    artifact_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
