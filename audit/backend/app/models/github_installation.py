import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class GitHubInstallation(Base):
    """Links a GitHub App installation to a SeQr org (PRD 07, CI-4).

    The hosted GitHub App reacts to webhooks keyed by `installation_id`, which GitHub
    assigns when an org/user installs the App. To sync a PR scan into a customer's CBOM
    (dashboard), we must know which SeQr org that installation belongs to — the webhook
    itself carries no SeQr identity. An operator creates the mapping once during onboarding
    (see docs/GITHUB_APP_OPERATIONS.md); scans without a mapping still post their review +
    commit status, they just skip dashboard persistence.

    `installation_id` is GitHub's own numeric id, stored as the primary key so a repeated
    install is idempotent.
    """

    __tablename__ = "github_installations"

    installation_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False
    )
    # GitHub account (org or user login) the App is installed on — operator-facing label.
    account_login: Mapped[str | None] = mapped_column(String, nullable=True)
    account_type: Mapped[str | None] = mapped_column(String, nullable=True)  # Organization | User

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
