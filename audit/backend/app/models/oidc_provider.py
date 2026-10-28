import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class OIDCProvider(Base):
    """Per-org OpenID Connect identity provider config (A5 SSO).

    One provider per org (``org_id`` unique). The client secret is stored **encrypted**
    (see :mod:`app.sso.crypto`) and never returned by the API. ``group_role_map`` maps IdP
    group names to SeQr roles (:mod:`app.rbac`); a group with no mapping falls back to
    ``default_role``. ``email_domain`` powers the "Sign in with SSO" email-first UX.
    """

    __tablename__ = "oidc_providers"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    display_name: Mapped[str] = mapped_column(String, default="SSO", nullable=False)
    issuer: Mapped[str] = mapped_column(String, nullable=False)
    client_id: Mapped[str] = mapped_column(String, nullable=False)
    # Fernet ciphertext — never plaintext, never serialised out.
    client_secret_encrypted: Mapped[str] = mapped_column(String, nullable=False)
    # Optional explicit discovery URL; defaults to ``{issuer}/.well-known/openid-configuration``.
    discovery_url: Mapped[str | None] = mapped_column(String, nullable=True)
    scopes: Mapped[str] = mapped_column(String, default="openid email profile groups", nullable=False)
    groups_claim: Mapped[str] = mapped_column(String, default="groups", nullable=False)
    group_role_map: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    default_role: Mapped[str] = mapped_column(String, default="member", nullable=False)
    # Lower-cased email domain for SSO discovery (e.g. "acme.com"). Unique not enforced at
    # DB level (two orgs *shouldn't* share a domain, but we don't hard-fail on it).
    email_domain: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    auto_provision: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
