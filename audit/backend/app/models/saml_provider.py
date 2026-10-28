import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SAMLProvider(Base):
    """Per-org SAML 2.0 identity provider config (A5 SSO).

    Sibling of :class:`app.models.oidc_provider.OIDCProvider` — one provider per org
    (``org_id`` unique). Unlike OIDC there is **no client secret to encrypt**: a SAML SP
    trusts the IdP by its public signing certificate (``idp_x509_cert``, PEM or bare base64),
    which is public by nature. ``group_role_map`` maps IdP group values (from the
    ``groups_attribute``) to SeQr roles (:mod:`app.rbac`); an unmapped group falls back to
    ``default_role``. ``email_domain`` powers the "Sign in with SSO" email-first UX.
    """

    __tablename__ = "saml_providers"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    display_name: Mapped[str] = mapped_column(String, default="SSO", nullable=False)
    # IdP EntityID (the assertion's Issuer must equal this).
    idp_entity_id: Mapped[str] = mapped_column(String, nullable=False)
    # IdP Single Sign-On endpoint (HTTP-Redirect binding target for the AuthnRequest).
    idp_sso_url: Mapped[str] = mapped_column(String, nullable=False)
    # IdP Single Logout endpoint (optional).
    idp_slo_url: Mapped[str | None] = mapped_column(String, nullable=True)
    # IdP signing certificate — PEM or bare base64 DER. Public; stored as-is.
    idp_x509_cert: Mapped[str] = mapped_column(String, nullable=False)
    # SP EntityID. Optional; defaults to this SP's metadata URL (see app.routers.saml).
    sp_entity_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # Require the Assertion element itself to be signed (safest, common default).
    want_assertions_signed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    name_id_format: Mapped[str | None] = mapped_column(String, nullable=True)
    # Where to read the email: an attribute Name, else the NameID (when it is an email).
    email_attribute: Mapped[str | None] = mapped_column(String, nullable=True)
    groups_attribute: Mapped[str] = mapped_column(String, default="groups", nullable=False)
    group_role_map: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    default_role: Mapped[str] = mapped_column(String, default="member", nullable=False)
    email_domain: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    auto_provision: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SAMLReplayID(Base):
    """Consumed SAML assertion IDs — replay protection.

    A bearer SAML assertion is single-use: once its ID has been accepted at the ACS, the same
    assertion (a captured POST replayed inside its validity window) must be rejected. The ACS
    inserts the assertion ID here inside the login transaction; a duplicate insert = replay.
    ``expires_at`` (the assertion's NotOnOrAfter) lets a sweeper prune rows that can no longer
    be replayed anyway.
    """

    __tablename__ = "saml_replay_ids"

    assertion_id: Mapped[str] = mapped_column(String, primary_key=True)
    org_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
