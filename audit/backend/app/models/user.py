import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organisations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    name: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, default="member")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    # OIDC subject ('sub' claim) bound on first SSO login — ties this account to the IdP
    # identity so a later email change at the IdP can't silently hijack a different account.
    oidc_subject: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    # SAML subject (NameID) bound on first SAML SSO login — same anti-hijack role as
    # oidc_subject, for the SAML IdP identity (see app.sso.saml).
    saml_subject: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    # Bumped on logout / forced sign-out to invalidate all outstanding JWTs for this user.
    token_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
