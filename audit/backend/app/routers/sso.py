"""Enterprise SSO — OIDC (A5).

Two surfaces:
- **Config** (``/api/v1/sso/config``) — org-admin CRUD of the org's OIDCProvider. Gated by
  ``org:manage``. The client secret is write-only (encrypted at rest, never returned).
- **Flow** (``/api/v1/sso/oidc/{start,callback}``) — the public SP-initiated login. ``start``
  redirects to the IdP; ``callback`` validates the id_token, maps IdP groups → a SeQr role,
  provisions/links the user, mints SeQr tokens, and redirects to the frontend.

Group→role mapping and JIT provisioning honour the RBAC matrix in :mod:`app.rbac`.
"""
import secrets
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit_log
from app.config import settings
from app.database import get_db
from app.deps import require_permission
from app.models.oidc_provider import OIDCProvider
from app.models.organisation import Organisation
from app.models.user import User
from app.rbac import ORG_MANAGE, VALID_ROLES
from app.security import create_access_token, create_refresh_token
from app.sso import oidc
from app.sso.crypto import encrypt_secret

router = APIRouter()

_CALLBACK_PATH = "/api/v1/sso/oidc/callback"


# --------------------------------------------------------------------------- schemas
class SSOConfigIn(BaseModel):
    issuer: str
    client_id: str
    client_secret: Optional[str] = None  # write-only; omit on update to keep existing
    display_name: str = "SSO"
    discovery_url: Optional[str] = None
    scopes: str = "openid email profile groups"
    groups_claim: str = "groups"
    group_role_map: dict[str, str] = {}
    default_role: str = "member"
    email_domain: Optional[str] = None
    auto_provision: bool = True
    enabled: bool = True


class SSOConfigOut(BaseModel):
    configured: bool
    id: Optional[uuid.UUID] = None
    issuer: Optional[str] = None
    client_id: Optional[str] = None
    display_name: Optional[str] = None
    discovery_url: Optional[str] = None
    scopes: Optional[str] = None
    groups_claim: Optional[str] = None
    group_role_map: dict[str, str] = {}
    default_role: Optional[str] = None
    email_domain: Optional[str] = None
    auto_provision: Optional[bool] = None
    enabled: Optional[bool] = None
    has_client_secret: bool = False
    # The redirect URI the admin must register with their IdP.
    redirect_uri: Optional[str] = None
    login_url: Optional[str] = None


# --------------------------------------------------------------------------- helpers
def _redirect_uri(request: Request) -> str:
    base = settings.OIDC_REDIRECT_BASE.rstrip("/") if settings.OIDC_REDIRECT_BASE else str(request.base_url).rstrip("/")
    return f"{base}{_CALLBACK_PATH}"


def _frontend_base() -> str:
    return (settings.FRONTEND_URL.split(",")[0] or "http://localhost:3000").strip().rstrip("/")


def _validate_roles(cfg: SSOConfigIn) -> None:
    if cfg.default_role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"default_role must be one of {sorted(VALID_ROLES)}")
    bad = {r for r in cfg.group_role_map.values() if r not in VALID_ROLES}
    if bad:
        raise HTTPException(status_code=400, detail=f"group_role_map has invalid roles: {sorted(bad)}")


def _to_out(provider: OIDCProvider | None, request: Request) -> SSOConfigOut:
    if not provider:
        return SSOConfigOut(configured=False, redirect_uri=_redirect_uri(request))
    return SSOConfigOut(
        configured=True,
        id=provider.id,
        issuer=provider.issuer,
        client_id=provider.client_id,
        display_name=provider.display_name,
        discovery_url=provider.discovery_url,
        scopes=provider.scopes,
        groups_claim=provider.groups_claim,
        group_role_map=provider.group_role_map or {},
        default_role=provider.default_role,
        email_domain=provider.email_domain,
        auto_provision=provider.auto_provision,
        enabled=provider.enabled,
        has_client_secret=bool(provider.client_secret_encrypted),
        redirect_uri=_redirect_uri(request),
        login_url=f"{str(request.base_url).rstrip('/')}/api/v1/sso/oidc/start?provider_id={provider.id}",
    )


async def _get_org_provider(db: AsyncSession, org_id) -> OIDCProvider | None:
    return (await db.execute(select(OIDCProvider).where(OIDCProvider.org_id == org_id))).scalar_one_or_none()


# --------------------------------------------------------------------------- config
@router.get("/config", response_model=SSOConfigOut)
async def get_config(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(ORG_MANAGE))],
    db: AsyncSession = Depends(get_db),
):
    provider = await _get_org_provider(db, current_user.org_id)
    return _to_out(provider, request)


@router.put("/config", response_model=SSOConfigOut)
async def upsert_config(
    body: SSOConfigIn,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(ORG_MANAGE))],
    db: AsyncSession = Depends(get_db),
):
    _validate_roles(body)
    provider = await _get_org_provider(db, current_user.org_id)

    if provider is None:
        if not body.client_secret:
            raise HTTPException(status_code=400, detail="client_secret is required to create an SSO config")
        provider = OIDCProvider(org_id=current_user.org_id, client_secret_encrypted=encrypt_secret(body.client_secret))
        db.add(provider)

    provider.issuer = body.issuer
    provider.client_id = body.client_id
    provider.display_name = body.display_name
    provider.discovery_url = body.discovery_url
    provider.scopes = body.scopes
    provider.groups_claim = body.groups_claim
    provider.group_role_map = body.group_role_map
    provider.default_role = body.default_role
    provider.email_domain = body.email_domain.lower().strip() if body.email_domain else None
    provider.auto_provision = body.auto_provision
    provider.enabled = body.enabled
    # Only overwrite the secret when a new one is supplied.
    if body.client_secret:
        provider.client_secret_encrypted = encrypt_secret(body.client_secret)

    await db.commit()
    await db.refresh(provider)
    return _to_out(provider, request)


@router.delete("/config", status_code=204)
async def delete_config(
    current_user: Annotated[User, Depends(require_permission(ORG_MANAGE))],
    db: AsyncSession = Depends(get_db),
):
    provider = await _get_org_provider(db, current_user.org_id)
    if provider:
        await db.delete(provider)
        await db.commit()


# ----------------------------------------------------------------------------- flow
async def _resolve_provider(
    db: AsyncSession, provider_id: Optional[str], domain: Optional[str], email: Optional[str]
) -> OIDCProvider:
    provider = None
    if provider_id:
        try:
            provider = await db.get(OIDCProvider, uuid.UUID(provider_id))
        except (ValueError, TypeError):
            provider = None
    if provider is None and (domain or email):
        dom = (domain or (email.split("@")[-1] if email and "@" in email else "")).lower().strip()
        if dom:
            provider = (
                await db.execute(select(OIDCProvider).where(OIDCProvider.email_domain == dom))
            ).scalar_one_or_none()
    if provider is None:
        raise HTTPException(status_code=404, detail="No SSO provider found")
    if not provider.enabled:
        raise HTTPException(status_code=403, detail="SSO is not enabled for this organisation")
    return provider


@router.get("/oidc/start")
async def oidc_start(
    request: Request,
    provider_id: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Begin SP-initiated OIDC login: 302 to the org's IdP. Public."""
    if not settings.SSO_ENABLED:
        raise HTTPException(status_code=404, detail="SSO not enabled on this deployment")
    provider = await _resolve_provider(db, provider_id, domain, email)

    nonce = secrets.token_urlsafe(16)
    state = oidc.make_state(provider.id, nonce)
    try:
        url = await oidc.build_authorization_url(provider, _redirect_uri(request), state, nonce)
    except oidc.OIDCError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return RedirectResponse(url, status_code=302)


def _fe_redirect(fragment: str) -> RedirectResponse:
    # Tokens/errors travel in the URL fragment so they never reach server logs / Referer.
    return RedirectResponse(f"{_frontend_base()}/auth/sso/callback#{fragment}", status_code=302)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """OIDC redirect target: validate, map role, provision/link, mint tokens, redirect FE."""
    if not settings.SSO_ENABLED:
        raise HTTPException(status_code=404, detail="SSO not enabled on this deployment")
    if error:
        return _fe_redirect(f"error={error}")
    if not code or not state:
        return _fe_redirect("error=missing_code_or_state")

    try:
        st = oidc.read_state(state)
    except oidc.OIDCError:
        return _fe_redirect("error=invalid_state")

    provider = await db.get(OIDCProvider, uuid.UUID(st["pid"]))
    if not provider or not provider.enabled:
        return _fe_redirect("error=unknown_provider")

    try:
        claims = await oidc.fetch_claims(provider, code, _redirect_uri(request), st["nonce"])
    except oidc.OIDCError:
        return _fe_redirect("error=token_validation_failed")

    email, sub, groups = oidc.extract_identity(provider, claims)
    if not email:
        return _fe_redirect("error=no_email_claim")
    email = email.lower().strip()
    role = oidc.map_role(provider, groups)

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()

    if user is not None:
        if user.org_id != provider.org_id:
            return _fe_redirect("error=email_belongs_to_other_org")
        # Bind identity on first SSO login; reject a mismatched subject thereafter.
        if user.oidc_subject and sub and user.oidc_subject != sub:
            return _fe_redirect("error=identity_mismatch")
        if sub and not user.oidc_subject:
            user.oidc_subject = sub
        # IdP groups are authoritative — sync the role each login.
        user.role = role
        action = "sso.login"
    else:
        if not provider.auto_provision:
            return _fe_redirect("error=user_not_provisioned")
        user = User(
            org_id=provider.org_id,
            email=email,
            password_hash=None,
            name=claims.get("name"),
            role=role,
            oidc_subject=sub,
        )
        db.add(user)
        action = "sso.provisioned"

    await db.commit()
    await db.refresh(user)

    await audit_log.record(
        org_id=provider.org_id,
        actor=str(user.id),
        actor_type="user",
        action=action,
        method="GET",
        path=_CALLBACK_PATH,
        status_code=302,
        detail={"provider_id": str(provider.id), "role": role, "groups": groups},
    )

    access = create_access_token(str(user.id), str(user.org_id), user.role, user.token_version)
    refresh = create_refresh_token(str(user.id))
    return _fe_redirect(f"access_token={access}&refresh_token={refresh}&token_type=bearer")
