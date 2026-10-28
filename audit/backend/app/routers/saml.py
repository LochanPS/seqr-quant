"""Enterprise SSO — SAML 2.0 (A5).

Sibling of :mod:`app.routers.sso` (OIDC). Two surfaces:

- **Config** (``/api/v1/saml/config``) — org-admin CRUD of the org's SAMLProvider. Gated by
  ``org:manage``. The IdP signing cert is public, so (unlike OIDC's client secret) it is
  returned by the API. ``/metadata`` serves the SP metadata the admin registers at the IdP.
- **Flow** (``/api/v1/saml/{login,acs}``) — SP-initiated login. ``login`` 302s to the IdP
  (HTTP-Redirect binding); ``acs`` consumes the POSTed SAMLResponse, fully validates it
  (:mod:`app.sso.saml`), maps IdP groups → a SeQr role, provisions/links the user, dedupes
  the assertion (replay), mints SeQr tokens, and redirects to the frontend.
- **Logout** (``/api/v1/saml/{logout,sls}``) — SP-initiated SLO + the SLO service endpoint.

Group→role mapping and JIT provisioning honour the RBAC matrix in :mod:`app.rbac`.
"""
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit_log
from app.config import settings
from app.database import get_db
from app.deps import require_permission
from app.models.saml_provider import SAMLProvider, SAMLReplayID
from app.models.user import User
from app.rbac import ORG_MANAGE, VALID_ROLES
from app.security import create_access_token, create_refresh_token
from app.sso import saml
from app.sso.xmldsig import SignatureError

router = APIRouter()

_ACS_PATH = "/api/v1/saml/acs"


# --------------------------------------------------------------------------- schemas
class SAMLConfigIn(BaseModel):
    idp_entity_id: str
    idp_sso_url: str
    idp_x509_cert: str
    idp_slo_url: Optional[str] = None
    sp_entity_id: Optional[str] = None
    display_name: str = "SSO"
    want_assertions_signed: bool = True
    name_id_format: Optional[str] = None
    email_attribute: Optional[str] = None
    groups_attribute: str = "groups"
    group_role_map: dict[str, str] = {}
    default_role: str = "member"
    email_domain: Optional[str] = None
    auto_provision: bool = True
    enabled: bool = True


class SAMLConfigOut(BaseModel):
    configured: bool
    id: Optional[uuid.UUID] = None
    idp_entity_id: Optional[str] = None
    idp_sso_url: Optional[str] = None
    idp_slo_url: Optional[str] = None
    idp_x509_cert: Optional[str] = None
    sp_entity_id: Optional[str] = None
    display_name: Optional[str] = None
    want_assertions_signed: Optional[bool] = None
    name_id_format: Optional[str] = None
    email_attribute: Optional[str] = None
    groups_attribute: Optional[str] = None
    group_role_map: dict[str, str] = {}
    default_role: Optional[str] = None
    email_domain: Optional[str] = None
    auto_provision: Optional[bool] = None
    enabled: Optional[bool] = None
    # What the admin must register with their IdP.
    acs_url: Optional[str] = None
    metadata_url: Optional[str] = None
    login_url: Optional[str] = None


# --------------------------------------------------------------------------- helpers
def _acs_base(request: Request) -> str:
    return (settings.SAML_ACS_BASE.rstrip("/") if settings.SAML_ACS_BASE
            else str(request.base_url).rstrip("/"))


def _acs_url(request: Request) -> str:
    return f"{_acs_base(request)}{_ACS_PATH}"


def _entity_id(provider: SAMLProvider, request: Request) -> str:
    return saml.sp_entity_id(provider, _acs_base(request))


def _frontend_base() -> str:
    return (settings.FRONTEND_URL.split(",")[0] or "http://localhost:3000").strip().rstrip("/")


def _fe_redirect(fragment: str) -> RedirectResponse:
    # Tokens/errors travel in the URL fragment so they never reach server logs / Referer.
    return RedirectResponse(f"{_frontend_base()}/auth/sso/callback#{fragment}", status_code=302)


def _validate_roles(cfg: SAMLConfigIn) -> None:
    if cfg.default_role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"default_role must be one of {sorted(VALID_ROLES)}")
    bad = {r for r in cfg.group_role_map.values() if r not in VALID_ROLES}
    if bad:
        raise HTTPException(status_code=400, detail=f"group_role_map has invalid roles: {sorted(bad)}")


def _to_out(provider: SAMLProvider | None, request: Request) -> SAMLConfigOut:
    if not provider:
        return SAMLConfigOut(configured=False, acs_url=_acs_url(request))
    base = str(request.base_url).rstrip("/")
    return SAMLConfigOut(
        configured=True,
        id=provider.id,
        idp_entity_id=provider.idp_entity_id,
        idp_sso_url=provider.idp_sso_url,
        idp_slo_url=provider.idp_slo_url,
        idp_x509_cert=provider.idp_x509_cert,
        sp_entity_id=_entity_id(provider, request),
        display_name=provider.display_name,
        want_assertions_signed=provider.want_assertions_signed,
        name_id_format=provider.name_id_format,
        email_attribute=provider.email_attribute,
        groups_attribute=provider.groups_attribute,
        group_role_map=provider.group_role_map or {},
        default_role=provider.default_role,
        email_domain=provider.email_domain,
        auto_provision=provider.auto_provision,
        enabled=provider.enabled,
        acs_url=_acs_url(request),
        metadata_url=f"{base}/api/v1/saml/metadata?provider_id={provider.id}",
        login_url=f"{base}/api/v1/saml/login?provider_id={provider.id}",
    )


async def _get_org_provider(db: AsyncSession, org_id) -> SAMLProvider | None:
    return (await db.execute(select(SAMLProvider).where(SAMLProvider.org_id == org_id))).scalar_one_or_none()


# --------------------------------------------------------------------------- config
@router.get("/config", response_model=SAMLConfigOut)
async def get_config(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(ORG_MANAGE))],
    db: AsyncSession = Depends(get_db),
):
    return _to_out(await _get_org_provider(db, current_user.org_id), request)


@router.put("/config", response_model=SAMLConfigOut)
async def upsert_config(
    body: SAMLConfigIn,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(ORG_MANAGE))],
    db: AsyncSession = Depends(get_db),
):
    _validate_roles(body)
    provider = await _get_org_provider(db, current_user.org_id)
    if provider is None:
        provider = SAMLProvider(org_id=current_user.org_id)
        db.add(provider)

    provider.idp_entity_id = body.idp_entity_id
    provider.idp_sso_url = body.idp_sso_url
    provider.idp_x509_cert = body.idp_x509_cert
    provider.idp_slo_url = body.idp_slo_url
    provider.sp_entity_id = body.sp_entity_id
    provider.display_name = body.display_name
    provider.want_assertions_signed = body.want_assertions_signed
    provider.name_id_format = body.name_id_format
    provider.email_attribute = body.email_attribute
    provider.groups_attribute = body.groups_attribute
    provider.group_role_map = body.group_role_map
    provider.default_role = body.default_role
    provider.email_domain = body.email_domain.lower().strip() if body.email_domain else None
    provider.auto_provision = body.auto_provision
    provider.enabled = body.enabled

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


@router.get("/metadata")
async def sp_metadata(
    request: Request,
    provider_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """SP metadata XML for the org's provider. Public (contains no secrets)."""
    provider = None
    if provider_id:
        try:
            provider = await db.get(SAMLProvider, uuid.UUID(provider_id))
        except (ValueError, TypeError):
            provider = None
    if provider is None:
        raise HTTPException(status_code=404, detail="No SAML provider found")
    xml = saml.sp_metadata_xml(_entity_id(provider, request), _acs_url(request), provider.idp_slo_url and _slo_url(request))
    return Response(content=xml, media_type="application/samlmetadata+xml")


def _slo_url(request: Request) -> str:
    return f"{_acs_base(request)}/api/v1/saml/sls"


# ----------------------------------------------------------------------------- flow
async def _resolve_provider(
    db: AsyncSession, provider_id: Optional[str], domain: Optional[str], email: Optional[str]
) -> SAMLProvider:
    provider = None
    if provider_id:
        try:
            provider = await db.get(SAMLProvider, uuid.UUID(provider_id))
        except (ValueError, TypeError):
            provider = None
    if provider is None and (domain or email):
        dom = (domain or (email.split("@")[-1] if email and "@" in email else "")).lower().strip()
        if dom:
            provider = (
                await db.execute(select(SAMLProvider).where(SAMLProvider.email_domain == dom))
            ).scalar_one_or_none()
    if provider is None:
        raise HTTPException(status_code=404, detail="No SAML provider found")
    if not provider.enabled:
        raise HTTPException(status_code=403, detail="SAML SSO is not enabled for this organisation")
    return provider


@router.get("/login")
async def saml_login(
    request: Request,
    provider_id: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Begin SP-initiated SAML login: 302 to the org's IdP. Public."""
    if not settings.SAML_ENABLED:
        raise HTTPException(status_code=404, detail="SAML SSO not enabled on this deployment")
    provider = await _resolve_provider(db, provider_id, domain, email)
    try:
        request_id, redirect_url = saml.build_authn_request(provider, _acs_url(request), _entity_id(provider, request))
    except saml.SAMLError as e:
        raise HTTPException(status_code=502, detail=str(e))
    relay = saml.make_relay_state(provider.id, request_id)
    sep = "&" if "?" in redirect_url else "?"
    return RedirectResponse(f"{redirect_url}{sep}RelayState={relay}", status_code=302)


@router.post("/acs")
async def saml_acs(
    request: Request,
    SAMLResponse: str = Form(...),
    RelayState: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Assertion Consumer Service (HTTP-POST binding): validate, provision, mint, redirect FE."""
    if not settings.SAML_ENABLED:
        raise HTTPException(status_code=404, detail="SAML SSO not enabled on this deployment")
    if not RelayState:
        return _fe_redirect("error=missing_relaystate")
    try:
        st = saml.read_relay_state(RelayState)
    except saml.SAMLError:
        return _fe_redirect("error=invalid_relaystate")

    provider = await db.get(SAMLProvider, uuid.UUID(st["pid"]))
    if not provider or not provider.enabled:
        return _fe_redirect("error=unknown_provider")

    try:
        ident = saml.parse_and_validate_response(
            provider, SAMLResponse, st["rid"], _acs_url(request), _entity_id(provider, request)
        )
    except (saml.SAMLError, SignatureError):
        return _fe_redirect("error=assertion_validation_failed")

    # Replay protection: an assertion ID may be consumed exactly once.
    if await db.get(SAMLReplayID, ident.assertion_id):
        return _fe_redirect("error=assertion_replayed")
    db.add(SAMLReplayID(assertion_id=ident.assertion_id, org_id=provider.org_id,
                        expires_at=ident.not_on_or_after))

    role = saml.map_role(provider, ident.groups)
    user = (await db.execute(select(User).where(User.email == ident.email))).scalar_one_or_none()

    if user is not None:
        if user.org_id != provider.org_id:
            return _fe_redirect("error=email_belongs_to_other_org")
        if user.saml_subject and ident.name_id and user.saml_subject != ident.name_id:
            return _fe_redirect("error=identity_mismatch")
        if ident.name_id and not user.saml_subject:
            user.saml_subject = ident.name_id
        user.role = role  # IdP groups are authoritative — sync each login.
        action = "sso.saml.login"
    else:
        if not provider.auto_provision:
            return _fe_redirect("error=user_not_provisioned")
        user = User(
            org_id=provider.org_id, email=ident.email, password_hash=None,
            name=ident.name, role=role, saml_subject=ident.name_id,
        )
        db.add(user)
        action = "sso.saml.provisioned"

    await db.commit()
    await db.refresh(user)

    await audit_log.record(
        org_id=provider.org_id, actor=str(user.id), actor_type="user", action=action,
        method="POST", path=_ACS_PATH, status_code=302,
        detail={"provider_id": str(provider.id), "role": role, "groups": ident.groups},
    )

    access = create_access_token(str(user.id), str(user.org_id), user.role, user.token_version)
    refresh = create_refresh_token(str(user.id))
    return _fe_redirect(f"access_token={access}&refresh_token={refresh}&token_type=bearer")


# ------------------------------------------------------------------------------- SLO
@router.get("/logout")
async def saml_logout(
    request: Request,
    name_id: str = Query(...),
    session_index: Optional[str] = Query(None),
    provider_id: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """SP-initiated Single Logout: 302 to the IdP's SLO endpoint."""
    if not settings.SAML_ENABLED:
        raise HTTPException(status_code=404, detail="SAML SSO not enabled on this deployment")
    provider = await _resolve_provider(db, provider_id, domain, name_id)
    try:
        _, redirect_url = saml.build_logout_request(provider, name_id, session_index, _entity_id(provider, request))
    except saml.SAMLError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await audit_log.record(
        org_id=provider.org_id, actor=name_id, actor_type="user", action="sso.saml.logout",
        method="GET", path="/api/v1/saml/logout", status_code=302,
        detail={"provider_id": str(provider.id)},
    )
    return RedirectResponse(redirect_url, status_code=302)


@router.get("/sls")
async def saml_sls(
    request: Request,
    SAMLResponse: Optional[str] = Query(None),
    SAMLRequest: Optional[str] = Query(None),
    provider_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Single Logout service endpoint. Accepts the IdP's LogoutResponse (to our request) or an
    IdP-initiated LogoutRequest (to which we reply with a LogoutResponse)."""
    if not settings.SAML_ENABLED:
        raise HTTPException(status_code=404, detail="SAML SSO not enabled on this deployment")
    if SAMLResponse:
        # IdP confirmed our logout — nothing to mint; bounce to the FE login page.
        return RedirectResponse(f"{_frontend_base()}/login?logout=1", status_code=302)
    if SAMLRequest and provider_id:
        provider = await db.get(SAMLProvider, uuid.UUID(provider_id))
        if provider:
            try:
                msg = saml.decode_redirect_message(SAMLRequest)
                resp = saml.build_logout_response(provider, msg.get("ID", ""), _entity_id(provider, request))
                target = provider.idp_slo_url or _frontend_base()
                sep = "&" if "?" in target else "?"
                return RedirectResponse(f"{target}{sep}SAMLResponse={resp}", status_code=302)
            except saml.SAMLError:
                pass
    return RedirectResponse(f"{_frontend_base()}/login?logout=1", status_code=302)
