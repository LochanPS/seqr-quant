"""OIDC engine (A5 SSO) — discovery, authorization, token exchange, id_token validation.

Multi-tenant by design: every org configures its own :class:`app.models.oidc_provider.
OIDCProvider`, so this uses Authlib's lower-level primitives (per-request client) rather
than a single app-global registration. The id_token — the security-critical part — is
verified with Authlib's JOSE (signature via the IdP's JWKS, plus iss/aud/exp/nonce).

CSRF + replay protection: the ``state`` parameter is a short-lived signed JWT carrying the
provider id and a ``nonce`` that must match the id_token's ``nonce`` claim on callback.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError
from jose import JWTError, jwt

from app.config import settings
from app.rbac import VALID_ROLES
from app.sso.crypto import decrypt_secret

_STATE_TTL = 600  # seconds an SSO login attempt stays valid
_DISCOVERY_TTL = 3600
_metadata_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}

# Role strength — group→role mapping picks the strongest role a user's groups grant.
_ROLE_RANK = {"viewer": 0, "member": 1, "auditor": 1, "analyst": 2, "admin": 3}


class OIDCError(Exception):
    """Any failure in the OIDC flow (config, network, or validation)."""


# --------------------------------------------------------------------------- state
def make_state(provider_id: uuid.UUID, nonce: str, next_url: str | None = None) -> str:
    return jwt.encode(
        {
            "type": "oidc_state",
            "pid": str(provider_id),
            "nonce": nonce,
            "next": next_url,
            "exp": datetime.now(timezone.utc) + timedelta(seconds=_STATE_TTL),
        },
        settings.SECRET_KEY,
        algorithm="HS256",
    )


def read_state(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except JWTError as e:
        raise OIDCError("Invalid or expired SSO state") from e
    if payload.get("type") != "oidc_state":
        raise OIDCError("Invalid SSO state type")
    return payload


# ----------------------------------------------------------------------- discovery
def discovery_url(provider) -> str:
    return provider.discovery_url or provider.issuer.rstrip("/") + "/.well-known/openid-configuration"


async def get_metadata(provider) -> dict:
    url = discovery_url(provider)
    now = time.time()
    hit = _metadata_cache.get(url)
    if hit and hit[0] > now:
        return hit[1]
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(url)
            r.raise_for_status()
            md = r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise OIDCError(f"OIDC discovery failed: {e}") from e
    for required in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if required not in md:
            raise OIDCError(f"OIDC discovery document missing {required}")
    _metadata_cache[url] = (now + _DISCOVERY_TTL, md)
    return md


async def get_jwks(jwks_uri: str) -> dict:
    now = time.time()
    hit = _jwks_cache.get(jwks_uri)
    if hit and hit[0] > now:
        return hit[1]
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(jwks_uri)
            r.raise_for_status()
            jwks = r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise OIDCError(f"OIDC JWKS fetch failed: {e}") from e
    _jwks_cache[jwks_uri] = (now + _DISCOVERY_TTL, jwks)
    return jwks


# --------------------------------------------------------------------------- flow
async def build_authorization_url(provider, redirect_uri: str, state: str, nonce: str) -> str:
    md = await get_metadata(provider)
    client = AsyncOAuth2Client(
        provider.client_id,
        decrypt_secret(provider.client_secret_encrypted),
        scope=provider.scopes,
        redirect_uri=redirect_uri,
    )
    url, _ = client.create_authorization_url(md["authorization_endpoint"], state=state, nonce=nonce)
    return url


async def fetch_claims(provider, code: str, redirect_uri: str, nonce: str) -> dict:
    """Exchange the auth code for tokens and return the validated id_token claims."""
    md = await get_metadata(provider)
    client = AsyncOAuth2Client(
        provider.client_id,
        decrypt_secret(provider.client_secret_encrypted),
        redirect_uri=redirect_uri,
    )
    try:
        token = await client.fetch_token(
            md["token_endpoint"], grant_type="authorization_code", code=code
        )
    except Exception as e:  # authlib raises various OAuth/HTTP errors
        raise OIDCError(f"Token exchange failed: {e}") from e
    id_token = token.get("id_token")
    if not id_token:
        raise OIDCError("IdP returned no id_token")
    return await validate_id_token(provider, md, id_token, nonce)


async def validate_id_token(provider, md: dict, id_token: str, nonce: str | None) -> dict:
    jwks = await get_jwks(md["jwks_uri"])
    jws = JsonWebToken(["RS256", "RS384", "RS512", "ES256", "ES384"])
    try:
        keyset = JsonWebKey.import_key_set(jwks)
        claims = jws.decode(
            id_token,
            keyset,
            claims_options={
                "iss": {"essential": True, "value": provider.issuer},
                "aud": {"essential": True, "values": [provider.client_id]},
            },
        )
        claims.validate()  # exp / iat / nbf
    except JoseError as e:
        raise OIDCError(f"id_token validation failed: {e}") from e
    if nonce and claims.get("nonce") != nonce:
        raise OIDCError("id_token nonce mismatch")
    return dict(claims)


# ----------------------------------------------------------------- identity mapping
def extract_identity(provider, claims: dict) -> tuple[str | None, str | None, list[str]]:
    email = claims.get("email")
    sub = claims.get("sub")
    raw = claims.get(provider.groups_claim) or []
    if isinstance(raw, str):
        # Some IdPs deliver groups as a space/comma-separated string.
        raw = [g.strip() for g in raw.replace(",", " ").split() if g.strip()]
    groups = [str(g) for g in raw]
    return email, sub, groups


def map_role(provider, groups: list[str]) -> str:
    """Map IdP groups → the strongest SeQr role they grant, else the provider default."""
    mapped = [provider.group_role_map.get(g) for g in groups]
    valid = [r for r in mapped if r in VALID_ROLES]
    if not valid:
        return provider.default_role if provider.default_role in VALID_ROLES else "member"
    return max(valid, key=lambda r: _ROLE_RANK.get(r, 0))
