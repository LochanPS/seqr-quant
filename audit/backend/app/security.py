import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

API_KEY_PREFIX = "sq_live_"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _make_token(payload: dict, expire: datetime) -> str:
    payload = {**payload, "exp": expire}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_access_token(user_id: str, org_id: str, role: str, token_version: int = 0) -> str:
    return _make_token(
        {"sub": user_id, "org_id": org_id, "role": role, "type": "access", "tv": token_version},
        datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(user_id: str) -> str:
    return _make_token(
        {"sub": user_id, "type": "refresh"},
        datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def create_mfa_temp_token(user_id: str) -> str:
    return _make_token(
        {"sub": user_id, "type": "mfa_temp"},
        datetime.now(timezone.utc) + timedelta(minutes=5),
    )


async def _user_from_api_key(raw_key: str, db: AsyncSession):
    """Authenticate a request bearing an sq_live_ API key."""
    from app.models.api_key import APIKey
    from app.models.user import User

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    api_key = (await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )).scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if api_key.expires_at and api_key.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="API key expired")
    if not api_key.user_id:
        raise HTTPException(status_code=401, detail="API key has no associated user")

    api_key.last_used_at = datetime.utcnow()
    await db.commit()

    user = await db.get(User, api_key.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="API key user not found")
    return user


def _stamp_audit_principal(request: Request | None, actor: str, actor_type: str, org_id) -> None:
    """Record the authenticated principal on request.state for the audit middleware.

    The middleware runs after the route (and its dependencies) and reads these to write
    one append-only audit row per mutating request. Set here so every authenticated path
    is covered uniformly, without instrumenting each handler.
    """
    if request is None:
        return
    request.state.audit_actor = actor
    request.state.audit_actor_type = actor_type
    request.state.audit_org_id = str(org_id) if org_id else None


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    from app.models.user import User  # local import avoids circular

    token = credentials.credentials

    # API-key auth (programmatic / CI): bearer token is an sq_live_ key.
    if token.startswith(API_KEY_PREFIX):
        user = await _user_from_api_key(token, db)
        _stamp_audit_principal(request, f"apikey:{token[:16]}", "api_key", user.org_id)
        return user

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await db.get(User, uuid.UUID(user_id))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # token_version: a logout / forced sign-out bumps the user's version,
    # invalidating every JWT issued before it.
    if payload.get("tv", 0) != (user.token_version or 0):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    await _block_if_suspended(user, db)
    _stamp_audit_principal(request, str(user.id), "user", user.org_id)
    return user


class AgentPrincipal:
    """The authenticated identity behind a discovery-agent request (PRD 15).

    Not a User: an agent credential is an org-scoped API key with the `agent` scope and
    may have no associated user. Carries just enough to attribute + tenant-scope an upload.
    """

    def __init__(self, org_id: uuid.UUID, key_id: uuid.UUID, key_prefix: str, name: str):
        self.org_id = org_id
        self.key_id = key_id
        self.key_prefix = key_prefix
        self.name = name

    @property
    def actor(self) -> str:
        """Stable actor string for the append-only event log (never the raw key)."""
        return f"agent:{self.key_prefix}"


async def get_current_agent(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    request: Request = None,
    db: AsyncSession = Depends(get_db),
) -> "AgentPrincipal":
    """Authenticate a discovery agent by its `agent`-scoped sq_live_ API key.

    Agents authenticate ONLY with an API key (never a user JWT) and the key must carry the
    `agent` scope. Unlike get_current_user, an agent key needs no associated user — the
    credential is org-owned. Returns a tenant-scoped principal; 401 on a bad/expired key,
    403 when the key lacks the `agent` scope.
    """
    from app.models.api_key import APIKey

    token = credentials.credentials
    if not token.startswith(API_KEY_PREFIX):
        raise HTTPException(status_code=401, detail="Agent credential required (sq_live_ key)")

    key_hash = hashlib.sha256(token.encode()).hexdigest()
    api_key = (await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )).scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if api_key.expires_at and api_key.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="API key expired")
    if "agent" not in (api_key.scopes or []):
        raise HTTPException(status_code=403, detail="API key lacks the 'agent' scope")

    api_key.last_used_at = datetime.utcnow()
    await db.commit()
    principal = AgentPrincipal(api_key.org_id, api_key.id, api_key.key_prefix, api_key.name)
    _stamp_audit_principal(request, principal.actor, "agent", api_key.org_id)
    return principal


def is_operator(user) -> bool:
    return (user.email or "").lower() in settings.operator_email_set


async def _block_if_suspended(user, db: AsyncSession):
    """Suspended orgs' users are blocked — except platform operators."""
    from app.models.organisation import Organisation
    if is_operator(user):
        return
    org = await db.get(Organisation, user.org_id)
    if org and getattr(org, "status", "active") == "suspended":
        raise HTTPException(status_code=403, detail="Organisation suspended. Contact support.")


async def require_operator(user=Depends(get_current_user)):
    """Dependency: only platform operators (OPERATOR_EMAILS) may pass."""
    if not is_operator(user):
        raise HTTPException(status_code=403, detail="Operator access required")
    return user
