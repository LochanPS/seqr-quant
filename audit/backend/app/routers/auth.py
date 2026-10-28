import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Annotated

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.api_key import APIKey
from app.models.organisation import Organisation
from app.models.user import User
from app.schemas.auth import (
    APIKeyCreate,
    APIKeyCreatedResponse,
    APIKeyResponse,
    MFALoginRequest,
    MFASetupResponse,
    MFAVerifyRequest,
    OrgOut,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    UserOut,
    LoginRequest,
)
from app.security import (
    _stamp_audit_principal,
    create_access_token,
    create_mfa_temp_token,
    create_refresh_token,
    get_current_user,
    hash_password,
    verify_password,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Brute-force / credential-stuffing protection for auth endpoints.
# In-memory per-IP limiter (per-process). NOTE: move to Redis when running
# multiple workers so the limit is shared across processes.
# ---------------------------------------------------------------------------
_AUTH_MAX_ATTEMPTS = 10
_AUTH_WINDOW = 900  # 15 minutes


def _auth_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _enforce_auth_rate_limit(request: Request) -> None:
    # Only enforced in production (real internet exposure). Dev/test run
    # unlimited so suites and local work aren't throttled. Redis-backed when
    # available so the limit holds across workers.
    if settings.ENVIRONMENT != "production":
        return
    from app.ratelimit import hit
    exceeded, _ = hit(f"auth:{_auth_client_ip(request)}", _AUTH_MAX_ATTEMPTS, _AUTH_WINDOW)
    if exceeded:
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Try again in a few minutes.",
        )


@router.post("/register", response_model=RegisterResponse)
async def register(body: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    _enforce_auth_rate_limit(request)
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    org = Organisation(name=body.org_name)
    db.add(org)
    await db.flush()

    user = User(
        org_id=org.id,
        email=body.email,
        password_hash=hash_password(body.password),
        name=body.name,
        role="admin",
    )
    db.add(user)
    await db.commit()
    await db.refresh(org)
    await db.refresh(user)

    _stamp_audit_principal(request, str(user.id), "user", user.org_id)
    request.state.audit_action = "auth.register"

    return RegisterResponse(
        access_token=create_access_token(str(user.id), str(user.org_id), user.role, user.token_version),
        refresh_token=create_refresh_token(str(user.id)),
        user=UserOut.model_validate(user),
        org=OrgOut.model_validate(org),
    )


@router.post("/login")
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    _enforce_auth_rate_limit(request)
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not user.password_hash or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.commit()

    _stamp_audit_principal(request, str(user.id), "user", user.org_id)

    if user.mfa_enabled:
        request.state.audit_action = "auth.login_mfa_challenge"
        return {"mfa_required": True, "temp_token": create_mfa_temp_token(str(user.id))}

    request.state.audit_action = "auth.login"
    return {
        "access_token": create_access_token(str(user.id), str(user.org_id), user.role, user.token_version),
        "refresh_token": create_refresh_token(str(user.id)),
        "token_type": "bearer",
    }


@router.post("/mfa/login")
async def mfa_login(body: MFALoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Exchange an MFA temp token + TOTP code for access/refresh tokens."""
    try:
        payload = jwt.decode(body.temp_token, settings.SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "mfa_temp":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    user = await db.get(User, uuid.UUID(user_id)) if user_id else None
    if not user or not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status_code=401, detail="MFA not available for this account")

    if not pyotp.TOTP(user.mfa_secret).verify(body.totp_code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    user.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.commit()
    _stamp_audit_principal(request, str(user.id), "user", user.org_id)
    request.state.audit_action = "auth.mfa_login"
    return {
        "access_token": create_access_token(str(user.id), str(user.org_id), user.role, user.token_version),
        "refresh_token": create_refresh_token(str(user.id)),
        "token_type": "bearer",
    }


@router.post("/refresh")
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(body.refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await db.get(User, uuid.UUID(user_id))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return {"access_token": create_access_token(str(user.id), str(user.org_id), user.role, user.token_version)}


@router.post("/logout")
async def logout(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Invalidate all of this user's outstanding access tokens (bumps token_version)."""
    current_user.token_version = (current_user.token_version or 0) + 1
    await db.commit()
    return {"status": "ok"}


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(current_user.email, issuer_name="SeQr Audit")

    current_user.mfa_secret = secret
    await db.commit()

    return MFASetupResponse(secret=secret, qr_code=uri, uri=uri)


@router.post("/mfa/verify")
async def mfa_verify(
    body: MFAVerifyRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not set up")

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(body.totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    current_user.mfa_enabled = True
    await db.commit()
    return {"mfa_enabled": True}


@router.post("/api-keys", response_model=APIKeyCreatedResponse)
async def create_api_key(
    body: APIKeyCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    raw_key = f"sq_live_{secrets.token_urlsafe(18)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]

    api_key = APIKey(
        org_id=current_user.org_id,
        user_id=current_user.id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        scopes=body.scopes,
        expires_at=body.expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return APIKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes or [],
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
        key=raw_key,
    )


@router.get("/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(APIKey).where(APIKey.org_id == current_user.org_id))
    keys = result.scalars().all()
    return [
        APIKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            scopes=k.scopes or [],
            expires_at=k.expires_at,
            created_at=k.created_at,
        )
        for k in keys
    ]


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.org_id == current_user.org_id)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    await db.delete(key)
    await db.commit()
