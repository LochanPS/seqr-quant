import secrets
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import require_permission
from app.models.organisation import Organisation
from app.models.user import User
from app.rbac import ORG_MANAGE, USERS_MANAGE, USERS_READ, VALID_ROLES
from app.schemas.auth import OrgOut, UserOut
from app.schemas.organisation import InviteUserRequest, InviteUserResponse, OrgUpdate, UpdateRoleRequest
from app.security import get_current_user, hash_password, is_operator

router = APIRouter()


def _validate_role(role: str) -> None:
    if role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"role must be one of {sorted(VALID_ROLES)}",
        )


@router.get("", response_model=OrgOut)
async def get_org(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organisation, current_user.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")
    # Lets the UI show operator navigation without probing /admin/* and eating a 403.
    return OrgOut.model_validate(org).model_copy(update={"viewer_is_operator": is_operator(current_user)})


@router.patch("", response_model=OrgOut)
async def update_org(
    body: OrgUpdate,
    current_user: Annotated[User, Depends(require_permission(ORG_MANAGE))],
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organisation, current_user.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")

    if body.name is not None:
        org.name = body.name
    if body.sector is not None:
        org.sector = body.sector

    await db.commit()
    await db.refresh(org)
    return org


@router.get("/users", response_model=list[UserOut])
async def list_users(
    current_user: Annotated[User, Depends(require_permission(USERS_READ))],
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.org_id == current_user.org_id))
    return result.scalars().all()


@router.post("/users/invite", response_model=InviteUserResponse)
async def invite_user(
    body: InviteUserRequest,
    current_user: Annotated[User, Depends(require_permission(USERS_MANAGE))],
    db: AsyncSession = Depends(get_db),
):
    _validate_role(body.role)

    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already exists")

    temp_password = secrets.token_urlsafe(16)
    user = User(
        org_id=current_user.org_id,
        email=body.email,
        password_hash=hash_password(temp_password),
        role=body.role,
    )
    db.add(user)
    await db.commit()

    # Return the temp password in the response body (HTTPS, admin-only) — NOT in a URL,
    # which would be logged, cached, and shared insecurely.
    return InviteUserResponse(
        email=body.email,
        role=body.role,
        temporary_password=temp_password,
    )


@router.patch("/users/{user_id}/role", response_model=UserOut)
async def update_user_role(
    user_id: uuid.UUID,
    body: UpdateRoleRequest,
    current_user: Annotated[User, Depends(require_permission(USERS_MANAGE))],
    db: AsyncSession = Depends(get_db),
):
    _validate_role(body.role)

    user = await db.get(User, user_id)
    if not user or user.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="User not found")

    # Guard: an admin must not strip the org's last admin (locks everyone out of
    # user/org management). Enforced only when demoting an existing admin.
    if user.role == "admin" and body.role != "admin":
        remaining = await db.execute(
            select(func.count()).select_from(User).where(
                User.org_id == current_user.org_id, User.role == "admin", User.id != user.id
            )
        )
        if (remaining.scalar() or 0) == 0:
            raise HTTPException(status_code=400, detail="Cannot remove the last admin of the org")

    user.role = body.role
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)
