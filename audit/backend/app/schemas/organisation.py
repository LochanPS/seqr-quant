from typing import Optional

from pydantic import BaseModel, EmailStr


class OrgUpdate(BaseModel):
    name: Optional[str] = None
    sector: Optional[str] = None


class InviteUserRequest(BaseModel):
    email: EmailStr
    role: str = "member"


class InviteUserResponse(BaseModel):
    email: str
    role: str
    # Returned ONCE in the response body (over HTTPS) for the admin to share securely —
    # never embedded in a URL. The invited user must change it on first login.
    temporary_password: str
    must_change_password: bool = True


class UpdateRoleRequest(BaseModel):
    role: str
