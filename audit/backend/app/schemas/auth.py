import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str
    org_name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class MFAVerifyRequest(BaseModel):
    totp_code: str


class MFALoginRequest(BaseModel):
    temp_token: str
    totp_code: str


class MFASetupResponse(BaseModel):
    secret: str
    qr_code: str
    uri: str


class APIKeyCreate(BaseModel):
    name: str
    scopes: list[str] = []
    expires_at: Optional[datetime] = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    name: Optional[str]
    role: str
    mfa_enabled: bool
    created_at: datetime


class OrgOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    domain: Optional[str]
    sector: Optional[str]
    plan: str
    quantum_risk_score: Optional[int]
    created_at: datetime


class RegisterResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut
    org: OrgOut


class APIKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: list[str]
    expires_at: Optional[datetime]
    created_at: datetime


class APIKeyCreatedResponse(APIKeyResponse):
    key: str
