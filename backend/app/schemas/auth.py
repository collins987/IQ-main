from pydantic import BaseModel, EmailStr
from typing import Optional


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserInfo(BaseModel):
    """User information included in authentication responses."""
    id: str
    email: str
    role: str
    first_name: str
    last_name: str


class TokenResponse(BaseModel):
    """Authentication response with tokens and user info."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: Optional[UserInfo] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str
