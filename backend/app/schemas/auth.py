from pydantic import BaseModel, field_validator
from typing import Optional
from email_validator import validate_email, EmailNotValidError


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        """Validate email format but allow special-use domains like .local."""
        try:
            result = validate_email(value, check_deliverability=False)
            return result.normalized
        except EmailNotValidError as e:
            raise ValueError(str(e))


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
