from pydantic import BaseModel, EmailStr, Field
from datetime import datetime

class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str = Field(
        min_length=8,
        max_length=72,
        description="Password must be between 8 and 72 characters"
    )
    role: str = "viewer"

class UserOut(BaseModel):
    id: str
    org_id: str | None
    first_name: str
    last_name: str
    email: EmailStr
    role: str
    risk_score: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

