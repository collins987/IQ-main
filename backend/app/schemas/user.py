"""
User Schemas - Pydantic models for user-related API requests/responses.

Supports:
- User creation with validation
- Multiple response formats based on access level
- System user representation
"""

from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional, List, Dict, Any


# =============================================================================
# Request Schemas
# =============================================================================

class UserCreate(BaseModel):
    """Schema for creating a new user."""
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(
        ...,
        min_length=8,
        max_length=72,
        description="Password must be between 8 and 72 characters"
    )
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")


class UserUpdate(BaseModel):
    """Schema for updating user profile."""
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    email: Optional[EmailStr] = None


# =============================================================================
# Response Schemas
# =============================================================================

class UserOut(BaseModel):
    """Full user response (for self or admin access)."""
    id: str
    org_id: Optional[str] = None
    first_name: str
    last_name: str
    email: EmailStr
    role: str
    status: Optional[str] = "active"
    visibility: Optional[str] = "private"
    is_system_user: Optional[bool] = False
    risk_score: int = 0
    is_active: bool = True
    email_verified: Optional[bool] = False
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserPublicOut(BaseModel):
    """Public user response (limited fields, no PII)."""
    id: str
    first_name: str
    last_name: str
    role: str
    status: Optional[str] = None
    is_system_user: bool = False
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserRedactedOut(BaseModel):
    """Heavily redacted user response (minimal fields)."""
    id: str
    first_name: str
    role: str
    is_system_user: bool = False

    class Config:
        from_attributes = True


class SystemUserOut(BaseModel):
    """System user response with appropriate visibility."""
    id: str
    first_name: str
    last_name: str
    role: str
    status: str
    is_system_user: bool = True
    visibility: str = "global"
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# =============================================================================
# List Response Schemas
# =============================================================================

class PaginationInfo(BaseModel):
    """Pagination metadata."""
    page: int
    page_size: int
    total: int
    total_pages: int


class UserListResponse(BaseModel):
    """Paginated list of users."""
    users: List[Dict[str, Any]]
    pagination: PaginationInfo


class UserDetailResponse(BaseModel):
    """Single user detail response."""
    user: Dict[str, Any]
    access_level: Optional[str] = None


# =============================================================================
# Activity & Audit Schemas
# =============================================================================

class UserActivityItem(BaseModel):
    """Single activity log entry."""
    id: str
    action: str
    target: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class UserActivityResponse(BaseModel):
    """User activity log response."""
    user_id: str
    activity: List[UserActivityItem]
    count: int


class UserAccessLogItem(BaseModel):
    """Single access audit log entry."""
    id: str
    accessor_id: str
    action: str
    access_level: str
    fields_accessed: List[str]
    ip_address: Optional[str] = None
    timestamp: Optional[datetime] = None
    success: bool
    failure_reason: Optional[str] = None


class UserAccessAuditResponse(BaseModel):
    """User access audit response (admin only)."""
    user_id: str
    access_logs: List[UserAccessLogItem]
    count: int


# =============================================================================
# Permission Schemas
# =============================================================================

class UserPermissionsResponse(BaseModel):
    """User permissions response."""
    user_id: str
    role: str
    role_description: str
    permissions: List[str]
