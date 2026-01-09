# app/routes/users.py
"""
User Routes - Comprehensive user management with visibility controls.

Implements:
- User registration with email verification
- User listing with role-based filtering
- User profile access with visibility enforcement
- User activity and audit log access
- Rate limiting on sensitive endpoints

All user data access goes through UserService for consistent security.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
import uuid

from app.dependencies import get_current_user, get_db, require_role, require_permission
from app.schemas.user import UserCreate, UserOut, UserListResponse, UserDetailResponse
from app.models import User, AuditLog, UserStatus, UserVisibility
from app.core.security import hash_password
from app.services.token_service import generate_email_token
from app.services.email_service import send_email
from app.services.template_service import render_template
from app.services.user_service import (
    UserService, get_user_service,
    UserNotFoundError, UserVisibilityError
)
from app.config import FRONTEND_BASE_URL

router = APIRouter(prefix="/users", tags=["Users"])


def _get_request_context(request: Request) -> tuple[str, str, str]:
    """Extract IP, user agent, and path from request for audit logging."""
    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "unknown")
    path = str(request.url.path)
    return ip, user_agent, path


# =============================================================================
# User Listing Endpoints
# =============================================================================

@router.get("/", response_model=dict, summary="List users with visibility filtering")
def list_users(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    include_system: bool = Query(True, description="Include system users"),
    org_id: Optional[str] = Query(None, description="Filter by organization (admin only)"),
    status: Optional[str] = Query(None, description="Filter by status"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List users with role-based visibility.
    
    Access levels:
    - **Admin**: See all users with full details
    - **Analyst**: See org users + system users
    - **Viewer**: See only system users (global visibility)
    
    Pagination and filtering supported.
    """
    ip, user_agent, path = _get_request_context(request)
    service = UserService(db)
    
    return service.list_users(
        accessor=current_user,
        page=page,
        page_size=page_size,
        include_system_users=include_system,
        org_filter=org_id,
        status_filter=status,
        ip_address=ip,
        user_agent=user_agent,
        request_path=path
    )


@router.get("/system", summary="Get the system user")
def get_system_user(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the designated system user profile.
    
    The system user is a special user visible to all authenticated users
    based on their permission level. Used for platform-wide notifications,
    system actions, and compliance requirements.
    """
    service = UserService(db)
    system_user = service.get_system_user(current_user)
    
    if not system_user:
        raise HTTPException(
            status_code=404,
            detail="No system user configured"
        )
    
    return {
        "system_user": system_user,
        "message": "System user retrieved successfully"
    }


# =============================================================================
# User Profile Endpoints
# =============================================================================

@router.get("/me", response_model=UserOut, summary="Get current user profile")
def read_current_user(current_user: User = Depends(get_current_user)):
    """Get the authenticated user's own profile with full details."""
    return current_user


@router.get("/{user_id}", summary="Get user by ID")
def get_user(
    user_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get user profile by ID with visibility enforcement.
    
    Access levels determine what fields are returned:
    - **full**: All fields (admin or self)
    - **metadata**: Public fields + metadata (with permission)
    - **public**: Public fields only
    - **redacted**: Minimal fields with PII masked
    
    All access is logged for compliance.
    """
    ip, user_agent, path = _get_request_context(request)
    service = UserService(db)
    
    try:
        user_data = service.get_user_by_id(
            user_id=user_id,
            accessor=current_user,
            ip_address=ip,
            user_agent=user_agent,
            request_path=path
        )
        return {"user": user_data}
    
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    
    except UserVisibilityError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.get("/{user_id}/activity", summary="Get user activity logs")
def get_user_activity(
    user_id: str,
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="Max results"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get user's activity logs (actions they performed).
    
    Requires:
    - Self-access (view own activity)
    - OR `users.read_audit` permission (admin)
    """
    ip, user_agent, path = _get_request_context(request)
    service = UserService(db)
    
    try:
        return service.get_user_activity(
            user_id=user_id,
            accessor=current_user,
            limit=limit,
            ip_address=ip,
            user_agent=user_agent,
            request_path=path
        )
    
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    
    except UserVisibilityError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.get("/{user_id}/audit", summary="Get user access audit logs")
def get_user_audit_logs(
    user_id: str,
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="Max results"),
    current_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """
    Get audit logs of who accessed this user's profile.
    
    **Admin only** - Used for compliance and security investigations.
    
    Shows:
    - Who accessed the user's data
    - When the access occurred
    - What fields were accessed
    - From what IP/location
    """
    ip, user_agent, path = _get_request_context(request)
    service = UserService(db)
    
    try:
        return service.get_user_access_logs(
            user_id=user_id,
            accessor=current_user,
            limit=limit,
            ip_address=ip,
            user_agent=user_agent,
            request_path=path
        )
    
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    
    except UserVisibilityError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.get("/{user_id}/permissions", summary="Get user permissions")
def get_user_permissions(
    user_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get user's role and permissions.
    
    Accessible by:
    - Self (view own permissions)
    - Admins (view any user's permissions)
    - Users with `users.read_metadata` permission
    """
    ip, user_agent, path = _get_request_context(request)
    service = UserService(db)
    
    try:
        return service.get_user_permissions(
            user_id=user_id,
            accessor=current_user,
            ip_address=ip,
            user_agent=user_agent,
            request_path=path
        )
    
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    
    except UserVisibilityError as e:
        raise HTTPException(status_code=403, detail=str(e))


# =============================================================================
# User Registration
# =============================================================================

@router.post("/", response_model=UserOut, summary="Register new user")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user account.
    
    - Email verification required before API access
    - Default role is 'viewer'
    - Password must be 8-72 characters
    """
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")

    db_user = User(
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        password_hash=hash_password(user.password),
        role=user.role if hasattr(user, "role") else "viewer",
        status=UserStatus.PENDING.value,
        visibility=UserVisibility.ORGANIZATION.value,  # Visible to org members by default
        email_verified=False
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Send verification email
    verification_token = generate_email_token(
        user_id=db_user.id,
        purpose="email_verification",
        db=db
    )
    
    verification_url = f"{FRONTEND_BASE_URL}/verify-email?token={verification_token}"
    html = render_template(
        "email_verification.html",
        {
            "first_name": db_user.first_name,
            "verification_url": verification_url,
        }
    )
    send_email(
        to=db_user.email,
        subject="Verify your SentinelIQ account",
        html_content=html
    )
    
    # Audit log
    audit = AuditLog(
        id=str(uuid.uuid4()),
        actor_id=db_user.id,
        action="user_registered",
        target=db_user.id,
        event_metadata={"email": db_user.email},
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return db_user

    return current_user
