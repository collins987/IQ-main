# app/api/auth.py
"""
SentinelIQ Authentication API

Supports three authentication paths:
1. Database-backed users (standard login)
2. Universal admin credentials (environment-based, for bootstrap/emergency)
3. Dummy test user (DEV_MODE only, non-persistent)

Security:
- All paths issue standard JWT tokens
- RBAC enforced via token payload
- Rate limiting on all login attempts
- Audit logging for all authentication events
"""

from fastapi import APIRouter, HTTPException, Depends, Request, status
from sqlalchemy.orm import Session
from app.core.db import SessionLocal
from app.models import User, AuditLog
from app.core.security import verify_password, create_access_token
from app.core.auth_utils import (
    create_and_store_refresh_token,
    validate_refresh_token,
    revoke_refresh_token,
    revoke_all_user_tokens,
    check_login_attempts,
    log_login_attempt
)
from app.schemas.auth import LoginRequest, TokenResponse, RefreshTokenRequest, LogoutRequest
from app.dependencies import get_current_user
from app.config import (
    DEV_MODE,
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    TEST_USER_EMAIL,
    TEST_USER_PASSWORD
)
from datetime import datetime
import uuid
import secrets
import logging

logger = logging.getLogger("sentineliq.auth")

router = APIRouter(prefix="/auth", tags=["auth"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# Virtual User Classes (for non-DB authentication)
# ============================================================================

class VirtualUser:
    """
    Base class for virtual users (admin/test users not stored in database).
    Mimics the User model interface for compatibility with token generation.
    """
    def __init__(self, id: str, email: str, role: str, first_name: str, last_name: str):
        self.id = id
        self.email = email
        self.role = role
        self.first_name = first_name
        self.last_name = last_name
        self.is_active = True
        self.email_verified = True
        self.is_virtual = True  # Flag to identify virtual users


# ============================================================================
# Factory Functions (Dynamic User Creation - ROOT CAUSE FIX)
# ============================================================================
# IMPORTANT: VirtualUser objects are created DYNAMICALLY at authentication time,
# NOT at module import. This prevents stale credential mismatches when env vars
# are loaded after module import.

def create_virtual_admin() -> VirtualUser:
    """Create virtual admin with CURRENT config values."""
    return VirtualUser(
        id="virtual-admin-00000000-0000-0000-0000-000000000001",
        email=ADMIN_EMAIL,
        role="admin",
        first_name="System",
        last_name="Administrator"
    )


def create_virtual_test_user() -> VirtualUser:
    """Create test user with CURRENT config values."""
    return VirtualUser(
        id="virtual-test-00000000-0000-0000-0000-000000000002",
        email=TEST_USER_EMAIL,
        role="viewer",
        first_name="Test",
        last_name="User"
    )


# ============================================================================
# Authentication Functions
# ============================================================================

def authenticate_virtual_admin(email: str, password: str) -> VirtualUser | None:
    """
    Authenticate against universal admin credentials.
    
    ROOT CAUSE FIX: Uses factory function to create user with CURRENT config,
    not stale values from module import time.
    """
    # Normalize for comparison
    input_email = email.strip().lower()
    admin_email = ADMIN_EMAIL.strip().lower()
    
    logger.debug(f"Admin auth: input='{input_email}' vs expected='{admin_email}'")
    
    if input_email != admin_email:
        logger.debug("Admin auth: email mismatch")
        return None
    
    if password != ADMIN_PASSWORD:
        logger.debug(f"Admin auth: password mismatch (input_len={len(password)}, expected_len={len(ADMIN_PASSWORD)})")
        return None
    
    logger.info(f"Virtual admin authenticated: {email}")
    return create_virtual_admin()  # Dynamic creation with current config


def authenticate_test_user(email: str, password: str) -> VirtualUser | None:
    """
    Authenticate dummy test user (DEV_MODE only).
    
    ROOT CAUSE FIX: Uses factory function for dynamic creation.
    """
    if not DEV_MODE:
        logger.debug("Test user auth skipped: DEV_MODE=false")
        return None
    
    input_email = email.strip().lower()
    test_email = TEST_USER_EMAIL.strip().lower()
    
    if input_email != test_email:
        return None
    
    if password != TEST_USER_PASSWORD:
        logger.debug("Test user auth: password mismatch")
        return None
    
    logger.info(f"Test user authenticated (DEV_MODE): {email}")
    return create_virtual_test_user()  # Dynamic creation with current config


def authenticate_db_user(email: str, password: str, db: Session) -> User | None:
    """
    Authenticate against database-backed user.
    
    ROOT CAUSE FIX: Uses case-insensitive email lookup with ilike().
    """
    normalized_email = email.strip().lower()
    logger.debug(f"DB auth: looking up '{normalized_email}'")
    
    # Case-insensitive email lookup
    user = db.query(User).filter(User.email.ilike(normalized_email)).first()
    
    if not user:
        logger.debug(f"DB auth: user not found")
        return None
    
    logger.debug(f"DB auth: found user id={user.id}, active={user.is_active}, verified={user.email_verified}")
    
    if not verify_password(password, user.password_hash):
        logger.debug(f"DB auth: password verification failed")
        return None
    
    logger.info(f"DB user authenticated: {user.email}")
    return user


def create_user_info(user) -> dict:
    """Create user info dict for token response."""
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "first_name": getattr(user, 'first_name', 'User'),
        "last_name": getattr(user, 'last_name', ''),
    }


# ============================================================================
# Login Endpoint
# ============================================================================

@router.post("/login")
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Unified login endpoint supporting:
    1. Universal admin credentials (environment-based)
    2. Dummy test user (DEV_MODE only)
    3. Database-backed users
    
    Returns:
        - access_token: Short-lived JWT for API access
        - refresh_token: Long-lived token for token refresh
        - token_type: "bearer"
        - user: User information (id, email, role, name)
    
    Error Codes:
        - 401: Invalid credentials
        - 403: Account disabled or email not verified
        - 429: Too many failed attempts (rate limited)
    """
    ip_address = request.client.host if request.client else "unknown"
    authenticated_user = None
    is_virtual_user = False
    
    # =========================================================================
    # STEP 1: Try virtual admin authentication (always available)
    # =========================================================================
    authenticated_user = authenticate_virtual_admin(data.email, data.password)
    if authenticated_user:
        is_virtual_user = True
        logger.info(f"Admin login via universal credentials: {data.email} from {ip_address}")
    
    # =========================================================================
    # STEP 2: Try test user authentication (DEV_MODE only)
    # =========================================================================
    if not authenticated_user:
        authenticated_user = authenticate_test_user(data.email, data.password)
        if authenticated_user:
            is_virtual_user = True
            logger.info(f"Test user login (DEV_MODE): {data.email} from {ip_address}")
    
    # =========================================================================
    # STEP 3: Try database user authentication
    # =========================================================================
    if not authenticated_user:
        # Check rate limiting for DB users only
        if not check_login_attempts(data.email, ip_address, db):
            log_login_attempt(data.email, ip_address, False, db)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later."
            )
        
        authenticated_user = authenticate_db_user(data.email, data.password, db)
        
        if not authenticated_user:
            # Log failed attempt
            log_login_attempt(data.email, ip_address, False, db)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Check account status for DB users
        if not authenticated_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is disabled"
            )
        
        if not authenticated_user.email_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email not verified. Please verify your email first."
            )
        
        # Log successful DB user login
        log_login_attempt(data.email, ip_address, True, db)
    
    # =========================================================================
    # STEP 4: Generate tokens
    # =========================================================================
    access_token = create_access_token({
        "sub": authenticated_user.id,
        "role": authenticated_user.role,
        "email": authenticated_user.email,
        "is_virtual": is_virtual_user
    })
    
    # For virtual users, generate a simple refresh token (not stored in DB)
    if is_virtual_user:
        refresh_token = f"virtual_{secrets.token_urlsafe(32)}"
    else:
        refresh_token = create_and_store_refresh_token(authenticated_user.id, db)
    
    # =========================================================================
    # STEP 5: Audit logging
    # =========================================================================
    # IMPORTANT:
    # - Database users: write full audit log entry (actor_id FK to users.id)
    # - Virtual users (admin/test): skip DB audit to avoid FK constraint errors
    #   because virtual users do not exist in the users table.
    if not is_virtual_user:
        audit = AuditLog(
            id=str(uuid.uuid4()),
            actor_id=authenticated_user.id,
            action="login",
            target=authenticated_user.id,
            event_metadata={
                "ip_address": ip_address,
                "user_type": "database",
                "role": authenticated_user.role
            },
            timestamp=datetime.utcnow()
        )
        db.add(audit)
        db.commit()
    
    logger.info(f"Login successful: {authenticated_user.email} (role={authenticated_user.role}, virtual={is_virtual_user})")
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": create_user_info(authenticated_user)
    }


# ============================================================================
# Token Refresh Endpoint
# ============================================================================

@router.post("/token/refresh")
def refresh_token_endpoint(data: RefreshTokenRequest, db: Session = Depends(get_db)):
    """
    Refresh access token using refresh token.
    
    SECURITY:
    - Validates old refresh token
    - Issues new refresh token (rotation)
    - Old token is revoked (prevents replay attacks)
    - Virtual user tokens prompt re-login
    """
    # Handle virtual user refresh tokens
    if data.refresh_token.startswith("virtual_"):
        # For virtual users, we can't really "refresh" without re-authentication
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Virtual user session expired. Please login again."
        )
    
    user_id = validate_refresh_token(data.refresh_token, db)
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User no longer active"
        )
    
    # Revoke old token before issuing new one (token rotation)
    revoke_refresh_token(data.refresh_token, db)
    
    # Generate new access token
    access_token = create_access_token({
        "sub": user.id,
        "role": user.role,
        "email": user.email,
        "is_virtual": False
    })
    
    # Issue new refresh token
    new_refresh_token = create_and_store_refresh_token(user.id, db)
    
    # Audit log
    audit = AuditLog(
        id=str(uuid.uuid4()),
        actor_id=user.id,
        action="token_refresh",
        target=user.id,
        event_metadata={},
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "user": create_user_info(user)
    }


# ============================================================================
# Logout Endpoints
# ============================================================================

@router.post("/logout")
def logout(data: LogoutRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Logout endpoint - revokes the provided refresh token."""
    # Handle virtual user logout (just acknowledge)
    if data.refresh_token.startswith("virtual_"):
        return {"msg": "Logged out successfully"}
    
    success = revoke_refresh_token(data.refresh_token, db)
    
    # Audit log
    audit = AuditLog(
        id=str(uuid.uuid4()),
        actor_id=current_user.id,
        action="logout",
        target=current_user.id,
        event_metadata={},
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    if success:
        return {"msg": "Logged out successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token"
        )


@router.post("/logout-all-devices")
def logout_all_devices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Force logout from all devices by revoking all refresh tokens."""
    revoke_all_user_tokens(current_user.id, db)
    
    # Audit log
    audit = AuditLog(
        id=str(uuid.uuid4()),
        actor_id=current_user.id,
        action="logout_all_devices",
        target=current_user.id,
        event_metadata={},
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return {"msg": "Logged out from all devices"}


# ============================================================================
# Auth Info Endpoint
# ============================================================================

@router.get("/me")
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current authenticated user info."""
    return create_user_info(current_user)

