from fastapi import APIRouter, HTTPException, Depends, Request
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
from datetime import datetime
import uuid

router = APIRouter(prefix="/auth", tags=["auth"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Login endpoint with rate limiting and refresh token support.
    Returns access_token and refresh_token.
    """
    ip_address = request.client.host if request.client else None
    
    # Check rate limiting
    if not check_login_attempts(data.email, ip_address, db):
        # Log the failed attempt
        log_login_attempt(data.email, ip_address, False, db)
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Please try again later."
        )
    
    # Verify user credentials
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user or not verify_password(data.password, user.password_hash):
        log_login_attempt(data.email, ip_address, False, db)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is disabled")
    
    # MILESTONE 6: Check email verification
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="Email not verified. Please verify your email first.")
    
    # Log successful login
    log_login_attempt(data.email, ip_address, True, db)
    
    # Create tokens
    access_token = create_access_token({
        "sub": user.id,
        "role": user.role
    })
    
    refresh_token = create_and_store_refresh_token(user.id, db)
    
    # Audit log
    audit = AuditLog(
        id=str(uuid.uuid4()),
        actor_id=user.id,
        action="login",
        target=user.id,
        event_metadata={"ip_address": ip_address},
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/token/refresh", response_model=TokenResponse)
def refresh_token(data: RefreshTokenRequest, db: Session = Depends(get_db)):
    """
    Refresh access token using refresh token.
    
    SECURITY:
    - Validates old refresh token
    - Issues new refresh token (rotation)
    - Old token is revoked (prevents replay attacks)
    - Returns new access_token + new refresh_token
    """
    user_id = validate_refresh_token(data.refresh_token, db)
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="User no longer active")
    
    # SECURITY FIX #2: Revoke old token before issuing new one (token rotation)
    revoke_refresh_token(data.refresh_token, db)
    
    # Generate new access token
    access_token = create_access_token({
        "sub": user.id,
        "role": user.role
    })
    
    # Issue new refresh token (prevents old token from being reused)
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
        "refresh_token": new_refresh_token,  # NEW token, not old one
        "token_type": "bearer"
    }

@router.post("/logout")
def logout(data: LogoutRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Logout endpoint - revokes the provided refresh token.
    """
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
        raise HTTPException(status_code=400, detail="Invalid refresh token")

@router.post("/logout-all-devices")
def logout_all_devices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Force logout from all devices by revoking all refresh tokens.
    """
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

