"""
Password Reset Routes (MILESTONE 6 - STEP 4)

Endpoints:
  POST /auth/password-reset/request?email=...
  POST /auth/password-reset/confirm

Handles secure password reset with single-use tokens.
Revokes all sessions on successful reset.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from datetime import datetime

from app.dependencies import get_db
from app.models import User, AuditLog, RefreshToken
from app.services.token_service import generate_email_token, verify_email_token
from app.services.email_service import send_email
from app.services.template_service import render_template
from app.core.security import hash_password
from app.config import FRONTEND_BASE_URL

router = APIRouter(prefix="/auth", tags=["Authentication"])


class PasswordResetRequest(BaseModel):
    """Request password reset by email."""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Confirm password reset with token."""
    token: str
    new_password: str


@router.post("/password-reset/request")
def request_password_reset(
    payload: PasswordResetRequest,
    db: Session = Depends(get_db)
):
    """
    Request password reset token via email.
    
    Query Parameters:
        email: User email address
    
    Security:
        - Does NOT leak whether email exists
        - Returns same response regardless
        - Token sent via email only
    
    Returns:
        Always: {"msg": "If email exists, a reset link has been sent"}
    """
    user = db.query(User).filter(User.email == payload.email).first()
    
    # Anti-enumeration: Don't reveal if email exists
    if user:
        # Generate single-use token
        token = generate_email_token(
            user_id=user.id,
            purpose="password_reset",
            db=db
        )
        
        # Render email template
        reset_url = f"{FRONTEND_BASE_URL}/reset-password?token={token}"
        html = render_template(
            "password_reset.html",
            {
                "first_name": user.first_name,
                "reset_url": reset_url,
            }
        )
        
        # Send email
        send_email(
            to=user.email,
            subject="Reset your SentinelIQ password",
            html_content=html
        )
        
        # Audit log
        audit_log = AuditLog(
            actor_id=user.id,
            action="password_reset_requested",
            target=user.email,
            event_metadata={"email": user.email}
        )
        db.add(audit_log)
        db.commit()
    
    # Always return same response (prevent enumeration)
    return {"msg": "If the email exists, a reset link has been sent"}


@router.post("/password-reset/confirm")
def confirm_password_reset(
    payload: PasswordResetConfirm,
    db: Session = Depends(get_db)
):
    """
    Complete password reset with token and new password.
    
    Request Body:
        token: Reset token (from email)
        new_password: New password
    
    Security:
        - Token must be valid and unused
        - Token expires after 30 minutes
        - Password is bcrypt hashed
        - ALL sessions revoked (user must re-login everywhere)
    
    Returns:
        Success: {"msg": "Password reset successful"}
        Error: 400 if token invalid/expired
    """
    # Verify token
    email_token = verify_email_token(
        raw_token=payload.token,
        purpose="password_reset",
        db=db
    )
    
    if not email_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token"
        )
    
    # Get user
    user = db.query(User).filter(User.id == email_token.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update password (bcrypt hashed)
    user.password_hash = hash_password(payload.new_password)
    user.updated_at = datetime.utcnow()
    db.commit()
    
    # SECURITY: Revoke ALL refresh tokens (all devices must re-login)
    tokens_to_revoke = db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.is_revoked == False
    ).all()
    
    for token in tokens_to_revoke:
        token.is_revoked = True
    
    db.commit()
    
    # Audit log
    audit_log = AuditLog(
        actor_id=user.id,
        action="password_reset_completed",
        target=user.email,
        event_metadata={"email": user.email}
    )
    db.add(audit_log)
    db.commit()
    
    return {"msg": "Password reset successful. Please login with your new password."}
