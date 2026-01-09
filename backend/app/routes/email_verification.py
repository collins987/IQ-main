"""
Email Verification Route (MILESTONE 6 - STEP 3)

Endpoint: POST /auth/verify-email?token=...

Verifies user email with single-use token.
Marks user as email_verified=True.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, AuditLog
from app.services.token_service import verify_email_token
from datetime import datetime

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/verify-email")
def verify_email(
    token: str,
    db: Session = Depends(get_db)
):
    """
    Verify user email with token.
    
    Query Parameters:
        token: Verification token (from email)
    
    Returns:
        Success: {"msg": "Email verified successfully"}
        Error: 400 if token invalid/expired
    """
    # Verify token (single-use, expiration, hash match)
    email_token = verify_email_token(
        raw_token=token,
        purpose="email_verification",
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
    
    # Already verified?
    if user.email_verified:
        return {"msg": "Email already verified"}
    
    # Mark as verified
    user.email_verified = True
    db.commit()
    
    # Audit log
    audit_log = AuditLog(
        actor_id=user.id,
        action="email_verified",
        target=user.email,
        event_metadata={"email": user.email}
    )
    db.add(audit_log)
    db.commit()
    
    return {"msg": "Email verified successfully"}
