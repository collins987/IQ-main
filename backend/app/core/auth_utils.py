# app/core/auth_utils.py
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models import RefreshToken, LoginAttempt, User
from app.config import REFRESH_TOKEN_EXPIRE_DAYS, MAX_SESSIONS_PER_USER, MAX_LOGIN_ATTEMPTS, LOGIN_ATTEMPT_WINDOW_MINUTES
from app.core.security import create_refresh_token, hash_password, verify_password
import uuid

def create_and_store_refresh_token(user_id: str, db: Session) -> str:
    """
    Create a refresh token and store it in the database (HASHED).
    Implements concurrent session limits.
    
    Security:
    - Tokens are hashed before storage (like passwords)
    - Plain token returned to client
    - Only hashed version stored in DB
    """
    # Check existing tokens
    existing_tokens = db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > datetime.utcnow()
    ).all()
    
    # Delete oldest token if at max sessions
    if len(existing_tokens) >= MAX_SESSIONS_PER_USER:
        oldest = min(existing_tokens, key=lambda t: t.created_at)
        db.delete(oldest)
        db.commit()
    
    # Create new refresh token
    refresh_token = create_refresh_token()
    # SECURITY FIX #1: Hash the token before storage
    hashed_token = hash_password(refresh_token)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    db_refresh_token = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=user_id,
        token=hashed_token,  # Store HASHED token
        expires_at=expires_at,
        is_revoked=False
    )
    db.add(db_refresh_token)
    db.commit()
    
    # Return PLAIN token (client will send this back)
    return refresh_token

def check_login_attempts(email: str, ip_address: str | None, db: Session) -> bool:
    """
    Check if user has exceeded max login attempts.
    Returns True if user can attempt login, False if locked out.
    """
    time_window = datetime.utcnow() - timedelta(minutes=LOGIN_ATTEMPT_WINDOW_MINUTES)
    
    failed_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.email == email,
        LoginAttempt.success == False,
        LoginAttempt.timestamp > time_window
    ).count()
    
    return failed_attempts < MAX_LOGIN_ATTEMPTS

def log_login_attempt(email: str, ip_address: str | None, success: bool, db: Session):
    """Log a login attempt for rate limiting and security auditing"""
    attempt = LoginAttempt(
        id=str(uuid.uuid4()),
        email=email,
        ip_address=ip_address,
        success=success,
        timestamp=datetime.utcnow()
    )
    db.add(attempt)
    db.commit()

def revoke_refresh_token(refresh_token: str, db: Session) -> bool:
    """
    Mark a refresh token as revoked (logout).
    Must verify hashed token before revoking.
    """
    # Find all tokens for this user and check hash
    all_tokens = db.query(RefreshToken).filter(
        RefreshToken.is_revoked == False
    ).all()
    
    for db_token in all_tokens:
        # Verify the plain token against hashed version
        if verify_password(refresh_token, db_token.token):
            db_token.is_revoked = True
            db.commit()
            return True
    
    return False

def revoke_all_user_tokens(user_id: str, db: Session):
    """Revoke all refresh tokens for a user (forced logout from all devices)"""
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.is_revoked == False
    ).update({"is_revoked": True})
    db.commit()

def validate_refresh_token(refresh_token: str, db: Session) -> str | None:
    """
    Validate a refresh token and return the user_id if valid.
    Returns None if invalid or expired.
    
    Must verify hashed token.
    """
    # Find all non-revoked, non-expired tokens
    candidate_tokens = db.query(RefreshToken).filter(
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > datetime.utcnow()
    ).all()
    
    # Check hash against candidates
    for db_token in candidate_tokens:
        if verify_password(refresh_token, db_token.token):
            return db_token.user_id
    
    return None
