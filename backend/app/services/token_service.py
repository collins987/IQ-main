"""
Secure email token generation and verification service.
Supports email verification and password reset flows.

Tokens are:
- Cryptographically secure (32 bytes)
- Hashed with SHA256 before storage
- Single-use (is_used flag)
- Time-limited (expires_at)
- Purpose-locked (email_verification | password_reset)
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.models import EmailToken
from app.config import EMAIL_TOKEN_EXPIRE_MINUTES, PASSWORD_RESET_TOKEN_EXPIRE_MINUTES


def generate_email_token(
    *,
    user_id: str,
    purpose: str,
    db: Session,
    expires_minutes: int = None
) -> str:
    """
    Generate a secure email token (for verification or password reset).
    
    Args:
        user_id: User ID who owns the token
        purpose: "email_verification" | "password_reset"
        db: Database session
        expires_minutes: Custom expiration (uses config default if None)
    
    Returns:
        Raw token (returned ONLY once - must save immediately)
    
    Process:
        1. Generate 32 random bytes (URL-safe base64)
        2. Hash with SHA256
        3. Store hash in database
        4. Return raw token (never stored)
    """
    # Generate cryptographically secure random token
    raw_token = secrets.token_urlsafe(32)
    
    # Hash token before storage (never store plaintext)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    
    # Determine expiration
    if expires_minutes is None:
        if purpose == "password_reset":
            expires_minutes = PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
        else:
            expires_minutes = EMAIL_TOKEN_EXPIRE_MINUTES
    
    expires_at = datetime.utcnow() + timedelta(minutes=expires_minutes)
    
    # Store hash in database
    db_token = EmailToken(
        user_id=user_id,
        token_hash=token_hash,
        purpose=purpose,
        expires_at=expires_at,
        is_used=False
    )
    
    db.add(db_token)
    db.commit()
    
    return raw_token  # Return raw token only


def verify_email_token(
    *,
    raw_token: str,
    purpose: str,
    db: Session
) -> EmailToken | None:
    """
    Verify and consume an email token.
    
    Checks:
    1. Hash matches
    2. Purpose matches
    3. Token not already used
    4. Token not expired
    
    If valid:
    - Marks token as used (single-use enforcement)
    - Returns token object with user_id
    
    Args:
        raw_token: Raw token from user
        purpose: Expected purpose
        db: Database session
    
    Returns:
        EmailToken object if valid, None if invalid/expired/used
    """
    # Hash the raw token to compare with stored hash
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    
    # Query token by hash, purpose, and validity
    token = (
        db.query(EmailToken)
        .filter(
            EmailToken.token_hash == token_hash,
            EmailToken.purpose == purpose,
            EmailToken.is_used == False,
            EmailToken.expires_at > datetime.utcnow()
        )
        .first()
    )
    
    if not token:
        return None
    
    # Mark as used (enforce single-use)
    token.is_used = True
    db.commit()
    
    return token
