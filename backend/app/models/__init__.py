"""
Core SQLAlchemy models for SentinelIQ.
This module exports all database models for the application.
"""

from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, DateTime, JSON, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
from enum import Enum

# Import Base from dedicated module to ensure single instance across all models
from app.models.base import Base, generate_uuid


class UserStatus(str, Enum):
    """User account status enum."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"
    SYSTEM = "system"  # System/service accounts


class UserVisibility(str, Enum):
    """User profile visibility level."""
    PUBLIC = "public"       # Visible to all authenticated users
    ORGANIZATION = "org"    # Visible only within same organization
    PRIVATE = "private"     # Visible only to self and admins
    GLOBAL = "global"       # System user visible to all based on permissions


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    users = relationship("User", back_populates="organization")


class User(Base):
    """
    User model with enhanced fields for system-wide visibility.
    
    Supports:
    - Standard users (viewer, analyst, admin)
    - System users (visible globally based on permissions)
    - Multi-tenant organization scoping
    - Comprehensive audit metadata
    """
    __tablename__ = "users"
    
    # Core identity
    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    
    # Role and permissions
    role = Column(String, default="viewer")  # admin, analyst, viewer
    
    # Status and visibility (NEW)
    status = Column(String, default=UserStatus.ACTIVE.value)  # active, suspended, pending, system
    visibility = Column(String, default=UserVisibility.PRIVATE.value)  # public, org, private, global
    
    # Risk and security
    risk_score = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    
    # System user flag (NEW)
    is_system_user = Column(Boolean, default=False)
    
    # Metadata (NEW) - stores device info, last login details, etc.
    # Named 'user_metadata' to avoid conflict with SQLAlchemy reserved 'metadata'
    user_metadata = Column(JSON, default=dict)
    
    # Device and session tracking (NEW)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String, nullable=True)
    last_device_info = Column(JSON, default=dict)
    
    # Audit trail (NEW)
    created_by = Column(String, ForeignKey("users.id"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="users")
    
    @property
    def full_name(self) -> str:
        """Return user's full name."""
        return f"{self.first_name} {self.last_name}"
    
    @property
    def is_globally_visible(self) -> bool:
        """Check if user is visible system-wide."""
        return self.is_system_user and self.visibility == UserVisibility.GLOBAL.value
    
    def to_public_dict(self) -> dict:
        """Return public-safe user data (no PII or sensitive fields)."""
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role": self.role,
            "status": self.status,
            "is_system_user": self.is_system_user,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
    
    def to_full_dict(self) -> dict:
        """Return full user data (admin access only)."""
        return {
            "id": self.id,
            "org_id": self.org_id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "role": self.role,
            "status": self.status,
            "visibility": self.visibility,
            "is_system_user": self.is_system_user,
            "risk_score": self.risk_score,
            "is_active": self.is_active,
            "email_verified": self.email_verified,
            "user_metadata": self.user_metadata,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "last_login_ip": self.last_login_ip,
            "last_device_info": self.last_device_info,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=generate_uuid)
    actor_id = Column(String, ForeignKey("users.id"))
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    event_metadata = Column(JSON, default={})
    timestamp = Column(DateTime, default=datetime.utcnow)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    token = Column(String, nullable=False, unique=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_revoked = Column(Boolean, default=False)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


class EmailToken(Base):
    """
    Secure email tokens for email verification and password reset.
    Tokens are hashed before storage (never stored in plaintext).
    Single-use, time-limited, purpose-locked.
    """
    __tablename__ = "email_tokens"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String, nullable=False, unique=True)  # SHA256 hash of token
    purpose = Column(String, nullable=False)  # "email_verification" | "password_reset"
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False)  # Enforce single-use
    created_at = Column(DateTime, default=datetime.utcnow)


# Re-export for convenience
__all__ = [
    "Base",
    "generate_uuid",
    "UserStatus",
    "UserVisibility",
    "Organization",
    "User",
    "AuditLog",
    "RefreshToken",
    "LoginAttempt",
    "EmailToken",
    "UserAccessLog",
]


class UserAccessLog(Base):
    """
    Tracks access to user profiles for audit and compliance.
    
    Records who accessed what user data, when, from where,
    and which fields were accessed.
    """
    __tablename__ = "user_access_logs"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    accessor_id = Column(String, ForeignKey("users.id"), nullable=False)  # Who accessed
    target_user_id = Column(String, ForeignKey("users.id"), nullable=False)  # Whose data
    action = Column(String, nullable=False)  # read, read_metadata, read_audit, etc.
    fields_accessed = Column(JSON, default=list)  # Which fields were returned
    access_level = Column(String, nullable=False)  # full, redacted, public
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    request_path = Column(String, nullable=True)
    success = Column(Boolean, default=True)
    failure_reason = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
