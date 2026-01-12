"""
Database Seeding - Initialize required system data.

Seeds:
- Default organization
- System user (globally visible)
- Admin user (for initial access - optional, credentials from env)

NOTE: Primary admin authentication now uses environment-based virtual admin.
      Database admin is seeded as fallback and for audit purposes.
"""

import os
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import Organization, User, UserStatus, UserVisibility
from app.core.constants import DEFAULT_ORG_ID, DEFAULT_ORG_NAME
from app.core.security import hash_password

logger = logging.getLogger("sentineliq.seed")

# System user constants
SYSTEM_USER_ID = "00000000-0000-0000-0000-000000000001"
SYSTEM_USER_EMAIL = "system@sentineliq.internal"

# Default DB admin constants (fallback, primary auth uses env-based virtual admin)
# Credentials loaded from environment for security
DEFAULT_ADMIN_ID = "00000000-0000-0000-0000-000000000002"
DEFAULT_ADMIN_EMAIL = os.getenv("SEED_ADMIN_EMAIL", "dbadmin@sentineliq.local")
DEFAULT_ADMIN_PASSWORD = os.getenv("SEED_ADMIN_PASSWORD", "DbAdmin@SentinelIQ#2025")


def seed_default_org(db: Session) -> Organization:
    """Seed the default organization."""
    org = db.query(Organization).filter(
        Organization.id == DEFAULT_ORG_ID
    ).first()

    if not org:
        logger.info(f"Creating default organization: {DEFAULT_ORG_NAME}")
        org = Organization(
            id=DEFAULT_ORG_ID,
            name=DEFAULT_ORG_NAME
        )
        db.add(org)
        db.commit()
        db.refresh(org)
    
    return org


def seed_system_user(db: Session) -> User:
    """
    Seed the system user.
    
    The system user is a special user that:
    - Is visible to all authenticated users (based on permissions)
    - Represents system-level actions in audit logs
    - Has global visibility for compliance tracking
    - Cannot be deleted or modified through normal APIs
    
    This user exists for:
    - Audit trail compliance (system actions have an actor)
    - Platform-wide notifications attribution
    - Security monitoring and compliance requirements
    """
    system_user = db.query(User).filter(
        User.id == SYSTEM_USER_ID
    ).first()
    
    if not system_user:
        logger.info("Creating system user with global visibility")
        system_user = User(
            id=SYSTEM_USER_ID,
            org_id=DEFAULT_ORG_ID,
            first_name="SentinelIQ",
            last_name="System",
            email=SYSTEM_USER_EMAIL,
            password_hash=hash_password("SystemUserNoLogin!@#$%"),  # Not usable for login
            role="admin",
            status=UserStatus.SYSTEM.value,
            visibility=UserVisibility.GLOBAL.value,
            is_system_user=True,
            is_active=True,
            email_verified=True,
            user_metadata={
                "description": "System user for platform operations",
                "purpose": "Audit trail, system actions, compliance",
                "created_by": "system_seed",
                "immutable": True
            },
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(system_user)
        db.commit()
        db.refresh(system_user)
        logger.info(f"System user created: {SYSTEM_USER_ID}")
    else:
        # Ensure system user has correct settings
        updated = False
        if not system_user.is_system_user:
            system_user.is_system_user = True
            updated = True
        if system_user.visibility != UserVisibility.GLOBAL.value:
            system_user.visibility = UserVisibility.GLOBAL.value
            updated = True
        if system_user.status != UserStatus.SYSTEM.value:
            system_user.status = UserStatus.SYSTEM.value
            updated = True
        if updated:
            system_user.updated_at = datetime.utcnow()
            db.commit()
            logger.info("System user settings updated")
    
    return system_user


def seed_default_admin(db: Session) -> User:
    """
    Seed a default admin user for initial platform access.
    
    WARNING: Change the password immediately in production!
    """
    admin_user = db.query(User).filter(
        User.id == DEFAULT_ADMIN_ID
    ).first()
    
    if not admin_user:
        logger.info("Creating default admin user")
        admin_user = User(
            id=DEFAULT_ADMIN_ID,
            org_id=DEFAULT_ORG_ID,
            first_name="Admin",
            last_name="User",
            email=DEFAULT_ADMIN_EMAIL,
            password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
            role="admin",
            status=UserStatus.ACTIVE.value,
            visibility=UserVisibility.ORGANIZATION.value,
            is_system_user=False,
            is_active=True,
            email_verified=True,
            user_metadata={
                "description": "Default admin user",
                "created_by": "system_seed",
                "note": "Change password immediately!"
            },
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        logger.warning(
            f"Default admin created: {DEFAULT_ADMIN_EMAIL} / {DEFAULT_ADMIN_PASSWORD} "
            "- CHANGE PASSWORD IMMEDIATELY!"
        )
    else:
        # Update existing admin to ensure correct credentials
        admin_user.email = DEFAULT_ADMIN_EMAIL
        admin_user.password_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
        admin_user.is_active = True
        admin_user.email_verified = True
        admin_user.role = "admin"
        admin_user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(admin_user)
        logger.info(f"Default admin updated: {DEFAULT_ADMIN_EMAIL}")
    
    return admin_user


def seed_all(db: Session) -> dict:
    """
    Run all seed operations.
    
    Returns dict with created/existing entities.
    """
    logger.info("Starting database seeding...")
    
    org = seed_default_org(db)
    system_user = seed_system_user(db)
    admin_user = seed_default_admin(db)
    
    logger.info("Database seeding complete")
    
    return {
        "organization": org,
        "system_user": system_user,
        "admin_user": admin_user
    }
