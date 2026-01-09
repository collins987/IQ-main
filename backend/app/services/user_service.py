"""
User Service - Centralized user data access with visibility rules.

This service implements:
- Role-based field visibility
- PII masking based on permissions
- Multi-tenant organization scoping
- Audit logging for all access
- Defensive checks for missing/inactive users

NEVER access User model directly from routes - use this service.
"""

import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.models import (
    User, UserAccessLog, AuditLog, 
    UserStatus, UserVisibility, generate_uuid
)
from app.config import ROLES, PERMISSION_ROLES

logger = logging.getLogger("sentineliq.user_service")


class UserVisibilityError(Exception):
    """Raised when user cannot view target user."""
    pass


class UserNotFoundError(Exception):
    """Raised when user does not exist."""
    pass


class UserService:
    """
    Service for secure user data access with visibility enforcement.
    
    Access Levels:
    - full: All fields including PII (admin only)
    - metadata: Public fields + metadata (admin, analyst on system users)
    - public: Public fields only (everyone on visible users)
    - redacted: Minimal fields with PII masked
    """
    
    # Fields by access level
    PUBLIC_FIELDS = [
        "id", "first_name", "last_name", "role", "status",
        "is_system_user", "created_at", "org_id"
    ]
    
    METADATA_FIELDS = PUBLIC_FIELDS + [
        "visibility", "user_metadata", "last_login_at", "email_verified"
    ]
    
    AUDIT_FIELDS = METADATA_FIELDS + [
        "last_login_ip", "last_device_info", "created_by", "updated_at"
    ]
    
    FULL_FIELDS = AUDIT_FIELDS + [
        "email", "risk_score", "is_active"
    ]
    
    # PII fields that require masking
    PII_FIELDS = ["email", "last_login_ip"]
    
    def __init__(self, db: Session):
        self.db = db
    
    def _has_permission(self, user: User, permission: str) -> bool:
        """Check if user has a specific permission."""
        role_permissions = ROLES.get(user.role, {}).get("permissions", [])
        return permission in role_permissions
    
    def _can_view_user(
        self, 
        accessor: User, 
        target: User
    ) -> tuple[bool, str]:
        """
        Determine if accessor can view target user.
        
        Returns:
            (can_view: bool, access_level: str)
            
        Access level: "full", "metadata", "public", "redacted", "none"
        
        Visibility Rules:
        - Self-access: Always full access
        - Admin: Full access to everyone
        - Analyst: Metadata access to org users, public for others
        - Viewer: Public access to org users, redacted for others
        """
        # Self-access is always allowed (full)
        if accessor.id == target.id:
            return True, "full"
        
        # Admin can view everyone with full access
        if accessor.role == "admin":
            return True, "full"
        
        # System users with global visibility - everyone can see them
        if target.is_system_user and target.visibility == UserVisibility.GLOBAL.value:
            if self._has_permission(accessor, "users.read_metadata"):
                return True, "metadata"
            return True, "public"
        
        # Same organization - check role-based access
        if accessor.org_id and accessor.org_id == target.org_id:
            # Analyst sees org users with metadata
            if accessor.role == "analyst":
                if self._has_permission(accessor, "users.read_metadata"):
                    return True, "metadata"
                return True, "public"
            
            # Viewer sees org users with public/redacted fields
            if accessor.role == "viewer":
                if self._has_permission(accessor, "users.read_own_org"):
                    return True, "public"
                return True, "redacted"
        
        # Public visibility users - anyone can see with appropriate level
        if target.visibility == UserVisibility.PUBLIC.value:
            if self._has_permission(accessor, "users.read_metadata"):
                return True, "metadata"
            if self._has_permission(accessor, "users.read_public"):
                return True, "public"
            return True, "redacted"
        
        # Organization-scoped visibility
        if target.visibility == UserVisibility.ORGANIZATION.value:
            if accessor.org_id and accessor.org_id == target.org_id:
                if self._has_permission(accessor, "users.read_own_org"):
                    return True, "public"
                return True, "redacted"
            # Different org - no access to org-scoped users
            return False, "none"
        
        # Private users - only accessible by admins (handled above) or self
        if target.visibility == UserVisibility.PRIVATE.value:
            return False, "none"
        
        # Default: no access
        return False, "none"
    
    def _mask_pii(self, value: str, field_name: str) -> str:
        """Mask PII field values."""
        if not value:
            return None
        
        if field_name == "email":
            # Show first 2 chars and domain
            parts = value.split("@")
            if len(parts) == 2:
                local, domain = parts
                masked_local = local[:2] + "***" if len(local) > 2 else "***"
                return f"{masked_local}@{domain}"
            return "***@***.***"
        
        if field_name == "last_login_ip":
            # Show first octet only
            parts = value.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.***.***.*"
            return "***.***.***.***"
        
        return "***"
    
    def _apply_field_filter(
        self, 
        user: User, 
        access_level: str,
        mask_pii: bool = True
    ) -> Dict[str, Any]:
        """
        Apply field filtering based on access level.
        
        Args:
            user: Target user
            access_level: full, metadata, public, or redacted
            mask_pii: Whether to mask PII fields (default True for non-full)
        """
        if access_level == "full":
            return user.to_full_dict()
        
        if access_level == "metadata":
            fields = self.METADATA_FIELDS
        elif access_level == "public":
            fields = self.PUBLIC_FIELDS
        else:  # redacted
            fields = ["id", "first_name", "role", "is_system_user"]
        
        result = {}
        for field in fields:
            value = getattr(user, field, None)
            
            # Handle datetime serialization
            if isinstance(value, datetime):
                value = value.isoformat()
            
            # Mask PII if needed
            if mask_pii and field in self.PII_FIELDS and value:
                value = self._mask_pii(value, field)
            
            result[field] = value
        
        return result
    
    def _log_access(
        self,
        accessor: User,
        target_user_id: str,
        action: str,
        access_level: str,
        fields_accessed: List[str],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None,
        success: bool = True,
        failure_reason: Optional[str] = None
    ):
        """Log user data access for audit compliance."""
        try:
            log = UserAccessLog(
                id=generate_uuid(),
                accessor_id=accessor.id,
                target_user_id=target_user_id,
                action=action,
                fields_accessed=fields_accessed,
                access_level=access_level,
                ip_address=ip_address,
                user_agent=user_agent,
                request_path=request_path,
                success=success,
                failure_reason=failure_reason,
                timestamp=datetime.utcnow()
            )
            self.db.add(log)
            self.db.commit()
        except Exception as e:
            logger.error(f"Failed to log user access: {e}")
            # Don't fail the main operation for logging errors
    
    def get_user_by_id(
        self,
        user_id: str,
        accessor: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get user by ID with visibility enforcement.
        
        Args:
            user_id: Target user ID
            accessor: User making the request
            ip_address: Request IP for audit
            user_agent: Request user agent for audit
            request_path: API path for audit
            
        Returns:
            User data dict filtered by access level
            
        Raises:
            UserNotFoundError: User doesn't exist
            UserVisibilityError: Accessor cannot view user
        """
        target = self.db.query(User).filter(User.id == user_id).first()
        
        if not target:
            self._log_access(
                accessor=accessor,
                target_user_id=user_id,
                action="read",
                access_level="none",
                fields_accessed=[],
                ip_address=ip_address,
                user_agent=user_agent,
                request_path=request_path,
                success=False,
                failure_reason="User not found"
            )
            raise UserNotFoundError(f"User {user_id} not found")
        
        can_view, access_level = self._can_view_user(accessor, target)
        
        if not can_view:
            self._log_access(
                accessor=accessor,
                target_user_id=user_id,
                action="read",
                access_level="none",
                fields_accessed=[],
                ip_address=ip_address,
                user_agent=user_agent,
                request_path=request_path,
                success=False,
                failure_reason="Insufficient permissions"
            )
            raise UserVisibilityError(
                f"You don't have permission to view this user"
            )
        
        # Get filtered data
        user_data = self._apply_field_filter(target, access_level)
        fields_accessed = list(user_data.keys())
        
        # Log successful access
        self._log_access(
            accessor=accessor,
            target_user_id=user_id,
            action="read",
            access_level=access_level,
            fields_accessed=fields_accessed,
            ip_address=ip_address,
            user_agent=user_agent,
            request_path=request_path,
            success=True
        )
        
        logger.info(
            f"User {accessor.id} accessed user {user_id} with level {access_level}"
        )
        
        return user_data
    
    def list_users(
        self,
        accessor: User,
        page: int = 1,
        page_size: int = 20,
        include_system_users: bool = True,
        org_filter: Optional[str] = None,
        status_filter: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List users with visibility filtering.
        
        Admins see all users.
        Analysts see org users + system users.
        Viewers see only system users (global visibility).
        """
        query = self.db.query(User)
        
        # Apply visibility filters based on accessor role
        if accessor.role == "admin":
            # Admin sees all users
            pass
        elif accessor.role == "analyst":
            # Analyst sees: own org + system users with global visibility + public users
            query = query.filter(
                or_(
                    User.org_id == accessor.org_id,
                    and_(
                        User.is_system_user == True,
                        User.visibility == UserVisibility.GLOBAL.value
                    ),
                    User.visibility == UserVisibility.PUBLIC.value
                )
            )
        else:
            # Viewer sees: own org users + system users with global visibility
            query = query.filter(
                or_(
                    User.org_id == accessor.org_id,
                    and_(
                        User.is_system_user == True,
                        User.visibility == UserVisibility.GLOBAL.value
                    )
                )
            )
        
        # Apply optional filters
        if org_filter and accessor.role == "admin":
            query = query.filter(User.org_id == org_filter)
        
        if status_filter:
            query = query.filter(User.status == status_filter)
        
        if not include_system_users:
            query = query.filter(User.is_system_user == False)
        
        # Filter out inactive users for non-admins
        if accessor.role != "admin":
            query = query.filter(User.is_active == True)
        
        # Count total
        total = query.count()
        
        # Paginate
        offset = (page - 1) * page_size
        users = query.order_by(User.created_at.desc()).offset(offset).limit(page_size).all()
        
        # Apply field filtering for each user
        results = []
        for user in users:
            can_view, access_level = self._can_view_user(accessor, user)
            if can_view:
                user_data = self._apply_field_filter(user, access_level)
                user_data["_access_level"] = access_level  # Include for debugging
                results.append(user_data)
        
        # Log the list access
        self._log_access(
            accessor=accessor,
            target_user_id="*",  # List operation
            action="list",
            access_level="mixed",
            fields_accessed=["list_operation"],
            ip_address=ip_address,
            user_agent=user_agent,
            request_path=request_path,
            success=True
        )
        
        return {
            "users": results,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": (total + page_size - 1) // page_size
            }
        }
    
    def get_user_activity(
        self,
        user_id: str,
        accessor: User,
        limit: int = 50,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get user activity (audit logs where user is the actor).
        
        Requires: users.read_audit permission or self-access
        """
        # Verify access
        target = self.db.query(User).filter(User.id == user_id).first()
        if not target:
            raise UserNotFoundError(f"User {user_id} not found")
        
        # Check permissions
        is_self = accessor.id == user_id
        has_audit_permission = self._has_permission(accessor, "users.read_audit")
        
        if not is_self and not has_audit_permission:
            self._log_access(
                accessor=accessor,
                target_user_id=user_id,
                action="read_activity",
                access_level="none",
                fields_accessed=[],
                ip_address=ip_address,
                user_agent=user_agent,
                request_path=request_path,
                success=False,
                failure_reason="Missing users.read_audit permission"
            )
            raise UserVisibilityError(
                "You don't have permission to view this user's activity"
            )
        
        # Fetch activity logs
        logs = (
            self.db.query(AuditLog)
            .filter(AuditLog.actor_id == user_id)
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
            .all()
        )
        
        # Log the access
        self._log_access(
            accessor=accessor,
            target_user_id=user_id,
            action="read_activity",
            access_level="full" if has_audit_permission else "limited",
            fields_accessed=["activity_logs"],
            ip_address=ip_address,
            user_agent=user_agent,
            request_path=request_path,
            success=True
        )
        
        return {
            "user_id": user_id,
            "activity": [
                {
                    "id": log.id,
                    "action": log.action,
                    "target": log.target,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "metadata": log.event_metadata if has_audit_permission else None
                }
                for log in logs
            ],
            "count": len(logs)
        }
    
    def get_user_access_logs(
        self,
        user_id: str,
        accessor: User,
        limit: int = 50,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get logs of who accessed this user's profile.
        
        Admin only feature for compliance auditing.
        """
        if accessor.role != "admin":
            raise UserVisibilityError(
                "Only admins can view user access audit logs"
            )
        
        target = self.db.query(User).filter(User.id == user_id).first()
        if not target:
            raise UserNotFoundError(f"User {user_id} not found")
        
        logs = (
            self.db.query(UserAccessLog)
            .filter(UserAccessLog.target_user_id == user_id)
            .order_by(UserAccessLog.timestamp.desc())
            .limit(limit)
            .all()
        )
        
        # Log this access
        self._log_access(
            accessor=accessor,
            target_user_id=user_id,
            action="read_access_audit",
            access_level="full",
            fields_accessed=["access_audit_logs"],
            ip_address=ip_address,
            user_agent=user_agent,
            request_path=request_path,
            success=True
        )
        
        return {
            "user_id": user_id,
            "access_logs": [
                {
                    "id": log.id,
                    "accessor_id": log.accessor_id,
                    "action": log.action,
                    "access_level": log.access_level,
                    "fields_accessed": log.fields_accessed,
                    "ip_address": log.ip_address,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "success": log.success,
                    "failure_reason": log.failure_reason
                }
                for log in logs
            ],
            "count": len(logs)
        }
    
    def get_user_permissions(
        self,
        user_id: str,
        accessor: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get user's permissions based on their role.
        
        Accessible by: self, admins, or users with users.read_metadata
        """
        target = self.db.query(User).filter(User.id == user_id).first()
        if not target:
            raise UserNotFoundError(f"User {user_id} not found")
        
        is_self = accessor.id == user_id
        is_admin = accessor.role == "admin"
        has_metadata_permission = self._has_permission(accessor, "users.read_metadata")
        
        if not is_self and not is_admin and not has_metadata_permission:
            raise UserVisibilityError(
                "You don't have permission to view this user's permissions"
            )
        
        role_config = ROLES.get(target.role, {})
        
        # Log the access
        self._log_access(
            accessor=accessor,
            target_user_id=user_id,
            action="read_permissions",
            access_level="full" if is_admin else "limited",
            fields_accessed=["permissions"],
            ip_address=ip_address,
            user_agent=user_agent,
            request_path=request_path,
            success=True
        )
        
        return {
            "user_id": user_id,
            "role": target.role,
            "role_description": role_config.get("description", ""),
            "permissions": role_config.get("permissions", [])
        }
    
    def get_system_user(self, accessor: User) -> Optional[Dict[str, Any]]:
        """
        Get the designated system user for global visibility.
        
        All authenticated users can access this.
        """
        system_user = (
            self.db.query(User)
            .filter(
                User.is_system_user == True,
                User.visibility == UserVisibility.GLOBAL.value,
                User.is_active == True
            )
            .first()
        )
        
        if not system_user:
            return None
        
        can_view, access_level = self._can_view_user(accessor, system_user)
        if not can_view:
            return None
        
        return self._apply_field_filter(system_user, access_level)


def get_user_service(db: Session) -> UserService:
    """Factory function for dependency injection."""
    return UserService(db)
