"""
Milestone 7: RBAC Usage Examples

Practical examples of implementing role-based access control in your routes.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
import uuid

from app.dependencies import require_role, require_permission, get_current_user, get_db
from app.models import User, AuditLog
from app.config import ROLES

# Example 1: Basic role-based protection (single role)
example1_router = APIRouter(prefix="/example1", tags=["Example 1: Single Role"])

@example1_router.get("/admin-only")
def admin_only_route(current_user: User = Depends(require_role(["admin"]))):
    """
    Only admin users can access this route.
    
    If a non-admin tries:
    - Returns 403 Forbidden
    - Access is logged to audit_logs
    """
    return {
        "message": f"Welcome, {current_user.first_name}",
        "role": current_user.role,
        "can_access": True
    }


# Example 2: Multiple allowed roles
example2_router = APIRouter(prefix="/example2", tags=["Example 2: Multiple Roles"])

@example2_router.get("/data")
def data_route(current_user: User = Depends(require_role(["admin", "analyst"]))):
    """
    Admin and Analyst users can access this route.
    
    Access matrix:
    - Admin: ✅ allowed
    - Analyst: ✅ allowed
    - Viewer: ❌ forbidden (403)
    """
    return {
        "data": "Sensitive analytics data",
        "accessible_by": ["admin", "analyst"],
        "current_user_role": current_user.role
    }


# Example 3: Permission-based access control
example3_router = APIRouter(prefix="/example3", tags=["Example 3: Permission-Based"])

@example3_router.post("/analytics/export")
def export_analytics(current_user: User = Depends(require_permission("analytics.export"))):
    """
    Any role with 'analytics.export' permission can use this.
    
    Internally checks:
    - User role
    - Looks up permission in config
    - Grants access if role has permission
    """
    return {
        "message": "Export started",
        "exported_by": current_user.email,
        "timestamp": datetime.utcnow()
    }


# Example 4: Conditional logic based on role
example4_router = APIRouter(prefix="/example4", tags=["Example 4: Conditional Role Logic"])

@example4_router.get("/profile/{user_id}")
def get_user_profile(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Anyone can view profiles, but what they see depends on their role.
    
    Admin: See full profile + sensitive data
    Analyst: See profile (same org)
    Viewer: See only own profile
    """
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Admin sees everything
    if current_user.role == "admin":
        return {
            "id": target_user.id,
            "name": f"{target_user.first_name} {target_user.last_name}",
            "email": target_user.email,
            "role": target_user.role,
            "is_active": target_user.is_active,
            "risk_score": target_user.risk_score,
            "created_at": target_user.created_at,
        }
    
    # Analysts see profile info (same org)
    if current_user.role == "analyst":
        if current_user.org_id != target_user.org_id:
            raise HTTPException(status_code=403, detail="Can only view profiles in your org")
        return {
            "id": target_user.id,
            "name": f"{target_user.first_name} {target_user.last_name}",
            "role": target_user.role,
            "created_at": target_user.created_at,
        }
    
    # Viewers only see their own profile
    if current_user.role == "viewer":
        if current_user.id != user_id:
            raise HTTPException(status_code=403, detail="Can only view your own profile")
        return {
            "id": target_user.id,
            "name": f"{target_user.first_name} {target_user.last_name}",
            "email": target_user.email,
            "created_at": target_user.created_at,
        }


# Example 5: Admin action with audit logging
example5_router = APIRouter(prefix="/example5", tags=["Example 5: Audit Logging"])

@example5_router.post("/admin/sensitive-action/{target_id}")
def sensitive_admin_action(
    target_id: str,
    current_admin: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """
    Admin-only action that performs sensitive operation and logs it.
    """
    # Perform the action
    action_result = {"status": "success", "target": target_id}
    
    # Log the action for compliance
    audit = AuditLog(
        id=str(uuid.uuid4()),
        actor_id=current_admin.id,
        action="sensitive_admin_action",
        target=target_id,
        event_metadata={
            "action_type": "sensitive_operation",
            "result": action_result["status"],
            "performed_by": current_admin.email
        },
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return {
        "message": "Sensitive action completed",
        "audit_logged": True,
        "audit_id": audit.id
    }


# Example 6: Custom role check with additional validation
example6_router = APIRouter(prefix="/example6", tags=["Example 6: Custom Validation"])

@example6_router.get("/protected-data")
def protected_data(
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """
    Route that requires a role AND custom validation.
    
    This pattern is useful when you need:
    - Role-based access
    - Additional checks (e.g., org membership, feature flags)
    """
    
    # Role already checked by require_role dependency
    # Now perform additional checks
    
    # Example: Check if user is in good standing
    if current_user.risk_score > 80:
        raise HTTPException(
            status_code=403,
            detail="Account flagged for review. Contact support."
        )
    
    # Example: Check organization status
    org = db.query(User).filter(User.id == current_user.id).first().organization
    if not org:
        raise HTTPException(status_code=403, detail="No organization assigned")
    
    return {
        "data": "Protected information",
        "access_granted_because": f"Role '{current_user.role}' + passed validation",
        "user": current_user.email
    }


# Example 7: Hierarchical role access (admin > analyst > viewer)
example7_router = APIRouter(prefix="/example7", tags=["Example 7: Role Hierarchy"])

def check_role_hierarchy(min_role: str):
    """
    Dependency that checks role hierarchy.
    
    Hierarchy: admin (3) > analyst (2) > viewer (1)
    """
    role_levels = {
        "admin": 3,
        "analyst": 2,
        "viewer": 1
    }
    
    if min_role not in role_levels:
        raise ValueError(f"Invalid role: {min_role}")
    
    def hierarchy_checker(current_user: User = Depends(get_current_user)):
        user_level = role_levels.get(current_user.role, 0)
        required_level = role_levels[min_role]
        
        if user_level < required_level:
            raise HTTPException(
                status_code=403,
                detail=f"Requires {min_role} or higher (you are {current_user.role})"
            )
        return current_user
    
    return hierarchy_checker

@example7_router.get("/tier1")
def tier1_access(current_user: User = Depends(check_role_hierarchy("viewer"))):
    """Viewer and above (analyst, admin)"""
    return {"access": "tier1", "role": current_user.role}

@example7_router.get("/tier2")
def tier2_access(current_user: User = Depends(check_role_hierarchy("analyst"))):
    """Analyst and above (admin only)"""
    return {"access": "tier2", "role": current_user.role}

@example7_router.get("/tier3")
def tier3_access(current_user: User = Depends(check_role_hierarchy("admin"))):
    """Admin only"""
    return {"access": "tier3", "role": current_user.role}


# Example 8: Role and organization access check
example8_router = APIRouter(prefix="/example8", tags=["Example 8: Multi-Tenant"])

@example8_router.get("/org-data/{org_id}")
def get_org_data(
    org_id: str,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """
    Multi-tenant safe: Users can only access their own org's data.
    
    Scenario:
    - Admin: Access any organization's data
    - Analyst: Access only own organization's data
    """
    
    if current_user.role == "analyst":
        # Analysts can only access their own org
        if current_user.org_id != org_id:
            raise HTTPException(
                status_code=403,
                detail="Can only access data from your organization"
            )
    
    # Admin can access any org
    
    return {
        "org_id": org_id,
        "accessed_by": current_user.email,
        "accessed_by_role": current_user.role,
        "data": "Organization data"
    }


# Example 9: Display available roles and permissions
example9_router = APIRouter(prefix="/example9", tags=["Example 9: Role Info"])

@example9_router.get("/roles")
def list_roles(current_user: User = Depends(get_current_user)):
    """
    Get list of available roles.
    Useful for frontend to display role options or user info.
    """
    return {
        "roles": [
            {
                "name": role,
                "description": ROLES[role]["description"],
                "permission_count": len(ROLES[role]["permissions"])
            }
            for role in ROLES.keys()
        ],
        "your_role": current_user.role
    }

@example9_router.get("/my-permissions")
def my_permissions(current_user: User = Depends(get_current_user)):
    """Get your current role's permissions."""
    perms = ROLES.get(current_user.role, {}).get("permissions", [])
    return {
        "role": current_user.role,
        "permissions": perms,
        "permission_count": len(perms)
    }


# Example 10: Rate limiting based on role
example10_router = APIRouter(prefix="/example10", tags=["Example 10: Role-Based Rate Limit"])

from fastapi import Query

@example10_router.get("/api-calls")
def api_calls_limit(
    current_user: User = Depends(get_current_user),
    limit: int = Query(None)
):
    """
    Different rate limits based on role.
    
    Admin: 10,000 calls/day
    Analyst: 1,000 calls/day
    Viewer: 100 calls/day
    """
    
    rate_limits = {
        "admin": 10000,
        "analyst": 1000,
        "viewer": 100
    }
    
    user_limit = rate_limits.get(current_user.role, 0)
    
    return {
        "your_role": current_user.role,
        "daily_limit": user_limit,
        "current_usage": 42,  # Mock
        "remaining": user_limit - 42
    }


if __name__ == "__main__":
    print("Milestone 7: RBAC Examples")
    print("\nExample routers (add to main.py):")
    print("- example1_router: Basic single role protection")
    print("- example2_router: Multiple allowed roles")
    print("- example3_router: Permission-based access")
    print("- example4_router: Conditional role logic")
    print("- example5_router: Audit logging")
    print("- example6_router: Custom validation")
    print("- example7_router: Role hierarchy")
    print("- example8_router: Multi-tenant access")
    print("- example9_router: Role information")
    print("- example10_router: Rate limiting by role")
