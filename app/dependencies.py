# app/dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.models import User, AuditLog
from app.core.db import SessionLocal
from app.config import SECRET_KEY, ALGORITHM
import uuid
from datetime import datetime

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    
    # MILESTONE 6: Check account status
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been disabled"
        )
    
    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please verify your email to continue."
        )
    
    return user

# MILESTONE 7: Enhanced role-based access control
def _log_forbidden_access(user_id: str, required_roles: list[str], user_role: str, db: Session):
    """Log forbidden access attempts for security audit trail."""
    audit = AuditLog(
        id=str(uuid.uuid4()),
        actor_id=user_id,
        action="forbidden_access",
        target="route_access",
        event_metadata={
            "required_roles": required_roles,
            "user_role": user_role,
            "reason": "Insufficient role/permissions"
        },
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()

def require_role(required_roles: list[str] | str):
    """
    Dependency to enforce role-based access control.
    
    Args:
        required_roles: Single role (str) or list of allowed roles
        
    Example:
        @router.get("/admin/dashboard")
        def admin_dashboard(user = Depends(require_role(["admin"]))):
            return {"message": "Admin only"}
            
        @router.get("/data")
        def data_route(user = Depends(require_role(["admin", "analyst"]))):
            return {"message": "Admin or analyst"}
    """
    # Normalize to list
    if isinstance(required_roles, str):
        required_roles = [required_roles]
    
    def role_checker(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        if current_user.role not in required_roles:
            # Log forbidden access
            _log_forbidden_access(current_user.id, required_roles, current_user.role, db)
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {', '.join(required_roles)}"
            )
        return current_user
    
    return role_checker

def require_permission(permission: str):
    """
    Dependency to enforce permission-based access control.
    
    Args:
        permission: Permission string (e.g., "admin.dashboard", "analytics.write")
        
    Example:
        @router.get("/admin/data")
        def admin_data(user = Depends(require_permission("admin.dashboard"))):
            return {"message": "Admin permission granted"}
    """
    from app.config import PERMISSION_ROLES
    
    allowed_roles = PERMISSION_ROLES.get(permission, [])
    if not allowed_roles:
        raise ValueError(f"Permission '{permission}' not found in configuration")
    
    def permission_checker(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        if current_user.role not in allowed_roles:
            # Log forbidden access
            _log_forbidden_access(current_user.id, allowed_roles, current_user.role, db)
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions for '{permission}'. Required roles: {', '.join(allowed_roles)}"
            )
        return current_user
    
    return permission_checker
