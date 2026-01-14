"""
Milestone 7: Role-Based Access Control (RBAC) Tests

Tests for role enforcement, permission checking, and audit logging.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import uuid

from app.main import app
from app.core.db import SessionLocal, engine
from app.models import Base, User, AuditLog, Organization
from app.core.security import hash_password
from app.services.token_service import create_access_token
from app.config import ROLES

# Setup test database
@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Create test database tables."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db():
    """Database session for tests."""
    connection = engine.connect()
    transaction = connection.begin()
    session = SessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)

@pytest.fixture
def test_org(db: Session):
    """Create a test organization."""
    org = Organization(id=str(uuid.uuid4()), name="Test Org")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org

@pytest.fixture
def admin_user(db: Session, test_org):
    """Create an admin user."""
    user = User(
        id=str(uuid.uuid4()),
        org_id=test_org.id,
        first_name="Admin",
        last_name="User",
        email="admin@test.com",
        password_hash=hash_password("password123"),
        role="admin",
        is_active=True,
        email_verified=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@pytest.fixture
def analyst_user(db: Session, test_org):
    """Create an analyst user."""
    user = User(
        id=str(uuid.uuid4()),
        org_id=test_org.id,
        first_name="Analyst",
        last_name="User",
        email="analyst@test.com",
        password_hash=hash_password("password123"),
        role="analyst",
        is_active=True,
        email_verified=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@pytest.fixture
def viewer_user(db: Session, test_org):
    """Create a viewer user."""
    user = User(
        id=str(uuid.uuid4()),
        org_id=test_org.id,
        first_name="Viewer",
        last_name="User",
        email="viewer@test.com",
        password_hash=hash_password("password123"),
        role="viewer",
        is_active=True,
        email_verified=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def get_auth_token(user: User) -> str:
    """Generate auth token for a user."""
    return create_access_token(
        data={"sub": user.id},
        expires_delta=timedelta(hours=1)
    )


class TestRBACAdminRoutes:
    """Tests for admin-only routes."""
    
    def test_admin_dashboard_success(self, client: TestClient, admin_user: User):
        """Admin should access admin dashboard."""
        token = get_auth_token(admin_user)
        response = client.get(
            "/admin/dashboard",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert "Admin Dashboard" in response.json()["msg"]
    
    def test_analyst_cannot_access_admin_dashboard(self, client: TestClient, analyst_user: User):
        """Analyst should NOT access admin dashboard."""
        token = get_auth_token(analyst_user)
        response = client.get(
            "/admin/dashboard",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]
    
    def test_viewer_cannot_access_admin_dashboard(self, client: TestClient, viewer_user: User):
        """Viewer should NOT access admin dashboard."""
        token = get_auth_token(viewer_user)
        response = client.get(
            "/admin/dashboard",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]
    
    def test_admin_view_audit_logs(self, client: TestClient, admin_user: User, db: Session):
        """Admin should view audit logs."""
        # Add some test audit logs
        for i in range(3):
            audit = AuditLog(
                id=str(uuid.uuid4()),
                actor_id=admin_user.id,
                action=f"test_action_{i}",
                target="test_target",
                timestamp=datetime.utcnow()
            )
            db.add(audit)
        db.commit()
        
        token = get_auth_token(admin_user)
        response = client.get(
            "/admin/audit-logs",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["count"] >= 3
    
    def test_analyst_cannot_view_audit_logs(self, client: TestClient, analyst_user: User):
        """Analyst should NOT view audit logs."""
        token = get_auth_token(analyst_user)
        response = client.get(
            "/admin/audit-logs",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403


class TestRoleManagement:
    """Tests for role change functionality."""
    
    def test_admin_can_change_user_role(self, client: TestClient, admin_user: User, viewer_user: User, db: Session):
        """Admin should be able to change user role."""
        token = get_auth_token(admin_user)
        response = client.post(
            f"/admin/users/{viewer_user.id}/change-role",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_role": "analyst"}
        )
        assert response.status_code == 200
        assert "analyst" in response.json()["msg"]
        
        # Verify in DB
        db.refresh(viewer_user)
        assert viewer_user.role == "analyst"
    
    def test_invalid_role_rejected(self, client: TestClient, admin_user: User, viewer_user: User):
        """Invalid role should be rejected."""
        token = get_auth_token(admin_user)
        response = client.post(
            f"/admin/users/{viewer_user.id}/change-role",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_role": "superuser"}  # Invalid role
        )
        assert response.status_code == 400
        assert "Invalid role" in response.json()["detail"]
    
    def test_analyst_cannot_change_roles(self, client: TestClient, analyst_user: User, viewer_user: User):
        """Analyst should NOT be able to change roles."""
        token = get_auth_token(analyst_user)
        response = client.post(
            f"/admin/users/{viewer_user.id}/change-role",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_role": "admin"}
        )
        assert response.status_code == 403


class TestUserDisableEnable:
    """Tests for user disable/enable functionality."""
    
    def test_admin_can_disable_user(self, client: TestClient, admin_user: User, viewer_user: User, db: Session):
        """Admin should be able to disable user."""
        token = get_auth_token(admin_user)
        response = client.post(
            f"/admin/users/{viewer_user.id}/disable",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        
        # Verify in DB
        db.refresh(viewer_user)
        assert viewer_user.is_active is False
    
    def test_admin_can_enable_user(self, client: TestClient, admin_user: User, viewer_user: User, db: Session):
        """Admin should be able to enable user."""
        # First disable
        viewer_user.is_active = False
        db.commit()
        
        token = get_auth_token(admin_user)
        response = client.post(
            f"/admin/users/{viewer_user.id}/enable",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        
        # Verify in DB
        db.refresh(viewer_user)
        assert viewer_user.is_active is True
    
    def test_admin_cannot_disable_self(self, client: TestClient, admin_user: User):
        """Admin should NOT be able to disable themselves."""
        token = get_auth_token(admin_user)
        response = client.post(
            f"/admin/users/{admin_user.id}/disable",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400
        assert "Cannot disable yourself" in response.json()["detail"]
    
    def test_analyst_cannot_disable_users(self, client: TestClient, analyst_user: User, viewer_user: User):
        """Analyst should NOT be able to disable users."""
        token = get_auth_token(analyst_user)
        response = client.post(
            f"/admin/users/{viewer_user.id}/disable",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403


class TestAuditLogging:
    """Tests for audit logging on forbidden access."""
    
    def test_forbidden_access_logged(self, client: TestClient, viewer_user: User, db: Session):
        """Forbidden access should be logged in audit_logs."""
        token = get_auth_token(viewer_user)
        
        # Try to access admin-only route
        response = client.get(
            "/admin/dashboard",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
        
        # Check if action was logged
        audit_logs = db.query(AuditLog).filter(
            AuditLog.actor_id == viewer_user.id,
            AuditLog.action == "forbidden_access"
        ).all()
        
        assert len(audit_logs) > 0
        assert audit_logs[0].event_metadata["required_roles"] == ["admin"]
        assert audit_logs[0].event_metadata["user_role"] == "viewer"
    
    def test_role_change_logged(self, client: TestClient, admin_user: User, viewer_user: User, db: Session):
        """Role changes should be logged in audit_logs."""
        # Clear existing logs
        db.query(AuditLog).filter(AuditLog.actor_id == admin_user.id).delete()
        db.commit()
        
        token = get_auth_token(admin_user)
        
        # Change role
        response = client.post(
            f"/admin/users/{viewer_user.id}/change-role",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_role": "analyst"}
        )
        assert response.status_code == 200
        
        # Check audit log
        audit_logs = db.query(AuditLog).filter(
            AuditLog.actor_id == admin_user.id,
            AuditLog.action == "role_changed"
        ).all()
        
        assert len(audit_logs) > 0
        assert audit_logs[0].event_metadata["old_role"] == "viewer"
        assert audit_logs[0].event_metadata["new_role"] == "analyst"


class TestRoleConfiguration:
    """Tests for role and permission configuration."""
    
    def test_all_roles_defined(self):
        """All expected roles should be defined."""
        expected_roles = ["admin", "analyst", "viewer"]
        for role in expected_roles:
            assert role in ROLES
            assert "description" in ROLES[role]
            assert "permissions" in ROLES[role]
    
    def test_admin_has_full_permissions(self):
        """Admin role should have extensive permissions."""
        admin_perms = ROLES["admin"]["permissions"]
        assert len(admin_perms) > 0
        assert "admin.dashboard" in admin_perms
    
    def test_analyst_has_analytics_permissions(self):
        """Analyst role should have analytics permissions."""
        analyst_perms = ROLES["analyst"]["permissions"]
        assert any("analytics" in perm for perm in analyst_perms)
    
    def test_viewer_has_limited_permissions(self):
        """Viewer role should have limited permissions."""
        viewer_perms = ROLES["viewer"]["permissions"]
        assert "profile.read_own" in viewer_perms
        assert "admin.dashboard" not in viewer_perms


class TestUnauthorizedAccess:
    """Tests for unauthenticated/unauthorized access."""
    
    def test_missing_token_rejected(self, client: TestClient):
        """Request without token should be rejected."""
        response = client.get("/admin/dashboard")
        assert response.status_code == 403
        assert "Not authenticated" in response.json()["detail"]
    
    def test_invalid_token_rejected(self, client: TestClient):
        """Request with invalid token should be rejected."""
        response = client.get(
            "/admin/dashboard",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401
