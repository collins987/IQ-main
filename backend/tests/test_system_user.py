"""
Tests for System User and User Visibility Features.

Tests:
- Permission enforcement at route level
- Field masking based on access level
- System user global visibility
- Cross-tenant access restrictions
- Audit logging of user access
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime
from sqlalchemy.orm import Session

from app.models import User, Organization, UserStatus, UserVisibility, UserAccessLog
from app.services.user_service import (
    UserService, UserNotFoundError, UserVisibilityError
)
from app.config import ROLES


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_db():
    """Create a mock database session."""
    return MagicMock(spec=Session)


@pytest.fixture
def admin_user():
    """Create an admin user."""
    user = MagicMock(spec=User)
    user.id = "admin-123"
    user.org_id = "org-1"
    user.role = "admin"
    user.first_name = "Admin"
    user.last_name = "User"
    user.email = "admin@test.com"
    user.status = UserStatus.ACTIVE.value
    user.visibility = UserVisibility.ORGANIZATION.value
    user.is_system_user = False
    user.is_active = True
    return user


@pytest.fixture
def analyst_user():
    """Create an analyst user."""
    user = MagicMock(spec=User)
    user.id = "analyst-123"
    user.org_id = "org-1"
    user.role = "analyst"
    user.first_name = "Analyst"
    user.last_name = "User"
    user.email = "analyst@test.com"
    user.status = UserStatus.ACTIVE.value
    user.visibility = UserVisibility.ORGANIZATION.value
    user.is_system_user = False
    user.is_active = True
    return user


@pytest.fixture
def viewer_user():
    """Create a viewer user."""
    user = MagicMock(spec=User)
    user.id = "viewer-123"
    user.org_id = "org-1"
    user.role = "viewer"
    user.first_name = "Viewer"
    user.last_name = "User"
    user.email = "viewer@test.com"
    user.status = UserStatus.ACTIVE.value
    user.visibility = UserVisibility.PRIVATE.value
    user.is_system_user = False
    user.is_active = True
    return user


@pytest.fixture
def system_user():
    """Create the system user."""
    user = MagicMock(spec=User)
    user.id = "00000000-0000-0000-0000-000000000001"
    user.org_id = "org-1"
    user.role = "admin"
    user.first_name = "SentinelIQ"
    user.last_name = "System"
    user.email = "system@sentineliq.internal"
    user.status = UserStatus.SYSTEM.value
    user.visibility = UserVisibility.GLOBAL.value
    user.is_system_user = True
    user.is_active = True
    user.user_metadata = {"description": "System user"}
    user.last_login_at = None
    user.last_login_ip = None
    user.last_device_info = {}
    user.created_by = None
    user.created_at = datetime.utcnow()
    user.updated_at = datetime.utcnow()
    user.risk_score = 0
    user.email_verified = True
    return user


@pytest.fixture
def other_org_user():
    """Create a user from a different organization."""
    user = MagicMock(spec=User)
    user.id = "other-123"
    user.org_id = "org-2"  # Different org
    user.role = "analyst"
    user.first_name = "Other"
    user.last_name = "User"
    user.email = "other@test.com"
    user.status = UserStatus.ACTIVE.value
    user.visibility = UserVisibility.PRIVATE.value
    user.is_system_user = False
    user.is_active = True
    return user


# =============================================================================
# Permission Tests
# =============================================================================

class TestPermissions:
    """Test RBAC permission configuration."""
    
    def test_admin_has_all_user_permissions(self):
        """Admin should have all user-related permissions."""
        admin_perms = ROLES["admin"]["permissions"]
        
        assert "users.read_all" in admin_perms
        assert "users.read_global" in admin_perms
        assert "users.read_metadata" in admin_perms
        assert "users.read_audit" in admin_perms
        assert "users.manage" in admin_perms
    
    def test_analyst_has_limited_user_permissions(self):
        """Analyst should have limited user permissions."""
        analyst_perms = ROLES["analyst"]["permissions"]
        
        assert "users.read_own_org" in analyst_perms
        assert "users.read_global" in analyst_perms
        assert "users.read_public" in analyst_perms
        assert "users.read_all" not in analyst_perms
        assert "users.manage" not in analyst_perms
    
    def test_viewer_has_minimal_user_permissions(self):
        """Viewer should only have global and public read access."""
        viewer_perms = ROLES["viewer"]["permissions"]
        
        assert "users.read_global" in viewer_perms
        assert "users.read_public" in viewer_perms
        assert "users.read_all" not in viewer_perms
        assert "users.read_own_org" not in viewer_perms


# =============================================================================
# Visibility Tests
# =============================================================================

class TestUserVisibility:
    """Test user visibility rules."""
    
    def test_admin_can_view_any_user(self, mock_db, admin_user, viewer_user):
        """Admin should be able to view any user with full access."""
        service = UserService(mock_db)
        
        can_view, access_level = service._can_view_user(admin_user, viewer_user)
        
        assert can_view is True
        assert access_level == "full"
    
    def test_user_can_view_self(self, mock_db, viewer_user):
        """User should be able to view themselves with full access."""
        service = UserService(mock_db)
        
        can_view, access_level = service._can_view_user(viewer_user, viewer_user)
        
        assert can_view is True
        assert access_level == "full"
    
    def test_viewer_can_view_system_user(self, mock_db, viewer_user, system_user):
        """Viewer should be able to view system user (public fields)."""
        service = UserService(mock_db)
        
        can_view, access_level = service._can_view_user(viewer_user, system_user)
        
        assert can_view is True
        assert access_level == "public"
    
    def test_analyst_can_view_system_user_metadata(self, mock_db, analyst_user, system_user):
        """Analyst should see metadata for system user."""
        service = UserService(mock_db)
        
        can_view, access_level = service._can_view_user(analyst_user, system_user)
        
        assert can_view is True
        # Analyst has users.read_metadata via users.read_own_org
        assert access_level in ["metadata", "public"]
    
    def test_viewer_cannot_view_private_user(self, mock_db, viewer_user, other_org_user):
        """Viewer should not be able to view private users in other orgs."""
        service = UserService(mock_db)
        
        can_view, access_level = service._can_view_user(viewer_user, other_org_user)
        
        assert can_view is False
        assert access_level == "none"
    
    def test_cross_tenant_isolation(self, mock_db, analyst_user, other_org_user):
        """Analyst should not see users from other organizations."""
        service = UserService(mock_db)
        
        # other_org_user is in org-2, analyst is in org-1
        can_view, access_level = service._can_view_user(analyst_user, other_org_user)
        
        # Private user in different org = no access
        assert can_view is False


# =============================================================================
# Field Masking Tests
# =============================================================================

class TestFieldMasking:
    """Test PII masking functionality."""
    
    def test_email_masking(self, mock_db):
        """Email should be properly masked."""
        service = UserService(mock_db)
        
        masked = service._mask_pii("john.doe@example.com", "email")
        
        assert masked.startswith("jo")
        assert "***" in masked
        assert "@example.com" in masked
    
    def test_ip_masking(self, mock_db):
        """IP address should be properly masked."""
        service = UserService(mock_db)
        
        masked = service._mask_pii("192.168.1.100", "last_login_ip")
        
        assert masked.startswith("192.")
        assert "***.***.*" in masked
    
    def test_public_fields_no_email(self, mock_db, system_user):
        """Public access level should not include email."""
        service = UserService(mock_db)
        
        # Mock the to_full_dict to return actual data
        system_user.to_full_dict = lambda: {
            "id": system_user.id,
            "first_name": system_user.first_name,
            "last_name": system_user.last_name,
            "email": system_user.email,
            "role": system_user.role,
            "status": system_user.status,
            "visibility": system_user.visibility,
            "is_system_user": system_user.is_system_user,
            "created_at": system_user.created_at,
        }
        
        result = service._apply_field_filter(system_user, "public")
        
        assert "email" not in result
        assert "id" in result
        assert "first_name" in result


# =============================================================================
# Audit Logging Tests
# =============================================================================

class TestAuditLogging:
    """Test access audit logging."""
    
    def test_successful_access_logged(self, mock_db, admin_user):
        """Successful user access should be logged."""
        service = UserService(mock_db)
        
        service._log_access(
            accessor=admin_user,
            target_user_id="target-123",
            action="read",
            access_level="full",
            fields_accessed=["id", "email", "role"],
            ip_address="192.168.1.1",
            success=True
        )
        
        # Verify add was called
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
        
        # Check the logged object
        logged_obj = mock_db.add.call_args[0][0]
        assert logged_obj.accessor_id == admin_user.id
        assert logged_obj.target_user_id == "target-123"
        assert logged_obj.action == "read"
        assert logged_obj.success is True
    
    def test_failed_access_logged(self, mock_db, viewer_user):
        """Failed access attempts should be logged."""
        service = UserService(mock_db)
        
        service._log_access(
            accessor=viewer_user,
            target_user_id="protected-123",
            action="read",
            access_level="none",
            fields_accessed=[],
            success=False,
            failure_reason="Insufficient permissions"
        )
        
        logged_obj = mock_db.add.call_args[0][0]
        assert logged_obj.success is False
        assert logged_obj.failure_reason == "Insufficient permissions"


# =============================================================================
# User Service Tests
# =============================================================================

class TestUserService:
    """Test UserService methods."""
    
    def test_get_user_not_found(self, mock_db, admin_user):
        """Should raise UserNotFoundError for non-existent user."""
        mock_db.query.return_value.filter.return_value.first.return_value = None
        
        service = UserService(mock_db)
        
        with pytest.raises(UserNotFoundError):
            service.get_user_by_id("nonexistent-id", admin_user)
    
    def test_get_user_permission_denied(self, mock_db, viewer_user, other_org_user):
        """Should raise UserVisibilityError when access denied."""
        mock_db.query.return_value.filter.return_value.first.return_value = other_org_user
        
        service = UserService(mock_db)
        
        with pytest.raises(UserVisibilityError):
            service.get_user_by_id(other_org_user.id, viewer_user)
    
    def test_list_users_admin_sees_all(self, mock_db, admin_user):
        """Admin should see all users in list."""
        service = UserService(mock_db)
        
        # Mock the query chain
        mock_query = MagicMock()
        mock_query.count.return_value = 10
        mock_query.order_by.return_value.offset.return_value.limit.return_value.all.return_value = []
        mock_db.query.return_value = mock_query
        
        result = service.list_users(admin_user, page=1, page_size=20)
        
        # Admin query should not be filtered by visibility
        assert "pagination" in result
        assert result["pagination"]["total"] == 10
    
    def test_get_system_user(self, mock_db, viewer_user, system_user):
        """Should return system user for any authenticated user."""
        mock_db.query.return_value.filter.return_value.first.return_value = system_user
        
        service = UserService(mock_db)
        result = service.get_system_user(viewer_user)
        
        assert result is not None
        assert result["is_system_user"] is True


# =============================================================================
# Integration-style Tests (requires test database)
# =============================================================================

class TestSystemUserEndpoints:
    """Test system user API endpoints (integration tests)."""
    
    @pytest.mark.skip(reason="Requires running FastAPI test client")
    def test_get_system_user_endpoint(self, client, auth_headers_viewer):
        """GET /users/system should return system user for any auth user."""
        response = client.get("/users/system", headers=auth_headers_viewer)
        
        assert response.status_code == 200
        data = response.json()
        assert data["system_user"]["is_system_user"] is True
    
    @pytest.mark.skip(reason="Requires running FastAPI test client")
    def test_list_users_respects_visibility(self, client, auth_headers_viewer):
        """GET /users should only return visible users for viewer."""
        response = client.get("/users/", headers=auth_headers_viewer)
        
        assert response.status_code == 200
        data = response.json()
        # Viewers should only see system users with global visibility
        for user in data["users"]:
            assert user["is_system_user"] is True
    
    @pytest.mark.skip(reason="Requires running FastAPI test client")
    def test_user_audit_admin_only(self, client, auth_headers_viewer, auth_headers_admin):
        """GET /users/{id}/audit should only work for admin."""
        user_id = "some-user-id"
        
        # Viewer should get 403
        response = client.get(f"/users/{user_id}/audit", headers=auth_headers_viewer)
        assert response.status_code == 403
        
        # Admin should succeed
        response = client.get(f"/users/{user_id}/audit", headers=auth_headers_admin)
        assert response.status_code in [200, 404]  # 404 if user doesn't exist


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
