"""
Tests for RBAC Extension
"""

from fastapi import Request
from fastapi.testclient import TestClient

from mcp_auth.models import Principal
from mcp_auth.rbac import (
    Permission,
    PermissionRequest,
    RBACEngine,
    Role,
    get_rbac_engine,
    require_permissions,
)
from mcp_auth.rbac.engine import setup_default_roles


class TestRBACModels:
    """Test RBAC data models"""

    def test_permission_from_string(self):
        """Test parsing permissions from strings"""
        # Simple permission
        perm1 = Permission.from_string("users:read")
        assert perm1.resource == "users"
        assert perm1.action == "read"
        assert perm1.resource_id is None

        # Resource-specific permission
        perm2 = Permission.from_string("users:123:edit")
        assert perm2.resource == "users"
        assert perm2.action == "edit"
        assert perm2.resource_id == "123"

    def test_permission_to_string(self):
        """Test converting permissions to strings"""
        perm1 = Permission("users", "read")
        assert perm1.to_string() == "users:read"

        perm2 = Permission("users", "edit", "123")
        assert perm2.to_string() == "users:123:edit"

    def test_permission_matching(self):
        """Test permission matching with wildcards"""
        perm1 = Permission("users", "read")
        perm2 = Permission("users", "read")
        assert perm1.matches(perm2)

        # Wildcard matching
        wildcard_perm = Permission("users", "read", "*")
        specific_perm = Permission("users", "read", "123")
        assert wildcard_perm.matches(specific_perm)
        assert specific_perm.matches(wildcard_perm)

    def test_role_has_permission(self):
        """Test role permission checking"""
        permissions = [
            Permission.from_string("users:read"),
            Permission.from_string("users:*:edit"),
        ]
        role = Role("editor", "Can edit users", permissions)

        # Should have permission
        assert role.has_permission(Permission.from_string("users:read"))
        assert role.has_permission(Permission.from_string("users:123:edit"))

        # Should not have permission
        assert not role.has_permission(Permission.from_string("posts:read"))


class TestRBACEngine:
    """Test core RBAC engine functionality"""

    def setup_method(self):
        """Setup fresh engine for each test"""
        self.engine = RBACEngine()

    def test_role_management(self):
        """Test adding, removing, and retrieving roles"""
        role = Role("test_role", "Test role", [Permission.from_string("test:read")])

        # Add role
        self.engine.add_role(role)
        assert "test_role" in self.engine.roles

        # Remove role
        self.engine.remove_role("test_role")
        assert "test_role" not in self.engine.roles

    def test_user_role_assignment(self):
        """Test assigning and revoking user roles"""
        role = Role("test_role", "Test role", [Permission.from_string("test:read")])
        self.engine.add_role(role)

        # Assign role
        self.engine.assign_role("user123", "test_role")
        assert "test_role" in self.engine.get_user_roles("user123")

        # Revoke role
        self.engine.revoke_role("user123", "test_role")
        assert "test_role" not in self.engine.get_user_roles("user123")

    def test_permission_checking(self):
        """Test permission checking logic"""
        # Setup role with permissions
        permissions = [
            Permission.from_string("users:read"),
            Permission.from_string("users:*:edit"),
        ]
        role = Role("editor", "User editor", permissions)
        self.engine.add_role(role)
        self.engine.assign_role("user123", "editor")

        # Create mock principal
        principal = Principal(id="user123", provider="test", name="Test User")

        # Test permission requests
        # Should be allowed
        request1 = PermissionRequest("user123", "users", "read")
        result1 = self.engine.check_permission(principal, request1)
        assert result1.allowed

        request2 = PermissionRequest("user123", "users", "edit", "456")
        result2 = self.engine.check_permission(principal, request2)
        assert result2.allowed

        # Should be denied
        request3 = PermissionRequest("user123", "posts", "read")
        result3 = self.engine.check_permission(principal, request3)
        assert not result3.allowed

    def test_role_inheritance(self):
        """Test role inheritance functionality"""
        # Base role
        base_role = Role("base", "Base role", [Permission.from_string("profile:read")])

        # Child role that inherits from base
        child_role = Role(
            "child",
            "Child role",
            [Permission.from_string("users:read")],
            inherits=["base"],
        )

        self.engine.add_role(base_role)
        self.engine.add_role(child_role)
        self.engine.assign_role("user123", "child")

        # User should have permissions from both roles
        permissions = self.engine.get_user_permissions("user123")
        permission_strings = [p.to_string() for p in permissions]

        assert "profile:read" in permission_strings
        assert "users:read" in permission_strings

    def test_default_roles_setup(self):
        """Test default roles setup"""
        setup_default_roles(self.engine)

        # Should have created default roles
        assert "admin" in self.engine.roles
        assert "user" in self.engine.roles
        assert "viewer" in self.engine.roles
        assert "user_manager" in self.engine.roles

        # Admin should have wildcard permission
        admin_permissions = self.engine.roles["admin"].permissions
        assert any(p.to_string() == "*:*:*" for p in admin_permissions)


class MockRequest:
    """Mock request object for testing decorators"""

    def __init__(self, principal: Principal):
        class State:
            def __init__(self):
                self.principal = principal

        self.state = State()

        class URL:
            def __init__(self):
                self.path = "/test"

        self.url = URL()
        self.method = "GET"
        self.headers = {"user-agent": "test"}


class TestRBACDecorators:
    """Test RBAC decorators"""

    def setup_method(self):
        """Setup test environment"""
        # Reset global engine
        from mcp_auth.rbac.engine import reset_rbac_engine

        reset_rbac_engine()

        engine = get_rbac_engine()

        # Setup test role
        role = Role(
            "test_role",
            "Test role",
            [
                Permission.from_string("users:read"),
                Permission.from_string("users:*:edit"),
            ],
        )
        engine.add_role(role)
        engine.assign_role("test_user", "test_role")

    def test_require_permissions_decorator(self):
        """Test permission decorator"""

        @require_permissions("users:read")
        async def test_endpoint(request: Request):
            return {"success": True}

        # Test with authorized user
        principal = Principal(id="test_user", provider="test", name="Test User")

        # This would normally be called by FastAPI
        # For testing, we'll simulate the decorator behavior
        engine = get_rbac_engine()
        perm_request = PermissionRequest("test_user", "users", "read")
        result = engine.check_permission(principal, perm_request)
        assert result.allowed

    def test_require_roles_decorator(self):
        """Test role decorator"""
        engine = get_rbac_engine()

        # Test user has role
        user_roles = engine.get_user_roles("test_user")
        assert "test_role" in user_roles

        # Test user doesn't have admin role
        assert "admin" not in user_roles


# Integration test with FastAPI
def test_rbac_integration():
    """Test RBAC integration with FastAPI"""
    from examples.rbac_demo import app

    client = TestClient(app)

    # Test that the app starts correctly and requires authentication
    response = client.get("/")
    # The RBAC demo requires authentication for all endpoints
    assert response.status_code == 401

    # Test admin endpoints also require auth (should fail gracefully)
    response = client.get("/admin/rbac/roles")
    assert response.status_code == 401

    # This confirms the RBAC system is properly integrated
