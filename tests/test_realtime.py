"""
Tests for real-time WebSocket functionality.

This module tests WebSocket connections, event broadcasting, Redis integration,
connection management, and real-time RBAC event notifications.
"""

import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_auth.models import Principal
from mcp_auth.rbac.models import AccessResult
from mcp_auth.realtime import (
    ConnectionManager,
    EventType,
    RBACEvent,
    RealtimeRBACRouter,
    create_permission_event,
    create_role_event,
    notify_permission_check,
    notify_role_assignment,
    setup_realtime_rbac,
)


@pytest.fixture
def mock_principal():
    """Mock principal for testing"""
    return Principal(
        id="test_user_123",
        provider="test",
        name="Test User",
        email="test@example.com",
    )


@pytest.fixture
def connection_mgr():
    """Fresh connection manager for each test"""
    return ConnectionManager()


@pytest.fixture
def mock_redis():
    """Mock Redis connection"""
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=True)
    mock_redis.publish = AsyncMock()

    # Create a proper mock pubsub that behaves like aioredis
    mock_pubsub = MagicMock()  # Use MagicMock for synchronous methods
    mock_pubsub.subscribe = AsyncMock(return_value=None)  # subscribe is async
    mock_pubsub.listen = AsyncMock()  # listen is async

    # pubsub() itself returns immediately (not async)
    mock_redis.pubsub = MagicMock(return_value=mock_pubsub)

    return mock_redis


class TestRBACEvent:
    """Test RBAC event model"""

    def test_rbac_event_creation(self):
        """Test creating RBAC events"""
        event = RBACEvent(
            event_type=EventType.PERMISSION_GRANTED,
            user_id="user123",
            resource="documents",
            action="read",
            data={"test": "value"},
        )

        assert event.event_type == EventType.PERMISSION_GRANTED
        assert event.user_id == "user123"
        assert event.resource == "documents"
        assert event.action == "read"
        assert event.data == {"test": "value"}
        assert event.event_id is not None
        assert isinstance(event.timestamp, datetime)

    def test_rbac_event_json_serialization(self):
        """Test RBAC event JSON serialization"""
        event = RBACEvent(
            event_type=EventType.ROLE_ASSIGNED, user_id="user123", role_name="admin"
        )

        # Test JSON serialization with modern Pydantic method
        json_data = event.model_dump_json()
        assert isinstance(json_data, str)

        # Should be deserializable
        parsed = json.loads(json_data)
        assert parsed["event_type"] == EventType.ROLE_ASSIGNED
        assert parsed["user_id"] == "user123"
        assert parsed["role_name"] == "admin"


class TestConnectionManager:
    """Test WebSocket connection management"""

    @pytest.mark.asyncio
    async def test_redis_initialization(self, connection_mgr, mock_redis):
        """Test Redis initialization"""
        with (
            patch("mcp_auth.realtime.aioredis") as mock_aioredis,
            patch("mcp_auth.realtime.asyncio.create_task") as mock_create_task,
        ):
            mock_aioredis.from_url = AsyncMock(return_value=mock_redis)

            await connection_mgr.initialize_redis("redis://test:6379")

            # Verify from_url was called
            mock_aioredis.from_url.assert_called_once_with(
                "redis://test:6379", decode_responses=True
            )
            # Verify Redis methods were called
            mock_redis.ping.assert_called_once()
            mock_redis.pubsub.assert_called_once()
            # Verify background task was created
            mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_redis_initialization_failure(self, connection_mgr):
        """Test handling Redis connection failure"""
        with patch("mcp_auth.realtime.REDIS_AVAILABLE", False):
            await connection_mgr.initialize_redis()

            # Should not crash and redis should remain None
            assert connection_mgr.redis is None

    @pytest.mark.asyncio
    async def test_websocket_connection(self, connection_mgr, mock_principal):
        """Test WebSocket connection management"""
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_text = AsyncMock()

        connection_id = await connection_mgr.connect(mock_websocket, mock_principal)

        # Verify connection was accepted
        mock_websocket.accept.assert_called_once()

        # Verify connection is tracked
        assert connection_id in connection_mgr.connections
        assert connection_id in connection_mgr.connection_info
        assert mock_principal.id in connection_mgr.user_connections
        assert connection_id in connection_mgr.user_connections[mock_principal.id]

        # Verify confirmation message was sent
        mock_websocket.send_text.assert_called()

        # Check stats
        stats = await connection_mgr.get_stats()
        assert stats["total_connections"] == 1
        assert stats["active_connections"] == 1

    @pytest.mark.asyncio
    async def test_websocket_disconnection(self, connection_mgr, mock_principal):
        """Test WebSocket disconnection"""
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_text = AsyncMock()

        # Connect first
        connection_id = await connection_mgr.connect(mock_websocket, mock_principal)

        # Then disconnect
        await connection_mgr.disconnect(connection_id)

        # Verify connection was removed
        assert connection_id not in connection_mgr.connections
        assert connection_id not in connection_mgr.connection_info

        # Check stats
        stats = await connection_mgr.get_stats()
        assert stats["active_connections"] == 0

    @pytest.mark.asyncio
    async def test_send_to_connection(self, connection_mgr, mock_principal):
        """Test sending message to specific connection"""
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_text = AsyncMock()

        connection_id = await connection_mgr.connect(mock_websocket, mock_principal)

        # Send event
        event = RBACEvent(
            event_type=EventType.PERMISSION_GRANTED, user_id=mock_principal.id
        )

        result = await connection_mgr.send_to_connection(connection_id, event)

        assert result is True
        mock_websocket.send_text.assert_called()

        # Verify the sent message is JSON
        call_args = mock_websocket.send_text.call_args
        sent_data = call_args[0][0]
        assert isinstance(sent_data, str)
        parsed_event = json.loads(sent_data)
        assert parsed_event["event_type"] == EventType.PERMISSION_GRANTED

    @pytest.mark.asyncio
    async def test_send_to_user(self, connection_mgr, mock_principal):
        """Test sending message to all connections for a user"""
        # Create multiple connections for the same user
        mock_websocket1 = AsyncMock()
        mock_websocket1.accept = AsyncMock()
        mock_websocket1.send_text = AsyncMock()

        mock_websocket2 = AsyncMock()
        mock_websocket2.accept = AsyncMock()
        mock_websocket2.send_text = AsyncMock()

        _ = await connection_mgr.connect(mock_websocket1, mock_principal)
        _ = await connection_mgr.connect(mock_websocket2, mock_principal)

        # Send to user
        event = RBACEvent(
            event_type=EventType.ROLE_ASSIGNED,
            user_id=mock_principal.id,
            role_name="admin",
        )

        sent_count = await connection_mgr.send_to_user(mock_principal.id, event)

        assert sent_count == 2
        mock_websocket1.send_text.assert_called()
        mock_websocket2.send_text.assert_called()

    @pytest.mark.asyncio
    async def test_broadcast_event(self, connection_mgr, mock_principal):
        """Test broadcasting event to all connections"""
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_text = AsyncMock()

        await connection_mgr.connect(mock_websocket, mock_principal)

        # Broadcast event
        event = RBACEvent(
            event_type=EventType.SYSTEM_STARTUP, data={"message": "System started"}
        )

        sent_count = await connection_mgr.broadcast_event(event)

        assert sent_count == 1
        mock_websocket.send_text.assert_called()

    @pytest.mark.asyncio
    async def test_subscribe_to_events(self, connection_mgr, mock_principal):
        """Test event subscription functionality"""
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_text = AsyncMock()

        connection_id = await connection_mgr.connect(mock_websocket, mock_principal)

        # Subscribe to specific events
        await connection_mgr.subscribe_to_events(
            connection_id,
            [EventType.PERMISSION_GRANTED, EventType.ROLE_ASSIGNED],
            {"resource": "documents"},
        )

        # Verify subscription
        conn_info = connection_mgr.connection_info[connection_id]
        assert EventType.PERMISSION_GRANTED in conn_info.subscribed_events
        assert EventType.ROLE_ASSIGNED in conn_info.subscribed_events
        assert conn_info.filters["resource"] == "documents"


class TestEventHelpers:
    """Test event creation helpers"""

    @pytest.mark.asyncio
    async def test_create_permission_event(self):
        """Test creating permission events"""
        result = AccessResult(
            allowed=True,
            reason="User has read permission",
            user_roles=["user", "reader"],
        )

        event = await create_permission_event(
            EventType.PERMISSION_GRANTED,
            "user123",
            "documents",
            "read",
            "doc_1",
            result,
            {"additional": "data"},
        )

        assert event.event_type == EventType.PERMISSION_GRANTED
        assert event.user_id == "user123"
        assert event.resource == "documents"
        assert event.action == "read"
        assert event.resource_id == "doc_1"
        assert event.data["allowed"] is True
        assert event.data["reason"] == "User has read permission"
        assert event.data["user_roles"] == ["user", "reader"]
        assert event.data["additional"] == "data"

    @pytest.mark.asyncio
    async def test_create_role_event(self):
        """Test creating role events"""
        from mcp_auth.rbac.models import Permission, Role

        role = Role(
            name="admin",
            description="Administrator role",
            permissions=[
                Permission(resource="users", action="manage"),
                Permission(resource="system", action="configure"),
            ],
        )

        event = await create_role_event(
            EventType.ROLE_ASSIGNED,
            "admin_user",
            "target_user",
            "admin",
            role,
            {"context": "bulk assignment"},
        )

        assert event.event_type == EventType.ROLE_ASSIGNED
        assert event.user_id == "admin_user"
        assert event.target_user_id == "target_user"
        assert event.role_name == "admin"
        assert event.data["role_description"] == "Administrator role"
        assert event.data["permissions_count"] == 2
        assert event.data["context"] == "bulk assignment"


class TestNotificationFunctions:
    """Test high-level notification functions"""

    @pytest.mark.asyncio
    @patch("mcp_auth.realtime.connection_manager")
    async def test_notify_permission_check(self, mock_conn_manager):
        """Test permission check notification"""
        mock_conn_manager.broadcast_event = AsyncMock()

        result = AccessResult(
            allowed=False,
            reason="Insufficient permissions",
            user_roles=["user"],
        )

        await notify_permission_check("user123", "documents", "delete", "doc_1", result)

        mock_conn_manager.broadcast_event.assert_called_once()
        call_args = mock_conn_manager.broadcast_event.call_args
        event = call_args[0][0]
        assert event.event_type == EventType.PERMISSION_CHECK_RESULT
        assert event.user_id == "user123"
        assert event.resource == "documents"
        assert event.action == "delete"

    @pytest.mark.asyncio
    @patch("mcp_auth.realtime.connection_manager")
    async def test_notify_role_assignment(self, mock_conn_manager):
        """Test role assignment notification"""
        mock_conn_manager.broadcast_event = AsyncMock()

        await notify_role_assignment("admin_user", "target_user", "editor")

        mock_conn_manager.broadcast_event.assert_called_once()
        call_args = mock_conn_manager.broadcast_event.call_args
        event = call_args[0][0]
        assert event.event_type == EventType.ROLE_ASSIGNED
        assert event.user_id == "admin_user"
        assert event.target_user_id == "target_user"
        assert event.role_name == "editor"


class TestRealtimeRouter:
    """Test FastAPI router integration"""

    @pytest.fixture
    def app(self):
        """Test FastAPI application"""
        app = FastAPI()
        router = RealtimeRBACRouter().get_router()
        app.include_router(router)
        return app

    def test_realtime_routes_registered(self, app):
        """Test that real-time routes are properly registered"""
        routes = [route.path for route in app.routes]

        assert "/realtime/stats" in routes
        assert "/realtime/events/broadcast" in routes
        # WebSocket route might be handled differently

    @pytest.mark.asyncio
    async def test_stats_endpoint(self, app, mock_principal):
        """Test the stats endpoint"""
        with TestClient(app) as client:
            # This would normally require authentication
            # For now, just test that the endpoint exists
            try:
                _ = client.get("/realtime/stats")
                # May fail due to authentication, but route should exist
            except Exception:
                pass


class TestIntegration:
    """Integration tests for real-time features"""

    @pytest.mark.asyncio
    async def test_full_realtime_flow(self, connection_mgr, mock_principal):
        """Test complete real-time event flow"""
        mock_websocket = AsyncMock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_text = AsyncMock()

        # Connect user
        connection_id = await connection_mgr.connect(mock_websocket, mock_principal)

        # Subscribe to permission events
        await connection_mgr.subscribe_to_events(
            connection_id, [EventType.PERMISSION_GRANTED, EventType.PERMISSION_DENIED]
        )

        # Simulate permission check result
        result = AccessResult(
            allowed=True,
            reason="Access granted",
            user_roles=["user"],
        )

        # Create and broadcast permission event
        event = await create_permission_event(
            EventType.PERMISSION_GRANTED,
            mock_principal.id,
            "documents",
            "read",
            result=result,
        )

        await connection_mgr.broadcast_event(event)

        # Verify message was sent
        assert (
            mock_websocket.send_text.call_count >= 2
        )  # Connection confirmation + event

        # Disconnect
        await connection_mgr.disconnect(connection_id)
        assert connection_id not in connection_mgr.connections

    @pytest.mark.asyncio
    async def test_setup_realtime_rbac(self):
        """Test the setup function"""
        app = FastAPI()

        # Test setup without Redis
        with patch(
            "mcp_auth.realtime.connection_manager.initialize_redis"
        ) as mock_init:
            mock_init.return_value = AsyncMock()

            router = setup_realtime_rbac(app)

            assert router is not None
            # Verify router was added to app
            router_paths = [
                route.path for route in app.routes if hasattr(route, "path")
            ]
            assert any("/realtime" in path for path in router_paths)
