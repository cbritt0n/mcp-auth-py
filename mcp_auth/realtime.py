"""
Real-time Permission Updates - WebSocket support for live RBAC events.

This module provides WebSocket endpoints and event broadcasting for real-time
permission updates, role changes, and security notifications. It includes
connection management, event filtering, and client-side JavaScript integration.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Optional

try:
    import redis.asyncio as aioredis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None

from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field

from .models import Principal

# Try to import RBAC dependencies if available
try:
    from .rbac.decorators import get_current_principal
    from .rbac.engine import get_rbac_engine
    from .rbac.models import AccessResult, Role

    _rbac_available = True
except ImportError:
    _rbac_available = False
    get_current_principal = None
    get_rbac_engine = None
    AccessResult = None
    Role = None

logger = logging.getLogger(__name__)


# Helper function for conditional RBAC support
def _get_principal_dependency():
    """Get principal dependency function, with or without RBAC"""
    if _rbac_available and get_current_principal:
        return get_current_principal
    else:
        # Fallback dependency function
        def get_principal_from_request(request: Request) -> Principal:
            return getattr(request.state, "principal", None)

        return get_principal_from_request


# Real-time event types
class EventType:
    """WebSocket event types for RBAC updates"""

    # Permission events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    PERMISSION_REVOKED = "permission_revoked"
    PERMISSION_CHECK_RESULT = "permission_check_result"

    # Role events
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    ROLE_CREATED = "role_created"
    ROLE_UPDATED = "role_updated"
    ROLE_DELETED = "role_deleted"

    # System events
    SYSTEM_STARTUP = "system_startup"
    POLICY_UPDATED = "policy_updated"
    CACHE_INVALIDATED = "cache_invalidated"
    SECURITY_ALERT = "security_alert"

    # Connection events
    USER_CONNECTED = "user_connected"
    USER_DISCONNECTED = "user_disconnected"


class RBACEvent(BaseModel):
    """Model for real-time RBAC events"""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    target_user_id: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    resource_id: Optional[str] = None
    role_name: Optional[str] = None
    permission: Optional[dict[str, Any]] = None
    data: Optional[dict[str, Any]] = None
    security_level: str = Field(default="info")  # info, warning, critical

    model_config = ConfigDict(
        # Use model_dump() instead of deprecated json() method
    )


class ConnectionInfo(BaseModel):
    """Information about a WebSocket connection"""

    connection_id: str
    user_id: str
    principal: Principal
    connected_at: datetime
    last_activity: datetime
    subscribed_events: set[str] = Field(default_factory=set)
    filters: dict[str, Any] = Field(default_factory=dict)


class ConnectionManager:
    """Manages WebSocket connections and event broadcasting"""

    def __init__(self):
        self.connections: dict[str, WebSocket] = {}
        self.connection_info: dict[str, ConnectionInfo] = {}
        self.user_connections: dict[str, set[str]] = {}  # user_id -> connection_ids
        self.redis: Optional[Any] = None  # aioredis.Redis when available
        self._lock = asyncio.Lock()
        self._stats = {
            "total_connections": 0,
            "active_connections": 0,
            "events_sent": 0,
            "events_received": 0,
        }

    async def initialize_redis(self, redis_url: str = "redis://localhost:6379"):
        """Initialize Redis connection for distributed event broadcasting"""
        if not REDIS_AVAILABLE:
            logger.warning(
                "aioredis not available. Real-time events will be local only."
            )
            return

        try:
            self.redis = aioredis.from_url(redis_url, decode_responses=True)
            await self.redis.ping()

            # Subscribe to RBAC events channel
            pubsub = self.redis.pubsub()
            await pubsub.subscribe("rbac:events")

            # Start Redis event listener in background
            asyncio.create_task(self._redis_event_listener(pubsub))

            logger.info("Redis connection initialized for real-time events")
        except Exception as e:
            logger.warning(
                f"Failed to initialize Redis: {e}. Running without distributed events."
            )
            self.redis = None

    async def _redis_event_listener(self, pubsub):
        """Listen for events from Redis and broadcast to connected clients"""
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        event_data = json.loads(message["data"])
                        event = RBACEvent(**event_data)
                        await self.broadcast_event(event, exclude_self=True)
                        self._stats["events_received"] += 1
                    except Exception as e:
                        logger.error(f"Error processing Redis event: {e}")
        except Exception as e:
            logger.error(f"Redis event listener error: {e}")

    async def connect(self, websocket: WebSocket, principal: Principal) -> str:
        """Accept a new WebSocket connection"""
        await websocket.accept()

        connection_id = str(uuid.uuid4())
        now = datetime.utcnow()

        async with self._lock:
            self.connections[connection_id] = websocket
            self.connection_info[connection_id] = ConnectionInfo(
                connection_id=connection_id,
                user_id=principal.id,
                principal=principal,
                connected_at=now,
                last_activity=now,
            )

            # Track user connections
            if principal.id not in self.user_connections:
                self.user_connections[principal.id] = set()
            self.user_connections[principal.id].add(connection_id)

            self._stats["total_connections"] += 1
            self._stats["active_connections"] += 1

        # Send connection confirmation
        await self.send_to_connection(
            connection_id,
            RBACEvent(
                event_type=EventType.USER_CONNECTED,
                user_id=principal.id,
                data={
                    "connection_id": connection_id,
                    "message": "Connected to RBAC real-time updates",
                    "server_time": now.isoformat(),
                },
            ),
        )

        # Broadcast user connection to other authorized users (admins)
        await self.broadcast_event(
            RBACEvent(
                event_type=EventType.USER_CONNECTED,
                user_id=principal.id,
                data={"user_name": principal.name, "provider": principal.provider},
            ),
            filters={"admin_only": True},
        )

        logger.info(
            f"WebSocket connected: {connection_id} for user {principal.id} ({principal.name})"
        )
        return connection_id

    async def disconnect(self, connection_id: str):
        """Disconnect a WebSocket connection"""
        async with self._lock:
            if connection_id not in self.connections:
                return

            info = self.connection_info.get(connection_id)
            if info:
                user_id = info.user_id

                # Remove from user connections
                if user_id in self.user_connections:
                    self.user_connections[user_id].discard(connection_id)
                    if not self.user_connections[user_id]:
                        del self.user_connections[user_id]

                # Broadcast user disconnection
                await self.broadcast_event(
                    RBACEvent(
                        event_type=EventType.USER_DISCONNECTED,
                        user_id=user_id,
                        data={
                            "user_name": info.principal.name,
                            "connection_duration": (
                                datetime.utcnow() - info.connected_at
                            ).total_seconds(),
                        },
                    ),
                    filters={"admin_only": True},
                )

            # Clean up connection data
            self.connections.pop(connection_id, None)
            self.connection_info.pop(connection_id, None)
            self._stats["active_connections"] = max(
                0, self._stats["active_connections"] - 1
            )

        logger.info(f"WebSocket disconnected: {connection_id}")

    async def send_to_connection(self, connection_id: str, event: RBACEvent):
        """Send an event to a specific connection"""
        if connection_id not in self.connections:
            return False

        websocket = self.connections[connection_id]
        try:
            await websocket.send_text(event.model_dump_json())

            # Update last activity
            if connection_id in self.connection_info:
                self.connection_info[connection_id].last_activity = datetime.utcnow()

            self._stats["events_sent"] += 1
            return True
        except Exception as e:
            logger.warning(f"Failed to send to connection {connection_id}: {e}")
            await self.disconnect(connection_id)
            return False

    async def send_to_user(self, user_id: str, event: RBACEvent) -> int:
        """Send an event to all connections for a specific user"""
        sent_count = 0
        if user_id in self.user_connections:
            for connection_id in self.user_connections[user_id].copy():
                if await self.send_to_connection(connection_id, event):
                    sent_count += 1
        return sent_count

    async def broadcast_event(
        self,
        event: RBACEvent,
        filters: Optional[dict[str, Any]] = None,
        exclude_self: bool = False,
    ):
        """Broadcast an event to all matching connections"""
        sent_count = 0

        # Publish to Redis for distributed broadcasting
        if self.redis and not exclude_self:
            try:
                await self.redis.publish("rbac:events", event.model_dump_json())
            except Exception as e:
                logger.warning(f"Failed to publish to Redis: {e}")

        for connection_id, info in self.connection_info.items():
            # Apply filters
            if filters:
                if not await self._should_send_to_connection(info, event, filters):
                    continue

            # Skip self if requested
            if exclude_self and event.user_id == info.user_id:
                continue

            if await self.send_to_connection(connection_id, event):
                sent_count += 1

        logger.debug(
            f"Broadcasted event {event.event_type} to {sent_count} connections"
        )
        return sent_count

    async def _should_send_to_connection(
        self, connection_info: ConnectionInfo, event: RBACEvent, filters: dict[str, Any]
    ) -> bool:
        """Check if an event should be sent to a connection based on filters"""

        # Admin-only events
        if filters.get("admin_only"):
            if _rbac_available and get_rbac_engine:
                rbac_engine = get_rbac_engine()
                user_roles = rbac_engine.get_user_roles(connection_info.user_id)
                if "admin" not in user_roles and "rbac_admin" not in user_roles:
                    return False
            else:
                # Without RBAC, check principal roles
                if (
                    not hasattr(connection_info, "principal")
                    or not connection_info.principal.roles
                ):
                    return False
                if (
                    "admin" not in connection_info.principal.roles
                    and "rbac_admin" not in connection_info.principal.roles
                ):
                    return False

        # User-specific events
        if filters.get("target_user_id"):
            if connection_info.user_id != filters["target_user_id"]:
                return False

        # Resource-based filtering
        if filters.get("resource"):
            if _rbac_available and get_rbac_engine:
                rbac_engine = get_rbac_engine()
                has_access = rbac_engine.has_permission(
                    connection_info.user_id,
                    filters["resource"],
                    filters.get("action", "read"),
                )
                if not has_access:
                    return False
            else:
                # Without RBAC, allow all resource access for now
                pass

        # Event type filtering (if connection has subscriptions)
        if connection_info.subscribed_events:
            if event.event_type not in connection_info.subscribed_events:
                return False

        return True

    async def subscribe_to_events(
        self,
        connection_id: str,
        event_types: list[str],
        filters: Optional[dict[str, Any]] = None,
    ):
        """Subscribe a connection to specific event types"""
        if connection_id in self.connection_info:
            info = self.connection_info[connection_id]
            info.subscribed_events.update(event_types)
            if filters:
                info.filters.update(filters)

    async def get_stats(self) -> dict[str, Any]:
        """Get connection and event statistics"""
        return {
            **self._stats,
            "connections_by_user": {
                user_id: len(connection_ids)
                for user_id, connection_ids in self.user_connections.items()
            },
            "timestamp": datetime.utcnow().isoformat(),
        }


# Global connection manager
connection_manager = ConnectionManager()


class RealtimeRBACRouter:
    """FastAPI router for real-time RBAC features"""

    def __init__(self):
        self.router = APIRouter(prefix="/realtime", tags=["Real-time RBAC"])
        self._setup_routes()

    def _setup_routes(self):
        """Setup WebSocket and HTTP routes"""

        @self.router.websocket("/ws")
        async def websocket_endpoint(
            websocket: WebSocket,
            token: Optional[str] = None,
        ):
            """WebSocket endpoint for real-time RBAC updates with proper authentication"""
            try:
                # Authenticate user with proper token validation
                if not token:
                    await websocket.close(code=4001, reason="Authentication required")
                    return

                # Validate JWT token properly
                try:
                    from fastapi.security import HTTPAuthorizationCredentials

                    from .security import TokenValidator

                    # Create mock credentials object for token validation
                    credentials = HTTPAuthorizationCredentials(
                        scheme="Bearer", credentials=token
                    )

                    token_validator = TokenValidator()
                    principal = await token_validator.validate_token(credentials)

                except Exception as e:
                    logger.warning("WebSocket authentication failed: %s", str(e))
                    await websocket.close(code=4001, reason="Invalid token")
                    return

                connection_id = await connection_manager.connect(websocket, principal)

                try:
                    while True:
                        # Handle incoming messages from client
                        data = await websocket.receive_text()
                        try:
                            message = json.loads(data)
                            await self._handle_client_message(connection_id, message)
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON from {connection_id}: {data}")

                except WebSocketDisconnect:
                    pass
                finally:
                    await connection_manager.disconnect(connection_id)

            except Exception as e:
                logger.error(f"WebSocket error: {e}", exc_info=True)
                try:
                    await websocket.close(code=4000, reason="Internal server error")
                except Exception:
                    pass

        @self.router.get("/stats")
        async def get_realtime_stats():
            """Get real-time connection statistics"""
            return await connection_manager.get_stats()

        @self.router.post("/events/broadcast")
        async def broadcast_custom_event(
            event: RBACEvent,
            filters: Optional[dict[str, Any]] = None,
            principal: Principal = Depends(_get_principal_dependency()),
        ):
            """Broadcast a custom RBAC event (admin only) with proper authorization"""

            # Check admin authorization
            from .security import AdminAuthorizer

            admin_auth = AdminAuthorizer()
            await admin_auth.require_admin_access(
                principal, "events.broadcast", "realtime"
            )

            logger.info("Admin user %s broadcasting custom event", principal.id)
            sent_count = await connection_manager.broadcast_event(event, filters)
            return {
                "message": f"Event broadcasted to {sent_count} connections",
                "event_id": event.event_id,
            }

    async def _handle_client_message(self, connection_id: str, message: dict[str, Any]):
        """Handle messages from WebSocket clients"""
        msg_type = message.get("type")

        if msg_type == "subscribe":
            # Subscribe to specific event types
            event_types = message.get("events", [])
            filters = message.get("filters", {})
            await connection_manager.subscribe_to_events(
                connection_id, event_types, filters
            )

            response = RBACEvent(
                event_type="subscription_confirmed",
                data={"subscribed_events": event_types, "filters": filters},
            )
            await connection_manager.send_to_connection(connection_id, response)

        elif msg_type == "ping":
            # Respond to ping with pong
            response = RBACEvent(
                event_type="pong",
                data={"timestamp": datetime.utcnow().isoformat()},
            )
            await connection_manager.send_to_connection(connection_id, response)

    def get_router(self) -> APIRouter:
        """Get the configured FastAPI router"""
        return self.router


# Event creation helpers
async def create_permission_event(
    event_type: str,
    user_id: str,
    resource: str,
    action: str,
    resource_id: Optional[str] = None,
    result: Optional[Any] = None,  # AccessResult when RBAC is available
    additional_data: Optional[dict[str, Any]] = None,
) -> RBACEvent:
    """Create a permission-related event"""
    data = additional_data or {}

    if result:
        data.update(
            {
                "allowed": result.allowed,
                "reason": result.reason,
                "user_roles": result.user_roles,
            }
        )

    return RBACEvent(
        event_type=event_type,
        user_id=user_id,
        resource=resource,
        action=action,
        resource_id=resource_id,
        data=data,
    )


async def create_role_event(
    event_type: str,
    user_id: str,
    target_user_id: str,
    role_name: str,
    role_data: Optional[Any] = None,  # Role when RBAC is available
    additional_data: Optional[dict[str, Any]] = None,
) -> RBACEvent:
    """Create a role-related event"""
    data = additional_data or {}

    if role_data:
        data.update(
            {
                "role_description": role_data.description,
                "permissions_count": len(role_data.permissions),
                "inherits_from": role_data.inherits,
            }
        )

    return RBACEvent(
        event_type=event_type,
        user_id=user_id,
        target_user_id=target_user_id,
        role_name=role_name,
        data=data,
    )


# Integration with existing RBAC engine
async def notify_permission_check(
    user_id: str,
    resource: str,
    action: str,
    resource_id: Optional[str],
    result: Any,  # AccessResult when RBAC is available
):
    """Notify about a permission check result"""
    event = await create_permission_event(
        EventType.PERMISSION_CHECK_RESULT,
        user_id,
        resource,
        action,
        resource_id,
        result,
    )

    # Only broadcast to the user and admins
    await connection_manager.broadcast_event(
        event,
        filters={"target_user_id": user_id, "admin_notifications": True},
    )


async def notify_role_assignment(
    admin_user_id: str,
    target_user_id: str,
    role_name: str,
    role_data: Optional[Any] = None,  # Role when RBAC is available
):
    """Notify about a role assignment"""
    event = await create_role_event(
        EventType.ROLE_ASSIGNED,
        admin_user_id,
        target_user_id,
        role_name,
        role_data,
    )

    await connection_manager.broadcast_event(event)


async def notify_role_revocation(
    admin_user_id: str,
    target_user_id: str,
    role_name: str,
):
    """Notify about a role revocation"""
    event = await create_role_event(
        EventType.ROLE_REVOKED,
        admin_user_id,
        target_user_id,
        role_name,
    )

    await connection_manager.broadcast_event(event)


# Setup function
def setup_realtime_rbac(app, redis_url: str = "redis://localhost:6379") -> APIRouter:
    """
    Setup real-time RBAC features on a FastAPI app

    Args:
        app: FastAPI application instance
        redis_url: Redis connection URL for distributed events

    Returns:
        Configured router instance
    """
    try:
        # Initialize connection manager with Redis
        asyncio.create_task(connection_manager.initialize_redis(redis_url))

        # Create and include router
        realtime_router = RealtimeRBACRouter()
        router = realtime_router.get_router()
        app.include_router(router)

        logger.info("Real-time RBAC features setup successfully")
        return router

    except Exception as e:
        logger.error(f"Failed to setup real-time RBAC features: {e}", exc_info=True)
        raise


# Alias for backward compatibility and cleaner API
setup_realtime_system = setup_realtime_rbac
