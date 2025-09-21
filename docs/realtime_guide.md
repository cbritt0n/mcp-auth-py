# Real-Time WebSocket Features Guide

## Overview

The MCP-Auth system provides real-time WebSocket support for immediate notification of RBAC events across all connected clients. This enables live updates for permission changes, role assignments, and security events.

## Key Features

- **Real-time Event Broadcasting**: Instant notifications for RBAC events
- **WebSocket Connection Management**: Automatic connection lifecycle handling
- **Redis-based Distribution**: Events distributed across multiple server instances
- **Authentication Integration**: Secure WebSocket connections with user authentication
- **Event Filtering**: Clients receive only relevant events based on permissions
- **Graceful Degradation**: System continues working if Redis is unavailable

## Architecture

```
Client WebSocket ←→ FastAPI WebSocket Handler ←→ ConnectionManager ←→ Redis Pub/Sub ←→ Other Instances
```

## Setup and Configuration

### 1. Install Dependencies

```bash
pip install websockets>=11.0.0 redis>=4.5.0 aioredis>=2.0.0
```

### 2. Environment Variables

```env
# Redis configuration for real-time features
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=your_password_here

# WebSocket configuration
WEBSOCKET_HEARTBEAT_INTERVAL=30  # seconds
WEBSOCKET_MAX_CONNECTIONS=1000
```

### 3. Enable Real-time Features

```python
from fastapi import FastAPI
from mcp_auth.realtime import setup_realtime_system

app = FastAPI()

# Enable real-time WebSocket support
realtime_router = setup_realtime_system(app)

# The WebSocket endpoint will be available at /ws
```

## Usage Examples

### Client-Side WebSocket Connection

```javascript
// Connect to WebSocket endpoint
const ws = new WebSocket('ws://localhost:8000/ws');

// Authentication (send token after connection)
ws.onopen = function() {
    ws.send(JSON.stringify({
        type: 'auth',
        token: 'your_jwt_token_here'
    }));
};

// Handle incoming events
ws.onmessage = function(event) {
    const data = JSON.parse(event.data);

    switch(data.event_type) {
        case 'permission_granted':
            console.log('Permission granted:', data.resource, data.action);
            updateUIPermissions(data);
            break;

        case 'role_assigned':
            console.log('Role assigned:', data.role_name);
            refreshUserRoles();
            break;

        case 'security_violation':
            console.log('Security alert:', data.message);
            showSecurityAlert(data);
            break;
    }
};

// Handle connection close
ws.onclose = function(event) {
    console.log('WebSocket closed:', event.code, event.reason);
    // Implement reconnection logic
    setTimeout(reconnect, 5000);
};
```

### Server-Side Event Broadcasting

```python
from mcp_auth.realtime import notify_rbac_event, RBACEvent, EventType
from mcp_auth.models import Principal

# Notify when permission is granted
async def grant_permission(principal: Principal, resource: str, action: str):
    # Your permission granting logic here

    # Broadcast event to all connected clients
    await notify_rbac_event(RBACEvent(
        event_type=EventType.PERMISSION_GRANTED,
        user_id=principal.id,
        user_name=principal.name,
        resource=resource,
        action=action,
        message=f"Permission granted for {action} on {resource}"
    ))

# Notify role changes
async def assign_role(admin_principal: Principal, target_user_id: str, role_name: str):
    # Your role assignment logic here

    # Broadcast role assignment event
    await notify_rbac_event(RBACEvent(
        event_type=EventType.ROLE_ASSIGNED,
        user_id=admin_principal.id,
        target_user_id=target_user_id,
        role_name=role_name,
        message=f"Role {role_name} assigned to user {target_user_id}"
    ))

# Security events
async def log_security_violation(principal: Principal, violation_type: str):
    await notify_rbac_event(RBACEvent(
        event_type=EventType.SECURITY_VIOLATION,
        user_id=principal.id,
        message=f"Security violation: {violation_type}",
        security_level="HIGH"
    ))
```

## Event Types

The system supports various RBAC event types:

```python
class EventType(str, Enum):
    # Permission events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    PERMISSION_REVOKED = "permission_revoked"

    # Role events
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    ROLE_MODIFIED = "role_modified"

    # User events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"

    # Security events
    SECURITY_VIOLATION = "security_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    ACCESS_DENIED = "access_denied"

    # System events
    POLICY_UPDATED = "policy_updated"
    CONFIGURATION_CHANGED = "configuration_changed"
```

## Advanced Features

### Event Filtering by User

Events are automatically filtered so users only receive events relevant to them:

- Users receive events about their own permissions and roles
- Administrators receive all events
- Events can be filtered by resource type or security level

### Connection Management

The system automatically handles:

- Connection authentication and authorization
- Heartbeat/ping-pong for connection health
- Automatic cleanup of disconnected clients
- Rate limiting for message broadcasting
- Memory management for large numbers of connections

### Redis Integration

When Redis is available:

- Events are distributed across multiple server instances
- Supports horizontal scaling
- Provides message persistence and reliability
- Enables pub/sub pattern for efficient broadcasting

When Redis is unavailable:

- System gracefully degrades to local-only events
- No errors or service interruption
- Automatic reconnection when Redis becomes available

## Performance Considerations

### Connection Limits

```python
# Configure connection limits
from mcp_auth.realtime import connection_manager

# Set maximum concurrent connections
connection_manager.max_connections = 1000

# Configure heartbeat interval
connection_manager.heartbeat_interval = 30  # seconds
```

### Message Rate Limiting

```python
# Configure per-connection message limits
connection_manager.rate_limit_messages = 100  # messages per minute
connection_manager.rate_limit_window = 60    # seconds
```

### Memory Management

The system automatically cleans up:

- Disconnected WebSocket connections
- Stale authentication tokens
- Expired event messages
- Redis connection pools

## Security Considerations

### Authentication

- All WebSocket connections must be authenticated
- JWT tokens are validated on connection and periodically
- Connections are automatically closed on authentication failure

### Authorization

- Event filtering ensures users only see authorized events
- Administrative events require elevated permissions
- Security events are logged and monitored

### Data Protection

- All WebSocket traffic can be secured with WSS (WebSocket Secure)
- Event payloads exclude sensitive data
- User data is filtered based on privacy settings

## Troubleshooting

### Common Issues

1. **Connection Refused**
   ```
   Error: WebSocket connection failed
   Solution: Verify WebSocket endpoint is enabled and accessible
   ```

2. **Authentication Failed**
   ```
   Error: Authentication required
   Solution: Send valid JWT token after connection establishment
   ```

3. **Redis Connection Issues**
   ```
   Error: Redis unavailable
   Solution: System will work in local mode; check Redis configuration
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.getLogger("mcp_auth.realtime").setLevel(logging.DEBUG)
```

### Health Monitoring

Monitor WebSocket system health:

```python
from mcp_auth.realtime import connection_manager

# Get connection statistics
stats = connection_manager.get_connection_stats()
print(f"Active connections: {stats['active_connections']}")
print(f"Total messages sent: {stats['total_messages_sent']}")
print(f"Failed authentications: {stats['auth_failures']}")
```

## Integration Examples

### React Integration

```jsx
import React, { useEffect, useState } from 'react';

const RealTimeUpdates = ({ token }) => {
    const [events, setEvents] = useState([]);
    const [connected, setConnected] = useState(false);

    useEffect(() => {
        const ws = new WebSocket('ws://localhost:8000/ws');

        ws.onopen = () => {
            ws.send(JSON.stringify({ type: 'auth', token }));
            setConnected(true);
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            setEvents(prev => [...prev, data]);
        };

        ws.onclose = () => setConnected(false);

        return () => ws.close();
    }, [token]);

    return (
        <div>
            <div>Status: {connected ? 'Connected' : 'Disconnected'}</div>
            <ul>
                {events.map((event, i) => (
                    <li key={i}>{event.message}</li>
                ))}
            </ul>
        </div>
    );
};
```

### Vue.js Integration

```vue
<template>
  <div>
    <div>Status: {{ connected ? 'Connected' : 'Disconnected' }}</div>
    <ul>
      <li v-for="event in events" :key="event.id">
        {{ event.message }}
      </li>
    </ul>
  </div>
</template>

<script>
export default {
  data() {
    return {
      ws: null,
      connected: false,
      events: []
    }
  },

  mounted() {
    this.connect();
  },

  beforeDestroy() {
    if (this.ws) {
      this.ws.close();
    }
  },

  methods: {
    connect() {
      this.ws = new WebSocket('ws://localhost:8000/ws');

      this.ws.onopen = () => {
        this.ws.send(JSON.stringify({
          type: 'auth',
          token: this.$store.state.auth.token
        }));
        this.connected = true;
      };

      this.ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        this.events.push(data);
      };

      this.ws.onclose = () => {
        this.connected = false;
      };
    }
  }
}
</script>
```

## Best Practices

1. **Authentication**: Always authenticate WebSocket connections immediately after opening
2. **Error Handling**: Implement proper error handling and reconnection logic
3. **Rate Limiting**: Respect rate limits to avoid connection termination
4. **Resource Cleanup**: Always close WebSocket connections when components unmount
5. **Event Filtering**: Use event filtering to reduce unnecessary client updates
6. **Graceful Degradation**: Design your application to work without real-time updates
7. **Security**: Use WSS in production environments
8. **Monitoring**: Monitor connection health and performance metrics
9. **Testing**: Test WebSocket functionality with various network conditions
10. **Documentation**: Document event schemas for frontend developers
