# Audit Trail and Analytics Guide

## Overview

The MCP-Auth system provides comprehensive audit logging and security analytics capabilities that track all RBAC activities, detect security patterns, and provide compliance reporting. This system is essential for security monitoring, compliance requirements, and operational insights.

## Key Features

- **Comprehensive Event Logging**: Tracks all RBAC operations with detailed context
- **Security Analytics**: Automated detection of suspicious patterns and security violations
- **Access Pattern Analysis**: User behavior analysis and anomaly detection
- **Compliance Reporting**: Built-in reports for SOX, GDPR, HIPAA, and other standards
- **Real-time Monitoring**: Integration with real-time alerting systems
- **Performance Metrics**: Detailed performance and cache utilization tracking
- **Risk Assessment**: Automated risk scoring based on activity patterns
- **Dashboard Analytics**: REST API endpoints for building security dashboards

## Architecture

```
RBAC Operations → Audit Logger → Audit Storage → Analytics Engine → Dashboard/Reports
                        ↓              ↓              ↓
                  Real-time       Event Index    Security Metrics
                  Notifications   Optimization   Risk Analysis
```

## Setup and Configuration

### 1. Enable Audit System

```python
from fastapi import FastAPI
from mcp_auth.audit import setup_audit_system

app = FastAPI()

# Enable comprehensive audit logging
audit_router = setup_audit_system(
    app,
    enable_real_time=True,    # Send events via WebSocket
    enable_analytics=True,    # Enable analytics endpoints
    storage_backend="memory", # or "redis", "database"
    retention_days=90,        # Keep audit logs for 90 days
)

# Audit endpoints will be available under /audit/*
```

### 2. Environment Variables

```env
# Audit Configuration
AUDIT_ENABLED=true
AUDIT_STORAGE_BACKEND=memory  # memory, redis, database
AUDIT_RETENTION_DAYS=90
AUDIT_MAX_EVENTS_MEMORY=100000

# Security Analytics
AUDIT_ENABLE_ANALYTICS=true
AUDIT_RISK_THRESHOLD_HIGH=75
AUDIT_RISK_THRESHOLD_CRITICAL=90
AUDIT_SUSPICIOUS_ACTIVITY_WINDOW=300  # 5 minutes

# Compliance
AUDIT_COMPLIANCE_STANDARDS=sox,gdpr,hipaa
AUDIT_EXPORT_FORMAT=json  # json, csv, pdf

# Performance
AUDIT_BATCH_SIZE=100
AUDIT_FLUSH_INTERVAL=30  # seconds
AUDIT_COMPRESSION=true
```

### 3. Automatic Integration

The audit system automatically integrates with RBAC operations:

```python
from mcp_auth.rbac.decorators import require_permissions
from mcp_auth.models import Principal

# All decorated functions are automatically audited
@require_permissions("documents:read")
async def get_document(document_id: str, principal: Principal):
    # This operation is automatically logged with:
    # - User information (principal)
    # - Resource accessed (documents)
    # - Action performed (read)
    # - Success/failure
    # - Performance metrics
    # - Context (IP, user agent, etc.)

    return await load_document(document_id)
```

## Usage Examples

### Manual Event Logging

```python
from mcp_auth.audit import get_audit_logger, AuditEventType

audit = get_audit_logger()

# Log custom security events
await audit.log_security_event(
    AuditEventType.SECURITY_VIOLATION,
    "Multiple failed login attempts detected",
    principal=principal,
    risk_score=85,
    details={
        "attempt_count": 5,
        "time_window": "5_minutes",
        "source_ips": ["192.168.1.100", "192.168.1.101"]
    }
)

# Log administrative actions
await audit.log_event(
    AuditEventType.ROLE_ASSIGNED,
    f"Admin assigned {role_name} role to user {target_user_id}",
    principal=admin_principal,
    target_user_id=target_user_id,
    role_name=role_name,
    details={"assigned_by": admin_principal.name}
)

# Log permission changes
await audit.log_event(
    AuditEventType.PERMISSION_GRANTED,
    f"Permission granted for {action} on {resource}",
    principal=principal,
    resource=resource,
    action=action,
    duration_ms=response_time,
    cache_hit=was_cached
)
```

### Querying Audit Events

```python
from mcp_auth.audit import AuditFilter, AuditStorage
from datetime import datetime, timedelta

storage = AuditStorage()

# Query recent security events
recent_security_events = await storage.query_events(
    AuditFilter(
        start_date=datetime.utcnow() - timedelta(days=7),
        event_types=[
            AuditEventType.SECURITY_VIOLATION,
            AuditEventType.SUSPICIOUS_ACTIVITY,
            AuditEventType.UNAUTHORIZED_ACCESS
        ],
        security_levels=[SecurityLevel.HIGH, SecurityLevel.CRITICAL]
    )
)

# Query user activity
user_activity = await storage.query_events(
    AuditFilter(
        user_ids=["user123"],
        start_date=datetime.utcnow() - timedelta(days=1),
        limit=50
    )
)

# Query failed access attempts
failed_attempts = await storage.query_events(
    AuditFilter(
        event_types=[AuditEventType.PERMISSION_DENIED],
        min_risk_score=50,
        resources=["sensitive_documents", "admin_panel"]
    )
)
```

### Security Metrics and Analytics

```python
# Get security metrics for time period
metrics = await storage.get_security_metrics(
    start_date=datetime.utcnow() - timedelta(days=30),
    end_date=datetime.utcnow()
)

print(f"Total events: {metrics.total_events}")
print(f"Security violations: {metrics.security_violations}")
print(f"Failed login rate: {metrics.failed_logins / metrics.total_logins:.2%}")
print(f"Permission denial rate: {metrics.permission_denials / metrics.permission_checks:.2%}")
print(f"Average risk score: {metrics.avg_risk_score:.1f}")
print(f"High-risk events: {metrics.high_risk_events}")

# Analyze user access patterns
user_pattern = await storage.analyze_access_patterns("user123", days=30)

print(f"Total sessions: {user_pattern.total_sessions}")
print(f"Average session duration: {user_pattern.avg_session_duration / 60:.1f} minutes")
print(f"Peak activity hours: {user_pattern.peak_activity_hours}")
print(f"Most accessed resources: {user_pattern.most_accessed_resources}")
print(f"Unusual activity detected: {user_pattern.unusual_activity}")
print(f"User risk score: {user_pattern.risk_score}")
```

## Event Types and Schemas

### Core Event Types

```python
class AuditEventType(str, Enum):
    # Authentication Events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_LOGIN_FAILED = "user_login_failed"
    SESSION_EXPIRED = "session_expired"

    # Authorization Events
    PERMISSION_CHECK = "permission_check"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    PERMISSION_REVOKED = "permission_revoked"

    # Role Management
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    ROLE_MODIFIED = "role_modified"
    ROLE_CREATED = "role_created"
    ROLE_DELETED = "role_deleted"

    # User Management
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_ACTIVATED = "user_activated"
    USER_DEACTIVATED = "user_deactivated"

    # Security Events
    SECURITY_VIOLATION = "security_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # System Events
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    CONFIGURATION_CHANGED = "configuration_changed"
    POLICY_UPDATED = "policy_updated"
```

### Event Schema

```python
{
    "event_id": "evt_1234567890abcdef",
    "timestamp": "2024-01-15T10:30:45.123Z",
    "event_type": "permission_granted",
    "message": "User granted read access to documents",

    # User Information
    "user_id": "user_12345",
    "user_name": "John Doe",
    "user_email": "john@company.com",
    "user_provider": "oauth_google",

    # Target User (for admin actions)
    "target_user_id": "user_67890",

    # Resource Information
    "resource": "documents",
    "action": "read",
    "resource_id": "doc_abc123",

    # Role Information
    "role_name": "document_reader",

    # Permission Details
    "permission": {
        "resource": "documents",
        "action": "read",
        "conditions": ["department:engineering"]
    },
    "access_granted": true,

    # Request Context
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "endpoint": "/api/documents/123",
    "method": "GET",
    "request_id": "req_abc123def456",
    "session_id": "sess_789xyz",

    # Additional Context
    "details": {
        "department": "engineering",
        "location": "san_francisco",
        "device_type": "desktop"
    },

    # Security Classification
    "security_level": "medium",
    "compliance_tags": ["sox", "gdpr"],
    "risk_score": 35,
    "correlation_id": "corr_analysis_123",

    # Performance Metrics
    "duration_ms": 25.5,
    "cache_hit": true
}
```

## Analytics Dashboard API

### Security Metrics Endpoint

```python
# GET /audit/metrics?start_date=2024-01-01&end_date=2024-01-31
{
    "total_events": 15420,
    "unique_users": 245,
    "security_violations": 12,
    "unauthorized_attempts": 34,
    "privilege_escalations": 2,
    "suspicious_activities": 28,
    "total_logins": 1840,
    "failed_logins": 92,
    "permission_checks": 8750,
    "permission_denials": 125,
    "avg_permission_check_time": 23.5,
    "cache_hit_rate": 87.3,
    "high_risk_events": 45,
    "critical_events": 8,
    "avg_risk_score": 28.4,
    "compliance_events": 420,
    "audit_coverage": 98.7,
    "period_start": "2024-01-01T00:00:00Z",
    "period_end": "2024-01-31T23:59:59Z",
    "generated_at": "2024-02-01T09:15:30Z"
}
```

### User Access Patterns Endpoint

```python
# GET /audit/users/user123/patterns?days=30
{
    "user_id": "user123",
    "user_name": "John Doe",
    "total_sessions": 28,
    "total_requests": 1250,
    "unique_resources": 8,
    "unique_endpoints": 15,
    "first_activity": "2024-01-01T08:30:00Z",
    "last_activity": "2024-01-30T17:45:00Z",
    "peak_activity_hours": [9, 14, 16],
    "avg_session_duration": 1800.0,
    "most_accessed_resources": [
        ["documents", 450],
        ["reports", 320],
        ["dashboard", 280]
    ],
    "permission_denials": 5,
    "security_violations": 1,
    "unusual_activity": false,
    "risk_score": 25,
    "risk_factors": []
}
```

### Security Dashboard Endpoint

```python
# GET /audit/dashboard
{
    "overview": {
        "total_events_today": 456,
        "active_users_today": 89,
        "security_alerts_today": 3,
        "system_health": "healthy"
    },
    "security_summary": {
        "high_risk_events_24h": 2,
        "failed_login_rate_24h": 4.2,
        "suspicious_activities_7d": 15,
        "top_risk_users": [
            {"user_id": "user789", "risk_score": 78},
            {"user_id": "user456", "risk_score": 65}
        ]
    },
    "performance": {
        "avg_response_time_ms": 28.5,
        "cache_hit_rate": 89.2,
        "error_rate": 0.3
    },
    "compliance": {
        "audit_coverage": 98.9,
        "retention_compliance": true,
        "export_ready": true
    }
}
```

## Compliance Features

### SOX Compliance

```python
# Generate SOX compliance report
sox_report = await generate_compliance_report(
    standard="sox",
    start_date=datetime(2024, 1, 1),
    end_date=datetime(2024, 12, 31),
    include_controls=[
        "access_controls",
        "segregation_of_duties",
        "audit_trails",
        "change_management"
    ]
)

# Export to various formats
await export_report(sox_report, format="pdf", filename="sox_2024.pdf")
```

### GDPR Compliance

```python
# Track GDPR-relevant events
gdpr_events = await storage.query_events(
    AuditFilter(
        compliance_tags=["gdpr"],
        event_types=[
            AuditEventType.USER_CREATED,
            AuditEventType.USER_UPDATED,
            AuditEventType.USER_DELETED,
            AuditEventType.PERMISSION_GRANTED
        ]
    )
)

# Generate data subject access report
user_data_access = await generate_user_data_report("user123")
```

### Custom Compliance Rules

```python
from mcp_auth.audit import ComplianceRule, ComplianceViolation

# Define custom compliance rules
class SODRule(ComplianceRule):
    """Segregation of Duties - users shouldn't have conflicting roles"""

    async def evaluate(self, events: List[AuditEvent]) -> List[ComplianceViolation]:
        violations = []

        # Check for conflicting role assignments
        role_assignments = [e for e in events if e.event_type == AuditEventType.ROLE_ASSIGNED]

        for event in role_assignments:
            if await self.has_conflicting_roles(event.target_user_id, event.role_name):
                violations.append(ComplianceViolation(
                    rule_name="segregation_of_duties",
                    violation_type="conflicting_roles",
                    user_id=event.target_user_id,
                    description=f"User assigned conflicting role: {event.role_name}",
                    severity="high"
                ))

        return violations

# Register compliance rule
audit.register_compliance_rule(SODRule())
```

## Security Analytics

### Anomaly Detection

```python
from mcp_auth.audit import AnomalyDetector

detector = AnomalyDetector()

# Detect unusual access patterns
anomalies = await detector.detect_anomalies(
    user_id="user123",
    analysis_window=timedelta(days=7),
    detection_types=[
        "unusual_times",      # Access outside normal hours
        "unusual_locations",  # Access from new IPs/locations
        "unusual_resources",  # Access to resources not normally used
        "high_failure_rate",  # High rate of failed attempts
        "privilege_escalation" # Attempts to access higher privileges
    ]
)

for anomaly in anomalies:
    print(f"⚠️ Anomaly detected: {anomaly.description}")
    print(f"Risk score: {anomaly.risk_score}")
    print(f"Confidence: {anomaly.confidence:.2%}")
```

### Risk Scoring

```python
# Automatic risk scoring based on activity
risk_factors = {
    "failed_login_attempts": 10,      # +10 per failed attempt
    "off_hours_access": 15,           # +15 for access outside business hours
    "high_privilege_access": 20,      # +20 for admin/sensitive access
    "multiple_ip_addresses": 25,      # +25 for access from multiple IPs
    "permission_denials": 5,          # +5 per permission denial
    "security_violations": 50,        # +50 per security violation
}

# Risk scoring is automatic, but can be customized
class CustomRiskScorer:
    def calculate_risk_score(self, events: List[AuditEvent]) -> int:
        score = 0

        for event in events:
            # Add base risk for event type
            if event.event_type in high_risk_events:
                score += 50
            elif event.event_type in medium_risk_events:
                score += 20

            # Add context-based risk
            if event.ip_address and self.is_suspicious_ip(event.ip_address):
                score += 30

            if event.timestamp.hour < 6 or event.timestamp.hour > 22:
                score += 15  # Off-hours activity

        return min(score, 100)  # Cap at 100
```

## Integration Examples

### Real-time Security Monitoring

```python
from mcp_auth.audit import get_audit_logger
from mcp_auth.realtime import notify_rbac_event

audit = get_audit_logger()

# Monitor for high-risk events and send real-time alerts
@audit.on_high_risk_event(threshold=75)
async def handle_high_risk_event(event: AuditEvent):
    # Send real-time notification
    await notify_rbac_event(RBACEvent(
        event_type=EventType.SECURITY_VIOLATION,
        user_id=event.user_id,
        message=f"High-risk activity detected: {event.message}",
        details={"risk_score": event.risk_score, "event_id": event.event_id}
    ))

    # Send to external security system
    await send_to_siem({
        "alert_type": "high_risk_rbac_event",
        "user_id": event.user_id,
        "risk_score": event.risk_score,
        "timestamp": event.timestamp.isoformat(),
        "details": event.details
    })
```

### Custom Analytics Dashboard

```python
from fastapi import FastAPI, Depends
from mcp_auth.audit import get_audit_logger, AuditStorage

app = FastAPI()
storage = AuditStorage()

@app.get("/dashboard/security-summary")
async def get_security_summary():
    """Custom security summary endpoint"""

    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Get recent metrics
    recent_events = await storage.query_events(
        AuditFilter(start_date=last_24h, limit=1000)
    )

    # Calculate custom metrics
    failed_logins = len([e for e in recent_events
                        if e.event_type == AuditEventType.USER_LOGIN_FAILED])

    security_events = len([e for e in recent_events
                          if e.security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]])

    # Identify top risk users
    user_risk_scores = {}
    for event in recent_events:
        if event.user_id and event.risk_score:
            user_risk_scores[event.user_id] = max(
                user_risk_scores.get(event.user_id, 0),
                event.risk_score
            )

    top_risk_users = sorted(user_risk_scores.items(),
                           key=lambda x: x[1], reverse=True)[:5]

    return {
        "period": "last_24_hours",
        "total_events": len(recent_events),
        "failed_logins": failed_logins,
        "security_events": security_events,
        "top_risk_users": [{"user_id": uid, "risk_score": score}
                          for uid, score in top_risk_users],
        "alerts": await get_active_alerts()
    }

async def get_active_alerts():
    """Get currently active security alerts"""
    # Implementation for active alerts
    return []
```

## Performance Considerations

### Event Storage Optimization

```python
# Batch event storage for high-volume systems
class BatchAuditLogger:
    def __init__(self, batch_size=100, flush_interval=30):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.pending_events = []
        self.last_flush = time.time()

    async def log_event(self, event: AuditEvent):
        self.pending_events.append(event)

        # Flush if batch is full or time interval exceeded
        if (len(self.pending_events) >= self.batch_size or
            time.time() - self.last_flush > self.flush_interval):
            await self.flush_events()

    async def flush_events(self):
        if self.pending_events:
            await storage.store_events_batch(self.pending_events)
            self.pending_events.clear()
            self.last_flush = time.time()
```

### Query Optimization

```python
# Use indices for common query patterns
class OptimizedAuditStorage:
    def __init__(self):
        # Create indices for fast lookups
        self._user_index = defaultdict(list)      # user_id -> event indices
        self._event_type_index = defaultdict(list) # event_type -> event indices
        self._time_index = []                     # (timestamp, index) sorted by time
        self._resource_index = defaultdict(list)  # resource -> event indices

    async def query_events_optimized(self, filter: AuditFilter) -> List[AuditEvent]:
        # Use indices to quickly find candidate events
        candidate_indices = set(range(len(self.events)))

        # Apply user filter using index
        if filter.user_ids:
            user_indices = set()
            for user_id in filter.user_ids:
                user_indices.update(self._user_index.get(user_id, []))
            candidate_indices &= user_indices

        # Apply event type filter using index
        if filter.event_types:
            type_indices = set()
            for event_type in filter.event_types:
                type_indices.update(self._event_type_index.get(event_type, []))
            candidate_indices &= type_indices

        # Convert indices to events and apply remaining filters
        candidate_events = [self.events[i] for i in candidate_indices]

        # Apply time range, risk score, and other filters
        filtered_events = self._apply_remaining_filters(candidate_events, filter)

        # Sort and paginate
        filtered_events.sort(key=lambda e: e.timestamp, reverse=True)
        return filtered_events[filter.offset:filter.offset + filter.limit]
```

## Best Practices

1. **Event Classification**: Properly classify events by security level and risk score
2. **Context Enrichment**: Include relevant context (IP, user agent, session) in audit events
3. **Performance**: Use batching and indexing for high-volume audit logging
4. **Retention**: Implement appropriate data retention policies for compliance
5. **Security**: Secure audit logs themselves from tampering and unauthorized access
6. **Monitoring**: Monitor audit system health and performance
7. **Compliance**: Regularly review and update compliance rules and reports
8. **Analysis**: Use analytics to proactively identify security issues
9. **Integration**: Integrate with existing SIEM and security monitoring tools
10. **Documentation**: Maintain clear documentation of audit events and their meanings

The audit system provides a solid foundation for security monitoring, compliance reporting, and operational insights while maintaining high performance and reliability.
