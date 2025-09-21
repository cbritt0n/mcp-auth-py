"""
Comprehensive Audit Trail & Analytics - Advanced logging and monitoring for RBAC events.

This module provides detailed audit logging with structured events, analytics APIs,
security monitoring, compliance reporting, and real-time dashboards for access patterns
and security insights.
"""

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from .models import Principal

# Try to import RBAC dependencies if available
try:
    from .rbac.decorators import get_current_principal, require_permissions
    from .rbac.models import AccessResult

    _rbac_available = True
except ImportError:
    _rbac_available = False
    get_current_principal = None
    require_permissions = None
    AccessResult = None

logger = logging.getLogger(__name__)


# Helper functions for conditional RBAC support
def _conditional_require_permissions(permission: str):
    """Conditionally apply RBAC permission requirement"""
    if _rbac_available and require_permissions:
        return require_permissions(permission)
    else:
        # No-op decorator when RBAC is not available
        def decorator(func):
            return func

        return decorator


def _conditional_get_current_principal(request: Request) -> Optional[Principal]:
    """Conditionally get current principal"""
    if _rbac_available and get_current_principal:
        return get_current_principal(request)
    else:
        # Fallback to request.state.principal when RBAC is not available
        return getattr(request.state, "principal", None)


class AuditEventType(str, Enum):
    """Types of audit events for RBAC operations"""

    # Authentication events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    TOKEN_ISSUED = "token_issued"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REVOKED = "token_revoked"

    # Permission events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    PERMISSION_CHECK = "permission_check"
    BULK_PERMISSION_CHECK = "bulk_permission_check"

    # Role management events
    ROLE_CREATED = "role_created"
    ROLE_UPDATED = "role_updated"
    ROLE_DELETED = "role_deleted"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"

    # Policy events
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_DELETED = "policy_deleted"
    POLICY_APPLIED = "policy_applied"

    # Security events
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # System events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CACHE_CLEARED = "cache_cleared"
    CONFIGURATION_CHANGED = "configuration_changed"

    # Administrative events
    ADMIN_ACTION = "admin_action"
    BULK_OPERATION = "bulk_operation"
    DATA_EXPORT = "data_export"
    COMPLIANCE_REPORT = "compliance_report"


class SecurityLevel(str, Enum):
    """Security levels for audit events"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEvent(BaseModel):
    """Comprehensive audit event model"""

    # Event identification
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: AuditEventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # User information
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    user_provider: Optional[str] = None
    target_user_id: Optional[str] = None

    # RBAC-specific fields
    resource: Optional[str] = None
    action: Optional[str] = None
    resource_id: Optional[str] = None
    role_name: Optional[str] = None
    permission: Optional[dict[str, Any]] = None
    access_granted: Optional[bool] = None

    # Request context
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    # Event details
    message: str
    details: Optional[dict[str, Any]] = None
    security_level: SecurityLevel = SecurityLevel.LOW

    # Compliance and tracking
    compliance_tags: list[str] = Field(default_factory=list)
    risk_score: Optional[int] = None  # 0-100
    correlation_id: Optional[str] = None

    # Performance metrics
    duration_ms: Optional[float] = None
    cache_hit: Optional[bool] = None

    model_config = ConfigDict(
        # Use model_dump() instead of deprecated json() method
    )


class AuditFilter(BaseModel):
    """Filtering criteria for audit queries"""

    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    event_types: Optional[list[AuditEventType]] = None
    user_ids: Optional[list[str]] = None
    resources: Optional[list[str]] = None
    security_levels: Optional[list[SecurityLevel]] = None
    ip_addresses: Optional[list[str]] = None
    access_granted: Optional[bool] = None
    min_risk_score: Optional[int] = None
    compliance_tags: Optional[list[str]] = None

    # Pagination
    offset: int = 0
    limit: int = 100


class SecurityMetrics(BaseModel):
    """Security and compliance metrics"""

    total_events: int
    security_violations: int
    unauthorized_attempts: int
    privilege_escalations: int
    suspicious_activities: int

    # Access patterns
    unique_users: int
    total_logins: int
    failed_logins: int
    permission_checks: int
    permission_denials: int

    # Performance metrics
    avg_permission_check_time: float
    cache_hit_rate: float

    # Risk assessment
    high_risk_events: int
    critical_events: int
    avg_risk_score: float

    # Compliance
    compliance_events: int
    audit_coverage: float

    # Time range
    period_start: datetime
    period_end: datetime
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class AccessPattern(BaseModel):
    """User access pattern analysis"""

    user_id: str
    user_name: str

    # Activity metrics
    total_sessions: int
    total_requests: int
    unique_resources: int
    unique_endpoints: int

    # Timing patterns
    first_activity: datetime
    last_activity: datetime
    peak_activity_hours: list[int]
    avg_session_duration: float

    # Access patterns
    most_accessed_resources: list[tuple[str, int]]
    permission_denials: int
    security_violations: int

    # Risk indicators
    unusual_activity: bool
    risk_score: int
    risk_factors: list[str]


class AuditStorage:
    """Storage interface for audit events"""

    def __init__(self):
        # In-memory storage for demo purposes
        # In production, use database, Elasticsearch, or other persistent storage
        self.events: list[AuditEvent] = []
        self._lock = None  # Lazy-initialized when first async method is called

        # Indices for faster queries
        self._user_index: dict[str, list[int]] = defaultdict(list)
        self._event_type_index: dict[AuditEventType, list[int]] = defaultdict(list)
        self._resource_index: dict[str, list[int]] = defaultdict(list)
        self._time_index: list[tuple[datetime, int]] = []

    def _ensure_lock(self):
        """Ensure the async lock is initialized"""
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def store_event(self, event: AuditEvent) -> str:
        """Store an audit event"""
        self._ensure_lock()
        async with self._lock:
            event_index = len(self.events)
            self.events.append(event)

            # Update indices
            if event.user_id:
                self._user_index[event.user_id].append(event_index)
            self._event_type_index[event.event_type].append(event_index)
            if event.resource:
                self._resource_index[event.resource].append(event_index)
            self._time_index.append((event.timestamp, event_index))

            # Keep time index sorted
            self._time_index.sort(key=lambda x: x[0])

            return event.event_id

    async def query_events(self, filter_criteria: AuditFilter) -> list[AuditEvent]:
        """Query audit events with filtering"""
        self._ensure_lock()
        async with self._lock:
            # Start with all events
            candidate_indices = set(range(len(self.events)))

            # Apply filters using indices
            if filter_criteria.user_ids:
                user_indices = set()
                for user_id in filter_criteria.user_ids:
                    user_indices.update(self._user_index.get(user_id, []))
                candidate_indices &= user_indices

            if filter_criteria.event_types:
                event_type_indices = set()
                for event_type in filter_criteria.event_types:
                    event_type_indices.update(
                        self._event_type_index.get(event_type, [])
                    )
                candidate_indices &= event_type_indices

            if filter_criteria.resources:
                resource_indices = set()
                for resource in filter_criteria.resources:
                    resource_indices.update(self._resource_index.get(resource, []))
                candidate_indices &= resource_indices

            # Filter by time range
            if filter_criteria.start_date or filter_criteria.end_date:
                time_indices = set()
                for timestamp, index in self._time_index:
                    if (
                        filter_criteria.start_date
                        and timestamp < filter_criteria.start_date
                    ):
                        continue
                    if (
                        filter_criteria.end_date
                        and timestamp > filter_criteria.end_date
                    ):
                        break
                    time_indices.add(index)
                candidate_indices &= time_indices

            # Get candidate events
            candidate_events = [self.events[i] for i in candidate_indices]

            # Apply remaining filters
            filtered_events = []
            for event in candidate_events:
                if (
                    filter_criteria.security_levels
                    and event.security_level not in filter_criteria.security_levels
                ):
                    continue
                if (
                    filter_criteria.ip_addresses
                    and event.ip_address not in filter_criteria.ip_addresses
                ):
                    continue
                if (
                    filter_criteria.access_granted is not None
                    and event.access_granted != filter_criteria.access_granted
                ):
                    continue
                if (
                    filter_criteria.min_risk_score
                    and (event.risk_score or 0) < filter_criteria.min_risk_score
                ):
                    continue
                if filter_criteria.compliance_tags:
                    if not any(
                        tag in event.compliance_tags
                        for tag in filter_criteria.compliance_tags
                    ):
                        continue

                filtered_events.append(event)

            # Sort by timestamp (newest first)
            filtered_events.sort(key=lambda x: x.timestamp, reverse=True)

            # Apply pagination
            start = filter_criteria.offset
            end = start + filter_criteria.limit
            return filtered_events[start:end]

    async def get_security_metrics(
        self, start_date: datetime, end_date: datetime
    ) -> SecurityMetrics:
        """Calculate security metrics for a time period"""
        events_in_period = await self.query_events(
            AuditFilter(start_date=start_date, end_date=end_date, limit=10000)
        )

        # Calculate metrics
        total_events = len(events_in_period)
        security_violations = len(
            [
                e
                for e in events_in_period
                if e.event_type == AuditEventType.SECURITY_VIOLATION
            ]
        )
        unauthorized_attempts = len(
            [
                e
                for e in events_in_period
                if e.event_type == AuditEventType.UNAUTHORIZED_ACCESS
            ]
        )
        privilege_escalations = len(
            [
                e
                for e in events_in_period
                if e.event_type == AuditEventType.PRIVILEGE_ESCALATION
            ]
        )
        suspicious_activities = len(
            [
                e
                for e in events_in_period
                if e.event_type == AuditEventType.SUSPICIOUS_ACTIVITY
            ]
        )

        unique_users = len({e.user_id for e in events_in_period if e.user_id})
        total_logins = len(
            [e for e in events_in_period if e.event_type == AuditEventType.USER_LOGIN]
        )
        failed_logins = len(
            [
                e
                for e in events_in_period
                if e.event_type == AuditEventType.USER_LOGIN and not e.access_granted
            ]
        )

        # Calculate metrics
        permission_checks = len(
            [
                e
                for e in events_in_period
                if e.event_type
                in [
                    AuditEventType.PERMISSION_CHECK,
                    AuditEventType.PERMISSION_GRANTED,
                    AuditEventType.PERMISSION_DENIED,
                ]
            ]
        )
        permission_denials = len(
            [
                e
                for e in events_in_period
                if e.event_type == AuditEventType.PERMISSION_DENIED
            ]
        )

        # Performance metrics
        permission_times = [
            e.duration_ms
            for e in events_in_period
            if e.duration_ms
            and e.event_type
            in [
                AuditEventType.PERMISSION_CHECK,
                AuditEventType.PERMISSION_GRANTED,
                AuditEventType.PERMISSION_DENIED,
            ]
        ]
        avg_permission_check_time = (
            sum(permission_times) / len(permission_times) if permission_times else 0
        )

        cache_hits = len([e for e in events_in_period if e.cache_hit is True])
        cache_total = len([e for e in events_in_period if e.cache_hit is not None])
        cache_hit_rate = (cache_hits / cache_total * 100) if cache_total > 0 else 0

        # Risk metrics
        high_risk_events = len(
            [
                e
                for e in events_in_period
                if e.security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]
            ]
        )
        critical_events = len(
            [e for e in events_in_period if e.security_level == SecurityLevel.CRITICAL]
        )

        risk_scores = [e.risk_score for e in events_in_period if e.risk_score]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        compliance_events = len([e for e in events_in_period if e.compliance_tags])
        audit_coverage = (
            total_events / max(1, total_events)
        ) * 100  # Simplified metric

        return SecurityMetrics(
            total_events=total_events,
            security_violations=security_violations,
            unauthorized_attempts=unauthorized_attempts,
            privilege_escalations=privilege_escalations,
            suspicious_activities=suspicious_activities,
            unique_users=unique_users,
            total_logins=total_logins,
            failed_logins=failed_logins,
            permission_checks=permission_checks,
            permission_denials=permission_denials,
            avg_permission_check_time=avg_permission_check_time,
            cache_hit_rate=cache_hit_rate,
            high_risk_events=high_risk_events,
            critical_events=critical_events,
            avg_risk_score=avg_risk_score,
            compliance_events=compliance_events,
            audit_coverage=audit_coverage,
            period_start=start_date,
            period_end=end_date,
        )

    async def analyze_access_patterns(
        self, user_id: str, days: int = 30
    ) -> AccessPattern:
        """Analyze access patterns for a specific user"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        user_events = await self.query_events(
            AuditFilter(
                start_date=start_date,
                end_date=end_date,
                user_ids=[user_id],
                limit=10000,
            )
        )

        if not user_events:
            return AccessPattern(
                user_id=user_id,
                user_name="Unknown",
                total_sessions=0,
                total_requests=0,
                unique_resources=0,
                unique_endpoints=0,
                first_activity=start_date,
                last_activity=start_date,
                peak_activity_hours=[],
                avg_session_duration=0,
                most_accessed_resources=[],
                permission_denials=0,
                security_violations=0,
                unusual_activity=False,
                risk_score=0,
                risk_factors=[],
            )

        # Calculate metrics
        login_events = [
            e for e in user_events if e.event_type == AuditEventType.USER_LOGIN
        ]
        total_sessions = len(login_events)
        total_requests = len(user_events)

        resources = {e.resource for e in user_events if e.resource}
        unique_resources = len(resources)

        endpoints = {e.endpoint for e in user_events if e.endpoint}
        unique_endpoints = len(endpoints)

        first_activity = min(e.timestamp for e in user_events)
        last_activity = max(e.timestamp for e in user_events)

        # Peak activity hours
        hour_counts = defaultdict(int)
        for event in user_events:
            hour_counts[event.timestamp.hour] += 1
        peak_hours = sorted(
            hour_counts.keys(), key=lambda h: hour_counts[h], reverse=True
        )[:3]

        # Session duration (simplified)
        avg_session_duration = (last_activity - first_activity).total_seconds() / max(
            1, total_sessions
        )

        # Most accessed resources
        resource_counts = defaultdict(int)
        for event in user_events:
            if event.resource:
                resource_counts[event.resource] += 1
        most_accessed = sorted(
            resource_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]

        permission_denials = len(
            [e for e in user_events if e.event_type == AuditEventType.PERMISSION_DENIED]
        )
        security_violations = len(
            [
                e
                for e in user_events
                if e.event_type == AuditEventType.SECURITY_VIOLATION
            ]
        )

        # Risk assessment
        risk_factors = []
        risk_score = 0

        if permission_denials > total_requests * 0.1:  # > 10% denials
            risk_factors.append("High permission denial rate")
            risk_score += 20

        if security_violations > 0:
            risk_factors.append("Security violations detected")
            risk_score += 30

        # Unusual timing
        night_activity = len(
            [e for e in user_events if e.timestamp.hour < 6 or e.timestamp.hour > 22]
        )
        if night_activity > total_requests * 0.2:  # > 20% night activity
            risk_factors.append("Unusual timing patterns")
            risk_score += 15

        unusual_activity = len(risk_factors) > 0

        # Find a user name from any event that has one
        user_name = "Unknown"
        for event in user_events:
            if event.user_name:
                user_name = event.user_name
                break

        return AccessPattern(
            user_id=user_id,
            user_name=user_name,
            total_sessions=total_sessions,
            total_requests=total_requests,
            unique_resources=unique_resources,
            unique_endpoints=unique_endpoints,
            first_activity=first_activity,
            last_activity=last_activity,
            peak_activity_hours=peak_hours,
            avg_session_duration=avg_session_duration,
            most_accessed_resources=most_accessed,
            permission_denials=permission_denials,
            security_violations=security_violations,
            unusual_activity=unusual_activity,
            risk_score=min(100, risk_score),
            risk_factors=risk_factors,
        )


# Global audit storage
_audit_storage = AuditStorage()


class AuditLogger:
    """High-level audit logging interface"""

    def __init__(self, storage: AuditStorage = None):
        self.storage = storage or _audit_storage

    async def log_event(
        self,
        event_type: AuditEventType,
        message: str,
        principal: Optional[Principal] = None,
        request: Optional[Request] = None,
        **kwargs,
    ) -> str:
        """Log an audit event with context"""

        # Extract request context
        ip_address = None
        user_agent = None
        endpoint = None
        method = None
        request_id = None

        if request:
            if (
                hasattr(request, "client")
                and request.client
                and hasattr(request.client, "host")
            ):
                ip_address = request.client.host
            else:
                ip_address = (
                    getattr(request.client, "host", None) if request.client else None
                )
            user_agent = request.headers.get("user-agent")
            endpoint = str(request.url.path)
            method = request.method
            request_id = request.headers.get("x-request-id")

        # Create event
        event = AuditEvent(
            event_type=event_type,
            message=message,
            user_id=principal.id if principal else None,
            user_name=principal.name if principal else None,
            user_email=principal.email if principal else None,
            user_provider=principal.provider if principal else None,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            method=method,
            request_id=request_id,
            **kwargs,
        )

        # Store event
        event_id = await self.storage.store_event(event)

        # Log to standard logger as well
        log_level = {
            SecurityLevel.LOW: logging.INFO,
            SecurityLevel.MEDIUM: logging.WARNING,
            SecurityLevel.HIGH: logging.ERROR,
            SecurityLevel.CRITICAL: logging.CRITICAL,
        }.get(event.security_level, logging.INFO)

        logger.log(
            log_level,
            f"AUDIT: {event_type.value} - {message}",
            extra={
                "event_id": event_id,
                "user_id": event.user_id,
                "event_type": event_type.value,
                "security_level": event.security_level.value,
            },
        )

        return event_id

    async def log_permission_check(
        self,
        principal: Principal,
        resource: str,
        action: str,
        resource_id: Optional[str],
        result: Any,  # AccessResult when RBAC is available
        duration_ms: float,
        cache_hit: bool = False,
        request: Optional[Request] = None,
    ):
        """Log a permission check event"""
        event_type = (
            AuditEventType.PERMISSION_GRANTED
            if result.allowed
            else AuditEventType.PERMISSION_DENIED
        )
        security_level = SecurityLevel.LOW if result.allowed else SecurityLevel.MEDIUM

        await self.log_event(
            event_type=event_type,
            message=f"Permission check: {resource}:{action} - {'GRANTED' if result.allowed else 'DENIED'}",
            principal=principal,
            request=request,
            resource=resource,
            action=action,
            resource_id=resource_id,
            access_granted=result.allowed,
            security_level=security_level,
            duration_ms=duration_ms,
            cache_hit=cache_hit,
            details={
                "reason": result.reason,
                "user_roles": result.user_roles,
                "context": getattr(result, "context", {}),
            },
        )

    async def log_security_event(
        self,
        event_type: AuditEventType,
        message: str,
        principal: Optional[Principal] = None,
        request: Optional[Request] = None,
        risk_score: int = 50,
        **kwargs,
    ):
        """Log a security-related event"""
        await self.log_event(
            event_type=event_type,
            message=message,
            principal=principal,
            request=request,
            security_level=(
                SecurityLevel.HIGH if risk_score > 70 else SecurityLevel.MEDIUM
            ),
            risk_score=risk_score,
            compliance_tags=["security", "monitoring"],
            **kwargs,
        )


# Global audit logger
audit_logger = AuditLogger()


class AuditAnalyticsRouter:
    """FastAPI router for audit and analytics endpoints"""

    def __init__(self):
        self.router = APIRouter(prefix="/audit", tags=["Audit & Analytics"])
        self._setup_routes()

    def _setup_routes(self):
        """Setup audit and analytics routes"""

        @self.router.get("/events", response_model=list[AuditEvent])
        @_conditional_require_permissions("audit:events:read")
        async def query_audit_events(
            request: Request,
            event_types: Optional[str] = Query(
                None, description="Comma-separated event types"
            ),
            user_ids: Optional[str] = Query(
                None, description="Comma-separated user IDs"
            ),
            resources: Optional[str] = Query(
                None, description="Comma-separated resources"
            ),
            start_date: Optional[datetime] = Query(
                None, description="Start date (ISO format)"
            ),
            end_date: Optional[datetime] = Query(
                None, description="End date (ISO format)"
            ),
            security_level: Optional[SecurityLevel] = Query(
                None, description="Minimum security level"
            ),
            access_granted: Optional[bool] = Query(
                None, description="Filter by access result"
            ),
            offset: int = Query(0, ge=0, description="Pagination offset"),
            limit: int = Query(100, ge=1, le=1000, description="Results per page"),
        ):
            """Query audit events with filtering"""

            # Parse comma-separated values
            filter_criteria = AuditFilter(
                event_types=(
                    [AuditEventType(t.strip()) for t in event_types.split(",")]
                    if event_types
                    else None
                ),
                user_ids=user_ids.split(",") if user_ids else None,
                resources=resources.split(",") if resources else None,
                start_date=start_date,
                end_date=end_date,
                security_levels=[security_level] if security_level else None,
                access_granted=access_granted,
                offset=offset,
                limit=limit,
            )

            events = await _audit_storage.query_events(filter_criteria)

            # Log the audit query
            principal = _conditional_get_current_principal(request)
            await audit_logger.log_event(
                AuditEventType.ADMIN_ACTION,
                f"Queried audit events: {len(events)} results",
                principal=principal,
                request=request,
                details={"filter": filter_criteria.dict()},
            )

            return events

        @self.router.get("/metrics", response_model=SecurityMetrics)
        @_conditional_require_permissions("audit:metrics:read")
        async def get_security_metrics(
            request: Request,
            days: int = Query(7, ge=1, le=365, description="Number of days to analyze"),
        ):
            """Get security and compliance metrics"""

            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)

            metrics = await _audit_storage.get_security_metrics(start_date, end_date)

            # Log metrics access
            principal = _conditional_get_current_principal(request)
            await audit_logger.log_event(
                AuditEventType.ADMIN_ACTION,
                f"Retrieved security metrics for {days} days",
                principal=principal,
                request=request,
            )

            return metrics

        @self.router.get("/patterns/{user_id}", response_model=AccessPattern)
        @_conditional_require_permissions("audit:patterns:read")
        async def analyze_user_patterns(
            user_id: str,
            request: Request,
            days: int = Query(
                30, ge=1, le=365, description="Number of days to analyze"
            ),
        ):
            """Analyze access patterns for a specific user"""

            pattern = await _audit_storage.analyze_access_patterns(user_id, days)

            # Log pattern analysis
            principal = _conditional_get_current_principal(request)
            await audit_logger.log_event(
                AuditEventType.ADMIN_ACTION,
                f"Analyzed access patterns for user {user_id}",
                principal=principal,
                request=request,
                target_user_id=user_id,
                details={"analysis_period_days": days},
            )

            return pattern

        @self.router.get("/dashboard")
        @_conditional_require_permissions("audit:dashboard:read")
        async def get_dashboard_data(
            request: Request,
            period: str = Query(
                "7d", pattern="^(1d|7d|30d|90d)$", description="Time period"
            ),
        ):
            """Get dashboard data for the analytics UI"""

            # Parse period
            period_days = {"1d": 1, "7d": 7, "30d": 30, "90d": 90}[period]
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=period_days)

            # Get metrics
            metrics = await _audit_storage.get_security_metrics(start_date, end_date)

            # Get recent high-risk events
            high_risk_events = await _audit_storage.query_events(
                AuditFilter(
                    start_date=start_date,
                    end_date=end_date,
                    security_levels=[SecurityLevel.HIGH, SecurityLevel.CRITICAL],
                    limit=10,
                )
            )

            # Get top active users
            recent_events = await _audit_storage.query_events(
                AuditFilter(start_date=start_date, end_date=end_date, limit=1000)
            )

            user_activity = defaultdict(int)
            for event in recent_events:
                if event.user_id:
                    user_activity[event.user_id] += 1

            top_users = sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[
                :10
            ]

            # Resource usage
            resource_activity = defaultdict(int)
            for event in recent_events:
                if event.resource:
                    resource_activity[event.resource] += 1

            top_resources = sorted(
                resource_activity.items(), key=lambda x: x[1], reverse=True
            )[:10]

            dashboard_data = {
                "metrics": metrics,
                "high_risk_events": high_risk_events,
                "top_users": [
                    {"user_id": uid, "activity_count": count}
                    for uid, count in top_users
                ],
                "top_resources": [
                    {"resource": res, "access_count": count}
                    for res, count in top_resources
                ],
                "period": period,
                "generated_at": datetime.utcnow(),
            }

            # Log dashboard access
            principal = _conditional_get_current_principal(request)
            await audit_logger.log_event(
                AuditEventType.ADMIN_ACTION,
                f"Accessed analytics dashboard ({period})",
                principal=principal,
                request=request,
            )

            return dashboard_data

        @self.router.post("/reports/compliance")
        @_conditional_require_permissions("audit:reports:generate")
        async def generate_compliance_report(
            request: Request,
            start_date: datetime = Query(..., description="Report start date"),
            end_date: datetime = Query(..., description="Report end date"),
            report_type: str = Query(
                "security", pattern="^(security|access|compliance)$"
            ),
        ):
            """Generate a compliance report"""

            # Generate report based on type
            if report_type == "security":
                metrics = await _audit_storage.get_security_metrics(
                    start_date, end_date
                )

                # Get security events
                security_events = await _audit_storage.query_events(
                    AuditFilter(
                        start_date=start_date,
                        end_date=end_date,
                        event_types=[
                            AuditEventType.SECURITY_VIOLATION,
                            AuditEventType.UNAUTHORIZED_ACCESS,
                            AuditEventType.PRIVILEGE_ESCALATION,
                            AuditEventType.SUSPICIOUS_ACTIVITY,
                        ],
                        limit=1000,
                    )
                )

                report = {
                    "report_type": report_type,
                    "period_start": start_date,
                    "period_end": end_date,
                    "generated_at": datetime.utcnow(),
                    "metrics": metrics,
                    "security_events": security_events,
                    "summary": {
                        "total_events": metrics.total_events,
                        "security_incidents": len(security_events),
                        "risk_level": (
                            "HIGH"
                            if metrics.critical_events > 0
                            else "MEDIUM" if metrics.high_risk_events > 0 else "LOW"
                        ),
                    },
                }

            else:
                # Other report types
                report = {
                    "report_type": report_type,
                    "period_start": start_date,
                    "period_end": end_date,
                    "generated_at": datetime.utcnow(),
                    "message": f"{report_type.title()} report generation not yet implemented",
                }

            # Log report generation
            principal = _conditional_get_current_principal(request)
            await audit_logger.log_event(
                AuditEventType.COMPLIANCE_REPORT,
                f"Generated {report_type} compliance report",
                principal=principal,
                request=request,
                compliance_tags=["compliance", "reporting", report_type],
                details={
                    "report_period_days": (end_date - start_date).days,
                    "report_type": report_type,
                },
            )

            return report

    def get_router(self) -> APIRouter:
        """Get the configured FastAPI router"""
        return self.router


def setup_audit_system(app, enable_real_time: bool = True) -> APIRouter:
    """
    Setup comprehensive audit system on a FastAPI app

    Args:
        app: FastAPI application instance
        enable_real_time: Enable real-time audit event broadcasting

    Returns:
        Configured router instance
    """
    try:
        # Create and include router
        audit_router = AuditAnalyticsRouter()
        router = audit_router.get_router()
        app.include_router(router)

        # Integration with real-time system
        if enable_real_time:
            try:
                from .realtime import connection_manager

                # Hook audit events to real-time broadcasting
                async def broadcast_audit_event(event: AuditEvent):
                    from .realtime import RBACEvent

                    realtime_event = RBACEvent(
                        event_type="audit_event",
                        user_id=event.user_id,
                        data={
                            "audit_event_type": event.event_type,
                            "security_level": event.security_level,
                            "message": event.message,
                            "resource": event.resource,
                            "action": event.action,
                        },
                    )
                    await connection_manager.broadcast_event(
                        realtime_event, filters={"admin_only": True}
                    )

                # Monkey patch the storage to broadcast events
                original_store = _audit_storage.store_event

                async def store_and_broadcast(event: AuditEvent) -> str:
                    event_id = await original_store(event)
                    if event.security_level in [
                        SecurityLevel.HIGH,
                        SecurityLevel.CRITICAL,
                    ]:
                        await broadcast_audit_event(event)
                    return event_id

                _audit_storage.store_event = store_and_broadcast

                # Set connection_manager attribute for imports
                import sys

                current_module = sys.modules[__name__]
                current_module.connection_manager = connection_manager

            except ImportError:
                logger.warning("Real-time module not available for audit integration")

        logger.info("Comprehensive audit system setup successfully")
        return router

    except Exception as e:
        logger.error(f"Failed to setup audit system: {e}", exc_info=True)
        raise


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance"""
    return audit_logger
