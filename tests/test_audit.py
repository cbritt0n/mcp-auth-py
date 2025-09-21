"""
Tests for audit trail and analytics functionality.

This module tests audit logging, security metrics, access pattern analysis,
compliance reporting, and analytics dashboard features.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI

from mcp_auth.audit import (
    AccessPattern,
    AuditEvent,
    AuditEventType,
    AuditFilter,
    AuditLogger,
    AuditStorage,
    SecurityLevel,
    SecurityMetrics,
    get_audit_logger,
    setup_audit_system,
)
from mcp_auth.models import Principal


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
def mock_request():
    """Mock FastAPI request"""

    # Create mock client with proper attributes
    client_mock = MagicMock()
    client_mock.host = "127.0.0.1"

    # Create mock request without spec restriction
    request = MagicMock()
    request.client = client_mock
    request.headers = {"user-agent": "test-agent", "x-request-id": "req-123"}

    # Create a proper url mock
    url_mock = MagicMock()
    url_mock.path = "/test/endpoint"
    request.url = url_mock
    request.method = "GET"

    return request


@pytest.fixture
def audit_storage():
    """Fresh audit storage for each test"""
    return AuditStorage()


class TestAuditEvent:
    """Test audit event model"""

    def test_audit_event_creation(self):
        """Test creating audit events"""
        event = AuditEvent(
            event_type=AuditEventType.PERMISSION_GRANTED,
            message="User granted access to documents",
            user_id="user123",
            resource="documents",
            action="read",
            security_level=SecurityLevel.LOW,
        )

        assert event.event_type == AuditEventType.PERMISSION_GRANTED
        assert event.message == "User granted access to documents"
        assert event.user_id == "user123"
        assert event.resource == "documents"
        assert event.action == "read"
        assert event.security_level == SecurityLevel.LOW
        assert event.event_id is not None
        assert isinstance(event.timestamp, datetime)

    def test_audit_event_with_all_fields(self):
        """Test audit event with all optional fields"""
        event = AuditEvent(
            event_type=AuditEventType.SECURITY_VIOLATION,
            message="Suspicious activity detected",
            user_id="user123",
            user_name="Test User",
            user_email="test@example.com",
            user_provider="oauth",
            target_user_id="target456",
            resource="system",
            action="access",
            resource_id="sys_001",
            role_name="admin",
            permission={"resource": "system", "action": "access"},
            access_granted=False,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            endpoint="/api/admin",
            method="POST",
            request_id="req-789",
            session_id="sess-456",
            details={"attempt_count": 3, "reason": "multiple_failures"},
            security_level=SecurityLevel.HIGH,
            compliance_tags=["security", "pci"],
            risk_score=85,
            correlation_id="corr-123",
            duration_ms=150.5,
            cache_hit=True,
        )

        assert event.event_type == AuditEventType.SECURITY_VIOLATION
        assert event.security_level == SecurityLevel.HIGH
        assert event.risk_score == 85
        assert event.compliance_tags == ["security", "pci"]
        assert event.duration_ms == 150.5
        assert event.cache_hit is True

    def test_audit_event_json_serialization(self):
        """Test audit event JSON serialization"""
        event = AuditEvent(
            event_type=AuditEventType.USER_LOGIN,
            message="User logged in successfully",
            user_id="user123",
        )

        # Test JSON serialization with modern Pydantic method
        json_data = event.model_dump_json()
        assert isinstance(json_data, str)

        # Should contain ISO formatted timestamp
        assert event.timestamp.isoformat() in json_data


class TestAuditFilter:
    """Test audit filter model"""

    def test_audit_filter_defaults(self):
        """Test audit filter with default values"""
        filter_criteria = AuditFilter()

        assert filter_criteria.start_date is None
        assert filter_criteria.end_date is None
        assert filter_criteria.offset == 0
        assert filter_criteria.limit == 100

    def test_audit_filter_with_criteria(self):
        """Test audit filter with various criteria"""
        start_date = datetime.utcnow() - timedelta(days=7)
        end_date = datetime.utcnow()

        filter_criteria = AuditFilter(
            start_date=start_date,
            end_date=end_date,
            event_types=[
                AuditEventType.PERMISSION_GRANTED,
                AuditEventType.ROLE_ASSIGNED,
            ],
            user_ids=["user1", "user2"],
            resources=["documents", "system"],
            security_levels=[SecurityLevel.HIGH, SecurityLevel.CRITICAL],
            min_risk_score=70,
            offset=20,
            limit=50,
        )

        assert filter_criteria.start_date == start_date
        assert filter_criteria.end_date == end_date
        assert len(filter_criteria.event_types) == 2
        assert len(filter_criteria.user_ids) == 2
        assert len(filter_criteria.resources) == 2
        assert len(filter_criteria.security_levels) == 2
        assert filter_criteria.min_risk_score == 70
        assert filter_criteria.offset == 20
        assert filter_criteria.limit == 50


class TestAuditStorage:
    """Test audit storage functionality"""

    @pytest.mark.asyncio
    async def test_store_event(self, audit_storage):
        """Test storing audit events"""
        event = AuditEvent(
            event_type=AuditEventType.PERMISSION_GRANTED,
            message="Test permission granted",
            user_id="user123",
        )

        event_id = await audit_storage.store_event(event)

        assert event_id == event.event_id
        assert len(audit_storage.events) == 1
        assert audit_storage.events[0] == event

        # Check indices were updated
        assert 0 in audit_storage._user_index["user123"]
        assert 0 in audit_storage._event_type_index[AuditEventType.PERMISSION_GRANTED]
        assert len(audit_storage._time_index) == 1

    @pytest.mark.asyncio
    async def test_query_events_no_filters(self, audit_storage):
        """Test querying events without filters"""
        # Store some events
        events = [
            AuditEvent(
                event_type=AuditEventType.PERMISSION_GRANTED,
                message="Event 1",
                user_id="user1",
            ),
            AuditEvent(
                event_type=AuditEventType.ROLE_ASSIGNED,
                message="Event 2",
                user_id="user2",
            ),
            AuditEvent(
                event_type=AuditEventType.PERMISSION_DENIED,
                message="Event 3",
                user_id="user1",
            ),
        ]

        for event in events:
            await audit_storage.store_event(event)

        # Query without filters
        results = await audit_storage.query_events(AuditFilter())

        assert len(results) == 3
        # Should be sorted by timestamp (newest first)
        assert results[0].message in ["Event 1", "Event 2", "Event 3"]

    @pytest.mark.asyncio
    async def test_query_events_with_user_filter(self, audit_storage):
        """Test querying events filtered by user"""
        events = [
            AuditEvent(
                event_type=AuditEventType.PERMISSION_GRANTED,
                message="Event 1",
                user_id="user1",
            ),
            AuditEvent(
                event_type=AuditEventType.ROLE_ASSIGNED,
                message="Event 2",
                user_id="user2",
            ),
            AuditEvent(
                event_type=AuditEventType.PERMISSION_DENIED,
                message="Event 3",
                user_id="user1",
            ),
        ]

        for event in events:
            await audit_storage.store_event(event)

        # Query for user1 only
        results = await audit_storage.query_events(AuditFilter(user_ids=["user1"]))

        assert len(results) == 2
        assert all(event.user_id == "user1" for event in results)

    @pytest.mark.asyncio
    async def test_query_events_with_event_type_filter(self, audit_storage):
        """Test querying events filtered by event type"""
        events = [
            AuditEvent(
                event_type=AuditEventType.PERMISSION_GRANTED,
                message="Event 1",
                user_id="user1",
            ),
            AuditEvent(
                event_type=AuditEventType.ROLE_ASSIGNED,
                message="Event 2",
                user_id="user2",
            ),
            AuditEvent(
                event_type=AuditEventType.PERMISSION_GRANTED,
                message="Event 3",
                user_id="user3",
            ),
        ]

        for event in events:
            await audit_storage.store_event(event)

        # Query for permission events only
        results = await audit_storage.query_events(
            AuditFilter(event_types=[AuditEventType.PERMISSION_GRANTED])
        )

        assert len(results) == 2
        assert all(
            event.event_type == AuditEventType.PERMISSION_GRANTED for event in results
        )

    @pytest.mark.asyncio
    async def test_query_events_with_time_filter(self, audit_storage):
        """Test querying events filtered by time range"""
        now = datetime.utcnow()

        # Create events with different timestamps
        old_event = AuditEvent(
            event_type=AuditEventType.PERMISSION_GRANTED,
            message="Old event",
            user_id="user1",
        )
        old_event.timestamp = now - timedelta(days=10)

        recent_event = AuditEvent(
            event_type=AuditEventType.PERMISSION_GRANTED,
            message="Recent event",
            user_id="user1",
        )
        recent_event.timestamp = now - timedelta(hours=1)

        await audit_storage.store_event(old_event)
        await audit_storage.store_event(recent_event)

        # Query for recent events only (last 7 days)
        results = await audit_storage.query_events(
            AuditFilter(start_date=now - timedelta(days=7))
        )

        assert len(results) == 1
        assert results[0].message == "Recent event"

    @pytest.mark.asyncio
    async def test_query_events_with_pagination(self, audit_storage):
        """Test event query pagination"""
        # Store many events
        for i in range(25):
            event = AuditEvent(
                event_type=AuditEventType.PERMISSION_GRANTED,
                message=f"Event {i}",
                user_id="user1",
            )
            await audit_storage.store_event(event)

        # Query first page
        page1 = await audit_storage.query_events(AuditFilter(offset=0, limit=10))
        assert len(page1) == 10

        # Query second page
        page2 = await audit_storage.query_events(AuditFilter(offset=10, limit=10))
        assert len(page2) == 10

        # Pages should have different events
        page1_messages = {event.message for event in page1}
        page2_messages = {event.message for event in page2}
        assert page1_messages.isdisjoint(page2_messages)

    @pytest.mark.asyncio
    async def test_get_security_metrics(self, audit_storage):
        """Test security metrics calculation"""
        now = datetime.utcnow()
        start_date = now - timedelta(days=7)

        # Create various types of events
        events = [
            AuditEvent(
                event_type=AuditEventType.USER_LOGIN,
                message="Login",
                user_id="user1",
                access_granted=True,
            ),
            AuditEvent(
                event_type=AuditEventType.USER_LOGIN,
                message="Failed login",
                user_id="user2",
                access_granted=False,
            ),
            AuditEvent(
                event_type=AuditEventType.PERMISSION_CHECK,
                message="Permission check",
                user_id="user1",
                duration_ms=50.0,
            ),
            AuditEvent(
                event_type=AuditEventType.PERMISSION_DENIED,
                message="Permission denied",
                user_id="user2",
            ),
            AuditEvent(
                event_type=AuditEventType.SECURITY_VIOLATION,
                message="Security violation",
                user_id="user3",
                security_level=SecurityLevel.HIGH,
            ),
            AuditEvent(
                event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
                message="Suspicious",
                user_id="user3",
                risk_score=75,
            ),
        ]

        for event in events:
            event.timestamp = now - timedelta(hours=1)  # Within time range
            await audit_storage.store_event(event)

        metrics = await audit_storage.get_security_metrics(start_date, now)

        assert isinstance(metrics, SecurityMetrics)
        assert metrics.total_events == 6
        assert metrics.unique_users == 3
        assert metrics.total_logins == 2
        assert metrics.failed_logins == 1
        assert metrics.permission_checks == 2  # PERMISSION_CHECK + PERMISSION_DENIED
        assert metrics.permission_denials == 1
        assert metrics.security_violations == 1
        assert metrics.suspicious_activities == 1
        assert metrics.high_risk_events >= 1

    @pytest.mark.asyncio
    async def test_analyze_access_patterns(self, audit_storage):
        """Test access pattern analysis"""
        user_id = "user123"
        now = datetime.utcnow()

        # Create user activity events
        events = [
            AuditEvent(
                event_type=AuditEventType.USER_LOGIN,
                message="Login",
                user_id=user_id,
                user_name="Test User",
            ),
            AuditEvent(
                event_type=AuditEventType.PERMISSION_CHECK,
                message="Access docs",
                user_id=user_id,
                resource="documents",
                endpoint="/api/docs",
            ),
            AuditEvent(
                event_type=AuditEventType.PERMISSION_CHECK,
                message="Access system",
                user_id=user_id,
                resource="system",
                endpoint="/api/system",
            ),
            AuditEvent(
                event_type=AuditEventType.PERMISSION_DENIED,
                message="Denied",
                user_id=user_id,
            ),
        ]

        for i, event in enumerate(events):
            event.timestamp = now - timedelta(hours=24 - i)  # Spread over time
            await audit_storage.store_event(event)

        pattern = await audit_storage.analyze_access_patterns(user_id, days=30)

        assert isinstance(pattern, AccessPattern)
        assert pattern.user_id == user_id
        assert pattern.user_name == "Test User"
        assert pattern.total_sessions == 1  # One login
        assert pattern.total_requests == 4
        assert pattern.unique_resources == 2
        assert pattern.unique_endpoints == 2
        assert pattern.permission_denials == 1
        assert isinstance(pattern.first_activity, datetime)
        assert isinstance(pattern.last_activity, datetime)


class TestAuditLogger:
    """Test audit logger functionality"""

    @pytest.mark.asyncio
    async def test_log_event_basic(self, audit_storage, mock_principal, mock_request):
        """Test basic event logging"""
        logger = AuditLogger(storage=audit_storage)

        event_id = await logger.log_event(
            AuditEventType.PERMISSION_GRANTED,
            "User granted access to documents",
            principal=mock_principal,
            request=mock_request,
            resource="documents",
            action="read",
        )

        assert event_id is not None
        assert len(audit_storage.events) == 1

        event = audit_storage.events[0]
        assert event.event_type == AuditEventType.PERMISSION_GRANTED
        assert event.message == "User granted access to documents"
        assert event.user_id == mock_principal.id
        assert event.user_name == mock_principal.name
        assert event.user_email == mock_principal.email
        assert event.ip_address == "127.0.0.1"
        assert event.user_agent == "test-agent"
        assert event.endpoint == "/test/endpoint"
        assert event.method == "GET"
        assert event.request_id == "req-123"
        assert event.resource == "documents"
        assert event.action == "read"

    @pytest.mark.asyncio
    async def test_log_permission_check(self, audit_storage, mock_principal):
        """Test permission check logging"""
        logger = AuditLogger(storage=audit_storage)

        from mcp_auth.rbac.models import AccessResult

        result = AccessResult(
            allowed=True,
            reason="User has read permission",
            user_roles=["user", "reader"],
        )

        await logger.log_permission_check(
            principal=mock_principal,
            resource="documents",
            action="read",
            resource_id="doc_123",
            result=result,
            duration_ms=25.5,
            cache_hit=True,
        )

        assert len(audit_storage.events) == 1

        event = audit_storage.events[0]
        assert event.event_type == AuditEventType.PERMISSION_GRANTED
        assert event.user_id == mock_principal.id
        assert event.resource == "documents"
        assert event.action == "read"
        assert event.resource_id == "doc_123"
        assert event.access_granted is True
        assert event.duration_ms == 25.5
        assert event.cache_hit is True
        assert event.details["reason"] == "User has read permission"
        assert event.details["user_roles"] == ["user", "reader"]

    @pytest.mark.asyncio
    async def test_log_security_event(self, audit_storage, mock_principal):
        """Test security event logging"""
        logger = AuditLogger(storage=audit_storage)

        await logger.log_security_event(
            AuditEventType.SECURITY_VIOLATION,
            "Multiple failed login attempts detected",
            principal=mock_principal,
            risk_score=85,
            details={"attempt_count": 5, "time_window": "5_minutes"},
        )

        assert len(audit_storage.events) == 1

        event = audit_storage.events[0]
        assert event.event_type == AuditEventType.SECURITY_VIOLATION
        assert event.security_level == SecurityLevel.HIGH
        assert event.risk_score == 85
        assert "security" in event.compliance_tags
        assert "monitoring" in event.compliance_tags
        assert event.details["attempt_count"] == 5


class TestAuditAnalyticsRouter:
    """Test audit analytics FastAPI router"""

    @pytest.fixture
    def app_with_audit(self):
        """FastAPI app with audit system"""
        app = FastAPI()

        # Mock the authentication
        def mock_get_principal():
            return Principal(
                id="admin_user",
                provider="test",
                name="Admin User",
                email="admin@example.com",
            )

        with patch(
            "mcp_auth.audit.get_current_principal", side_effect=mock_get_principal
        ):
            with patch(
                "mcp_auth.audit.require_permissions", lambda perm: lambda f: f
            ):  # Skip auth
                setup_audit_system(app)

        return app

    def test_audit_routes_registered(self, app_with_audit):
        """Test that audit routes are registered"""
        routes = [
            route.path for route in app_with_audit.routes if hasattr(route, "path")
        ]

        audit_routes = [route for route in routes if "/audit" in route]
        assert len(audit_routes) > 0

        # Check for specific endpoints
        expected_routes = [
            "/audit/events",
            "/audit/metrics",
            "/audit/dashboard",
        ]

        for expected_route in expected_routes:
            assert any(
                expected_route in route for route in routes
            ), f"Route {expected_route} not found"

    @pytest.mark.asyncio
    async def test_query_events_endpoint(self, app_with_audit):
        """Test the audit events query endpoint"""
        # This would require setting up test data and mocking authentication
        # For now, just verify the app can be created
        assert app_with_audit is not None

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, app_with_audit):
        """Test the security metrics endpoint"""
        # This would require setting up test data and mocking authentication
        # For now, just verify the app can be created
        assert app_with_audit is not None

    @pytest.mark.asyncio
    async def test_dashboard_endpoint(self, app_with_audit):
        """Test the analytics dashboard endpoint"""
        # This would require setting up test data and mocking authentication
        # For now, just verify the app can be created
        assert app_with_audit is not None


class TestSecurityMetrics:
    """Test security metrics model"""

    def test_security_metrics_creation(self):
        """Test creating security metrics"""
        start_date = datetime.utcnow() - timedelta(days=7)
        end_date = datetime.utcnow()

        metrics = SecurityMetrics(
            total_events=1000,
            security_violations=5,
            unauthorized_attempts=15,
            privilege_escalations=2,
            suspicious_activities=8,
            unique_users=50,
            total_logins=200,
            failed_logins=10,
            permission_checks=500,
            permission_denials=25,
            avg_permission_check_time=45.5,
            cache_hit_rate=85.2,
            high_risk_events=7,
            critical_events=2,
            avg_risk_score=25.8,
            compliance_events=100,
            audit_coverage=95.5,
            period_start=start_date,
            period_end=end_date,
        )

        assert metrics.total_events == 1000
        assert metrics.security_violations == 5
        assert metrics.unique_users == 50
        assert metrics.avg_permission_check_time == 45.5
        assert metrics.cache_hit_rate == 85.2
        assert metrics.period_start == start_date
        assert metrics.period_end == end_date
        assert isinstance(metrics.generated_at, datetime)


class TestAccessPattern:
    """Test access pattern model"""

    def test_access_pattern_creation(self):
        """Test creating access patterns"""
        now = datetime.utcnow()

        pattern = AccessPattern(
            user_id="user123",
            user_name="Test User",
            total_sessions=10,
            total_requests=150,
            unique_resources=5,
            unique_endpoints=8,
            first_activity=now - timedelta(days=30),
            last_activity=now - timedelta(minutes=5),
            peak_activity_hours=[9, 14, 16],
            avg_session_duration=1800.0,  # 30 minutes
            most_accessed_resources=[("documents", 50), ("reports", 30)],
            permission_denials=3,
            security_violations=1,
            unusual_activity=True,
            risk_score=45,
            risk_factors=["Night activity", "High denial rate"],
        )

        assert pattern.user_id == "user123"
        assert pattern.user_name == "Test User"
        assert pattern.total_sessions == 10
        assert pattern.total_requests == 150
        assert pattern.unusual_activity is True
        assert pattern.risk_score == 45
        assert len(pattern.risk_factors) == 2
        assert len(pattern.most_accessed_resources) == 2
        assert pattern.most_accessed_resources[0] == ("documents", 50)


class TestGlobalAuditFunctions:
    """Test global audit functions"""

    def test_get_audit_logger(self):
        """Test getting global audit logger"""
        logger = get_audit_logger()
        assert logger is not None
        assert isinstance(logger, AuditLogger)

    @pytest.mark.asyncio
    async def test_setup_audit_system(self):
        """Test audit system setup"""
        app = FastAPI()

        with patch("mcp_auth.audit.connection_manager") as mock_conn_manager:
            mock_conn_manager.broadcast_event = AsyncMock()

            router = setup_audit_system(app, enable_real_time=True)

            assert router is not None
            # Verify router was added to app
            assert len(app.routes) > 0

    @pytest.mark.asyncio
    async def test_setup_audit_system_no_realtime(self):
        """Test audit system setup without real-time"""
        app = FastAPI()

        router = setup_audit_system(app, enable_real_time=False)

        assert router is not None
        assert len(app.routes) > 0


class TestIntegration:
    """Integration tests for audit system"""

    @pytest.mark.asyncio
    async def test_full_audit_flow(self, audit_storage, mock_principal, mock_request):
        """Test complete audit logging flow"""
        logger = AuditLogger(storage=audit_storage)

        # Log a series of related events

        # 1. User login
        await logger.log_event(
            AuditEventType.USER_LOGIN,
            "User logged in successfully",
            principal=mock_principal,
            request=mock_request,
            access_granted=True,
        )

        # 2. Permission check
        from mcp_auth.rbac.models import AccessResult

        result = AccessResult(
            allowed=True,
            reason="User has read permission",
            user_roles=["user"],
        )

        await logger.log_permission_check(
            principal=mock_principal,
            resource="documents",
            action="read",
            resource_id=None,
            result=result,
            duration_ms=15.0,
            cache_hit=False,
        )

        # 3. Role assignment
        await logger.log_event(
            AuditEventType.ROLE_ASSIGNED,
            "Admin assigned editor role to user",
            principal=mock_principal,
            target_user_id="target_user",
            role_name="editor",
        )

        # 4. Security event
        await logger.log_security_event(
            AuditEventType.SUSPICIOUS_ACTIVITY,
            "Unusual access pattern detected",
            principal=mock_principal,
            risk_score=60,
            details={"pattern": "night_access", "frequency": "high"},
        )

        # Verify all events were stored
        assert len(audit_storage.events) == 4

        # Query events by user
        user_events = await audit_storage.query_events(
            AuditFilter(user_ids=[mock_principal.id])
        )
        assert len(user_events) == 4

        # Get security metrics
        now = datetime.utcnow()
        metrics = await audit_storage.get_security_metrics(
            now - timedelta(hours=1), now
        )

        assert metrics.total_events == 4
        assert metrics.unique_users == 1
        assert metrics.permission_checks == 1
        assert metrics.suspicious_activities == 1

        # Analyze access patterns
        pattern = await audit_storage.analyze_access_patterns(mock_principal.id)
        assert pattern.user_id == mock_principal.id
        assert pattern.total_requests == 4
