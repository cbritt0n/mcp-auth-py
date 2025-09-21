"""
Production Security Middleware - FastAPI middleware for comprehensive security.

This module provides FastAPI middleware for production security features including:
- Rate limiting
- Security headers
- Request validation
- Login attempt tracking
- IP-based restrictions
"""

import logging
import time
from collections import defaultdict
from typing import Any, Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from .security import RateLimiter, SecurityMiddleware, SecurityValidationError
from .settings import Settings

logger = logging.getLogger(__name__)


class ProductionSecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware for production deployment"""

    def __init__(self, app: FastAPI, settings: Settings = None):
        super().__init__(app)
        self.settings = settings or Settings()
        self.rate_limiter = RateLimiter(
            max_requests=self.settings.rate_limit_requests_per_minute, window_seconds=60
        )

        # Security configuration
        self.enable_rate_limiting = self.settings.enable_rate_limiting
        self.enable_security_headers = self.settings.enable_security_headers
        self.require_https = self.settings.require_https

        logger.info("Production security middleware initialized")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with security checks"""

        try:
            # Pre-request security checks
            await self._pre_request_security(request)

            # Process the request
            start_time = time.time()
            response = await call_next(request)
            process_time = time.time() - start_time

            # Post-request security enhancements
            self._post_request_security(response, process_time)

            return response

        except SecurityValidationError as e:
            logger.warning("Security validation failed: %s", e.detail)
            return StarletteResponse(
                content=f'{{"detail": "{e.detail}"}}',
                status_code=e.status_code,
                media_type="application/json",
            )

        except Exception as e:
            logger.error("Security middleware error: %s", str(e))
            return StarletteResponse(
                content='{"detail": "Internal security error"}',
                status_code=500,
                media_type="application/json",
            )

    async def _pre_request_security(self, request: Request) -> None:
        """Pre-request security validation"""

        # HTTPS enforcement
        if self.require_https and request.url.scheme != "https":
            logger.warning("HTTP request blocked in HTTPS-only mode: %s", request.url)
            raise SecurityValidationError("HTTPS required", 400)

        # Rate limiting
        if self.enable_rate_limiting:
            await self.rate_limiter.check_rate_limit(request)

        # Request validation
        SecurityMiddleware.validate_request_security(request)

        # Log security-relevant requests
        if request.method in ["POST", "PUT", "DELETE"]:
            logger.info(
                "Security-relevant request: %s %s from %s",
                request.method,
                request.url.path,
                self._get_client_ip(request),
            )

    def _post_request_security(self, response: Response, process_time: float) -> None:
        """Post-request security enhancements"""

        # Add security headers
        if self.enable_security_headers:
            SecurityMiddleware.add_security_headers(response)

        # Add timing headers for monitoring
        response.headers["X-Process-Time"] = str(round(process_time, 4))

        # Rate limiting headers
        response.headers["X-RateLimit-Limit"] = str(self.rate_limiter.max_requests)
        response.headers["X-RateLimit-Window"] = str(self.rate_limiter.window_seconds)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        if request.client:
            return request.client.host

        return "unknown"


def setup_production_security(app: FastAPI, settings: Settings = None) -> None:
    """
    Setup comprehensive production security for FastAPI app.

    Args:
        app: FastAPI application instance
        settings: Optional settings override
    """
    settings = settings or Settings()

    # Add security middleware
    app.add_middleware(ProductionSecurityMiddleware, settings=settings)

    # Add CORS middleware with secure defaults if not already present
    try:
        from fastapi.middleware.cors import CORSMiddleware

        # Only add if not already present
        for middleware in app.middleware_stack:
            if isinstance(middleware, CORSMiddleware):
                break
        else:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://*"] if settings.require_https else ["*"],
                allow_credentials=True,
                allow_methods=["GET", "POST", "PUT", "DELETE"],
                allow_headers=["*"],
                max_age=600,  # 10 minutes
            )

    except ImportError:
        logger.warning("FastAPI CORS middleware not available")

    # Add trusted host middleware for production
    try:
        from fastapi.middleware.trustedhost import TrustedHostMiddleware

        if settings.require_https:
            # In production, specify your actual domains
            app.add_middleware(
                TrustedHostMiddleware,
                allowed_hosts=["*.yourdomain.com", "yourdomain.com"],
            )

    except ImportError:
        logger.warning("FastAPI TrustedHost middleware not available")

    # Add GZip compression for performance
    try:
        from fastapi.middleware.gzip import GZipMiddleware

        app.add_middleware(GZipMiddleware, minimum_size=1000)
    except ImportError:
        logger.warning("FastAPI GZip middleware not available")

    logger.info("Production security setup completed")


class SecurityMonitor:
    """Monitor and log security events for production analysis"""

    def __init__(self):
        self.security_events = defaultdict(int)
        self.start_time = time.time()

    def record_event(self, event_type: str, details: dict[str, Any] = None) -> None:
        """Record a security event"""
        self.security_events[event_type] += 1

        logger.info(
            "Security event: %s (total: %d) - %s",
            event_type,
            self.security_events[event_type],
            details or {},
        )

    def get_security_summary(self) -> dict[str, Any]:
        """Get security monitoring summary"""
        uptime = time.time() - self.start_time

        return {
            "uptime_seconds": uptime,
            "security_events": dict(self.security_events),
            "events_per_hour": {
                event_type: (count / (uptime / 3600)) if uptime > 0 else 0
                for event_type, count in self.security_events.items()
            },
            "total_events": sum(self.security_events.values()),
        }


# Global security monitor instance
_security_monitor = SecurityMonitor()


def get_security_monitor() -> SecurityMonitor:
    """Get global security monitor instance"""
    return _security_monitor
