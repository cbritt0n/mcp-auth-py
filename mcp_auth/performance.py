"""
Performance Monitoring and Optimization for mcp-auth-py

This module provides comprehensive performance monitoring, caching optimization,
and scalability features for high-performance authentication deployments.
"""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Optional, Union

from pydantic import BaseModel

try:
    import redis.asyncio as aioredis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None

logger = logging.getLogger(__name__)


class MetricType(str, Enum):
    """Types of performance metrics"""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class PerformanceMetric(BaseModel):
    """Performance metric model"""

    name: str
    type: MetricType
    value: Union[int, float]
    timestamp: datetime
    tags: dict[str, str] = {}
    tenant_id: Optional[str] = None


class CacheStrategy(str, Enum):
    """Caching strategies"""

    LRU = "lru"
    LFU = "lfu"
    TTL = "ttl"
    WRITE_THROUGH = "write_through"
    WRITE_BEHIND = "write_behind"


class CircuitBreakerState(str, Enum):
    """Circuit breaker states"""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class PerformanceMonitor:
    """Real-time performance monitoring system"""

    def __init__(self, redis_url: Optional[str] = None, retention_period: int = 3600):
        self.redis_url = redis_url
        self.redis = None
        self.retention_period = retention_period

        # In-memory metrics storage
        self._metrics: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._counters: dict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = defaultdict(float)
        self._timers: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Performance thresholds
        self._thresholds = {
            "auth_latency_ms": 100,
            "cache_hit_rate": 0.8,
            "error_rate": 0.01,
            "throughput_rps": 1000,
        }

        # Alert callbacks
        self._alert_callbacks: list[Callable] = []

        self._lock = None

    def _ensure_lock(self):
        """Ensure async lock is initialized"""
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def initialize(self):
        """Initialize performance monitor"""
        self._ensure_lock()

        if REDIS_AVAILABLE and self.redis_url:
            try:
                self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
                await self.redis.ping()
                logger.info("Performance monitor initialized with Redis backend")
            except Exception as e:
                logger.warning(f"Redis initialization failed: {e}")

        # Start background cleanup task
        asyncio.create_task(self._cleanup_old_metrics())

    async def record_metric(
        self,
        name: str,
        metric_type: MetricType,
        value: Union[int, float],
        tags: Optional[dict[str, str]] = None,
        tenant_id: Optional[str] = None,
    ):
        """Record a performance metric"""

        metric = PerformanceMetric(
            name=name,
            type=metric_type,
            value=value,
            timestamp=datetime.utcnow(),
            tags=tags or {},
            tenant_id=tenant_id,
        )

        # Store in memory
        self._metrics[name].append(metric)

        if metric_type == MetricType.COUNTER:
            self._counters[name] += value
        elif metric_type == MetricType.GAUGE:
            self._gauges[name] = value
        elif metric_type == MetricType.TIMER:
            self._timers[name].append(value)

        # Store in Redis if available
        if self.redis:
            try:
                pipe = self.redis.pipeline()
                pipe.zadd(f"metrics:{name}", {metric.json(): time.time()})
                pipe.expire(f"metrics:{name}", self.retention_period)
                await pipe.execute()
            except Exception as e:
                logger.warning(f"Failed to store metric in Redis: {e}")

        # Check thresholds and trigger alerts
        await self._check_thresholds(name, value, metric_type)

    async def get_metric_stats(
        self, name: str, time_range: int = 300  # 5 minutes
    ) -> dict[str, Any]:
        """Get statistics for a metric"""

        cutoff_time = datetime.utcnow() - timedelta(seconds=time_range)
        recent_metrics = [m for m in self._metrics[name] if m.timestamp > cutoff_time]

        if not recent_metrics:
            return {"name": name, "count": 0}

        values = [m.value for m in recent_metrics]

        stats = {
            "name": name,
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "sum": sum(values),
            "latest": values[-1] if values else 0,
            "time_range_seconds": time_range,
        }

        # Calculate percentiles for timers/histograms
        if recent_metrics[0].type in [MetricType.TIMER, MetricType.HISTOGRAM]:
            sorted_values = sorted(values)
            count = len(sorted_values)
            if count > 0:
                stats.update(
                    {
                        "p50": sorted_values[int(count * 0.5)],
                        "p90": sorted_values[int(count * 0.9)],
                        "p95": sorted_values[int(count * 0.95)],
                        "p99": sorted_values[int(count * 0.99)],
                    }
                )

        return stats

    async def get_dashboard_data(
        self, tenant_id: Optional[str] = None
    ) -> dict[str, Any]:
        """Get performance dashboard data"""

        dashboard = {
            "timestamp": datetime.utcnow().isoformat(),
            "tenant_id": tenant_id,
            "metrics": {},
            "alerts": [],
            "system_health": "healthy",
        }

        # Key metrics
        key_metrics = [
            "auth_requests_total",
            "auth_latency_ms",
            "cache_hit_rate",
            "error_rate",
            "active_sessions",
        ]

        for metric_name in key_metrics:
            if metric_name in self._metrics:
                stats = await self.get_metric_stats(metric_name)
                dashboard["metrics"][metric_name] = stats

        # System health assessment
        health_score = await self._calculate_health_score()
        if health_score < 0.8:
            dashboard["system_health"] = "degraded"
        elif health_score < 0.6:
            dashboard["system_health"] = "unhealthy"

        return dashboard

    async def _calculate_health_score(self) -> float:
        """Calculate overall system health score"""

        scores = []

        # Authentication latency score
        if "auth_latency_ms" in self._timers:
            recent_latencies = list(self._timers["auth_latency_ms"])
            if recent_latencies:
                avg_latency = sum(recent_latencies) / len(recent_latencies)
                latency_score = max(0, 1 - (avg_latency / 500))  # Normalize to 500ms
                scores.append(latency_score)

        # Cache hit rate score
        if "cache_hits" in self._counters and "cache_misses" in self._counters:
            hits = self._counters["cache_hits"]
            misses = self._counters["cache_misses"]
            total = hits + misses
            if total > 0:
                hit_rate = hits / total
                scores.append(hit_rate)

        # Error rate score
        if "requests_total" in self._counters and "errors_total" in self._counters:
            total = self._counters["requests_total"]
            errors = self._counters["errors_total"]
            if total > 0:
                error_rate = errors / total
                error_score = max(0, 1 - error_rate * 100)  # Normalize error rate
                scores.append(error_score)

        return sum(scores) / len(scores) if scores else 1.0

    async def _check_thresholds(
        self, metric_name: str, value: Union[int, float], metric_type: MetricType
    ):
        """Check if metric value exceeds thresholds"""

        threshold = self._thresholds.get(metric_name)
        if not threshold:
            return

        alert_triggered = False

        if metric_name == "auth_latency_ms" and value > threshold:
            alert_triggered = True
            alert_type = "high_latency"
        elif metric_name == "error_rate" and value > threshold:
            alert_triggered = True
            alert_type = "high_error_rate"
        elif metric_name == "cache_hit_rate" and value < threshold:
            alert_triggered = True
            alert_type = "low_cache_hit_rate"

        if alert_triggered:
            alert = {
                "type": alert_type,
                "metric": metric_name,
                "value": value,
                "threshold": threshold,
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "warning",
            }

            # Trigger alert callbacks
            for callback in self._alert_callbacks:
                try:
                    await callback(alert)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")

    def add_alert_callback(self, callback: Callable):
        """Add alert callback function"""
        self._alert_callbacks.append(callback)

    async def _cleanup_old_metrics(self):
        """Background task to clean up old metrics"""
        while True:
            try:
                cutoff_time = datetime.utcnow() - timedelta(
                    seconds=self.retention_period
                )

                # Clean up in-memory metrics
                for metric_queue in self._metrics.values():
                    while metric_queue and metric_queue[0].timestamp < cutoff_time:
                        metric_queue.popleft()

                await asyncio.sleep(300)  # Clean up every 5 minutes

            except Exception as e:
                logger.error(f"Metrics cleanup error: {e}")
                await asyncio.sleep(60)


class OptimizedCache:
    """High-performance cache with multiple strategies"""

    def __init__(
        self,
        strategy: CacheStrategy = CacheStrategy.LRU,
        max_size: int = 10000,
        ttl_seconds: int = 3600,
        redis_url: Optional[str] = None,
    ):
        self.strategy = strategy
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.redis_url = redis_url
        self.redis = None

        # Local cache storage
        self._cache: dict[str, Any] = {}
        self._access_times: dict[str, float] = {}
        self._access_counts: dict[str, int] = defaultdict(int)
        self._expiry_times: dict[str, float] = {}

        # Performance tracking
        self._hits = 0
        self._misses = 0
        self._lock = None

    def _ensure_lock(self):
        """Ensure async lock is initialized"""
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def initialize(self):
        """Initialize optimized cache"""
        self._ensure_lock()

        if REDIS_AVAILABLE and self.redis_url:
            try:
                self.redis = aioredis.from_url(self.redis_url, decode_responses=False)
                await self.redis.ping()
                logger.info("Optimized cache initialized with Redis backend")
            except Exception as e:
                logger.warning(f"Redis initialization failed: {e}")

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""

        current_time = time.time()

        # Check local cache first
        if key in self._cache:
            # Check TTL expiration
            if key in self._expiry_times and current_time > self._expiry_times[key]:
                await self._evict(key)
                self._misses += 1
                return None

            # Update access tracking
            self._access_times[key] = current_time
            self._access_counts[key] += 1
            self._hits += 1

            return self._cache[key]

        # Check Redis if available
        if self.redis:
            try:
                redis_value = await self.redis.get(key)
                if redis_value:
                    # Deserialize and cache locally
                    value = json.loads(redis_value.decode("utf-8"))
                    await self.set(key, value, from_redis=True)
                    self._hits += 1
                    return value
            except Exception as e:
                logger.warning(f"Redis get error: {e}")

        self._misses += 1
        return None

    async def set(
        self, key: str, value: Any, ttl: Optional[int] = None, from_redis: bool = False
    ):
        """Set value in cache"""

        async with self._lock:
            current_time = time.time()
            ttl = ttl or self.ttl_seconds

            # Ensure cache size limit
            if len(self._cache) >= self.max_size:
                await self._make_room()

            # Store in local cache
            self._cache[key] = value
            self._access_times[key] = current_time
            self._access_counts[key] = 1

            if ttl > 0:
                self._expiry_times[key] = current_time + ttl

            # Store in Redis if available and not coming from Redis
            if self.redis and not from_redis:
                try:
                    serialized = json.dumps(value, default=str)
                    if ttl > 0:
                        await self.redis.setex(key, ttl, serialized)
                    else:
                        await self.redis.set(key, serialized)
                except Exception as e:
                    logger.warning(f"Redis set error: {e}")

    async def delete(self, key: str):
        """Delete value from cache"""

        await self._evict(key)

        if self.redis:
            try:
                await self.redis.delete(key)
            except Exception as e:
                logger.warning(f"Redis delete error: {e}")

    async def clear(self):
        """Clear entire cache"""

        async with self._lock:
            self._cache.clear()
            self._access_times.clear()
            self._access_counts.clear()
            self._expiry_times.clear()

        if self.redis:
            try:
                await self.redis.flushdb()
            except Exception as e:
                logger.warning(f"Redis clear error: {e}")

    async def _make_room(self):
        """Evict items based on strategy to make room"""

        if self.strategy == CacheStrategy.LRU:
            # Evict least recently used
            if self._access_times:
                oldest_key = min(self._access_times, key=self._access_times.get)
                await self._evict(oldest_key)

        elif self.strategy == CacheStrategy.LFU:
            # Evict least frequently used
            if self._access_counts:
                least_used_key = min(self._access_counts, key=self._access_counts.get)
                await self._evict(least_used_key)

        elif self.strategy == CacheStrategy.TTL:
            # Evict expired items first
            current_time = time.time()
            expired_keys = [
                key
                for key, expiry in self._expiry_times.items()
                if expiry <= current_time
            ]

            if expired_keys:
                for key in expired_keys:
                    await self._evict(key)
            else:
                # Fall back to LRU if no expired items
                if self._access_times:
                    oldest_key = min(self._access_times, key=self._access_times.get)
                    await self._evict(oldest_key)

    async def _evict(self, key: str):
        """Remove key from all tracking structures"""

        self._cache.pop(key, None)
        self._access_times.pop(key, None)
        self._access_counts.pop(key, None)
        self._expiry_times.pop(key, None)

    async def get_stats(self) -> dict[str, Any]:
        """Get cache performance statistics"""

        total_requests = self._hits + self._misses
        hit_rate = self._hits / total_requests if total_requests > 0 else 0

        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": hit_rate,
            "total_requests": total_requests,
            "cache_size": len(self._cache),
            "max_size": self.max_size,
            "strategy": self.strategy,
            "memory_usage_bytes": sum(
                len(str(k)) + len(str(v)) for k, v in self._cache.items()
            ),
        }


class CircuitBreaker:
    """Circuit breaker pattern for fault tolerance"""

    def __init__(
        self,
        failure_threshold: int = 5,
        timeout_seconds: int = 60,
        expected_exception: type = Exception,
    ):
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.expected_exception = expected_exception

        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self._lock = None

    def _ensure_lock(self):
        """Ensure async lock is initialized"""
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def call(self, func: Callable, *args, **kwargs):
        """Execute function through circuit breaker"""

        self._ensure_lock()

        async with self._lock:
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitBreakerState.HALF_OPEN
                    logger.info("Circuit breaker moving to HALF_OPEN state")
                else:
                    raise Exception("Circuit breaker is OPEN")

        try:
            result = (
                await func(*args, **kwargs)
                if asyncio.iscoroutinefunction(func)
                else func(*args, **kwargs)
            )
            await self._on_success()
            return result

        except self.expected_exception as e:
            await self._on_failure()
            raise e

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self.last_failure_time is None:
            return True

        return time.time() - self.last_failure_time >= self.timeout_seconds

    async def _on_success(self):
        """Handle successful execution"""
        async with self._lock:
            self.failure_count = 0
            if self.state == CircuitBreakerState.HALF_OPEN:
                self.state = CircuitBreakerState.CLOSED
                logger.info("Circuit breaker moved to CLOSED state")

    async def _on_failure(self):
        """Handle failed execution"""
        async with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                self.state = CircuitBreakerState.OPEN
                logger.warning(
                    f"Circuit breaker opened after {self.failure_count} failures"
                )


class PerformanceMiddleware:
    """ASGI middleware for performance monitoring"""

    def __init__(self, app, performance_monitor: PerformanceMonitor):
        self.app = app
        self.monitor = performance_monitor

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            start_time = time.time()

            # Wrap send to capture response
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    # Record response time
                    duration_ms = (time.time() - start_time) * 1000

                    await self.monitor.record_metric(
                        "request_duration_ms",
                        MetricType.TIMER,
                        duration_ms,
                        tags={
                            "path": scope.get("path", "unknown"),
                            "method": scope.get("method", "unknown"),
                            "status": str(message.get("status", 0)),
                        },
                    )

                    # Record total requests
                    await self.monitor.record_metric(
                        "requests_total",
                        MetricType.COUNTER,
                        1,
                        tags={
                            "path": scope.get("path", "unknown"),
                            "method": scope.get("method", "unknown"),
                        },
                    )

                    # Record errors
                    status_code = message.get("status", 200)
                    if status_code >= 400:
                        await self.monitor.record_metric(
                            "errors_total",
                            MetricType.COUNTER,
                            1,
                            tags={
                                "path": scope.get("path", "unknown"),
                                "status": str(status_code),
                            },
                        )

                await send(message)

            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)


# Performance testing utilities


class LoadTester:
    """Built-in load testing utility"""

    def __init__(self, base_url: str, concurrency: int = 10):
        self.base_url = base_url
        self.concurrency = concurrency
        self.results = []

    async def run_test(
        self,
        endpoints: list[dict[str, Any]],
        duration_seconds: int = 60,
        ramp_up_seconds: int = 10,
    ) -> dict[str, Any]:
        """Run load test against specified endpoints"""

        import httpx

        start_time = time.time()
        end_time = start_time + duration_seconds
        ramp_up_end = start_time + ramp_up_seconds

        tasks = []
        semaphore = asyncio.Semaphore(self.concurrency)

        async def make_request(endpoint: dict[str, Any]):
            async with semaphore:
                async with httpx.AsyncClient() as client:
                    try:
                        request_start = time.time()

                        response = await client.request(
                            method=endpoint.get("method", "GET"),
                            url=f"{self.base_url}{endpoint['path']}",
                            headers=endpoint.get("headers", {}),
                            json=endpoint.get("data"),
                            timeout=30.0,
                        )

                        request_time = (time.time() - request_start) * 1000

                        result = {
                            "endpoint": endpoint["path"],
                            "method": endpoint.get("method", "GET"),
                            "status_code": response.status_code,
                            "response_time_ms": request_time,
                            "timestamp": time.time(),
                            "success": 200 <= response.status_code < 400,
                        }

                        self.results.append(result)

                    except Exception as e:
                        result = {
                            "endpoint": endpoint["path"],
                            "method": endpoint.get("method", "GET"),
                            "error": str(e),
                            "response_time_ms": 0,
                            "timestamp": time.time(),
                            "success": False,
                        }
                        self.results.append(result)

        # Generate load
        while time.time() < end_time:
            current_time = time.time()

            # Ramp up concurrency gradually
            if current_time < ramp_up_end:
                active_concurrency = int(
                    self.concurrency * (current_time - start_time) / ramp_up_seconds
                )
            else:
                active_concurrency = self.concurrency

            # Launch requests for each endpoint
            for endpoint in endpoints:
                if len(tasks) < active_concurrency:
                    task = asyncio.create_task(make_request(endpoint))
                    tasks.append(task)

            # Clean up completed tasks
            tasks = [task for task in tasks if not task.done()]

            await asyncio.sleep(0.1)  # Small delay to prevent tight loop

        # Wait for remaining tasks
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Calculate statistics
        return self._calculate_stats()

    def _calculate_stats(self) -> dict[str, Any]:
        """Calculate load test statistics"""

        if not self.results:
            return {"error": "No results available"}

        successful_results = [r for r in self.results if r["success"]]
        failed_results = [r for r in self.results if not r["success"]]

        response_times = [r["response_time_ms"] for r in successful_results]

        if response_times:
            sorted_times = sorted(response_times)
            count = len(sorted_times)

            percentiles = {
                "p50": sorted_times[int(count * 0.5)] if count > 0 else 0,
                "p90": sorted_times[int(count * 0.9)] if count > 0 else 0,
                "p95": sorted_times[int(count * 0.95)] if count > 0 else 0,
                "p99": sorted_times[int(count * 0.99)] if count > 0 else 0,
            }

            avg_response_time = sum(response_times) / len(response_times)
        else:
            percentiles = {"p50": 0, "p90": 0, "p95": 0, "p99": 0}
            avg_response_time = 0

        total_requests = len(self.results)
        successful_requests = len(successful_results)
        failed_requests = len(failed_results)

        # Calculate throughput
        if self.results:
            test_duration = max(r["timestamp"] for r in self.results) - min(
                r["timestamp"] for r in self.results
            )
            throughput = total_requests / test_duration if test_duration > 0 else 0
        else:
            throughput = 0

        return {
            "summary": {
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "success_rate": (
                    successful_requests / total_requests if total_requests > 0 else 0
                ),
                "throughput_rps": throughput,
                "avg_response_time_ms": avg_response_time,
            },
            "response_times": percentiles,
            "errors": [r for r in failed_results if "error" in r],
            "detailed_results": self.results,
        }
