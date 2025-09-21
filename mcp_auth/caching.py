"""
Advanced Caching System - Redis-based distributed caching for RBAC performance optimization.

This module provides comprehensive caching solutions for permission results, role lookups,
user assignments, and policy evaluations. It includes intelligent cache invalidation,
performance monitoring, and distributed cache coordination.
"""

import hashlib
import json
import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

try:
    import redis.asyncio as aioredis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    # Mock aioredis for type hints
    aioredis = None

# Check if RBAC is available for conditional imports
try:
    from .rbac.engine import get_rbac_engine

    _rbac_available = True
except ImportError:
    _rbac_available = False
    get_rbac_engine = None


logger = logging.getLogger(__name__)


class CacheKey:
    """Utility class for generating consistent cache keys"""

    VERSION = "v1"

    @staticmethod
    def _hash_key(*parts: str) -> str:
        """Create a hash from key parts for consistent short keys"""
        key_string = ":".join(str(part) for part in parts if part is not None)
        return hashlib.md5(key_string.encode(), usedforsecurity=False).hexdigest()[:16]

    @classmethod
    def permission_check(
        cls, user_id: str, resource: str, action: str, resource_id: Optional[str] = None
    ) -> str:
        """Generate cache key for permission checks"""
        parts = ["rbac", "perm", user_id, resource, action]
        if resource_id:
            parts.append(resource_id)
        key = ":".join(parts)
        # Add hash for very long keys
        if len(key) > 200:
            key = f"rbac:perm:{cls._hash_key(user_id, resource, action, resource_id or '')}"
        return key

    @classmethod
    def permission(
        cls, user_id: str, resource: str, action: str, resource_id: Optional[str] = None
    ) -> str:
        """Generate cache key for permission checks (alias for permission_check)"""
        return cls.permission_check(user_id, resource, action, resource_id)

    @classmethod
    def user(cls, user_id: str) -> str:
        """Generate cache key for user data"""
        return f"rbac:user:{user_id}"

    @classmethod
    def user_roles(cls, user_id: str) -> str:
        """Generate cache key for user roles"""
        return f"rbac:user_roles:{user_id}"

    @classmethod
    def user_permissions(cls, user_id: str) -> str:
        """Generate cache key for user permissions"""
        return f"rbac:user_perms:{user_id}"

    @classmethod
    def role_data(cls, role_name: str) -> str:
        """Generate cache key for role data"""
        return f"rbac:role:{role_name}"

    @classmethod
    def role(cls, role_name: str) -> str:
        """Generate cache key for role data (alias)"""
        return cls.role_data(role_name)

    @classmethod
    def bulk_permissions(cls, user_id: str, resource: str) -> str:
        """Generate cache key for bulk permissions"""
        return f"rbac:bulk_perms:{user_id}:{resource}"

    @classmethod
    def custom(cls, *parts: str) -> str:
        """Generate custom cache key"""
        return ":".join(parts)


class CacheStats:
    """Cache statistics tracking"""

    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.errors = 0
        self.total_time_ms = 0.0
        self.operations = defaultdict(int)
        self.start_time = time.time()
        self.last_updated = datetime.now()

    def record_hit(self, operation: str = "get", duration_ms: float = 0.0):
        self.hits += 1
        self.operations[operation] += 1
        self.total_time_ms += duration_ms
        self.last_updated = datetime.now()

    def record_miss(self, operation: str = "get", duration_ms: float = 0.0):
        self.misses += 1
        self.operations[operation] += 1
        self.total_time_ms += duration_ms
        self.last_updated = datetime.now()

    def record_set(self, duration_ms: float = 0.0):
        self.sets += 1
        self.operations["set"] += 1
        self.total_time_ms += duration_ms
        self.last_updated = datetime.now()

    def record_delete(self, duration_ms: float = 0.0):
        self.deletes += 1
        self.operations["delete"] += 1
        self.total_time_ms += duration_ms
        self.last_updated = datetime.now()

    def record_error(self, operation: str = "unknown"):
        self.errors += 1
        self.operations[f"{operation}_error"] += 1
        self.last_updated = datetime.now()

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total) if total > 0 else 0.0

    @property
    def avg_response_time_ms(self) -> float:
        total_ops = sum(self.operations.values())
        return (self.total_time_ms / total_ops) if total_ops > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "sets": self.sets,
            "deletes": self.deletes,
            "errors": self.errors,
            "hit_rate": self.hit_rate,
            "avg_response_time_ms": self.avg_response_time_ms,
            "total_operations": sum(self.operations.values()),
            "uptime_seconds": time.time() - self.start_time,
            "operations": dict(self.operations),
            "last_updated": self.last_updated,
        }


class DistributedCache:
    """Production-ready distributed cache with Redis backend"""

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "mcp_auth",
        default_ttl: int = 3600,
        max_memory_mb: int = 100,
        connection_pool_size: int = 10,
    ):
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self.default_ttl = default_ttl
        self.max_memory_mb = max_memory_mb
        self.connection_pool_size = connection_pool_size

        self._redis: Optional[Any] = None  # aioredis.Redis when available
        self._connection_pool: Optional[Any] = (
            None  # aioredis.ConnectionPool when available
        )
        self._stats = CacheStats()
        self._fallback_cache: dict[str, tuple[Any, float]] = {}
        self._initialized = False

    @property
    def redis(self):
        """Get redis instance for tests"""
        return self._redis

    async def initialize(self) -> None:
        """Initialize Redis connection"""
        if self._initialized:
            return

        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, using in-memory fallback cache")
            self._initialized = True
            return

        try:
            self._connection_pool = aioredis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=self.connection_pool_size,
                retry_on_timeout=True,
                socket_keepalive=True,
                socket_keepalive_options={},
                health_check_interval=30,
            )

            self._redis = aioredis.Redis(connection_pool=self._connection_pool)

            # Test connection
            await self._redis.ping()
            logger.info(f"Redis cache initialized successfully: {self.redis_url}")

        except Exception as e:
            logger.error(f"Failed to initialize Redis cache: {e}")
            self._redis = None
            self._connection_pool = None

        self._initialized = True

    def _make_key(self, key: str) -> str:
        """Create prefixed cache key"""
        return f"{self.key_prefix}:{key}"

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        start_time = time.time()
        prefixed_key = self._make_key(key)

        try:
            if self._redis:
                # Try Redis first
                value = await self._redis.get(prefixed_key)
                duration_ms = (time.time() - start_time) * 1000

                if value is not None:
                    self._stats.record_hit("get", duration_ms)
                    return json.loads(value)
                else:
                    self._stats.record_miss("get", duration_ms)
                    return None
            else:
                # Fallback to in-memory cache
                if prefixed_key in self._fallback_cache:
                    value, expiry = self._fallback_cache[prefixed_key]
                    if time.time() < expiry:
                        self._stats.record_hit(
                            "get_fallback", (time.time() - start_time) * 1000
                        )
                        return value
                    else:
                        # Expired
                        del self._fallback_cache[prefixed_key]

                self._stats.record_miss(
                    "get_fallback", (time.time() - start_time) * 1000
                )
                return None

        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            self._stats.record_error("get")
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        start_time = time.time()
        prefixed_key = self._make_key(key)
        ttl = ttl or self.default_ttl

        try:
            if self._redis:
                # Use Redis
                serialized = json.dumps(value, default=str)
                await self._redis.setex(prefixed_key, ttl, serialized)
                self._stats.record_set((time.time() - start_time) * 1000)
                return True
            else:
                # Fallback to in-memory cache
                expiry_time = time.time() + ttl
                self._fallback_cache[prefixed_key] = (value, expiry_time)

                # Simple LRU cleanup
                if len(self._fallback_cache) > 1000:
                    # Remove expired entries
                    current_time = time.time()
                    expired_keys = [
                        k
                        for k, (_, exp) in self._fallback_cache.items()
                        if current_time >= exp
                    ]
                    for k in expired_keys:
                        del self._fallback_cache[k]

                self._stats.record_set((time.time() - start_time) * 1000)
                return True

        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            self._stats.record_error("set")
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        start_time = time.time()
        prefixed_key = self._make_key(key)

        try:
            if self._redis:
                result = await self._redis.delete(prefixed_key)
                self._stats.record_delete((time.time() - start_time) * 1000)
                return result > 0
            else:
                # Fallback cache
                if prefixed_key in self._fallback_cache:
                    del self._fallback_cache[prefixed_key]
                    self._stats.record_delete((time.time() - start_time) * 1000)
                    return True
                return False

        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            self._stats.record_error("delete")
            return False

    async def mget(self, keys: list[str]) -> list[Optional[Any]]:
        """Get multiple values from cache"""
        if not keys:
            return []

        prefixed_keys = [self._make_key(key) for key in keys]

        try:
            if self._redis:
                values = await self._redis.mget(prefixed_keys)
                result = []
                for value in values:
                    if value is not None:
                        result.append(json.loads(value))
                        self._stats.record_hit("mget")
                    else:
                        result.append(None)
                        self._stats.record_miss("mget")
                return result
            else:
                # Fallback cache
                result = []
                current_time = time.time()
                for prefixed_key in prefixed_keys:
                    if prefixed_key in self._fallback_cache:
                        value, expiry = self._fallback_cache[prefixed_key]
                        if current_time < expiry:
                            result.append(value)
                            self._stats.record_hit("mget_fallback")
                        else:
                            del self._fallback_cache[prefixed_key]
                            result.append(None)
                            self._stats.record_miss("mget_fallback")
                    else:
                        result.append(None)
                        self._stats.record_miss("mget_fallback")
                return result

        except Exception as e:
            logger.error(f"Cache mget error: {e}")
            self._stats.record_error("mget")
            return [None] * len(keys)

    async def get_many(self, keys: list[str]) -> list[Optional[Any]]:
        """Alias for mget"""
        return await self.mget(keys)

    async def mset(self, data: dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Set multiple values in cache"""
        if not data:
            return True

        ttl = ttl or self.default_ttl

        try:
            if self._redis:
                pipeline = self._redis.pipeline()
                for key, value in data.items():
                    prefixed_key = self._make_key(key)
                    serialized = json.dumps(value, default=str)
                    pipeline.setex(prefixed_key, ttl, serialized)

                await pipeline.execute()
                self._stats.record_set()
                return True
            else:
                # Fallback cache
                expiry_time = time.time() + ttl
                for key, value in data.items():
                    prefixed_key = self._make_key(key)
                    self._fallback_cache[prefixed_key] = (value, expiry_time)

                self._stats.record_set()
                return True

        except Exception as e:
            logger.error(f"Cache mset error: {e}")
            self._stats.record_error("mset")
            return False

    async def set_many(self, data: dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Alias for mset"""
        return await self.mset(data, ttl)

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        try:
            if self._redis:
                # Use Redis SCAN for efficiency
                deleted = 0
                pattern_key = self._make_key(pattern)
                async for key in self._redis.scan_iter(match=pattern_key):
                    await self._redis.delete(key)
                    deleted += 1
                return deleted
            else:
                # Fallback cache pattern matching
                deleted = 0
                pattern_key = self._make_key(pattern.replace("*", ""))
                # Create a list of keys to avoid dictionary size change during iteration
                keys_to_delete = [
                    k for k in list(self._fallback_cache.keys()) if pattern_key in k
                ]
                for key in keys_to_delete:
                    if key in self._fallback_cache:  # Double-check key still exists
                        del self._fallback_cache[key]
                        deleted += 1
                return deleted

        except Exception as e:
            logger.error(f"Cache delete_pattern error for {pattern}: {e}")
            self._stats.record_error("delete_pattern")
            return 0

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        prefixed_key = self._make_key(key)

        try:
            if self._redis:
                return await self._redis.exists(prefixed_key) > 0
            else:
                if prefixed_key in self._fallback_cache:
                    _, expiry = self._fallback_cache[prefixed_key]
                    if time.time() < expiry:
                        return True
                    else:
                        del self._fallback_cache[prefixed_key]
                return False

        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False

    async def ping(self) -> bool:
        """Test cache connectivity"""
        try:
            if self._redis:
                await self._redis.ping()
                return True
            else:
                return True  # Fallback cache always "available"
        except Exception:
            return False

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics"""
        stats = self._stats.to_dict()
        stats.update(
            {
                "redis_available": self._redis is not None,
                "fallback_cache_size": len(self._fallback_cache),
                "cache_prefix": self.key_prefix,
                "default_ttl": self.default_ttl,
            }
        )
        return stats

    async def cleanup(self) -> None:
        """Cleanup cache resources"""
        if self._connection_pool:
            await self._connection_pool.disconnect()
        if self._fallback_cache:
            self._fallback_cache.clear()

    async def clear_all(self) -> int:
        """Clear all cache entries"""
        try:
            if self._redis:
                # Get all keys with our prefix
                pattern = f"{self.key_prefix}:*"
                deleted = 0
                async for key in self._redis.scan_iter(match=pattern):
                    await self._redis.delete(key)
                    deleted += 1
                return deleted
            else:
                # Clear fallback cache
                size = len(self._fallback_cache)
                self._fallback_cache.clear()
                return size
        except Exception as e:
            logger.error(f"Cache clear_all error: {e}")
            return 0

    async def invalidate_user_cache(self, user_id: str) -> int:
        """Invalidate all cache entries for a specific user"""
        patterns = [
            f"*user_roles:{user_id}*",
            f"*user_perms:{user_id}*",
            f"*user:{user_id}*",
            f"*perm:{user_id}:*",
        ]

        total_deleted = 0

        # For fallback cache, do direct pattern matching
        if not self._redis:
            keys_to_delete = []
            for key in list(self._fallback_cache.keys()):
                for pattern in patterns:
                    # Convert pattern to simple string matching
                    pattern_parts = pattern.split("*")
                    if (
                        len(pattern_parts) == 3
                        and pattern_parts[0] == ""
                        and pattern_parts[2] == ""
                    ):
                        # Pattern like "*user_roles:user123*"
                        if pattern_parts[1] in key:
                            keys_to_delete.append(key)
                            break
                    elif len(pattern_parts) == 2:
                        # Pattern like "*user:user123" or "perm:user123:*"
                        if pattern.startswith("*") and key.endswith(pattern[1:]):
                            keys_to_delete.append(key)
                            break
                        elif pattern.endswith("*") and key.startswith(pattern[:-1]):
                            keys_to_delete.append(key)
                            break

            for key in keys_to_delete:
                if key in self._fallback_cache:
                    del self._fallback_cache[key]
                    total_deleted += 1
        else:
            # Use Redis pattern deletion
            for pattern in patterns:
                deleted = await self.delete_pattern(pattern)
                total_deleted += deleted

        return total_deleted

    async def invalidate_role_cache(self, role_name: str) -> int:
        """Invalidate all cache entries for a specific role"""
        patterns = [
            f"*role:{role_name}*",
            "*bulk_perms:*",  # Role changes affect all bulk permissions
        ]

        total_deleted = 0

        # For fallback cache, do direct pattern matching
        if not self._redis:
            keys_to_delete = []
            for key in list(self._fallback_cache.keys()):
                for pattern in patterns:
                    # Convert pattern to simple string matching
                    pattern_parts = pattern.split("*")
                    if (
                        len(pattern_parts) == 3
                        and pattern_parts[0] == ""
                        and pattern_parts[2] == ""
                    ):
                        # Pattern like "*role:admin*"
                        if pattern_parts[1] in key:
                            keys_to_delete.append(key)
                            break
                    elif len(pattern_parts) == 2:
                        # Pattern like "*bulk_perms:"
                        if pattern.startswith("*") and key.endswith(pattern[1:]):
                            keys_to_delete.append(key)
                            break
                        elif pattern.endswith("*") and key.startswith(pattern[:-1]):
                            keys_to_delete.append(key)
                            break

            for key in keys_to_delete:
                if key in self._fallback_cache:
                    del self._fallback_cache[key]
                    total_deleted += 1
        else:
            # Use Redis pattern deletion
            for pattern in patterns:
                deleted = await self.delete_pattern(pattern)
                total_deleted += deleted

        return total_deleted


class CachedRBACMixin:
    """Mixin to add caching capabilities to RBAC engine"""

    def __init__(self, *args, cache: Optional[DistributedCache] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache = cache
        self._cache_enabled = cache is not None

    async def cached_has_permission(
        self,
        user_id: str,
        resource: str,
        action: str,
        resource_id: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
        ttl: Optional[int] = None,
    ) -> bool:
        """Check permission with caching"""
        if not self._cache_enabled:
            return self.has_permission(user_id, resource, action, resource_id, context)

        # Generate cache key
        cache_key = CacheKey.permission_check(user_id, resource, action, resource_id)

        # Try cache first
        cached_result = await self.cache.get(cache_key)
        if cached_result is not None:
            return cached_result.get("allowed", False)

        # Not in cache, check permission
        result = self.has_permission(user_id, resource, action, resource_id, context)

        # Cache the result
        await self.cache.set(cache_key, {"allowed": result}, ttl)

        return result

    async def cached_get_user_roles(
        self, user_id: str, ttl: Optional[int] = None
    ) -> list[str]:
        """Get user roles with caching"""
        if not self._cache_enabled:
            return self.get_user_roles(user_id)

        cache_key = CacheKey.user_roles(user_id)

        # Try cache first
        cached_roles = await self.cache.get(cache_key)
        if cached_roles is not None:
            return cached_roles

        # Not in cache, get from engine
        roles = self.get_user_roles(user_id)

        # Cache the result
        await self.cache.set(cache_key, roles, ttl)

        return roles

    async def cached_get_user_permissions(
        self, user_id: str, ttl: Optional[int] = None
    ) -> list[str]:
        """Get user permissions with caching"""
        if not self._cache_enabled:
            return self.get_user_permissions(user_id)

        cache_key = CacheKey.user_permissions(user_id)

        # Try cache first
        cached_permissions = await self.cache.get(cache_key)
        if cached_permissions is not None:
            return cached_permissions

        # Not in cache, get from engine
        permissions = self.get_user_permissions(user_id)

        # Cache the result
        await self.cache.set(cache_key, permissions, ttl)

        return permissions

    async def invalidate_user(self, user_id: str) -> None:
        """Invalidate all cache entries for a user"""
        if not self._cache_enabled:
            return

        # Delete user-specific patterns
        patterns = [
            f"*:{user_id}:*",  # Any key containing user_id
            f"user:{user_id}:*",
            f"user_roles:{user_id}:*",
            f"user_permissions:{user_id}:*",
            f"permission:{user_id}:*",
        ]

        for pattern in patterns:
            await self.cache.delete_pattern(pattern)


# Global cache instance
_global_cache: Optional[DistributedCache] = None


def get_cache() -> Optional[DistributedCache]:
    """Get the global cache instance"""
    return _global_cache


async def initialize_cache(
    redis_url: str = "redis://localhost:6379/0",
    key_prefix: str = "mcp_auth",
    default_ttl: int = 3600,
    max_memory_mb: int = 100,
) -> DistributedCache:
    """Initialize the global cache system"""
    global _global_cache

    _global_cache = DistributedCache(
        redis_url=redis_url,
        key_prefix=key_prefix,
        default_ttl=default_ttl,
        max_memory_mb=max_memory_mb,
    )

    await _global_cache.initialize()
    return _global_cache


async def setup_caching_system(
    redis_url: str = "redis://localhost:6379/0",
    key_prefix: str = "mcp_auth",
    default_ttl: int = 3600,
    max_memory_mb: int = 100,
) -> DistributedCache:
    """
    Setup the distributed caching system

    Args:
        redis_url: Redis connection URL
        key_prefix: Cache key prefix
        default_ttl: Default TTL for cache entries in seconds
        max_memory_mb: Maximum memory usage for cache

    Returns:
        Configured DistributedCache instance
    """
    return await initialize_cache(redis_url, key_prefix, default_ttl, max_memory_mb)


def enable_rbac_caching(app):
    """
    Enable RBAC caching on a FastAPI app

    Args:
        app: FastAPI application instance
    """
    # This is handled by the CachedRBACMixin
    # Just ensure cache is initialized
    pass


# Cache-aware permission checking helper
async def check_permission_cached(
    user_id: str,
    resource: str,
    action: str,
    resource_id: Optional[str] = None,
    context: Optional[dict[str, Any]] = None,
    ttl: Optional[int] = None,
) -> bool:
    """Standalone cached permission check function"""
    cache = get_cache()

    if not cache:
        # Fallback to direct engine call - only if RBAC is available
        try:
            from .rbac.engine import get_rbac_engine

            engine = get_rbac_engine()
            return engine.has_permission(
                user_id, resource, action, resource_id, context
            )
        except ImportError:
            # RBAC not available, return False for safety
            return False

    # Use cached approach
    cache_key = CacheKey.permission_check(user_id, resource, action, resource_id)

    # Try cache first
    cached_result = await cache.get(cache_key)
    if cached_result is not None:
        return cached_result.get("allowed", False)

    # Fallback to engine - only if RBAC is available
    try:
        from .rbac.engine import get_rbac_engine

        engine = get_rbac_engine()
        result = engine.has_permission(user_id, resource, action, resource_id, context)

        # Cache result
        await cache.set(cache_key, {"allowed": result}, ttl=ttl)

        return result
    except ImportError:
        # RBAC not available, return False for safety
        return False
