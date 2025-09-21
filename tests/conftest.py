import asyncio
import importlib.util
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# Ensure project root is on sys.path so tests can import the package under test
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Minimal BaseSettings shim for tests when 'pydantic-settings' is not installed.
if importlib.util.find_spec("pydantic_settings") is None:

    class BaseSettings:
        """Minimal shim: uses class attributes as defaults and allows
        overrides via constructor.
        """

        def __init__(self, **kwargs):
            for name, val in self.__class__.__dict__.items():
                if (
                    name.startswith("_")
                    or callable(val)
                    or isinstance(val, (staticmethod, classmethod))
                ):
                    continue
                setattr(self, name, val)
            for k, v in kwargs.items():
                setattr(self, k, v)

    # expose for tests/modules importing BaseSettings from pydantic_settings
    import types

    sys.modules.setdefault(
        "pydantic_settings", types.SimpleNamespace(BaseSettings=BaseSettings)
    )


# Configure pytest-asyncio
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


class MockPubSub:
    """Mock Redis PubSub for testing"""

    def __init__(self):
        self.subscriptions = set()

    async def subscribe(self, channel):
        self.subscriptions.add(channel)

    async def listen(self):
        """Mock listen that yields test messages"""
        # Return empty generator for tests
        return
        yield  # pragma: no cover


class MockRedis:
    """Mock Redis for testing without actual Redis dependency"""

    def __init__(self):
        self.data = {}
        self.expired_keys = set()

    async def ping(self):
        return True

    async def pubsub(self):
        """Mock pubsub for testing"""
        return MockPubSub()

    async def get(self, key):
        if key in self.expired_keys:
            return None
        return self.data.get(key)

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.data:
            return False
        self.data[key] = value
        return True

    async def setex(self, key, time, value):
        self.data[key] = value
        return True

    async def delete(self, *keys):
        deleted = 0
        for key in keys:
            if key in self.data:
                del self.data[key]
                deleted += 1
        return deleted

    async def keys(self, pattern):
        # Simple pattern matching for tests
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return [key for key in self.data.keys() if key.startswith(prefix)]
        return [key for key in self.data.keys() if key == pattern]

    async def exists(self, key):
        return 1 if key in self.data else 0

    async def mget(self, keys):
        return [self.data.get(key) for key in keys]

    def pipeline(self):
        return MockRedisPipeline(self)

    async def scan_iter(self, match=None):
        """Mock scan_iter for pattern matching"""
        if match:
            if match.endswith("*"):
                prefix = match[:-1]
                for key in list(self.data.keys()):
                    if key.startswith(prefix):
                        yield key
            else:
                if match in self.data:
                    yield match
        else:
            for key in list(self.data.keys()):
                yield key


class MockRedisPipeline:
    """Mock Redis pipeline for testing"""

    def __init__(self, redis_mock):
        self.redis = redis_mock
        self.commands = []

    def setex(self, key, time, value):
        self.commands.append(("setex", key, time, value))
        return self

    def set(self, key, value, ex=None):
        self.commands.append(("set", key, value, ex))
        return self

    async def execute(self):
        results = []
        for cmd in self.commands:
            if cmd[0] == "setex":
                result = await self.redis.setex(cmd[1], cmd[2], cmd[3])
                results.append(result)
            elif cmd[0] == "set":
                result = await self.redis.set(cmd[1], cmd[2], ex=cmd[3])
                results.append(result)
        return results


@pytest_asyncio.fixture
async def mock_redis():
    """Mock Redis instance for testing"""
    mock = MockRedis()
    # Make ping and other methods callable for tests
    mock.ping = AsyncMock(return_value=True)
    mock.pubsub = MagicMock(return_value=MockPubSub())
    return mock


class MockAuditStorage:
    """Mock audit storage for testing"""

    def __init__(self):
        self.events = []
        self._event_id_counter = 1000

    async def store_event(self, event):
        """Store an audit event"""
        event_id = f"event_{self._event_id_counter}"
        self._event_id_counter += 1
        self.events.append((event_id, event))
        return event_id

    async def query_events(self, filter_criteria):
        """Query audit events with filtering"""
        return [event for _, event in self.events]

    def get_stored_events(self):
        """Get all stored events for testing"""
        return self.events


# Audit storage fixture
@pytest.fixture
def audit_storage():
    """Create audit storage for testing"""
    return MockAuditStorage()


# Cache instance fixture
@pytest_asyncio.fixture
async def cache_instance(mock_redis):
    """Cache instance with mocked Redis"""
    import mcp_auth.caching
    from mcp_auth.caching import DistributedCache

    cache = DistributedCache(redis_url="redis://test:6379")

    # Mock Redis availability and initialization
    with patch.object(mcp_auth.caching, "REDIS_AVAILABLE", True):
        with patch.object(mcp_auth.caching, "aioredis") as mock_aioredis:
            # Setup mock connection pool
            mock_pool = MagicMock()
            mock_aioredis.ConnectionPool.from_url.return_value = mock_pool
            mock_aioredis.Redis.return_value = mock_redis

            await cache.initialize()

            # Override the redis instance directly
            cache._redis = mock_redis

    return cache
