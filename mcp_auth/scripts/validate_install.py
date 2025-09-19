#!/usr/bin/env python3
"""
Quick validation script to test mcp-auth-py installation
"""
import sys
import asyncio

def test_basic_imports():
    """Test that core modules can be imported"""
    try:
        from mcp_auth.settings import Settings
        from mcp_auth.models import Principal
        from mcp_auth.providers.local import LocalProvider
        from mcp_auth.middleware import AuthMiddleware
        print("✅ Core imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False


def test_local_provider():
    """Test local provider functionality"""
    try:
        from mcp_auth.providers.local import LocalProvider
        from mcp_auth.settings import Settings
        from mcp_auth.providers.base import AuthResult
        
        settings = Settings(jwt_secret="test-secret")
        provider = LocalProvider(settings)
        
        # Create a mock request object
        class MockRequest:
            def __init__(self, auth_header=None):
                self.headers = {"authorization": auth_header} if auth_header else {}
        
        # Test invalid token
        mock_request = MockRequest("Bearer invalid-token")
        result = provider.authenticate(mock_request)
        
        if not isinstance(result, AuthResult):
            print("❌ Provider should return AuthResult")
            return False
            
        if result.valid:
            print("❌ Local provider should reject invalid tokens")
            return False
        
        print("✅ Local provider working correctly")
        return True
    except Exception as e:
        print(f"❌ Local provider test failed: {e}")
        return False


async def test_async_capabilities():
    """Test async authentication flow"""
    try:
        from mcp_auth.providers.local import LocalProvider
        from mcp_auth.settings import Settings
        from mcp_auth.providers.base import AuthResult
        import inspect
        
        settings = Settings(jwt_secret="test-secret")
        provider = LocalProvider(settings)
        
        class MockRequest:
            def __init__(self, auth_header=None):
                self.headers = {"authorization": auth_header} if auth_header else {}
        
        mock_request = MockRequest("Bearer invalid-token")
        result = provider.authenticate(mock_request)
        
        # Check if the method is async-capable
        if inspect.iscoroutine(result):
            result = await result
        
        if not isinstance(result, AuthResult):
            print("❌ Async auth should return AuthResult")
            return False
            
        if result.valid:
            print("❌ Async auth should reject invalid tokens") 
            return False
        
        print("✅ Authentication flow working")
        return True
    except Exception as e:
        print(f"❌ Auth test failed: {e}")
        return False


def test_optional_dependencies():
    """Check which optional providers are available"""
    available = []
    
    # Test Google provider
    try:
        from mcp_auth.providers.google import GoogleProvider
        available.append("google")
    except ImportError:
        pass
    
    # Test AWS provider
    try:
        from mcp_auth.providers.aws import AWSProvider
        available.append("aws")
    except ImportError:
        pass
    
    # Test Azure provider
    try:
        from mcp_auth.providers.azure import AzureProvider
        available.append("azure")
    except ImportError:
        pass
    
    # Test Redis JWKS
    try:
        from mcp_auth.providers.redis_jwks import RedisJWKSCache
        available.append("redis_jwks")
    except ImportError:
        pass
    
    print(f"📦 Available providers: {', '.join(available) if available else 'local only'}")
    return True


def main():
    """Run all validation tests"""
    print("🧪 Testing mcp-auth-py installation...")
    print("=" * 50)
    
    tests = [
        test_basic_imports,
        test_local_provider, 
        test_optional_dependencies,
    ]
    
    passed = 0
    for test in tests:
        if test():
            passed += 1
    
    # Run async test
    try:
        if asyncio.run(test_async_capabilities()):
            passed += 1
    except Exception as e:
        print(f"❌ Async test failed: {e}")
    
    print("=" * 50)
    print(f"✅ {passed}/{len(tests) + 1} tests passed")
    
    if passed == len(tests) + 1:
        print("🎉 mcp-auth-py is ready to use!")
        print("\nNext steps:")
        print("  1. Run: mcp-auth-setup  # Interactive setup")
        print("  2. Check examples/ directory for usage patterns")
        print("  3. See DEPLOYMENT.md for production setup")
        print("  4. Generate tokens: mcp-auth-generate-token --help")
    else:
        print("⚠️  Some tests failed. Check your installation.")
        sys.exit(1)


if __name__ == "__main__":
    main()