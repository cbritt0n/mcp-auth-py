#!/usr/bin/env python3
"""
Production readiness validation script for mcp-auth-py
"""

import importlib
import os
import sys

# Add the parent directory to Python path so we can import mcp_auth
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List, Tuple


def test_imports() -> List[Tuple[str, bool, str]]:
    """Test all core module imports"""
    results = []

    modules_to_test = [
        ("mcp_auth", "Core package"),
        ("mcp_auth.settings", "Settings management"),
        ("mcp_auth.providers", "Provider system"),
        ("mcp_auth.providers.local", "Local JWT provider"),
        ("mcp_auth.providers.google", "Google OAuth2 provider"),
        ("mcp_auth.providers.aws", "AWS Cognito provider"),
        ("mcp_auth.providers.azure", "Azure AD provider"),
        ("mcp_auth.providers.github", "GitHub OAuth2 provider"),
        ("mcp_auth.providers.discord", "Discord OAuth2 provider"),
        ("mcp_auth.middleware", "ASGI middleware"),
        ("mcp_auth.models", "Data models"),
        ("mcp_auth.setup", "Application setup"),
        ("mcp_auth.rbac", "RBAC system"),
        ("mcp_auth.audit", "Audit logging"),
        ("mcp_auth.caching", "Caching system"),
        ("mcp_auth.realtime", "Real-time features"),
        ("mcp_auth.enterprise", "Enterprise multi-tenancy"),
        ("mcp_auth.enterprise.compliance", "Compliance monitoring"),
        ("mcp_auth.performance", "Performance monitoring"),
    ]

    for module_name, description in modules_to_test:
        try:
            importlib.import_module(module_name)
            results.append((description, True, "✅ OK"))
        except ImportError as e:
            results.append((description, False, f"❌ FAIL: {e}"))
        except Exception as e:
            results.append((description, False, f"⚠️  ERROR: {e}"))

    return results


def test_settings() -> Tuple[bool, str]:
    """Test settings configuration"""
    try:
        from mcp_auth.settings import Settings

        # Test basic settings
        settings = Settings(
            auth_provider="local",
            jwt_secret="test-secret-key-for-validation",
            provider_config={},
        )

        # Test provider config parsing
        settings_json = Settings(
            auth_provider="local",
            jwt_secret="test-key",
            provider_config='{"test": "value"}',  # JSON string
        )

        if settings_json.provider_config == {"test": "value"}:
            return True, "✅ Settings validation passed"
        else:
            return False, "❌ Provider config parsing failed"

    except Exception as e:
        return False, f"❌ Settings test failed: {e}"


def test_providers() -> List[Tuple[str, bool, str]]:
    """Test provider instantiation"""
    results = []

    try:
        from mcp_auth.providers.local import LocalProvider
        from mcp_auth.settings import Settings

        settings = Settings(
            auth_provider="local",
            jwt_secret="test-secret-key-for-validation",
            provider_config={},
        )

        provider = LocalProvider(settings)
        results.append(("Local provider instantiation", True, "✅ OK"))

    except Exception as e:
        results.append(("Local provider instantiation", False, f"❌ FAIL: {e}"))

    return results


def main():
    """Run all validation tests"""
    print("🔍 mcp-auth-py Production Readiness Validation")
    print("=" * 50)

    # Test imports
    print("\n📦 Module Import Tests:")
    import_results = test_imports()
    for description, success, message in import_results:
        print(f"  {message:<50} {description}")

    import_success_count = sum(1 for _, success, _ in import_results if success)
    print(
        f"\n📊 Import Results: {import_success_count}/{len(import_results)} modules imported successfully"
    )

    # Test settings
    print("\n⚙️  Settings Configuration Tests:")
    settings_success, settings_message = test_settings()
    print(f"  {settings_message}")

    # Test providers
    print("\n🔐 Provider Instantiation Tests:")
    provider_results = test_providers()
    for description, success, message in provider_results:
        print(f"  {message:<50} {description}")

    # Overall results
    print("\n" + "=" * 50)

    total_tests = len(import_results) + 1 + len(provider_results)
    passed_tests = (
        import_success_count
        + (1 if settings_success else 0)
        + sum(1 for _, success, _ in provider_results if success)
    )

    if passed_tests == total_tests:
        print("🎉 ALL TESTS PASSED - Ready for production deployment!")
        print("\n📋 Next Steps:")
        print("  1. Run: python tests/setup_wizard.py")
        print("  2. Configure your .env file")
        print("  3. Deploy with Docker or Kubernetes")
        print("  4. Check examples/ for usage patterns")
        return 0
    else:
        print(f"⚠️  {passed_tests}/{total_tests} tests passed - Review failures above")
        print("\n🔧 Troubleshooting:")
        print("  1. Install missing dependencies: pip install -e .[full]")
        print("  2. Check Python version compatibility (>=3.9)")
        print("  3. Review error messages above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
