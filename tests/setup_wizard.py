#!/usr/bin/env python3
"""
mcp-auth setup utility - Quick configuration for different auth providers
"""

import json
import os


def create_env_file(provider: str, config: dict):
    """Create .env file with provider-specific configuration"""
    env_content = f"""# mcp-auth-py configuration
AUTH_PROVIDER={provider}
PROVIDER_CONFIG='{json.dumps(config["provider_config"])}'
JWT_SECRET={config.get("jwt_secret", "your-jwt-secret-key")}
JWT_ALGORITHM=HS256

# Optional Redis JWKS caching
REDIS_JWKS={str(config.get("redis_jwks", False)).lower()}
"""

    if config.get("redis_url"):
        env_content += f"REDIS_URL={config['redis_url']}\n"

    with open(".env", "w") as f:
        f.write(env_content)

    print(f"✅ Created .env file for {provider} provider")


def setup_local():
    """Setup local JWT provider"""
    print("🔧 Setting up Local JWT Provider")

    jwt_secret = input("JWT Secret Key (leave blank for auto-generated): ").strip()
    if not jwt_secret:
        import secrets

        jwt_secret = secrets.token_urlsafe(32)
        print(f"Generated JWT secret: {jwt_secret}")

    config = {"provider_config": {}, "jwt_secret": jwt_secret}

    create_env_file("local", config)
    print("\n🎯 Local setup complete!")
    print("Test token generation:")
    token_cmd = (
        'python -c "import jwt; '
        f"print(jwt.encode({{'sub': 'test-user', 'name': 'Test User'}}, "
        f"'{jwt_secret}', algorithm='HS256'))\""
    )
    print(token_cmd)


def setup_google():
    """Setup Google OAuth2 provider"""
    print("🔧 Setting up Google OAuth2 Provider")
    print(
        "You'll need a Google OAuth2 Client ID from: https://console.cloud.google.com/"
    )

    client_id = input("Google Client ID: ").strip()
    if not client_id:
        print("❌ Client ID is required")
        return

    redis_jwks = input("Enable Redis JWKS caching? (y/N): ").lower().startswith("y")
    redis_url = None
    if redis_jwks:
        redis_url = (
            input("Redis URL (redis://localhost:6379/0): ").strip()
            or "redis://localhost:6379/0"
        )

    config = {
        "provider_config": {"audience": client_id},
        "redis_jwks": redis_jwks,
        "redis_url": redis_url,
    }

    create_env_file("google", config)
    print("\n🎯 Google setup complete!")
    print("Install the Google provider: pip install -e .[google]")


def setup_aws():
    """Setup AWS Cognito provider"""
    print("🔧 Setting up AWS Cognito Provider")
    print("You'll need AWS Cognito User Pool details")

    region = input("AWS Region (us-east-1): ").strip() or "us-east-1"
    user_pool_id = input("User Pool ID: ").strip()
    app_client_id = input("App Client ID: ").strip()

    if not user_pool_id or not app_client_id:
        print("❌ User Pool ID and App Client ID are required")
        return

    config = {
        "provider_config": {
            "region": region,
            "user_pool_id": user_pool_id,
            "app_client_id": app_client_id,
        }
    }

    create_env_file("aws", config)
    print("\n🎯 AWS setup complete!")
    print("Install the AWS provider: pip install -e .[aws]")


def setup_azure():
    """Setup Azure AD provider"""
    print("🔧 Setting up Azure AD Provider")
    print("You'll need Azure AD Application details")

    tenant_id = input("Azure Tenant ID: ").strip()
    client_id = input("Azure Client ID: ").strip()

    if not tenant_id or not client_id:
        print("❌ Tenant ID and Client ID are required")
        return

    config = {
        "provider_config": {
            "tenant_id": tenant_id,
            "client_id": client_id,
        }
    }

    create_env_file("azure", config)
    print("\n🎯 Azure setup complete!")
    print("Install the Azure provider: pip install -e .[azure]")


def setup_github():
    """Setup GitHub OAuth2 provider"""
    print("🔧 Setting up GitHub OAuth2 Provider")
    print(
        "You'll need a GitHub OAuth App from: https://github.com/settings/applications/new"
    )

    client_id = input("GitHub Client ID: ").strip()
    if not client_id:
        print("❌ Client ID is required")
        return

    client_secret = input(
        "GitHub Client Secret (optional for token validation): "
    ).strip()

    # Organization restrictions
    use_org_restrictions = (
        input("Restrict to specific organizations? (y/N): ").lower().startswith("y")
    )
    allowed_orgs = []
    if use_org_restrictions:
        orgs_input = input("Allowed organizations (comma-separated): ").strip()
        if orgs_input:
            allowed_orgs = [org.strip() for org in orgs_input.split(",")]

    provider_config = {"client_id": client_id, "scopes": ["user:email", "read:org"]}

    if client_secret:
        provider_config["client_secret"] = client_secret

    if allowed_orgs:
        provider_config["allowed_organizations"] = allowed_orgs

    config = {"provider_config": provider_config}

    create_env_file("github", config)
    print("\n🎯 GitHub setup complete!")
    print("GitHub provider is built-in, no additional installation required")


def setup_discord():
    """Setup Discord OAuth2 provider"""
    print("🔧 Setting up Discord OAuth2 Provider")
    print(
        "You'll need a Discord Application from: https://discord.com/developers/applications"
    )

    client_id = input("Discord Client ID: ").strip()
    if not client_id:
        print("❌ Client ID is required")
        return

    client_secret = input(
        "Discord Client Secret (optional for token validation): "
    ).strip()
    bot_token = input("Discord Bot Token (optional, for role verification): ").strip()

    # Guild restrictions
    use_guild_restrictions = (
        input("Restrict to specific Discord servers? (y/N): ").lower().startswith("y")
    )
    allowed_guilds = []
    if use_guild_restrictions:
        guilds_input = input("Allowed server IDs (comma-separated): ").strip()
        if guilds_input:
            allowed_guilds = [guild.strip() for guild in guilds_input.split(",")]

    provider_config = {
        "client_id": client_id,
        "scopes": ["identify", "email", "guilds"],
    }

    if client_secret:
        provider_config["client_secret"] = client_secret

    if bot_token:
        provider_config["bot_token"] = bot_token

    if allowed_guilds:
        provider_config["allowed_guilds"] = allowed_guilds

    config = {"provider_config": provider_config}

    create_env_file("discord", config)
    print("\n🎯 Discord setup complete!")
    print("Discord provider is built-in, no additional installation required")


def setup_enterprise():
    """Setup enterprise multi-tenant features"""
    print("🏢 Setting up Enterprise Multi-Tenant Features")

    tenant_strategy = input(
        "Tenant strategy (1=database_per_tenant, 2=schema_per_tenant, 3=row_level_security): "
    ).strip()
    strategies = {
        "1": "database_per_tenant",
        "2": "schema_per_tenant",
        "3": "row_level_security",
    }

    strategy = strategies.get(tenant_strategy, "row_level_security")

    redis_url = input(
        "Redis URL for multi-tenant cache (redis://localhost:6379/0): "
    ).strip()
    if not redis_url:
        redis_url = "redis://localhost:6379/0"

    # Add enterprise settings to .env
    enterprise_config = f"""

# Enterprise Multi-Tenant Configuration
TENANT_STRATEGY={strategy}
TENANT_RESOLVER=header  # header, subdomain, path, jwt
REDIS_URL={redis_url}

# Performance Monitoring
ENABLE_PERFORMANCE_MONITORING=true
PERFORMANCE_METRICS_RETENTION=3600

# Compliance Features
ENABLE_COMPLIANCE_MONITORING=true
ENABLED_STANDARDS=gdpr,hipaa,sox

# Advanced Security
ENABLE_CIRCUIT_BREAKER=true
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
CIRCUIT_BREAKER_TIMEOUT=60
"""

    # Append to existing .env or create new one
    mode = "a" if os.path.exists(".env") else "w"
    with open(".env", mode) as f:
        f.write(enterprise_config)

    print("\n🎯 Enterprise setup complete!")
    print("Install enterprise features: pip install -e .[enterprise]")


def main():
    print("🚀 mcp-auth-py Setup Utility")
    print("=" * 40)

    if os.path.exists(".env"):
        overwrite = (
            input("⚠️  .env file exists. Overwrite? (y/N): ").lower().startswith("y")
        )
        if not overwrite:
            print("Setup cancelled.")
            return

    print("\nChoose your authentication provider:")
    print("1. Local (JWT with secret key)")
    print("2. Google (OAuth2)")
    print("3. AWS (Cognito)")
    print("4. Azure (Active Directory)")
    print("5. GitHub (OAuth2)")
    print("6. Discord (OAuth2)")
    print("7. Enterprise (Multi-tenant)")

    choice = input("\nEnter choice (1-7): ").strip()

    providers = {
        "1": setup_local,
        "2": setup_google,
        "3": setup_aws,
        "4": setup_azure,
        "5": setup_github,
        "6": setup_discord,
        "7": setup_enterprise,
    }

    if choice in providers:
        providers[choice]()
        print("\n📝 Next steps:")
        print("1. Review your .env file")
        print("2. Add mcp-auth middleware to your FastAPI app")
        print("3. Check examples/ directory for usage patterns")

        if choice == "7":
            print("4. Review docs/enterprise_guide.md for advanced features")
            print("5. Set up tenant configurations and RBAC policies")
    else:
        print("❌ Invalid choice")


if __name__ == "__main__":
    main()
