#!/usr/bin/env python3
"""
Token generator utility for testing mcp-auth-py
"""
import sys
from mcp_auth.settings import Settings

try:
    from jose import jwt
except ImportError:
    print("❌ python-jose not installed. Run: pip install python-jose[cryptography]")
    sys.exit(1)


def generate_local_token(user_id: str = "test-user", name: str = "Test User", 
                        email: str = None, roles: list = None):
    """Generate a local JWT token for testing"""
    settings = Settings()
    
    payload = {
        "sub": user_id,
        "name": name,
        "email": email or f"{user_id}@example.com",
    }
    
    if roles:
        payload["roles"] = roles
    
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate test tokens for mcp-auth-py")
    parser.add_argument("--user", "-u", default="test-user", help="User ID")
    parser.add_argument("--name", "-n", default="Test User", help="User name")
    parser.add_argument("--email", "-e", help="User email (defaults to user@example.com)")
    parser.add_argument("--roles", "-r", nargs="*", help="User roles")
    parser.add_argument("--format", "-f", choices=["token", "header", "curl"], 
                       default="token", help="Output format")
    
    args = parser.parse_args()
    
    try:
        token = generate_local_token(
            user_id=args.user,
            name=args.name, 
            email=args.email,
            roles=args.roles
        )
        
        if args.format == "token":
            print(token)
        elif args.format == "header":
            print(f"Authorization: Bearer {token}")
        elif args.format == "curl":
            print(f'curl -H "Authorization: Bearer {token}" http://localhost:8000/me')
            
    except Exception as e:
        print(f"❌ Error generating token: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
