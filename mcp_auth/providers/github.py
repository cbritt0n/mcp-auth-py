"""
GitHub OAuth2 Provider for mcp-auth-py

This provider implements GitHub OAuth2 authentication with support for:
- Public GitHub.com authentication
- GitHub Enterprise Server
- Organization membership verification
- Team-based authorization
- Fine-grained personal access tokens
"""

import logging
from typing import Any, Dict, List, Optional

import httpx
from fastapi import HTTPException

from ..models import Principal
from .base import Provider

logger = logging.getLogger(__name__)


class GitHubProvider(Provider):
    """GitHub OAuth2 authentication provider"""

    provider_name = "github"

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize GitHub provider

        Args:
            config: Configuration dictionary containing:
                - client_id: GitHub OAuth App client ID
                - client_secret: GitHub OAuth App client secret (for server-side)
                - base_url: GitHub base URL (default: https://github.com)
                - api_base_url: GitHub API base URL (default: https://api.github.com)
                - allowed_organizations: Optional list of allowed GitHub organizations
                - required_teams: Optional dict of org -> teams mapping
                - scopes: OAuth scopes to request (default: user:email)
        """
        super().__init__(config)

        self.client_id = config["client_id"]
        self.client_secret = config.get("client_secret")
        self.base_url = config.get("base_url", "https://github.com")
        self.api_base_url = config.get("api_base_url", "https://api.github.com")
        self.allowed_organizations = config.get("allowed_organizations", [])
        self.required_teams = config.get("required_teams", {})
        self.scopes = config.get("scopes", ["user:email"])

        # GitHub Enterprise Server support
        if self.base_url != "https://github.com":
            self.api_base_url = f"{self.base_url}/api/v3"

    async def validate_token(self, token: str) -> Principal:
        """
        Validate GitHub access token and return user principal

        Args:
            token: GitHub access token

        Returns:
            Principal with user information

        Raises:
            HTTPException: If token validation fails
        """
        try:
            async with httpx.AsyncClient() as client:
                # Get user information
                user_response = await client.get(
                    f"{self.api_base_url}/user",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": "mcp-auth-py/1.0",
                    },
                    timeout=10.0,
                )
                user_response.raise_for_status()
                user_data = user_response.json()

                # Get user email if not public
                email = user_data.get("email")
                if not email:
                    email_response = await client.get(
                        f"{self.api_base_url}/user/emails",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/vnd.github.v3+json",
                            "User-Agent": "mcp-auth-py/1.0",
                        },
                        timeout=10.0,
                    )
                    if email_response.status_code == 200:
                        emails = email_response.json()
                        primary_email = next(
                            (e["email"] for e in emails if e.get("primary")), None
                        )
                        if primary_email:
                            email = primary_email

                # Verify organization membership if required
                organizations = []
                if self.allowed_organizations:
                    orgs_response = await client.get(
                        f"{self.api_base_url}/user/orgs",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/vnd.github.v3+json",
                            "User-Agent": "mcp-auth-py/1.0",
                        },
                        timeout=10.0,
                    )
                    if orgs_response.status_code == 200:
                        user_orgs = orgs_response.json()
                        organizations = [org["login"] for org in user_orgs]

                        # Check if user belongs to allowed organizations
                        allowed_orgs = set(self.allowed_organizations)
                        user_org_set = set(organizations)
                        if not allowed_orgs.intersection(user_org_set):
                            raise HTTPException(
                                status_code=403,
                                detail=f"User not member of allowed organizations: {self.allowed_organizations}",
                            )

                # Get team memberships if required
                teams = []
                roles = []
                if self.required_teams:
                    for org, required_teams in self.required_teams.items():
                        if org in organizations:
                            teams_response = await client.get(
                                f"{self.api_base_url}/user/teams",
                                headers={
                                    "Authorization": f"Bearer {token}",
                                    "Accept": "application/vnd.github.v3+json",
                                    "User-Agent": "mcp-auth-py/1.0",
                                },
                                timeout=10.0,
                            )
                            if teams_response.status_code == 200:
                                user_teams = teams_response.json()
                                org_teams = [
                                    team["slug"]
                                    for team in user_teams
                                    if team["organization"]["login"] == org
                                ]
                                teams.extend(org_teams)

                                # Check required team membership
                                required_team_set = set(required_teams)
                                user_team_set = set(org_teams)
                                if not required_team_set.intersection(user_team_set):
                                    raise HTTPException(
                                        status_code=403,
                                        detail=f"User not member of required teams in {org}: {required_teams}",
                                    )

                # Map GitHub data to roles
                if organizations:
                    roles.extend([f"github_org_{org}" for org in organizations])
                if teams:
                    roles.extend([f"github_team_{team}" for team in teams])

                # Add admin role for organization owners
                for org in organizations:
                    membership_response = await client.get(
                        f"{self.api_base_url}/orgs/{org}/memberships/{user_data['login']}",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/vnd.github.v3+json",
                            "User-Agent": "mcp-auth-py/1.0",
                        },
                        timeout=10.0,
                    )
                    if membership_response.status_code == 200:
                        membership = membership_response.json()
                        if membership.get("role") == "admin":
                            roles.append(f"github_org_admin_{org}")

                # Create principal
                principal = Principal(
                    id=f"github_{user_data['id']}",
                    name=user_data.get("name") or user_data["login"],
                    email=email,
                    provider=self.provider_name,
                    roles=roles,
                    attributes={
                        "github_login": user_data["login"],
                        "github_id": user_data["id"],
                        "github_avatar_url": user_data.get("avatar_url"),
                        "github_profile_url": user_data.get("html_url"),
                        "github_organizations": organizations,
                        "github_teams": teams,
                        "github_account_type": user_data.get("type", "User"),
                        "github_company": user_data.get("company"),
                        "github_location": user_data.get("location"),
                        "github_bio": user_data.get("bio"),
                        "github_public_repos": user_data.get("public_repos"),
                        "github_followers": user_data.get("followers"),
                        "github_following": user_data.get("following"),
                    },
                )

                logger.info(f"Successfully validated GitHub user: {user_data['login']}")
                return principal

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise HTTPException(status_code=401, detail="Invalid GitHub token")
            elif e.response.status_code == 403:
                # Check if it's a rate limit
                if "X-RateLimit-Remaining" in e.response.headers:
                    if int(e.response.headers["X-RateLimit-Remaining"]) == 0:
                        reset_time = e.response.headers.get("X-RateLimit-Reset")
                        raise HTTPException(
                            status_code=429,
                            detail=f"GitHub API rate limit exceeded. Reset at: {reset_time}",
                        )
                raise HTTPException(status_code=403, detail="GitHub API access denied")
            else:
                logger.error(
                    f"GitHub API error: {e.response.status_code} - {e.response.text}"
                )
                raise HTTPException(
                    status_code=500, detail="GitHub authentication failed"
                )

        except httpx.TimeoutException:
            logger.error("Timeout connecting to GitHub API")
            raise HTTPException(status_code=504, detail="GitHub API timeout")

        except Exception as e:
            logger.error(f"Unexpected error during GitHub authentication: {str(e)}")
            raise HTTPException(status_code=500, detail="Authentication error")

    async def get_authorization_url(
        self, redirect_uri: str, state: Optional[str] = None
    ) -> str:
        """
        Generate GitHub OAuth authorization URL

        Args:
            redirect_uri: Callback URL after authorization
            state: Optional state parameter for security

        Returns:
            Authorization URL
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes),
            "response_type": "code",
        }

        if state:
            params["state"] = state

        # Add organization preference if configured
        if self.allowed_organizations and len(self.allowed_organizations) == 1:
            params["login"] = self.allowed_organizations[0]

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{self.base_url}/login/oauth/authorize?{query_string}"

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token

        Args:
            code: Authorization code from GitHub
            redirect_uri: Same redirect URI used in authorization

        Returns:
            Token response dictionary
        """
        if not self.client_secret:
            raise ValueError("Client secret required for code exchange")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/login/oauth/access_token",
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "code": code,
                        "redirect_uri": redirect_uri,
                    },
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "mcp-auth-py/1.0",
                    },
                    timeout=10.0,
                )
                response.raise_for_status()
                return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(
                f"GitHub token exchange failed: {e.response.status_code} - {e.response.text}"
            )
            raise HTTPException(
                status_code=400, detail="Failed to exchange code for token"
            )

        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {str(e)}")
            raise HTTPException(status_code=500, detail="Token exchange failed")

    async def revoke_token(self, token: str) -> bool:
        """
        Revoke GitHub access token

        Args:
            token: Access token to revoke

        Returns:
            True if successful
        """
        if not self.client_secret:
            return False

        try:
            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    f"{self.api_base_url}/applications/{self.client_id}/token",
                    json={"access_token": token},
                    auth=(self.client_id, self.client_secret),
                    headers={
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": "mcp-auth-py/1.0",
                    },
                    timeout=10.0,
                )
                return response.status_code == 204

        except Exception as e:
            logger.warning(f"Failed to revoke GitHub token: {str(e)}")
            return False

    def get_provider_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for provider configuration"""
        return {
            "type": "object",
            "properties": {
                "client_id": {
                    "type": "string",
                    "description": "GitHub OAuth App client ID",
                },
                "client_secret": {
                    "type": "string",
                    "description": "GitHub OAuth App client secret (optional for validation-only)",
                },
                "base_url": {
                    "type": "string",
                    "default": "https://github.com",
                    "description": "GitHub base URL (use for GitHub Enterprise Server)",
                },
                "api_base_url": {
                    "type": "string",
                    "default": "https://api.github.com",
                    "description": "GitHub API base URL",
                },
                "allowed_organizations": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of allowed GitHub organizations",
                },
                "required_teams": {
                    "type": "object",
                    "description": "Required team memberships per organization",
                },
                "scopes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["user:email"],
                    "description": "OAuth scopes to request",
                },
            },
            "required": ["client_id"],
        }


# Helper functions for GitHub integration


async def get_github_user_repositories(
    token: str, api_base_url: str = "https://api.github.com"
) -> List[Dict[str, Any]]:
    """
    Get user's GitHub repositories

    Args:
        token: GitHub access token
        api_base_url: GitHub API base URL

    Returns:
        List of repository information
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{api_base_url}/user/repos",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "mcp-auth-py/1.0",
            },
            params={"per_page": 100, "sort": "updated", "direction": "desc"},
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()


async def check_github_repository_access(
    token: str,
    owner: str,
    repo: str,
    permission: str = "read",
    api_base_url: str = "https://api.github.com",
) -> bool:
    """
    Check if user has specific permission on a repository

    Args:
        token: GitHub access token
        owner: Repository owner
        repo: Repository name
        permission: Permission level (read, write, admin)
        api_base_url: GitHub API base URL

    Returns:
        True if user has permission
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{api_base_url}/repos/{owner}/{repo}/collaborators/permissions",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "mcp-auth-py/1.0",
                },
                timeout=10.0,
            )

            if response.status_code == 200:
                data = response.json()
                user_permission = data.get("permission", "none")

                # Permission hierarchy: read < write < admin
                permission_levels = {"read": 1, "write": 2, "admin": 3}
                required_level = permission_levels.get(permission, 0)
                user_level = permission_levels.get(user_permission, 0)

                return user_level >= required_level

            return False

    except Exception:
        return False


# Example usage and configuration helpers


def create_github_provider_config(
    client_id: str,
    client_secret: Optional[str] = None,
    allowed_organizations: Optional[List[str]] = None,
    required_teams: Optional[Dict[str, List[str]]] = None,
    enterprise_server_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Helper function to create GitHub provider configuration

    Args:
        client_id: GitHub OAuth App client ID
        client_secret: GitHub OAuth App client secret
        allowed_organizations: List of allowed GitHub organizations
        required_teams: Required team memberships per organization
        enterprise_server_url: GitHub Enterprise Server URL

    Returns:
        Provider configuration dictionary
    """
    config = {"client_id": client_id, "scopes": ["user:email", "read:org"]}

    if client_secret:
        config["client_secret"] = client_secret

    if allowed_organizations:
        config["allowed_organizations"] = allowed_organizations

    if required_teams:
        config["required_teams"] = required_teams

    if enterprise_server_url:
        config["base_url"] = enterprise_server_url
        config["api_base_url"] = f"{enterprise_server_url}/api/v3"

    return config


# Integration with mcp-auth RBAC system


def setup_github_rbac_integration():
    """
    Example setup for GitHub-based RBAC integration

    This function shows how to map GitHub organizations and teams to RBAC roles.
    """
    from ..rbac.engine import get_rbac_engine
    from ..rbac.models import Permission, Role

    rbac_engine = get_rbac_engine()

    # Create GitHub organization-based roles
    github_member_role = Role(
        name="github_member",
        description="Member of GitHub organization",
        permissions=[
            Permission.from_string("repositories:read"),
            Permission.from_string("issues:read"),
            Permission.from_string("pull_requests:read"),
        ],
    )
    rbac_engine.add_role(github_member_role)

    # Create GitHub team-based roles
    github_admin_role = Role(
        name="github_admin",
        description="GitHub organization admin",
        permissions=[
            Permission.from_string("repositories:*"),
            Permission.from_string("issues:*"),
            Permission.from_string("pull_requests:*"),
            Permission.from_string("admin:*"),
        ],
    )
    rbac_engine.add_role(github_admin_role)

    # Auto-assign roles based on GitHub attributes
    def assign_github_roles(principal):
        """Automatically assign roles based on GitHub attributes"""
        github_orgs = principal.attributes.get("github_organizations", [])
        github_teams = principal.attributes.get("github_teams", [])

        roles = []

        # Assign organization member role
        if github_orgs:
            roles.append("github_member")

        # Assign admin role for organization admins
        for role in principal.roles:
            if role.startswith("github_org_admin_"):
                roles.append("github_admin")
                break

        # Assign team-specific roles
        if "maintainers" in github_teams:
            roles.append("github_admin")
        elif "contributors" in github_teams:
            roles.append("github_member")

        return roles

    return assign_github_roles
