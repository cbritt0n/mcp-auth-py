"""
Discord OAuth2 Provider for mcp-auth-py

This provider implements Discord OAuth2 authentication with support for:
- Discord application authentication
- Server (guild) membership verification
- Role-based authorization from Discord servers
- Bot integration for advanced permissions
"""

import logging
from typing import Any, Optional

import httpx
from fastapi import HTTPException

from ..models import Principal
from .base import Provider

logger = logging.getLogger(__name__)


class DiscordProvider(Provider):
    """Discord OAuth2 authentication provider"""

    provider_name = "discord"

    def __init__(self, config: dict[str, Any]):
        """
        Initialize Discord provider

        Args:
            config: Configuration dictionary containing:
                - client_id: Discord application client ID
                - client_secret: Discord application client secret
                - bot_token: Optional Discord bot token for guild verification
                - allowed_guilds: Optional list of allowed Discord server IDs
                - required_roles: Optional dict of guild_id -> role_names mapping
                - scopes: OAuth scopes to request (default: identify, email)
        """
        super().__init__(config)

        self.client_id = config["client_id"]
        self.client_secret = config.get("client_secret")
        self.bot_token = config.get("bot_token")
        self.allowed_guilds = config.get("allowed_guilds", [])
        self.required_roles = config.get("required_roles", {})
        self.scopes = config.get("scopes", ["identify", "email"])

        self.api_base_url = "https://discord.com/api/v10"

    async def validate_token(self, token: str) -> Principal:
        """
        Validate Discord access token and return user principal

        Args:
            token: Discord access token

        Returns:
            Principal with user information

        Raises:
            HTTPException: If token validation fails
        """
        try:
            async with httpx.AsyncClient() as client:
                # Get user information
                user_response = await client.get(
                    f"{self.api_base_url}/users/@me",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "User-Agent": "mcp-auth-py/1.0",
                    },
                    timeout=10.0,
                )
                user_response.raise_for_status()
                user_data = user_response.json()

                # Get user's guilds if guild restrictions are configured
                guilds = []
                user_guild_roles = {}
                roles = []

                if self.allowed_guilds or self.required_roles:
                    # Get user's guilds
                    guilds_response = await client.get(
                        f"{self.api_base_url}/users/@me/guilds",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "User-Agent": "mcp-auth-py/1.0",
                        },
                        timeout=10.0,
                    )

                    if guilds_response.status_code == 200:
                        user_guilds = guilds_response.json()
                        guilds = [guild["id"] for guild in user_guilds]

                        # Check allowed guilds restriction
                        if self.allowed_guilds:
                            allowed_set = set(self.allowed_guilds)
                            user_guild_set = set(guilds)
                            if not allowed_set.intersection(user_guild_set):
                                raise HTTPException(
                                    status_code=403,
                                    detail="User not member of allowed Discord servers",
                                )

                        # Get detailed guild information with roles using bot token
                        if self.bot_token and self.required_roles:
                            user_guild_roles = await self._get_user_guild_roles(
                                user_data["id"], guilds
                            )

                            # Check required roles
                            for guild_id, required_roles in self.required_roles.items():
                                if guild_id in guilds:
                                    user_roles_in_guild = user_guild_roles.get(
                                        guild_id, []
                                    )
                                    required_set = set(required_roles)
                                    user_role_set = set(user_roles_in_guild)
                                    if not required_set.intersection(user_role_set):
                                        raise HTTPException(
                                            status_code=403,
                                            detail=f"User missing required roles in Discord server {guild_id}",
                                        )

                        # Map Discord guilds to roles
                        for guild in user_guilds:
                            roles.append(f"discord_guild_{guild['id']}")

                            # Add admin role if user has admin permissions
                            if (
                                guild.get("permissions", 0) & 0x8
                            ):  # Administrator permission
                                roles.append(f"discord_guild_admin_{guild['id']}")

                            # Add owner role
                            if guild.get("owner"):
                                roles.append(f"discord_guild_owner_{guild['id']}")

                        # Add role-based roles
                        for guild_id, guild_roles in user_guild_roles.items():
                            for role_name in guild_roles:
                                roles.append(
                                    f"discord_role_{guild_id}_{role_name.lower()}"
                                )

                # Determine user type and add relevant roles
                if user_data.get("premium_type"):  # Discord Nitro user
                    roles.append("discord_nitro")

                if user_data.get("system"):  # Discord system user
                    roles.append("discord_system")

                if user_data.get("bot"):  # Bot account
                    roles.append("discord_bot")

                # Create principal
                principal = Principal(
                    id=f"discord_{user_data['id']}",
                    name=(
                        f"{user_data['username']}#{user_data['discriminator']}"
                        if user_data.get("discriminator") != "0"
                        else user_data["username"]
                    ),
                    email=user_data.get("email"),
                    provider=self.provider_name,
                    roles=roles,
                    attributes={
                        "discord_id": user_data["id"],
                        "discord_username": user_data["username"],
                        "discord_discriminator": user_data.get("discriminator"),
                        "discord_global_name": user_data.get("global_name"),
                        "discord_avatar": user_data.get("avatar"),
                        "discord_avatar_url": self._get_avatar_url(user_data),
                        "discord_banner": user_data.get("banner"),
                        "discord_accent_color": user_data.get("accent_color"),
                        "discord_locale": user_data.get("locale"),
                        "discord_premium_type": user_data.get("premium_type"),
                        "discord_public_flags": user_data.get("public_flags"),
                        "discord_verified": user_data.get("verified", False),
                        "discord_mfa_enabled": user_data.get("mfa_enabled", False),
                        "discord_guilds": guilds,
                        "discord_guild_roles": user_guild_roles,
                    },
                )

                logger.info(
                    f"Successfully validated Discord user: {user_data['username']}"
                )
                return principal

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise HTTPException(status_code=401, detail="Invalid Discord token")
            elif e.response.status_code == 429:
                # Rate limited
                retry_after = e.response.headers.get("Retry-After", "60")
                raise HTTPException(
                    status_code=429,
                    detail=f"Discord API rate limited. Retry after {retry_after} seconds",
                )
            else:
                logger.error(
                    f"Discord API error: {e.response.status_code} - {e.response.text}"
                )
                raise HTTPException(
                    status_code=500, detail="Discord authentication failed"
                )

        except httpx.TimeoutException:
            logger.error("Timeout connecting to Discord API")
            raise HTTPException(status_code=504, detail="Discord API timeout")

        except Exception as e:
            logger.error(f"Unexpected error during Discord authentication: {str(e)}")
            raise HTTPException(status_code=500, detail="Authentication error")

    async def _get_user_roles_in_guilds(
        self, user_id: str, guild_ids: list[str]
    ) -> dict[str, list[str]]:
        """
        Get user's roles in specified guilds using bot token

        Args:
            user_id: Discord user ID
            guild_ids: List of guild IDs to check

        Returns:
            Dictionary mapping guild_id to list of role names
        """
        if not self.bot_token:
            return {}

        guild_roles = {}

        async with httpx.AsyncClient() as client:
            for guild_id in guild_ids:
                try:
                    # Get guild member information
                    member_response = await client.get(
                        f"{self.api_base_url}/guilds/{guild_id}/members/{user_id}",
                        headers={
                            "Authorization": f"Bot {self.bot_token}",
                            "User-Agent": "mcp-auth-py/1.0",
                        },
                        timeout=10.0,
                    )

                    if member_response.status_code == 200:
                        member_data = member_response.json()
                        role_ids = member_data.get("roles", [])

                        if role_ids:
                            # Get guild roles to map IDs to names
                            roles_response = await client.get(
                                f"{self.api_base_url}/guilds/{guild_id}/roles",
                                headers={
                                    "Authorization": f"Bot {self.bot_token}",
                                    "User-Agent": "mcp-auth-py/1.0",
                                },
                                timeout=10.0,
                            )

                            if roles_response.status_code == 200:
                                guild_roles_data = roles_response.json()
                                role_map = {
                                    role["id"]: role["name"]
                                    for role in guild_roles_data
                                }

                                user_role_names = [
                                    role_map[role_id]
                                    for role_id in role_ids
                                    if role_id in role_map
                                ]
                                guild_roles[guild_id] = user_role_names

                except Exception as e:
                    logger.warning(
                        f"Failed to get roles for guild {guild_id}: {str(e)}"
                    )
                    continue

        return guild_roles

    def _get_avatar_url(self, user_data: dict[str, Any]) -> Optional[str]:
        """Generate Discord avatar URL from user data"""
        if not user_data.get("avatar"):
            # Default avatar
            discriminator = user_data.get("discriminator", "0")
            if discriminator == "0":
                # New username system
                index = (int(user_data["id"]) >> 22) % 6
            else:
                # Legacy discriminator system
                index = int(discriminator) % 5
            return f"https://cdn.discordapp.com/embed/avatars/{index}.png"

        # Custom avatar
        user_id = user_data["id"]
        avatar_hash = user_data["avatar"]
        extension = "gif" if avatar_hash.startswith("a_") else "png"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{extension}"

    async def get_authorization_url(
        self, redirect_uri: str, state: Optional[str] = None
    ) -> str:
        """
        Generate Discord OAuth authorization URL

        Args:
            redirect_uri: Callback URL after authorization
            state: Optional state parameter for security

        Returns:
            Authorization URL
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
        }

        if state:
            params["state"] = state

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"https://discord.com/oauth2/authorize?{query_string}"

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str
    ) -> dict[str, Any]:
        """
        Exchange authorization code for access token

        Args:
            code: Authorization code from Discord
            redirect_uri: Same redirect URI used in authorization

        Returns:
            Token response dictionary
        """
        if not self.client_secret:
            raise ValueError("Client secret required for code exchange")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_base_url}/oauth2/token",
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": redirect_uri,
                    },
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "mcp-auth-py/1.0",
                    },
                    timeout=10.0,
                )
                response.raise_for_status()
                return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(
                f"Discord token exchange failed: {e.response.status_code} - {e.response.text}"
            )
            raise HTTPException(
                status_code=400, detail="Failed to exchange code for token"
            )

        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {str(e)}")
            raise HTTPException(status_code=500, detail="Token exchange failed")

    async def revoke_token(self, token: str) -> bool:
        """
        Revoke Discord access token

        Args:
            token: Access token to revoke

        Returns:
            True if successful
        """
        if not self.client_secret:
            return False

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_base_url}/oauth2/token/revoke",
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "token": token,
                    },
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "mcp-auth-py/1.0",
                    },
                    timeout=10.0,
                )
                return response.status_code == 200

        except Exception as e:
            logger.warning(f"Failed to revoke Discord token: {str(e)}")
            return False

    def get_provider_config_schema(self) -> dict[str, Any]:
        """Get JSON schema for provider configuration"""
        return {
            "type": "object",
            "properties": {
                "client_id": {
                    "type": "string",
                    "description": "Discord application client ID",
                },
                "client_secret": {
                    "type": "string",
                    "description": "Discord application client secret (optional for validation-only)",
                },
                "bot_token": {
                    "type": "string",
                    "description": "Discord bot token for guild role verification",
                },
                "allowed_guilds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of allowed Discord server IDs",
                },
                "required_roles": {
                    "type": "object",
                    "description": "Required role names per guild ID",
                },
                "scopes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["identify", "email"],
                    "description": "OAuth scopes to request",
                },
            },
            "required": ["client_id"],
        }


# Helper functions for Discord integration


async def get_discord_user_guilds(token: str) -> list[dict[str, Any]]:
    """
    Get user's Discord guilds

    Args:
        token: Discord access token

    Returns:
        List of guild information
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://discord.com/api/v10/users/@me/guilds",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "mcp-auth-py/1.0",
            },
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()


async def check_discord_guild_permission(
    bot_token: str, guild_id: str, user_id: str, permission: str
) -> bool:
    """
    Check if user has specific permission in a Discord guild

    Args:
        bot_token: Discord bot token
        guild_id: Guild ID to check
        user_id: User ID to check
        permission: Permission name to check

    Returns:
        True if user has permission
    """
    try:
        async with httpx.AsyncClient() as client:
            # Get guild member
            response = await client.get(
                f"https://discord.com/api/v10/guilds/{guild_id}/members/{user_id}",
                headers={
                    "Authorization": f"Bot {bot_token}",
                    "User-Agent": "mcp-auth-py/1.0",
                },
                timeout=10.0,
            )

            if response.status_code != 200:
                return False

            member_data = response.json()
            role_ids = member_data.get("roles", [])

            # Get guild roles
            roles_response = await client.get(
                f"https://discord.com/api/v10/guilds/{guild_id}/roles",
                headers={
                    "Authorization": f"Bot {bot_token}",
                    "User-Agent": "mcp-auth-py/1.0",
                },
                timeout=10.0,
            )

            if roles_response.status_code != 200:
                return False

            roles_data = roles_response.json()

            # Check permissions
            permission_map = {
                "administrator": 0x8,
                "manage_guild": 0x20,
                "manage_channels": 0x10,
                "manage_roles": 0x10000000,
                "kick_members": 0x2,
                "ban_members": 0x4,
                "manage_messages": 0x2000,
                "view_channel": 0x400,
                "send_messages": 0x800,
                "read_message_history": 0x10000,
            }

            required_permission = permission_map.get(permission.lower(), 0)
            if not required_permission:
                return False

            # Check if user has the permission through any role
            for role in roles_data:
                if role["id"] in role_ids:
                    role_permissions = int(role.get("permissions", 0))
                    if role_permissions & required_permission:
                        return True

            return False

    except Exception:
        return False


def create_discord_provider_config(
    client_id: str,
    client_secret: Optional[str] = None,
    bot_token: Optional[str] = None,
    allowed_guilds: Optional[list[str]] = None,
    required_roles: Optional[dict[str, list[str]]] = None,
) -> dict[str, Any]:
    """
    Helper function to create Discord provider configuration

    Args:
        client_id: Discord application client ID
        client_secret: Discord application client secret
        bot_token: Discord bot token for guild verification
        allowed_guilds: List of allowed Discord server IDs
        required_roles: Required role names per guild ID

    Returns:
        Provider configuration dictionary
    """
    config = {"client_id": client_id, "scopes": ["identify", "email", "guilds"]}

    if client_secret:
        config["client_secret"] = client_secret

    if bot_token:
        config["bot_token"] = bot_token

    if allowed_guilds:
        config["allowed_guilds"] = allowed_guilds

    if required_roles:
        config["required_roles"] = required_roles

    return config


# Integration with mcp-auth RBAC system


def setup_discord_rbac_integration():
    """
    Example setup for Discord-based RBAC integration
    """
    from ..rbac.engine import get_rbac_engine
    from ..rbac.models import Permission, Role

    rbac_engine = get_rbac_engine()

    # Create Discord guild-based roles
    discord_member_role = Role(
        name="discord_member",
        description="Member of Discord server",
        permissions=[
            Permission.from_string("chat:read"),
            Permission.from_string("voice:join"),
            Permission.from_string("reactions:add"),
        ],
    )
    rbac_engine.add_role(discord_member_role)

    # Create Discord role-based roles
    discord_moderator_role = Role(
        name="discord_moderator",
        description="Discord server moderator",
        permissions=[
            Permission.from_string("chat:*"),
            Permission.from_string("voice:*"),
            Permission.from_string("moderation:kick"),
            Permission.from_string("moderation:mute"),
        ],
    )
    rbac_engine.add_role(discord_moderator_role)

    discord_admin_role = Role(
        name="discord_admin",
        description="Discord server administrator",
        permissions=[Permission.from_string("*:*"), Permission.from_string("admin:*")],
    )
    rbac_engine.add_role(discord_admin_role)

    def assign_discord_roles(principal):
        """Automatically assign roles based on Discord attributes"""
        discord_guilds = principal.attributes.get("discord_guilds", [])
        discord_guild_roles = principal.attributes.get("discord_guild_roles", {})

        roles = []

        # Basic member role
        if discord_guilds:
            roles.append("discord_member")

        # Check for administrative roles
        for role in principal.roles:
            if "discord_guild_admin_" in role or "discord_guild_owner_" in role:
                roles.append("discord_admin")
                break

        # Check for moderator roles based on Discord roles
        for _guild_id, guild_roles in discord_guild_roles.items():
            mod_keywords = ["moderator", "mod", "staff", "admin", "manager"]
            for role_name in guild_roles:
                if any(keyword in role_name.lower() for keyword in mod_keywords):
                    if "discord_admin" not in roles:
                        roles.append("discord_moderator")
                    break

        return roles

    return assign_discord_roles
