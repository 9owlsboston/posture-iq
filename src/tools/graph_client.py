"""PostureIQ — Shared Microsoft Graph client factory.

Provides a single factory function for creating authenticated
GraphServiceClient instances, used by all tool modules.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from azure.core.credentials import AccessToken, TokenCredential

from src.agent.config import settings

logger = structlog.get_logger(__name__)


class StaticAccessTokenCredential(TokenCredential):
    """Minimal TokenCredential wrapper around an already-issued bearer token."""

    def __init__(self, access_token: str) -> None:
        self._access_token = access_token

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        # Token lifetime is unknown; set a short future expiry for SDK compatibility.
        expires_on = int((datetime.now(UTC) + timedelta(minutes=10)).timestamp())
        return AccessToken(self._access_token, expires_on)


def create_graph_client(
    tool_name: str = "unknown",
    *,
    tenant_id: str = "",
    user_access_token: str = "",
) -> Any:
    """Create an authenticated Microsoft Graph client.

    Preferred auth order:
      1) Use the request user's delegated access token (multi-tenant safe)
      2) Fall back to app credentials (single-tenant / service-to-service)

    Args:
        tool_name: Name of the calling tool, used in log messages.
        tenant_id: Tenant identifier from request context.
        user_access_token: Delegated bearer token from the authenticated user.

    Returns:
        GraphServiceClient ready for API calls, or None if credentials
        are not configured (triggers fallback to mock data).
    """
    if not settings.azure_client_id:
        logger.info(
            f"tool.{tool_name}.graph_client.skipped",
            reason="AZURE_CLIENT_ID not configured — using mock data",
        )
        return None

    try:
        from msgraph import GraphServiceClient  # type: ignore[attr-defined]

        if user_access_token:
            credential: Any = StaticAccessTokenCredential(user_access_token)
        elif settings.azure_tenant_id and settings.azure_client_secret:
            from azure.identity import ClientSecretCredential

            credential = ClientSecretCredential(
                tenant_id=settings.azure_tenant_id,
                client_id=settings.azure_client_id,
                client_secret=settings.azure_client_secret,
            )
        else:
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()

        return GraphServiceClient(
            credential,
            scopes=["https://graph.microsoft.com/.default"],
        )
    except Exception as e:
        logger.error(
            f"tool.{tool_name}.graph_client.error",
            error=str(e),
            tenant_id=tenant_id,
        )
        raise
