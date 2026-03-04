"""SecPostureIQ — Shared Microsoft Graph client factory.

Provides factory functions for creating authenticated
GraphServiceClient instances, used by all tool modules.

Two modes of authentication:
  1. **User-delegated**: A pre-existing OAuth2 access_token (with Graph
     scopes) obtained from the user's login flow is wrapped in a static
     credential and passed to the Graph SDK.
  2. **App-level**: ClientSecretCredential or DefaultAzureCredential is
     used when the server has its own Azure identity configured.

If neither is available the factory returns ``None`` and the calling
tool should fall back to mock data.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.agent.config import settings

logger = structlog.get_logger(__name__)


# ── Static-token credential (for user-delegated flow) ─────────────────


class _StaticTokenCredential:
    """Wraps an existing access token so it can be used with the Graph SDK.

    The Azure SDK credential protocol requires a ``get_token`` method that
    returns an ``AccessToken`` namedtuple.  We set ``expires_on=0`` because
    the backend does not refresh user tokens — the SPA is responsible for
    re-authenticating when the token expires.
    """

    def __init__(self, token: str) -> None:
        self._token = token

    def get_token(self, *scopes: str, **kwargs: Any) -> Any:  # noqa: ARG002
        from azure.core.credentials import AccessToken

        return AccessToken(self._token, 0)


# ── Factory functions ──────────────────────────────────────────────────


def create_graph_client_with_token(
    access_token: str,
    tool_name: str = "unknown",
) -> Any:
    """Create a GraphServiceClient using a user-delegated access token.

    Args:
        access_token: A valid OAuth2 token with Microsoft Graph scopes
            (e.g. ``SecurityEvents.Read.All``).
        tool_name: Name of the calling tool, for log messages.

    Returns:
        GraphServiceClient ready for API calls.
    """
    try:
        from msgraph import GraphServiceClient  # type: ignore[attr-defined]

        credential = _StaticTokenCredential(access_token)
        logger.info(f"tool.{tool_name}.graph_client.user_token", source="delegated")
        return GraphServiceClient(
            credential,
            scopes=["https://graph.microsoft.com/.default"],
        )
    except Exception as e:
        logger.error(f"tool.{tool_name}.graph_client.user_token_error", error=str(e))
        raise


def create_graph_client(
    tool_name: str = "unknown",
    graph_token: str = "",
) -> Any:
    """Create an authenticated Microsoft Graph client.

    Resolution order:
      1. *graph_token* — a user-delegated access token (preferred).
      2. App-level credentials (``AZURE_CLIENT_SECRET`` or Managed Identity).
      3. Return ``None`` → caller should fall back to mock data.

    Args:
        tool_name: Name of the calling tool, used in log messages.
        graph_token: Optional user-delegated access token from the SPA.

    Returns:
        GraphServiceClient ready for API calls, or None if credentials
        are not configured (triggers fallback to mock data).
    """
    # 1. User-delegated token takes priority
    if graph_token:
        return create_graph_client_with_token(graph_token, tool_name)

    # 2. App-level credentials
    if not settings.azure_tenant_id or not settings.azure_client_id:
        logger.info(
            f"tool.{tool_name}.graph_client.skipped",
            reason="Graph API credentials not configured — using mock data",
        )
        return None

    try:
        from msgraph import GraphServiceClient  # type: ignore[attr-defined]

        if settings.azure_client_secret:
            from azure.identity import ClientSecretCredential

            credential: Any = ClientSecretCredential(
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
        logger.error(f"tool.{tool_name}.graph_client.error", error=str(e))
        raise
