"""PostureIQ — Shared Microsoft Graph client factory.

Provides a single factory function for creating authenticated
GraphServiceClient instances, used by all tool modules.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.agent.config import settings

logger = structlog.get_logger(__name__)


def create_graph_client(tool_name: str = "unknown") -> Any:
    """Create an authenticated Microsoft Graph client.

    Uses ClientSecretCredential when explicit credentials are configured,
    otherwise falls back to DefaultAzureCredential (Managed Identity).

    Args:
        tool_name: Name of the calling tool, used in log messages.

    Returns:
        GraphServiceClient ready for API calls, or None if credentials
        are not configured (triggers fallback to mock data).
    """
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
