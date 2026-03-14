"""SecPostureIQ — Shared Microsoft Graph client factory.

Provides factory functions for creating authenticated
GraphServiceClient instances, used by all tool modules.

Authentication mode:
  **User-delegated only**: A pre-existing OAuth2 access_token (with
  Graph scopes) obtained from the user's login flow is wrapped in a
  static credential and passed to the Graph SDK.

If no user token is available the factory returns ``None`` and the
calling tool falls back to mock / demo data.

.. note::
   The app-level Azure identity (Managed Identity) is intentionally
   **not** used for Graph queries.  It exists for infrastructure
   operations (ACR pull, Key Vault) and would assess the *hosting*
   tenant, not the signed-in user's tenant.
"""

from __future__ import annotations

from typing import Any

import structlog

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

    Only user-delegated tokens are accepted.  When no *graph_token* is
    supplied the function returns ``None`` so the caller falls back to
    mock / demo data.

    The app-level Azure identity (Managed Identity / ``AZURE_CLIENT_ID``)
    is used for infrastructure operations (ACR pull, Key Vault) and must
    **never** be used for Microsoft Graph queries — that would
    inadvertently assess the *hosting* tenant instead of the user's
    tenant.

    Args:
        tool_name: Name of the calling tool, used in log messages.
        graph_token: User-delegated access token from the SPA login flow.

    Returns:
        GraphServiceClient ready for API calls, or ``None`` when the
        user is not authenticated (triggers mock-data fallback).
    """
    if graph_token:
        return create_graph_client_with_token(graph_token, tool_name)

    logger.info(
        f"tool.{tool_name}.graph_client.skipped",
        reason="No user Graph token — using mock data",
    )
    return None


async def fetch_control_scores(client: Any) -> dict[str, float] | None:
    """Fetch the latest SecureScore snapshot and return per-control scores.

    Calls ``GET /security/secureScores?$top=1&$orderby=createdDateTime desc``
    and extracts the ``control_scores`` list into a dict mapping
    ``control_name → score``.

    This is the authoritative source for which controls a tenant has
    actually achieved — it matches the Microsoft Secure Score dashboard.
    The ``controlStateUpdates`` field on profiles is manually-managed
    and unreliable.

    Returns:
        Dict mapping control_name to achieved score, or None on failure.
    """
    try:
        from kiota_abstractions.base_request_configuration import (  # noqa: PLC0415
            RequestConfiguration,
        )

        from src.tools.secure_score import _SecureScoresQueryParameters  # noqa: PLC0415

        query = _SecureScoresQueryParameters(top=1, orderby=["createdDateTime desc"])
        config = RequestConfiguration(query_parameters=query)
        response = await client.security.secure_scores.get(request_configuration=config)

        snapshots = response.value if response and response.value else []
        if not snapshots:
            logger.warning("graph_client.control_scores.empty")
            return None

        latest = snapshots[0]
        control_score_list = getattr(latest, "control_scores", None) or []

        scores: dict[str, float] = {}
        for cs in control_score_list:
            name = getattr(cs, "control_name", None) or ""
            score = getattr(cs, "score", None)
            if name and score is not None:
                scores[name] = float(score)

        logger.info("graph_client.control_scores.loaded", count=len(scores))
        return scores

    except Exception as exc:
        logger.warning("graph_client.control_scores.fetch_failed", error=str(exc))
        return None
