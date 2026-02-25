"""PostureIQ Tool — query_secure_score

Retrieves the tenant's Microsoft Secure Score via Graph Security API.
Returns current score, category breakdown, 30-day trend, and industry comparison.

Graph API endpoint: GET /security/secureScores
Docs: https://learn.microsoft.com/en-us/graph/api/security-list-securescores
Required scope: SecurityEvents.Read.All
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog

from src.middleware.pii_redaction import redact_pii
from src.middleware.tracing import trace_tool_call

logger = structlog.get_logger(__name__)


@trace_tool_call("query_secure_score")
async def query_secure_score(tenant_id: str = "") -> dict[str, Any]:
    """Query Microsoft Secure Score for the authenticated tenant.

    Args:
        tenant_id: Optional tenant identifier. Uses current auth context if omitted.

    Returns:
        dict with keys:
          - current_score: float (e.g., 72.5)
          - max_score: float (e.g., 100.0)
          - score_percentage: float (e.g., 72.5)
          - categories: dict of category → {score, max_score, percentage}
          - trend_30d: list of {date, score} for the last 30 days
          - industry_comparison: dict with avg_score for similar tenants
          - assessed_at: ISO timestamp
    """
    logger.info("tool.secure_score.start", tenant_id=redact_pii(tenant_id))

    # TODO: Replace with actual Graph API call
    # from msgraph import GraphServiceClient
    # from azure.identity import ClientSecretCredential
    #
    # credential = ClientSecretCredential(
    #     tenant_id=settings.azure_tenant_id,
    #     client_id=settings.azure_client_id,
    #     client_secret=settings.azure_client_secret,
    # )
    # client = GraphServiceClient(credential, scopes=["https://graph.microsoft.com/.default"])
    # scores = await client.security.secure_scores.get()

    # ── Mock response for development ──────────────────────
    result = {
        "current_score": 47.3,
        "max_score": 100.0,
        "score_percentage": 47.3,
        "categories": {
            "Identity": {"score": 62.0, "max_score": 100.0, "percentage": 62.0},
            "Data": {"score": 28.5, "max_score": 100.0, "percentage": 28.5},
            "Device": {"score": 55.0, "max_score": 100.0, "percentage": 55.0},
            "Apps": {"score": 40.0, "max_score": 100.0, "percentage": 40.0},
            "Infrastructure": {"score": 51.0, "max_score": 100.0, "percentage": 51.0},
        },
        "trend_30d": [
            {"date": (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d"), "score": 47.3 - (i * 0.1)}
            for i in range(30)
        ],
        "industry_comparison": {
            "tenant_score": 47.3,
            "industry_avg": 63.2,
            "percentile": 32,
        },
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "status": "out_of_green",
        "green_threshold": 70.0,
        "gap_to_green": 22.7,
    }

    logger.info(
        "tool.secure_score.complete",
        score=result["current_score"],
        gap_to_green=result["gap_to_green"],
    )

    return result
