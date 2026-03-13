"""SecPostureIQ Tool — query_secure_score

Retrieves the tenant's Microsoft Secure Score via Graph Security API.
Returns current score, category breakdown, 30-day trend, and industry comparison.

Graph API endpoint: GET /security/secureScores
Docs: https://learn.microsoft.com/en-us/graph/api/security-list-securescores
Required scope: SecurityEvents.Read.All
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from src.middleware.pii_redaction import redact_pii
from src.middleware.tracing import trace_tool_call
from src.tools.graph_client import create_graph_client

logger = structlog.get_logger(__name__)

# ── Constants ──────────────────────────────────────────────────────────
GREEN_THRESHOLD = 70.0
TREND_DAYS = 30
GRAPH_TOP_N = 30  # Number of recent score snapshots to fetch (one per day)

# Known Secure Score control categories (from Microsoft docs)
KNOWN_CATEGORIES = frozenset({"Identity", "Data", "Device", "Apps", "Infrastructure"})


@dataclass
class _SecureScoresQueryParameters:
    """Graph query parameters encoded for Kiota RequestInformation."""

    top: int | None = None
    orderby: list[str] | None = None

    def get_query_parameter(self, original_name: str) -> str:
        if original_name == "top":
            return "%24top"
        if original_name == "orderby":
            return "%24orderby"
        return original_name


@dataclass
class _ControlProfilesQueryParameters:
    """Graph query parameters for secureScoreControlProfiles."""

    top: int | None = None

    def get_query_parameter(self, original_name: str) -> str:
        if original_name == "top":
            return "%24top"
        return original_name


# ── Graph client factory ───────────────────────────────────────────────


def _create_graph_client(graph_token: str = "") -> Any:
    """Create an authenticated Microsoft Graph client.

    Delegates to the shared factory in ``src.tools.graph_client``.
    """
    return create_graph_client("secure_score", graph_token=graph_token)


# ── Parsing helpers ────────────────────────────────────────────────────


def _parse_category_breakdown(
    control_scores: list[Any],
    profile_max_scores: dict[str, float] | None = None,
) -> dict[str, dict[str, float]]:
    """Aggregate control-level scores into category-level breakdown.

    The Graph API returns scores per *control* (e.g., "MFA for admins"),
    each tagged with a ``control_category`` (e.g., "Identity").
    We sum scores within each category to produce the category breakdown.

    When ``profile_max_scores`` is provided (a mapping of control name → real
    max score from ``secureScoreControlProfiles``), it is used for accurate
    per-category max score calculation.  Without it the function falls back
    to summing the ``score`` field on each ``ControlScore`` as ``max_score``
    (i.e. max becomes the sum of all control scores in the category — which
    is only useful for the achieved-score total, not the denominator).

    Args:
        control_scores: List of ControlScore objects from the Graph SDK.
        profile_max_scores: Optional mapping of control name → max_score
            from ``secureScoreControlProfiles``.

    Returns:
        Dict mapping category name → {score, max_score, percentage}.
    """
    category_totals: dict[str, float] = defaultdict(float)
    category_max: dict[str, float] = defaultdict(float)

    for cs in control_scores:
        category = getattr(cs, "control_category", None) or "Unknown"
        score = getattr(cs, "score", 0.0) or 0.0
        control_name = getattr(cs, "control_name", None) or ""
        category_totals[category] += score

        # Use real max_score from control profiles when available
        if profile_max_scores and control_name in profile_max_scores:
            category_max[category] += profile_max_scores[control_name]
        else:
            # Fallback: use the control's own score as a rough max
            # (only reached when profiles were not fetched)
            category_max[category] += max(score, 1.0)

    result: dict[str, dict[str, float]] = {}
    for category in sorted(category_totals):
        total = category_totals[category]
        cat_max = category_max[category]
        percentage = round((total / cat_max) * 100, 1) if cat_max > 0 else 0.0
        result[category] = {
            "score": round(total, 1),
            "max_score": round(cat_max, 1),
            "percentage": percentage,
        }

    return result


def _parse_industry_comparison(
    average_comparative_scores: list[Any] | None,
    current_score: float,
) -> dict[str, Any]:
    """Extract industry comparison from comparative scores.

    The Graph API provides multiple comparison bases:
    - "AllTenants" — all Microsoft 365 tenants
    - "TotalSeats" — tenants of similar size
    - "IndustryTypes" — tenants in the same industry

    We prefer "IndustryTypes" → "TotalSeats" → "AllTenants" fallback.

    Args:
        average_comparative_scores: List of AverageComparativeScore objects.
        current_score: The tenant's current score for delta calculation.

    Returns:
        Dict with tenant_score, industry_avg, delta, and basis.
    """
    if not average_comparative_scores:
        return {
            "tenant_score": current_score,
            "industry_avg": None,
            "delta": None,
            "basis": "unavailable",
        }

    # Build lookup by basis
    by_basis: dict[str, float] = {}
    for acs in average_comparative_scores:
        basis = getattr(acs, "basis", None) or "Unknown"
        avg = getattr(acs, "average_score", None)
        if avg is not None:
            by_basis[basis] = avg

    # Prefer industry → seat-size → all tenants
    for preferred in ("IndustryTypes", "TotalSeats", "AllTenants"):
        if preferred in by_basis:
            avg = by_basis[preferred]
            return {
                "tenant_score": current_score,
                "industry_avg": round(avg, 1),
                "delta": round(current_score - avg, 1),
                "basis": preferred,
            }

    # Fall back to first available
    if by_basis:
        basis, avg = next(iter(by_basis.items()))
        return {
            "tenant_score": current_score,
            "industry_avg": round(avg, 1),
            "delta": round(current_score - avg, 1),
            "basis": basis,
        }

    return {
        "tenant_score": current_score,
        "industry_avg": None,
        "delta": None,
        "basis": "unavailable",
    }


def _parse_trend(
    score_snapshots: list[Any],
) -> list[dict[str, Any]]:
    """Extract date/score trend from a list of SecureScore snapshots.

    Snapshots should already be ordered newest-first (from the API query).
    We cap at TREND_DAYS entries.

    Args:
        score_snapshots: List of SecureScore objects (newest first).

    Returns:
        List of {date, score, max_score} dicts, newest first.
    """
    trend: list[dict[str, Any]] = []

    for snap in score_snapshots[:TREND_DAYS]:
        created = getattr(snap, "created_date_time", None)
        date_str = (
            created.strftime("%Y-%m-%d") if isinstance(created, datetime) else str(created) if created else "unknown"
        )
        current = getattr(snap, "current_score", 0.0) or 0.0
        max_s = getattr(snap, "max_score", 0.0) or 0.0
        trend.append(
            {
                "date": date_str,
                "score": round(current, 1),
                "max_score": round(max_s, 1),
            }
        )

    return trend


def _compute_status(
    score_percentage: float,
    threshold: float = GREEN_THRESHOLD,
) -> str:
    """Determine posture status based on score vs. threshold.

    Returns:
        "green", "yellow" (within 10 pts of green), or "red".
    """
    if score_percentage >= threshold:
        return "green"
    elif score_percentage >= threshold - 10:
        return "yellow"
    else:
        return "red"


# ── Control profile max-score fetcher ──────────────────────────────────


async def _fetch_profile_max_scores(
    client: Any,
) -> tuple[dict[str, float] | None, list[dict[str, Any]]]:
    """Fetch secureScoreControlProfiles and return lookup + detail list.

    Returns:
        A tuple of (lookup, profiles_detail) where *lookup* maps
        control_name → max_score (None on failure) and *profiles_detail*
        is a list of per-control dicts with key fields for display.
    """
    try:
        from kiota_abstractions.base_request_configuration import RequestConfiguration

        query = _ControlProfilesQueryParameters(top=999)
        config = RequestConfiguration(query_parameters=query)
        response = await client.security.secure_score_control_profiles.get(
            request_configuration=config,
        )
        profiles = response.value if response and response.value else []
        if not profiles:
            logger.warning("tool.secure_score.profiles_empty")
            return None, []

        lookup: dict[str, float] = {}
        details: list[dict[str, Any]] = []
        for p in profiles:
            ctrl_id = getattr(p, "id", None) or ""
            ms = getattr(p, "max_score", None) or 0.0
            if ctrl_id:
                lookup[ctrl_id] = float(ms)
                details.append(
                    {
                        "id": ctrl_id,
                        "title": getattr(p, "title", None) or ctrl_id,
                        "category": getattr(p, "control_category", None) or "Unknown",
                        "max_score": float(ms),
                        "tier": getattr(p, "tier", None) or "",
                        "deprecated": bool(getattr(p, "deprecated", False)),
                        "service": getattr(p, "service", None) or "",
                    }
                )
        logger.info("tool.secure_score.profiles_fetched", count=len(lookup))
        return lookup, details
    except Exception as e:
        logger.warning("tool.secure_score.profiles_fetch_error", error=str(e))
        return None, []


# ── Mock data (development fallback) ──────────────────────────────────


def _generate_mock_response() -> dict[str, Any]:
    """Generate realistic mock Secure Score data for development.

    Used when Graph API credentials are not configured.
    """
    now = datetime.now(UTC)
    score = 47.3
    max_score = 100.0
    pct = round((score / max_score) * 100, 1)

    return {
        "current_score": score,
        "max_score": max_score,
        "score_percentage": pct,
        "categories": {
            "Identity": {"score": 62.0, "max_score": 100.0, "percentage": 62.0},
            "Data": {"score": 28.5, "max_score": 100.0, "percentage": 28.5},
            "Device": {"score": 55.0, "max_score": 100.0, "percentage": 55.0},
            "Apps": {"score": 40.0, "max_score": 100.0, "percentage": 40.0},
            "Infrastructure": {"score": 51.0, "max_score": 100.0, "percentage": 51.0},
        },
        "trend_30d": [
            {
                "date": (now - timedelta(days=i)).strftime("%Y-%m-%d"),
                "score": round(score - (i * 0.1), 1),
                "max_score": max_score,
            }
            for i in range(TREND_DAYS)
        ],
        "industry_comparison": {
            "tenant_score": score,
            "industry_avg": 63.2,
            "delta": round(score - 63.2, 1),
            "basis": "IndustryTypes",
        },
        "assessed_at": now.isoformat(),
        "status": _compute_status(pct),
        "green_threshold": GREEN_THRESHOLD,
        "gap_to_green": round(max(0, GREEN_THRESHOLD - pct), 1),
        "data_source": "mock",
    }


# ── Main tool entry point ─────────────────────────────────────────────


@trace_tool_call("query_secure_score")
async def query_secure_score(tenant_id: str = "", graph_token: str = "") -> dict[str, Any]:
    """Query Microsoft Secure Score for the authenticated tenant.

    Calls ``GET /security/secureScores`` via the Microsoft Graph SDK.
    Falls back to mock data when Graph API credentials are not configured.

    Args:
        tenant_id: Optional tenant identifier for logging. Uses current
            auth context regardless — Graph API scopes are per-credential.
        graph_token: User-delegated Graph API access token (preferred over
            app-level credentials when present).

    Returns:
        dict with keys:
          - current_score: float (e.g., 72.5)
          - max_score: float (e.g., 100.0)
          - score_percentage: float (e.g., 72.5)
          - categories: dict of category → {score, max_score, percentage}
          - trend_30d: list of {date, score, max_score} for the last 30 days
          - industry_comparison: dict with tenant_score, industry_avg, delta, basis
          - assessed_at: ISO timestamp
          - status: "green" | "yellow" | "red"
          - green_threshold: float
          - gap_to_green: float
          - data_source: "graph_api" | "mock"
    """
    logger.info("tool.secure_score.start", tenant_id=redact_pii(tenant_id))

    # Try real Graph API first; fall back to mock if not configured
    client = _create_graph_client(graph_token=graph_token)
    if client is None:
        logger.info("tool.secure_score.fallback", source="mock")
        result = _generate_mock_response()
        logger.info(
            "tool.secure_score.complete",
            score=result["current_score"],
            gap_to_green=result["gap_to_green"],
            source="mock",
        )
        return result

    # ── Real Graph API call ────────────────────────────────
    try:
        from kiota_abstractions.base_request_configuration import RequestConfiguration

        query_params = _SecureScoresQueryParameters(
            top=GRAPH_TOP_N,
            orderby=["createdDateTime desc"],
        )
        request_config = RequestConfiguration(query_parameters=query_params)
        response = await client.security.secure_scores.get(
            request_configuration=request_config,
        )

        snapshots = response.value if response and response.value else []

        if not snapshots:
            logger.warning("tool.secure_score.empty", reason="no score data returned")
            result = _generate_mock_response()
            result["data_source"] = "graph_api_empty"
            return result

        # ── Fetch control profiles for accurate per-category max scores
        profile_max_scores, control_profiles = await _fetch_profile_max_scores(client)

        # Latest snapshot is the current score
        latest = snapshots[0]
        current_score = latest.current_score or 0.0
        max_score = latest.max_score or 0.0
        score_pct = round((current_score / max_score) * 100, 1) if max_score > 0 else 0.0

        # Parse components
        categories = _parse_category_breakdown(
            latest.control_scores or [],
            profile_max_scores=profile_max_scores,
        )
        industry = _parse_industry_comparison(
            latest.average_comparative_scores,
            current_score,
        )
        trend = _parse_trend(snapshots)

        result = {
            "current_score": round(current_score, 1),
            "max_score": round(max_score, 1),
            "score_percentage": score_pct,
            "categories": categories,
            "control_profiles": control_profiles,
            "profiles_assessed": len(control_profiles),
            "trend_30d": trend,
            "industry_comparison": industry,
            "assessed_at": datetime.now(UTC).isoformat(),
            "status": _compute_status(score_pct),
            "green_threshold": GREEN_THRESHOLD,
            "gap_to_green": round(max(0, GREEN_THRESHOLD - score_pct), 1),
            "data_source": "graph_api",
        }

        logger.info(
            "tool.secure_score.complete",
            score=result["current_score"],
            gap_to_green=result["gap_to_green"],
            categories_count=len(categories),
            trend_points=len(trend),
            source="graph_api",
        )

        return result

    except Exception as e:
        logger.error(
            "tool.secure_score.graph_api_error",
            error=str(e),
            fallback="mock",
        )
        raise
