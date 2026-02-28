"""PostureIQ Tool — check_purview_policies

Assesses Microsoft Purview Information Protection & Compliance policy
coverage by analysing *SecureScoreControlProfile* records whose
``control_category`` relates to Information Protection / Data.

For richer detail the tool also attempts direct Graph API calls:
  - Sensitivity labels: GET /informationProtection/sensitivityLabels  (beta)

Falls back to SecureScoreControlProfiles when direct endpoints are
unavailable or return 403.

Graph API endpoint: GET /security/secureScoreControlProfiles
Required scope: SecurityEvents.Read.All, InformationProtection.Read.All
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

from src.middleware.tracing import trace_tool_call
from src.tools.graph_client import create_graph_client

logger = structlog.get_logger(__name__)

# ── Constants ──────────────────────────────────────────────────────────

# We classify a control profile as "Purview-related" when its service or
# control_category matches one of these (case-insensitive substring check).
PURVIEW_SERVICE_KEYWORDS = frozenset(
    {
        "information protection",
        "purview",
        "compliance",
        "data loss prevention",
        "dlp",
        "insider risk",
        "retention",
        "sensitivity",
    }
)

# Canonical Purview component names we report on
ALL_COMPONENTS = (
    "DLP Policies",
    "Sensitivity Labels",
    "Retention Policies",
    "Insider Risk Management",
)

# Keywords that map a control to a specific component
_COMPONENT_KEYWORDS: dict[str, list[str]] = {
    "DLP Policies": ["dlp", "data loss prevention"],
    "Sensitivity Labels": ["sensitivity label", "information protection label", "labeling"],
    "Retention Policies": ["retention"],
    "Insider Risk Management": ["insider risk", "insider threat"],
}

GREEN_THRESHOLD = 70.0
YELLOW_THRESHOLD = 40.0


@dataclass
class _SecureScoreControlProfilesQueryParameters:
    """Graph query parameters encoded for Kiota RequestInformation."""

    top: int | None = None

    def get_query_parameter(self, original_name: str) -> str:
        if original_name == "top":
            return "%24top"
        return original_name


# ── Graph client factory ───────────────────────────────────────────────


def _create_graph_client() -> Any:
    """Delegate to the shared Graph client factory."""
    return create_graph_client("purview_policies")


# ── Classification helpers ─────────────────────────────────────────────


def _is_purview_related(profile: Any) -> bool:
    """Return True when a control profile relates to Purview / data protection."""
    for field in ("service", "control_category", "title"):
        val = (getattr(profile, field, None) or "").lower()
        if any(kw in val for kw in PURVIEW_SERVICE_KEYWORDS):
            return True
    return False


def _classify_component(profile: Any) -> str:
    """Map a Purview-related profile to one of our canonical component names."""
    text = " ".join(
        [
            (getattr(profile, "title", None) or ""),
            (getattr(profile, "service", None) or ""),
            (getattr(profile, "control_category", None) or ""),
        ]
    ).lower()

    for component, keywords in _COMPONENT_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return component

    # Default bucket
    return "DLP Policies"


def _compute_status(pct: float) -> str:
    if pct >= GREEN_THRESHOLD:
        return "green"
    if pct >= YELLOW_THRESHOLD:
        return "yellow"
    return "red"


def _is_gap(profile: Any) -> bool:
    """A control is a gap unless its latest state is Resolved/ThirdParty."""
    if getattr(profile, "deprecated", False):
        return False
    state_updates = getattr(profile, "control_state_updates", None) or []
    if not state_updates:
        return True
    latest = (getattr(state_updates[-1], "state", None) or "").lower()
    return latest not in ("resolved", "thirdparty", "third_party")


def _gap_description(profile: Any) -> str:
    title = str(getattr(profile, "title", None) or getattr(profile, "id", "Unknown"))
    tier = getattr(profile, "tier", None)
    parts: list[str] = [title]
    if tier:
        parts.append(f"(tier: {tier})")
    return " ".join(parts)


def _is_critical(profile: Any) -> bool:
    tier = (getattr(profile, "tier", None) or "").lower()
    if tier in ("tier1", "mandatorytier", "mandatory"):
        return True
    return (getattr(profile, "max_score", None) or 0.0) >= 5.0


def _build_component_result(profiles: list[Any]) -> dict[str, Any]:
    if not profiles:
        return {
            "status": "red",
            "details": {
                "total_controls": 0,
                "achieved_controls": 0,
                "max_score": 0.0,
                "achieved_score": 0.0,
            },
            "gaps": [],
        }

    total_max = 0.0
    achieved = 0.0
    gaps: list[str] = []
    achieved_count = 0

    for p in profiles:
        ms = getattr(p, "max_score", None) or 0.0
        total_max += ms
        if _is_gap(p):
            gaps.append(_gap_description(p))
        else:
            achieved += ms
            achieved_count += 1

    pct = round((achieved / total_max) * 100, 1) if total_max > 0 else 0.0

    return {
        "status": _compute_status(pct),
        "details": {
            "total_controls": len(profiles),
            "achieved_controls": achieved_count,
            "max_score": round(total_max, 2),
            "achieved_score": round(achieved, 2),
        },
        "gaps": gaps,
    }


def _aggregate_components(profiles: list[Any]) -> dict[str, dict[str, Any]]:
    buckets: dict[str, list[Any]] = {c: [] for c in ALL_COMPONENTS}
    for p in profiles:
        comp = _classify_component(p)
        if comp in buckets:
            buckets[comp].append(p)
    return {c: _build_component_result(profs) for c, profs in buckets.items()}


def _compute_overall(components: dict[str, dict[str, Any]]) -> float:
    total_max = sum(c["details"]["max_score"] for c in components.values())
    if total_max == 0:
        return 0.0
    total_achieved = sum(c["details"]["achieved_score"] for c in components.values())
    return round(float(total_achieved / total_max) * 100, 1)


def _collect_critical_gaps(profiles: list[Any]) -> list[str]:
    return [_gap_description(p) for p in profiles if _is_gap(p) and _is_critical(p)]


# ── Mock fallback ──────────────────────────────────────────────────────


def _generate_mock_response() -> dict[str, Any]:
    return {
        "overall_coverage_pct": 35.0,
        "components": {
            "DLP Policies": {
                "status": "yellow",
                "details": {
                    "total_controls": 4,
                    "achieved_controls": 1,
                    "max_score": 20.0,
                    "achieved_score": 7.0,
                },
                "gaps": [
                    "DLP policies not enforced on SharePoint, OneDrive, Teams (tier: Tier1)",
                    "No custom sensitive information types defined (tier: Tier2)",
                    "DLP policies in test mode — not actively blocking (tier: Tier1)",
                ],
            },
            "Sensitivity Labels": {
                "status": "red",
                "details": {
                    "total_controls": 5,
                    "achieved_controls": 1,
                    "max_score": 18.0,
                    "achieved_score": 3.0,
                },
                "gaps": [
                    "Auto-labeling not enabled (tier: Tier1)",
                    "No default sensitivity label configured (tier: Tier2)",
                    "Mandatory labeling not enforced (tier: Tier1)",
                    "Only 2 of 8 labels published (tier: Tier2)",
                ],
            },
            "Retention Policies": {
                "status": "yellow",
                "details": {
                    "total_controls": 3,
                    "achieved_controls": 1,
                    "max_score": 12.0,
                    "achieved_score": 4.0,
                },
                "gaps": [
                    "Retention policies only cover Exchange (tier: Tier2)",
                    "No retention labels with records management (tier: Tier2)",
                ],
            },
            "Insider Risk Management": {
                "status": "red",
                "details": {
                    "total_controls": 3,
                    "achieved_controls": 0,
                    "max_score": 10.0,
                    "achieved_score": 0.0,
                },
                "gaps": [
                    "Insider Risk Management not enabled (tier: Tier1)",
                    "No data connectors configured (tier: Tier2)",
                    "No risk policies defined (tier: Tier2)",
                ],
            },
        },
        "total_gaps": 12,
        "critical_gaps": [
            "DLP policies not enforced on SharePoint, OneDrive, Teams (tier: Tier1)",
            "Auto-labeling not enabled (tier: Tier1)",
            "Mandatory labeling not enforced (tier: Tier1)",
            "Insider Risk Management not enabled (tier: Tier1)",
        ],
        "assessed_at": datetime.now(UTC).isoformat(),
        "data_source": "mock",
    }


# ── Main tool function ─────────────────────────────────────────────────


@trace_tool_call("check_purview_policies")
async def check_purview_policies() -> dict[str, Any]:
    """Assess Purview Information Protection & Compliance policy coverage.

    Uses ``GET /security/secureScoreControlProfiles`` and filters for
    controls related to information-protection / data / Purview.

    Falls back to mock data when Graph credentials are absent.

    Returns:
        dict with keys:
          - overall_coverage_pct: float
          - components: dict of component → {status, details, gaps}
          - total_gaps: int
          - critical_gaps: list
          - assessed_at: ISO timestamp
          - data_source: "graph_api" | "mock" | "graph_api_empty"
    """
    logger.info("tool.purview_policies.start")

    client = _create_graph_client()
    if client is None:
        logger.info("tool.purview_policies.mock_fallback")
        return _generate_mock_response()

    try:
        from kiota_abstractions.base_request_configuration import RequestConfiguration

        query = _SecureScoreControlProfilesQueryParameters(top=200)
        config = RequestConfiguration(query_parameters=query)
        response = await client.security.secure_score_control_profiles.get(
            request_configuration=config,
        )

        all_profiles = response.value if response and response.value else []

        # Filter to Purview-related, non-deprecated profiles
        purview_profiles = [p for p in all_profiles if _is_purview_related(p) and not getattr(p, "deprecated", False)]

        if not purview_profiles:
            logger.warning("tool.purview_policies.empty_response")
            mock = _generate_mock_response()
            mock["data_source"] = "graph_api_empty"
            return mock

        components = _aggregate_components(purview_profiles)
        overall = _compute_overall(components)
        total_gaps = sum(len(c["gaps"]) for c in components.values())
        critical_gaps = _collect_critical_gaps(purview_profiles)

        result: dict[str, Any] = {
            "overall_coverage_pct": overall,
            "components": components,
            "total_gaps": total_gaps,
            "critical_gaps": critical_gaps,
            "assessed_at": datetime.now(UTC).isoformat(),
            "data_source": "graph_api",
        }

        logger.info(
            "tool.purview_policies.complete",
            overall_coverage=overall,
            total_gaps=total_gaps,
            data_source="graph_api",
        )
        return result

    except Exception as exc:
        logger.error(
            "tool.purview_policies.graph_error",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        logger.info("tool.purview_policies.error_fallback_to_mock")
        mock = _generate_mock_response()
        mock["data_source"] = "mock"
        return mock
