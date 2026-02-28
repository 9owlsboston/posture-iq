"""PostureIQ Tool — assess_defender_coverage

Evaluates M365 Defender deployment status across all workloads by
analysing *SecureScoreControlProfile* records from the Graph Security API.

Each control profile has a ``service`` field that maps it to a Defender
workload (e.g. "Microsoft Defender for Endpoint").  We group the profiles
by service, compute what fraction of the available max-score the tenant
has achieved per workload, and surface gaps from non-achieved controls.

Graph API endpoint: GET /security/secureScoreControlProfiles
Docs: https://learn.microsoft.com/en-us/graph/api/security-list-securescorecontrolprofiles
Required scope: SecurityEvents.Read.All
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

# Mapping of *service* field values in SecureScoreControlProfile to the
# display name we expose in our JSON response.
WORKLOAD_SERVICE_MAP: dict[str, str] = {
    "MDE": "Defender for Endpoint",
    "MDO": "Defender for Office 365",
    "MDI": "Defender for Identity",
    "MDA": "Defender for Cloud Apps",
    # Full display strings returned by some Graph tenants
    "Microsoft Defender for Endpoint": "Defender for Endpoint",
    "Microsoft Defender for Office 365": "Defender for Office 365",
    "Microsoft Defender for Identity": "Defender for Identity",
    "Microsoft Defender for Cloud Apps": "Defender for Cloud Apps",
    "Microsoft Cloud App Security": "Defender for Cloud Apps",
}

# Canonical workload display names — we always return every workload.
ALL_WORKLOADS = (
    "Defender for Endpoint",
    "Defender for Office 365",
    "Defender for Identity",
    "Defender for Cloud Apps",
)

GREEN_THRESHOLD = 70.0  # ≥ 70% → green
YELLOW_THRESHOLD = 40.0  # ≥ 40% → yellow, else red


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
    return create_graph_client("defender_coverage")


# ── Parsing / classification helpers ───────────────────────────────────


def _classify_workload(service: str | None) -> str | None:
    """Map a ``service`` string from the API to our canonical workload name.

    Returns None when the service does not map to a known Defender workload.
    """
    if not service:
        return None
    return WORKLOAD_SERVICE_MAP.get(service)


def _compute_status(pct: float) -> str:
    """Return 'green', 'yellow', or 'red' based on coverage percentage."""
    if pct >= GREEN_THRESHOLD:
        return "green"
    if pct >= YELLOW_THRESHOLD:
        return "yellow"
    return "red"


def _is_gap(profile: Any) -> bool:
    """Determine whether a control profile represents a gap.

    A control is considered a gap when the latest ``control_state_updates``
    entry does **not** have state "Resolved" or "ThirdParty", or when
    no state updates exist at all.  We also consider deprecated controls
    as non-gaps (they are excluded from the analysis).
    """
    if getattr(profile, "deprecated", False):
        return False

    state_updates = getattr(profile, "control_state_updates", None) or []
    if not state_updates:
        # No state has been set → the control is unresolved
        return True

    # Take the last (most recent) update
    latest_state = getattr(state_updates[-1], "state", None) or ""
    return latest_state.lower() not in ("resolved", "thirdparty", "third_party")


def _gap_description(profile: Any) -> str:
    """Build a human-readable gap description from a control profile."""
    title = str(getattr(profile, "title", None) or getattr(profile, "id", "Unknown control"))
    tier = getattr(profile, "tier", None)
    remediation = getattr(profile, "remediation", None)

    parts: list[str] = [title]
    if tier:
        parts.append(f"(tier: {tier})")
    if remediation:
        # Truncate long remediation text
        short = remediation[:120] + ("…" if len(remediation) > 120 else "")
        parts.append(f"— {short}")
    return " ".join(parts)


def _is_critical_gap(profile: Any) -> bool:
    """A gap is critical if tier is 'Tier1' / 'MandatoryTier' or max_score ≥ 5."""
    tier = (getattr(profile, "tier", None) or "").lower()
    if tier in ("tier1", "mandatorytier", "mandatory"):
        return True
    max_score = getattr(profile, "max_score", None) or 0.0
    return max_score >= 5.0


def _build_workload_result(
    profiles: list[Any],
) -> dict[str, Any]:
    """Compute coverage metrics for a list of profiles belonging to one workload."""
    if not profiles:
        return {
            "coverage_pct": 0.0,
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
    achieved_score = 0.0
    gaps: list[str] = []
    achieved_count = 0

    for p in profiles:
        ms = getattr(p, "max_score", None) or 0.0
        total_max += ms

        if _is_gap(p):
            gaps.append(_gap_description(p))
        else:
            achieved_score += ms
            achieved_count += 1

    coverage_pct = round((achieved_score / total_max) * 100, 1) if total_max > 0 else 0.0

    return {
        "coverage_pct": coverage_pct,
        "status": _compute_status(coverage_pct),
        "details": {
            "total_controls": len(profiles),
            "achieved_controls": achieved_count,
            "max_score": round(total_max, 2),
            "achieved_score": round(achieved_score, 2),
        },
        "gaps": gaps,
    }


def _aggregate_workloads(
    profiles: list[Any],
) -> dict[str, dict[str, Any]]:
    """Group profiles by workload and compute per-workload results."""
    buckets: dict[str, list[Any]] = {wl: [] for wl in ALL_WORKLOADS}

    for profile in profiles:
        service = getattr(profile, "service", None)
        workload = _classify_workload(service)
        if workload and workload in buckets:
            buckets[workload].append(profile)

    return {wl: _build_workload_result(profs) for wl, profs in buckets.items()}


def _compute_overall_coverage(workloads: dict[str, dict[str, Any]]) -> float:
    """Weighted-average coverage across all workloads (by max_score)."""
    total_max = sum(w["details"]["max_score"] for w in workloads.values())
    if total_max == 0:
        return 0.0
    total_achieved = sum(w["details"]["achieved_score"] for w in workloads.values())
    return round(float(total_achieved / total_max) * 100, 1)


def _collect_critical_gaps(profiles: list[Any]) -> list[str]:
    """Return descriptions for critical gaps across all workloads."""
    critical: list[str] = []
    for p in profiles:
        if _is_gap(p) and _is_critical_gap(p):
            workload = _classify_workload(getattr(p, "service", None)) or "Unknown"
            title = getattr(p, "title", None) or getattr(p, "id", "Unknown")
            critical.append(f"{title} [{workload}]")
    return critical


# ── Mock fallback ──────────────────────────────────────────────────────


def _generate_mock_response() -> dict[str, Any]:
    """Return realistic-looking mock data for development/testing."""
    return {
        "overall_coverage_pct": 52.0,
        "workloads": {
            "Defender for Endpoint": {
                "coverage_pct": 68.0,
                "status": "yellow",
                "details": {
                    "total_controls": 8,
                    "achieved_controls": 5,
                    "max_score": 25.0,
                    "achieved_score": 17.0,
                },
                "gaps": [
                    "Enable Attack Surface Reduction rules (tier: Tier1)",
                    "Turn on automated investigation (tier: Tier2)",
                    "Enable network protection (tier: Tier2)",
                ],
            },
            "Defender for Office 365": {
                "coverage_pct": 45.0,
                "status": "yellow",
                "details": {
                    "total_controls": 6,
                    "achieved_controls": 3,
                    "max_score": 20.0,
                    "achieved_score": 9.0,
                },
                "gaps": [
                    "Enable Safe Attachments (tier: Tier1) — critical gap",
                    "Configure custom anti-phishing policy (tier: Tier2)",
                    "Enable Safe Links for Teams (tier: Tier2)",
                ],
            },
            "Defender for Identity": {
                "coverage_pct": 30.0,
                "status": "red",
                "details": {
                    "total_controls": 5,
                    "achieved_controls": 1,
                    "max_score": 15.0,
                    "achieved_score": 4.5,
                },
                "gaps": [
                    "Deploy sensors to all domain controllers (tier: Tier1)",
                    "Enable lateral movement path detection (tier: Tier1)",
                    "Configure honeytoken accounts (tier: Tier2)",
                    "Enable entity tags (tier: Tier3)",
                ],
            },
            "Defender for Cloud Apps": {
                "coverage_pct": 65.0,
                "status": "yellow",
                "details": {
                    "total_controls": 7,
                    "achieved_controls": 4,
                    "max_score": 18.0,
                    "achieved_score": 11.7,
                },
                "gaps": [
                    "Review discovered shadow-IT apps (tier: Tier2)",
                    "Configure session control policies (tier: Tier2)",
                    "Enable OAuth app governance (tier: Tier2)",
                ],
            },
        },
        "total_gaps": 13,
        "critical_gaps": [
            "Enable Safe Attachments [Defender for Office 365]",
            "Deploy sensors to all domain controllers [Defender for Identity]",
            "Enable lateral movement path detection [Defender for Identity]",
            "Enable Attack Surface Reduction rules [Defender for Endpoint]",
        ],
        "assessed_at": datetime.now(UTC).isoformat(),
        "data_source": "mock",
    }


# ── Main tool function ─────────────────────────────────────────────────


@trace_tool_call("assess_defender_coverage")
async def assess_defender_coverage() -> dict[str, Any]:
    """Assess M365 Defender deployment coverage across all workloads.

    Uses ``GET /security/secureScoreControlProfiles`` from the Graph
    Security API to obtain control-level data for each Defender workload.
    Profiles are grouped by their ``service`` field, and per-workload
    coverage is computed as ``achieved_score / max_score``.

    Falls back to realistic mock data when Graph credentials are not
    configured (e.g. local development).

    Returns:
        dict with keys:
          - overall_coverage_pct: float
          - workloads: dict of workload → {coverage_pct, status, details, gaps}
          - total_gaps: int
          - critical_gaps: list of gap descriptions
          - assessed_at: ISO timestamp
          - data_source: "graph_api" | "mock" | "graph_api_empty"
    """
    logger.info("tool.defender_coverage.start")

    client = _create_graph_client()

    if client is None:
        logger.info("tool.defender_coverage.mock_fallback")
        return _generate_mock_response()

    # ── Graph API path ─────────────────────────────────────────────
    try:
        from kiota_abstractions.base_request_configuration import RequestConfiguration

        query = _SecureScoreControlProfilesQueryParameters(
            top=200,  # Fetch all profiles in one page (typical tenants have < 100)
        )
        config = RequestConfiguration(query_parameters=query)
        response = await client.security.secure_score_control_profiles.get(
            request_configuration=config,
        )

        all_profiles = response.value if response and response.value else []

        if not all_profiles:
            logger.warning("tool.defender_coverage.empty_response")
            mock = _generate_mock_response()
            mock["data_source"] = "graph_api_empty"
            return mock

        # Filter out deprecated controls
        active_profiles = [p for p in all_profiles if not getattr(p, "deprecated", False)]

        workloads = _aggregate_workloads(active_profiles)
        overall = _compute_overall_coverage(workloads)
        total_gaps = sum(len(w["gaps"]) for w in workloads.values())
        critical_gaps = _collect_critical_gaps(active_profiles)

        result: dict[str, Any] = {
            "overall_coverage_pct": overall,
            "workloads": workloads,
            "total_gaps": total_gaps,
            "critical_gaps": critical_gaps,
            "assessed_at": datetime.now(UTC).isoformat(),
            "data_source": "graph_api",
        }

        logger.info(
            "tool.defender_coverage.complete",
            overall_coverage=overall,
            total_gaps=total_gaps,
            data_source="graph_api",
        )
        return result

    except Exception as exc:
        logger.error(
            "tool.defender_coverage.graph_error",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        logger.info("tool.defender_coverage.error_fallback_to_mock")
        mock = _generate_mock_response()
        mock["data_source"] = "mock"
        return mock
