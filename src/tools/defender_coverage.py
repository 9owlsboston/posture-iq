"""PostureIQ Tool — assess_defender_coverage

Evaluates M365 Defender deployment status across all workloads.
Returns coverage percentages per workload and a gap list.

Graph API endpoints:
  - Defender for Endpoint: GET /security/alerts_v2 + device management APIs
  - Defender for Office 365: GET /security/secureScoreControlProfiles
  - Defender for Identity: sensor status via Graph
  - Defender for Cloud Apps: connected app status
Required scope: SecurityEvents.Read.All, SecurityActions.Read.All
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from src.middleware.tracing import trace_tool_call

logger = structlog.get_logger(__name__)


@trace_tool_call("assess_defender_coverage")
async def assess_defender_coverage() -> dict[str, Any]:
    """Assess M365 Defender deployment coverage across all workloads.

    Returns:
        dict with keys:
          - overall_coverage_pct: float
          - workloads: dict of workload → {coverage_pct, status, details, gaps}
          - total_gaps: int
          - critical_gaps: list of gap descriptions
          - assessed_at: ISO timestamp
    """
    logger.info("tool.defender_coverage.start")

    # TODO: Replace with actual Graph API calls for each Defender workload
    #
    # For Defender for Endpoint:
    #   GET /deviceManagement/managedDevices → count onboarded vs total
    #
    # For Defender for Office 365:
    #   GET /security/secureScoreControlProfiles → filter Safe Links / Safe Attachments
    #
    # For Defender for Identity:
    #   GET /security/secureScoreControlProfiles → identity sensor controls
    #
    # For Defender for Cloud Apps:
    #   GET /security/secureScoreControlProfiles → MCAS controls

    # ── Mock response for development ──────────────────────
    result = {
        "overall_coverage_pct": 52.0,
        "workloads": {
            "Defender for Endpoint": {
                "coverage_pct": 68.0,
                "status": "yellow",
                "details": {
                    "total_devices": 1250,
                    "onboarded_devices": 850,
                    "policy_compliance_pct": 72.0,
                },
                "gaps": [
                    "400 devices not onboarded (32% gap)",
                    "Attack Surface Reduction rules not enabled on 60% of devices",
                    "Automated investigation not enabled",
                ],
            },
            "Defender for Office 365": {
                "coverage_pct": 45.0,
                "status": "red",
                "details": {
                    "safe_links_enabled": True,
                    "safe_attachments_enabled": False,
                    "anti_phishing_policy": "default_only",
                    "zap_enabled": True,
                },
                "gaps": [
                    "Safe Attachments not enabled — critical gap",
                    "No custom anti-phishing policy (only default)",
                    "No Safe Links policy for Teams",
                ],
            },
            "Defender for Identity": {
                "coverage_pct": 30.0,
                "status": "red",
                "details": {
                    "sensors_deployed": 3,
                    "domain_controllers_total": 12,
                    "sensor_coverage_pct": 25.0,
                },
                "gaps": [
                    "Only 3 of 12 domain controllers have sensors (25% coverage)",
                    "Lateral movement path detection disabled",
                    "No honeytoken accounts configured",
                ],
            },
            "Defender for Cloud Apps": {
                "coverage_pct": 65.0,
                "status": "yellow",
                "details": {
                    "connected_apps": 8,
                    "discovered_apps": 342,
                    "sanctioned_apps": 15,
                    "policies_active": 4,
                },
                "gaps": [
                    "334 discovered apps not reviewed (shadow IT risk)",
                    "No session control policies configured",
                    "OAuth app governance not enabled",
                ],
            },
        },
        "total_gaps": 12,
        "critical_gaps": [
            "Safe Attachments not enabled in Defender for Office 365",
            "Only 25% domain controller sensor coverage in Defender for Identity",
            "400 devices not onboarded to Defender for Endpoint",
        ],
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "tool.defender_coverage.complete",
        overall_coverage=result["overall_coverage_pct"],
        total_gaps=result["total_gaps"],
    )

    return result
