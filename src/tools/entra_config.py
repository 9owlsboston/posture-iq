"""PostureIQ Tool — get_entra_config

Reviews Entra ID P2 security configuration including Conditional Access,
PIM, Identity Protection, Access Reviews, and SSO registrations.

Graph API endpoints:
  - Conditional Access: GET /identity/conditionalAccess/policies
  - PIM: GET /roleManagement/directory/roleAssignments
  - Identity Protection: GET /identityProtection/riskDetections
  - Access Reviews: GET /identityGovernance/accessReviews
Required scope: Policy.Read.All
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from src.middleware.tracing import trace_tool_call

logger = structlog.get_logger(__name__)


@trace_tool_call("get_entra_config")
async def get_entra_config() -> dict[str, Any]:
    """Review Entra ID P2 security configuration.

    Returns:
        dict with keys:
          - overall_coverage_pct: float
          - components: dict of component → {status, details, gaps}
          - total_gaps: int
          - critical_gaps: list
          - assessed_at: ISO timestamp
    """
    logger.info("tool.entra_config.start")

    # TODO: Replace with actual Graph API calls
    #
    # Conditional Access:
    #   GET /identity/conditionalAccess/policies
    #   Count active policies, check for MFA enforcement, named locations
    #
    # PIM:
    #   GET /roleManagement/directory/roleAssignments
    #   Compare active (permanent) vs eligible assignments
    #
    # Identity Protection:
    #   GET /identityProtection/riskyUsers
    #   GET /policies/identitySecurityDefaultsEnforcementPolicy
    #   Check sign-in risk policy, user risk policy
    #
    # Access Reviews:
    #   GET /identityGovernance/accessReviews/definitions
    #   Check if reviews are configured

    # ── Mock response for development ──────────────────────
    result = {
        "overall_coverage_pct": 48.0,
        "components": {
            "Conditional Access": {
                "status": "yellow",
                "details": {
                    "total_policies": 5,
                    "active_policies": 3,
                    "report_only_policies": 2,
                    "mfa_enforced_all_users": False,
                    "mfa_enforced_admins": True,
                    "named_locations_configured": 2,
                    "device_compliance_required": False,
                    "legacy_auth_blocked": False,
                },
                "gaps": [
                    "MFA not enforced for all users (only admins)",
                    "Legacy authentication not blocked — significant risk",
                    "Device compliance not required for access",
                    "2 policies in report-only mode (not enforcing)",
                ],
            },
            "Privileged Identity Management": {
                "status": "red",
                "details": {
                    "total_role_assignments": 42,
                    "permanent_active_assignments": 35,
                    "eligible_assignments": 7,
                    "permanent_global_admins": 8,
                    "just_in_time_enabled": True,
                    "approval_required_for_activation": False,
                },
                "gaps": [
                    "83% of role assignments are permanent (should be eligible/JIT)",
                    "8 permanent Global Admin assignments — should be ≤ 2",
                    "No approval required for role activation",
                    "No access review configured for privileged roles",
                ],
            },
            "Identity Protection": {
                "status": "red",
                "details": {
                    "sign_in_risk_policy_enabled": False,
                    "user_risk_policy_enabled": False,
                    "risky_users_count": 12,
                    "risky_sign_ins_last_30d": 47,
                    "mfa_registration_policy": True,
                },
                "gaps": [
                    "Sign-in risk policy not enabled — 47 risky sign-ins in last 30 days unaddressed",
                    "User risk policy not enabled — 12 risky users not remediated",
                    "No automated risk remediation configured",
                ],
            },
            "Access Reviews": {
                "status": "red",
                "details": {
                    "reviews_configured": 0,
                    "guest_access_review": False,
                    "privileged_role_review": False,
                    "group_membership_review": False,
                },
                "gaps": [
                    "No access reviews configured",
                    "Guest access not reviewed — potential data exposure",
                    "Privileged role access not reviewed",
                ],
            },
            "SSO & App Registrations": {
                "status": "yellow",
                "details": {
                    "enterprise_apps_total": 156,
                    "sso_enabled_apps": 42,
                    "apps_with_expired_credentials": 8,
                    "apps_with_excessive_permissions": 15,
                },
                "gaps": [
                    "Only 27% of enterprise apps have SSO enabled",
                    "8 apps have expired credentials",
                    "15 apps have excessive Graph API permissions",
                ],
            },
        },
        "total_gaps": 16,
        "critical_gaps": [
            "Legacy authentication not blocked",
            "83% of privileged role assignments are permanent (not JIT)",
            "Identity Protection risk policies not enabled despite 47 risky sign-ins",
            "No access reviews configured for any resource type",
        ],
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "tool.entra_config.complete",
        overall_coverage=result["overall_coverage_pct"],
        total_gaps=result["total_gaps"],
    )

    return result
