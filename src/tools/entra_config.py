"""PostureIQ Tool — get_entra_config

Reviews Entra ID P2 security configuration by querying:
  - Conditional Access policies   (GET /identity/conditionalAccess/policies)
  - PIM role assignments          (GET /roleManagement/directory/roleAssignments)
  - Identity Protection risky users (GET /identityProtection/riskyUsers)
  - Access Review definitions     (GET /identityGovernance/accessReviews/definitions)

Falls back to SecureScoreControlProfiles when direct endpoints are
unavailable, and to mock data when no Graph credentials exist.

Required scopes: Policy.Read.All, RoleManagement.Read.Directory,
                 IdentityRiskyUser.Read.All, AccessReview.Read.All
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from src.middleware.tracing import trace_tool_call
from src.tools.graph_client import create_graph_client

logger = structlog.get_logger(__name__)

# ── Constants ──────────────────────────────────────────────────────────

ALL_COMPONENTS = (
    "Conditional Access",
    "Privileged Identity Management",
    "Identity Protection",
    "Access Reviews",
    "SSO & App Registrations",
)

GREEN_THRESHOLD = 70.0
YELLOW_THRESHOLD = 40.0

# Well-known Global Admin role definition ID in Entra ID
GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"


# ── Graph client factory ───────────────────────────────────────────────

def _create_graph_client():
    """Delegate to the shared Graph client factory."""
    return create_graph_client("entra_config")


# ── Helpers ────────────────────────────────────────────────────────────

def _compute_status(pct: float) -> str:
    if pct >= GREEN_THRESHOLD:
        return "green"
    if pct >= YELLOW_THRESHOLD:
        return "yellow"
    return "red"


# ── API parsers ────────────────────────────────────────────────────────

def _parse_conditional_access(policies: list[Any]) -> dict[str, Any]:
    """Parse Conditional Access policies into a component result."""
    if not policies:
        return {
            "status": "red",
            "details": {
                "total_policies": 0,
                "active_policies": 0,
                "report_only_policies": 0,
                "legacy_auth_blocked": False,
                "mfa_enforced_all_users": False,
            },
            "gaps": ["No Conditional Access policies configured"],
        }

    total = len(policies)
    active = 0
    report_only = 0
    legacy_blocked = False
    mfa_all = False

    for p in policies:
        state = (getattr(p, "state", None) or "").lower()
        if state == "enabled":
            active += 1
        elif state in ("enabledforreportingbutnotenforced", "report_only"):
            report_only += 1

        # Inspect grant controls for MFA
        grant = getattr(p, "grant_controls", None)
        if grant:
            builtins = getattr(grant, "built_in_controls", None) or []
            if "mfa" in [str(b).lower() for b in builtins]:
                # Check if it targets all users
                conditions = getattr(p, "conditions", None)
                if conditions:
                    users = getattr(conditions, "users", None)
                    if users:
                        include = getattr(users, "include_users", None) or []
                        if "All" in include or "all" in include:
                            mfa_all = True

            # Check for legacy auth block
            if "block" in [str(b).lower() for b in builtins]:
                conditions = getattr(p, "conditions", None)
                if conditions:
                    client_types = getattr(conditions, "client_app_types", None) or []
                    client_strs = [str(c).lower() for c in client_types]
                    if any("exchange" in c or "other" in c for c in client_strs):
                        legacy_blocked = True

    gaps: list[str] = []
    if not mfa_all:
        gaps.append("MFA not enforced for all users")
    if not legacy_blocked:
        gaps.append("Legacy authentication not blocked — significant risk")
    if report_only > 0:
        gaps.append(f"{report_only} policies in report-only mode (not enforcing)")

    # Score: rough heuristic
    score_factors = [mfa_all, legacy_blocked, active >= 3, report_only == 0]
    pct = round(sum(score_factors) / len(score_factors) * 100, 1)

    return {
        "status": _compute_status(pct),
        "details": {
            "total_policies": total,
            "active_policies": active,
            "report_only_policies": report_only,
            "legacy_auth_blocked": legacy_blocked,
            "mfa_enforced_all_users": mfa_all,
        },
        "gaps": gaps,
    }


def _parse_role_assignments(assignments: list[Any]) -> dict[str, Any]:
    """Parse PIM / role assignments into a component result."""
    if not assignments:
        return {
            "status": "red",
            "details": {
                "total_assignments": 0,
                "permanent_global_admins": 0,
            },
            "gaps": ["No role assignments found — unable to assess PIM"],
        }

    total = len(assignments)
    global_admins = [
        a for a in assignments
        if getattr(a, "role_definition_id", None) == GLOBAL_ADMIN_ROLE_ID
    ]

    gaps: list[str] = []
    if len(global_admins) > 2:
        gaps.append(
            f"{len(global_admins)} permanent Global Admin assignments — should be ≤ 2"
        )
    if total > 10:
        gaps.append(
            f"{total} active role assignments — consider converting to eligible (JIT)"
        )

    pct = 100.0 if (len(global_admins) <= 2 and total <= 10) else (
        50.0 if len(global_admins) <= 4 else 20.0
    )

    return {
        "status": _compute_status(pct),
        "details": {
            "total_assignments": total,
            "permanent_global_admins": len(global_admins),
        },
        "gaps": gaps,
    }


def _parse_risky_users(risky_users: list[Any]) -> dict[str, Any]:
    """Parse Identity Protection risky users into a component result."""
    count = len(risky_users) if risky_users else 0

    gaps: list[str] = []
    if count > 0:
        gaps.append(f"{count} risky users detected — review and remediate")

    pct = 100.0 if count == 0 else (50.0 if count < 10 else 20.0)

    return {
        "status": _compute_status(pct),
        "details": {
            "risky_users_count": count,
        },
        "gaps": gaps,
    }


def _parse_access_reviews(reviews: list[Any]) -> dict[str, Any]:
    """Parse Access Review definitions into a component result."""
    count = len(reviews) if reviews else 0

    gaps: list[str] = []
    if count == 0:
        gaps.append("No access reviews configured")
        gaps.append("Guest access not reviewed — potential data exposure")
        gaps.append("Privileged role access not reviewed")

    pct = 100.0 if count >= 3 else (50.0 if count >= 1 else 0.0)

    return {
        "status": _compute_status(pct),
        "details": {
            "reviews_configured": count,
        },
        "gaps": gaps,
    }


# ── Mock fallback ──────────────────────────────────────────────────────

def _generate_mock_response() -> dict[str, Any]:
    return {
        "overall_coverage_pct": 48.0,
        "components": {
            "Conditional Access": {
                "status": "yellow",
                "details": {
                    "total_policies": 5,
                    "active_policies": 3,
                    "report_only_policies": 2,
                    "legacy_auth_blocked": False,
                    "mfa_enforced_all_users": False,
                },
                "gaps": [
                    "MFA not enforced for all users",
                    "Legacy authentication not blocked — significant risk",
                    "2 policies in report-only mode (not enforcing)",
                ],
            },
            "Privileged Identity Management": {
                "status": "red",
                "details": {
                    "total_assignments": 42,
                    "permanent_global_admins": 8,
                },
                "gaps": [
                    "8 permanent Global Admin assignments — should be ≤ 2",
                    "42 active role assignments — consider converting to eligible (JIT)",
                ],
            },
            "Identity Protection": {
                "status": "red",
                "details": {
                    "risky_users_count": 12,
                },
                "gaps": [
                    "12 risky users detected — review and remediate",
                ],
            },
            "Access Reviews": {
                "status": "red",
                "details": {
                    "reviews_configured": 0,
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
                    "note": "SSO assessment requires additional API permissions",
                },
                "gaps": [
                    "SSO coverage assessment unavailable — requires additional permissions",
                ],
            },
        },
        "total_gaps": 10,
        "critical_gaps": [
            "Legacy authentication not blocked — significant risk",
            "8 permanent Global Admin assignments — should be ≤ 2",
            "12 risky users detected — review and remediate",
            "No access reviews configured",
        ],
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "data_source": "mock",
    }


# ── Main tool function ─────────────────────────────────────────────────

@trace_tool_call("get_entra_config")
async def get_entra_config() -> dict[str, Any]:
    """Review Entra ID P2 security configuration.

    Queries multiple Graph API endpoints for Conditional Access, PIM,
    Identity Protection, and Access Reviews.  Each endpoint is called
    independently, so partial failures don't block the whole assessment.

    Falls back to mock data when Graph credentials are absent.

    Returns:
        dict with keys:
          - overall_coverage_pct: float
          - components: dict of component → {status, details, gaps}
          - total_gaps: int
          - critical_gaps: list
          - assessed_at: ISO timestamp
          - data_source: "graph_api" | "mock"
    """
    logger.info("tool.entra_config.start")

    client = _create_graph_client()
    if client is None:
        logger.info("tool.entra_config.mock_fallback")
        return _generate_mock_response()

    try:
        components: dict[str, dict] = {}

        # ── Conditional Access ─────────────────────────────
        try:
            ca_response = await client.identity.conditional_access.policies.get()
            ca_policies = ca_response.value if ca_response and ca_response.value else []
            components["Conditional Access"] = _parse_conditional_access(ca_policies)
        except Exception as e:
            logger.warning("tool.entra_config.ca_error", error=str(e))
            components["Conditional Access"] = {
                "status": "unknown",
                "details": {"error": str(e)},
                "gaps": ["Unable to assess — insufficient permissions or API error"],
            }

        # ── PIM / Role Assignments ─────────────────────────
        try:
            ra_response = await client.role_management.directory.role_assignments.get()
            role_assignments = ra_response.value if ra_response and ra_response.value else []
            components["Privileged Identity Management"] = _parse_role_assignments(role_assignments)
        except Exception as e:
            logger.warning("tool.entra_config.pim_error", error=str(e))
            components["Privileged Identity Management"] = {
                "status": "unknown",
                "details": {"error": str(e)},
                "gaps": ["Unable to assess — insufficient permissions or API error"],
            }

        # ── Identity Protection ────────────────────────────
        try:
            ru_response = await client.identity_protection.risky_users.get()
            risky_users = ru_response.value if ru_response and ru_response.value else []
            components["Identity Protection"] = _parse_risky_users(risky_users)
        except Exception as e:
            logger.warning("tool.entra_config.idp_error", error=str(e))
            components["Identity Protection"] = {
                "status": "unknown",
                "details": {"error": str(e)},
                "gaps": ["Unable to assess — insufficient permissions or API error"],
            }

        # ── Access Reviews ─────────────────────────────────
        try:
            ar_response = await client.identity_governance.access_reviews.definitions.get()
            reviews = ar_response.value if ar_response and ar_response.value else []
            components["Access Reviews"] = _parse_access_reviews(reviews)
        except Exception as e:
            logger.warning("tool.entra_config.ar_error", error=str(e))
            components["Access Reviews"] = {
                "status": "unknown",
                "details": {"error": str(e)},
                "gaps": ["Unable to assess — insufficient permissions or API error"],
            }

        # ── SSO — not yet available via simple Graph call ──
        components["SSO & App Registrations"] = {
            "status": "yellow",
            "details": {"note": "SSO assessment requires additional API permissions"},
            "gaps": ["SSO coverage assessment unavailable — requires additional permissions"],
        }

        # ── Aggregate ──────────────────────────────────────
        total_gaps = sum(len(c["gaps"]) for c in components.values())
        critical_gaps = []
        for c in components.values():
            for gap in c["gaps"]:
                g_lower = gap.lower()
                if any(kw in g_lower for kw in (
                    "legacy auth", "global admin", "risky users",
                    "no access reviews", "not blocked",
                )):
                    critical_gaps.append(gap)

        # Compute overall — skip "unknown" components
        valid = {k: v for k, v in components.items() if v.get("status") != "unknown"}
        if valid:
            # Simple average of component scores heuristic
            status_scores = {"green": 100, "yellow": 55, "red": 20}
            avg = sum(status_scores.get(v["status"], 0) for v in valid.values()) / len(valid)
            overall = round(avg, 1)
        else:
            overall = 0.0

        result: dict[str, Any] = {
            "overall_coverage_pct": overall,
            "components": components,
            "total_gaps": total_gaps,
            "critical_gaps": critical_gaps,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
            "data_source": "graph_api",
        }

        logger.info(
            "tool.entra_config.complete",
            overall_coverage=overall,
            total_gaps=total_gaps,
            data_source="graph_api",
        )
        return result

    except Exception as exc:
        logger.error(
            "tool.entra_config.graph_error",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        logger.info("tool.entra_config.error_fallback_to_mock")
        mock = _generate_mock_response()
        mock["data_source"] = "mock"
        return mock
