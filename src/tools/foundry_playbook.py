"""PostureIQ Tool — get_project479_playbook

Retrieves relevant Project 479 playbook sections from Foundry IQ based on
identified security gaps.  Provides the agent with actionable context:

  * **ME5 Get to Green standard playbook** — step-by-step remediation
    workflow per workload area.
  * **Offer catalog** — which Project 479 offers to recommend based on gaps.
  * **Customer onboarding checklists** — readiness tasks for each ME5
    security workload.

When a live Foundry IQ API is unavailable the tool returns built-in
playbook content that mirrors the real structure, so the agent always has
useful context.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from src.agent.config import settings
from src.middleware.tracing import trace_tool_call

logger = structlog.get_logger(__name__)


# ── Constants ──────────────────────────────────────────────────────────

PLAYBOOK_VERSION = "2026.2"

# Canonical workload area keys (aligned with the scorecard tool)
WORKLOAD_AREAS: list[str] = [
    "defender_endpoint",
    "defender_office365",
    "defender_identity",
    "defender_cloud_apps",
    "purview_dlp",
    "purview_labels",
    "purview_retention",
    "purview_insider_risk",
    "entra_conditional_access",
    "entra_pim",
    "entra_identity_protection",
    "entra_access_reviews",
]

# ── Built-in Playbook Content ──────────────────────────────────────────
# Structured playbooks that mirror the Foundry IQ Project 479 knowledge
# base.  Each entry maps a workload area to its remediation playbook,
# recommended Project 479 offer, and onboarding checklist.

_PLAYBOOKS: dict[str, dict[str, Any]] = {
    # ── Defender XDR ───────────────────────────────────────
    "defender_endpoint": {
        "title": "Microsoft Defender for Endpoint — Get to Green",
        "remediation_playbook": [
            "1. Enable Defender for Endpoint Plan 2 in the M365 Security portal.",
            "2. Configure device onboarding via Intune MDM enrollment policy.",
            "3. Set attack surface reduction (ASR) rules to audit → block.",
            "4. Enable automated investigation & response (AIR).",
            "5. Deploy endpoint detection & response (EDR) in block mode.",
            "6. Configure web content filtering and network protection.",
            "7. Validate with simulated attack evaluation lab.",
        ],
        "offer": {
            "name": "Defender XDR Deployment Workshop",
            "id": "P479-DEF-001",
            "description": (
                "Two-day hands-on workshop covering onboarding, ASR rules, AIR configuration, and threat analytics."
            ),
            "duration": "2 days",
            "delivery": "Remote or on-site",
        },
        "onboarding_checklist": [
            "☐ Verify M365 E5 or ME5 licensing for all target users",
            "☐ Ensure Intune device enrollment is configured",
            "☐ Identify pilot group (50–100 devices)",
            "☐ Collect current AV/EDR product list for migration planning",
            "☐ Confirm network proxy/firewall allows Defender cloud traffic",
        ],
        "estimated_effort": "3–5 days",
        "impact_on_score": 8.0,
    },
    "defender_office365": {
        "title": "Microsoft Defender for Office 365 — Get to Green",
        "remediation_playbook": [
            "1. Enable Safe Attachments policy with Dynamic Delivery.",
            "2. Enable Safe Links policy for email, Teams, and Office apps.",
            "3. Configure anti-phishing policies with mailbox intelligence.",
            "4. Enable zero-hour auto purge (ZAP) for malware and phish.",
            "5. Set up attack simulation training for end users.",
            "6. Review and tune alert policies for high-confidence phishing.",
        ],
        "offer": {
            "name": "Email Protection Optimization",
            "id": "P479-DEF-002",
            "description": (
                "One-day assessment and configuration of Safe Attachments, Safe Links, and anti-phishing policies."
            ),
            "duration": "1 day",
            "delivery": "Remote",
        },
        "onboarding_checklist": [
            "☐ Confirm Exchange Online licensing for target mailboxes",
            "☐ Identify VIP / high-risk user list",
            "☐ Document current third-party email security gateway",
            "☐ Plan mail-flow rule migration if replacing gateway",
        ],
        "estimated_effort": "1–2 days",
        "impact_on_score": 6.0,
    },
    "defender_identity": {
        "title": "Microsoft Defender for Identity — Get to Green",
        "remediation_playbook": [
            "1. Install Defender for Identity sensors on all domain controllers.",
            "2. Configure a Directory Service account (gMSA recommended).",
            "3. Integrate with Defender for Endpoint for cross-signal detection.",
            "4. Resolve all health alerts in the Defender for Identity portal.",
            "5. Enable honeytoken account detection.",
            "6. Review and remediate exposed lateral movement paths.",
        ],
        "offer": {
            "name": "Identity Threat Protection Engagement",
            "id": "P479-DEF-003",
            "description": (
                "Sensor deployment, health remediation, and lateral movement path analysis with the customer's AD team."
            ),
            "duration": "2 days",
            "delivery": "Remote or on-site",
        },
        "onboarding_checklist": [
            "☐ Inventory all domain controllers (forest-wide)",
            "☐ Confirm .NET Framework 4.7+ on DCs",
            "☐ Ensure port 443 outbound to Defender for Identity cloud",
            "☐ Create gMSA account with DS read permissions",
        ],
        "estimated_effort": "2–3 days",
        "impact_on_score": 7.0,
    },
    "defender_cloud_apps": {
        "title": "Microsoft Defender for Cloud Apps — Get to Green",
        "remediation_playbook": [
            "1. Connect sanctioned SaaS apps (Salesforce, Box, etc.) as API connectors.",
            "2. Enable Cloud Discovery with Defender for Endpoint log integration.",
            "3. Configure session policies for Conditional Access App Control.",
            "4. Set up anomaly detection policies (impossible travel, mass download).",
            "5. Create file policies for sensitive content in cloud storage.",
        ],
        "offer": {
            "name": "Cloud App Security Assessment",
            "id": "P479-DEF-004",
            "description": ("Shadow IT discovery, API connector setup, and session policy configuration workshop."),
            "duration": "1–2 days",
            "delivery": "Remote",
        },
        "onboarding_checklist": [
            "☐ List sanctioned SaaS applications",
            "☐ Confirm admin credentials for API connector setup",
            "☐ Identify high-risk apps for Conditional Access App Control",
        ],
        "estimated_effort": "1–2 days",
        "impact_on_score": 5.0,
    },
    # ── Purview ────────────────────────────────────────────
    "purview_dlp": {
        "title": "Microsoft Purview DLP — Get to Green",
        "remediation_playbook": [
            "1. Identify sensitive information types (SITs) relevant to the org.",
            "2. Create DLP policies for Exchange, SharePoint, OneDrive, and Teams.",
            "3. Start in test mode (audit-only), review policy matches.",
            "4. Enable policy tips for end-user education.",
            "5. Switch policies to enforce mode after tuning false positives.",
            "6. Configure endpoint DLP for managed devices.",
        ],
        "offer": {
            "name": "Data Loss Prevention Workshop",
            "id": "P479-PUR-001",
            "description": (
                "Classification strategy, SIT customization, and DLP policy deployment across M365 workloads."
            ),
            "duration": "2 days",
            "delivery": "Remote",
        },
        "onboarding_checklist": [
            "☐ Identify regulatory requirements (GDPR, HIPAA, PCI-DSS, etc.)",
            "☐ Document existing DLP or classification tools",
            "☐ Identify pilot department / data set",
        ],
        "estimated_effort": "3–5 days",
        "impact_on_score": 6.0,
    },
    "purview_labels": {
        "title": "Microsoft Purview Sensitivity Labels — Get to Green",
        "remediation_playbook": [
            "1. Design a label taxonomy (Public, Internal, Confidential, Highly Confidential).",
            "2. Publish labels to all users via label policies.",
            "3. Configure default labeling for new Office documents.",
            "4. Enable auto-labeling for documents matching SITs.",
            "5. Extend labels to containers (Teams, Groups, Sites).",
        ],
        "offer": {
            "name": "Information Protection Readiness",
            "id": "P479-PUR-002",
            "description": (
                "Label taxonomy design, publishing, and auto-labeling strategy "
                "aligned with data classification requirements."
            ),
            "duration": "1–2 days",
            "delivery": "Remote",
        },
        "onboarding_checklist": [
            "☐ Review existing classification scheme (if any)",
            "☐ Identify data stewards / classification owners",
            "☐ Confirm Azure Information Protection (AIP) add-in status",
        ],
        "estimated_effort": "2–3 days",
        "impact_on_score": 5.0,
    },
    "purview_retention": {
        "title": "Microsoft Purview Retention Policies — Get to Green",
        "remediation_playbook": [
            "1. Define retention schedule per data source (email, files, Teams).",
            "2. Create org-wide retention policies in the Purview compliance portal.",
            "3. Configure retention labels for records management use cases.",
            "4. Enable auto-apply retention labels for regulatory content.",
            "5. Validate with eDiscovery search against retained content.",
        ],
        "offer": {
            "name": "Records & Retention Strategy",
            "id": "P479-PUR-003",
            "description": ("Retention schedule development, policy creation, and records management configuration."),
            "duration": "1 day",
            "delivery": "Remote",
        },
        "onboarding_checklist": [
            "☐ Document legal / compliance retention requirements",
            "☐ Identify data sources requiring retention (Exchange, SPO, Teams, etc.)",
        ],
        "estimated_effort": "1–2 days",
        "impact_on_score": 4.0,
    },
    "purview_insider_risk": {
        "title": "Microsoft Purview Insider Risk Management — Get to Green",
        "remediation_playbook": [
            "1. Enable Insider Risk Management in the Purview compliance portal.",
            "2. Configure HR connector for termination / resignation signals.",
            "3. Create data theft and data leak policy templates.",
            "4. Set risk indicator thresholds (data exfil volume, sequences).",
            "5. Designate Insider Risk analysts and investigators.",
        ],
        "offer": {
            "name": "Insider Risk Management Workshop",
            "id": "P479-PUR-004",
            "description": ("Config-based setup: HR connector, policy templates, and analyst role assignment."),
            "duration": "1 day",
            "delivery": "Remote",
        },
        "onboarding_checklist": [
            "☐ Confirm M365 E5 Insider Risk Management licensing",
            "☐ Identify HR data source for connector",
            "☐ Designate investigation team with appropriate RBAC roles",
        ],
        "estimated_effort": "1–2 days",
        "impact_on_score": 4.0,
    },
    # ── Entra ID P2 ────────────────────────────────────────
    "entra_conditional_access": {
        "title": "Entra ID Conditional Access — Get to Green",
        "remediation_playbook": [
            "1. Implement baseline CA policies: require MFA for all users.",
            "2. Block legacy authentication protocols.",
            "3. Require compliant or hybrid-joined devices for corporate apps.",
            "4. Configure risk-based CA policies (sign-in risk, user risk).",
            "5. Enable session controls for sensitive apps (sign-in frequency).",
            "6. Create named locations for trusted networks.",
        ],
        "offer": {
            "name": "Conditional Access Hardening",
            "id": "P479-EID-001",
            "description": ("Architecture review, policy design, and staged rollout of Conditional Access policies."),
            "duration": "2 days",
            "delivery": "Remote or on-site",
        },
        "onboarding_checklist": [
            "☐ Inventory existing CA policies (export from Entra portal)",
            "☐ Identify break-glass / emergency accounts",
            "☐ Document MFA registration status across user base",
            "☐ Identify legacy auth–dependent applications",
        ],
        "estimated_effort": "2–3 days",
        "impact_on_score": 9.0,
    },
    "entra_pim": {
        "title": "Entra ID Privileged Identity Management — Get to Green",
        "remediation_playbook": [
            "1. Convert permanent admin assignments to PIM-eligible.",
            "2. Configure activation requirements (MFA, justification, approval).",
            "3. Set maximum activation duration (8 hours recommended).",
            "4. Enable PIM alerts for stale and excessive assignments.",
            "5. Create access reviews for privileged roles (quarterly).",
        ],
        "offer": {
            "name": "Privileged Access Management Engagement",
            "id": "P479-EID-002",
            "description": (
                "PIM rollout: role inventory, migration from permanent to "
                "eligible, activation policies, and alert setup."
            ),
            "duration": "1–2 days",
            "delivery": "Remote",
        },
        "onboarding_checklist": [
            "☐ Export current role assignments from Entra ID",
            "☐ Identify role owners / approvers",
            "☐ Confirm Entra ID P2 licensing",
        ],
        "estimated_effort": "1–2 days",
        "impact_on_score": 7.0,
    },
    "entra_identity_protection": {
        "title": "Entra ID Identity Protection — Get to Green",
        "remediation_playbook": [
            "1. Enable user risk policy: require password change at high risk.",
            "2. Enable sign-in risk policy: require MFA at medium+ risk.",
            "3. Configure risk-based Conditional Access policies.",
            "4. Review risky users and risky sign-ins reports weekly.",
            "5. Integrate risk signals with SIEM/SOAR via Graph API.",
        ],
        "offer": {
            "name": "Identity Protection Configuration",
            "id": "P479-EID-003",
            "description": ("Risk policy setup, tuning, and integration with existing security operations workflows."),
            "duration": "1 day",
            "delivery": "Remote",
        },
        "onboarding_checklist": [
            "☐ Confirm Entra ID P2 licensing",
            "☐ Review current MFA coverage",
            "☐ Identify SIEM integration requirements",
        ],
        "estimated_effort": "1 day",
        "impact_on_score": 6.0,
    },
    "entra_access_reviews": {
        "title": "Entra ID Access Reviews — Get to Green",
        "remediation_playbook": [
            "1. Create access reviews for privileged roles (Global Admin, etc.).",
            "2. Create access reviews for guest users in sensitive groups.",
            "3. Configure auto-apply of review decisions.",
            "4. Set review frequency: quarterly for privileged, semi-annual for guests.",
            "5. Assign reviewers: resource owners or managers.",
        ],
        "offer": {
            "name": "Access Governance Workshop",
            "id": "P479-EID-004",
            "description": (
                "Access review design, entitlement management setup, and governance reporting configuration."
            ),
            "duration": "1 day",
            "delivery": "Remote",
        },
        "onboarding_checklist": [
            "☐ Identify groups and roles requiring periodic review",
            "☐ Confirm Entra ID P2 licensing",
            "☐ Designate review owners / delegates",
        ],
        "estimated_effort": "1 day",
        "impact_on_score": 4.0,
    },
}


# ── Gap-to-Workload Mapping ───────────────────────────────────────────

# Maps common gap keywords / phrases from assessment tools to workload area keys.
_GAP_KEYWORD_MAP: dict[str, str] = {
    # Defender
    "endpoint": "defender_endpoint",
    "device onboarding": "defender_endpoint",
    "edr": "defender_endpoint",
    "asr": "defender_endpoint",
    "safe attachments": "defender_office365",
    "safe links": "defender_office365",
    "anti-phishing": "defender_office365",
    "phishing": "defender_office365",
    "email protection": "defender_office365",
    "identity sensor": "defender_identity",
    "domain controller": "defender_identity",
    "lateral movement": "defender_identity",
    "cloud apps": "defender_cloud_apps",
    "shadow it": "defender_cloud_apps",
    "cloud discovery": "defender_cloud_apps",
    "session policy": "defender_cloud_apps",
    # Purview
    "dlp": "purview_dlp",
    "data loss": "purview_dlp",
    "sensitivity label": "purview_labels",
    "classification": "purview_labels",
    "auto-labeling": "purview_labels",
    "retention": "purview_retention",
    "records management": "purview_retention",
    "insider risk": "purview_insider_risk",
    "data theft": "purview_insider_risk",
    "data leak": "purview_insider_risk",
    # Entra
    "conditional access": "entra_conditional_access",
    "mfa": "entra_conditional_access",
    "legacy auth": "entra_conditional_access",
    "pim": "entra_pim",
    "privileged": "entra_pim",
    "eligible assignment": "entra_pim",
    "identity protection": "entra_identity_protection",
    "risk policy": "entra_identity_protection",
    "risky sign-in": "entra_identity_protection",
    "access review": "entra_access_reviews",
    "guest access": "entra_access_reviews",
}


def _identify_workload_areas(gaps: list[str]) -> list[str]:
    """Map a list of gap descriptions to unique workload area keys.

    Scans each gap for keywords and returns matching workload area keys
    (deduplicated, preserving insertion order).

    Args:
        gaps: List of gap description strings from assessment tools.

    Returns:
        Ordered list of unique workload area keys.
    """
    matched: dict[str, None] = {}  # ordered-set via dict
    for gap in gaps:
        gap_lower = gap.lower()
        for keyword, area in _GAP_KEYWORD_MAP.items():
            if keyword in gap_lower and area not in matched:
                matched[area] = None
    return list(matched.keys())


# ── Foundry IQ Client ─────────────────────────────────────────────────


def _create_foundry_client() -> dict[str, Any] | None:
    """Create a Foundry IQ API client.

    Returns None when the Foundry IQ endpoint is not configured,
    triggering the built-in playbook fallback.
    """
    endpoint = settings.foundry_iq_endpoint
    if not endpoint:
        logger.info(
            "tool.foundry_playbook.client.skipped",
            reason="Foundry IQ endpoint not configured — using built-in playbooks",
        )
        return None

    # Placeholder for real Foundry IQ SDK client
    logger.info("tool.foundry_playbook.client.created", endpoint=endpoint)
    return {"endpoint": endpoint}


async def _fetch_from_foundry(
    client: dict[str, Any],
    workload_areas: list[str],
) -> dict[str, Any] | None:
    """Fetch playbook content from the live Foundry IQ API.

    Args:
        client: Foundry IQ client dict (or SDK instance).
        workload_areas: Workload area keys to retrieve playbooks for.

    Returns:
        Dict of playbook data keyed by workload area, or None on failure.
    """
    try:
        # Placeholder — in production this would call the Foundry IQ REST API
        # e.g. POST /api/playbooks/query with workload_areas body
        logger.info(
            "tool.foundry_playbook.fetch_remote",
            workload_areas=workload_areas,
            endpoint=client["endpoint"],
        )
        return None  # Fallback to built-in playbooks
    except Exception as exc:
        logger.warning(
            "tool.foundry_playbook.fetch_failed",
            error=str(exc),
        )
        return None


def _get_built_in_playbooks(
    workload_areas: list[str],
) -> dict[str, dict[str, Any]]:
    """Retrieve built-in playbook sections for the given workload areas.

    Args:
        workload_areas: Workload area keys to retrieve.

    Returns:
        Subset of ``_PLAYBOOKS`` matching the requested areas.
        Returns all playbooks if ``workload_areas`` is empty.
    """
    if not workload_areas:
        return dict(_PLAYBOOKS)

    return {area: _PLAYBOOKS[area] for area in workload_areas if area in _PLAYBOOKS}


def _build_playbook_context(
    playbooks: dict[str, dict[str, Any]],
) -> str:
    """Build a concise text summary of playbook content for the LLM context.

    Args:
        playbooks: Dict of playbook entries keyed by workload area.

    Returns:
        Formatted text string summarizing remediation steps, offers, and
        checklists — suitable for injection into the system prompt or tool
        response.
    """
    sections: list[str] = []
    for _area, pb in playbooks.items():
        lines = [f"### {pb['title']}"]
        lines.append("\n**Remediation Steps:**")
        lines.extend(pb["remediation_playbook"])
        offer = pb.get("offer", {})
        if offer:
            lines.append(
                f"\n**Recommended Offer:** {offer['name']} ({offer['id']}) — "
                f"{offer['description']} [{offer['duration']}, {offer['delivery']}]"
            )
        checklist = pb.get("onboarding_checklist", [])
        if checklist:
            lines.append("\n**Onboarding Checklist:**")
            lines.extend(checklist)
        lines.append(
            f"\nEstimated Effort: {pb.get('estimated_effort', 'TBD')} | Score Impact: +{pb.get('impact_on_score', 0)}"
        )
        sections.append("\n".join(lines))
    return "\n\n---\n\n".join(sections)


# ── Public Tool Function ──────────────────────────────────────────────


@trace_tool_call("get_project479_playbook")
async def get_project479_playbook(
    *,
    gaps: list[str] | None = None,
    workload_areas: list[str] | None = None,
    include_offers: bool = True,
    include_checklists: bool = True,
) -> dict[str, Any]:
    """Retrieve Project 479 Get-to-Green playbook sections from Foundry IQ.

    The agent calls this tool after identifying gaps via the assessment tools.
    It maps gaps to workload areas and returns the relevant remediation
    playbooks, recommended Project 479 offers, and onboarding checklists.

    When Foundry IQ is unavailable, returns built-in playbook content that
    mirrors the real structure.

    Args:
        gaps: Optional list of gap descriptions (from assessment tools).
            Used to automatically identify relevant workload areas.
        workload_areas: Optional explicit list of workload area keys.
            Takes precedence over gap-based mapping when provided.
        include_offers: Whether to include Project 479 offer recommendations.
        include_checklists: Whether to include onboarding checklists.

    Returns:
        Dict with playbook_version, matched workload areas, playbook data,
        context summary for LLM, and metadata.
    """
    # Determine workload areas
    if workload_areas:
        # Explicit areas provided — validate against known areas
        valid_areas = [a for a in workload_areas if a in _PLAYBOOKS]
        resolved_areas = valid_areas
    elif gaps:
        resolved_areas = _identify_workload_areas(gaps)
    else:
        # No gaps or areas specified — return all playbooks
        resolved_areas = list(_PLAYBOOKS.keys())

    logger.info(
        "tool.foundry_playbook.resolve",
        requested_gaps=len(gaps or []),
        requested_areas=len(workload_areas or []),
        resolved_areas=resolved_areas,
    )

    # Try Foundry IQ API first, fall back to built-in
    client = _create_foundry_client()
    playbook_data: dict[str, dict[str, Any]] | None = None
    source = "built_in"

    if client:
        playbook_data = await _fetch_from_foundry(client, resolved_areas)
        if playbook_data:
            source = "foundry_iq"

    if not playbook_data:
        playbook_data = _get_built_in_playbooks(resolved_areas)

    # Optionally strip offers / checklists
    if not include_offers or not include_checklists:
        filtered: dict[str, dict[str, Any]] = {}
        for area, pb in playbook_data.items():
            entry = dict(pb)
            if not include_offers:
                entry.pop("offer", None)
            if not include_checklists:
                entry.pop("onboarding_checklist", None)
            filtered[area] = entry
        playbook_data = filtered

    # Build LLM-friendly context summary
    context_summary = _build_playbook_context(playbook_data)

    # Compute aggregate stats
    total_impact = sum(pb.get("impact_on_score", 0) for pb in playbook_data.values())
    offer_ids = [pb["offer"]["id"] for pb in playbook_data.values() if "offer" in pb]

    return {
        "playbook_version": PLAYBOOK_VERSION,
        "source": source,
        "matched_areas": list(playbook_data.keys()),
        "matched_count": len(playbook_data),
        "total_areas": len(_PLAYBOOKS),
        "total_estimated_score_impact": total_impact,
        "recommended_offers": offer_ids,
        "playbooks": {
            area: {
                "title": pb.get("title", ""),
                "remediation_steps": pb.get("remediation_playbook", []),
                "offer": pb.get("offer"),
                "onboarding_checklist": pb.get("onboarding_checklist"),
                "estimated_effort": pb.get("estimated_effort"),
                "impact_on_score": pb.get("impact_on_score", 0),
            }
            for area, pb in playbook_data.items()
        },
        "context_summary": context_summary,
        "timestamp": datetime.now(UTC).isoformat(),
    }
