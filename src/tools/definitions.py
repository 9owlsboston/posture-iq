"""Tool JSON schemas shared between CLI agent (main.py) and Chainlit app.

These OpenAI-compatible function definitions describe the tools available to
the LLM for function calling.  Both the Copilot SDK CLI agent and the
Chainlit web agent import from here to keep schemas in sync.
"""

from __future__ import annotations

TOOL_SCHEMAS: list[dict[str, object]] = [
    {
        "type": "function",
        "function": {
            "name": "query_secure_score",
            "description": (
                "Retrieve the tenant's Microsoft Secure Score. Returns the current "
                "score, category breakdown (Identity, Data, Device, Apps, Infrastructure), "
                "30-day trend, and industry comparison."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "description": (
                            "The tenant identifier to assess (optional — uses current auth context if omitted)"
                        ),
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "assess_defender_coverage",
            "description": (
                "Evaluate M365 Defender deployment status across all workloads: "
                "Defender for Endpoint (device onboarding), Defender for Office 365 "
                "(Safe Links/Attachments), Defender for Identity (sensors), and "
                "Defender for Cloud Apps (connected apps). Returns coverage percentage "
                "per workload and a list of gaps."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_purview_policies",
            "description": (
                "Assess Information Protection & Compliance policy coverage: "
                "DLP policies (count, status, scope), sensitivity labels (published, "
                "auto-labeling), retention policies (Exchange, SharePoint, OneDrive, Teams), "
                "and Insider Risk Management status."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_entra_config",
            "description": (
                "Review Entra ID P2 security configuration: Conditional Access policies, "
                "PIM (active vs eligible assignments), Identity Protection risk policies, "
                "Access Reviews configuration, and SSO app registrations."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_remediation_plan",
            "description": (
                "Generate a prioritized remediation plan based on gaps identified by "
                "the assessment tools. Returns P0/P1/P2 steps, each with description, "
                "Secure Score impact, effort estimate, and PowerShell/CLI configuration "
                "scripts. Includes estimated time-to-green."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_context": {
                        "type": "string",
                        "description": (
                            "JSON summary of findings from secure_score, defender, purview, and entra assessments"
                        ),
                    },
                },
                "required": ["assessment_context"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_adoption_scorecard",
            "description": (
                "Produce a structured ME5 adoption scorecard: overall adoption percentage, "
                "per-workload status (green/yellow/red) for Defender XDR, Purview, and "
                "Entra ID P2, top 5 gaps with priority, estimated days to green, and "
                "historical trend."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "assessment_context": {
                        "type": "string",
                        "description": "JSON summary of all assessment findings",
                    },
                },
                "required": ["assessment_context"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_green_playbook",
            "description": (
                "Retrieve Get to Green Get-to-Green playbooks from Foundry IQ. "
                "Given identified security gaps or workload area keys, returns "
                "step-by-step remediation playbooks, recommended Get to Green offers "
                "(workshops, engagements), and customer onboarding checklists. "
                "Use this AFTER identifying gaps to enrich remediation plans with "
                "Get to Green offer recommendations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "gaps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "List of gap descriptions from assessment tools. "
                            "The tool maps these to workload areas automatically."
                        ),
                    },
                    "workload_areas": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Explicit workload area keys (e.g. defender_endpoint, "
                            "purview_dlp, entra_conditional_access). Takes precedence "
                            "over gap-based mapping."
                        ),
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "push_posture_snapshot",
            "description": (
                "Push a security posture snapshot to the Fabric lakehouse for "
                "longitudinal dashboarding. Call this AFTER completing an assessment "
                "to persist the tenant's current secure score, workload coverage, "
                "gap count, and estimated days-to-green. The tenant ID is hashed "
                "and gap descriptions anonymised before storage."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "description": "Tenant identifier (will be hashed before storage)",
                    },
                    "secure_score_current": {
                        "type": "number",
                        "description": "Current secure score value",
                    },
                    "secure_score_max": {
                        "type": "number",
                        "description": "Maximum possible secure score",
                    },
                    "workload_scores": {
                        "type": "object",
                        "description": "Per-workload coverage percentages",
                    },
                    "gap_count": {
                        "type": "integer",
                        "description": "Total number of identified gaps",
                    },
                    "estimated_days_to_green": {
                        "type": "integer",
                        "description": "Estimated days to green status",
                    },
                    "top_gaps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Top gap descriptions (will be anonymised)",
                    },
                    "assessment_summary": {
                        "type": "string",
                        "description": "Brief assessment summary text",
                    },
                },
                "required": ["tenant_id", "secure_score_current", "secure_score_max"],
            },
        },
    },
]
