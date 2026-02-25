"""PostureIQ — Agent host entry point.

This is the main application that initializes the Copilot SDK, registers tools,
sets the system prompt, and runs the agent session loop.

Architecture:
    Your App (this file) → Copilot SDK → Agent Runtime → Models + Tools
    The SDK is the thin client; the runtime (Copilot CLI) does the planning.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import structlog

from src.agent.config import settings
from src.agent.system_prompt import SYSTEM_PROMPT
from src.middleware.tracing import setup_tracing
from src.middleware.audit_logger import AuditLogger

# Tool implementations
from src.tools.secure_score import query_secure_score
from src.tools.defender_coverage import assess_defender_coverage
from src.tools.purview_policies import check_purview_policies
from src.tools.entra_config import get_entra_config
from src.tools.remediation_plan import generate_remediation_plan
from src.tools.adoption_scorecard import create_adoption_scorecard

logger = structlog.get_logger(__name__)


# ── Tool Registry ──────────────────────────────────────────────────────────
# Each tool is a dict describing the function + its schema for the SDK runtime.
# The Copilot runtime decides WHEN and in WHAT ORDER to call these.

TOOLS: list[dict[str, Any]] = [
    {
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
                    "description": "The tenant identifier to assess (optional — uses current auth context if omitted)",
                },
            },
            "required": [],
        },
        "handler": query_secure_score,
    },
    {
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
        "handler": assess_defender_coverage,
    },
    {
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
        "handler": check_purview_policies,
    },
    {
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
        "handler": get_entra_config,
    },
    {
        "name": "generate_remediation_plan",
        "description": (
            "Generate a prioritized remediation plan based on gaps identified by "
            "the assessment tools. Returns P0/P1/P2 steps, each with description, "
            "Secure Score impact, effort estimate, and PowerShell/CLI configuration scripts. "
            "Includes estimated time-to-green."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "assessment_context": {
                    "type": "string",
                    "description": "JSON summary of findings from secure_score, defender, purview, and entra assessments",
                },
            },
            "required": ["assessment_context"],
        },
        "handler": generate_remediation_plan,
    },
    {
        "name": "create_adoption_scorecard",
        "description": (
            "Produce a structured ME5 adoption scorecard: overall adoption percentage, "
            "per-workload status (green/yellow/red) for Defender XDR, Purview, and Entra ID P2, "
            "top 5 gaps with priority, estimated days to green, and historical trend."
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
        "handler": create_adoption_scorecard,
    },
]


async def create_agent_session():
    """Initialize the Copilot SDK client and create an agent session.

    Returns the session object for multi-turn conversation.

    NOTE: This is a placeholder structure. The actual Copilot SDK API
    may differ — update as the SDK documentation stabilizes.
    Track deviations in docs/sdk-feedback.md.
    """
    # TODO: Replace with actual Copilot SDK initialization once API is finalized
    # from copilot_sdk import CopilotClient
    #
    # client = CopilotClient()
    #
    # # Register tools — the runtime decides when to call them
    # for tool in TOOLS:
    #     client.register_tool(
    #         name=tool["name"],
    #         description=tool["description"],
    #         parameters=tool["parameters"],
    #         handler=tool["handler"],
    #     )
    #
    # # Set the agent's persona
    # client.set_system_prompt(SYSTEM_PROMPT)
    #
    # # Create a persistent session
    # session = client.create_session()
    # return session

    logger.info("agent.session.created", tools_registered=len(TOOLS))
    return None  # placeholder


async def run_conversation_loop(session: Any) -> None:
    """Run the interactive conversation loop.

    In production, this would be driven by the API layer (FastAPI).
    This CLI loop is for local development and testing.
    """
    audit = AuditLogger()
    print("\n🛡️  PostureIQ — ME5 Security Posture Assessment Agent")
    print("    Type 'quit' to exit.\n")

    while True:
        user_input = input("You: ").strip()
        if user_input.lower() in ("quit", "exit", "q"):
            print("\n👋 PostureIQ session ended.")
            break

        if not user_input:
            continue

        # TODO: Replace with actual SDK session.send() call
        # response = await session.send(user_input)
        # print(f"\nPostureIQ: {response}\n")

        audit.log_interaction(
            user_input=user_input,
            agent_response="[placeholder — SDK not yet integrated]",
        )

        print("\nPostureIQ: [SDK integration pending — see docs/sdk-feedback.md]\n")


async def main() -> None:
    """Application entry point."""
    # Set up observability
    setup_tracing()

    logger.info(
        "postureiq.starting",
        environment=settings.environment,
        log_level=settings.log_level,
    )

    # Create agent session
    session = await create_agent_session()

    # Run conversation (CLI mode for dev; API mode for production)
    await run_conversation_loop(session)


if __name__ == "__main__":
    asyncio.run(main())
