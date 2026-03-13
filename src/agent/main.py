# mypy: disable-error-code="call-arg, no-any-return"
"""SecPostureIQ — Agent host entry point.

This is the main application that initializes the Copilot SDK, registers tools,
sets the system prompt, and runs the agent session loop.

Architecture:
    Your App (this file) → Copilot SDK → Agent Runtime → Models + Tools
    The SDK is the thin client; the runtime (Copilot CLI) does the planning.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from typing import Any

import structlog
from copilot import (
    CopilotClient,
    CopilotSession,
    PermissionHandler,
    SessionConfig,
    SessionEvent,
    Tool,
    ToolInvocation,
    ToolResult,
)
from copilot.generated.session_events import SessionEventType

from src.agent.config import settings
from src.agent.system_prompt import SYSTEM_PROMPT
from src.middleware.audit_logger import AuditLogger
from src.middleware.tracing import setup_tracing

# Tool implementations
from src.tools.adoption_scorecard import create_adoption_scorecard
from src.tools.defender_coverage import assess_defender_coverage
from src.tools.entra_config import get_entra_config
from src.tools.fabric_telemetry import push_posture_snapshot
from src.tools.foundry_playbook import get_green_playbook
from src.tools.purview_policies import check_purview_policies
from src.tools.remediation_plan import generate_remediation_plan
from src.tools.secure_score import query_secure_score

logger = structlog.get_logger(__name__)

# ── Graph Token (shared across tool handlers) ─────────────────────────────
# Acquired via device code flow at CLI startup; passed to Graph-dependent tools.
_graph_token: str = ""


async def _acquire_graph_token_interactive() -> str:
    """Acquire a delegated Graph API token via MSAL device code flow.

    Uses the same Entra app registration as the web app's OAuth2 flow.
    Returns an empty string if credentials are missing or the user declines.
    """
    client_id = settings.oauth_client_id
    tenant_id = settings.azure_tenant_id
    if not client_id or not tenant_id:
        logger.info("graph_auth.skipped", reason="No AZURE_CLIENT_ID or AZURE_TENANT_ID")
        return ""

    try:
        import msal  # noqa: PLC0415
    except ImportError:
        logger.warning("graph_auth.skipped", reason="msal not installed")
        return ""

    scopes = [f"https://graph.microsoft.com/{s}" for s in settings.graph_scope_list]
    authority = f"https://login.microsoftonline.com/{tenant_id}"

    app = msal.PublicClientApplication(client_id, authority=authority)

    # Try cached token first
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(scopes, account=accounts[0])
        if result and "access_token" in result:
            logger.info("graph_auth.cached", tenant=tenant_id)
            return result["access_token"]

    # Device code flow
    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        logger.error("graph_auth.device_flow_failed", error=flow.get("error_description", "unknown"))
        return ""

    print("\n🔐 To connect to your real M365 tenant, authenticate via browser:")
    print(f"   {flow['message']}")
    print("   (Press Ctrl+C to skip and use mock data)\n")

    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: app.acquire_token_by_device_flow(flow, timeout=120)
        )
    except KeyboardInterrupt:
        print("\n   Skipped — using mock data.\n")
        return ""

    if "access_token" in result:
        logger.info("graph_auth.success", tenant=tenant_id)
        return result["access_token"]

    logger.warning("graph_auth.failed", error=result.get("error_description", "unknown"))
    return ""


# ── SDK Compatibility ──────────────────────────────────────────────────────


def _tool_result(text: str) -> ToolResult:
    """Create a ToolResult with the LLM text."""
    return ToolResult(text_result_for_llm=text)


def _get_tool_result_text(result: Any) -> str:
    """Extract the LLM text from a ToolResult."""
    return getattr(result, "text_result_for_llm", "") or ""


# ── Tool Handler Adapters ──────────────────────────────────────────────────
# The Copilot SDK expects handlers with signature:
#   (ToolInvocation) → ToolResult | Awaitable[ToolResult]
# Our existing tool functions return dict[str, Any], so we wrap them here.


async def _handle_secure_score(invocation: ToolInvocation) -> ToolResult:
    """Adapter: query_secure_score → ToolResult."""
    args = invocation.arguments or {}
    tenant_id = args.get("tenant_id", "")
    result = await query_secure_score(tenant_id=tenant_id, graph_token=_graph_token)
    return _tool_result(json.dumps(result, indent=2, default=str))


async def _handle_defender_coverage(invocation: ToolInvocation) -> ToolResult:
    """Adapter: assess_defender_coverage → ToolResult."""
    result = await assess_defender_coverage(graph_token=_graph_token)
    return _tool_result(json.dumps(result, indent=2, default=str))


async def _handle_purview_policies(invocation: ToolInvocation) -> ToolResult:
    """Adapter: check_purview_policies → ToolResult."""
    result = await check_purview_policies(graph_token=_graph_token)
    return _tool_result(json.dumps(result, indent=2, default=str))


async def _handle_entra_config(invocation: ToolInvocation) -> ToolResult:
    """Adapter: get_entra_config → ToolResult."""
    result = await get_entra_config(graph_token=_graph_token)
    return _tool_result(json.dumps(result, indent=2, default=str))


async def _handle_remediation_plan(invocation: ToolInvocation) -> ToolResult:
    """Adapter: generate_remediation_plan → ToolResult."""
    args = invocation.arguments or {}
    assessment_context = args.get("assessment_context", "{}")
    result = await generate_remediation_plan(assessment_context=assessment_context)
    return _tool_result(json.dumps(result, indent=2, default=str))


async def _handle_adoption_scorecard(invocation: ToolInvocation) -> ToolResult:
    """Adapter: create_adoption_scorecard → ToolResult."""
    args = invocation.arguments or {}
    assessment_context = args.get("assessment_context", "{}")
    result = await create_adoption_scorecard(assessment_context=assessment_context)
    return _tool_result(json.dumps(result, indent=2, default=str))


async def _handle_foundry_playbook(invocation: ToolInvocation) -> ToolResult:
    """Adapter: get_green_playbook → ToolResult."""
    args = invocation.arguments or {}
    gaps_raw = args.get("gaps", [])
    workload_areas_raw = args.get("workload_areas", [])
    # Ensure lists (the SDK may pass JSON strings)
    gaps = json.loads(gaps_raw) if isinstance(gaps_raw, str) else gaps_raw
    workload_areas = json.loads(workload_areas_raw) if isinstance(workload_areas_raw, str) else workload_areas_raw
    result = await get_green_playbook(
        gaps=gaps or None,
        workload_areas=workload_areas or None,
    )
    return _tool_result(json.dumps(result, indent=2, default=str))


async def _handle_fabric_telemetry(invocation: ToolInvocation) -> ToolResult:
    """Adapter: push_posture_snapshot → ToolResult."""
    args = invocation.arguments or {}
    result = await push_posture_snapshot(
        tenant_id=args.get("tenant_id", ""),
        secure_score_current=float(args.get("secure_score_current", 0)),
        secure_score_max=float(args.get("secure_score_max", 100)),
        workload_scores=args.get("workload_scores"),
        gap_count=int(args.get("gap_count", 0)),
        estimated_days_to_green=int(args.get("estimated_days_to_green", 0)),
        top_gaps=args.get("top_gaps"),
        assessment_summary=args.get("assessment_summary", ""),
    )
    return _tool_result(json.dumps(result, indent=2, default=str))


# ── Tool Registry ──────────────────────────────────────────────────────────
# Each Tool is registered with the Copilot SDK. The runtime decides WHEN and
# in WHAT ORDER to call these based on the user's query and system prompt.

TOOLS: list[Tool] = [
    Tool(
        name="query_secure_score",
        description=(
            "Retrieve the tenant's Microsoft Secure Score. Returns the current "
            "score, category breakdown (Identity, Data, Device, Apps, Infrastructure), "
            "30-day trend, and industry comparison."
        ),
        handler=_handle_secure_score,
        parameters={
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
    ),
    Tool(
        name="assess_defender_coverage",
        description=(
            "Evaluate M365 Defender deployment status across all workloads: "
            "Defender for Endpoint (device onboarding), Defender for Office 365 "
            "(Safe Links/Attachments), Defender for Identity (sensors), and "
            "Defender for Cloud Apps (connected apps). Returns coverage percentage "
            "per workload and a list of gaps."
        ),
        handler=_handle_defender_coverage,
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="check_purview_policies",
        description=(
            "Assess Information Protection & Compliance policy coverage: "
            "DLP policies (count, status, scope), sensitivity labels (published, "
            "auto-labeling), retention policies (Exchange, SharePoint, OneDrive, Teams), "
            "and Insider Risk Management status."
        ),
        handler=_handle_purview_policies,
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="get_entra_config",
        description=(
            "Review Entra ID P2 security configuration: Conditional Access policies, "
            "PIM (active vs eligible assignments), Identity Protection risk policies, "
            "Access Reviews configuration, and SSO app registrations."
        ),
        handler=_handle_entra_config,
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="generate_remediation_plan",
        description=(
            "Generate a prioritized remediation plan based on gaps identified by "
            "the assessment tools. Returns P0/P1/P2 steps, each with description, "
            "Secure Score impact, effort estimate, and PowerShell/CLI configuration scripts. "
            "Includes estimated time-to-green."
        ),
        handler=_handle_remediation_plan,
        parameters={
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
    ),
    Tool(
        name="create_adoption_scorecard",
        description=(
            "Produce a structured ME5 adoption scorecard: overall adoption percentage, "
            "per-workload status (green/yellow/red) for Defender XDR, Purview, and Entra ID P2, "
            "top 5 gaps with priority, estimated days to green, and historical trend."
        ),
        handler=_handle_adoption_scorecard,
        parameters={
            "type": "object",
            "properties": {
                "assessment_context": {
                    "type": "string",
                    "description": "JSON summary of all assessment findings",
                },
            },
            "required": ["assessment_context"],
        },
    ),
    Tool(
        name="get_green_playbook",
        description=(
            "Retrieve Get to Green Get-to-Green playbooks from Foundry IQ. "
            "Given identified security gaps or workload area keys, returns "
            "step-by-step remediation playbooks, recommended Get to Green offers "
            "(workshops, engagements), and customer onboarding checklists. "
            "Use this AFTER identifying gaps to enrich remediation plans with "
            "Get to Green offer recommendations."
        ),
        handler=_handle_foundry_playbook,
        parameters={
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
    ),
    Tool(
        name="push_posture_snapshot",
        description=(
            "Push a security posture snapshot to the Fabric lakehouse for "
            "longitudinal dashboarding. Call this AFTER completing an assessment "
            "to persist the tenant's current secure score, workload coverage, "
            "gap count, and estimated days-to-green. The tenant ID is hashed "
            "and gap descriptions anonymised before storage."
        ),
        handler=_handle_fabric_telemetry,
        parameters={
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
    ),
]


# ── Session Manager ────────────────────────────────────────────────────────


class SecPostureIQAgent:
    """Manages the Copilot SDK client and session lifecycle.

    Responsibilities:
      - Initialize the CopilotClient and start the runtime subprocess
      - Create sessions with tools + system prompt registered
      - Handle multi-turn conversation with streaming event processing
      - Gracefully shut down on exit (SIGINT/SIGTERM)
    """

    def __init__(self) -> None:
        self._client: CopilotClient | None = None
        self._session: CopilotSession | None = None
        self._audit = AuditLogger()
        self._event_unsubscribe: Any = None

    # ── Lifecycle ──────────────────────────────────────────

    async def start_client(self) -> CopilotClient:
        """Create and start the CopilotClient (launches the runtime process)."""
        opts = {}
        if os.environ.get("GITHUB_TOKEN"):
            opts["github_token"] = os.environ["GITHUB_TOKEN"]
        self._client = CopilotClient(opts or None)
        await self._client.start()

        state = self._client.get_state()
        logger.info("agent.client.started", state=state)
        return self._client

    async def create_session(self) -> CopilotSession:
        """Create a new agent session with tools and system prompt.

        The session is the primary unit of multi-turn interaction.
        Tools and the system prompt are passed via SessionConfig so the
        runtime knows what capabilities the agent has.
        """
        if self._client is None:
            raise RuntimeError("CopilotClient not started — call start_client() first")

        session_config: SessionConfig = {
            "tools": TOOLS,
            "system_message": {
                "mode": "replace",
                "content": SYSTEM_PROMPT,
            },
            "streaming": True,
            "on_permission_request": PermissionHandler.approve_all,
        }

        # Wire Azure OpenAI as the model provider if configured.
        # Note: BYOK provider requires the Copilot runtime to support the
        # provider type.  If COPILOT_USE_BUILTIN_MODELS is set, skip the
        # custom provider and use Copilot's built-in model catalog instead.
        if settings.azure_openai_endpoint and not os.environ.get("COPILOT_USE_BUILTIN_MODELS"):
            session_config["provider"] = {
                "type": "azure",
                "base_url": settings.azure_openai_endpoint,
                "azure": {
                    "api_version": settings.azure_openai_api_version,
                },
            }
            if settings.azure_openai_api_key:
                session_config["provider"]["api_key"] = settings.azure_openai_api_key
            else:
                # No API key → use Azure AD token (for disableLocalAuth=true resources)
                try:
                    from azure.identity import DefaultAzureCredential

                    credential = DefaultAzureCredential()
                    token = credential.get_token("https://cognitiveservices.azure.com/.default")
                    session_config["provider"]["bearer_token"] = token.token
                    logger.info("agent.provider.auth", method="bearer_token")
                except Exception as exc:
                    logger.warning("agent.provider.auth_fallback", error=str(exc))

            session_config["model"] = settings.azure_openai_deployment
            logger.info(
                "agent.provider.azure",
                endpoint=settings.azure_openai_endpoint,
                deployment=settings.azure_openai_deployment,
            )

        self._session = await self._client.create_session(session_config)

        # Subscribe to session events for streaming output + audit logging
        self._event_unsubscribe = self._session.on(self._handle_session_event)

        self._audit.log_session_start()
        logger.info(
            "agent.session.created",
            tools_registered=len(TOOLS),
            streaming=True,
        )

        return self._session

    async def resume_session(self, session_id: str) -> CopilotSession:
        """Resume a previously created session by ID."""
        if self._client is None:
            raise RuntimeError("CopilotClient not started — call start_client() first")

        self._session = await self._client.resume_session(session_id)  # type: ignore[call-arg,unused-ignore]
        self._event_unsubscribe = self._session.on(self._handle_session_event)

        logger.info("agent.session.resumed", session_id=session_id)
        return self._session

    async def close_session(self) -> None:
        """Close the current session and unsubscribe from events."""
        if self._event_unsubscribe:
            self._event_unsubscribe()
            self._event_unsubscribe = None

        if self._session:
            await self._session.destroy()
            logger.info("agent.session.destroyed")
            self._session = None

    async def stop(self) -> None:
        """Gracefully shut down: close session, then stop the client."""
        await self.close_session()
        if self._client:
            errors = await self._client.stop()  # type: ignore[func-returns-value,unused-ignore]
            if errors:
                logger.warning("agent.client.stop_errors", errors=[str(e) for e in errors])
            else:
                logger.info("agent.client.stopped")
            self._client = None

    # ── Conversation ───────────────────────────────────────

    async def send_message(self, prompt: str) -> str | None:
        """Send a user message and wait for the full agent response.

        Uses send_and_wait() for synchronous request/response.
        Streaming deltas are handled by the event listener registered in
        create_session(). This method blocks until the turn completes.

        Args:
            prompt: The user's message text.

        Returns:
            The final assistant message text, or None on timeout/error.
        """
        if self._session is None:
            raise RuntimeError("No active session — call create_session() first")

        logger.info("agent.message.sending", prompt_length=len(prompt))

        response_event = await self._session.send_and_wait(  # type: ignore[func-returns-value,unused-ignore]
            {"prompt": prompt},
            timeout=120.0,
        )

        if response_event is None:
            logger.warning("agent.message.timeout")
            return None

        # Extract the final assistant message content
        response_text = self._extract_response_text(response_event)

        self._audit.log_interaction(
            user_input=prompt,
            agent_response=response_text or "[no response]",
        )

        return response_text

    async def send_message_streaming(self, prompt: str) -> None:
        """Send a user message with streaming output (fire-and-forget).

        The event handler (_handle_session_event) prints deltas in real time.
        Use this for CLI mode where you want character-by-character output.
        """
        if self._session is None:
            raise RuntimeError("No active session — call create_session() first")

        logger.info("agent.message.sending_streaming", prompt_length=len(prompt))
        await self._session.send({"prompt": prompt})

    # ── Event Handling ─────────────────────────────────────

    def _handle_session_event(self, event: SessionEvent) -> None:
        """Process streaming session events from the runtime.

        Handles:
          - assistant.message_delta → print token-by-token for real-time UX
          - assistant.message → log the complete message
          - assistant.turn_start/end → bracket the agent's reasoning turn
          - tool.execution_start/complete → log tool invocations for audit
          - session.error → log errors
        """
        event_type = event.type
        data = event.data

        if event_type == SessionEventType.ASSISTANT_MESSAGE_DELTA:
            # Stream tokens to stdout for real-time display
            delta = data.delta_content or ""
            print(delta, end="", flush=True)

        elif event_type == SessionEventType.ASSISTANT_MESSAGE:
            # Complete message received — newline after streaming
            print()

        elif event_type == SessionEventType.ASSISTANT_TURN_START:
            logger.debug("agent.turn.start", turn_id=data.turn_id)

        elif event_type == SessionEventType.ASSISTANT_TURN_END:
            logger.debug("agent.turn.end", turn_id=data.turn_id)

        elif event_type == SessionEventType.TOOL_EXECUTION_START:
            tool_name = data.tool_name or "unknown"
            logger.info("agent.tool.start", tool=tool_name)
            print(f"\n  ⚙️  Calling {tool_name}...", flush=True)

        elif event_type == SessionEventType.TOOL_EXECUTION_COMPLETE:
            tool_name = data.tool_name or "unknown"
            logger.info("agent.tool.complete", tool=tool_name)

            # Log to audit trail
            self._audit.log_tool_call(
                tool_name=tool_name,
                input_params=data.arguments if data.arguments else {},
                output_summary=(
                    data.result.text_result[:200]
                    if data.result and hasattr(data.result, "text_result")
                    else "[no output]"
                ),
            )

        elif event_type == SessionEventType.SESSION_ERROR:
            error_msg = data.message or "Unknown error"
            logger.error("agent.session.error", error=error_msg, stack=data.stack)
            print(f"\n❌ Error: {error_msg}", flush=True)

        elif event_type == SessionEventType.ASSISTANT_REASONING:
            # Optional: log reasoning traces for debugging
            logger.debug("agent.reasoning", content=data.content)

    @staticmethod
    def _extract_response_text(event: SessionEvent) -> str | None:
        """Extract the text content from a completed response event."""
        if event.data and event.data.content:
            return event.data.content
        if event.data and event.data.message:
            return event.data.message
        return None


# ── CLI Entry Point ────────────────────────────────────────────────────────


async def run_cli(agent: SecPostureIQAgent) -> None:
    """Run the interactive CLI conversation loop.

    For local development and testing. In production, the FastAPI layer
    in src/api/app.py drives the agent via HTTP endpoints.
    """
    print("\n🛡️  SecPostureIQ — ME5 Security Posture Assessment Agent")
    print("    Type 'quit' to exit.\n")

    while True:
        try:
            user_input = await asyncio.get_event_loop().run_in_executor(None, lambda: input("You: ").strip())
        except (EOFError, KeyboardInterrupt):
            print("\n👋 SecPostureIQ session ended.")
            break

        if user_input.lower() in ("quit", "exit", "q"):
            print("\n👋 SecPostureIQ session ended.")
            break

        if not user_input:
            continue

        print("\nSecPostureIQ: ", end="", flush=True)

        # send_and_wait blocks until the turn is complete;
        # streaming deltas are printed via the event handler.
        response = await agent.send_message(user_input)

        if response is None:
            print("[No response received — check logs for errors]")

        print()  # blank line between turns


async def main() -> None:
    """Application entry point."""
    # Set up observability
    setup_tracing()

    logger.info(
        "secpostureiq.starting",
        environment=settings.environment,
        log_level=settings.log_level,
    )

    # Acquire a delegated Graph token so tools query the real tenant
    global _graph_token  # noqa: PLW0603
    _graph_token = await _acquire_graph_token_interactive()
    if _graph_token:
        print("✅ Authenticated — tools will query your real M365 tenant.\n")
    else:
        print("ℹ️  No Graph token — tools will return mock data.\n")

    agent = SecPostureIQAgent()

    # Register signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown(agent)))

    try:
        await agent.start_client()
        await agent.create_session()

        # Run conversation (CLI mode for dev; API mode uses FastAPI)
        await run_cli(agent)
    finally:
        await agent.stop()


async def _shutdown(agent: SecPostureIQAgent) -> None:
    """Handle graceful shutdown on SIGINT/SIGTERM."""
    logger.info("secpostureiq.shutting_down")
    await agent.stop()
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
