"""SecPostureIQ — Chat endpoint that bridges HTTP to the Copilot SDK agent.

Provides a ``POST /chat`` endpoint that:
  1. Manages agent sessions (create on first message, reuse on subsequent)
  2. Forwards user messages to the Copilot SDK agent
  3. Returns agent responses with tool-call metadata

For demo / local testing when the Copilot SDK runtime is not available,
falls back to a direct-tool-call mode that invokes tools directly.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import structlog
from pydantic import BaseModel

from src.middleware.audit_logger import AuditLogger
from src.middleware.tracing import trace_agent_invocation

logger = structlog.get_logger(__name__)


# ── Request / Response models ─────────────────────────────────────────────


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


class ChatResponse(BaseModel):
    response: str
    session_id: str
    tools_called: list[str] = []
    tenant_id: str = ""
    data_source: str = "mock"  # "mock" or "live" — shown in UI badge


# ── Session store (in-memory for demo) ────────────────────────────────────
# In multi-tenant mode, session keys are "tenant_id:user_id:session_id"
# to prevent cross-tenant session collisions.

_sessions: dict[str, dict[str, Any]] = {}


def _session_key(session_id: str, tenant_id: str = "", user_id: str = "") -> str:
    """Build composite session key for tenant isolation."""
    if tenant_id and user_id:
        return f"{tenant_id}:{user_id}:{session_id}"
    return session_id


# ── Tool dispatcher for direct mode ──────────────────────────────────────


async def _run_tool(
    name: str,
    args: dict[str, Any] | None = None,
    graph_token: str = "",
) -> dict[str, Any]:
    """Run a tool directly (bypass Copilot SDK) for demo / testing mode.

    Args:
        name: Tool function name to invoke.
        args: Extra keyword arguments forwarded to the tool.
        graph_token: User-delegated Graph access token (from the SPA).
            Passed to tools that call the Microsoft Graph API so they
            can query the real tenant instead of returning mock data.
    """
    args = args or {}

    if name == "query_secure_score":
        from src.tools.secure_score import query_secure_score

        return await query_secure_score(
            tenant_id=args.get("tenant_id", ""),
            graph_token=graph_token,
        )

    if name == "assess_defender_coverage":
        from src.tools.defender_coverage import assess_defender_coverage

        return await assess_defender_coverage(graph_token=graph_token)

    if name == "check_purview_policies":
        from src.tools.purview_policies import check_purview_policies

        return await check_purview_policies(graph_token=graph_token)

    if name == "get_entra_config":
        from src.tools.entra_config import get_entra_config

        return await get_entra_config(graph_token=graph_token)

    if name == "generate_remediation_plan":
        from src.tools.remediation_plan import generate_remediation_plan

        return await generate_remediation_plan(
            assessment_context=args.get("assessment_context", "{}"),
        )

    if name == "create_adoption_scorecard":
        from src.tools.adoption_scorecard import create_adoption_scorecard

        return await create_adoption_scorecard(
            assessment_context=args.get("assessment_context", "{}"),
        )

    if name == "get_green_playbook":
        from src.tools.foundry_playbook import get_green_playbook

        return await get_green_playbook(
            gaps=args.get("gaps"),
            workload_areas=args.get("workload_areas"),
        )

    if name == "push_posture_snapshot":
        from src.tools.fabric_telemetry import push_posture_snapshot

        return await push_posture_snapshot(
            tenant_id=args.get("tenant_id", ""),
            secure_score_current=float(args.get("secure_score_current", 0)),
            secure_score_max=float(args.get("secure_score_max", 100)),
            workload_scores=args.get("workload_scores"),
            gap_count=int(args.get("gap_count", 0)),
            estimated_days_to_green=int(args.get("estimated_days_to_green", 0)),
            top_gaps=args.get("top_gaps"),
            assessment_summary=args.get("assessment_summary", ""),
        )

    return {"error": f"Unknown tool: {name}"}


# ── Intent classifier (keyword-based for demo) ───────────────────────────

_TOOL_INTENTS: list[tuple[list[str], str]] = [
    (["scorecard", "adoption", "dashboard", "executive summary", "rag status"], "create_adoption_scorecard"),
    (["secure score", "securescor"], "query_secure_score"),
    (["defender", "coverage", "endpoint", "device onboard"], "assess_defender_coverage"),
    (["purview", "dlp", "compliance", "retention", "sensitivity label", "insider risk"], "check_purview_policies"),
    (["entra", "conditional access", "pim", "identity protection", "mfa", "access review"], "get_entra_config"),
    (["remediation", "remediate", "fix list", "get-to-green", "get to green"], "generate_remediation_plan"),
    (
        ["playbook", "get to green", "foundry", "get to green playbook", "onboarding checklist", "offer catalog"],
        "get_green_playbook",
    ),
    (
        ["fabric", "telemetry", "lakehouse", "snapshot", "push posture", "longitudinal"],
        "push_posture_snapshot",
    ),
]


def _classify_intent(message: str) -> list[str]:
    """Return tool names that match the user's message intent."""
    lower = message.lower()

    # Full assessment → run all assessment tools
    full_kws = ["full assessment", "assess this tenant", "assess my tenant", "full posture", "run full"]
    if any(kw in lower for kw in full_kws):
        return [
            "query_secure_score",
            "assess_defender_coverage",
            "check_purview_policies",
            "get_entra_config",
        ]

    matched = []
    for keywords, tool_name in _TOOL_INTENTS:
        if any(kw in lower for kw in keywords):
            matched.append(tool_name)

    return matched


# ── Format results for chat ───────────────────────────────────────────────


def _format_secure_score(data: dict[str, Any]) -> str:
    lines = ["## 📊 Microsoft Secure Score\n"]
    lines.append(f"**Current Score**: {data.get('current_score', 'N/A')} / {data.get('max_score', 'N/A')}")
    pct = data.get("score_percentage") or data.get("percentage")
    if pct is not None:
        icon = "🟢" if pct >= 80 else ("🟡" if pct >= 60 else "🔴")
        lines.append(f"**Percentage**: {icon} {pct:.0f}%")
    profiles_assessed = data.get("profiles_assessed", 0)
    if profiles_assessed:
        lines.append(f"**Control Profiles Assessed**: {profiles_assessed}")
    # trend_30d is a list of {date, score, max_score} dicts
    trend = data.get("trend_30d") or data.get("trend")
    if isinstance(trend, list) and len(trend) >= 2:
        delta = round(trend[0].get("score", 0) - trend[-1].get("score", 0), 1)
        lines.append(f"**30-day Trend**: {'+' if delta > 0 else ''}{delta} points")
    elif isinstance(trend, int | float) and trend:
        lines.append(f"**30-day Trend**: {'+' if trend > 0 else ''}{trend} points")
    cats = data.get("categories", {})
    if cats:
        lines.append("\n### Category Breakdown\n")
        lines.append("| Category | Score | Max |")
        lines.append("| --- | --- | --- |")
        for name, info in cats.items():
            lines.append(f"| {name} | {info.get('score', '?')} | {info.get('max_score', info.get('max', '?'))} |")
    # Control profiles detail — grouped by category
    control_profiles = data.get("control_profiles", [])
    if control_profiles:
        # Group active (non-deprecated) profiles by category
        by_cat: dict[str, list[dict[str, Any]]] = {}
        deprecated_count = 0
        for cp in control_profiles:
            if cp.get("deprecated"):
                deprecated_count += 1
                continue
            cat = cp.get("category", "Unknown")
            by_cat.setdefault(cat, []).append(cp)

        lines.append("\n### Control Profiles\n")
        if deprecated_count:
            lines.append(f"*{deprecated_count} deprecated profile(s) hidden*\n")
        for cat_name in sorted(by_cat):
            cat_profiles = sorted(by_cat[cat_name], key=lambda p: p.get("max_score", 0), reverse=True)
            lines.append(f"\n**{cat_name}** ({len(cat_profiles)} controls)\n")
            lines.append("| Control | Service | Tier | Max Score |")
            lines.append("| --- | --- | --- | --- |")
            for cp in cat_profiles:
                title = cp.get("title", cp.get("id", "?"))
                service = cp.get("service", "")
                tier = cp.get("tier", "")
                ms = cp.get("max_score", 0)
                lines.append(f"| {title} | {service} | {tier} | {ms} |")
    # industry_comparison is a dict with tenant_score, industry_avg, delta, basis
    comp = data.get("industry_comparison") or data.get("comparison")
    if isinstance(comp, dict):
        avg = comp.get("industry_avg", "?")
        delta = comp.get("delta", "?")
        sign = "+" if isinstance(delta, int | float) and delta > 0 else ""
        lines.append(f"\n**Industry Comparison**: avg {avg}, delta {sign}{delta}")
    elif isinstance(comp, str) and comp:
        lines.append(f"\n**Industry Comparison**: {comp}")
    return "\n".join(lines)


def _format_defender(data: dict[str, Any]) -> str:
    lines = ["## 🛡️ Defender Coverage Assessment\n"]
    overall = data.get("overall_coverage_pct") or data.get("overall_coverage")
    if overall is not None:
        icon = "🟢" if overall >= 80 else ("🟡" if overall >= 60 else "🔴")
        lines.append(f"**Overall Coverage**: {icon} {overall:.0f}%\n")
    workloads = data.get("workloads", {})
    if workloads:
        lines.append("| Workload | Coverage | Controls | Score | Status |")
        lines.append("| --- | --- | --- | --- | --- |")
        for wl, info in workloads.items():
            cov = info.get("coverage_pct") or info.get("coverage", 0)
            status = "🟢" if cov >= 80 else ("🟡" if cov >= 60 else "🔴")
            details = info.get("details", {})
            achieved = details.get("achieved_controls", "?")
            total = details.get("total_controls", "?")
            achieved_score = details.get("achieved_score", "?")
            max_score = details.get("max_score", "?")
            lines.append(f"| {wl} | {cov}% | {achieved}/{total} | {achieved_score}/{max_score} | {status} |")
        # Per-workload gaps
        for wl, info in workloads.items():
            wl_gaps = info.get("gaps", [])
            if wl_gaps:
                lines.append(f"\n**{wl}** — {len(wl_gaps)} gap(s)\n")
                for g in wl_gaps:
                    lines.append(f"- {g}")
    gaps = data.get("critical_gaps") or data.get("gaps", [])
    if gaps:
        lines.append("\n### Critical Gaps\n")
        for g in gaps[:10]:
            lines.append(f"- {g}")
    return "\n".join(lines)


def _format_purview(data: dict[str, Any]) -> str:
    lines = ["## 📋 Purview Policy Assessment\n"]
    overall = data.get("overall_coverage_pct")
    if overall is not None:
        icon = "🟢" if overall >= 70 else ("🟡" if overall >= 40 else "🔴")
        lines.append(f"**Overall Coverage**: {icon} {overall:.0f}%\n")
    total_gaps = data.get("total_gaps")
    if total_gaps is not None:
        lines.append(f"**Total Gaps**: {total_gaps}\n")
    # Tool returns "components" dict, not "policies"
    components = data.get("components") or data.get("policies", {})
    if components:
        lines.append("| Component | Status | Controls | Score | Gaps |")
        lines.append("| --- | --- | --- | --- | --- |")
        for name, info in components.items():
            status = info.get("status", "unknown")
            icon = "🟢" if status == "green" else ("🟡" if status == "yellow" else "🔴")
            gap_list = info.get("gaps", [])
            details = info.get("details", {})
            achieved = details.get("achieved_controls", "?")
            total = details.get("total_controls", "?")
            achieved_score = details.get("achieved_score", "?")
            max_score = details.get("max_score", "?")
            score_col = f"{achieved_score}/{max_score}" if achieved_score != "?" else ""
            ctrl_col = f"{achieved}/{total}" if achieved != "?" else ""
            lines.append(f"| {name} | {icon} {status} | {ctrl_col} | {score_col} | {len(gap_list)} |")
        # Per-component gap details
        for name, info in components.items():
            gap_list = info.get("gaps", [])
            if gap_list:
                lines.append(f"\n**{name}** — {len(gap_list)} gap(s)\n")
                for g in gap_list:
                    lines.append(f"- {g}")
    # Tool returns "critical_gaps", not "gaps"
    gaps = data.get("critical_gaps") or data.get("gaps", [])
    if gaps:
        lines.append("\n### Critical Gaps\n")
        for g in gaps[:10]:
            lines.append(f"- {g}")
    return "\n".join(lines)


def _format_entra(data: dict[str, Any]) -> str:
    lines = ["## 🔐 Entra ID P2 Configuration\n"]
    overall = data.get("overall_coverage_pct")
    if overall is not None:
        icon = "🟢" if overall >= 70 else ("🟡" if overall >= 40 else "🔴")
        lines.append(f"**Overall Coverage**: {icon} {overall:.0f}%\n")
    total_gaps = data.get("total_gaps")
    if total_gaps is not None:
        lines.append(f"**Total Gaps**: {total_gaps}\n")
    # Tool returns "components", not "configuration"
    config = data.get("components") or data.get("configuration", {})
    if config:
        for section, info in config.items():
            if isinstance(info, dict):
                status = info.get("status", info.get("enabled", "unknown"))
                icon = (
                    "✅"
                    if status in (True, "enabled", "configured", "green")
                    else ("🟡" if status == "yellow" else "⚠️")
                )
                lines.append(f"\n### {icon} {section} — {status}\n")
                # Surface component-specific details
                details = info.get("details", {})
                for dk, dv in details.items():
                    label = dk.replace("_", " ").title()
                    if isinstance(dv, bool):
                        dv = "Yes" if dv else "No"
                    lines.append(f"- **{label}**: {dv}")
                for g in info.get("gaps", []):
                    lines.append(f"- ⚠️ {g}")
    # Tool returns "critical_gaps", not "risk_flags"
    risks = data.get("critical_gaps") or data.get("risk_flags", [])
    if risks:
        lines.append("\n### ⚠️ Critical Gaps\n")
        for r in risks:
            lines.append(f"- 🚨 {r}")
    return "\n".join(lines)


def _format_remediation(data: dict[str, Any]) -> str:
    lines = ["## 📝 Remediation Plan\n"]
    ttg = data.get("estimated_days_to_green") or data.get("time_to_green")
    if ttg:
        lines.append(f"**Estimated Days to Green**: {ttg}\n")
    improvement = data.get("estimated_score_improvement")
    if improvement:
        lines.append(f"**Estimated Score Improvement**: +{improvement} points\n")
    steps = data.get("steps", [])
    for i, step in enumerate(steps, 1):
        pri = step.get("priority", "P2")
        icon = "🔴" if pri == "P0" else ("🟡" if pri == "P1" else "🟢")
        title = step.get("title") or step.get("description", "N/A")
        lines.append(f"### {icon} {pri} — Step {i}: {title}\n")
        desc = step.get("description", "")
        if desc and desc != title:
            lines.append(f"{desc}\n")
        impact = step.get("impact_on_score") or step.get("impact")
        if impact:
            lines.append(f"- **Score Impact**: +{impact} points")
        if step.get("effort"):
            lines.append(f"- **Effort**: {step['effort']}")
        if step.get("confidence"):
            conf = step["confidence"]
            conf_icon = "🟢" if conf == "high" else ("🟡" if conf == "medium" else "🔴")
            lines.append(f"- **Confidence**: {conf_icon} {conf}")
        offer = step.get("green_offer")
        if offer:
            lines.append(
                f"- **GTG Offer**: 📘 {offer['name']} ({offer['id']}) — {offer['duration']}, {offer['delivery']}"
            )
        if step.get("script"):
            lines.append(f"\n```powershell\n{step['script']}\n```\n")
    lines.append("\n> ⚠️ *Generated by AI — review with your security team before implementing.*")
    return "\n".join(lines)


def _format_scorecard(data: dict[str, Any]) -> str:
    # The tool returns a full markdown report in "scorecard_markdown"
    md = data.get("scorecard_markdown") or data.get("markdown")
    if md:
        return str(md)
    lines = ["## 📈 ME5 Adoption Scorecard\n"]
    overall = data.get("overall_adoption_pct") or data.get("overall_adoption")
    if overall is not None:
        lines.append(f"**Overall Adoption**: {overall:.0f}%\n")
    workloads = data.get("workload_status") or data.get("workloads", {})
    if workloads:
        lines.append("| Workload | Status | Adoption |")
        lines.append("| --- | --- | --- |")
        for wl, info in workloads.items():
            status = info.get("status", "unknown")
            icon = "🟢" if status == "green" else ("🟡" if status == "yellow" else "🔴")
            pct = info.get("coverage_pct") or info.get("adoption", "?")
            lines.append(f"| {wl} | {icon} {status} | {pct}% |")
    return "\n".join(lines)


def _format_playbook(data: dict[str, Any]) -> str:
    lines = ["## 📖 Get to Green — Get-to-Green Playbook\n"]
    lines.append(f"**Version**: {data.get('playbook_version', 'N/A')}")
    lines.append(f"**Source**: {data.get('source', 'built_in')}")
    lines.append(f"**Matched Areas**: {data.get('matched_count', 0)} / {data.get('total_areas', 0)}\n")

    playbooks = data.get("playbooks", {})
    for area, pb in playbooks.items():
        title = pb.get("title", area)
        lines.append(f"### {title}\n")
        steps = pb.get("remediation_steps", [])
        if steps:
            for step in steps:
                lines.append(f"- {step}")
        effort = pb.get("estimated_effort")
        impact = pb.get("impact_on_score", 0)
        if effort or impact:
            lines.append(f"\n*Effort: {effort or 'N/A'} | Score Impact: +{impact} pts*\n")
        offer = pb.get("offer")
        if offer:
            lines.append(f"**Recommended Offer**: {offer.get('name', offer.get('id', 'N/A'))}\n")

    offers = data.get("recommended_offers", [])
    if offers:
        lines.append(f"\n**Total Score Impact**: +{data.get('total_estimated_score_impact', 0)} pts")
        lines.append(f"**Recommended Offers**: {', '.join(offers)}")

    return "\n".join(lines)


def _format_fabric_snapshot(data: dict[str, Any]) -> str:
    lines = ["## 📊 Fabric Posture Snapshot\n"]
    success = data.get("write_success", False)
    status = "✅ Written" if success else "❌ Failed"
    lines.append(f"**Status**: {status}")
    lines.append(f"**Destination**: {data.get('destination', 'N/A')}")
    lines.append(f"**Snapshot ID**: `{data.get('snapshot_id', 'N/A')}`")
    lines.append(f"**Schema Version**: {data.get('schema_version', 'N/A')}")
    lines.append(f"**Secure Score**: {data.get('secure_score_percentage', 0):.0f}%")
    lines.append(f"**Gap Count**: {data.get('gap_count', 0)}")
    lines.append(f"**Est. Days to Green**: {data.get('estimated_days_to_green', 0)}")
    errors = data.get("validation_errors", [])
    if errors:
        lines.append(f"\n⚠️ **Validation Errors**: {', '.join(errors)}")
    return "\n".join(lines)


_FORMATTERS = {
    "query_secure_score": _format_secure_score,
    "assess_defender_coverage": _format_defender,
    "check_purview_policies": _format_purview,
    "get_entra_config": _format_entra,
    "generate_remediation_plan": _format_remediation,
    "create_adoption_scorecard": _format_scorecard,
    "get_green_playbook": _format_playbook,
    "push_posture_snapshot": _format_fabric_snapshot,
}


# ── Chat handler (direct tool mode) ──────────────────────────────────────


async def handle_chat(
    request: ChatRequest,
    tenant_id: str = "",
    user_id: str = "",
    graph_token: str = "",
) -> ChatResponse:
    """Process a chat message by classifying intent → running tools → formatting response.

    Each call creates an ``invoke_agent`` GenAI span so it appears in the
    App Insights Agent (preview) → Agent Runs panel.  Individual tool
    functions carry ``@trace_tool_call`` decorators that emit ``execute_tool``
    spans for the Tool Calls panel.

    Args:
        request: The chat request with message and optional session_id.
        tenant_id: The Entra ID tenant (from UserContext, if authenticated).
        user_id: The user's oid (from UserContext, if authenticated).
        graph_token: User-delegated Graph API access token (from OAuth flow).
            When present, tools will use this to query the real tenant via
            the Microsoft Graph API instead of returning mock data.
    """
    sid = request.session_id or str(uuid.uuid4())
    skey = _session_key(sid, tenant_id, user_id)

    # Store session history
    if skey not in _sessions:
        _sessions[skey] = {"history": [], "results": {}}

    session = _sessions[skey]
    session["history"].append({"role": "user", "content": request.message})

    audit = AuditLogger(session_id=sid)
    tools_called: list[str] = []
    sections: list[str] = []

    # Classify which tools to call
    intended_tools = _classify_intent(request.message)

    # Wrap the entire turn in a GenAI "invoke_agent" span
    async with trace_agent_invocation(session_id=sid) as agent_span:
        if not intended_tools:
            # No tools matched — provide a helpful response
            response_text = (
                "I can help you assess your tenant's ME5 security posture. "
                "Here are some things I can do:\n\n"
                "- **📊 Secure Score** — Check your current Microsoft Secure Score\n"
                "- **🛡️ Defender Coverage** — Assess M365 Defender deployment across workloads\n"
                "- **📋 Purview Policies** — Review DLP, sensitivity labels, and retention policies\n"
                "- **🔐 Entra ID Config** — Evaluate Conditional Access, PIM, and Identity Protection\n"
                "- **📝 Remediation Plan** — Generate a prioritized Get-to-Green plan\n"
                "- **📈 Adoption Scorecard** — Create an overall ME5 adoption scorecard\n\n"
                'Try asking: *"Assess this tenant\'s ME5 security posture"* for a full assessment.'
            )
        else:
            # Run tools and format results
            for tool_name in intended_tools:
                try:
                    logger.info("chat.tool.invoking", tool=tool_name, session_id=sid)

                    # For remediation/scorecard, pass prior results as context
                    args: dict[str, Any] = {}
                    if tool_name in ("generate_remediation_plan", "create_adoption_scorecard"):
                        args["assessment_context"] = json.dumps(session["results"])

                    result = await _run_tool(tool_name, args, graph_token=graph_token)

                    session["results"][tool_name] = result
                    tools_called.append(tool_name)

                    # Format for display
                    formatter = _FORMATTERS.get(tool_name)
                    if formatter:
                        sections.append(formatter(result))
                    else:
                        sections.append(f"### {tool_name}\n```json\n{json.dumps(result, indent=2, default=str)}\n```")

                    audit.log_tool_call(
                        tool_name=tool_name,
                        input_params=args,
                        output_summary=f"{len(json.dumps(result))} bytes",
                    )

                except Exception as e:
                    logger.error("chat.tool.error", tool=tool_name, error=str(e))
                    sections.append(f"### ⚠️ {tool_name}\nError: {e}")

            response_text = "\n\n---\n\n".join(sections)

            # Add a summary intro for multi-tool calls
            if len(tools_called) > 1:
                response_text = (
                    f"I've completed the assessment using **{len(tools_called)} tools**. "
                    "Here are the results:\n\n---\n\n" + response_text
                )

        # Record tool count on the agent span
        agent_span.set_attribute("secpostureiq.tools_called", len(tools_called))

    session["history"].append({"role": "assistant", "content": response_text})

    # Determine data source from tool results (mock vs live)
    # Tools return "graph_api" for live Graph data, "mock" for demo data.
    data_source = "mock"
    for result in session["results"].values():
        if isinstance(result, dict) and result.get("data_source") not in ("mock", None):
            data_source = "live"
            break

    return ChatResponse(
        response=response_text,
        session_id=sid,
        tools_called=tools_called,
        tenant_id=tenant_id,
        data_source=data_source,
    )
