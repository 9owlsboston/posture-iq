"""PostureIQ — Chat endpoint that bridges HTTP to the Copilot SDK agent.

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

logger = structlog.get_logger(__name__)


# ── Request / Response models ─────────────────────────────────────────────


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


class ChatResponse(BaseModel):
    response: str
    session_id: str
    tools_called: list[str] = []


# ── Session store (in-memory for demo) ────────────────────────────────────

_sessions: dict[str, dict[str, Any]] = {}


# ── Tool dispatcher for direct mode ──────────────────────────────────────


async def _run_tool(name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a tool directly (bypass Copilot SDK) for demo / testing mode."""
    args = args or {}

    if name == "query_secure_score":
        from src.tools.secure_score import query_secure_score

        return await query_secure_score(tenant_id=args.get("tenant_id", ""))

    if name == "assess_defender_coverage":
        from src.tools.defender_coverage import assess_defender_coverage

        return await assess_defender_coverage()

    if name == "check_purview_policies":
        from src.tools.purview_policies import check_purview_policies

        return await check_purview_policies()

    if name == "get_entra_config":
        from src.tools.entra_config import get_entra_config

        return await get_entra_config()

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

    if name == "get_project479_playbook":
        from src.tools.foundry_playbook import get_project479_playbook

        return await get_project479_playbook(
            gaps=args.get("gaps"),
            workload_areas=args.get("workload_areas"),
        )

    return {"error": f"Unknown tool: {name}"}


# ── Intent classifier (keyword-based for demo) ───────────────────────────

_TOOL_INTENTS: list[tuple[list[str], str]] = [
    (["scorecard", "adoption", "dashboard"], "create_adoption_scorecard"),
    (["secure score", "securescor"], "query_secure_score"),
    (["defender", "coverage", "endpoint", "device onboard"], "assess_defender_coverage"),
    (["purview", "dlp", "compliance", "retention", "sensitivity label"], "check_purview_policies"),
    (["entra", "conditional access", "pim", "identity protection", "mfa"], "get_entra_config"),
    (["remediation", "remediate", "fix", "plan", "get-to-green", "get to green"], "generate_remediation_plan"),
    (
        ["playbook", "project 479", "foundry", "get to green playbook", "onboarding checklist", "offer catalog"],
        "get_project479_playbook",
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
    # trend_30d is a list of {date, score, max_score} dicts
    trend = data.get("trend_30d") or data.get("trend")
    if isinstance(trend, list) and len(trend) >= 2:
        delta = round(trend[0].get("score", 0) - trend[-1].get("score", 0), 1)
        lines.append(f"**30-day Trend**: {'+' if delta > 0 else ''}{delta} points")
    elif isinstance(trend, (int, float)) and trend:
        lines.append(f"**30-day Trend**: {'+' if trend > 0 else ''}{trend} points")
    cats = data.get("categories", {})
    if cats:
        lines.append("\n### Category Breakdown\n")
        lines.append("| Category | Score | Max |")
        lines.append("| --- | --- | --- |")
        for name, info in cats.items():
            lines.append(f"| {name} | {info.get('score', '?')} | {info.get('max_score', info.get('max', '?'))} |")
    # industry_comparison is a dict with tenant_score, industry_avg, delta, basis
    comp = data.get("industry_comparison") or data.get("comparison")
    if isinstance(comp, dict):
        avg = comp.get("industry_avg", "?")
        delta = comp.get("delta", "?")
        sign = "+" if isinstance(delta, (int, float)) and delta > 0 else ""
        lines.append(
            f"\n**Industry Comparison**: avg {avg}, delta {sign}{delta}"
        )
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
        lines.append("| Workload | Coverage | Status |")
        lines.append("| --- | --- | --- |")
        for wl, info in workloads.items():
            cov = info.get("coverage_pct") or info.get("coverage", 0)
            status = "🟢" if cov >= 80 else ("🟡" if cov >= 60 else "🔴")
            lines.append(f"| {wl} | {cov}% | {status} |")
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
    # Tool returns "components" dict, not "policies"
    components = data.get("components") or data.get("policies", {})
    if components:
        lines.append("| Component | Status | Gaps |")
        lines.append("| --- | --- | --- |")
        for name, info in components.items():
            status = info.get("status", "unknown")
            icon = "🟢" if status == "green" else ("🟡" if status == "yellow" else "🔴")
            gap_list = info.get("gaps", [])
            lines.append(f"| {name} | {icon} {status} | {len(gap_list)} |")
            for g in gap_list:
                lines.append(f"  - {g}")
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
    # Tool returns "components", not "configuration"
    config = data.get("components") or data.get("configuration", {})
    if config:
        for section, info in config.items():
            if isinstance(info, dict):
                status = info.get("status", info.get("enabled", "unknown"))
                icon = "✅" if status in (True, "enabled", "configured", "green") else (
                    "🟡" if status == "yellow" else "⚠️"
                )
                lines.append(f"- **{section}**: {icon} {status}")
                for g in info.get("gaps", []):
                    lines.append(f"  - {g}")
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
        if step.get("script"):
            lines.append(f"\n```powershell\n{step['script']}\n```\n")
    lines.append("\n> ⚠️ *Generated by AI — review with your security team before implementing.*")
    return "\n".join(lines)


def _format_scorecard(data: dict[str, Any]) -> str:
    # The tool returns a full markdown report in "scorecard_markdown"
    md = data.get("scorecard_markdown") or data.get("markdown")
    if md:
        return md
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
    lines = ["## 📖 Project 479 — Get-to-Green Playbook\n"]
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


_FORMATTERS = {
    "query_secure_score": _format_secure_score,
    "assess_defender_coverage": _format_defender,
    "check_purview_policies": _format_purview,
    "get_entra_config": _format_entra,
    "generate_remediation_plan": _format_remediation,
    "create_adoption_scorecard": _format_scorecard,
    "get_project479_playbook": _format_playbook,
}


# ── Chat handler (direct tool mode) ──────────────────────────────────────


async def handle_chat(request: ChatRequest) -> ChatResponse:
    """Process a chat message by classifying intent → running tools → formatting response."""
    sid = request.session_id or str(uuid.uuid4())

    # Store session history
    if sid not in _sessions:
        _sessions[sid] = {"history": [], "results": {}}

    session = _sessions[sid]
    session["history"].append({"role": "user", "content": request.message})

    audit = AuditLogger(session_id=sid)
    tools_called: list[str] = []
    sections: list[str] = []

    # Classify which tools to call
    intended_tools = _classify_intent(request.message)

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

                result = await _run_tool(tool_name, args)
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

    session["history"].append({"role": "assistant", "content": response_text})

    return ChatResponse(
        response=response_text,
        session_id=sid,
        tools_called=tools_called,
    )
