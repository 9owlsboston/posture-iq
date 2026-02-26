"""PostureIQ Tool — create_adoption_scorecard

Produces a structured ME5 adoption scorecard summarising deployment status
per workload with green/yellow/red ratings, gap priorities, and time-to-green
estimates.

This is a pure aggregation tool — it parses assessment_context JSON produced
by the other tools (secure_score, defender_coverage, purview_policies,
entra_config, remediation_plan) and computes workload-level coverage,
top gaps, and a markdown report.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import structlog

from src.middleware.tracing import trace_tool_call

logger = structlog.get_logger(__name__)

# ── Thresholds ─────────────────────────────────────────────────────────
GREEN_THRESHOLD = 70.0
YELLOW_THRESHOLD = 40.0


# ── Helpers ────────────────────────────────────────────────────────────


def _status_from_pct(pct: float) -> str:
    """Convert a percentage to green / yellow / red status."""
    if pct >= GREEN_THRESHOLD:
        return "green"
    if pct >= YELLOW_THRESHOLD:
        return "yellow"
    return "red"


def _parse_assessment(raw: str) -> dict[str, Any]:
    """Safely parse the assessment_context JSON string.

    Returns an empty dict when parsing fails.
    """
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        return {}
    except (json.JSONDecodeError, TypeError):
        logger.warning("tool.adoption_scorecard.parse_error", raw=raw[:200])
        return {}


def _extract_defender(data: dict) -> dict[str, Any]:
    """Build Defender XDR workload entry from assessment data."""
    defender = data.get("defender_coverage", {})
    if not defender:
        return _default_workload()

    components = defender.get("components", {})
    sub_workloads: dict[str, dict] = {}
    for name, comp in components.items():
        pct = comp.get("coverage_pct", 0.0)
        sub_workloads[name] = {"status": _status_from_pct(pct), "coverage_pct": pct}

    overall_pct = defender.get("overall_coverage_pct", 0.0)
    total_gaps = defender.get("total_gaps", 0)
    return {
        "status": _status_from_pct(overall_pct),
        "coverage_pct": overall_pct,
        "gaps_count": total_gaps,
        "sub_workloads": sub_workloads,
    }


def _extract_purview(data: dict) -> dict[str, Any]:
    """Build Purview workload entry from assessment data."""
    purview = data.get("purview_policies", {})
    if not purview:
        return _default_workload()

    components = purview.get("components", {})
    sub_workloads: dict[str, dict] = {}
    for name, comp in components.items():
        pct = comp.get("coverage_pct", 0.0)
        sub_workloads[name] = {"status": _status_from_pct(pct), "coverage_pct": pct}

    overall_pct = purview.get("overall_coverage_pct", 0.0)
    total_gaps = purview.get("total_gaps", 0)
    return {
        "status": _status_from_pct(overall_pct),
        "coverage_pct": overall_pct,
        "gaps_count": total_gaps,
        "sub_workloads": sub_workloads,
    }


def _extract_entra(data: dict) -> dict[str, Any]:
    """Build Entra ID P2 workload entry from assessment data."""
    entra = data.get("entra_config", {})
    if not entra:
        return _default_workload()

    components = entra.get("components", {})
    sub_workloads: dict[str, dict] = {}
    for name, comp in components.items():
        pct = comp.get("coverage_pct", 0.0)
        sub_workloads[name] = {"status": _status_from_pct(pct), "coverage_pct": pct}

    overall_pct = entra.get("overall_coverage_pct", 0.0)
    total_gaps = entra.get("total_gaps", 0)
    return {
        "status": _status_from_pct(overall_pct),
        "coverage_pct": overall_pct,
        "gaps_count": total_gaps,
        "sub_workloads": sub_workloads,
    }


def _default_workload() -> dict[str, Any]:
    """Default workload entry when assessment data is missing."""
    return {
        "status": "unknown",
        "coverage_pct": 0.0,
        "gaps_count": 0,
        "sub_workloads": {},
    }


def _collect_critical_gaps(data: dict) -> list[dict[str, str]]:
    """Gather critical / high-priority gaps from all assessments."""
    gaps: list[dict[str, str]] = []

    for source_key, workload_label in [
        ("defender_coverage", "Defender XDR"),
        ("purview_policies", "Microsoft Purview"),
        ("entra_config", "Entra ID P2"),
    ]:
        source = data.get(source_key, {})
        for gap in source.get("critical_gaps", []):
            if isinstance(gap, str):
                gaps.append({"gap": gap, "priority": "P0", "workload": workload_label})
            elif isinstance(gap, dict):
                gaps.append(
                    {
                        "gap": gap.get("description", gap.get("gap", str(gap))),
                        "priority": gap.get("priority", "P0"),
                        "workload": workload_label,
                    }
                )

    # Also pull P0 steps from remediation plan if present
    remediation = data.get("remediation_plan", {})
    for step in remediation.get("steps", []):
        if step.get("priority") == "P0" and not any(g["gap"] == step.get("title") for g in gaps):
            gaps.append(
                {
                    "gap": step["title"],
                    "priority": "P0",
                    "workload": step.get("workload", "General"),
                }
            )

    return gaps[:5]


def _extract_days_to_green(data: dict) -> int:
    """Get estimated days to green from remediation plan, or estimate."""
    remediation = data.get("remediation_plan", {})
    if "estimated_days_to_green" in remediation:
        return remediation["estimated_days_to_green"]
    # Rough heuristic based on gap count
    total_gaps = sum(
        data.get(k, {}).get("total_gaps", 0) for k in ("defender_coverage", "purview_policies", "entra_config")
    )
    return max(1, total_gaps * 2)


# ── Mock fallback ──────────────────────────────────────────────────────


def _generate_mock_response() -> dict[str, Any]:
    """Return realistic hardcoded mock data for development / testing."""
    workload_status = {
        "Defender XDR": {
            "status": "yellow",
            "coverage_pct": 52.0,
            "gaps_count": 12,
            "sub_workloads": {
                "Defender for Endpoint": {"status": "yellow", "coverage_pct": 68.0},
                "Defender for Office 365": {"status": "red", "coverage_pct": 45.0},
                "Defender for Identity": {"status": "red", "coverage_pct": 30.0},
                "Defender for Cloud Apps": {"status": "yellow", "coverage_pct": 65.0},
            },
        },
        "Microsoft Purview": {
            "status": "red",
            "coverage_pct": 35.0,
            "gaps_count": 12,
            "sub_workloads": {
                "DLP Policies": {"status": "yellow", "coverage_pct": 40.0},
                "Sensitivity Labels": {"status": "red", "coverage_pct": 25.0},
                "Retention Policies": {"status": "yellow", "coverage_pct": 40.0},
                "Insider Risk Management": {"status": "red", "coverage_pct": 0.0},
            },
        },
        "Entra ID P2": {
            "status": "yellow",
            "coverage_pct": 48.0,
            "gaps_count": 16,
            "sub_workloads": {
                "Conditional Access": {"status": "yellow", "coverage_pct": 55.0},
                "PIM": {"status": "red", "coverage_pct": 30.0},
                "Identity Protection": {"status": "red", "coverage_pct": 20.0},
                "Access Reviews": {"status": "red", "coverage_pct": 0.0},
            },
        },
    }

    top_5_gaps = [
        {"gap": "Legacy authentication not blocked", "priority": "P0", "workload": "Entra ID P2"},
        {"gap": "Safe Attachments not enabled", "priority": "P0", "workload": "Defender XDR"},
        {"gap": "Identity Protection policies disabled", "priority": "P0", "workload": "Entra ID P2"},
        {"gap": "83% permanent privileged role assignments", "priority": "P1", "workload": "Entra ID P2"},
        {"gap": "Insider Risk Management not enabled", "priority": "P1", "workload": "Microsoft Purview"},
    ]

    overall_pct = sum(w["coverage_pct"] for w in workload_status.values()) / len(workload_status)
    scorecard_md = _generate_markdown_scorecard(workload_status, top_5_gaps, overall_pct, 21)

    return {
        "overall_adoption_pct": round(overall_pct, 1),
        "overall_status": _status_from_pct(overall_pct),
        "green_threshold": GREEN_THRESHOLD,
        "workload_status": workload_status,
        "top_5_gaps": top_5_gaps,
        "estimated_days_to_green": 21,
        "scorecard_markdown": scorecard_md,
        "disclaimer": (
            "⚠️ Generated by PostureIQ (AI-assisted) — review with your security "
            "team before implementing any remediation steps."
        ),
        "generated_at": datetime.now(UTC).isoformat(),
        "data_source": "mock",
    }


# ── Markdown generation ───────────────────────────────────────────────


def _generate_markdown_scorecard(
    workload_status: dict[str, Any],
    top_5_gaps: list[dict[str, str]],
    overall_pct: float,
    estimated_days: int,
) -> str:
    """Generate a human-readable markdown scorecard."""

    status_emoji = {"green": "🟢", "yellow": "🟡", "red": "🔴", "unknown": "⚪"}

    overall_status = _status_from_pct(overall_pct)

    lines = [
        "# PostureIQ — ME5 Adoption Scorecard",
        "",
        f"**Overall ME5 Adoption: {overall_pct:.1f}% {status_emoji.get(overall_status, '⚪')}**",
        f"**Status: {'OUT OF GREEN ❌' if overall_status != 'green' else 'GREEN ✅'}**",
        f"**Estimated days to green: {estimated_days}**",
        "",
        "---",
        "",
        "## Workload Summary",
        "",
        "| Workload | Coverage | Status |",
        "|----------|----------|--------|",
    ]

    for workload, data in workload_status.items():
        emoji = status_emoji.get(data["status"], "⚪")
        lines.append(f"| {workload} | {data['coverage_pct']:.0f}% | {emoji} {data['status'].upper()} |")

    lines.extend(["", "---", "", "## Top 5 Gaps", ""])
    for i, gap in enumerate(top_5_gaps, 1):
        lines.append(f"{i}. **[{gap['priority']}]** {gap['gap']} ({gap['workload']})")

    lines.extend(
        [
            "",
            "---",
            "",
            "*⚠️ Generated by PostureIQ (AI-assisted) — review with your security team before implementing.*",
        ]
    )

    return "\n".join(lines)


# ── Main tool function ─────────────────────────────────────────────────


@trace_tool_call("create_adoption_scorecard")
async def create_adoption_scorecard(assessment_context: str) -> dict[str, Any]:
    """Produce a structured ME5 adoption scorecard.

    Args:
        assessment_context: JSON string with all assessment findings.
            Expected keys: secure_score, defender_coverage, purview_policies,
            entra_config, remediation_plan (all optional).

    Returns:
        dict with keys:
          - overall_adoption_pct: float
          - overall_status: str (green/yellow/red)
          - workload_status: dict of workload → {status, coverage_pct, gaps_count}
          - top_5_gaps: list of {gap, priority, workload}
          - estimated_days_to_green: int
          - scorecard_markdown: str (human-readable markdown)
          - disclaimer: str
          - generated_at: ISO timestamp
          - data_source: "live" | "mock"
    """
    logger.info("tool.adoption_scorecard.start")

    data = _parse_assessment(assessment_context)

    # If assessment context is empty or unparseable, use mock
    has_any_data = any(key in data for key in ("secure_score", "defender_coverage", "purview_policies", "entra_config"))

    if not has_any_data:
        logger.info("tool.adoption_scorecard.mock_fallback", reason="no assessment data found")
        return _generate_mock_response()

    # ── Build workload status from real data ───────────────
    workload_status = {
        "Defender XDR": _extract_defender(data),
        "Microsoft Purview": _extract_purview(data),
        "Entra ID P2": _extract_entra(data),
    }

    # ── Collect top gaps ───────────────────────────────────
    top_5_gaps = _collect_critical_gaps(data)

    # ── Compute overall ────────────────────────────────────
    known_workloads = [w for w in workload_status.values() if w["status"] != "unknown"]
    if known_workloads:
        overall_pct = round(sum(w["coverage_pct"] for w in known_workloads) / len(known_workloads), 1)
    else:
        overall_pct = 0.0

    estimated_days = _extract_days_to_green(data)
    scorecard_md = _generate_markdown_scorecard(workload_status, top_5_gaps, overall_pct, estimated_days)

    result: dict[str, Any] = {
        "overall_adoption_pct": overall_pct,
        "overall_status": _status_from_pct(overall_pct),
        "green_threshold": GREEN_THRESHOLD,
        "workload_status": workload_status,
        "top_5_gaps": top_5_gaps,
        "estimated_days_to_green": estimated_days,
        "scorecard_markdown": scorecard_md,
        "disclaimer": (
            "⚠️ Generated by PostureIQ (AI-assisted) — review with your security "
            "team before implementing any remediation steps."
        ),
        "generated_at": datetime.now(UTC).isoformat(),
        "data_source": "live",
    }

    logger.info(
        "tool.adoption_scorecard.complete",
        overall_adoption=overall_pct,
        overall_status=result["overall_status"],
        data_source="live",
    )

    return result
