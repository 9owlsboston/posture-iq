"""PostureIQ Tool — generate_remediation_plan

Generates a prioritised remediation plan based on assessment findings.
Uses Azure OpenAI (GPT-4o) for reasoning over gaps and producing
actionable remediation steps with PowerShell / CLI configuration scripts.

Routes LLM output through Azure AI Content Safety before returning.
Redacts PII from the assessment context before sending to the model.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import structlog

from src.agent.config import settings
from src.middleware.content_safety import check_content_safety
from src.middleware.pii_redaction import redact_pii
from src.middleware.tracing import trace_tool_call
from src.tools.foundry_playbook import _GAP_KEYWORD_MAP, _PLAYBOOKS

logger = structlog.get_logger(__name__)

# ── System prompt for remediation generation ───────────────────────────

REMEDIATION_SYSTEM_PROMPT = """\
You are an ME5 security remediation planner. Given an assessment summary of a
Microsoft 365 tenant, produce a JSON array of remediation steps.

Each step MUST have these fields:
  - priority: "P0" | "P1" | "P2" (P0 = critical/quick-win, P1 = important, P2 = housekeeping)
  - title: short action label
  - description: 1-2 sentences explaining the gap and impact
  - impact_on_score: estimated Secure Score improvement (float, 0-10)
  - effort: effort estimate string ("Low (X hours)" / "Medium (X hours)" / "High (X days)")
  - confidence: "high" | "medium" | "low"
  - script: PowerShell or CLI script for the remediation (may be multi-line)

Order by priority then impact_on_score descending.
Include 5-10 steps. Be specific — include real PowerShell cmdlets.
Output ONLY the JSON array, no markdown fences, no extra text.
"""


# ── Azure OpenAI client factory ────────────────────────────────────────


def _create_openai_client() -> Any:
    """Create an Azure OpenAI client.

    Returns None when endpoint is not configured (triggers mock fallback).
    """
    if not settings.azure_openai_endpoint:
        logger.info(
            "tool.remediation_plan.openai_client.skipped",
            reason="Azure OpenAI endpoint not configured — using mock data",
        )
        return None

    try:
        if settings.azure_openai_api_key:
            from openai import AzureOpenAI

            return AzureOpenAI(
                azure_endpoint=settings.azure_openai_endpoint,
                api_version=settings.azure_openai_api_version,
                api_key=settings.azure_openai_api_key,
            )
        else:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
            from openai import AzureOpenAI

            credential = DefaultAzureCredential()
            token_provider = get_bearer_token_provider(credential, "https://cognitiveservices.azure.com/.default")
            return AzureOpenAI(
                azure_endpoint=settings.azure_openai_endpoint,
                api_version=settings.azure_openai_api_version,
                azure_ad_token_provider=token_provider,
            )
    except Exception as e:
        logger.error("tool.remediation_plan.openai_client.error", error=str(e))
        return None


# ── Helpers ────────────────────────────────────────────────────────────


def _parse_llm_steps(raw_text: str) -> list[dict[str, Any]]:  # noqa: C901
    """Parse the LLM response into a list of remediation steps.

    Handles JSON wrapped in markdown code fences.
    """
    text = raw_text.strip()
    # Strip markdown code blocks if present
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return list(parsed)
        if isinstance(parsed, dict) and "steps" in parsed:
            return list(parsed["steps"])
        return [parsed]
    except (json.JSONDecodeError, TypeError):
        logger.warning("tool.remediation_plan.parse_error", raw=text[:200])
        return []


def _validate_step(step: dict[str, Any]) -> dict[str, Any]:
    """Ensure a step dict has all required fields with sensible defaults."""
    return {
        "priority": step.get("priority", "P2"),
        "title": step.get("title", "Untitled step"),
        "description": step.get("description", ""),
        "impact_on_score": float(step.get("impact_on_score", 0.0)),
        "effort": step.get("effort", "Unknown"),
        "confidence": step.get("confidence", "low"),
        "script": step.get("script", "# No script provided"),
    }


def _compute_estimated_days(steps: list[dict[str, Any]]) -> int:
    """Rough estimate of days-to-green based on step effort."""
    total_hours = 0.0
    for s in steps:
        effort = (s.get("effort") or "").lower()
        if "low" in effort:
            total_hours += 2
        elif "medium" in effort:
            total_hours += 6
        elif "high" in effort:
            total_hours += 16
        else:
            total_hours += 4
    # Assume 4 productive hours/day for security remediation
    return max(1, round(total_hours / 4))


def _compute_total_score_improvement(steps: list[dict[str, Any]]) -> float:
    return round(float(sum(s.get("impact_on_score", 0.0) for s in steps)), 1)


def _enrich_step_with_p479_offer(step: dict[str, Any]) -> dict[str, Any]:
    """Map a remediation step to a Project 479 offer from Foundry IQ.

    Scans the step title and description for keywords that match a workload
    area, then attaches the corresponding offer and workload_area to the step.
    """
    text = f"{step.get('title', '')} {step.get('description', '')}".lower()

    # Find the best-matching workload area via keyword scan
    matched_area: str | None = None
    for keyword, area in _GAP_KEYWORD_MAP.items():
        if keyword in text:
            matched_area = area
            break  # first match wins (keywords are ordered by specificity)

    if matched_area and matched_area in _PLAYBOOKS:
        playbook = _PLAYBOOKS[matched_area]
        offer = playbook.get("offer")
        step["workload_area"] = matched_area
        if offer:
            step["project_479_offer"] = {
                "name": offer["name"],
                "id": offer["id"],
                "description": offer["description"],
                "duration": offer["duration"],
                "delivery": offer["delivery"],
            }
    return step


def _enrich_steps_with_p479(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrich all remediation steps with Foundry IQ Project 479 offers."""
    return [_enrich_step_with_p479_offer(dict(s)) for s in steps]


# ── Mock fallback ──────────────────────────────────────────────────────


def _generate_mock_response() -> dict[str, Any]:
    """Return realistic mock data for development / testing."""
    steps = [
        {
            "priority": "P0",
            "title": "Block legacy authentication",
            "description": (
                "Create a Conditional Access policy to block legacy authentication protocols across all users."
            ),
            "impact_on_score": 5.0,
            "effort": "Low (1-2 hours)",
            "confidence": "high",
            "script": (
                "# PowerShell — Block legacy auth via Conditional Access\n"
                "Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess'\n\n"
                "$params = @{\n"
                '    DisplayName = "PostureIQ: Block Legacy Authentication"\n'
                "    State = 'enabled'\n"
                "    Conditions = @{\n"
                "        ClientAppTypes = @('exchangeActiveSync', 'other')\n"
                "        Users = @{ IncludeUsers = @('All') }\n"
                "    }\n"
                "    GrantControls = @{\n"
                "        BuiltInControls = @('block')\n"
                "        Operator = 'OR'\n"
                "    }\n"
                "}\n"
                "New-MgIdentityConditionalAccessPolicy @params"
            ),
        },
        {
            "priority": "P0",
            "title": "Enable Identity Protection risk policies",
            "description": "Enable sign-in risk and user risk policies to auto-remediate risky sign-ins and users.",
            "impact_on_score": 4.5,
            "effort": "Low (1 hour)",
            "confidence": "high",
            "script": (
                "# PowerShell — Enable sign-in risk policy\n"
                "Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess'\n\n"
                "$params = @{\n"
                '    DisplayName = "PostureIQ: Sign-in Risk — Require MFA"\n'
                "    State = 'enabled'\n"
                "    Conditions = @{\n"
                "        SignInRiskLevels = @('medium', 'high')\n"
                "        Users = @{ IncludeUsers = @('All') }\n"
                "    }\n"
                "    GrantControls = @{\n"
                "        BuiltInControls = @('mfa')\n"
                "        Operator = 'OR'\n"
                "    }\n"
                "}\n"
                "New-MgIdentityConditionalAccessPolicy @params"
            ),
        },
        {
            "priority": "P0",
            "title": "Enable Safe Attachments in Defender for Office 365",
            "description": (
                "Safe Attachments is not enabled — critical gap leaving the org vulnerable to malware via email."
            ),
            "impact_on_score": 3.5,
            "effort": "Low (30 min)",
            "confidence": "high",
            "script": (
                "# PowerShell — Enable Safe Attachments\n"
                "Connect-ExchangeOnline\n\n"
                "New-SafeAttachmentPolicy -Name 'PostureIQ: Safe Attachments' `\n"
                "    -Enable $true `\n"
                "    -Action 'DynamicDelivery' `\n"
                "    -ActionOnError $true"
            ),
        },
        {
            "priority": "P1",
            "title": "Convert permanent role assignments to eligible (PIM)",
            "description": "83% of privileged role assignments are permanent. Convert to eligible with JIT activation.",
            "impact_on_score": 4.0,
            "effort": "Medium (4-8 hours)",
            "confidence": "high",
            "script": (
                "# PowerShell — Audit permanent assignments\n"
                "Connect-MgGraph -Scopes 'RoleManagement.ReadWrite.Directory'\n\n"
                "$permanentAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All\n"
                'Write-Host "Found $($permanentAssignments.Count) assignments to review"'
            ),
        },
        {
            "priority": "P1",
            "title": "Enforce MFA for all users via Conditional Access",
            "description": "MFA is currently only enforced for admins. Extend to all users.",
            "impact_on_score": 3.0,
            "effort": "Medium (2-4 hours)",
            "confidence": "high",
            "script": (
                "# PowerShell — Require MFA for all users\n"
                "Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess'\n\n"
                "$params = @{\n"
                '    DisplayName = "PostureIQ: Require MFA for All Users"\n'
                "    State = 'enabledForReportingButNotEnforced'\n"
                "    Conditions = @{\n"
                "        Users = @{ IncludeUsers = @('All') }\n"
                "        Applications = @{ IncludeApplications = @('All') }\n"
                "    }\n"
                "    GrantControls = @{\n"
                "        BuiltInControls = @('mfa')\n"
                "        Operator = 'OR'\n"
                "    }\n"
                "}\n"
                "New-MgIdentityConditionalAccessPolicy @params"
            ),
        },
        {
            "priority": "P1",
            "title": "Extend DLP policies to SharePoint, OneDrive, Teams",
            "description": "DLP currently only covers Exchange. Extend coverage.",
            "impact_on_score": 2.0,
            "effort": "Medium (2-4 hours)",
            "confidence": "high",
            "script": (
                "# PowerShell — Extend DLP\n"
                "Connect-IPPSSession\n\n"
                "Set-DlpCompliancePolicy -Identity 'Your-DLP-Policy' `\n"
                "    -SharePointLocation All `\n"
                "    -OneDriveLocation All `\n"
                "    -TeamsLocation All"
            ),
        },
        {
            "priority": "P2",
            "title": "Configure Access Reviews for privileged roles",
            "description": "No access reviews configured. Set up quarterly reviews.",
            "impact_on_score": 1.2,
            "effort": "Low-Medium (2 hours)",
            "confidence": "medium",
            "script": (
                "# PowerShell — Create access review\n"
                "Connect-MgGraph -Scopes 'AccessReview.ReadWrite.All'\n\n"
                "# See: https://learn.microsoft.com/en-us/graph/api/accessreviewset-post-definitions"
            ),
        },
        {
            "priority": "P2",
            "title": "Enable Insider Risk Management",
            "description": "Insider Risk Management is completely disabled. Enable core policies.",
            "impact_on_score": 1.5,
            "effort": "Medium (4 hours)",
            "confidence": "medium",
            "script": (
                "# Navigate to Microsoft Purview compliance portal\n"
                "# https://compliance.microsoft.com/insiderriskmanagement\n"
                "# Enable data connectors and create initial policy"
            ),
        },
    ]

    # Enrich steps with Foundry IQ Project 479 offers
    steps = _enrich_steps_with_p479(steps)

    return {
        "estimated_days_to_green": _compute_estimated_days(steps),
        "total_steps": len(steps),
        "estimated_score_improvement": _compute_total_score_improvement(steps),
        "steps": steps,
        "disclaimer": (
            "⚠️ Generated by PostureIQ (AI-assisted) — review with your security team "
            "before implementing. Scripts should be tested in a non-production environment first."
        ),
        "generated_at": datetime.now(UTC).isoformat(),
        "data_source": "mock",
    }


# ── Main tool function ─────────────────────────────────────────────────


@trace_tool_call("generate_remediation_plan")
async def generate_remediation_plan(assessment_context: str) -> dict[str, Any]:
    """Generate a prioritised remediation plan from assessment results.

    Args:
        assessment_context: JSON string summarising findings from all
            assessment tools.

    Returns:
        dict with keys:
          - estimated_days_to_green: int
          - total_steps: int
          - steps: list of remediation steps (P0 / P1 / P2)
          - estimated_score_improvement: float
          - disclaimer: str
          - generated_at: ISO timestamp
          - data_source: "openai" | "mock"
    """
    logger.info("tool.remediation_plan.start")

    # Step 1: Redact PII from assessment context
    redacted_context = redact_pii(assessment_context)

    # Step 2: Try Azure OpenAI
    oai_client = _create_openai_client()

    if oai_client is None:
        logger.info("tool.remediation_plan.mock_fallback")
        return _generate_mock_response()

    try:
        response = oai_client.chat.completions.create(
            model=settings.azure_openai_deployment,
            messages=[
                {"role": "system", "content": REMEDIATION_SYSTEM_PROMPT},
                {"role": "user", "content": f"Assessment findings:\n{redacted_context}"},
            ],
            temperature=0.3,
            max_tokens=4000,
        )

        raw_text = response.choices[0].message.content or ""
        steps_raw = _parse_llm_steps(raw_text)
        steps = [_validate_step(s) for s in steps_raw] if steps_raw else []

        if not steps:
            logger.warning("tool.remediation_plan.empty_llm_response")
            return _generate_mock_response()

        # Step 3: Enrich with Foundry IQ offers
        steps = _enrich_steps_with_p479(steps)

        # Step 4: Content safety check
        plan_text = json.dumps(steps, indent=2)
        safety_result = await check_content_safety(plan_text)

        if not safety_result["is_safe"]:
            logger.warning(
                "tool.remediation_plan.content_safety_blocked",
                reason=safety_result.get("reason"),
            )
            return {
                "estimated_days_to_green": 0,
                "total_steps": 0,
                "estimated_score_improvement": 0.0,
                "steps": [],
                "error": "Content safety check failed — plan not generated",
                "disclaimer": "Content was blocked by Azure AI Content Safety.",
                "generated_at": datetime.now(UTC).isoformat(),
                "data_source": "openai",
            }

        result: dict[str, Any] = {
            "estimated_days_to_green": _compute_estimated_days(steps),
            "total_steps": len(steps),
            "estimated_score_improvement": _compute_total_score_improvement(steps),
            "steps": steps,
            "disclaimer": (
                "⚠️ Generated by PostureIQ (AI-assisted) — review with your security team "
                "before implementing. Scripts should be tested in a non-production environment first."
            ),
            "generated_at": datetime.now(UTC).isoformat(),
            "data_source": "openai",
        }

        logger.info(
            "tool.remediation_plan.complete",
            total_steps=len(steps),
            estimated_days=result["estimated_days_to_green"],
            data_source="openai",
        )
        return result

    except Exception as exc:
        logger.error(
            "tool.remediation_plan.openai_error",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        logger.info("tool.remediation_plan.error_fallback_to_mock")
        return _generate_mock_response()
