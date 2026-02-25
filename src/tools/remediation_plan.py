"""PostureIQ Tool — generate_remediation_plan

Generates a prioritized remediation plan based on assessment findings.
Uses Azure OpenAI (GPT-4o) for reasoning over gaps and producing
actionable remediation steps with PowerShell/CLI configuration scripts.

Routes LLM output through Azure AI Content Safety before returning.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import structlog

from src.agent.config import settings
from src.middleware.content_safety import check_content_safety
from src.middleware.pii_redaction import redact_pii
from src.middleware.tracing import trace_tool_call

logger = structlog.get_logger(__name__)


@trace_tool_call("generate_remediation_plan")
async def generate_remediation_plan(assessment_context: str) -> dict[str, Any]:
    """Generate a prioritized remediation plan from assessment results.

    Args:
        assessment_context: JSON string summarizing findings from all assessment tools.

    Returns:
        dict with keys:
          - estimated_days_to_green: int
          - total_steps: int
          - steps: list of remediation steps (P0/P1/P2)
          - estimated_score_improvement: float
          - disclaimer: str
          - generated_at: ISO timestamp
    """
    logger.info("tool.remediation_plan.start")

    # Step 1: Redact PII from assessment context before sending to LLM
    redacted_context = redact_pii(assessment_context)

    # Step 2: Call Azure OpenAI for remediation plan generation
    # TODO: Replace with actual Azure OpenAI call
    #
    # from openai import AzureOpenAI
    #
    # client = AzureOpenAI(
    #     azure_endpoint=settings.azure_openai_endpoint,
    #     api_version=settings.azure_openai_api_version,
    #     # Use Managed Identity via azure-identity DefaultAzureCredential
    # )
    #
    # response = client.chat.completions.create(
    #     model=settings.azure_openai_deployment,
    #     messages=[
    #         {"role": "system", "content": REMEDIATION_SYSTEM_PROMPT},
    #         {"role": "user", "content": f"Assessment findings:\n{redacted_context}"},
    #     ],
    #     temperature=0.3,  # Low temperature for consistent, factual plans
    #     max_tokens=4000,
    # )

    # ── Mock response for development ──────────────────────
    result = {
        "estimated_days_to_green": 21,
        "total_steps": 8,
        "estimated_score_improvement": 25.7,
        "steps": [
            {
                "priority": "P0",
                "title": "Block legacy authentication",
                "description": "Create a Conditional Access policy to block legacy authentication protocols across all users.",
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
                "description": "Enable sign-in risk and user risk policies to auto-remediate the 47 risky sign-ins and 12 risky users detected.",
                "impact_on_score": 4.5,
                "effort": "Low (1 hour)",
                "confidence": "high",
                "script": (
                    "# PowerShell — Enable sign-in risk policy\n"
                    "Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess'\n\n"
                    "# Sign-in risk policy: require MFA for medium+ risk\n"
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
                "description": "Safe Attachments is not enabled — this is a critical gap leaving the organization vulnerable to malware via email attachments.",
                "impact_on_score": 3.5,
                "effort": "Low (30 min)",
                "confidence": "high",
                "script": (
                    "# PowerShell — Enable Safe Attachments\n"
                    "Connect-ExchangeOnline\n\n"
                    "New-SafeAttachmentPolicy -Name 'PostureIQ: Safe Attachments' `\n"
                    "    -Enable $true `\n"
                    "    -Action 'DynamicDelivery' `\n"
                    "    -ActionOnError $true\n\n"
                    "New-SafeAttachmentRule -Name 'PostureIQ: Safe Attachments Rule' `\n"
                    "    -SafeAttachmentPolicy 'PostureIQ: Safe Attachments' `\n"
                    "    -RecipientDomainIs (Get-AcceptedDomain).Name `\n"
                    "    -Enabled $true"
                ),
            },
            {
                "priority": "P1",
                "title": "Convert permanent role assignments to eligible (PIM)",
                "description": "83% of privileged role assignments are permanent. Convert to eligible with JIT activation and approval workflows.",
                "impact_on_score": 4.0,
                "effort": "Medium (4-8 hours)",
                "confidence": "high",
                "script": (
                    "# PowerShell — Convert permanent to eligible assignments\n"
                    "Connect-MgGraph -Scopes 'RoleManagement.ReadWrite.Directory'\n\n"
                    "# Get all permanent active assignments\n"
                    "$permanentAssignments = Get-MgRoleManagementDirectoryRoleAssignment `\n"
                    "    -Filter \"assignmentType eq 'Assigned'\" -All\n\n"
                    "# For each (except break-glass accounts), create eligible assignment\n"
                    "foreach ($assignment in $permanentAssignments) {\n"
                    "    # Review before removing — do NOT auto-remove\n"
                    '    Write-Host "Review: $($assignment.PrincipalId) in role $($assignment.RoleDefinitionId)"\n'
                    "}"
                ),
            },
            {
                "priority": "P1",
                "title": "Enforce MFA for all users via Conditional Access",
                "description": "MFA is currently only enforced for admins. Extend to all users with a Conditional Access policy.",
                "impact_on_score": 3.0,
                "effort": "Medium (2-4 hours, requires communication to users)",
                "confidence": "high",
                "script": (
                    "# PowerShell — Require MFA for all users\n"
                    "Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess'\n\n"
                    "$params = @{\n"
                    '    DisplayName = "PostureIQ: Require MFA for All Users"\n'
                    "    State = 'enabledForReportingButNotEnforced'  # Start in report-only\n"
                    "    Conditions = @{\n"
                    "        Users = @{ IncludeUsers = @('All'); ExcludeGroups = @('<break-glass-group-id>') }\n"
                    "        Applications = @{ IncludeApplications = @('All') }\n"
                    "    }\n"
                    "    GrantControls = @{\n"
                    "        BuiltInControls = @('mfa')\n"
                    "        Operator = 'OR'\n"
                    "    }\n"
                    "}\n"
                    "New-MgIdentityConditionalAccessPolicy @params\n"
                    "# Note: Switch to 'enabled' after validating in report-only mode"
                ),
            },
            {
                "priority": "P1",
                "title": "Deploy Defender for Identity sensors to all DCs",
                "description": "Only 3 of 12 domain controllers have sensors. Deploy to remaining 9 for full coverage.",
                "impact_on_score": 2.5,
                "effort": "Medium (4-8 hours, requires DC access)",
                "confidence": "medium",
                "script": (
                    "# Manual process — download sensor installer from\n"
                    "# https://portal.atp.azure.com > Settings > Sensors\n"
                    "#\n"
                    "# For each unmonitored DC:\n"
                    "# 1. Download the sensor installer package\n"
                    "# 2. Run: Azure ATP Sensor Setup.exe /quiet NetFrameworkCommandLineArguments='/q'\n"
                    "# 3. Verify sensor status in the Defender for Identity portal"
                ),
            },
            {
                "priority": "P1",
                "title": "Enable DLP policies on SharePoint, OneDrive, Teams",
                "description": "DLP currently only covers Exchange. Extend to SharePoint, OneDrive, and Teams.",
                "impact_on_score": 2.0,
                "effort": "Medium (2-4 hours)",
                "confidence": "high",
                "script": (
                    "# PowerShell — Extend DLP to SharePoint, OneDrive, Teams\n"
                    "Connect-IPPSSession\n\n"
                    "# Modify existing DLP policy to add locations\n"
                    "Set-DlpCompliancePolicy -Identity 'Your-DLP-Policy-Name' `\n"
                    "    -SharePointLocation All `\n"
                    "    -OneDriveLocation All `\n"
                    "    -TeamsLocation All"
                ),
            },
            {
                "priority": "P2",
                "title": "Configure Access Reviews for privileged roles and guests",
                "description": "No access reviews are configured. Set up quarterly reviews for Global Admin, guest users, and sensitive groups.",
                "impact_on_score": 1.2,
                "effort": "Low-Medium (2 hours)",
                "confidence": "medium",
                "script": (
                    "# PowerShell — Create access review for Global Admins\n"
                    "Connect-MgGraph -Scopes 'AccessReview.ReadWrite.All'\n\n"
                    "# This requires the Access Reviews API (beta)\n"
                    "# See: https://learn.microsoft.com/en-us/graph/api/accessreviewset-post-definitions"
                ),
            },
        ],
        "disclaimer": (
            "⚠️ Generated by PostureIQ (AI-assisted) — review with your security team "
            "before implementing. Scripts should be tested in a non-production environment first."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # Step 3: Run content safety check on generated plan
    plan_text = json.dumps(result["steps"], indent=2)
    safety_result = await check_content_safety(plan_text)
    if not safety_result["is_safe"]:
        logger.warning("tool.remediation_plan.content_safety_blocked", reason=safety_result.get("reason"))
        result["steps"] = []
        result["error"] = "Content safety check failed — plan not generated"

    logger.info(
        "tool.remediation_plan.complete",
        total_steps=result["total_steps"],
        estimated_days_to_green=result["estimated_days_to_green"],
    )

    return result
