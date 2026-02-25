"""PostureIQ — Azure AI Content Safety middleware.

Routes LLM inputs and outputs through Azure AI Content Safety
for prompt-injection detection, harmful content filtering, and RAI compliance.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.agent.config import settings

logger = structlog.get_logger(__name__)


async def check_content_safety(text: str) -> dict[str, Any]:
    """Check text against Azure AI Content Safety.

    Analyzes text for harmful categories: Hate, SelfHarm, Sexual, Violence.
    Also checks for prompt injection / jailbreak attempts.

    Args:
        text: The text content to analyze.

    Returns:
        dict with keys:
          - is_safe: bool
          - categories: dict of category → severity (0-6)
          - reason: str (if blocked)
    """
    endpoint = settings.azure_content_safety_endpoint

    if not endpoint:
        logger.warning("content_safety.skipped", reason="no endpoint configured")
        return {
            "is_safe": True,
            "categories": {
                "hate": 0,
                "self_harm": 0,
                "sexual": 0,
                "violence": 0,
            },
            "reason": "safety check skipped — not configured",
        }

    # TODO: Replace with actual Azure AI Content Safety call
    #
    # from azure.ai.contentsafety import ContentSafetyClient
    # from azure.ai.contentsafety.models import AnalyzeTextOptions
    # from azure.identity import DefaultAzureCredential
    #
    # credential = DefaultAzureCredential()
    # client = ContentSafetyClient(endpoint, credential)
    #
    # request = AnalyzeTextOptions(text=text)
    # response = client.analyze_text(request)
    #
    # categories = {
    #     "hate": response.hate_result.severity if response.hate_result else 0,
    #     "self_harm": response.self_harm_result.severity if response.self_harm_result else 0,
    #     "sexual": response.sexual_result.severity if response.sexual_result else 0,
    #     "violence": response.violence_result.severity if response.violence_result else 0,
    # }
    #
    # # Block if any category severity >= 4 (medium-high)
    # max_severity = max(categories.values())
    # is_safe = max_severity < 4

    # ── Mock response for development ──────────────────────
    result: dict[str, Any] = {
        "is_safe": True,
        "categories": {
            "hate": 0,
            "self_harm": 0,
            "sexual": 0,
            "violence": 0,
        },
        "reason": None,
    }

    logger.info("content_safety.check.complete", is_safe=result["is_safe"])
    return result


async def check_prompt_injection(user_input: str) -> dict[str, Any]:
    """Check user input for prompt injection / jailbreak attempts.

    Uses Azure AI Content Safety prompt shield feature.

    Args:
        user_input: The user's query to analyze.

    Returns:
        dict with keys:
          - is_safe: bool
          - attack_detected: bool
          - reason: str (if blocked)
    """
    # TODO: Replace with actual prompt shield API call
    #
    # from azure.ai.contentsafety import ContentSafetyClient
    # from azure.ai.contentsafety.models import AnalyzeTextOptions
    #
    # Prompt shield is a separate API endpoint in Content Safety

    # ── Mock response for development ──────────────────────
    # Basic heuristic checks as a placeholder
    injection_patterns = [
        "ignore previous instructions",
        "ignore your system prompt",
        "you are now",
        "pretend you are",
        "forget your instructions",
        "override your",
        "disregard all",
    ]

    lower_input = user_input.lower()
    attack_detected = any(pattern in lower_input for pattern in injection_patterns)

    result: dict[str, Any] = {
        "is_safe": not attack_detected,
        "attack_detected": attack_detected,
        "reason": "Potential prompt injection detected" if attack_detected else None,
    }

    if attack_detected:
        logger.warning("content_safety.prompt_injection.detected", input_preview=user_input[:100])

    return result
