"""Comprehensive tests for the generate_remediation_plan tool.

Covers:
  - Helper functions (_parse_llm_steps, _validate_step, _compute_estimated_days,
    _compute_total_score_improvement)
  - OpenAI client factory (_create_openai_client)
  - Mock fallback path (no OpenAI endpoint configured)
  - OpenAI integration path (mocked SDK responses)
  - Content safety post-processing
  - PII redaction pre-processing
  - Error handling and fallback
  - Trace span creation via @trace_tool_call decorator
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════


def _make_step(
    *,
    priority: str = "P0",
    title: str = "Block legacy auth",
    description: str = "Block it",
    impact_on_score: float = 5.0,
    effort: str = "Low (1-2 hours)",
    confidence: str = "high",
    script: str = "# do something",
) -> dict[str, Any]:
    return {
        "priority": priority,
        "title": title,
        "description": description,
        "impact_on_score": impact_on_score,
        "effort": effort,
        "confidence": confidence,
        "script": script,
    }


def _make_openai_response(content: str) -> SimpleNamespace:
    """Build a fake ChatCompletion response."""
    message = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


# ═══════════════════════════════════════════════════════════════════════
# 1. _parse_llm_steps
# ═══════════════════════════════════════════════════════════════════════


class TestParseLlmSteps:
    def test_valid_json_array(self):
        from src.tools.remediation_plan import _parse_llm_steps

        steps = [_make_step(), _make_step(title="Step 2")]
        raw = json.dumps(steps)
        result = _parse_llm_steps(raw)
        assert len(result) == 2
        assert result[0]["title"] == "Block legacy auth"

    def test_json_with_markdown_fences(self):
        from src.tools.remediation_plan import _parse_llm_steps

        steps = [_make_step()]
        raw = f"```json\n{json.dumps(steps)}\n```"
        result = _parse_llm_steps(raw)
        assert len(result) == 1

    def test_json_with_plain_fences(self):
        from src.tools.remediation_plan import _parse_llm_steps

        steps = [_make_step()]
        raw = f"```\n{json.dumps(steps)}\n```"
        result = _parse_llm_steps(raw)
        assert len(result) == 1

    def test_dict_with_steps_key(self):
        from src.tools.remediation_plan import _parse_llm_steps

        raw = json.dumps({"steps": [_make_step()]})
        result = _parse_llm_steps(raw)
        assert len(result) == 1

    def test_single_dict(self):
        from src.tools.remediation_plan import _parse_llm_steps

        raw = json.dumps(_make_step())
        result = _parse_llm_steps(raw)
        assert len(result) == 1

    def test_invalid_json_returns_empty(self):
        from src.tools.remediation_plan import _parse_llm_steps

        result = _parse_llm_steps("not valid json at all")
        assert result == []

    def test_empty_string(self):
        from src.tools.remediation_plan import _parse_llm_steps

        result = _parse_llm_steps("")
        assert result == []

    def test_whitespace_only(self):
        from src.tools.remediation_plan import _parse_llm_steps

        result = _parse_llm_steps("   \n\n  ")
        assert result == []

    def test_extra_whitespace_around_json(self):
        from src.tools.remediation_plan import _parse_llm_steps

        steps = [_make_step()]
        raw = f"  \n{json.dumps(steps)}\n  "
        result = _parse_llm_steps(raw)
        assert len(result) == 1


# ═══════════════════════════════════════════════════════════════════════
# 2. _validate_step
# ═══════════════════════════════════════════════════════════════════════


class TestValidateStep:
    def test_complete_step(self):
        from src.tools.remediation_plan import _validate_step

        step = _make_step()
        result = _validate_step(step)
        assert result["priority"] == "P0"
        assert result["title"] == "Block legacy auth"
        assert result["impact_on_score"] == 5.0

    def test_missing_fields_get_defaults(self):
        from src.tools.remediation_plan import _validate_step

        result = _validate_step({})
        assert result["priority"] == "P2"
        assert result["title"] == "Untitled step"
        assert result["impact_on_score"] == 0.0
        assert result["confidence"] == "low"
        assert result["script"] == "# No script provided"

    def test_partial_step(self):
        from src.tools.remediation_plan import _validate_step

        result = _validate_step({"title": "Do something", "priority": "P1"})
        assert result["title"] == "Do something"
        assert result["priority"] == "P1"
        assert result["effort"] == "Unknown"

    def test_impact_converted_to_float(self):
        from src.tools.remediation_plan import _validate_step

        result = _validate_step({"impact_on_score": "3.5"})
        assert result["impact_on_score"] == 3.5


# ═══════════════════════════════════════════════════════════════════════
# 3. _compute_estimated_days
# ═══════════════════════════════════════════════════════════════════════


class TestComputeEstimatedDays:
    def test_low_effort(self):
        from src.tools.remediation_plan import _compute_estimated_days

        steps = [{"effort": "Low (1 hour)"}]
        result = _compute_estimated_days(steps)
        assert result == 1  # 2 hours / 4 = 0.5 → max(1, round(0.5)) = 1

    def test_medium_effort(self):
        from src.tools.remediation_plan import _compute_estimated_days

        steps = [{"effort": "Medium (4 hours)"}]
        result = _compute_estimated_days(steps)
        assert result == 2  # 6 / 4 = 1.5 → round to 2

    def test_high_effort(self):
        from src.tools.remediation_plan import _compute_estimated_days

        steps = [{"effort": "High (2 days)"}]
        result = _compute_estimated_days(steps)
        assert result == 4  # 16 / 4 = 4

    def test_unknown_effort(self):
        from src.tools.remediation_plan import _compute_estimated_days

        steps = [{"effort": "???"}]
        result = _compute_estimated_days(steps)
        assert result == 1  # 4 / 4 = 1

    def test_none_effort(self):
        from src.tools.remediation_plan import _compute_estimated_days

        steps = [{"effort": None}]
        result = _compute_estimated_days(steps)
        assert result == 1

    def test_multiple_steps(self):
        from src.tools.remediation_plan import _compute_estimated_days

        steps = [
            {"effort": "Low (1 hour)"},  # 2h
            {"effort": "Medium (4h)"},  # 6h
            {"effort": "High (2 days)"},  # 16h
        ]
        result = _compute_estimated_days(steps)
        assert result == 6  # (2+6+16)/4 = 6

    def test_empty_list(self):
        from src.tools.remediation_plan import _compute_estimated_days

        result = _compute_estimated_days([])
        assert result == 1  # max(1, 0) = 1


# ═══════════════════════════════════════════════════════════════════════
# 4. _compute_total_score_improvement
# ═══════════════════════════════════════════════════════════════════════


class TestComputeTotalScoreImprovement:
    def test_basic(self):
        from src.tools.remediation_plan import _compute_total_score_improvement

        steps = [{"impact_on_score": 5.0}, {"impact_on_score": 3.5}]
        assert _compute_total_score_improvement(steps) == 8.5

    def test_empty(self):
        from src.tools.remediation_plan import _compute_total_score_improvement

        assert _compute_total_score_improvement([]) == 0.0

    def test_missing_field(self):
        from src.tools.remediation_plan import _compute_total_score_improvement

        assert _compute_total_score_improvement([{}]) == 0.0

    def test_rounding(self):
        from src.tools.remediation_plan import _compute_total_score_improvement

        steps = [{"impact_on_score": 1.1}, {"impact_on_score": 2.2}]
        result = _compute_total_score_improvement(steps)
        assert result == 3.3


# ═══════════════════════════════════════════════════════════════════════
# 5. _create_openai_client
# ═══════════════════════════════════════════════════════════════════════


class TestCreateOpenAIClient:
    @patch("src.tools.remediation_plan.settings")
    def test_no_endpoint_returns_none(self, mock_settings):
        from src.tools.remediation_plan import _create_openai_client

        mock_settings.azure_openai_endpoint = ""
        result = _create_openai_client()
        assert result is None

    @patch("src.tools.remediation_plan.settings")
    def test_none_endpoint_returns_none(self, mock_settings):
        from src.tools.remediation_plan import _create_openai_client

        mock_settings.azure_openai_endpoint = None
        result = _create_openai_client()
        assert result is None

    @patch("src.tools.remediation_plan.settings")
    def test_api_key_creates_client(self, mock_settings):
        from src.tools.remediation_plan import _create_openai_client

        mock_settings.azure_openai_endpoint = "https://test.openai.azure.com"
        mock_settings.azure_openai_api_version = "2024-02-01"
        mock_settings.azure_openai_api_key = "test-key"

        with patch("openai.AzureOpenAI") as mock_cls:
            mock_cls.return_value = MagicMock()
            client = _create_openai_client()
            assert client is not None
            mock_cls.assert_called_once()

    @patch("src.tools.remediation_plan.settings")
    def test_managed_identity_creates_client(self, mock_settings):
        from src.tools.remediation_plan import _create_openai_client

        mock_settings.azure_openai_endpoint = "https://test.openai.azure.com"
        mock_settings.azure_openai_api_version = "2024-02-01"
        mock_settings.azure_openai_api_key = ""

        with (
            patch("azure.identity.DefaultAzureCredential") as mock_cred,
            patch("azure.identity.get_bearer_token_provider") as mock_tp,
            patch("openai.AzureOpenAI") as mock_cls,
        ):
            mock_cred.return_value = MagicMock()
            mock_tp.return_value = MagicMock()
            mock_cls.return_value = MagicMock()
            client = _create_openai_client()
            assert client is not None

    @patch("src.tools.remediation_plan.settings")
    def test_creation_error_returns_none(self, mock_settings):
        from src.tools.remediation_plan import _create_openai_client

        mock_settings.azure_openai_endpoint = "https://test.openai.azure.com"
        mock_settings.azure_openai_api_key = "key"

        with patch("openai.AzureOpenAI", side_effect=Exception("init error")):
            result = _create_openai_client()
            assert result is None


# ═══════════════════════════════════════════════════════════════════════
# 6. Mock fallback — no OpenAI endpoint configured
# ═══════════════════════════════════════════════════════════════════════


class TestRemediationMockFallback:
    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_returns_mock_data_source(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("{}")
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_mock_has_steps(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("{}")
        assert result["total_steps"] > 0
        assert len(result["steps"]) == result["total_steps"]

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_mock_has_estimated_days(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("{}")
        assert result["estimated_days_to_green"] > 0

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_mock_has_score_improvement(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("{}")
        assert result["estimated_score_improvement"] > 0

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_mock_has_disclaimer(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("{}")
        assert "disclaimer" in result
        assert "PostureIQ" in result["disclaimer"]

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_mock_has_generated_at(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("{}")
        assert "generated_at" in result

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_mock_step_structure(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("{}")
        for step in result["steps"]:
            assert "priority" in step
            assert "title" in step
            assert "description" in step
            assert "impact_on_score" in step
            assert "effort" in step
            assert "confidence" in step
            assert "script" in step

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_mock_priorities_present(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("{}")
        priorities = {s["priority"] for s in result["steps"]}
        assert "P0" in priorities


# ═══════════════════════════════════════════════════════════════════════
# 7. OpenAI integration path (mocked)
# ═══════════════════════════════════════════════════════════════════════


class TestRemediationOpenAIPath:
    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_successful_generation(self, mock_factory, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        steps = [_make_step(), _make_step(title="Step 2", priority="P1")]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response(json.dumps(steps))
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True, "categories": {}, "reason": None}

        result = await generate_remediation_plan('{"gaps": []}')
        assert result["data_source"] == "openai"
        assert result["total_steps"] == 2
        assert len(result["steps"]) == 2

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_steps_validated(self, mock_factory, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        # Return partial step — validator should fill defaults
        steps = [{"title": "Only title"}]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response(json.dumps(steps))
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True, "categories": {}, "reason": None}

        result = await generate_remediation_plan("{}")
        assert result["steps"][0]["priority"] == "P2"  # default
        assert result["steps"][0]["title"] == "Only title"

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_empty_llm_response_falls_back_to_mock(self, mock_factory, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response("")
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True, "categories": {}, "reason": None}

        result = await generate_remediation_plan("{}")
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_invalid_json_falls_back_to_mock(self, mock_factory, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response("This is not JSON at all")
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True, "categories": {}, "reason": None}

        result = await generate_remediation_plan("{}")
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_openai_exception_falls_back_to_mock(self, mock_factory):
        from src.tools.remediation_plan import generate_remediation_plan

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("rate limit")
        mock_factory.return_value = mock_client

        result = await generate_remediation_plan("{}")
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_markdown_fences_handled(self, mock_factory, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        steps = [_make_step()]
        raw = f"```json\n{json.dumps(steps)}\n```"
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response(raw)
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True, "categories": {}, "reason": None}

        result = await generate_remediation_plan("{}")
        assert result["data_source"] == "openai"
        assert result["total_steps"] == 1

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_null_content_falls_back_to_mock(self, mock_factory, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        mock_client = MagicMock()
        msg = SimpleNamespace(content=None)
        choice = SimpleNamespace(message=msg)
        mock_client.chat.completions.create.return_value = SimpleNamespace(choices=[choice])
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True}

        result = await generate_remediation_plan("{}")
        assert result["data_source"] == "mock"


# ═══════════════════════════════════════════════════════════════════════
# 8. Content safety integration
# ═══════════════════════════════════════════════════════════════════════


class TestRemediationContentSafety:
    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_unsafe_content_blocked(self, mock_factory, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        steps = [_make_step()]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response(json.dumps(steps))
        mock_factory.return_value = mock_client
        mock_safety.return_value = {
            "is_safe": False,
            "categories": {"violence": 6},
            "reason": "Violence detected",
        }

        result = await generate_remediation_plan("{}")
        assert result["data_source"] == "openai"
        assert result["total_steps"] == 0
        assert result["steps"] == []
        assert "error" in result

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_safe_content_passes_through(self, mock_factory, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        steps = [_make_step()]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response(json.dumps(steps))
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True, "categories": {}, "reason": None}

        result = await generate_remediation_plan("{}")
        assert result["total_steps"] == 1
        assert "error" not in result


# ═══════════════════════════════════════════════════════════════════════
# 9. PII redaction integration
# ═══════════════════════════════════════════════════════════════════════


class TestRemediationPIIRedaction:
    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan.redact_pii")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_pii_redacted_before_llm(self, mock_factory, mock_redact, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        mock_redact.return_value = "REDACTED CONTEXT"
        steps = [_make_step()]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response(json.dumps(steps))
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True, "categories": {}, "reason": None}

        await generate_remediation_plan("user@example.com has issues")

        # Verify redact_pii was called with original input
        mock_redact.assert_called_once_with("user@example.com has issues")

        # Verify the redacted text was sent to the LLM
        call_args = mock_client.chat.completions.create.call_args
        messages = call_args[1]["messages"] if "messages" in call_args[1] else call_args[0][0]
        user_message = [m for m in messages if m["role"] == "user"][0]
        assert "REDACTED" in user_message["content"]


# ═══════════════════════════════════════════════════════════════════════
# 10. Tracing
# ═══════════════════════════════════════════════════════════════════════


class TestRemediationTracing:
    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_created(self, mock_tracer_fn, _mock_client):
        from src.tools.remediation_plan import generate_remediation_plan

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await generate_remediation_plan("{}")
        mock_tracer.start_as_current_span.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_name_contains_tool(self, mock_tracer_fn, _mock_client):
        from src.tools.remediation_plan import generate_remediation_plan

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await generate_remediation_plan("{}")
        call_args = mock_tracer.start_as_current_span.call_args
        span_name = call_args.kwargs.get("name", call_args[0][0] if call_args[0] else "")
        assert "generate_remediation_plan" in span_name


# ═══════════════════════════════════════════════════════════════════════
# 11. Edge cases
# ═══════════════════════════════════════════════════════════════════════


class TestRemediationEdgeCases:
    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_empty_assessment_context(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("")
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_large_assessment_context(self, _mock):
        from src.tools.remediation_plan import generate_remediation_plan

        large_ctx = json.dumps({"gaps": ["gap"] * 100})
        result = await generate_remediation_plan(large_ctx)
        assert result["data_source"] == "mock"
        assert result["total_steps"] > 0

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_result_has_all_required_keys(self, mock_factory, mock_safety):
        from src.tools.remediation_plan import generate_remediation_plan

        steps = [_make_step()]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response(json.dumps(steps))
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True, "categories": {}, "reason": None}

        result = await generate_remediation_plan("{}")
        required_keys = {
            "estimated_days_to_green",
            "total_steps",
            "steps",
            "estimated_score_improvement",
            "disclaimer",
            "generated_at",
            "data_source",
        }
        assert required_keys.issubset(set(result.keys()))

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan.check_content_safety")
    @patch("src.tools.remediation_plan._create_openai_client")
    async def test_model_deployment_used(self, mock_factory, mock_safety):
        """Verify the correct deployment/model is passed to the API."""
        from src.tools.remediation_plan import generate_remediation_plan

        steps = [_make_step()]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response(json.dumps(steps))
        mock_factory.return_value = mock_client
        mock_safety.return_value = {"is_safe": True, "categories": {}, "reason": None}

        await generate_remediation_plan("{}")
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert "model" in call_kwargs
        assert call_kwargs["temperature"] == 0.3


# ═══════════════════════════════════════════════════════════════════════
# 8. Foundry IQ (Project 479) Enrichment
# ═══════════════════════════════════════════════════════════════════════


class TestFoundryIQEnrichment:
    """Tests for _enrich_step_with_p479_offer and _enrich_steps_with_p479."""

    def test_step_with_legacy_auth_maps_to_conditional_access(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Block legacy authentication", description="Block legacy auth protocols")
        enriched = _enrich_step_with_p479_offer(step)
        assert enriched["workload_area"] == "entra_conditional_access"
        assert "project_479_offer" in enriched
        assert enriched["project_479_offer"]["id"] == "P479-EID-001"

    def test_step_with_safe_attachments_maps_to_defender_o365(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Enable Safe Attachments", description="Safe Attachments not enabled")
        enriched = _enrich_step_with_p479_offer(step)
        assert enriched["workload_area"] == "defender_office365"
        assert enriched["project_479_offer"]["id"] == "P479-DEF-002"

    def test_step_with_pim_maps_to_entra_pim(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Convert permanent role assignments to eligible (PIM)")
        enriched = _enrich_step_with_p479_offer(step)
        assert enriched["workload_area"] == "entra_pim"
        assert enriched["project_479_offer"]["id"] == "P479-EID-002"

    def test_step_with_dlp_maps_to_purview_dlp(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Extend DLP policies to SharePoint and Teams")
        enriched = _enrich_step_with_p479_offer(step)
        assert enriched["workload_area"] == "purview_dlp"
        assert enriched["project_479_offer"]["id"] == "P479-PUR-001"

    def test_step_with_mfa_maps_to_conditional_access(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Enforce MFA for all users via Conditional Access")
        enriched = _enrich_step_with_p479_offer(step)
        assert enriched["workload_area"] == "entra_conditional_access"

    def test_step_with_identity_protection_maps_correctly(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Enable Identity Protection risk policies")
        enriched = _enrich_step_with_p479_offer(step)
        assert enriched["workload_area"] == "entra_identity_protection"
        assert enriched["project_479_offer"]["id"] == "P479-EID-003"

    def test_step_with_insider_risk_maps_correctly(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Enable Insider Risk Management")
        enriched = _enrich_step_with_p479_offer(step)
        assert enriched["workload_area"] == "purview_insider_risk"
        assert enriched["project_479_offer"]["id"] == "P479-PUR-004"

    def test_step_with_access_review_maps_correctly(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Configure Access Reviews for guest users")
        enriched = _enrich_step_with_p479_offer(step)
        assert enriched["workload_area"] == "entra_access_reviews"
        assert enriched["project_479_offer"]["id"] == "P479-EID-004"

    def test_unmatched_step_has_no_offer(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Something completely unrelated", description="No keywords here")
        enriched = _enrich_step_with_p479_offer(step)
        assert "project_479_offer" not in enriched
        assert "workload_area" not in enriched

    def test_offer_has_all_required_fields(self):
        from src.tools.remediation_plan import _enrich_step_with_p479_offer

        step = _make_step(title="Enable Safe Attachments")
        enriched = _enrich_step_with_p479_offer(step)
        offer = enriched["project_479_offer"]
        assert "name" in offer
        assert "id" in offer
        assert "description" in offer
        assert "duration" in offer
        assert "delivery" in offer

    def test_enrich_steps_batch(self):
        from src.tools.remediation_plan import _enrich_steps_with_p479

        steps = [
            _make_step(title="Block legacy auth"),
            _make_step(title="Enable Safe Attachments"),
            _make_step(title="Something unknown"),
        ]
        enriched = _enrich_steps_with_p479(steps)
        assert len(enriched) == 3
        # First two should have offers, third should not
        assert "project_479_offer" in enriched[0]
        assert "project_479_offer" in enriched[1]
        assert "project_479_offer" not in enriched[2]

    def test_enrich_does_not_mutate_original(self):
        from src.tools.remediation_plan import _enrich_steps_with_p479

        original = _make_step(title="Block legacy auth")
        enriched = _enrich_steps_with_p479([original])
        # Original should not be mutated (we dict-copy inside)
        assert "project_479_offer" not in original

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_mock_response_has_p479_offers(self, _mock):
        """The mock fallback path should also produce P479 offers on steps."""
        from src.tools.remediation_plan import generate_remediation_plan

        result = await generate_remediation_plan("{}")
        steps_with_offer = [s for s in result["steps"] if "project_479_offer" in s]
        # Most mock steps should match a workload area
        assert len(steps_with_offer) >= 5, f"Expected >=5 steps with P479 offers, got {len(steps_with_offer)}"
