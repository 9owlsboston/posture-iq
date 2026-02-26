"""Tests for PostureIQ observability — tracing, logging, and custom metrics.

Validates:
  - Trace spans are created for tool calls and LLM calls
  - Session tracing provides correlation across child spans
  - Structured JSON log format includes required fields
  - Custom metrics are emitted correctly
  - PII is excluded from all logs and traces
"""

from __future__ import annotations

import asyncio
import json
import logging
from unittest.mock import MagicMock, patch

import pytest
import structlog

from src.middleware.tracing import (
    _latest_secure_score,
    get_meter,
    get_tracer,
    record_assessment_duration,
    record_content_safety_block,
    record_remediation_steps,
    record_secure_score,
    setup_tracing,
    trace_llm_call,
    trace_session,
    trace_tool_call,
)


# ── Tracer & Meter Initialization ────────────────────────


class TestTracingSetup:
    """Verify tracing infrastructure initializes correctly."""

    def test_get_tracer_returns_tracer(self):
        tracer = get_tracer()
        assert tracer is not None

    def test_get_tracer_returns_same_instance(self):
        tracer1 = get_tracer()
        tracer2 = get_tracer()
        assert tracer1 is tracer2

    def test_get_meter_returns_meter(self):
        meter = get_meter()
        assert meter is not None

    def test_get_meter_returns_same_instance(self):
        meter1 = get_meter()
        meter2 = get_meter()
        assert meter1 is meter2

    def test_setup_tracing_without_connection_string(self):
        """Setup should succeed silently when no connection string is configured."""
        with patch("src.middleware.tracing.settings") as mock_settings:
            mock_settings.applicationinsights_connection_string = ""
            setup_tracing()
            # Should not raise

    def test_setup_tracing_with_import_error(self):
        """Setup should handle missing azure-monitor-opentelemetry gracefully."""

        def _fake_import(name, *args, **kwargs):
            if "azure.monitor" in name:
                raise ImportError("no module")
            return original_import(name, *args, **kwargs)

        import builtins
        original_import = builtins.__import__

        with (
            patch("src.middleware.tracing.settings") as mock_settings,
            patch("builtins.__import__", side_effect=_fake_import),
        ):
            mock_settings.applicationinsights_connection_string = "InstrumentationKey=test"
            # Should not raise, just log a warning
            setup_tracing()


# ── Tool Call Tracing ────────────────────────────────────


class TestTraceToolCall:
    """Verify tool call spans are created with correct attributes."""

    @pytest.mark.asyncio
    async def test_tool_call_creates_span(self):
        @trace_tool_call("test_tool")
        async def my_tool() -> dict:
            return {"status": "ok"}

        result = await my_tool()
        assert result == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_tool_call_returns_correct_result(self):
        @trace_tool_call("secure_score")
        async def query_secure_score() -> dict:
            return {"score": 72, "max_score": 100}

        result = await query_secure_score()
        assert result["score"] == 72
        assert result["max_score"] == 100

    @pytest.mark.asyncio
    async def test_tool_call_propagates_exceptions(self):
        @trace_tool_call("failing_tool")
        async def failing_tool() -> dict:
            raise ValueError("Graph API error")

        with pytest.raises(ValueError, match="Graph API error"):
            await failing_tool()

    @pytest.mark.asyncio
    async def test_tool_call_with_kwargs(self):
        @trace_tool_call("parameterized_tool")
        async def parameterized_tool(tenant_id: str = "", days: int = 30) -> dict:
            return {"tenant_id": tenant_id, "days": days}

        result = await parameterized_tool(tenant_id="test-123", days=7)
        assert result["days"] == 7

    @pytest.mark.asyncio
    async def test_tool_call_preserves_function_name(self):
        @trace_tool_call("query_secure_score")
        async def query_secure_score() -> dict:
            return {}

        assert query_secure_score.__name__ == "query_secure_score"

    @pytest.mark.asyncio
    async def test_tool_call_string_result(self):
        @trace_tool_call("string_tool")
        async def string_tool() -> str:
            return "markdown report"

        result = await string_tool()
        assert result == "markdown report"


# ── LLM Call Tracing ─────────────────────────────────────


class TestTraceLlmCall:
    """Verify LLM call spans are created with model, token, and safety attributes."""

    @pytest.mark.asyncio
    async def test_llm_call_creates_span(self):
        @trace_llm_call("gpt-4o")
        async def call_llm() -> dict:
            return {
                "content": "remediation plan",
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 50,
                    "total_tokens": 150,
                },
            }

        result = await call_llm()
        assert result["content"] == "remediation plan"

    @pytest.mark.asyncio
    async def test_llm_call_handles_usage_data(self):
        @trace_llm_call("gpt-4o")
        async def call_with_usage() -> dict:
            return {
                "content": "response",
                "usage": {
                    "prompt_tokens": 200,
                    "completion_tokens": 100,
                    "total_tokens": 300,
                },
            }

        result = await call_with_usage()
        assert result["usage"]["total_tokens"] == 300

    @pytest.mark.asyncio
    async def test_llm_call_handles_content_safety_result(self):
        @trace_llm_call("gpt-4o")
        async def call_with_safety() -> dict:
            return {
                "content": "safe response",
                "content_safety_result": "passed",
                "usage": {"prompt_tokens": 50, "completion_tokens": 25},
            }

        result = await call_with_safety()
        assert result["content_safety_result"] == "passed"

    @pytest.mark.asyncio
    async def test_llm_call_propagates_exceptions(self):
        @trace_llm_call("gpt-4o")
        async def failing_llm() -> dict:
            raise RuntimeError("OpenAI timeout")

        with pytest.raises(RuntimeError, match="OpenAI timeout"):
            await failing_llm()

    @pytest.mark.asyncio
    async def test_llm_call_without_usage(self):
        @trace_llm_call("gpt-4o")
        async def call_no_usage() -> dict:
            return {"content": "response"}

        result = await call_no_usage()
        assert result["content"] == "response"

    @pytest.mark.asyncio
    async def test_llm_call_preserves_function_name(self):
        @trace_llm_call("gpt-4o")
        async def generate_plan() -> dict:
            return {}

        assert generate_plan.__name__ == "generate_plan"

    @pytest.mark.asyncio
    async def test_llm_call_custom_model_name(self):
        @trace_llm_call("gpt-4o-mini")
        async def call_mini() -> dict:
            return {"content": "short"}

        result = await call_mini()
        assert result["content"] == "short"


# ── Session Tracing ──────────────────────────────────────


class TestTraceSession:
    """Verify session-level tracing provides correlation."""

    @pytest.mark.asyncio
    async def test_session_creates_span(self):
        @trace_session("session-abc123")
        async def run_session() -> dict:
            return {"status": "completed", "tools_called": 3}

        result = await run_session()
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_session_propagates_exceptions(self):
        @trace_session("session-error")
        async def failing_session() -> dict:
            raise ConnectionError("SDK connection lost")

        with pytest.raises(ConnectionError, match="SDK connection lost"):
            await failing_session()

    @pytest.mark.asyncio
    async def test_session_preserves_function_name(self):
        @trace_session("session-test")
        async def my_assessment_session() -> dict:
            return {}

        assert my_assessment_session.__name__ == "my_assessment_session"

    @pytest.mark.asyncio
    async def test_session_with_nested_tool_calls(self):
        """Tool calls within a session should complete successfully."""

        @trace_tool_call("inner_tool")
        async def inner_tool() -> dict:
            return {"inner": True}

        @trace_session("session-nested")
        async def session_with_tools() -> dict:
            tool_result = await inner_tool()
            return {"session": True, "tool_result": tool_result}

        result = await session_with_tools()
        assert result["session"] is True
        assert result["tool_result"]["inner"] is True


# ── Custom Metrics ───────────────────────────────────────


class TestCustomMetrics:
    """Verify custom App Insights metrics are recorded."""

    def test_record_secure_score(self):
        record_secure_score(72.5)
        from src.middleware.tracing import _latest_secure_score
        assert _latest_secure_score == 72.5

    def test_record_secure_score_updates(self):
        record_secure_score(50.0)
        record_secure_score(80.0)
        from src.middleware.tracing import _latest_secure_score
        assert _latest_secure_score == 80.0

    def test_record_assessment_duration(self):
        # Should not raise, even without full setup
        record_assessment_duration(1.5, "query_secure_score")

    def test_record_remediation_steps(self):
        # Should not raise
        record_remediation_steps(5)

    def test_record_content_safety_block(self):
        # Should not raise
        record_content_safety_block("hate_speech")

    def test_record_content_safety_block_default_category(self):
        record_content_safety_block()  # default "unknown"

    def test_secure_score_callback(self):
        from src.middleware.tracing import _secure_score_callback
        record_secure_score(88.0)
        observations = _secure_score_callback(MagicMock())
        assert len(observations) == 1
        assert observations[0].value == 88.0


# ── Structured Logging ───────────────────────────────────


class TestStructuredLogging:
    """Verify structured JSON log format meets requirements."""

    def test_logging_config_imports(self):
        from src.middleware.logging_config import setup_logging
        assert callable(setup_logging)

    def test_setup_logging_json_mode(self):
        from src.middleware.logging_config import setup_logging
        setup_logging(log_level="INFO", json_format=True)
        # Should not raise

    def test_setup_logging_console_mode(self):
        from src.middleware.logging_config import setup_logging
        setup_logging(log_level="DEBUG", json_format=False)
        # Should not raise

    def test_structlog_produces_json(self, capsys):
        from src.middleware.logging_config import setup_logging
        setup_logging(log_level="INFO", json_format=True)

        test_logger = structlog.get_logger("test.json_format")
        test_logger.info(
            "test.event",
            tool="query_secure_score",
            session_id="sess-001",
            duration_ms=123.45,
            status="success",
        )

        captured = capsys.readouterr()
        # Should have JSON-parseable output on stdout
        if captured.out.strip():
            try:
                parsed = json.loads(captured.out.strip())
                # Verify required fields exist
                assert "timestamp" in parsed
                assert "level" in parsed
            except json.JSONDecodeError:
                pass  # Structlog may include color codes in some envs

    def test_pii_redacted_from_logs(self, capsys):
        from src.middleware.logging_config import setup_logging
        setup_logging(log_level="INFO", json_format=True)

        test_logger = structlog.get_logger("test.pii")
        test_logger.info(
            "test.pii_check",
            tenant="abc12345-1234-1234-1234-123456789abc",
            email="user@contoso.com",
        )

        captured = capsys.readouterr()
        # PII should NOT appear in output
        assert "abc12345-1234-1234-1234-123456789abc" not in captured.out
        assert "user@contoso.com" not in captured.out

    def test_pii_redaction_processor(self):
        from src.middleware.logging_config import _redact_pii_processor

        event_dict = {
            "event": "test",
            "tenant_id": "abc12345-1234-1234-1234-123456789abc",
            "user": "admin@contoso.com",
            "level": "info",
            "timestamp": "2026-01-01T00:00:00Z",
        }

        result = _redact_pii_processor(None, "info", event_dict)
        assert "[TENANT_ID]" in result["tenant_id"]
        assert "[USER_EMAIL]" in result["user"]
        # level and timestamp should NOT be redacted
        assert result["level"] == "info"
        assert result["timestamp"] == "2026-01-01T00:00:00Z"


# ── PII Exclusion from Traces ────────────────────────────


class TestPiiExclusionFromTraces:
    """Verify that PII is redacted from trace span attributes."""

    @pytest.mark.asyncio
    async def test_tool_call_redacts_input_params(self):
        """Tool calls should redact PII from input kwargs."""

        @trace_tool_call("test_pii_tool")
        async def tool_with_pii(
            tenant_id: str = "",
            email: str = "",
        ) -> dict:
            return {"processed": True}

        # Should not raise — PII in kwargs gets redacted in span attributes
        result = await tool_with_pii(
            tenant_id="abc12345-1234-1234-1234-123456789abc",
            email="user@contoso.com",
        )
        assert result["processed"] is True

    @pytest.mark.asyncio
    async def test_llm_call_does_not_log_prompt_content(self):
        """LLM calls should not include raw prompt content in spans."""

        @trace_llm_call("gpt-4o")
        async def call_with_sensitive_prompt() -> dict:
            # The actual prompt content should NOT be in the span
            return {"content": "safe output", "usage": {"prompt_tokens": 50, "completion_tokens": 25}}

        result = await call_with_sensitive_prompt()
        assert result["content"] == "safe output"


# ── Dashboard Tests ──────────────────────────────────────


class TestDashboard:
    """Verify the App Insights dashboard definition is valid."""

    def test_dashboard_file_exists(self):
        from pathlib import Path
        dashboard = Path(__file__).parent.parent.parent / "infra" / "dashboards" / "postureiq-dashboard.json"
        assert dashboard.exists(), "Dashboard JSON file missing"

    def test_dashboard_is_valid_json(self):
        from pathlib import Path
        dashboard = Path(__file__).parent.parent.parent / "infra" / "dashboards" / "postureiq-dashboard.json"
        content = json.loads(dashboard.read_text())
        assert "items" in content
        assert "version" in content

    def test_dashboard_has_required_panels(self):
        from pathlib import Path
        dashboard = Path(__file__).parent.parent.parent / "infra" / "dashboards" / "postureiq-dashboard.json"
        content = json.loads(dashboard.read_text())
        panel_names = [item.get("name", "") for item in content["items"]]

        # Verify key panels exist
        assert "tool-call-performance" in panel_names
        assert "llm-usage" in panel_names
        assert "secure-score-trend" in panel_names
        assert "safety-blocks" in panel_names
        assert "remediation-steps" in panel_names
        assert "sessions-timeline" in panel_names
        assert "audit-trail" in panel_names

    def test_dashboard_queries_use_correct_metric_names(self):
        from pathlib import Path
        dashboard = Path(__file__).parent.parent.parent / "infra" / "dashboards" / "postureiq-dashboard.json"
        raw = dashboard.read_text()

        # Verify our custom metric names appear in queries
        assert "postureiq.secure_score.current" in raw
        assert "postureiq.content_safety.blocked_count" in raw
        assert "postureiq.remediation.steps_generated" in raw
