"""Unit tests for Phase 1.1 — Agent Host Setup (src/agent/main.py).

Tests cover:
  - Tool adapter handlers (ToolInvocation → ToolResult bridging)
  - TOOLS registry (completeness, schema, types)
  - PostureIQAgent lifecycle (start, create session, resume, close, stop)
  - Session event handling (streaming deltas, tool events, errors)
  - send_message / send_message_streaming
  - _extract_response_text
  - Error paths (no client, no session)
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, AsyncMock, patch, call

import pytest
from copilot import Tool, ToolInvocation, ToolResult
from copilot.generated.session_events import SessionEventType

from src.agent.main import (
    TOOLS,
    PostureIQAgent,
    _handle_secure_score,
    _handle_defender_coverage,
    _handle_purview_policies,
    _handle_entra_config,
    _handle_remediation_plan,
    _handle_adoption_scorecard,
)
from src.agent.system_prompt import SYSTEM_PROMPT


# ── Helpers ────────────────────────────────────────────────────────────────


def _make_invocation(
    arguments: dict[str, Any] | None = None,
    tool_name: str = "test_tool",
) -> ToolInvocation:
    """Create a minimal ToolInvocation for testing.

    ToolInvocation is a TypedDict, so we construct it as a plain dict.
    """
    return {
        "session_id": "test-session",
        "tool_call_id": "call-001",
        "tool_name": tool_name,
        "arguments": arguments,
    }


def _make_session_event(
    event_type: SessionEventType,
    **data_kwargs: Any,
) -> Any:
    """Create a mock SessionEvent with the given type and data fields."""
    data = SimpleNamespace(**data_kwargs)
    event = SimpleNamespace(type=event_type, data=data, id=None, timestamp=None, ephemeral=None, parent_id=None)
    return event


# ═══════════════════════════════════════════════════════════════════════════
# 1. TOOL ADAPTER HANDLER TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestHandleSecureScore:
    """Tests for _handle_secure_score adapter."""

    @pytest.mark.asyncio
    async def test_returns_tool_result_dict(self):
        inv = _make_invocation(tool_name="query_secure_score")
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            result = await _handle_secure_score(inv)
        assert isinstance(result, dict)
        assert "textResultForLlm" in result

    @pytest.mark.asyncio
    async def test_result_contains_valid_json(self):
        inv = _make_invocation(tool_name="query_secure_score")
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            result = await _handle_secure_score(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert "current_score" in parsed
        assert "categories" in parsed

    @pytest.mark.asyncio
    async def test_passes_tenant_id_argument(self):
        inv = _make_invocation(
            arguments={"tenant_id": "test-tenant-123"},
            tool_name="query_secure_score",
        )
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            result = await _handle_secure_score(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert parsed["current_score"] > 0

    @pytest.mark.asyncio
    async def test_handles_no_arguments(self):
        inv = _make_invocation(arguments=None, tool_name="query_secure_score")
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            result = await _handle_secure_score(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert "current_score" in parsed


class TestHandleDefenderCoverage:
    """Tests for _handle_defender_coverage adapter."""

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client", return_value=None)
    async def test_returns_tool_result_dict(self, _mock_client):
        inv = _make_invocation(tool_name="assess_defender_coverage")
        result = await _handle_defender_coverage(inv)
        assert isinstance(result, dict)
        assert "textResultForLlm" in result

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client", return_value=None)
    async def test_result_is_valid_json(self, _mock_client):
        inv = _make_invocation(tool_name="assess_defender_coverage")
        result = await _handle_defender_coverage(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert isinstance(parsed, dict)


class TestHandlePurviewPolicies:
    """Tests for _handle_purview_policies adapter."""

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    async def test_returns_tool_result_dict(self, _mock_client):
        inv = _make_invocation(tool_name="check_purview_policies")
        result = await _handle_purview_policies(inv)
        assert isinstance(result, dict)
        assert "textResultForLlm" in result

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    async def test_result_is_valid_json(self, _mock_client):
        inv = _make_invocation(tool_name="check_purview_policies")
        result = await _handle_purview_policies(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert isinstance(parsed, dict)


class TestHandleEntraConfig:
    """Tests for _handle_entra_config adapter."""

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    async def test_returns_tool_result_dict(self, _mock_client):
        inv = _make_invocation(tool_name="get_entra_config")
        result = await _handle_entra_config(inv)
        assert isinstance(result, dict)
        assert "textResultForLlm" in result

    @pytest.mark.asyncio
    @patch("src.tools.entra_config._create_graph_client", return_value=None)
    async def test_result_is_valid_json(self, _mock_client):
        inv = _make_invocation(tool_name="get_entra_config")
        result = await _handle_entra_config(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert isinstance(parsed, dict)


class TestHandleRemediationPlan:
    """Tests for _handle_remediation_plan adapter."""

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_returns_tool_result_dict(self, _mock_client):
        inv = _make_invocation(
            arguments={"assessment_context": '{"score": 47}'},
            tool_name="generate_remediation_plan",
        )
        result = await _handle_remediation_plan(inv)
        assert isinstance(result, dict)
        assert "textResultForLlm" in result

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_result_is_valid_json(self, _mock_client):
        inv = _make_invocation(
            arguments={"assessment_context": '{"score": 47}'},
            tool_name="generate_remediation_plan",
        )
        result = await _handle_remediation_plan(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert isinstance(parsed, dict)

    @pytest.mark.asyncio
    @patch("src.tools.remediation_plan._create_openai_client", return_value=None)
    async def test_defaults_to_empty_context(self, _mock_client):
        inv = _make_invocation(arguments=None, tool_name="generate_remediation_plan")
        result = await _handle_remediation_plan(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert isinstance(parsed, dict)


class TestHandleAdoptionScorecard:
    """Tests for _handle_adoption_scorecard adapter."""

    @pytest.mark.asyncio
    async def test_returns_tool_result_dict(self):
        inv = _make_invocation(
            arguments={"assessment_context": '{"score": 47}'},
            tool_name="create_adoption_scorecard",
        )
        result = await _handle_adoption_scorecard(inv)
        assert isinstance(result, dict)
        assert "textResultForLlm" in result

    @pytest.mark.asyncio
    async def test_result_is_valid_json(self):
        inv = _make_invocation(
            arguments={"assessment_context": '{"score": 47}'},
            tool_name="create_adoption_scorecard",
        )
        result = await _handle_adoption_scorecard(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert isinstance(parsed, dict)

    @pytest.mark.asyncio
    async def test_defaults_to_empty_context(self):
        inv = _make_invocation(arguments=None, tool_name="create_adoption_scorecard")
        result = await _handle_adoption_scorecard(inv)
        parsed = json.loads(result["textResultForLlm"])
        assert isinstance(parsed, dict)


# ═══════════════════════════════════════════════════════════════════════════
# 2. TOOLS REGISTRY TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestToolsRegistry:
    """Tests for the TOOLS list — completeness, naming, and schema."""

    EXPECTED_TOOL_NAMES = [
        "query_secure_score",
        "assess_defender_coverage",
        "check_purview_policies",
        "get_entra_config",
        "generate_remediation_plan",
        "create_adoption_scorecard",
        "get_project479_playbook",
    ]

    def test_exactly_seven_tools(self):
        assert len(TOOLS) == 7

    def test_all_expected_tools_present(self):
        tool_names = [t.name for t in TOOLS]
        for expected in self.EXPECTED_TOOL_NAMES:
            assert expected in tool_names, f"Missing tool: {expected}"

    def test_all_tools_are_tool_instances(self):
        for tool in TOOLS:
            assert isinstance(tool, Tool)

    def test_every_tool_has_description(self):
        for tool in TOOLS:
            assert tool.description, f"{tool.name} has empty description"
            assert len(tool.description) > 20, f"{tool.name} description too short"

    def test_every_tool_has_callable_handler(self):
        for tool in TOOLS:
            assert callable(tool.handler), f"{tool.name} handler not callable"

    def test_every_tool_has_parameters_schema(self):
        for tool in TOOLS:
            assert tool.parameters is not None, f"{tool.name} missing parameters"
            assert tool.parameters["type"] == "object"
            assert "properties" in tool.parameters

    def test_remediation_requires_assessment_context(self):
        tool = next(t for t in TOOLS if t.name == "generate_remediation_plan")
        assert "assessment_context" in tool.parameters["required"]

    def test_scorecard_requires_assessment_context(self):
        tool = next(t for t in TOOLS if t.name == "create_adoption_scorecard")
        assert "assessment_context" in tool.parameters["required"]

    def test_secure_score_tenant_id_is_optional(self):
        tool = next(t for t in TOOLS if t.name == "query_secure_score")
        assert "tenant_id" in tool.parameters["properties"]
        assert "tenant_id" not in tool.parameters.get("required", [])

    def test_no_duplicate_tool_names(self):
        names = [t.name for t in TOOLS]
        assert len(names) == len(set(names)), "Duplicate tool names found"


# ═══════════════════════════════════════════════════════════════════════════
# 3. PostureIQAgent LIFECYCLE TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestPostureIQAgentInit:
    """Tests for PostureIQAgent initialization."""

    def test_initial_state(self):
        agent = PostureIQAgent()
        assert agent._client is None
        assert agent._session is None
        assert agent._event_unsubscribe is None

    def test_has_audit_logger(self):
        agent = PostureIQAgent()
        assert agent._audit is not None


class TestPostureIQAgentStartClient:
    """Tests for start_client()."""

    def test_creates_and_starts_client(self):
        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_client.get_state.return_value = "connected"

        with patch("src.agent.main.CopilotClient", return_value=mock_client):
            result = agent.start_client()

        mock_client.start.assert_called_once()
        mock_client.get_state.assert_called_once()
        assert agent._client is mock_client
        assert result is mock_client


class TestPostureIQAgentCreateSession:
    """Tests for create_session()."""

    def test_raises_if_client_not_started(self):
        agent = PostureIQAgent()
        with pytest.raises(RuntimeError, match="CopilotClient not started"):
            agent.create_session()

    def test_creates_session_with_config(self):
        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_session = MagicMock()
        mock_session.on.return_value = MagicMock()  # unsubscribe function
        mock_client.create_session.return_value = mock_session
        agent._client = mock_client

        result = agent.create_session()

        # Verify create_session was called with a config dict
        mock_client.create_session.assert_called_once()
        config_arg = mock_client.create_session.call_args[0][0]

        assert config_arg["tools"] is TOOLS
        assert config_arg["streaming"] is True
        assert config_arg["system_message"]["mode"] == "replace"
        assert config_arg["system_message"]["content"] == SYSTEM_PROMPT

        assert result is mock_session
        assert agent._session is mock_session

    def test_subscribes_to_session_events(self):
        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_session = MagicMock()
        unsub_fn = MagicMock()
        mock_session.on.return_value = unsub_fn
        mock_client.create_session.return_value = mock_session
        agent._client = mock_client

        agent.create_session()

        mock_session.on.assert_called_once_with(agent._handle_session_event)
        assert agent._event_unsubscribe is unsub_fn

    @patch("src.agent.main.settings")
    def test_wires_azure_provider_when_configured(self, mock_settings):
        mock_settings.azure_openai_endpoint = "https://my-openai.openai.azure.com/"
        mock_settings.azure_openai_api_key = "test-key-123"
        mock_settings.azure_openai_api_version = "2024-02-01"
        mock_settings.azure_openai_deployment = "gpt-4o"

        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_session = MagicMock()
        mock_session.on.return_value = MagicMock()
        mock_client.create_session.return_value = mock_session
        agent._client = mock_client

        agent.create_session()

        config_arg = mock_client.create_session.call_args[0][0]
        assert "provider" in config_arg
        assert config_arg["provider"]["type"] == "azure"
        assert config_arg["provider"]["base_url"] == "https://my-openai.openai.azure.com/"
        assert config_arg["provider"]["api_key"] == "test-key-123"
        assert config_arg["provider"]["azure"]["api_version"] == "2024-02-01"
        assert config_arg["model"] == "gpt-4o"

    @patch("src.agent.main.settings")
    def test_no_provider_when_endpoint_not_configured(self, mock_settings):
        mock_settings.azure_openai_endpoint = ""

        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_session = MagicMock()
        mock_session.on.return_value = MagicMock()
        mock_client.create_session.return_value = mock_session
        agent._client = mock_client

        agent.create_session()

        config_arg = mock_client.create_session.call_args[0][0]
        assert "provider" not in config_arg

    @patch("src.agent.main.settings")
    def test_azure_provider_without_api_key_uses_managed_identity(self, mock_settings):
        mock_settings.azure_openai_endpoint = "https://my-openai.openai.azure.com/"
        mock_settings.azure_openai_api_key = ""  # empty → managed identity
        mock_settings.azure_openai_api_version = "2024-02-01"
        mock_settings.azure_openai_deployment = "gpt-4o"

        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_session = MagicMock()
        mock_session.on.return_value = MagicMock()
        mock_client.create_session.return_value = mock_session
        agent._client = mock_client

        agent.create_session()

        config_arg = mock_client.create_session.call_args[0][0]
        assert "provider" in config_arg
        assert "api_key" not in config_arg["provider"]


class TestPostureIQAgentResumeSession:
    """Tests for resume_session()."""

    def test_raises_if_client_not_started(self):
        agent = PostureIQAgent()
        with pytest.raises(RuntimeError, match="CopilotClient not started"):
            agent.resume_session("some-session-id")

    def test_resumes_session_by_id(self):
        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_session = MagicMock()
        mock_session.on.return_value = MagicMock()
        mock_client.resume_session.return_value = mock_session
        agent._client = mock_client

        result = agent.resume_session("session-abc")

        mock_client.resume_session.assert_called_once_with("session-abc")
        assert result is mock_session
        assert agent._session is mock_session

    def test_subscribes_events_on_resume(self):
        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_session = MagicMock()
        unsub_fn = MagicMock()
        mock_session.on.return_value = unsub_fn
        mock_client.resume_session.return_value = mock_session
        agent._client = mock_client

        agent.resume_session("session-abc")

        mock_session.on.assert_called_once_with(agent._handle_session_event)
        assert agent._event_unsubscribe is unsub_fn


class TestPostureIQAgentCloseSession:
    """Tests for close_session()."""

    def test_unsubscribes_and_destroys(self):
        agent = PostureIQAgent()
        unsub_fn = MagicMock()
        mock_session = MagicMock()
        agent._event_unsubscribe = unsub_fn
        agent._session = mock_session

        agent.close_session()

        unsub_fn.assert_called_once()
        mock_session.destroy.assert_called_once()
        assert agent._session is None
        assert agent._event_unsubscribe is None

    def test_noop_when_no_session(self):
        agent = PostureIQAgent()
        agent.close_session()  # should not raise
        assert agent._session is None

    def test_only_unsubscribe_when_no_session(self):
        agent = PostureIQAgent()
        unsub_fn = MagicMock()
        agent._event_unsubscribe = unsub_fn
        agent._session = None

        agent.close_session()

        unsub_fn.assert_called_once()
        assert agent._event_unsubscribe is None


class TestPostureIQAgentStop:
    """Tests for stop()."""

    def test_closes_session_then_stops_client(self):
        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_client.stop.return_value = []
        mock_session = MagicMock()
        unsub_fn = MagicMock()

        agent._client = mock_client
        agent._session = mock_session
        agent._event_unsubscribe = unsub_fn

        agent.stop()

        # Session closed first
        unsub_fn.assert_called_once()
        mock_session.destroy.assert_called_once()
        # Then client stopped
        mock_client.stop.assert_called_once()
        assert agent._client is None
        assert agent._session is None

    def test_noop_when_nothing_active(self):
        agent = PostureIQAgent()
        agent.stop()  # should not raise

    def test_handles_stop_errors(self):
        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_client.stop.return_value = [RuntimeError("cleanup failed")]
        agent._client = mock_client

        agent.stop()  # should log warning, not raise

        mock_client.stop.assert_called_once()
        assert agent._client is None


# ═══════════════════════════════════════════════════════════════════════════
# 4. SEND MESSAGE TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestSendMessage:
    """Tests for send_message()."""

    def test_raises_if_no_session(self):
        agent = PostureIQAgent()
        with pytest.raises(RuntimeError, match="No active session"):
            agent.send_message("hello")

    def test_calls_send_and_wait(self):
        agent = PostureIQAgent()
        mock_session = MagicMock()
        response_event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content="Here is your secure score.",
            message=None,
        )
        mock_session.send_and_wait.return_value = response_event
        agent._session = mock_session

        result = agent.send_message("What is my secure score?")

        mock_session.send_and_wait.assert_called_once_with(
            {"prompt": "What is my secure score?"},
            timeout=120.0,
        )
        assert result == "Here is your secure score."

    def test_returns_none_on_timeout(self):
        agent = PostureIQAgent()
        mock_session = MagicMock()
        mock_session.send_and_wait.return_value = None
        agent._session = mock_session

        result = agent.send_message("hello")

        assert result is None

    def test_falls_back_to_message_field(self):
        agent = PostureIQAgent()
        mock_session = MagicMock()
        response_event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content=None,
            message="Fallback message content",
        )
        mock_session.send_and_wait.return_value = response_event
        agent._session = mock_session

        result = agent.send_message("test")

        assert result == "Fallback message content"

    def test_returns_none_when_no_content(self):
        agent = PostureIQAgent()
        mock_session = MagicMock()
        response_event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content=None,
            message=None,
        )
        mock_session.send_and_wait.return_value = response_event
        agent._session = mock_session

        result = agent.send_message("test")

        assert result is None

    def test_logs_to_audit_trail(self):
        agent = PostureIQAgent()
        mock_session = MagicMock()
        response_event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content="Agent response text",
            message=None,
        )
        mock_session.send_and_wait.return_value = response_event
        agent._session = mock_session

        with patch.object(agent._audit, "log_interaction") as mock_audit:
            agent.send_message("user question")

            mock_audit.assert_called_once_with(
                user_input="user question",
                agent_response="Agent response text",
            )

    def test_audit_logs_no_response_placeholder(self):
        agent = PostureIQAgent()
        mock_session = MagicMock()
        response_event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content=None,
            message=None,
        )
        mock_session.send_and_wait.return_value = response_event
        agent._session = mock_session

        with patch.object(agent._audit, "log_interaction") as mock_audit:
            agent.send_message("user question")

            mock_audit.assert_called_once_with(
                user_input="user question",
                agent_response="[no response]",
            )


class TestSendMessageStreaming:
    """Tests for send_message_streaming()."""

    def test_raises_if_no_session(self):
        agent = PostureIQAgent()
        with pytest.raises(RuntimeError, match="No active session"):
            agent.send_message_streaming("hello")

    def test_calls_session_send(self):
        agent = PostureIQAgent()
        mock_session = MagicMock()
        agent._session = mock_session

        agent.send_message_streaming("stream this")

        mock_session.send.assert_called_once_with({"prompt": "stream this"})


# ═══════════════════════════════════════════════════════════════════════════
# 5. SESSION EVENT HANDLING TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestHandleSessionEvent:
    """Tests for _handle_session_event()."""

    def _agent(self) -> PostureIQAgent:
        agent = PostureIQAgent()
        agent._audit = MagicMock()
        return agent

    def test_message_delta_prints_to_stdout(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE_DELTA,
            delta_content="Hello ",
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        assert captured.out == "Hello "

    def test_message_delta_handles_none_content(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE_DELTA,
            delta_content=None,
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_assistant_message_prints_newline(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content="Full message",
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        assert captured.out == "\n"

    def test_tool_execution_start_prints_status(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.TOOL_EXECUTION_START,
            tool_name="query_secure_score",
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        assert "query_secure_score" in captured.out
        assert "⚙️" in captured.out

    def test_tool_execution_start_handles_none_name(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.TOOL_EXECUTION_START,
            tool_name=None,
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        assert "unknown" in captured.out

    def test_tool_execution_complete_logs_audit(self):
        agent = self._agent()
        mock_result = SimpleNamespace(text_result="score: 47.3")
        event = _make_session_event(
            SessionEventType.TOOL_EXECUTION_COMPLETE,
            tool_name="query_secure_score",
            arguments={"tenant_id": "test"},
            result=mock_result,
        )

        agent._handle_session_event(event)

        agent._audit.log_tool_call.assert_called_once()
        call_kwargs = agent._audit.log_tool_call.call_args
        assert call_kwargs.kwargs["tool_name"] == "query_secure_score"
        assert call_kwargs.kwargs["input_params"] == {"tenant_id": "test"}

    def test_tool_execution_complete_handles_no_result(self):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.TOOL_EXECUTION_COMPLETE,
            tool_name="get_entra_config",
            arguments=None,
            result=None,
        )

        agent._handle_session_event(event)

        agent._audit.log_tool_call.assert_called_once()
        call_kwargs = agent._audit.log_tool_call.call_args
        assert call_kwargs.kwargs["output_summary"] == "[no output]"
        assert call_kwargs.kwargs["input_params"] == {}

    def test_session_error_prints_error(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.SESSION_ERROR,
            message="Something went wrong",
            stack="traceback here",
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        assert "Something went wrong" in captured.out
        assert "❌" in captured.out

    def test_session_error_handles_none_message(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.SESSION_ERROR,
            message=None,
            stack=None,
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        assert "Unknown error" in captured.out

    def test_turn_start_does_not_print_user_facing(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.ASSISTANT_TURN_START,
            turn_id="turn-1",
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        # Should not print user-facing tool status or error messages
        # (structlog debug output may appear but is not user-facing)
        assert "⚙️" not in captured.out
        assert "❌" not in captured.out

    def test_turn_end_does_not_print_user_facing(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.ASSISTANT_TURN_END,
            turn_id="turn-1",
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        assert "⚙️" not in captured.out
        assert "❌" not in captured.out

    def test_reasoning_event_does_not_print_user_facing(self, capsys):
        agent = self._agent()
        event = _make_session_event(
            SessionEventType.ASSISTANT_REASONING,
            content="thinking...",
        )

        agent._handle_session_event(event)

        captured = capsys.readouterr()
        assert "⚙️" not in captured.out
        assert "❌" not in captured.out


# ═══════════════════════════════════════════════════════════════════════════
# 6. _extract_response_text TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractResponseText:
    """Tests for _extract_response_text static method."""

    def test_extracts_content(self):
        event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content="Primary content",
            message="Fallback",
        )
        result = PostureIQAgent._extract_response_text(event)
        assert result == "Primary content"

    def test_falls_back_to_message(self):
        event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content=None,
            message="Fallback content",
        )
        result = PostureIQAgent._extract_response_text(event)
        assert result == "Fallback content"

    def test_returns_none_when_both_empty(self):
        event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content=None,
            message=None,
        )
        result = PostureIQAgent._extract_response_text(event)
        assert result is None

    def test_prefers_content_over_message(self):
        event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content="content wins",
            message="message loses",
        )
        result = PostureIQAgent._extract_response_text(event)
        assert result == "content wins"

    def test_empty_string_content_is_falsy(self):
        event = _make_session_event(
            SessionEventType.ASSISTANT_MESSAGE,
            content="",
            message="fallback",
        )
        result = PostureIQAgent._extract_response_text(event)
        # empty string is falsy → falls through to message
        assert result == "fallback"


# ═══════════════════════════════════════════════════════════════════════════
# 7. SYSTEM PROMPT INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestSystemPromptIntegration:
    """Verify the system prompt is wired correctly into session config."""

    def test_system_prompt_is_non_empty(self):
        assert SYSTEM_PROMPT
        assert len(SYSTEM_PROMPT) > 100

    def test_system_prompt_mentions_all_tools(self):
        for tool in TOOLS:
            assert tool.name in SYSTEM_PROMPT, (
                f"System prompt should mention tool '{tool.name}'"
            )

    def test_system_prompt_includes_guardrails(self):
        assert "read-only" in SYSTEM_PROMPT.lower() or "Read-only" in SYSTEM_PROMPT
        assert "PII" in SYSTEM_PROMPT or "pii" in SYSTEM_PROMPT.lower()

    def test_system_prompt_includes_persona(self):
        assert "PostureIQ" in SYSTEM_PROMPT

    def test_session_config_uses_replace_mode(self):
        """Ensure we replace (not append to) the default system prompt."""
        agent = PostureIQAgent()
        mock_client = MagicMock()
        mock_session = MagicMock()
        mock_session.on.return_value = MagicMock()
        mock_client.create_session.return_value = mock_session
        agent._client = mock_client

        agent.create_session()

        config = mock_client.create_session.call_args[0][0]
        assert config["system_message"]["mode"] == "replace"
        assert config["system_message"]["content"] == SYSTEM_PROMPT
