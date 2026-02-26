"""Tests for src/api/chat — chat endpoint and intent classification."""

from __future__ import annotations

import pytest

from src.api.chat import ChatRequest, ChatResponse, _classify_intent, handle_chat

# ── Intent Classification ─────────────────────────────────────────────────


class TestClassifyIntent:
    """Test keyword-based intent classification."""

    def test_full_assessment_triggers_all_tools(self):
        tools = _classify_intent("Assess this tenant's ME5 security posture")
        assert "query_secure_score" in tools
        assert "assess_defender_coverage" in tools
        assert "check_purview_policies" in tools
        assert "get_entra_config" in tools
        assert len(tools) == 4

    def test_secure_score_intent(self):
        tools = _classify_intent("What is the current Secure Score?")
        assert tools == ["query_secure_score"]

    def test_defender_intent(self):
        tools = _classify_intent("Check Defender coverage")
        assert tools == ["assess_defender_coverage"]

    def test_purview_intent(self):
        tools = _classify_intent("Review DLP policies")
        assert tools == ["check_purview_policies"]

    def test_entra_intent(self):
        tools = _classify_intent("Check conditional access policies")
        assert tools == ["get_entra_config"]

    def test_remediation_intent(self):
        tools = _classify_intent("Generate a remediation plan")
        assert tools == ["generate_remediation_plan"]

    def test_scorecard_intent(self):
        tools = _classify_intent("Create an adoption scorecard")
        assert "create_adoption_scorecard" in tools

    def test_no_match_returns_empty(self):
        tools = _classify_intent("Hello, how are you?")
        assert tools == []

    def test_case_insensitive(self):
        tools = _classify_intent("WHAT IS THE SECURE SCORE?")
        assert tools == ["query_secure_score"]

    def test_multiple_intents(self):
        tools = _classify_intent("Check the secure score and defender coverage")
        assert "query_secure_score" in tools
        assert "assess_defender_coverage" in tools

    def test_full_posture_variant(self):
        tools = _classify_intent("Run a full posture check")
        assert len(tools) == 4

    def test_get_to_green_maps_to_remediation(self):
        tools = _classify_intent("Help me get-to-green")
        assert "generate_remediation_plan" in tools

    def test_mfa_maps_to_entra(self):
        tools = _classify_intent("Is MFA enabled?")
        assert "get_entra_config" in tools

    def test_sensitivity_label_maps_to_purview(self):
        tools = _classify_intent("Are sensitivity labels configured?")
        assert "check_purview_policies" in tools

    def test_pim_maps_to_entra(self):
        tools = _classify_intent("Review PIM configuration")
        assert "get_entra_config" in tools

    def test_retention_maps_to_purview(self):
        tools = _classify_intent("Check retention policies")
        assert "check_purview_policies" in tools

    def test_dashboard_maps_to_scorecard(self):
        tools = _classify_intent("Show me the dashboard")
        assert "create_adoption_scorecard" in tools

    def test_endpoint_maps_to_defender(self):
        tools = _classify_intent("How many endpoints are onboarded?")
        assert "assess_defender_coverage" in tools


# ── Chat Handler ──────────────────────────────────────────────────────────


class TestHandleChat:
    """Test the full chat handler flow."""

    @pytest.mark.asyncio
    async def test_no_intent_returns_help(self):
        req = ChatRequest(message="Hello!")
        resp = await handle_chat(req)
        assert isinstance(resp, ChatResponse)
        assert resp.tools_called == []
        assert "Secure Score" in resp.response
        assert resp.session_id  # should be assigned

    @pytest.mark.asyncio
    async def test_session_id_assigned_on_first_message(self):
        req = ChatRequest(message="Hi there")
        resp = await handle_chat(req)
        assert resp.session_id
        assert len(resp.session_id) > 0

    @pytest.mark.asyncio
    async def test_session_id_reused(self):
        req1 = ChatRequest(message="Hi")
        resp1 = await handle_chat(req1)
        sid = resp1.session_id

        req2 = ChatRequest(message="What is the secure score?", session_id=sid)
        resp2 = await handle_chat(req2)
        assert resp2.session_id == sid

    @pytest.mark.asyncio
    async def test_secure_score_intent_detected(self):
        req = ChatRequest(message="What is the current Secure Score?")
        resp = await handle_chat(req)
        # Tool may error in test env (no Graph API), but response still generated
        assert isinstance(resp, ChatResponse)
        assert len(resp.response) > 0

    @pytest.mark.asyncio
    async def test_defender_tool_called(self):
        req = ChatRequest(message="Check Defender coverage")
        resp = await handle_chat(req)
        assert "assess_defender_coverage" in resp.tools_called

    @pytest.mark.asyncio
    async def test_full_assessment_runs(self):
        req = ChatRequest(message="Assess this tenant's security posture")
        resp = await handle_chat(req)
        # In test env, some tools may error (no Graph API creds)
        # but the handler should still return a response
        assert isinstance(resp, ChatResponse)
        assert len(resp.response) > 0

    @pytest.mark.asyncio
    async def test_response_contains_tool_results(self):
        req = ChatRequest(message="What is the Secure Score?")
        resp = await handle_chat(req)
        # Should contain formatted output (not empty)
        assert len(resp.response) > 50

    @pytest.mark.asyncio
    async def test_chat_response_model(self):
        req = ChatRequest(message="Hello")
        resp = await handle_chat(req)
        assert hasattr(resp, "response")
        assert hasattr(resp, "session_id")
        assert hasattr(resp, "tools_called")
        assert isinstance(resp.tools_called, list)


# ── ChatRequest Model ────────────────────────────────────────────────────


class TestChatRequest:
    """Test request model validation."""

    def test_valid_request(self):
        req = ChatRequest(message="Hello")
        assert req.message == "Hello"
        assert req.session_id is None

    def test_with_session_id(self):
        req = ChatRequest(message="Hello", session_id="abc-123")
        assert req.session_id == "abc-123"

    def test_message_required(self):
        with pytest.raises((TypeError, ValueError)):
            ChatRequest()
