"""Comprehensive tests for Task 4.1 — Foundry IQ Integration.

Covers:
  - Playbook retrieval with mocked Foundry IQ responses
  - Gap-to-playbook workload area mapping
  - Built-in playbook content validation
  - Offer catalog inclusion / exclusion
  - Onboarding checklist inclusion / exclusion
  - System prompt context injection
  - Tool registration in main.py
  - Edge cases (empty gaps, unknown areas, all areas)
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.tools.foundry_playbook import (
    PLAYBOOK_VERSION,
    WORKLOAD_AREAS,
    _GAP_KEYWORD_MAP,
    _PLAYBOOKS,
    _build_playbook_context,
    _get_built_in_playbooks,
    _identify_workload_areas,
    get_project479_playbook,
)


# ========================================================================
# SECTION 1: Built-in Playbook Content Validation
# ========================================================================


class TestBuiltInPlaybooks:
    """Validate the built-in playbook data structure."""

    def test_all_workload_areas_have_playbooks(self):
        for area in WORKLOAD_AREAS:
            assert area in _PLAYBOOKS, f"Missing playbook for {area}"

    def test_each_playbook_has_title(self):
        for area, pb in _PLAYBOOKS.items():
            assert "title" in pb, f"{area} missing title"
            assert pb["title"], f"{area} has empty title"

    def test_each_playbook_has_remediation_steps(self):
        for area, pb in _PLAYBOOKS.items():
            assert "remediation_playbook" in pb, f"{area} missing remediation_playbook"
            assert len(pb["remediation_playbook"]) >= 3, f"{area} has too few steps"

    def test_each_playbook_has_offer(self):
        for area, pb in _PLAYBOOKS.items():
            offer = pb.get("offer", {})
            assert offer, f"{area} missing offer"
            assert "name" in offer, f"{area} offer missing name"
            assert "id" in offer, f"{area} offer missing id"
            assert offer["id"].startswith("P479-"), f"{area} offer ID not P479 format"
            assert "description" in offer, f"{area} offer missing description"
            assert "duration" in offer, f"{area} offer missing duration"
            assert "delivery" in offer, f"{area} offer missing delivery"

    def test_each_playbook_has_onboarding_checklist(self):
        for area, pb in _PLAYBOOKS.items():
            checklist = pb.get("onboarding_checklist", [])
            assert len(checklist) >= 2, f"{area} has too few checklist items"

    def test_each_playbook_has_estimated_effort(self):
        for area, pb in _PLAYBOOKS.items():
            assert "estimated_effort" in pb, f"{area} missing estimated_effort"

    def test_each_playbook_has_impact_on_score(self):
        for area, pb in _PLAYBOOKS.items():
            assert "impact_on_score" in pb, f"{area} missing impact_on_score"
            assert pb["impact_on_score"] > 0, f"{area} has non-positive impact"

    def test_playbook_version_format(self):
        assert PLAYBOOK_VERSION
        assert "." in PLAYBOOK_VERSION  # e.g. "2026.2"

    def test_total_playbook_count(self):
        assert len(_PLAYBOOKS) == 12  # 4 Defender + 4 Purview + 4 Entra

    def test_workload_areas_matches_playbooks(self):
        assert set(WORKLOAD_AREAS) == set(_PLAYBOOKS.keys())


# ========================================================================
# SECTION 2: Gap-to-Workload Area Mapping
# ========================================================================


class TestGapMapping:
    """Test _identify_workload_areas gap keyword mapping."""

    def test_endpoint_gap(self):
        areas = _identify_workload_areas(["Device onboarding not configured"])
        assert "defender_endpoint" in areas

    def test_safe_links_gap(self):
        areas = _identify_workload_areas(["Safe Links policy not enabled"])
        assert "defender_office365" in areas

    def test_dlp_gap(self):
        areas = _identify_workload_areas(["No DLP policies configured"])
        assert "purview_dlp" in areas

    def test_mfa_gap(self):
        areas = _identify_workload_areas(["MFA not enforced for all users"])
        assert "entra_conditional_access" in areas

    def test_pim_gap(self):
        areas = _identify_workload_areas(["Permanent privileged assignments found"])
        assert "entra_pim" in areas

    def test_multiple_gaps_map_to_multiple_areas(self):
        gaps = [
            "Safe Links not enabled",
            "No DLP policies",
            "PIM not configured",
            "No access review scheduled",
        ]
        areas = _identify_workload_areas(gaps)
        assert "defender_office365" in areas
        assert "purview_dlp" in areas
        assert "entra_pim" in areas
        assert "entra_access_reviews" in areas

    def test_dedup_areas(self):
        gaps = [
            "Safe Links disabled",
            "Safe Attachments disabled",  # both map to defender_office365
        ]
        areas = _identify_workload_areas(gaps)
        assert areas.count("defender_office365") == 1

    def test_no_matching_gaps(self):
        areas = _identify_workload_areas(["Something completely unrelated"])
        assert areas == []

    def test_empty_gaps(self):
        areas = _identify_workload_areas([])
        assert areas == []

    def test_case_insensitive(self):
        areas = _identify_workload_areas(["SAFE LINKS not enabled"])
        assert "defender_office365" in areas

    def test_identity_protection_gap(self):
        areas = _identify_workload_areas(["Identity Protection risk policies missing"])
        assert "entra_identity_protection" in areas

    def test_insider_risk_gap(self):
        areas = _identify_workload_areas(["Insider Risk Management not enabled"])
        assert "purview_insider_risk" in areas

    def test_retention_gap(self):
        areas = _identify_workload_areas(["No retention policies configured"])
        assert "purview_retention" in areas

    def test_cloud_apps_gap(self):
        areas = _identify_workload_areas(["Shadow IT not monitored, Cloud Discovery disabled"])
        assert "defender_cloud_apps" in areas

    def test_domain_controller_gap(self):
        areas = _identify_workload_areas(["Domain controller sensors missing"])
        assert "defender_identity" in areas

    def test_sensitivity_label_gap(self):
        areas = _identify_workload_areas(["Sensitivity labels not published"])
        assert "purview_labels" in areas

    def test_gap_keyword_map_covers_all_areas(self):
        """Every workload area should be reachable via at least one keyword."""
        covered = set(_GAP_KEYWORD_MAP.values())
        for area in WORKLOAD_AREAS:
            assert area in covered, f"No keyword maps to {area}"


# ========================================================================
# SECTION 3: _get_built_in_playbooks
# ========================================================================


class TestGetBuiltInPlaybooks:
    """Test the built-in playbook retrieval helper."""

    def test_specific_areas(self):
        result = _get_built_in_playbooks(["defender_endpoint", "purview_dlp"])
        assert len(result) == 2
        assert "defender_endpoint" in result
        assert "purview_dlp" in result

    def test_empty_areas_returns_all(self):
        result = _get_built_in_playbooks([])
        assert len(result) == len(_PLAYBOOKS)

    def test_unknown_area_ignored(self):
        result = _get_built_in_playbooks(["nonexistent_workload"])
        assert len(result) == 0

    def test_mixed_valid_invalid(self):
        result = _get_built_in_playbooks(["defender_endpoint", "fake_area"])
        assert len(result) == 1
        assert "defender_endpoint" in result


# ========================================================================
# SECTION 4: _build_playbook_context
# ========================================================================


class TestBuildPlaybookContext:
    """Test LLM context summary generation."""

    def test_context_contains_titles(self):
        playbooks = _get_built_in_playbooks(["defender_endpoint"])
        ctx = _build_playbook_context(playbooks)
        assert "Defender for Endpoint" in ctx

    def test_context_contains_remediation_steps(self):
        playbooks = _get_built_in_playbooks(["defender_endpoint"])
        ctx = _build_playbook_context(playbooks)
        assert "Enable Defender for Endpoint" in ctx

    def test_context_contains_offer(self):
        playbooks = _get_built_in_playbooks(["defender_endpoint"])
        ctx = _build_playbook_context(playbooks)
        assert "P479-DEF-001" in ctx

    def test_context_contains_checklist(self):
        playbooks = _get_built_in_playbooks(["defender_endpoint"])
        ctx = _build_playbook_context(playbooks)
        assert "☐" in ctx

    def test_context_contains_effort_and_impact(self):
        playbooks = _get_built_in_playbooks(["defender_endpoint"])
        ctx = _build_playbook_context(playbooks)
        assert "Score Impact" in ctx

    def test_multiple_playbooks_separated(self):
        playbooks = _get_built_in_playbooks(["defender_endpoint", "purview_dlp"])
        ctx = _build_playbook_context(playbooks)
        assert "---" in ctx  # separator
        assert "Defender for Endpoint" in ctx
        assert "Purview DLP" in ctx


# ========================================================================
# SECTION 5: get_project479_playbook Tool — Gap-based
# ========================================================================


class TestGetPlaybookByGaps:
    """Test the public tool function with gaps-based lookup."""

    @pytest.mark.asyncio
    async def test_gap_based_lookup(self):
        result = await get_project479_playbook(
            gaps=["MFA not enforced", "No DLP policies configured"]
        )
        assert result["matched_count"] >= 2
        assert "entra_conditional_access" in result["matched_areas"]
        assert "purview_dlp" in result["matched_areas"]

    @pytest.mark.asyncio
    async def test_result_has_playbook_version(self):
        result = await get_project479_playbook(gaps=["MFA not enforced"])
        assert result["playbook_version"] == PLAYBOOK_VERSION

    @pytest.mark.asyncio
    async def test_result_has_source(self):
        result = await get_project479_playbook(gaps=["MFA not enforced"])
        assert result["source"] == "built_in"

    @pytest.mark.asyncio
    async def test_result_has_context_summary(self):
        result = await get_project479_playbook(gaps=["MFA not enforced"])
        assert result["context_summary"]
        assert "Conditional Access" in result["context_summary"]

    @pytest.mark.asyncio
    async def test_result_has_recommended_offers(self):
        result = await get_project479_playbook(
            gaps=["MFA not enforced", "Safe Links disabled"]
        )
        assert len(result["recommended_offers"]) >= 2
        assert all(o.startswith("P479-") for o in result["recommended_offers"])

    @pytest.mark.asyncio
    async def test_result_has_timestamp(self):
        result = await get_project479_playbook(gaps=["MFA not enforced"])
        assert "timestamp" in result
        assert "T" in result["timestamp"]

    @pytest.mark.asyncio
    async def test_result_has_total_areas(self):
        result = await get_project479_playbook(gaps=["MFA not enforced"])
        assert result["total_areas"] == 12

    @pytest.mark.asyncio
    async def test_result_has_total_score_impact(self):
        result = await get_project479_playbook(gaps=["MFA not enforced"])
        assert result["total_estimated_score_impact"] > 0


# ========================================================================
# SECTION 6: get_project479_playbook Tool — Area-based
# ========================================================================


class TestGetPlaybookByAreas:
    """Test the public tool function with explicit workload areas."""

    @pytest.mark.asyncio
    async def test_explicit_areas(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint", "entra_pim"]
        )
        assert result["matched_count"] == 2
        assert "defender_endpoint" in result["matched_areas"]
        assert "entra_pim" in result["matched_areas"]

    @pytest.mark.asyncio
    async def test_areas_take_precedence_over_gaps(self):
        result = await get_project479_playbook(
            gaps=["MFA not enforced"],
            workload_areas=["defender_endpoint"],
        )
        # Areas should win — only defender_endpoint
        assert result["matched_areas"] == ["defender_endpoint"]

    @pytest.mark.asyncio
    async def test_invalid_areas_filtered(self):
        result = await get_project479_playbook(
            workload_areas=["fake_area", "defender_endpoint"]
        )
        assert result["matched_areas"] == ["defender_endpoint"]

    @pytest.mark.asyncio
    async def test_all_invalid_areas(self):
        result = await get_project479_playbook(workload_areas=["fake1", "fake2"])
        # All invalid areas are filtered out → empty valid list → falls back to all
        # Actually, valid_areas=[] then resolved_areas=[] → _get_built_in_playbooks([]) → all
        # This is intentional: unknown areas should not crash.
        assert result["matched_count"] == 12


# ========================================================================
# SECTION 7: get_project479_playbook — No Args (All Playbooks)
# ========================================================================


class TestGetPlaybookAll:
    """Test retrieving all playbooks when no filters are provided."""

    @pytest.mark.asyncio
    async def test_no_args_returns_all(self):
        result = await get_project479_playbook()
        assert result["matched_count"] == 12
        assert len(result["playbooks"]) == 12

    @pytest.mark.asyncio
    async def test_all_areas_present(self):
        result = await get_project479_playbook()
        for area in WORKLOAD_AREAS:
            assert area in result["playbooks"]


# ========================================================================
# SECTION 8: Offer / Checklist Inclusion Flags
# ========================================================================


class TestOfferChecklistFlags:
    """Test include_offers and include_checklists toggles."""

    @pytest.mark.asyncio
    async def test_exclude_offers(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"],
            include_offers=False,
        )
        pb = result["playbooks"]["defender_endpoint"]
        assert pb.get("offer") is None

    @pytest.mark.asyncio
    async def test_exclude_checklists(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"],
            include_checklists=False,
        )
        pb = result["playbooks"]["defender_endpoint"]
        assert pb.get("onboarding_checklist") is None

    @pytest.mark.asyncio
    async def test_exclude_both(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"],
            include_offers=False,
            include_checklists=False,
        )
        pb = result["playbooks"]["defender_endpoint"]
        assert pb.get("offer") is None
        assert pb.get("onboarding_checklist") is None
        # Remediation steps still present
        assert len(pb["remediation_steps"]) > 0

    @pytest.mark.asyncio
    async def test_include_both_default(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"],
        )
        pb = result["playbooks"]["defender_endpoint"]
        assert pb["offer"] is not None
        assert pb["onboarding_checklist"] is not None


# ========================================================================
# SECTION 9: Playbook Response Structure
# ========================================================================


class TestPlaybookResponseStructure:
    """Validate the shape of individual playbook entries in the response."""

    @pytest.mark.asyncio
    async def test_playbook_entry_fields(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"]
        )
        pb = result["playbooks"]["defender_endpoint"]
        assert "title" in pb
        assert "remediation_steps" in pb
        assert "offer" in pb
        assert "onboarding_checklist" in pb
        assert "estimated_effort" in pb
        assert "impact_on_score" in pb

    @pytest.mark.asyncio
    async def test_remediation_steps_are_list(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"]
        )
        pb = result["playbooks"]["defender_endpoint"]
        assert isinstance(pb["remediation_steps"], list)
        assert len(pb["remediation_steps"]) >= 3

    @pytest.mark.asyncio
    async def test_offer_has_required_fields(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"]
        )
        offer = result["playbooks"]["defender_endpoint"]["offer"]
        assert "name" in offer
        assert "id" in offer
        assert "description" in offer


# ========================================================================
# SECTION 10: Foundry IQ Client Fallback
# ========================================================================


class TestFoundryIQFallback:
    """Test fallback to built-in playbooks when Foundry IQ is unavailable."""

    @pytest.mark.asyncio
    async def test_default_uses_builtin(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"]
        )
        assert result["source"] == "built_in"

    @pytest.mark.asyncio
    @patch("src.tools.foundry_playbook._create_foundry_client")
    async def test_no_client_uses_builtin(self, mock_client):
        mock_client.return_value = None
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"]
        )
        assert result["source"] == "built_in"
        assert result["matched_count"] == 1

    @pytest.mark.asyncio
    @patch("src.tools.foundry_playbook._fetch_from_foundry")
    @patch("src.tools.foundry_playbook._create_foundry_client")
    async def test_fetch_failure_falls_back(self, mock_client, mock_fetch):
        mock_client.return_value = {"endpoint": "https://foundry.example.com"}
        mock_fetch.return_value = None  # API failed
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"]
        )
        assert result["source"] == "built_in"

    @pytest.mark.asyncio
    @patch("src.tools.foundry_playbook._fetch_from_foundry")
    @patch("src.tools.foundry_playbook._create_foundry_client")
    async def test_successful_foundry_fetch(self, mock_client, mock_fetch):
        mock_client.return_value = {"endpoint": "https://foundry.example.com"}
        mock_fetch.return_value = {
            "defender_endpoint": {
                "title": "Remote Playbook",
                "remediation_playbook": ["Step 1", "Step 2", "Step 3"],
                "offer": {
                    "name": "Remote Offer",
                    "id": "P479-REMOTE-001",
                    "description": "Remote offer desc",
                    "duration": "1 day",
                    "delivery": "Remote",
                },
                "onboarding_checklist": ["☐ Item 1", "☐ Item 2"],
                "estimated_effort": "1 day",
                "impact_on_score": 10.0,
            }
        }
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"]
        )
        assert result["source"] == "foundry_iq"
        assert result["playbooks"]["defender_endpoint"]["title"] == "Remote Playbook"


# ========================================================================
# SECTION 11: System Prompt Context Injection
# ========================================================================


class TestSystemPromptInjection:
    """Verify the system prompt references the Foundry IQ tool."""

    def test_system_prompt_mentions_playbook_tool(self):
        from src.agent.system_prompt import SYSTEM_PROMPT

        assert "get_project479_playbook" in SYSTEM_PROMPT

    def test_system_prompt_mentions_foundry_iq(self):
        from src.agent.system_prompt import SYSTEM_PROMPT

        assert "Foundry IQ" in SYSTEM_PROMPT

    def test_system_prompt_mentions_project_479(self):
        from src.agent.system_prompt import SYSTEM_PROMPT

        assert "Project 479" in SYSTEM_PROMPT

    def test_system_prompt_mentions_offers(self):
        from src.agent.system_prompt import SYSTEM_PROMPT

        assert "offer" in SYSTEM_PROMPT.lower()

    def test_system_prompt_mentions_onboarding(self):
        from src.agent.system_prompt import SYSTEM_PROMPT

        assert "onboarding" in SYSTEM_PROMPT.lower()


# ========================================================================
# SECTION 12: Tool Registration
# ========================================================================


class TestToolRegistration:
    """Verify the tool is registered in main.py TOOLS list."""

    def test_foundry_tool_in_registry(self):
        from src.agent.main import TOOLS

        tool_names = [t.name for t in TOOLS]
        assert "get_project479_playbook" in tool_names

    def test_foundry_tool_has_handler(self):
        from src.agent.main import TOOLS

        tool = next(t for t in TOOLS if t.name == "get_project479_playbook")
        assert tool.handler is not None

    def test_foundry_tool_has_parameters(self):
        from src.agent.main import TOOLS

        tool = next(t for t in TOOLS if t.name == "get_project479_playbook")
        props = tool.parameters["properties"]
        assert "gaps" in props
        assert "workload_areas" in props

    def test_total_tool_count(self):
        from src.agent.main import TOOLS

        assert len(TOOLS) == 7  # 6 original + 1 new


# ========================================================================
# SECTION 13: Edge Cases
# ========================================================================


class TestEdgeCases:
    """Edge cases for the playbook tool."""

    @pytest.mark.asyncio
    async def test_empty_gaps_list(self):
        result = await get_project479_playbook(gaps=[])
        # Empty gaps → all playbooks
        assert result["matched_count"] == 12

    @pytest.mark.asyncio
    async def test_none_gaps(self):
        result = await get_project479_playbook(gaps=None)
        assert result["matched_count"] == 12

    @pytest.mark.asyncio
    async def test_empty_workload_areas(self):
        result = await get_project479_playbook(workload_areas=[])
        # Empty areas → all playbooks
        assert result["matched_count"] == 12

    @pytest.mark.asyncio
    async def test_single_area(self):
        result = await get_project479_playbook(
            workload_areas=["entra_pim"]
        )
        assert result["matched_count"] == 1
        assert "entra_pim" in result["matched_areas"]

    @pytest.mark.asyncio
    async def test_result_is_json_serializable(self):
        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"]
        )
        # Should not raise
        serialized = json.dumps(result, default=str)
        assert serialized
