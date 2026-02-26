"""Comprehensive tests for the check_purview_policies tool.

Covers:
  - Classification / parsing helpers (_is_purview_related, _classify_component)
  - Gap detection (_is_gap, _gap_description, _is_critical)
  - Component result building (_build_component_result)
  - Aggregation (_aggregate_components, _compute_overall, _collect_critical_gaps)
  - Mock fallback path (no Graph credentials)
  - Graph API integration path (mocked SDK responses)
  - Error handling and edge cases
  - Trace span creation via @trace_tool_call decorator
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ═══════════════════════════════════════════════════════════════════════
# Helpers — build fake Graph SDK objects
# ═══════════════════════════════════════════════════════════════════════

def _make_state_update(state: str = "Default") -> SimpleNamespace:
    return SimpleNamespace(
        state=state,
        assigned_to="",
        comment="",
        updated_by="",
        updated_date_time=None,
    )


def _make_profile(
    *,
    id: str = "ctrl-1",
    title: str = "Enable DLP policies",
    service: str = "Information Protection",
    control_category: str = "",
    max_score: float = 10.0,
    tier: str = "Tier1",
    deprecated: bool = False,
    control_state_updates: list | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=id,
        title=title,
        service=service,
        control_category=control_category,
        max_score=max_score,
        tier=tier,
        deprecated=deprecated,
        control_state_updates=control_state_updates,
    )


def _resolved_profile(**kwargs) -> SimpleNamespace:
    kwargs.setdefault("control_state_updates", [_make_state_update("Resolved")])
    return _make_profile(**kwargs)


def _gap_profile(**kwargs) -> SimpleNamespace:
    kwargs.setdefault("control_state_updates", [_make_state_update("Default")])
    return _make_profile(**kwargs)


def _build_graph_response(profiles: list[SimpleNamespace]) -> SimpleNamespace:
    return SimpleNamespace(value=profiles, odata_next_link=None)


# ═══════════════════════════════════════════════════════════════════════
# 1. _is_purview_related
# ═══════════════════════════════════════════════════════════════════════

class TestIsPurviewRelated:
    """Tests for the _is_purview_related helper."""

    def test_service_information_protection(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="Information Protection")
        assert _is_purview_related(p) is True

    def test_service_purview(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="Microsoft Purview")
        assert _is_purview_related(p) is True

    def test_service_compliance(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="Compliance Center")
        assert _is_purview_related(p) is True

    def test_service_dlp(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="DLP")
        assert _is_purview_related(p) is True

    def test_service_data_loss_prevention(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="Data Loss Prevention Center")
        assert _is_purview_related(p) is True

    def test_service_insider_risk(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="Insider Risk Management")
        assert _is_purview_related(p) is True

    def test_service_retention(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="Retention Policies")
        assert _is_purview_related(p) is True

    def test_service_sensitivity(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="Sensitivity Labels Service")
        assert _is_purview_related(p) is True

    def test_control_category_match(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="SomeService", control_category="Information Protection")
        assert _is_purview_related(p) is True

    def test_title_match(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="SomeService", title="Enable DLP for Exchange")
        assert _is_purview_related(p) is True

    def test_unrelated_service(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="MDE", title="Some unrelated control")
        assert _is_purview_related(p) is False

    def test_empty_fields(self):
        from src.tools.purview_policies import _is_purview_related
        p = SimpleNamespace(service="", control_category="", title="")
        assert _is_purview_related(p) is False

    def test_none_attrs(self):
        from src.tools.purview_policies import _is_purview_related
        p = SimpleNamespace(service=None, control_category=None, title=None)
        assert _is_purview_related(p) is False

    def test_case_insensitive(self):
        from src.tools.purview_policies import _is_purview_related
        p = _make_profile(service="INFORMATION PROTECTION")
        assert _is_purview_related(p) is True


# ═══════════════════════════════════════════════════════════════════════
# 2. _classify_component
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyComponent:
    """Tests for _classify_component."""

    def test_dlp_by_title(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(title="Enable DLP policies everywhere")
        assert _classify_component(p) == "DLP Policies"

    def test_dlp_by_service(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(service="Data Loss Prevention")
        assert _classify_component(p) == "DLP Policies"

    def test_sensitivity_labels(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(title="Configure sensitivity label auto-labeling")
        assert _classify_component(p) == "Sensitivity Labels"

    def test_information_protection_label(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(title="Use information protection labels")
        assert _classify_component(p) == "Sensitivity Labels"

    def test_labeling_keyword(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(title="Mandatory labeling for documents")
        assert _classify_component(p) == "Sensitivity Labels"

    def test_retention(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(title="Enforce data retention across workloads")
        assert _classify_component(p) == "Retention Policies"

    def test_insider_risk(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(title="Enable insider risk policies")
        assert _classify_component(p) == "Insider Risk Management"

    def test_insider_threat(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(title="Detect insider threat activities")
        assert _classify_component(p) == "Insider Risk Management"

    def test_default_bucket_is_dlp(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(title="Generic compliance control", service="Compliance")
        assert _classify_component(p) == "DLP Policies"

    def test_control_category_matters(self):
        from src.tools.purview_policies import _classify_component
        p = _make_profile(title="Some control", control_category="Retention")
        assert _classify_component(p) == "Retention Policies"


# ═══════════════════════════════════════════════════════════════════════
# 3. _compute_status
# ═══════════════════════════════════════════════════════════════════════

class TestPurviewComputeStatus:
    def test_green_at_70(self):
        from src.tools.purview_policies import _compute_status
        assert _compute_status(70.0) == "green"

    def test_green_above(self):
        from src.tools.purview_policies import _compute_status
        assert _compute_status(100.0) == "green"

    def test_yellow_at_40(self):
        from src.tools.purview_policies import _compute_status
        assert _compute_status(40.0) == "yellow"

    def test_yellow_between(self):
        from src.tools.purview_policies import _compute_status
        assert _compute_status(55.0) == "yellow"

    def test_red_below_40(self):
        from src.tools.purview_policies import _compute_status
        assert _compute_status(39.9) == "red"

    def test_red_at_zero(self):
        from src.tools.purview_policies import _compute_status
        assert _compute_status(0.0) == "red"


# ═══════════════════════════════════════════════════════════════════════
# 4. _is_gap
# ═══════════════════════════════════════════════════════════════════════

class TestPurviewIsGap:
    def test_no_state_updates(self):
        from src.tools.purview_policies import _is_gap
        p = _make_profile(control_state_updates=None)
        assert _is_gap(p) is True

    def test_empty_state_updates(self):
        from src.tools.purview_policies import _is_gap
        p = _make_profile(control_state_updates=[])
        assert _is_gap(p) is True

    def test_default_state(self):
        from src.tools.purview_policies import _is_gap
        p = _gap_profile()
        assert _is_gap(p) is True

    def test_resolved_not_gap(self):
        from src.tools.purview_policies import _is_gap
        p = _resolved_profile()
        assert _is_gap(p) is False

    def test_thirdparty_not_gap(self):
        from src.tools.purview_policies import _is_gap
        p = _make_profile(control_state_updates=[_make_state_update("ThirdParty")])
        assert _is_gap(p) is False

    def test_deprecated_not_gap(self):
        from src.tools.purview_policies import _is_gap
        p = _make_profile(deprecated=True, control_state_updates=None)
        assert _is_gap(p) is False

    def test_latest_state_wins(self):
        from src.tools.purview_policies import _is_gap
        p = _make_profile(control_state_updates=[
            _make_state_update("Default"),
            _make_state_update("Resolved"),
        ])
        assert _is_gap(p) is False


# ═══════════════════════════════════════════════════════════════════════
# 5. _gap_description
# ═══════════════════════════════════════════════════════════════════════

class TestPurviewGapDescription:
    def test_basic(self):
        from src.tools.purview_policies import _gap_description
        p = _make_profile(title="Enable DLP", tier="Tier1")
        desc = _gap_description(p)
        assert "Enable DLP" in desc
        assert "Tier1" in desc

    def test_no_tier(self):
        from src.tools.purview_policies import _gap_description
        p = _make_profile(title="Some control", tier=None)
        desc = _gap_description(p)
        assert "Some control" in desc

    def test_fallback_to_id(self):
        from src.tools.purview_policies import _gap_description
        p = SimpleNamespace(id="ctrl-42", tier="Tier2")
        desc = _gap_description(p)
        assert "ctrl-42" in desc


# ═══════════════════════════════════════════════════════════════════════
# 6. _is_critical
# ═══════════════════════════════════════════════════════════════════════

class TestPurviewIsCritical:
    def test_tier1_is_critical(self):
        from src.tools.purview_policies import _is_critical
        p = _make_profile(tier="Tier1", max_score=1.0)
        assert _is_critical(p) is True

    def test_mandatory_tier(self):
        from src.tools.purview_policies import _is_critical
        p = _make_profile(tier="MandatoryTier", max_score=1.0)
        assert _is_critical(p) is True

    def test_high_max_score(self):
        from src.tools.purview_policies import _is_critical
        p = _make_profile(tier="Tier3", max_score=5.0)
        assert _is_critical(p) is True

    def test_low_tier_low_score(self):
        from src.tools.purview_policies import _is_critical
        p = _make_profile(tier="Tier3", max_score=2.0)
        assert _is_critical(p) is False

    def test_none_tier_low_score(self):
        from src.tools.purview_policies import _is_critical
        p = _make_profile(tier=None, max_score=1.0)
        assert _is_critical(p) is False


# ═══════════════════════════════════════════════════════════════════════
# 7. _build_component_result
# ═══════════════════════════════════════════════════════════════════════

class TestBuildComponentResult:
    def test_empty_list(self):
        from src.tools.purview_policies import _build_component_result
        r = _build_component_result([])
        assert r["status"] == "red"
        assert r["details"]["total_controls"] == 0
        assert r["gaps"] == []

    def test_all_resolved(self):
        from src.tools.purview_policies import _build_component_result
        profiles = [
            _resolved_profile(max_score=10.0),
            _resolved_profile(max_score=5.0),
        ]
        r = _build_component_result(profiles)
        assert r["status"] == "green"
        assert r["details"]["achieved_controls"] == 2
        assert r["details"]["achieved_score"] == 15.0
        assert r["gaps"] == []

    def test_all_gaps(self):
        from src.tools.purview_policies import _build_component_result
        profiles = [
            _gap_profile(title="Gap A", max_score=10.0),
            _gap_profile(title="Gap B", max_score=5.0),
        ]
        r = _build_component_result(profiles)
        assert r["status"] == "red"
        assert r["details"]["achieved_controls"] == 0
        assert r["details"]["achieved_score"] == 0.0
        assert len(r["gaps"]) == 2

    def test_mixed(self):
        from src.tools.purview_policies import _build_component_result
        profiles = [
            _resolved_profile(max_score=10.0),
            _gap_profile(title="Gap", max_score=10.0),
        ]
        r = _build_component_result(profiles)
        assert r["status"] == "yellow"  # 50% → yellow
        assert r["details"]["achieved_controls"] == 1
        assert len(r["gaps"]) == 1

    def test_zero_max_score(self):
        from src.tools.purview_policies import _build_component_result
        profiles = [_resolved_profile(max_score=0.0)]
        r = _build_component_result(profiles)
        assert r["details"]["max_score"] == 0.0


# ═══════════════════════════════════════════════════════════════════════
# 8. _aggregate_components
# ═══════════════════════════════════════════════════════════════════════

class TestAggregateComponents:
    def test_profiles_sorted_into_components(self):
        from src.tools.purview_policies import _aggregate_components, ALL_COMPONENTS
        profiles = [
            _gap_profile(title="Enable DLP on Teams", service="DLP"),
            _gap_profile(title="Enforce sensitivity label", service="Information Protection"),
            _gap_profile(title="Retention policy for Exchange", service="Compliance"),
            _gap_profile(title="Monitor insider risk", service="Insider Risk"),
        ]
        result = _aggregate_components(profiles)
        assert set(result.keys()) == set(ALL_COMPONENTS)
        assert result["DLP Policies"]["details"]["total_controls"] >= 1
        assert result["Sensitivity Labels"]["details"]["total_controls"] >= 1
        assert result["Retention Policies"]["details"]["total_controls"] >= 1
        assert result["Insider Risk Management"]["details"]["total_controls"] >= 1

    def test_all_components_present_even_empty(self):
        from src.tools.purview_policies import _aggregate_components, ALL_COMPONENTS
        profiles = [_gap_profile(title="DLP stuff", service="DLP")]
        result = _aggregate_components(profiles)
        assert set(result.keys()) == set(ALL_COMPONENTS)
        assert result["Insider Risk Management"]["details"]["total_controls"] == 0

    def test_empty_profiles(self):
        from src.tools.purview_policies import _aggregate_components, ALL_COMPONENTS
        result = _aggregate_components([])
        assert set(result.keys()) == set(ALL_COMPONENTS)
        for comp in result.values():
            assert comp["details"]["total_controls"] == 0


# ═══════════════════════════════════════════════════════════════════════
# 9. _compute_overall
# ═══════════════════════════════════════════════════════════════════════

class TestComputeOverall:
    def test_all_achieved(self):
        from src.tools.purview_policies import _compute_overall
        components = {
            "A": {"details": {"max_score": 10.0, "achieved_score": 10.0}},
            "B": {"details": {"max_score": 10.0, "achieved_score": 10.0}},
        }
        assert _compute_overall(components) == 100.0

    def test_none_achieved(self):
        from src.tools.purview_policies import _compute_overall
        components = {
            "A": {"details": {"max_score": 10.0, "achieved_score": 0.0}},
        }
        assert _compute_overall(components) == 0.0

    def test_half_achieved(self):
        from src.tools.purview_policies import _compute_overall
        components = {
            "A": {"details": {"max_score": 20.0, "achieved_score": 10.0}},
        }
        assert _compute_overall(components) == 50.0

    def test_zero_max_returns_zero(self):
        from src.tools.purview_policies import _compute_overall
        components = {
            "A": {"details": {"max_score": 0.0, "achieved_score": 0.0}},
        }
        assert _compute_overall(components) == 0.0


# ═══════════════════════════════════════════════════════════════════════
# 10. _collect_critical_gaps
# ═══════════════════════════════════════════════════════════════════════

class TestCollectCriticalGaps:
    def test_tier1_gap_collected(self):
        from src.tools.purview_policies import _collect_critical_gaps
        profiles = [_gap_profile(title="Critical DLP", tier="Tier1")]
        gaps = _collect_critical_gaps(profiles)
        assert len(gaps) == 1
        assert "Critical DLP" in gaps[0]

    def test_resolved_not_collected(self):
        from src.tools.purview_policies import _collect_critical_gaps
        profiles = [_resolved_profile(title="Done thing", tier="Tier1")]
        gaps = _collect_critical_gaps(profiles)
        assert len(gaps) == 0

    def test_low_tier_not_collected(self):
        from src.tools.purview_policies import _collect_critical_gaps
        profiles = [_gap_profile(title="Minor", tier="Tier3", max_score=1.0)]
        gaps = _collect_critical_gaps(profiles)
        assert len(gaps) == 0

    def test_high_score_gap_collected(self):
        from src.tools.purview_policies import _collect_critical_gaps
        profiles = [_gap_profile(title="Big gap", tier="Tier2", max_score=5.0)]
        gaps = _collect_critical_gaps(profiles)
        assert len(gaps) == 1


# ═══════════════════════════════════════════════════════════════════════
# 11. Mock fallback — check_purview_policies with no Graph client
# ═══════════════════════════════════════════════════════════════════════

class TestPurviewMockFallback:
    """Tests that run check_purview_policies with _create_graph_client → None."""

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    async def test_returns_mock_data_source(self, _mock):
        from src.tools.purview_policies import check_purview_policies
        result = await check_purview_policies()
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    async def test_mock_has_all_components(self, _mock):
        from src.tools.purview_policies import check_purview_policies, ALL_COMPONENTS
        result = await check_purview_policies()
        assert set(result["components"].keys()) == set(ALL_COMPONENTS)

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    async def test_mock_has_overall_coverage(self, _mock):
        from src.tools.purview_policies import check_purview_policies
        result = await check_purview_policies()
        assert 0.0 <= result["overall_coverage_pct"] <= 100.0

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    async def test_mock_has_total_gaps(self, _mock):
        from src.tools.purview_policies import check_purview_policies
        result = await check_purview_policies()
        assert result["total_gaps"] > 0

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    async def test_mock_has_critical_gaps(self, _mock):
        from src.tools.purview_policies import check_purview_policies
        result = await check_purview_policies()
        assert isinstance(result["critical_gaps"], list)
        assert len(result["critical_gaps"]) > 0

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    async def test_mock_has_assessed_at(self, _mock):
        from src.tools.purview_policies import check_purview_policies
        result = await check_purview_policies()
        assert "assessed_at" in result

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    async def test_mock_component_structure(self, _mock):
        from src.tools.purview_policies import check_purview_policies
        result = await check_purview_policies()
        for component in result["components"].values():
            assert "status" in component
            assert "details" in component
            assert "gaps" in component
            assert component["status"] in ("green", "yellow", "red")


# ═══════════════════════════════════════════════════════════════════════
# 12. Graph API path — check_purview_policies with mocked SDK
# ═══════════════════════════════════════════════════════════════════════

class TestPurviewGraphPath:
    """Tests with Graph API returning mocked control profiles."""

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_basic_graph_response(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profiles = [
            _resolved_profile(
                service="Information Protection", title="Enable DLP",
                max_score=10.0,
            ),
            _gap_profile(
                service="Information Protection", title="Auto-labeling for sensitivity",
                max_score=8.0, tier="Tier1",
            ),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "graph_api"
        assert result["total_gaps"] >= 1
        assert "overall_coverage_pct" in result

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_empty_profiles_returns_empty_source(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response([]),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "graph_api_empty"

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_none_response_returns_empty_source(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=None,
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "graph_api_empty"

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_api_error_falls_back_to_mock(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            side_effect=Exception("403 Forbidden"),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_non_purview_profiles_filtered_out(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profiles = [
            _resolved_profile(
                service="MDE", title="MDE control",
                max_score=10.0, control_category="Endpoint",
            ),
            _resolved_profile(
                service="Information Protection", title="DLP control",
                max_score=8.0,
            ),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "graph_api"
        # Only the purview profile should be counted
        total_controls = sum(
            c["details"]["total_controls"] for c in result["components"].values()
        )
        assert total_controls == 1

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_deprecated_profiles_excluded(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profiles = [
            _resolved_profile(service="Information Protection", max_score=10.0),
            _make_profile(
                service="Information Protection", deprecated=True,
                max_score=5.0, control_state_updates=None,
            ),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "graph_api"
        total_controls = sum(
            c["details"]["total_controls"] for c in result["components"].values()
        )
        assert total_controls == 1

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_overall_coverage_weighted(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profiles = [
            _resolved_profile(
                service="Information Protection", title="DLP resolved",
                max_score=20.0,
            ),
            _gap_profile(
                service="Purview", title="DLP gap",
                max_score=20.0,
            ),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["overall_coverage_pct"] == 50.0

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_critical_gaps_from_graph(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profiles = [
            _gap_profile(
                service="Information Protection", title="Critical DLP",
                tier="Tier1", max_score=10.0,
            ),
            _gap_profile(
                service="Information Protection", title="Minor fix",
                tier="Tier3", max_score=1.0,
            ),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert len(result["critical_gaps"]) == 1
        assert "Critical DLP" in result["critical_gaps"][0]

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_all_components_present_in_graph_result(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies, ALL_COMPONENTS

        profiles = [
            _gap_profile(service="Information Protection", title="DLP thing"),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert set(result["components"].keys()) == set(ALL_COMPONENTS)

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_all_purview_filtered_returns_empty(self, mock_factory):
        """When all profiles are non-Purview, treat as empty."""
        from src.tools.purview_policies import check_purview_policies

        profiles = [
            _resolved_profile(service="MDE", title="Endpoint thing"),
            _resolved_profile(service="Azure AD", title="Auth thing"),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "graph_api_empty"

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_assessed_at_present(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profiles = [_resolved_profile(service="Information Protection")]
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert "assessed_at" in result


# ═══════════════════════════════════════════════════════════════════════
# 13. Tracing
# ═══════════════════════════════════════════════════════════════════════

class TestPurviewTracing:
    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_created(self, mock_tracer_fn, _mock_client):
        from src.tools.purview_policies import check_purview_policies

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await check_purview_policies()
        mock_tracer.start_as_current_span.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client", return_value=None)
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_name_contains_tool(self, mock_tracer_fn, _mock_client):
        from src.tools.purview_policies import check_purview_policies

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await check_purview_policies()
        call_args = mock_tracer.start_as_current_span.call_args
        span_name = call_args[0][0] if call_args[0] else call_args[1].get("name", "")
        assert "check_purview_policies" in span_name


# ═══════════════════════════════════════════════════════════════════════
# 14. Edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestPurviewEdgeCases:
    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_all_deprecated_purview_profiles(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profiles = [
            _make_profile(
                service="Information Protection", deprecated=True,
                max_score=10.0, control_state_updates=None,
            ),
        ]
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "graph_api_empty"

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_profile_with_zero_max_score(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profiles = [
            _resolved_profile(service="Information Protection", max_score=0.0),
        ]
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "graph_api"

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_profile_missing_service(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profile = SimpleNamespace(
            id="no-svc", title="dlp thing", service=None,
            control_category=None, max_score=5.0, tier="Tier2",
            deprecated=False, control_state_updates=[_make_state_update("Default")],
        )
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response([profile]),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        # "dlp thing" in title → is purview related
        assert result["data_source"] == "graph_api"

    @pytest.mark.asyncio
    @patch("src.tools.purview_policies._create_graph_client")
    async def test_many_profiles_across_components(self, mock_factory):
        from src.tools.purview_policies import check_purview_policies

        profiles = [
            _resolved_profile(
                service="Information Protection", title="DLP rule 1",
                max_score=10.0,
            ),
            _gap_profile(
                service="Information Protection", title="sensitivity label auto",
                max_score=10.0, tier="Tier1",
            ),
            _gap_profile(
                service="Compliance", title="retention policy Exchange",
                max_score=5.0, tier="Tier2",
            ),
            _gap_profile(
                service="Insider Risk", title="insider risk policy",
                max_score=8.0, tier="Tier1",
            ),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response(profiles),
        )
        mock_factory.return_value = mock_client

        result = await check_purview_policies()
        assert result["data_source"] == "graph_api"
        assert result["total_gaps"] == 3
        assert result["overall_coverage_pct"] < 50.0
        assert len(result["critical_gaps"]) >= 1
