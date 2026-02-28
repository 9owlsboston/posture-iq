"""Comprehensive tests for the assess_defender_coverage tool.

Covers:
  - Classification / parsing helpers
  - Per-workload result building
  - Overall aggregation across workloads
  - Critical-gap collection
  - Mock fallback path (no Graph credentials)
  - Graph API integration path (mocked SDK responses)
  - Error handling and edge cases
  - Trace span creation via @trace_tool_call decorator
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════
# Helpers — build fake Graph SDK objects using SimpleNamespace
# ═══════════════════════════════════════════════════════════════════════


def _make_state_update(state: str = "Default", **kwargs) -> SimpleNamespace:
    return SimpleNamespace(
        state=state,
        assigned_to=kwargs.get("assigned_to", ""),
        comment=kwargs.get("comment", ""),
        updated_by=kwargs.get("updated_by", ""),
        updated_date_time=kwargs.get("updated_date_time"),
    )


def _make_profile(
    *,
    id: str = "ctrl-1",
    title: str = "Enable MFA for admins",
    service: str = "MDE",
    max_score: float = 10.0,
    tier: str = "Tier1",
    deprecated: bool = False,
    remediation: str = "Go to Security Center and enable this.",
    control_state_updates: list | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=id,
        title=title,
        service=service,
        max_score=max_score,
        tier=tier,
        deprecated=deprecated,
        remediation=remediation,
        control_state_updates=control_state_updates,
    )


def _resolved_profile(**kwargs) -> SimpleNamespace:
    """Shortcut for a profile whose latest state is Resolved."""
    kwargs.setdefault("control_state_updates", [_make_state_update("Resolved")])
    return _make_profile(**kwargs)


def _gap_profile(**kwargs) -> SimpleNamespace:
    """Shortcut for a profile that constitutes a gap."""
    kwargs.setdefault("control_state_updates", [_make_state_update("Default")])
    return _make_profile(**kwargs)


# ═══════════════════════════════════════════════════════════════════════
# 1. _classify_workload
# ═══════════════════════════════════════════════════════════════════════


class TestClassifyWorkload:
    """Tests for _classify_workload helper."""

    def test_short_code_mde(self):
        from src.tools.defender_coverage import _classify_workload

        assert _classify_workload("MDE") == "Defender for Endpoint"

    def test_short_code_mdo(self):
        from src.tools.defender_coverage import _classify_workload

        assert _classify_workload("MDO") == "Defender for Office 365"

    def test_short_code_mdi(self):
        from src.tools.defender_coverage import _classify_workload

        assert _classify_workload("MDI") == "Defender for Identity"

    def test_short_code_mda(self):
        from src.tools.defender_coverage import _classify_workload

        assert _classify_workload("MDA") == "Defender for Cloud Apps"

    def test_full_name_endpoint(self):
        from src.tools.defender_coverage import _classify_workload

        assert _classify_workload("Microsoft Defender for Endpoint") == "Defender for Endpoint"

    def test_full_name_cloud_app_security_legacy(self):
        from src.tools.defender_coverage import _classify_workload

        assert _classify_workload("Microsoft Cloud App Security") == "Defender for Cloud Apps"

    def test_unknown_service_returns_none(self):
        from src.tools.defender_coverage import _classify_workload

        assert _classify_workload("SomeOtherService") is None

    def test_none_returns_none(self):
        from src.tools.defender_coverage import _classify_workload

        assert _classify_workload(None) is None

    def test_empty_string_returns_none(self):
        from src.tools.defender_coverage import _classify_workload

        assert _classify_workload("") is None


# ═══════════════════════════════════════════════════════════════════════
# 2. _compute_status
# ═══════════════════════════════════════════════════════════════════════


class TestComputeStatus:
    """Tests for _compute_status helper."""

    def test_green_at_threshold(self):
        from src.tools.defender_coverage import _compute_status

        assert _compute_status(70.0) == "green"

    def test_green_above_threshold(self):
        from src.tools.defender_coverage import _compute_status

        assert _compute_status(95.0) == "green"

    def test_yellow_at_lower_threshold(self):
        from src.tools.defender_coverage import _compute_status

        assert _compute_status(40.0) == "yellow"

    def test_yellow_between_thresholds(self):
        from src.tools.defender_coverage import _compute_status

        assert _compute_status(55.0) == "yellow"

    def test_red_below_yellow(self):
        from src.tools.defender_coverage import _compute_status

        assert _compute_status(39.9) == "red"

    def test_red_at_zero(self):
        from src.tools.defender_coverage import _compute_status

        assert _compute_status(0.0) == "red"

    def test_green_at_100(self):
        from src.tools.defender_coverage import _compute_status

        assert _compute_status(100.0) == "green"


# ═══════════════════════════════════════════════════════════════════════
# 3. _is_gap
# ═══════════════════════════════════════════════════════════════════════


class TestIsGap:
    """Tests for _is_gap helper."""

    def test_no_state_updates_is_gap(self):
        from src.tools.defender_coverage import _is_gap

        p = _make_profile(control_state_updates=None)
        assert _is_gap(p) is True

    def test_empty_state_updates_is_gap(self):
        from src.tools.defender_coverage import _is_gap

        p = _make_profile(control_state_updates=[])
        assert _is_gap(p) is True

    def test_default_state_is_gap(self):
        from src.tools.defender_coverage import _is_gap

        p = _make_profile(control_state_updates=[_make_state_update("Default")])
        assert _is_gap(p) is True

    def test_resolved_state_is_not_gap(self):
        from src.tools.defender_coverage import _is_gap

        p = _make_profile(control_state_updates=[_make_state_update("Resolved")])
        assert _is_gap(p) is False

    def test_thirdparty_state_is_not_gap(self):
        from src.tools.defender_coverage import _is_gap

        p = _make_profile(control_state_updates=[_make_state_update("ThirdParty")])
        assert _is_gap(p) is False

    def test_third_party_underscore_is_not_gap(self):
        from src.tools.defender_coverage import _is_gap

        p = _make_profile(control_state_updates=[_make_state_update("Third_Party")])
        assert _is_gap(p) is False

    def test_deprecated_is_never_gap(self):
        from src.tools.defender_coverage import _is_gap

        p = _make_profile(deprecated=True, control_state_updates=None)
        assert _is_gap(p) is False

    def test_latest_state_matters(self):
        """Multiple updates — the last one wins."""
        from src.tools.defender_coverage import _is_gap

        p = _make_profile(
            control_state_updates=[
                _make_state_update("Default"),
                _make_state_update("Resolved"),
            ]
        )
        assert _is_gap(p) is False

    def test_latest_state_reverted_to_default(self):
        from src.tools.defender_coverage import _is_gap

        p = _make_profile(
            control_state_updates=[
                _make_state_update("Resolved"),
                _make_state_update("Default"),
            ]
        )
        assert _is_gap(p) is True


# ═══════════════════════════════════════════════════════════════════════
# 4. _gap_description
# ═══════════════════════════════════════════════════════════════════════


class TestGapDescription:
    """Tests for _gap_description helper."""

    def test_basic(self):
        from src.tools.defender_coverage import _gap_description

        p = _make_profile(title="Enable MFA", tier="Tier1", remediation="Do it now")
        desc = _gap_description(p)
        assert "Enable MFA" in desc
        assert "Tier1" in desc
        assert "Do it now" in desc

    def test_no_tier(self):
        from src.tools.defender_coverage import _gap_description

        p = _make_profile(title="Some control", tier=None, remediation="Fix it")
        desc = _gap_description(p)
        assert "Some control" in desc
        assert "tier" not in desc.lower() or "None" not in desc

    def test_no_remediation(self):
        from src.tools.defender_coverage import _gap_description

        p = _make_profile(title="Some control", remediation=None)
        desc = _gap_description(p)
        assert "Some control" in desc

    def test_long_remediation_truncated(self):
        from src.tools.defender_coverage import _gap_description

        long_text = "A" * 200
        p = _make_profile(title="Ctrl", remediation=long_text)
        desc = _gap_description(p)
        assert len(desc) < 250  # well under the full 200 chars of remediation
        assert "…" in desc

    def test_fallback_to_id(self):
        from src.tools.defender_coverage import _gap_description

        p = SimpleNamespace(id="ctrl-42", tier=None, remediation=None)
        desc = _gap_description(p)
        assert "ctrl-42" in desc


# ═══════════════════════════════════════════════════════════════════════
# 5. _is_critical_gap
# ═══════════════════════════════════════════════════════════════════════


class TestIsCriticalGap:
    """Tests for _is_critical_gap helper."""

    def test_tier1_is_critical(self):
        from src.tools.defender_coverage import _is_critical_gap

        p = _make_profile(tier="Tier1", max_score=2.0)
        assert _is_critical_gap(p) is True

    def test_mandatory_tier_is_critical(self):
        from src.tools.defender_coverage import _is_critical_gap

        p = _make_profile(tier="MandatoryTier", max_score=2.0)
        assert _is_critical_gap(p) is True

    def test_high_max_score_is_critical(self):
        from src.tools.defender_coverage import _is_critical_gap

        p = _make_profile(tier="Tier3", max_score=5.0)
        assert _is_critical_gap(p) is True

    def test_low_tier_low_score_is_not_critical(self):
        from src.tools.defender_coverage import _is_critical_gap

        p = _make_profile(tier="Tier3", max_score=2.0)
        assert _is_critical_gap(p) is False

    def test_none_tier_high_score(self):
        from src.tools.defender_coverage import _is_critical_gap

        p = _make_profile(tier=None, max_score=10.0)
        assert _is_critical_gap(p) is True


# ═══════════════════════════════════════════════════════════════════════
# 6. _build_workload_result
# ═══════════════════════════════════════════════════════════════════════


class TestBuildWorkloadResult:
    """Tests for _build_workload_result helper."""

    def test_empty_profiles(self):
        from src.tools.defender_coverage import _build_workload_result

        result = _build_workload_result([])
        assert result["coverage_pct"] == 0.0
        assert result["status"] == "red"
        assert result["details"]["total_controls"] == 0
        assert result["gaps"] == []

    def test_all_resolved(self):
        from src.tools.defender_coverage import _build_workload_result

        profiles = [
            _resolved_profile(max_score=10.0),
            _resolved_profile(max_score=5.0),
        ]
        result = _build_workload_result(profiles)
        assert result["coverage_pct"] == 100.0
        assert result["status"] == "green"
        assert result["details"]["achieved_controls"] == 2
        assert result["gaps"] == []

    def test_all_gaps(self):
        from src.tools.defender_coverage import _build_workload_result

        profiles = [
            _gap_profile(max_score=10.0, title="Gap A"),
            _gap_profile(max_score=5.0, title="Gap B"),
        ]
        result = _build_workload_result(profiles)
        assert result["coverage_pct"] == 0.0
        assert result["status"] == "red"
        assert len(result["gaps"]) == 2

    def test_mixed_profiles(self):
        from src.tools.defender_coverage import _build_workload_result

        profiles = [
            _resolved_profile(max_score=10.0),
            _gap_profile(max_score=10.0, title="Missing ctrl"),
        ]
        result = _build_workload_result(profiles)
        assert result["coverage_pct"] == 50.0
        assert result["status"] == "yellow"
        assert result["details"]["achieved_controls"] == 1
        assert result["details"]["total_controls"] == 2
        assert len(result["gaps"]) == 1

    def test_deprecated_excluded_from_gap_count(self):
        from src.tools.defender_coverage import _build_workload_result

        profiles = [
            _resolved_profile(max_score=10.0),
            _make_profile(max_score=5.0, deprecated=True, control_state_updates=None),
        ]
        result = _build_workload_result(profiles)
        # deprecated is not a gap, not resolved either — doesn't add to achieved
        assert result["details"]["total_controls"] == 2
        # max_score still counted
        assert result["details"]["max_score"] == 15.0


# ═══════════════════════════════════════════════════════════════════════
# 7. _aggregate_workloads
# ═══════════════════════════════════════════════════════════════════════


class TestAggregateWorkloads:
    """Tests for _aggregate_workloads helper."""

    def test_groups_by_service(self):
        from src.tools.defender_coverage import ALL_WORKLOADS, _aggregate_workloads

        profiles = [
            _resolved_profile(service="MDE", max_score=10.0),
            _gap_profile(service="MDO", max_score=5.0),
            _resolved_profile(service="MDI", max_score=8.0),
            _gap_profile(service="MDA", max_score=3.0),
        ]
        result = _aggregate_workloads(profiles)
        assert set(result.keys()) == set(ALL_WORKLOADS)
        assert result["Defender for Endpoint"]["coverage_pct"] == 100.0
        assert result["Defender for Office 365"]["coverage_pct"] == 0.0
        assert result["Defender for Identity"]["coverage_pct"] == 100.0
        assert result["Defender for Cloud Apps"]["coverage_pct"] == 0.0

    def test_unknown_service_ignored(self):
        from src.tools.defender_coverage import _aggregate_workloads

        profiles = [
            _resolved_profile(service="UnknownSvc", max_score=10.0),
        ]
        result = _aggregate_workloads(profiles)
        # All workloads should have 0 controls
        for wl_result in result.values():
            assert wl_result["details"]["total_controls"] == 0

    def test_empty_list(self):
        from src.tools.defender_coverage import ALL_WORKLOADS, _aggregate_workloads

        result = _aggregate_workloads([])
        assert set(result.keys()) == set(ALL_WORKLOADS)
        for wl_result in result.values():
            assert wl_result["coverage_pct"] == 0.0

    def test_full_name_service_mapping(self):
        from src.tools.defender_coverage import _aggregate_workloads

        profiles = [
            _resolved_profile(service="Microsoft Defender for Endpoint", max_score=5.0),
        ]
        result = _aggregate_workloads(profiles)
        assert result["Defender for Endpoint"]["details"]["total_controls"] == 1


# ═══════════════════════════════════════════════════════════════════════
# 8. _compute_overall_coverage
# ═══════════════════════════════════════════════════════════════════════


class TestComputeOverallCoverage:
    """Tests for _compute_overall_coverage helper."""

    def test_weighted_average(self):
        from src.tools.defender_coverage import _compute_overall_coverage

        workloads = {
            "A": {"details": {"max_score": 100.0, "achieved_score": 80.0}},
            "B": {"details": {"max_score": 100.0, "achieved_score": 60.0}},
        }
        assert _compute_overall_coverage(workloads) == 70.0

    def test_all_zero_max(self):
        from src.tools.defender_coverage import _compute_overall_coverage

        workloads = {
            "A": {"details": {"max_score": 0.0, "achieved_score": 0.0}},
        }
        assert _compute_overall_coverage(workloads) == 0.0

    def test_full_coverage(self):
        from src.tools.defender_coverage import _compute_overall_coverage

        workloads = {
            "A": {"details": {"max_score": 50.0, "achieved_score": 50.0}},
            "B": {"details": {"max_score": 25.0, "achieved_score": 25.0}},
        }
        assert _compute_overall_coverage(workloads) == 100.0


# ═══════════════════════════════════════════════════════════════════════
# 9. _collect_critical_gaps
# ═══════════════════════════════════════════════════════════════════════


class TestCollectCriticalGaps:
    """Tests for _collect_critical_gaps helper."""

    def test_finds_critical_gaps(self):
        from src.tools.defender_coverage import _collect_critical_gaps

        profiles = [
            _gap_profile(service="MDE", title="ASR rules", tier="Tier1", max_score=10.0),
            _gap_profile(service="MDO", title="Low prio", tier="Tier3", max_score=1.0),
        ]
        result = _collect_critical_gaps(profiles)
        assert len(result) == 1
        assert "ASR rules" in result[0]
        assert "Defender for Endpoint" in result[0]

    def test_resolved_profiles_excluded(self):
        from src.tools.defender_coverage import _collect_critical_gaps

        profiles = [
            _resolved_profile(service="MDE", title="Fixed", tier="Tier1", max_score=10.0),
        ]
        assert _collect_critical_gaps(profiles) == []

    def test_high_score_is_critical(self):
        from src.tools.defender_coverage import _collect_critical_gaps

        profiles = [
            _gap_profile(service="MDI", title="Big gap", tier="Tier3", max_score=7.0),
        ]
        result = _collect_critical_gaps(profiles)
        assert len(result) == 1
        assert "Big gap" in result[0]

    def test_empty_list(self):
        from src.tools.defender_coverage import _collect_critical_gaps

        assert _collect_critical_gaps([]) == []


# ═══════════════════════════════════════════════════════════════════════
# 10. _generate_mock_response
# ═══════════════════════════════════════════════════════════════════════


class TestGenerateMockResponse:
    """Tests for the mock-data fallback."""

    def test_has_all_top_level_keys(self):
        from src.tools.defender_coverage import _generate_mock_response

        mock = _generate_mock_response()
        for key in ("overall_coverage_pct", "workloads", "total_gaps", "critical_gaps", "assessed_at", "data_source"):
            assert key in mock, f"Missing key: {key}"

    def test_all_four_workloads_present(self):
        from src.tools.defender_coverage import ALL_WORKLOADS, _generate_mock_response

        mock = _generate_mock_response()
        assert set(mock["workloads"].keys()) == set(ALL_WORKLOADS)

    def test_workload_structure(self):
        from src.tools.defender_coverage import _generate_mock_response

        mock = _generate_mock_response()
        for _wl_name, wl_data in mock["workloads"].items():
            assert "coverage_pct" in wl_data
            assert "status" in wl_data
            assert "details" in wl_data
            assert "gaps" in wl_data
            assert isinstance(wl_data["gaps"], list)

    def test_data_source_is_mock(self):
        from src.tools.defender_coverage import _generate_mock_response

        assert _generate_mock_response()["data_source"] == "mock"

    def test_total_gaps_matches_sum(self):
        from src.tools.defender_coverage import _generate_mock_response

        mock = _generate_mock_response()
        total = sum(len(w["gaps"]) for w in mock["workloads"].values())
        assert mock["total_gaps"] == total

    def test_assessed_at_is_iso(self):
        from datetime import datetime

        from src.tools.defender_coverage import _generate_mock_response

        mock = _generate_mock_response()
        # Should not throw
        datetime.fromisoformat(mock["assessed_at"])


# ═══════════════════════════════════════════════════════════════════════
# 11. assess_defender_coverage — Mock path
# ═══════════════════════════════════════════════════════════════════════


class TestDefenderCoverageMockPath:
    """Tests for the tool when Graph client is not available (mock fallback)."""

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client", return_value=None)
    async def test_returns_mock_when_no_client(self, mock_client):
        from src.tools.defender_coverage import assess_defender_coverage

        result = await assess_defender_coverage()
        assert result["data_source"] == "mock"
        assert "workloads" in result

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client", return_value=None)
    async def test_mock_has_overall_coverage(self, mock_client):
        from src.tools.defender_coverage import assess_defender_coverage

        result = await assess_defender_coverage()
        assert isinstance(result["overall_coverage_pct"], float)

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client", return_value=None)
    async def test_mock_has_critical_gaps(self, mock_client):
        from src.tools.defender_coverage import assess_defender_coverage

        result = await assess_defender_coverage()
        assert isinstance(result["critical_gaps"], list)
        assert len(result["critical_gaps"]) > 0

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client", return_value=None)
    async def test_mock_has_assessed_at(self, mock_client):
        from src.tools.defender_coverage import assess_defender_coverage

        result = await assess_defender_coverage()
        assert "assessed_at" in result


# ═══════════════════════════════════════════════════════════════════════
# 12. assess_defender_coverage — Graph API path
# ═══════════════════════════════════════════════════════════════════════


def _build_graph_response(profiles: list[SimpleNamespace]) -> SimpleNamespace:
    """Build a fake SecureScoreControlProfileCollectionResponse."""
    return SimpleNamespace(value=profiles, odata_next_link=None)


class TestDefenderCoverageGraphPath:
    """Tests for the tool when Graph API responds with real data."""

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_basic_graph_response(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = [
            _resolved_profile(service="MDE", max_score=10.0, title="MDE Ctrl 1"),
            _gap_profile(service="MDE", max_score=10.0, title="MDE Ctrl 2", tier="Tier1"),
            _resolved_profile(service="MDO", max_score=5.0, title="MDO Ctrl 1"),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert result["data_source"] == "graph_api"
        assert result["workloads"]["Defender for Endpoint"]["coverage_pct"] == 50.0
        assert result["workloads"]["Defender for Office 365"]["coverage_pct"] == 100.0

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_empty_response_returns_mock(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response([]))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert result["data_source"] == "graph_api_empty"

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_none_response_returns_mock(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=None)
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert result["data_source"] == "graph_api_empty"

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_api_error_falls_back_to_mock(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(side_effect=Exception("403 Forbidden"))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_deprecated_profiles_excluded(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = [
            _resolved_profile(service="MDE", max_score=10.0),
            _make_profile(service="MDE", max_score=10.0, deprecated=True, control_state_updates=None),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert result["data_source"] == "graph_api"
        # Only the active resolved profile should be in the workload
        ep = result["workloads"]["Defender for Endpoint"]
        assert ep["details"]["total_controls"] == 1  # deprecated filtered before aggregation
        assert ep["coverage_pct"] == 100.0

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_overall_coverage_weighted(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = [
            _resolved_profile(service="MDE", max_score=20.0),
            _gap_profile(service="MDO", max_score=20.0),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert result["overall_coverage_pct"] == 50.0

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_critical_gaps_collected(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = [
            _gap_profile(service="MDE", title="Critical ASR", tier="Tier1", max_score=10.0),
            _gap_profile(service="MDO", title="Minor thing", tier="Tier3", max_score=1.0),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert len(result["critical_gaps"]) == 1
        assert "Critical ASR" in result["critical_gaps"][0]

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_total_gaps_summed(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = [
            _gap_profile(service="MDE", title="Gap1"),
            _gap_profile(service="MDE", title="Gap2"),
            _gap_profile(service="MDO", title="Gap3"),
            _resolved_profile(service="MDI"),
        ]

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert result["total_gaps"] == 3

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_assessed_at_present(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = [_resolved_profile(service="MDE")]
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert "assessed_at" in result

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_all_workloads_always_present(self, mock_factory):
        """Even if no profiles match a workload it should appear with 0%."""
        from src.tools.defender_coverage import ALL_WORKLOADS, assess_defender_coverage

        profiles = [_resolved_profile(service="MDE", max_score=10.0)]
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert set(result["workloads"].keys()) == set(ALL_WORKLOADS)
        assert result["workloads"]["Defender for Identity"]["coverage_pct"] == 0.0

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_unknown_service_profiles_excluded(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = [
            _resolved_profile(service="UnknownSvc", max_score=10.0),
            _resolved_profile(service="MDE", max_score=5.0),
        ]
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        # Only MDE profile counted
        assert result["workloads"]["Defender for Endpoint"]["details"]["total_controls"] == 1
        assert result["overall_coverage_pct"] > 0

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_graph_path_works_without_generated_request_builder(self, mock_factory):
        import builtins

        from src.tools.defender_coverage import assess_defender_coverage

        original_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name.startswith("msgraph.generated.security.secure_score_control_profiles"):
                raise ModuleNotFoundError("No module named 'msgraph.generated.security.secure_score_control_profiles'")
            return original_import(name, *args, **kwargs)

        profiles = [_resolved_profile(service="MDE", max_score=10.0)]
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        with patch("builtins.__import__", side_effect=_fake_import):
            result = await assess_defender_coverage()

        assert result["data_source"] == "graph_api"
        assert mock_client.security.secure_score_control_profiles.get.call_count == 1
        assert "request_configuration" in mock_client.security.secure_score_control_profiles.get.call_args.kwargs


# ═══════════════════════════════════════════════════════════════════════
# 13. Tracing
# ═══════════════════════════════════════════════════════════════════════


class TestDefenderCoverageTracing:
    """Verify the @trace_tool_call decorator creates a span."""

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client", return_value=None)
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_created(self, mock_tracer_fn, _mock_client):
        from src.tools.defender_coverage import assess_defender_coverage

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await assess_defender_coverage()
        mock_tracer.start_as_current_span.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client", return_value=None)
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_name_contains_tool(self, mock_tracer_fn, _mock_client):
        from src.tools.defender_coverage import assess_defender_coverage

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await assess_defender_coverage()
        call_args = mock_tracer.start_as_current_span.call_args
        span_name = call_args[0][0] if call_args[0] else call_args[1].get("name", "")
        assert "assess_defender_coverage" in span_name


# ═══════════════════════════════════════════════════════════════════════
# 14. Edge cases
# ═══════════════════════════════════════════════════════════════════════


class TestDefenderCoverageEdgeCases:
    """Edge cases and boundary conditions."""

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_all_deprecated_profiles(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = [
            _make_profile(service="MDE", max_score=10.0, deprecated=True),
            _make_profile(service="MDO", max_score=5.0, deprecated=True),
        ]
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        # All deprecated → filtered out → empty profiles → triggers empty fallback
        result = await assess_defender_coverage()
        # After filtering, no active profiles remain → goes to empty branch
        # But the profiles list isn't empty before filtering, so we hit the
        # aggregation path with the filtered list.
        assert result["data_source"] == "graph_api"
        # All workloads should show 0%
        for wl_data in result["workloads"].values():
            assert wl_data["coverage_pct"] == 0.0

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_profile_with_zero_max_score(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = [
            _resolved_profile(service="MDE", max_score=0.0),
        ]
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        ep = result["workloads"]["Defender for Endpoint"]
        assert ep["coverage_pct"] == 0.0  # 0/0 → 0%

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_profile_missing_service_attribute(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        # Profile without service field → no workload → ignored
        profile = SimpleNamespace(
            id="no-svc",
            title="No service",
            max_score=5.0,
            tier="Tier2",
            deprecated=False,
            control_state_updates=[_make_state_update("Default")],
        )
        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(
            return_value=_build_graph_response([profile])
        )
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert result["data_source"] == "graph_api"
        # Should not crash; all workloads at 0%
        for wl_data in result["workloads"].values():
            assert wl_data["details"]["total_controls"] == 0

    @pytest.mark.asyncio
    @patch("src.tools.defender_coverage._create_graph_client")
    async def test_many_profiles_all_workloads(self, mock_factory):
        from src.tools.defender_coverage import assess_defender_coverage

        profiles = []
        for svc in ("MDE", "MDO", "MDI", "MDA"):
            profiles.append(_resolved_profile(service=svc, max_score=10.0))
            profiles.append(_gap_profile(service=svc, max_score=10.0, tier="Tier2"))

        mock_client = MagicMock()
        mock_client.security.secure_score_control_profiles.get = AsyncMock(return_value=_build_graph_response(profiles))
        mock_factory.return_value = mock_client

        result = await assess_defender_coverage()
        assert result["overall_coverage_pct"] == 50.0
        assert result["total_gaps"] == 4
        for wl_data in result["workloads"].values():
            assert wl_data["coverage_pct"] == 50.0
            assert wl_data["status"] == "yellow"
