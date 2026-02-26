"""Comprehensive tests for the query_secure_score tool.

Covers:
  - Parsing helpers: category breakdown, industry comparison, trend, status
  - Mock fallback path (no Graph credentials configured)
  - Graph API integration path (mocked Graph SDK responses)
  - Error handling and edge cases
  - Trace span creation via the @trace_tool_call decorator
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════
# Helpers — build fake Graph SDK objects using SimpleNamespace
# ═══════════════════════════════════════════════════════════════════════


def _make_control_score(
    name: str = "MFAForAdmin",
    category: str = "Identity",
    score: float = 8.0,
) -> SimpleNamespace:
    return SimpleNamespace(
        control_name=name,
        control_category=category,
        score=score,
        description=f"Enable {name}",
    )


def _make_comparative_score(
    basis: str = "IndustryTypes",
    average_score: float = 63.2,
) -> SimpleNamespace:
    return SimpleNamespace(basis=basis, average_score=average_score)


def _make_secure_score_snapshot(
    current_score: float = 72.0,
    max_score: float = 100.0,
    created: datetime | None = None,
    control_scores: list | None = None,
    comparatives: list | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        current_score=current_score,
        max_score=max_score,
        created_date_time=created or datetime.now(UTC),
        control_scores=control_scores or [],
        average_comparative_scores=comparatives or [],
        azure_tenant_id="test-tenant-id",
    )


def _make_graph_response(snapshots: list) -> SimpleNamespace:
    return SimpleNamespace(value=snapshots)


# ═══════════════════════════════════════════════════════════════════════
# _parse_category_breakdown
# ═══════════════════════════════════════════════════════════════════════


class TestParseCategoryBreakdown:
    """Tests for _parse_category_breakdown helper."""

    def test_groups_controls_by_category(self):
        from src.tools.secure_score import _parse_category_breakdown

        controls = [
            _make_control_score("MFA", "Identity", 8.0),
            _make_control_score("CondAccess", "Identity", 6.0),
            _make_control_score("DLP", "Data", 4.0),
        ]
        result = _parse_category_breakdown(controls)

        assert "Identity" in result
        assert "Data" in result
        # Identity: 8 + 6 = 14, max = 2 * 10 = 20, pct = 70%
        assert result["Identity"]["score"] == 14.0
        assert result["Identity"]["max_score"] == 20.0
        assert result["Identity"]["percentage"] == 70.0
        # Data: 4, max = 10, pct = 40%
        assert result["Data"]["score"] == 4.0
        assert result["Data"]["percentage"] == 40.0

    def test_empty_controls(self):
        from src.tools.secure_score import _parse_category_breakdown

        result = _parse_category_breakdown([])
        assert result == {}

    def test_unknown_category_handled(self):
        from src.tools.secure_score import _parse_category_breakdown

        controls = [_make_control_score("X", None, 5.0)]
        result = _parse_category_breakdown(controls)
        # None category maps to "Unknown"
        assert "Unknown" in result
        assert result["Unknown"]["score"] == 5.0

    def test_zero_score_controls(self):
        from src.tools.secure_score import _parse_category_breakdown

        controls = [_make_control_score("ZeroCtrl", "Device", 0.0)]
        result = _parse_category_breakdown(controls)
        assert result["Device"]["score"] == 0.0
        assert result["Device"]["percentage"] == 0.0

    def test_single_control_per_category(self):
        from src.tools.secure_score import _parse_category_breakdown

        controls = [_make_control_score("SingleCtrl", "Apps", 7.5)]
        result = _parse_category_breakdown(controls)
        assert result["Apps"]["score"] == 7.5
        assert result["Apps"]["max_score"] == 10.0
        assert result["Apps"]["percentage"] == 75.0

    def test_none_score_treated_as_zero(self):
        from src.tools.secure_score import _parse_category_breakdown

        ctrl = SimpleNamespace(
            control_name="NullScore",
            control_category="Identity",
            score=None,
        )
        result = _parse_category_breakdown([ctrl])
        assert result["Identity"]["score"] == 0.0


# ═══════════════════════════════════════════════════════════════════════
# _parse_industry_comparison
# ═══════════════════════════════════════════════════════════════════════


class TestParseIndustryComparison:
    """Tests for _parse_industry_comparison helper."""

    def test_prefers_industry_types(self):
        from src.tools.secure_score import _parse_industry_comparison

        comparatives = [
            _make_comparative_score("AllTenants", 55.0),
            _make_comparative_score("IndustryTypes", 63.2),
            _make_comparative_score("TotalSeats", 58.0),
        ]
        result = _parse_industry_comparison(comparatives, 47.3)
        assert result["basis"] == "IndustryTypes"
        assert result["industry_avg"] == 63.2
        assert result["delta"] == round(47.3 - 63.2, 1)

    def test_falls_back_to_total_seats(self):
        from src.tools.secure_score import _parse_industry_comparison

        comparatives = [
            _make_comparative_score("AllTenants", 55.0),
            _make_comparative_score("TotalSeats", 58.0),
        ]
        result = _parse_industry_comparison(comparatives, 50.0)
        assert result["basis"] == "TotalSeats"
        assert result["industry_avg"] == 58.0

    def test_falls_back_to_all_tenants(self):
        from src.tools.secure_score import _parse_industry_comparison

        comparatives = [_make_comparative_score("AllTenants", 55.0)]
        result = _parse_industry_comparison(comparatives, 50.0)
        assert result["basis"] == "AllTenants"

    def test_falls_back_to_first_available(self):
        from src.tools.secure_score import _parse_industry_comparison

        comparatives = [_make_comparative_score("CustomBasis", 60.0)]
        result = _parse_industry_comparison(comparatives, 50.0)
        assert result["basis"] == "CustomBasis"
        assert result["industry_avg"] == 60.0

    def test_empty_comparatives(self):
        from src.tools.secure_score import _parse_industry_comparison

        result = _parse_industry_comparison([], 50.0)
        assert result["basis"] == "unavailable"
        assert result["industry_avg"] is None
        assert result["delta"] is None

    def test_none_comparatives(self):
        from src.tools.secure_score import _parse_industry_comparison

        result = _parse_industry_comparison(None, 50.0)
        assert result["basis"] == "unavailable"

    def test_delta_calculation_positive(self):
        from src.tools.secure_score import _parse_industry_comparison

        comparatives = [_make_comparative_score("IndustryTypes", 40.0)]
        result = _parse_industry_comparison(comparatives, 50.0)
        assert result["delta"] == 10.0  # above average

    def test_delta_calculation_negative(self):
        from src.tools.secure_score import _parse_industry_comparison

        comparatives = [_make_comparative_score("IndustryTypes", 70.0)]
        result = _parse_industry_comparison(comparatives, 50.0)
        assert result["delta"] == -20.0  # below average

    def test_none_average_score_skipped(self):
        from src.tools.secure_score import _parse_industry_comparison

        comp = SimpleNamespace(basis="IndustryTypes", average_score=None)
        result = _parse_industry_comparison([comp], 50.0)
        # None average_score means this entry is skipped → unavailable
        assert result["basis"] == "unavailable"


# ═══════════════════════════════════════════════════════════════════════
# _parse_trend
# ═══════════════════════════════════════════════════════════════════════


class TestParseTrend:
    """Tests for _parse_trend helper."""

    def test_extracts_date_and_score(self):
        from src.tools.secure_score import _parse_trend

        now = datetime.now(UTC)
        snapshots = [
            _make_secure_score_snapshot(72.0, 100.0, now),
            _make_secure_score_snapshot(71.0, 100.0, now - timedelta(days=1)),
        ]
        trend = _parse_trend(snapshots)
        assert len(trend) == 2
        assert trend[0]["score"] == 72.0
        assert trend[0]["max_score"] == 100.0
        assert trend[1]["score"] == 71.0
        # Date should be formatted
        assert trend[0]["date"] == now.strftime("%Y-%m-%d")

    def test_caps_at_30_entries(self):
        from src.tools.secure_score import TREND_DAYS, _parse_trend

        now = datetime.now(UTC)
        snapshots = [_make_secure_score_snapshot(70.0, 100.0, now - timedelta(days=i)) for i in range(50)]
        trend = _parse_trend(snapshots)
        assert len(trend) == TREND_DAYS

    def test_empty_snapshots(self):
        from src.tools.secure_score import _parse_trend

        assert _parse_trend([]) == []

    def test_handles_none_created_datetime(self):
        from src.tools.secure_score import _parse_trend

        snap = SimpleNamespace(
            current_score=50.0,
            max_score=100.0,
            created_date_time=None,
        )
        trend = _parse_trend([snap])
        assert trend[0]["date"] == "unknown"

    def test_handles_none_scores_as_zero(self):
        from src.tools.secure_score import _parse_trend

        snap = SimpleNamespace(
            current_score=None,
            max_score=None,
            created_date_time=datetime.now(UTC),
        )
        trend = _parse_trend([snap])
        assert trend[0]["score"] == 0.0
        assert trend[0]["max_score"] == 0.0

    def test_single_snapshot(self):
        from src.tools.secure_score import _parse_trend

        snap = _make_secure_score_snapshot(85.0, 100.0)
        trend = _parse_trend([snap])
        assert len(trend) == 1
        assert trend[0]["score"] == 85.0


# ═══════════════════════════════════════════════════════════════════════
# _compute_status
# ═══════════════════════════════════════════════════════════════════════


class TestComputeStatus:
    """Tests for _compute_status helper."""

    def test_green_at_threshold(self):
        from src.tools.secure_score import GREEN_THRESHOLD, _compute_status

        assert _compute_status(GREEN_THRESHOLD) == "green"

    def test_green_above_threshold(self):
        from src.tools.secure_score import _compute_status

        assert _compute_status(95.0) == "green"

    def test_yellow_just_below_threshold(self):
        from src.tools.secure_score import GREEN_THRESHOLD, _compute_status

        assert _compute_status(GREEN_THRESHOLD - 1) == "yellow"

    def test_yellow_at_boundary(self):
        from src.tools.secure_score import GREEN_THRESHOLD, _compute_status

        assert _compute_status(GREEN_THRESHOLD - 10) == "yellow"

    def test_red_below_yellow_boundary(self):
        from src.tools.secure_score import GREEN_THRESHOLD, _compute_status

        assert _compute_status(GREEN_THRESHOLD - 11) == "red"

    def test_red_at_zero(self):
        from src.tools.secure_score import _compute_status

        assert _compute_status(0.0) == "red"

    def test_custom_threshold(self):
        from src.tools.secure_score import _compute_status

        assert _compute_status(80.0, threshold=80.0) == "green"
        assert _compute_status(75.0, threshold=80.0) == "yellow"
        assert _compute_status(69.0, threshold=80.0) == "red"


# ═══════════════════════════════════════════════════════════════════════
# _generate_mock_response
# ═══════════════════════════════════════════════════════════════════════


class TestGenerateMockResponse:
    """Tests for _generate_mock_response helper."""

    def test_mock_has_all_required_fields(self):
        from src.tools.secure_score import _generate_mock_response

        result = _generate_mock_response()
        required = {
            "current_score",
            "max_score",
            "score_percentage",
            "categories",
            "trend_30d",
            "industry_comparison",
            "assessed_at",
            "status",
            "green_threshold",
            "gap_to_green",
            "data_source",
        }
        assert required.issubset(result.keys())

    def test_mock_data_source_is_mock(self):
        from src.tools.secure_score import _generate_mock_response

        assert _generate_mock_response()["data_source"] == "mock"

    def test_mock_has_five_categories(self):
        from src.tools.secure_score import KNOWN_CATEGORIES, _generate_mock_response

        cats = _generate_mock_response()["categories"]
        assert set(cats.keys()) == KNOWN_CATEGORIES

    def test_mock_trend_has_30_entries(self):
        from src.tools.secure_score import TREND_DAYS, _generate_mock_response

        trend = _generate_mock_response()["trend_30d"]
        assert len(trend) == TREND_DAYS

    def test_mock_trend_entries_have_max_score(self):
        from src.tools.secure_score import _generate_mock_response

        for entry in _generate_mock_response()["trend_30d"]:
            assert "max_score" in entry
            assert "score" in entry
            assert "date" in entry

    def test_mock_industry_has_delta(self):
        from src.tools.secure_score import _generate_mock_response

        ind = _generate_mock_response()["industry_comparison"]
        assert "delta" in ind
        assert "basis" in ind

    def test_mock_gap_is_nonnegative(self):
        from src.tools.secure_score import _generate_mock_response

        assert _generate_mock_response()["gap_to_green"] >= 0

    def test_mock_score_consistency(self):
        from src.tools.secure_score import _generate_mock_response

        r = _generate_mock_response()
        expected_pct = round((r["current_score"] / r["max_score"]) * 100, 1)
        assert r["score_percentage"] == expected_pct


# ═══════════════════════════════════════════════════════════════════════
# _create_graph_client
# ═══════════════════════════════════════════════════════════════════════


class TestCreateGraphClient:
    """Tests for _create_graph_client factory."""

    def test_returns_none_when_no_credentials(self):
        from src.tools.secure_score import _create_graph_client

        with patch("src.tools.graph_client.settings") as mock_settings:
            mock_settings.azure_tenant_id = ""
            mock_settings.azure_client_id = ""
            assert _create_graph_client() is None

    def test_returns_none_when_no_client_id(self):
        from src.tools.secure_score import _create_graph_client

        with patch("src.tools.graph_client.settings") as mock_settings:
            mock_settings.azure_tenant_id = "some-tenant"
            mock_settings.azure_client_id = ""
            assert _create_graph_client() is None

    def test_uses_client_secret_credential_when_secret_set(self):
        from src.tools.secure_score import _create_graph_client

        with patch("src.tools.graph_client.settings") as mock_settings:
            mock_settings.azure_tenant_id = "tenant-123"
            mock_settings.azure_client_id = "client-123"
            mock_settings.azure_client_secret = "secret-123"

            mock_cred = MagicMock()
            mock_client = MagicMock()

            with (
                patch("azure.identity.ClientSecretCredential", return_value=mock_cred),
                patch("msgraph.GraphServiceClient", return_value=mock_client),
            ):
                result = _create_graph_client()
                assert result is not None

    def test_uses_default_credential_when_no_secret(self):
        from src.tools.secure_score import _create_graph_client

        with patch("src.tools.graph_client.settings") as mock_settings:
            mock_settings.azure_tenant_id = "tenant-123"
            mock_settings.azure_client_id = "client-123"
            mock_settings.azure_client_secret = ""

            mock_cred = MagicMock()
            mock_client = MagicMock()

            with (
                patch("azure.identity.DefaultAzureCredential", return_value=mock_cred),
                patch("msgraph.GraphServiceClient", return_value=mock_client),
            ):
                result = _create_graph_client()
                assert result is not None

    def test_raises_on_credential_error(self):
        from src.tools.secure_score import _create_graph_client

        with patch("src.tools.graph_client.settings") as mock_settings:
            mock_settings.azure_tenant_id = "tenant-123"
            mock_settings.azure_client_id = "client-123"
            mock_settings.azure_client_secret = "secret-123"

            with (
                patch(
                    "azure.identity.ClientSecretCredential",
                    side_effect=ValueError("bad cred"),
                ),
                pytest.raises(ValueError, match="bad cred"),
            ):
                _create_graph_client()


# ═══════════════════════════════════════════════════════════════════════
# query_secure_score — mock fallback path
# ═══════════════════════════════════════════════════════════════════════


class TestQuerySecureScoreMockPath:
    """Tests for query_secure_score when Graph credentials are absent (mock path)."""

    @pytest.mark.asyncio
    async def test_returns_mock_when_no_credentials(self):
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()
            assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    async def test_mock_result_has_all_required_fields(self):
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()
            required = {
                "current_score",
                "max_score",
                "score_percentage",
                "categories",
                "trend_30d",
                "industry_comparison",
                "assessed_at",
                "status",
                "green_threshold",
                "gap_to_green",
                "data_source",
            }
            assert required.issubset(result.keys())

    @pytest.mark.asyncio
    async def test_mock_score_within_range(self):
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()
            assert 0 <= result["current_score"] <= result["max_score"]

    @pytest.mark.asyncio
    async def test_mock_has_category_breakdown(self):
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()
            cats = result["categories"]
            assert len(cats) > 0
            for name, details in cats.items():
                assert isinstance(name, str)
                assert "score" in details
                assert "max_score" in details
                assert "percentage" in details

    @pytest.mark.asyncio
    async def test_mock_has_gap_to_green(self):
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()
            assert "gap_to_green" in result
            assert result["gap_to_green"] >= 0

    @pytest.mark.asyncio
    async def test_accepts_tenant_id_param(self):
        with patch("src.tools.secure_score._create_graph_client", return_value=None):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score(tenant_id="test-tenant")
            assert result["data_source"] == "mock"


# ═══════════════════════════════════════════════════════════════════════
# query_secure_score — Graph API path (mocked SDK)
# ═══════════════════════════════════════════════════════════════════════


class TestQuerySecureScoreGraphPath:
    """Tests for query_secure_score with a mocked Graph API client."""

    def _make_mock_client(self, snapshots: list) -> MagicMock:
        """Create a mock GraphServiceClient that returns given snapshots."""
        client = MagicMock()
        response = _make_graph_response(snapshots)
        client.security.secure_scores.get = AsyncMock(return_value=response)
        return client

    @pytest.mark.asyncio
    async def test_graph_api_returns_structured_result(self):
        now = datetime.now(UTC)
        snapshots = [
            _make_secure_score_snapshot(
                current_score=72.5,
                max_score=100.0,
                created=now,
                control_scores=[
                    _make_control_score("MFA", "Identity", 8.0),
                    _make_control_score("DLP", "Data", 5.0),
                ],
                comparatives=[
                    _make_comparative_score("IndustryTypes", 63.0),
                ],
            ),
        ]
        client = self._make_mock_client(snapshots)

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["data_source"] == "graph_api"
        assert result["current_score"] == 72.5
        assert result["max_score"] == 100.0
        assert "Identity" in result["categories"]
        assert "Data" in result["categories"]
        assert result["industry_comparison"]["basis"] == "IndustryTypes"

    @pytest.mark.asyncio
    async def test_graph_api_score_percentage(self):
        snapshots = [_make_secure_score_snapshot(75.0, 100.0)]
        client = self._make_mock_client(snapshots)

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["score_percentage"] == 75.0

    @pytest.mark.asyncio
    async def test_graph_api_green_status(self):
        snapshots = [_make_secure_score_snapshot(75.0, 100.0)]
        client = self._make_mock_client(snapshots)

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["status"] == "green"
        assert result["gap_to_green"] == 0.0

    @pytest.mark.asyncio
    async def test_graph_api_red_status(self):
        snapshots = [_make_secure_score_snapshot(30.0, 100.0)]
        client = self._make_mock_client(snapshots)

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["status"] == "red"
        assert result["gap_to_green"] == 40.0

    @pytest.mark.asyncio
    async def test_graph_api_trend_from_multiple_snapshots(self):
        now = datetime.now(UTC)
        snapshots = [
            _make_secure_score_snapshot(72.0, 100.0, now),
            _make_secure_score_snapshot(70.0, 100.0, now - timedelta(days=1)),
            _make_secure_score_snapshot(68.0, 100.0, now - timedelta(days=2)),
        ]
        client = self._make_mock_client(snapshots)

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert len(result["trend_30d"]) == 3
        assert result["trend_30d"][0]["score"] == 72.0
        assert result["trend_30d"][2]["score"] == 68.0

    @pytest.mark.asyncio
    async def test_graph_api_empty_response_falls_back(self):
        client = MagicMock()
        client.security.secure_scores.get = AsyncMock(return_value=SimpleNamespace(value=[]))

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["data_source"] == "graph_api_empty"

    @pytest.mark.asyncio
    async def test_graph_api_none_response_falls_back(self):
        client = MagicMock()
        client.security.secure_scores.get = AsyncMock(return_value=SimpleNamespace(value=None))

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["data_source"] == "graph_api_empty"

    @pytest.mark.asyncio
    async def test_graph_api_error_raises(self):
        client = MagicMock()
        client.security.secure_scores.get = AsyncMock(side_effect=RuntimeError("Graph API unavailable"))

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            with pytest.raises(RuntimeError, match="Graph API unavailable"):
                await query_secure_score()

    @pytest.mark.asyncio
    async def test_graph_api_zero_max_score(self):
        """Edge case: max_score is 0 (shouldn't happen but protect against div-by-zero)."""
        snapshots = [_make_secure_score_snapshot(0.0, 0.0)]
        client = self._make_mock_client(snapshots)

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["score_percentage"] == 0.0
        assert result["status"] == "red"

    @pytest.mark.asyncio
    async def test_graph_api_uses_query_params(self):
        """Verify the Graph call passes $top and $orderby params."""
        client = MagicMock()
        response = _make_graph_response([_make_secure_score_snapshot(50.0, 100.0)])
        client.security.secure_scores.get = AsyncMock(return_value=response)

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            await query_secure_score()

        # Verify .get() was called with a request_configuration
        call_kwargs = client.security.secure_scores.get.call_args
        assert call_kwargs is not None
        # The request_configuration should be passed
        assert "request_configuration" in call_kwargs.kwargs

    @pytest.mark.asyncio
    async def test_graph_api_control_scores_aggregation(self):
        """Verify controls are aggregated by category from real Graph data."""
        snapshots = [
            _make_secure_score_snapshot(
                current_score=60.0,
                max_score=100.0,
                control_scores=[
                    _make_control_score("MFA", "Identity", 8.0),
                    _make_control_score("SSO", "Identity", 6.0),
                    _make_control_score("BitLocker", "Device", 9.0),
                    _make_control_score("DLP", "Data", 3.0),
                    _make_control_score("AppConsent", "Apps", 7.0),
                    _make_control_score("Firewall", "Infrastructure", 5.0),
                ],
            ),
        ]
        client = self._make_mock_client(snapshots)

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        cats = result["categories"]
        assert len(cats) == 5
        assert cats["Identity"]["score"] == 14.0  # 8 + 6
        assert cats["Device"]["score"] == 9.0
        assert cats["Data"]["score"] == 3.0
        assert cats["Apps"]["score"] == 7.0
        assert cats["Infrastructure"]["score"] == 5.0

    @pytest.mark.asyncio
    async def test_graph_api_assessed_at_is_iso(self):
        snapshots = [_make_secure_score_snapshot(50.0, 100.0)]
        client = self._make_mock_client(snapshots)

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        # Should parse as valid ISO timestamp
        datetime.fromisoformat(result["assessed_at"])


# ═══════════════════════════════════════════════════════════════════════
# Trace span integration
# ═══════════════════════════════════════════════════════════════════════


class TestSecureScoreTracing:
    """Tests that trace spans are created correctly."""

    @pytest.mark.asyncio
    async def test_trace_span_created_on_success(self):
        with (
            patch("src.tools.secure_score._create_graph_client", return_value=None),
            patch("src.middleware.tracing.get_tracer") as mock_get_tracer,
        ):
            mock_tracer = MagicMock()
            mock_span = MagicMock()
            mock_tracer.start_as_current_span.return_value.__enter__ = MagicMock(return_value=mock_span)
            mock_tracer.start_as_current_span.return_value.__exit__ = MagicMock(return_value=False)
            mock_get_tracer.return_value = mock_tracer

            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

            mock_tracer.start_as_current_span.assert_called_once()
            call_kwargs = mock_tracer.start_as_current_span.call_args
            assert "tool.query_secure_score" in str(call_kwargs)

    @pytest.mark.asyncio
    async def test_trace_span_records_error(self):
        client = MagicMock()
        client.security.secure_scores.get = AsyncMock(
            side_effect=RuntimeError("boom"),
        )

        with (
            patch("src.tools.secure_score._create_graph_client", return_value=client),
            patch("src.middleware.tracing.get_tracer") as mock_get_tracer,
        ):
            mock_tracer = MagicMock()
            mock_span = MagicMock()
            mock_tracer.start_as_current_span.return_value.__enter__ = MagicMock(return_value=mock_span)
            mock_tracer.start_as_current_span.return_value.__exit__ = MagicMock(return_value=False)
            mock_get_tracer.return_value = mock_tracer

            from src.tools.secure_score import query_secure_score

            with pytest.raises(RuntimeError):
                await query_secure_score()

            # Span should have recorded the error
            mock_span.set_attribute.assert_any_call("postureiq.tool.status", "error")
            mock_span.record_exception.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════
# Edge cases & integration
# ═══════════════════════════════════════════════════════════════════════


class TestSecureScoreEdgeCases:
    """Edge cases and integration-level checks."""

    @pytest.mark.asyncio
    async def test_none_control_scores_handled(self):
        """Graph API may return None for control_scores."""
        snap = _make_secure_score_snapshot(50.0, 100.0)
        snap.control_scores = None
        client = MagicMock()
        client.security.secure_scores.get = AsyncMock(return_value=_make_graph_response([snap]))

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["categories"] == {}

    @pytest.mark.asyncio
    async def test_none_comparatives_handled(self):
        """Graph API may return None for average_comparative_scores."""
        snap = _make_secure_score_snapshot(50.0, 100.0)
        snap.average_comparative_scores = None
        client = MagicMock()
        client.security.secure_scores.get = AsyncMock(return_value=_make_graph_response([snap]))

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["industry_comparison"]["basis"] == "unavailable"

    @pytest.mark.asyncio
    async def test_response_values_are_rounded(self):
        """All numeric outputs should be cleanly rounded."""
        snap = _make_secure_score_snapshot(72.3456789, 99.99999)
        client = MagicMock()
        client.security.secure_scores.get = AsyncMock(return_value=_make_graph_response([snap]))

        with patch("src.tools.secure_score._create_graph_client", return_value=client):
            from src.tools.secure_score import query_secure_score

            result = await query_secure_score()

        assert result["current_score"] == 72.3
        assert result["max_score"] == 100.0  # rounded
        assert isinstance(result["score_percentage"], float)

    def test_green_threshold_constant(self):
        from src.tools.secure_score import GREEN_THRESHOLD

        assert GREEN_THRESHOLD == 70.0

    def test_trend_days_constant(self):
        from src.tools.secure_score import TREND_DAYS

        assert TREND_DAYS == 30

    def test_known_categories(self):
        from src.tools.secure_score import KNOWN_CATEGORIES

        assert (
            frozenset(
                {
                    "Identity",
                    "Data",
                    "Device",
                    "Apps",
                    "Infrastructure",
                }
            )
            == KNOWN_CATEGORIES
        )
