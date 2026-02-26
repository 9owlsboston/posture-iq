"""Comprehensive tests for the create_adoption_scorecard tool.

Covers:
  - Helpers (_status_from_pct, _parse_assessment, _extract_defender,
    _extract_purview, _extract_entra, _default_workload,
    _collect_critical_gaps, _extract_days_to_green)
  - Markdown generation (_generate_markdown_scorecard)
  - Mock fallback path (empty / unparseable assessment context)
  - Live data path (valid assessment context JSON)
  - Trace span creation via @trace_tool_call decorator
  - Edge cases
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _make_assessment_data(
    *,
    defender_pct: float = 60.0,
    purview_pct: float = 40.0,
    entra_pct: float = 50.0,
    defender_gaps: int = 5,
    purview_gaps: int = 8,
    entra_gaps: int = 10,
    include_remediation: bool = False,
    remediation_days: int = 14,
) -> dict[str, Any]:
    """Build a minimal but realistic assessment_context dict."""
    data: dict[str, Any] = {
        "secure_score": {"current_score": 45.0, "max_score": 100.0},
        "defender_coverage": {
            "overall_coverage_pct": defender_pct,
            "total_gaps": defender_gaps,
            "components": {
                "Defender for Endpoint": {"coverage_pct": defender_pct + 5},
                "Defender for Office 365": {"coverage_pct": defender_pct - 10},
            },
            "critical_gaps": ["Gap A", "Gap B"],
        },
        "purview_policies": {
            "overall_coverage_pct": purview_pct,
            "total_gaps": purview_gaps,
            "components": {
                "DLP Policies": {"coverage_pct": purview_pct},
            },
            "critical_gaps": ["Gap C"],
        },
        "entra_config": {
            "overall_coverage_pct": entra_pct,
            "total_gaps": entra_gaps,
            "components": {
                "Conditional Access": {"coverage_pct": entra_pct + 10},
                "PIM": {"coverage_pct": entra_pct - 20},
            },
            "critical_gaps": [
                {"description": "Legacy auth not blocked", "priority": "P0"},
            ],
        },
    }
    if include_remediation:
        data["remediation_plan"] = {
            "estimated_days_to_green": remediation_days,
            "steps": [
                {"priority": "P0", "title": "Block legacy auth"},
                {"priority": "P1", "title": "Enable MFA for all"},
            ],
        }
    return data


# ═══════════════════════════════════════════════════════════════════════
# 1. _status_from_pct
# ═══════════════════════════════════════════════════════════════════════

class TestStatusFromPct:
    def test_green(self):
        from src.tools.adoption_scorecard import _status_from_pct
        assert _status_from_pct(70.0) == "green"
        assert _status_from_pct(100.0) == "green"
        assert _status_from_pct(85.5) == "green"

    def test_yellow(self):
        from src.tools.adoption_scorecard import _status_from_pct
        assert _status_from_pct(40.0) == "yellow"
        assert _status_from_pct(69.9) == "yellow"

    def test_red(self):
        from src.tools.adoption_scorecard import _status_from_pct
        assert _status_from_pct(0.0) == "red"
        assert _status_from_pct(39.9) == "red"

    def test_boundaries(self):
        from src.tools.adoption_scorecard import _status_from_pct
        assert _status_from_pct(70.0) == "green"
        assert _status_from_pct(40.0) == "yellow"
        assert _status_from_pct(39.99) == "red"


# ═══════════════════════════════════════════════════════════════════════
# 2. _parse_assessment
# ═══════════════════════════════════════════════════════════════════════

class TestParseAssessment:
    def test_valid_json(self):
        from src.tools.adoption_scorecard import _parse_assessment
        result = _parse_assessment(json.dumps({"key": "value"}))
        assert result == {"key": "value"}

    def test_invalid_json(self):
        from src.tools.adoption_scorecard import _parse_assessment
        result = _parse_assessment("not json!!!")
        assert result == {}

    def test_empty_string(self):
        from src.tools.adoption_scorecard import _parse_assessment
        result = _parse_assessment("")
        assert result == {}

    def test_none_input(self):
        from src.tools.adoption_scorecard import _parse_assessment
        result = _parse_assessment(None)
        assert result == {}

    def test_non_dict_json(self):
        from src.tools.adoption_scorecard import _parse_assessment
        result = _parse_assessment(json.dumps([1, 2, 3]))
        assert result == {}

    def test_whitespace_only(self):
        from src.tools.adoption_scorecard import _parse_assessment
        result = _parse_assessment("   \n  ")
        assert result == {}


# ═══════════════════════════════════════════════════════════════════════
# 3. _extract_defender
# ═══════════════════════════════════════════════════════════════════════

class TestExtractDefender:
    def test_with_data(self):
        from src.tools.adoption_scorecard import _extract_defender
        data = _make_assessment_data(defender_pct=75.0, defender_gaps=3)
        result = _extract_defender(data)
        assert result["status"] == "green"
        assert result["coverage_pct"] == 75.0
        assert result["gaps_count"] == 3
        assert "Defender for Endpoint" in result["sub_workloads"]

    def test_without_data(self):
        from src.tools.adoption_scorecard import _extract_defender
        result = _extract_defender({})
        assert result["status"] == "unknown"
        assert result["coverage_pct"] == 0.0

    def test_empty_components(self):
        from src.tools.adoption_scorecard import _extract_defender
        data = {"defender_coverage": {"overall_coverage_pct": 50.0, "total_gaps": 2, "components": {}}}
        result = _extract_defender(data)
        assert result["status"] == "yellow"
        assert result["sub_workloads"] == {}


# ═══════════════════════════════════════════════════════════════════════
# 4. _extract_purview
# ═══════════════════════════════════════════════════════════════════════

class TestExtractPurview:
    def test_with_data(self):
        from src.tools.adoption_scorecard import _extract_purview
        data = _make_assessment_data(purview_pct=30.0, purview_gaps=8)
        result = _extract_purview(data)
        assert result["status"] == "red"
        assert result["coverage_pct"] == 30.0
        assert result["gaps_count"] == 8

    def test_without_data(self):
        from src.tools.adoption_scorecard import _extract_purview
        result = _extract_purview({})
        assert result["status"] == "unknown"


# ═══════════════════════════════════════════════════════════════════════
# 5. _extract_entra
# ═══════════════════════════════════════════════════════════════════════

class TestExtractEntra:
    def test_with_data(self):
        from src.tools.adoption_scorecard import _extract_entra
        data = _make_assessment_data(entra_pct=72.0, entra_gaps=2)
        result = _extract_entra(data)
        assert result["status"] == "green"
        assert result["coverage_pct"] == 72.0

    def test_without_data(self):
        from src.tools.adoption_scorecard import _extract_entra
        result = _extract_entra({})
        assert result["status"] == "unknown"

    def test_sub_workloads(self):
        from src.tools.adoption_scorecard import _extract_entra
        data = _make_assessment_data(entra_pct=50.0)
        result = _extract_entra(data)
        assert "Conditional Access" in result["sub_workloads"]
        assert "PIM" in result["sub_workloads"]
        # PIM is 50 - 20 = 30 → red
        assert result["sub_workloads"]["PIM"]["status"] == "red"


# ═══════════════════════════════════════════════════════════════════════
# 6. _default_workload
# ═══════════════════════════════════════════════════════════════════════

class TestDefaultWorkload:
    def test_returns_unknown(self):
        from src.tools.adoption_scorecard import _default_workload
        result = _default_workload()
        assert result["status"] == "unknown"
        assert result["coverage_pct"] == 0.0
        assert result["gaps_count"] == 0
        assert result["sub_workloads"] == {}


# ═══════════════════════════════════════════════════════════════════════
# 7. _collect_critical_gaps
# ═══════════════════════════════════════════════════════════════════════

class TestCollectCriticalGaps:
    def test_from_all_sources(self):
        from src.tools.adoption_scorecard import _collect_critical_gaps
        data = _make_assessment_data()
        gaps = _collect_critical_gaps(data)
        # defender_coverage: Gap A, Gap B − purview: Gap C − entra: legacy auth
        assert len(gaps) >= 3
        assert len(gaps) <= 5

    def test_includes_remediaton_p0_steps(self):
        from src.tools.adoption_scorecard import _collect_critical_gaps
        data = _make_assessment_data(include_remediation=True)
        gaps = _collect_critical_gaps(data)
        titles = [g["gap"] for g in gaps]
        # P0 step "Block legacy auth" should appear
        assert "Block legacy auth" in titles

    def test_no_remediaton_p1_steps(self):
        from src.tools.adoption_scorecard import _collect_critical_gaps
        data = _make_assessment_data(include_remediation=True)
        gaps = _collect_critical_gaps(data)
        titles = [g["gap"] for g in gaps]
        # P1 step should NOT appear
        assert "Enable MFA for all" not in titles

    def test_dedup_with_remediation(self):
        """Gap title matching existing gap should not be duplicated."""
        from src.tools.adoption_scorecard import _collect_critical_gaps
        data = _make_assessment_data(include_remediation=True)
        # Add a remediation step whose title matches an existing gap
        data["remediation_plan"]["steps"].append(
            {"priority": "P0", "title": "Gap A"}
        )
        gaps = _collect_critical_gaps(data)
        titles = [g["gap"] for g in gaps]
        assert titles.count("Gap A") == 1

    def test_max_five(self):
        from src.tools.adoption_scorecard import _collect_critical_gaps
        data = _make_assessment_data()
        # Add many critical gaps
        data["defender_coverage"]["critical_gaps"] = [f"Gap {i}" for i in range(20)]
        gaps = _collect_critical_gaps(data)
        assert len(gaps) <= 5

    def test_empty_data(self):
        from src.tools.adoption_scorecard import _collect_critical_gaps
        gaps = _collect_critical_gaps({})
        assert gaps == []

    def test_dict_gaps(self):
        from src.tools.adoption_scorecard import _collect_critical_gaps
        data = {
            "defender_coverage": {
                "critical_gaps": [
                    {"description": "MFA missing", "priority": "P0"},
                    {"gap": "Safe Links off", "priority": "P1"},
                ],
            },
        }
        gaps = _collect_critical_gaps(data)
        descs = [g["gap"] for g in gaps]
        assert "MFA missing" in descs
        assert "Safe Links off" in descs


# ═══════════════════════════════════════════════════════════════════════
# 8. _extract_days_to_green
# ═══════════════════════════════════════════════════════════════════════

class TestExtractDaysToGreen:
    def test_from_remediation_plan(self):
        from src.tools.adoption_scorecard import _extract_days_to_green
        data = _make_assessment_data(include_remediation=True, remediation_days=14)
        assert _extract_days_to_green(data) == 14

    def test_heuristic_from_gaps(self):
        from src.tools.adoption_scorecard import _extract_days_to_green
        data = _make_assessment_data(defender_gaps=5, purview_gaps=3, entra_gaps=2)
        # no remediation plan → heuristic: total_gaps * 2 = (5+3+2)*2 = 20
        result = _extract_days_to_green(data)
        assert result == 20

    def test_minimum_one_day(self):
        from src.tools.adoption_scorecard import _extract_days_to_green
        data = _make_assessment_data(defender_gaps=0, purview_gaps=0, entra_gaps=0)
        assert _extract_days_to_green(data) >= 1

    def test_no_data_at_all(self):
        from src.tools.adoption_scorecard import _extract_days_to_green
        result = _extract_days_to_green({})
        assert result >= 1


# ═══════════════════════════════════════════════════════════════════════
# 9. _generate_markdown_scorecard
# ═══════════════════════════════════════════════════════════════════════

class TestGenerateMarkdownScorecard:
    def test_contains_header(self):
        from src.tools.adoption_scorecard import _generate_markdown_scorecard
        workloads = {"Test Workload": {"status": "green", "coverage_pct": 80.0}}
        md = _generate_markdown_scorecard(workloads, [], 80.0, 5)
        assert "# PostureIQ" in md
        assert "ME5 Adoption Scorecard" in md

    def test_contains_overall_pct(self):
        from src.tools.adoption_scorecard import _generate_markdown_scorecard
        workloads = {"Test": {"status": "green", "coverage_pct": 80.0}}
        md = _generate_markdown_scorecard(workloads, [], 80.0, 5)
        assert "80.0%" in md

    def test_contains_workload_table(self):
        from src.tools.adoption_scorecard import _generate_markdown_scorecard
        workloads = {
            "Defender XDR": {"status": "yellow", "coverage_pct": 55.0},
            "Entra ID": {"status": "red", "coverage_pct": 20.0},
        }
        md = _generate_markdown_scorecard(workloads, [], 37.5, 10)
        assert "Defender XDR" in md
        assert "Entra ID" in md
        assert "🟡" in md
        assert "🔴" in md

    def test_contains_gaps(self):
        from src.tools.adoption_scorecard import _generate_markdown_scorecard
        gaps = [
            {"gap": "MFA missing", "priority": "P0", "workload": "Entra"},
        ]
        md = _generate_markdown_scorecard({}, gaps, 50.0, 10)
        assert "MFA missing" in md
        assert "P0" in md

    def test_green_status_message(self):
        from src.tools.adoption_scorecard import _generate_markdown_scorecard
        workloads = {"All": {"status": "green", "coverage_pct": 90.0}}
        md = _generate_markdown_scorecard(workloads, [], 90.0, 0)
        assert "GREEN ✅" in md

    def test_out_of_green_message(self):
        from src.tools.adoption_scorecard import _generate_markdown_scorecard
        workloads = {"All": {"status": "red", "coverage_pct": 20.0}}
        md = _generate_markdown_scorecard(workloads, [], 20.0, 30)
        assert "OUT OF GREEN" in md

    def test_days_to_green(self):
        from src.tools.adoption_scorecard import _generate_markdown_scorecard
        md = _generate_markdown_scorecard({}, [], 50.0, 42)
        assert "42" in md


# ═══════════════════════════════════════════════════════════════════════
# 10. Mock fallback path
# ═══════════════════════════════════════════════════════════════════════

class TestScorecardMockFallback:
    @pytest.mark.asyncio
    async def test_empty_context_returns_mock(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        result = await create_adoption_scorecard("")
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    async def test_invalid_json_returns_mock(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        result = await create_adoption_scorecard("not json!!!")
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    async def test_no_assessment_keys_returns_mock(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        result = await create_adoption_scorecard(json.dumps({"foo": "bar"}))
        assert result["data_source"] == "mock"

    @pytest.mark.asyncio
    async def test_mock_has_all_keys(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        result = await create_adoption_scorecard("")
        required_keys = {
            "overall_adoption_pct", "overall_status", "green_threshold",
            "workload_status", "top_5_gaps", "estimated_days_to_green",
            "scorecard_markdown", "disclaimer", "generated_at", "data_source",
        }
        assert required_keys.issubset(set(result.keys()))

    @pytest.mark.asyncio
    async def test_mock_workloads(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        result = await create_adoption_scorecard("")
        workloads = result["workload_status"]
        assert "Defender XDR" in workloads
        assert "Microsoft Purview" in workloads
        assert "Entra ID P2" in workloads

    @pytest.mark.asyncio
    async def test_mock_has_markdown(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        result = await create_adoption_scorecard("")
        assert "PostureIQ" in result["scorecard_markdown"]


# ═══════════════════════════════════════════════════════════════════════
# 11. Live data path
# ═══════════════════════════════════════════════════════════════════════

class TestScorecardLiveData:
    @pytest.mark.asyncio
    async def test_data_source_is_live(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data()
        result = await create_adoption_scorecard(json.dumps(data))
        assert result["data_source"] == "live"

    @pytest.mark.asyncio
    async def test_overall_pct_computed(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data(defender_pct=60.0, purview_pct=40.0, entra_pct=50.0)
        result = await create_adoption_scorecard(json.dumps(data))
        # average of 60, 40, 50 = 50.0
        assert result["overall_adoption_pct"] == 50.0

    @pytest.mark.asyncio
    async def test_overall_status_yellow(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data(defender_pct=60.0, purview_pct=40.0, entra_pct=50.0)
        result = await create_adoption_scorecard(json.dumps(data))
        assert result["overall_status"] == "yellow"

    @pytest.mark.asyncio
    async def test_overall_status_green(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data(defender_pct=80.0, purview_pct=75.0, entra_pct=90.0)
        result = await create_adoption_scorecard(json.dumps(data))
        assert result["overall_status"] == "green"

    @pytest.mark.asyncio
    async def test_overall_status_red(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data(defender_pct=10.0, purview_pct=20.0, entra_pct=15.0)
        result = await create_adoption_scorecard(json.dumps(data))
        assert result["overall_status"] == "red"

    @pytest.mark.asyncio
    async def test_workloads_extracted(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data()
        result = await create_adoption_scorecard(json.dumps(data))
        assert "Defender XDR" in result["workload_status"]
        assert "Microsoft Purview" in result["workload_status"]
        assert "Entra ID P2" in result["workload_status"]

    @pytest.mark.asyncio
    async def test_has_markdown(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data()
        result = await create_adoption_scorecard(json.dumps(data))
        assert "PostureIQ" in result["scorecard_markdown"]
        assert "Workload Summary" in result["scorecard_markdown"]

    @pytest.mark.asyncio
    async def test_days_from_remediation(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data(include_remediation=True, remediation_days=10)
        result = await create_adoption_scorecard(json.dumps(data))
        assert result["estimated_days_to_green"] == 10

    @pytest.mark.asyncio
    async def test_days_heuristic(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data(defender_gaps=3, purview_gaps=2, entra_gaps=1)
        result = await create_adoption_scorecard(json.dumps(data))
        # heuristic: (3+2+1)*2 = 12
        assert result["estimated_days_to_green"] == 12

    @pytest.mark.asyncio
    async def test_green_threshold(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data()
        result = await create_adoption_scorecard(json.dumps(data))
        assert result["green_threshold"] == 70.0

    @pytest.mark.asyncio
    async def test_partial_data_only_defender(self):
        """Only defender_coverage present — should still produce live result."""
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = {
            "defender_coverage": {
                "overall_coverage_pct": 55.0,
                "total_gaps": 4,
                "components": {},
                "critical_gaps": [],
            }
        }
        result = await create_adoption_scorecard(json.dumps(data))
        assert result["data_source"] == "live"
        # Only Defender is known; Purview + Entra are "unknown" and excluded from avg
        assert result["overall_adoption_pct"] == 55.0


# ═══════════════════════════════════════════════════════════════════════
# 12. Tracing
# ═══════════════════════════════════════════════════════════════════════

class TestScorecardTracing:
    @pytest.mark.asyncio
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_created(self, mock_tracer_fn):
        from src.tools.adoption_scorecard import create_adoption_scorecard

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await create_adoption_scorecard("")
        mock_tracer.start_as_current_span.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.middleware.tracing.get_tracer")
    async def test_span_name(self, mock_tracer_fn):
        from src.tools.adoption_scorecard import create_adoption_scorecard

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer = MagicMock()
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_tracer_fn.return_value = mock_tracer

        await create_adoption_scorecard("")
        call_args = mock_tracer.start_as_current_span.call_args
        # start_as_current_span uses keyword arg name=
        span_name = call_args.kwargs.get("name", call_args[0][0] if call_args[0] else "")
        assert "create_adoption_scorecard" in span_name


# ═══════════════════════════════════════════════════════════════════════
# 13. Edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestScorecardEdgeCases:
    @pytest.mark.asyncio
    async def test_all_unknown_workloads(self):
        """When no assessment keys match extraction, unknown workloads → 0% overall."""
        from src.tools.adoption_scorecard import create_adoption_scorecard
        # Has a key that triggers "live" path but no matching sub-keys
        data = {"secure_score": {"current_score": 50}}
        result = await create_adoption_scorecard(json.dumps(data))
        assert result["data_source"] == "live"
        assert result["overall_adoption_pct"] == 0.0

    @pytest.mark.asyncio
    async def test_disclaimer_present(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        result = await create_adoption_scorecard("")
        assert "PostureIQ" in result["disclaimer"]

    @pytest.mark.asyncio
    async def test_generated_at_is_iso(self):
        from src.tools.adoption_scorecard import create_adoption_scorecard
        result = await create_adoption_scorecard("")
        # Should not raise
        datetime.fromisoformat(result["generated_at"])

    @pytest.mark.asyncio
    async def test_sub_workload_status(self):
        """Verify sub-workload statuses follow thresholds."""
        from src.tools.adoption_scorecard import create_adoption_scorecard
        data = _make_assessment_data(defender_pct=60.0)
        result = await create_adoption_scorecard(json.dumps(data))
        defender = result["workload_status"]["Defender XDR"]
        # Endpoint = 65 → yellow, Office 365 = 50 → yellow
        assert defender["sub_workloads"]["Defender for Endpoint"]["status"] == "yellow"
        assert defender["sub_workloads"]["Defender for Office 365"]["status"] == "yellow"
