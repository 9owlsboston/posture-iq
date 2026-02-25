"""Unit tests for secure_score tool."""

import pytest
from src.tools.secure_score import query_secure_score


class TestQuerySecureScore:
    """Tests for the query_secure_score() function."""

    @pytest.mark.asyncio
    async def test_returns_expected_fields(self):
        result = await query_secure_score()
        assert "current_score" in result
        assert "max_score" in result
        assert "categories" in result
        assert "trend_30d" in result

    @pytest.mark.asyncio
    async def test_score_within_range(self):
        result = await query_secure_score()
        assert 0 <= result["current_score"] <= result["max_score"]

    @pytest.mark.asyncio
    async def test_has_category_breakdown(self):
        result = await query_secure_score()
        categories = result["categories"]
        assert len(categories) > 0
        for name, details in categories.items():
            assert isinstance(name, str)
            assert "score" in details
            assert "max_score" in details

    @pytest.mark.asyncio
    async def test_has_gap_to_green(self):
        result = await query_secure_score()
        assert "gap_to_green" in result
        assert result["gap_to_green"] >= 0
