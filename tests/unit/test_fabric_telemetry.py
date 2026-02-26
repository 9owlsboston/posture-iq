"""Comprehensive tests for Task 4.2 — Fabric Integration (Telemetry Push).

Covers:
  - Snapshot schema validation (hashed tenant ID, scores, gaps)
  - Data anonymisation (tenant ID hashing, gap PII removal)
  - Lakehouse write with mocked Fabric API
  - In-memory buffer operations (append, query, clear)
  - Snapshot immutability (frozen dataclass)
  - Aggregation helpers (trend, common gaps, avg days-to-green)
  - Power BI dashboard template validation
  - Edge cases
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from unittest.mock import patch

import pytest

from src.tools.fabric_telemetry import (
    REQUIRED_SCHEMA_FIELDS,
    SNAPSHOT_SCHEMA_VERSION,
    PostureSnapshot,
    anonymise_gaps,
    build_snapshot,
    clear_snapshot_buffer,
    compute_avg_days_to_green,
    compute_common_gaps,
    compute_trend,
    get_snapshot_buffer,
    hash_tenant_id,
    push_posture_snapshot,
    query_snapshots,
    validate_snapshot,
)

# ── Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_buffer():
    """Clear the in-memory snapshot buffer before each test."""
    clear_snapshot_buffer()
    yield
    clear_snapshot_buffer()


def _make_snapshot(**kwargs) -> PostureSnapshot:
    """Helper to build a snapshot with sensible defaults."""
    defaults = {
        "tenant_id": "12345678-1234-1234-1234-123456789abc",
        "secure_score_current": 72.0,
        "secure_score_max": 100.0,
        "workload_scores": {
            "defender_xdr": 80.0,
            "purview": 60.0,
            "entra_id_p2": 75.0,
        },
        "gap_count": 8,
        "estimated_days_to_green": 45,
        "top_gaps": ["MFA not enforced", "No DLP policies"],
    }
    defaults.update(kwargs)
    return build_snapshot(**defaults)


# ========================================================================
# SECTION 1: Tenant ID Hashing
# ========================================================================


class TestHashTenantId:
    """Test tenant ID anonymisation."""

    def test_produces_64_char_hex(self):
        h = hash_tenant_id("12345678-1234-1234-1234-123456789abc")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic(self):
        h1 = hash_tenant_id("test-tenant")
        h2 = hash_tenant_id("test-tenant")
        assert h1 == h2

    def test_case_insensitive(self):
        h1 = hash_tenant_id("ABC-123")
        h2 = hash_tenant_id("abc-123")
        assert h1 == h2

    def test_different_tenants_different_hashes(self):
        h1 = hash_tenant_id("tenant-a")
        h2 = hash_tenant_id("tenant-b")
        assert h1 != h2

    def test_empty_tenant_id(self):
        h = hash_tenant_id("")
        assert len(h) == 64  # produces sentinel hash

    def test_none_like_blank(self):
        h1 = hash_tenant_id("")
        h2 = hash_tenant_id("   ")
        assert h1 == h2  # both produce sentinel

    def test_strips_whitespace(self):
        h1 = hash_tenant_id("  test  ")
        h2 = hash_tenant_id("test")
        assert h1 == h2


# ========================================================================
# SECTION 2: Gap Anonymisation
# ========================================================================


class TestAnonymiseGaps:
    """Test PII removal from gap descriptions."""

    def test_removes_guids(self):
        gaps = ["Tenant 12345678-1234-1234-1234-123456789abc has issues"]
        result = anonymise_gaps(gaps)
        assert "12345678-1234-1234-1234-123456789abc" not in result[0]
        assert "[TENANT]" in result[0]

    def test_removes_emails(self):
        gaps = ["Alert for admin@contoso.com"]
        result = anonymise_gaps(gaps)
        assert "admin@contoso.com" not in result[0]
        assert "[EMAIL]" in result[0]

    def test_removes_ips(self):
        gaps = ["Connection from 192.168.1.100"]
        result = anonymise_gaps(gaps)
        assert "192.168.1.100" not in result[0]
        assert "[IP]" in result[0]

    def test_truncates_to_max_gaps(self):
        gaps = [f"Gap {i}" for i in range(20)]
        result = anonymise_gaps(gaps, max_gaps=5)
        assert len(result) == 5

    def test_clean_gaps_pass_through(self):
        gaps = ["MFA not enforced for all users"]
        result = anonymise_gaps(gaps)
        assert result[0] == "MFA not enforced for all users"

    def test_empty_list(self):
        assert anonymise_gaps([]) == []


# ========================================================================
# SECTION 3: Snapshot Building
# ========================================================================


class TestBuildSnapshot:
    """Test build_snapshot() constructor."""

    def test_returns_posture_snapshot(self):
        snap = _make_snapshot()
        assert isinstance(snap, PostureSnapshot)

    def test_tenant_id_is_hashed(self):
        snap = _make_snapshot(tenant_id="raw-tenant-id")
        assert snap.tenant_id_hash != "raw-tenant-id"
        assert len(snap.tenant_id_hash) == 64

    def test_score_rounded(self):
        snap = _make_snapshot(secure_score_current=72.345)
        assert snap.secure_score_current == 72.3

    def test_percentage_calculated(self):
        snap = _make_snapshot(secure_score_current=72, secure_score_max=100)
        assert snap.secure_score_percentage == 72.0

    def test_percentage_with_custom_max(self):
        snap = _make_snapshot(secure_score_current=50, secure_score_max=200)
        assert snap.secure_score_percentage == 25.0

    def test_gaps_anonymised(self):
        snap = _make_snapshot(top_gaps=["Tenant 12345678-1234-1234-1234-123456789abc exposed"])
        assert "12345678" not in snap.top_gaps[0]

    def test_summary_truncated(self):
        snap = _make_snapshot(assessment_summary="x" * 1000)
        assert len(snap.assessment_summary) <= 500

    def test_has_uuid_snapshot_id(self):
        snap = _make_snapshot()
        assert len(snap.snapshot_id) == 36

    def test_has_timestamp(self):
        snap = _make_snapshot()
        assert "T" in snap.timestamp

    def test_has_schema_version(self):
        snap = _make_snapshot()
        assert snap.schema_version == SNAPSHOT_SCHEMA_VERSION

    def test_workload_scores_preserved(self):
        scores = {"defender_xdr": 80.0, "purview": 60.0}
        snap = _make_snapshot(workload_scores=scores)
        assert snap.workload_scores == scores


# ========================================================================
# SECTION 4: Snapshot Immutability
# ========================================================================


class TestSnapshotImmutability:
    """PostureSnapshot must be frozen."""

    def test_cannot_modify_tenant_hash(self):
        snap = _make_snapshot()
        with pytest.raises(FrozenInstanceError):
            snap.tenant_id_hash = "tampered"  # type: ignore[misc]

    def test_cannot_modify_score(self):
        snap = _make_snapshot()
        with pytest.raises(FrozenInstanceError):
            snap.secure_score_current = 100.0  # type: ignore[misc]

    def test_cannot_modify_gap_count(self):
        snap = _make_snapshot()
        with pytest.raises(FrozenInstanceError):
            snap.gap_count = 0  # type: ignore[misc]

    def test_cannot_delete_field(self):
        snap = _make_snapshot()
        with pytest.raises(FrozenInstanceError):
            del snap.timestamp  # type: ignore[misc]


# ========================================================================
# SECTION 5: Schema Validation
# ========================================================================


class TestValidateSnapshot:
    """Test validate_snapshot() schema checks."""

    def test_valid_snapshot_passes(self):
        snap = _make_snapshot()
        errors = validate_snapshot(snap)
        assert errors == []

    def test_negative_score_fails(self):
        snap = PostureSnapshot(
            tenant_id_hash="abc",
            secure_score_current=-5,
            secure_score_max=100,
        )
        errors = validate_snapshot(snap)
        assert any("non-negative" in e for e in errors)

    def test_zero_max_score_fails(self):
        snap = PostureSnapshot(
            tenant_id_hash="abc",
            secure_score_current=50,
            secure_score_max=0,
        )
        errors = validate_snapshot(snap)
        assert any("positive" in e for e in errors)

    def test_negative_gap_count_fails(self):
        snap = PostureSnapshot(
            tenant_id_hash="abc",
            gap_count=-1,
        )
        errors = validate_snapshot(snap)
        assert any("gap_count" in e for e in errors)

    def test_negative_days_to_green_fails(self):
        snap = PostureSnapshot(
            tenant_id_hash="abc",
            estimated_days_to_green=-10,
        )
        errors = validate_snapshot(snap)
        assert any("estimated_days_to_green" in e for e in errors)

    def test_required_fields_constant(self):
        assert "snapshot_id" in REQUIRED_SCHEMA_FIELDS
        assert "tenant_id_hash" in REQUIRED_SCHEMA_FIELDS
        assert "secure_score_current" in REQUIRED_SCHEMA_FIELDS
        assert "workload_scores" in REQUIRED_SCHEMA_FIELDS
        assert "gap_count" in REQUIRED_SCHEMA_FIELDS


# ========================================================================
# SECTION 6: to_dict Serialisation
# ========================================================================


class TestSnapshotSerialisation:
    """Test snapshot serialisation."""

    def test_to_dict_returns_all_fields(self):
        snap = _make_snapshot()
        d = snap.to_dict()
        assert "snapshot_id" in d
        assert "tenant_id_hash" in d
        assert "secure_score_current" in d
        assert "workload_scores" in d
        assert "gap_count" in d
        assert "estimated_days_to_green" in d
        assert "top_gaps" in d

    def test_json_serialisable(self):
        snap = _make_snapshot()
        serialised = json.dumps(snap.to_dict(), default=str)
        assert serialised

    def test_to_dict_preserves_values(self):
        snap = _make_snapshot(secure_score_current=85.0, gap_count=3)
        d = snap.to_dict()
        assert d["secure_score_current"] == 85.0
        assert d["gap_count"] == 3


# ========================================================================
# SECTION 7: push_posture_snapshot Tool
# ========================================================================


class TestPushPostureSnapshot:
    """Test the public push_posture_snapshot tool function."""

    @pytest.mark.asyncio
    async def test_writes_to_buffer_when_no_fabric(self):
        result = await push_posture_snapshot(
            tenant_id="test-tenant",
            secure_score_current=72.0,
            gap_count=5,
        )
        assert result["destination"] == "in_memory_buffer"
        assert result["write_success"] is True
        assert len(get_snapshot_buffer()) == 1

    @pytest.mark.asyncio
    async def test_result_has_snapshot_id(self):
        result = await push_posture_snapshot(tenant_id="t1")
        assert result["snapshot_id"]
        assert len(result["snapshot_id"]) == 36

    @pytest.mark.asyncio
    async def test_result_has_tenant_hash(self):
        result = await push_posture_snapshot(tenant_id="my-tenant")
        assert result["tenant_id_hash"]
        assert result["tenant_id_hash"] == hash_tenant_id("my-tenant")

    @pytest.mark.asyncio
    async def test_result_has_schema_version(self):
        result = await push_posture_snapshot(tenant_id="t1")
        assert result["schema_version"] == SNAPSHOT_SCHEMA_VERSION

    @pytest.mark.asyncio
    async def test_result_has_timestamp(self):
        result = await push_posture_snapshot(tenant_id="t1")
        assert "T" in result["timestamp"]

    @pytest.mark.asyncio
    async def test_validation_errors_empty_for_valid(self):
        result = await push_posture_snapshot(
            tenant_id="t1",
            secure_score_current=80,
            secure_score_max=100,
        )
        assert result["validation_errors"] == []

    @pytest.mark.asyncio
    async def test_multiple_pushes_accumulate(self):
        await push_posture_snapshot(tenant_id="t1")
        await push_posture_snapshot(tenant_id="t2")
        await push_posture_snapshot(tenant_id="t3")
        assert len(get_snapshot_buffer()) == 3

    @pytest.mark.asyncio
    @patch("src.tools.fabric_telemetry._write_to_lakehouse")
    @patch("src.tools.fabric_telemetry._create_fabric_client")
    async def test_writes_to_fabric_when_available(self, mock_client, mock_write):
        mock_client.return_value = {"endpoint": "https://fabric.example.com"}
        mock_write.return_value = True

        result = await push_posture_snapshot(
            tenant_id="t1",
            secure_score_current=85.0,
        )
        assert result["destination"] == "fabric_lakehouse"
        assert result["write_success"] is True
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.tools.fabric_telemetry._write_to_lakehouse")
    @patch("src.tools.fabric_telemetry._create_fabric_client")
    async def test_fabric_write_failure(self, mock_client, mock_write):
        mock_client.return_value = {"endpoint": "https://fabric.example.com"}
        mock_write.return_value = False

        result = await push_posture_snapshot(tenant_id="t1")
        assert result["write_success"] is False


# ========================================================================
# SECTION 8: In-Memory Buffer Operations
# ========================================================================


class TestSnapshotBuffer:
    """Test in-memory buffer operations."""

    def test_buffer_starts_empty(self):
        assert len(get_snapshot_buffer()) == 0

    @pytest.mark.asyncio
    async def test_buffer_is_tuple(self):
        await push_posture_snapshot(tenant_id="t1")
        buf = get_snapshot_buffer()
        assert isinstance(buf, tuple)

    @pytest.mark.asyncio
    async def test_clear_buffer(self):
        await push_posture_snapshot(tenant_id="t1")
        assert len(get_snapshot_buffer()) == 1
        clear_snapshot_buffer()
        assert len(get_snapshot_buffer()) == 0


# ========================================================================
# SECTION 9: Query Snapshots
# ========================================================================


class TestQuerySnapshots:
    """Test query_snapshots() filtering."""

    @pytest.mark.asyncio
    async def test_query_all(self):
        await push_posture_snapshot(tenant_id="t1")
        await push_posture_snapshot(tenant_id="t2")
        results = query_snapshots()
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_query_by_tenant_hash(self):
        await push_posture_snapshot(tenant_id="t1")
        await push_posture_snapshot(tenant_id="t2")
        h = hash_tenant_id("t1")
        results = query_snapshots(tenant_id_hash=h)
        assert len(results) == 1
        assert results[0].tenant_id_hash == h

    @pytest.mark.asyncio
    async def test_query_with_limit(self):
        for i in range(10):
            await push_posture_snapshot(tenant_id=f"t{i}")
        results = query_snapshots(limit=3)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_query_newest_first(self):
        await push_posture_snapshot(tenant_id="first")
        await push_posture_snapshot(tenant_id="second")
        results = query_snapshots()
        # Newest (second) should come first
        assert results[0].tenant_id_hash == hash_tenant_id("second")


# ========================================================================
# SECTION 10: Aggregation — Trend
# ========================================================================


class TestComputeTrend:
    """Test secure score trend computation."""

    def test_trend_sorted_chronologically(self):
        s1 = PostureSnapshot(
            timestamp="2026-01-01T00:00:00",
            secure_score_current=60,
            secure_score_percentage=60.0,
        )
        s2 = PostureSnapshot(
            timestamp="2026-02-01T00:00:00",
            secure_score_current=70,
            secure_score_percentage=70.0,
        )
        s3 = PostureSnapshot(
            timestamp="2026-03-01T00:00:00",
            secure_score_current=80,
            secure_score_percentage=80.0,
        )
        trend = compute_trend([s3, s1, s2])  # out of order
        assert trend[0]["score"] == 60
        assert trend[1]["score"] == 70
        assert trend[2]["score"] == 80

    def test_trend_contains_expected_fields(self):
        s = PostureSnapshot(
            timestamp="2026-01-01T00:00:00",
            secure_score_current=72,
            secure_score_percentage=72.0,
            gap_count=5,
        )
        trend = compute_trend([s])
        assert "timestamp" in trend[0]
        assert "score" in trend[0]
        assert "percentage" in trend[0]
        assert "gap_count" in trend[0]

    def test_empty_snapshots(self):
        assert compute_trend([]) == []


# ========================================================================
# SECTION 11: Aggregation — Common Gaps
# ========================================================================


class TestComputeCommonGaps:
    """Test gap frequency aggregation."""

    def test_counts_gap_frequency(self):
        s1 = PostureSnapshot(top_gaps=["MFA missing", "No DLP"])
        s2 = PostureSnapshot(top_gaps=["MFA missing", "No retention"])
        s3 = PostureSnapshot(top_gaps=["MFA missing"])
        result = compute_common_gaps([s1, s2, s3])
        assert result[0]["gap"] == "MFA missing"
        assert result[0]["count"] == 3

    def test_top_n_limits(self):
        snapshots = [PostureSnapshot(top_gaps=[f"Gap {i}" for i in range(20)])]
        result = compute_common_gaps(snapshots, top_n=5)
        assert len(result) == 5

    def test_empty_snapshots(self):
        assert compute_common_gaps([]) == []

    def test_no_gaps_in_snapshots(self):
        s = PostureSnapshot(top_gaps=[])
        assert compute_common_gaps([s]) == []


# ========================================================================
# SECTION 12: Aggregation — Average Days to Green
# ========================================================================


class TestComputeAvgDaysToGreen:
    """Test average days-to-green calculation."""

    def test_average(self):
        s1 = PostureSnapshot(estimated_days_to_green=30)
        s2 = PostureSnapshot(estimated_days_to_green=60)
        s3 = PostureSnapshot(estimated_days_to_green=90)
        avg = compute_avg_days_to_green([s1, s2, s3])
        assert avg == 60.0

    def test_single_snapshot(self):
        s = PostureSnapshot(estimated_days_to_green=45)
        assert compute_avg_days_to_green([s]) == 45.0

    def test_empty_returns_zero(self):
        assert compute_avg_days_to_green([]) == 0.0

    def test_rounded(self):
        s1 = PostureSnapshot(estimated_days_to_green=10)
        s2 = PostureSnapshot(estimated_days_to_green=20)
        s3 = PostureSnapshot(estimated_days_to_green=30)
        avg = compute_avg_days_to_green([s1, s2, s3])
        assert avg == 20.0


# ========================================================================
# SECTION 13: Power BI Dashboard Template
# ========================================================================


class TestPowerBIDashboardTemplate:
    """Validate the Power BI dashboard template JSON."""

    @pytest.fixture
    def template(self) -> dict:
        import pathlib

        path = pathlib.Path(__file__).parent.parent.parent / "infra" / "dashboards" / "powerbi-posture-dashboard.json"
        with open(path) as f:
            return json.load(f)

    def test_template_loads_valid_json(self, template):
        assert isinstance(template, dict)

    def test_has_name(self, template):
        assert "PostureIQ" in template["name"]

    def test_has_data_source(self, template):
        assert template["dataSource"]["type"] == "fabric_lakehouse"
        assert template["dataSource"]["table"] == "posture_snapshots"

    def test_has_schema(self, template):
        schema = template["dataSource"]["schema"]
        assert "tenant_id_hash" in schema
        assert "secure_score_current" in schema
        assert "gap_count" in schema
        assert "estimated_days_to_green" in schema

    def test_has_three_pages(self, template):
        assert len(template["pages"]) == 3

    def test_page_names(self, template):
        page_names = [p["name"] for p in template["pages"]]
        assert "Secure Score Trend" in page_names
        assert "Most Common Gaps" in page_names
        assert "Time to Green" in page_names

    def test_score_trend_page_has_line_chart(self, template):
        page = template["pages"][0]
        visual_types = [v["type"] for v in page["visuals"]]
        assert "lineChart" in visual_types

    def test_gaps_page_has_bar_chart(self, template):
        page = template["pages"][1]
        visual_types = [v["type"] for v in page["visuals"]]
        assert "barChart" in visual_types

    def test_time_to_green_page_has_gauge(self, template):
        page = template["pages"][2]
        visual_types = [v["type"] for v in page["visuals"]]
        assert "gauge" in visual_types

    def test_has_theme(self, template):
        assert "theme" in template
        assert template["theme"]["primary"] == "#0078D4"

    def test_has_refresh_schedule(self, template):
        assert template["refreshSchedule"]["frequency"] == "daily"


# ========================================================================
# SECTION 14: Edge Cases
# ========================================================================


class TestEdgeCases:
    """Edge case tests for fabric telemetry."""

    @pytest.mark.asyncio
    async def test_zero_score(self):
        result = await push_posture_snapshot(
            tenant_id="t1",
            secure_score_current=0,
            secure_score_max=100,
        )
        assert result["secure_score_percentage"] == 0.0
        assert result["validation_errors"] == []

    @pytest.mark.asyncio
    async def test_perfect_score(self):
        result = await push_posture_snapshot(
            tenant_id="t1",
            secure_score_current=100,
            secure_score_max=100,
        )
        assert result["secure_score_percentage"] == 100.0

    @pytest.mark.asyncio
    async def test_no_gaps(self):
        result = await push_posture_snapshot(
            tenant_id="t1",
            gap_count=0,
            top_gaps=[],
        )
        assert result["gap_count"] == 0

    @pytest.mark.asyncio
    async def test_empty_tenant_id(self):
        result = await push_posture_snapshot(tenant_id="")
        assert result["tenant_id_hash"]  # should get sentinel hash

    @pytest.mark.asyncio
    async def test_result_json_serialisable(self):
        result = await push_posture_snapshot(
            tenant_id="t1",
            secure_score_current=72,
            workload_scores={"defender": 80.0},
            top_gaps=["MFA gap"],
        )
        serialised = json.dumps(result, default=str)
        assert serialised

    def test_snapshot_schema_version_constant(self):
        assert SNAPSHOT_SCHEMA_VERSION == "1.0"
