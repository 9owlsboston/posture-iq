"""PostureIQ Tool — Fabric Telemetry Push.

Pushes security posture assessment snapshots to a **Microsoft Fabric
lakehouse** for longitudinal analysis and Power BI dashboarding.

After each assessment the agent writes a snapshot row containing:
  - Tenant ID (SHA-256 hashed for anonymity)
  - Assessment timestamp (UTC)
  - Secure Score (current value and max)
  - Per-workload scores (Defender, Purview, Entra)
  - Gap count
  - Estimated days to green
  - Summary metadata

When the Fabric lakehouse endpoint is not configured, snapshots are
stored in an in-memory buffer (useful for testing and local dev).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from src.agent.config import settings
from src.middleware.tracing import trace_tool_call

logger = structlog.get_logger(__name__)


# ── Constants ──────────────────────────────────────────────────────────

SNAPSHOT_SCHEMA_VERSION = "1.0"

# Required fields in every snapshot row
REQUIRED_SCHEMA_FIELDS: frozenset[str] = frozenset({
    "snapshot_id",
    "schema_version",
    "tenant_id_hash",
    "timestamp",
    "secure_score_current",
    "secure_score_max",
    "workload_scores",
    "gap_count",
    "estimated_days_to_green",
})


# ── Snapshot Dataclass ─────────────────────────────────────────────────


@dataclass(frozen=True)
class PostureSnapshot:
    """Immutable security posture snapshot for Fabric lakehouse.

    All tenant-identifying information is hashed before storage to
    comply with data anonymisation requirements.
    """

    snapshot_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = SNAPSHOT_SCHEMA_VERSION
    tenant_id_hash: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    secure_score_current: float = 0.0
    secure_score_max: float = 100.0
    secure_score_percentage: float = 0.0
    workload_scores: dict[str, float] = field(default_factory=dict)
    gap_count: int = 0
    estimated_days_to_green: int = 0
    top_gaps: list[str] = field(default_factory=list)
    assessment_summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON / lakehouse write."""
        return asdict(self)


# ── Anonymisation Helpers ──────────────────────────────────────────────


def hash_tenant_id(tenant_id: str) -> str:
    """SHA-256 hash a tenant identifier for anonymised storage.

    Empty or blank tenant IDs produce a stable empty-hash sentinel.

    Args:
        tenant_id: Raw tenant GUID.

    Returns:
        Hex-encoded SHA-256 digest (64 chars).
    """
    if not tenant_id or not tenant_id.strip():
        return hashlib.sha256(b"unknown-tenant").hexdigest()
    return hashlib.sha256(tenant_id.strip().lower().encode("utf-8")).hexdigest()


def anonymise_gaps(gaps: list[str], max_gaps: int = 5) -> list[str]:
    """Anonymise gap descriptions for lakehouse storage.

    Strips any tenant-specific identifiers and truncates to ``max_gaps``.

    Args:
        gaps: Raw gap descriptions.
        max_gaps: Maximum number of gaps to include.

    Returns:
        Truncated list of anonymised gap descriptions.
    """
    anonymised: list[str] = []
    for gap in gaps[:max_gaps]:
        # Remove common PII patterns (GUIDs, emails, IPs)
        import re

        clean = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "[TENANT]",
            gap,
            flags=re.IGNORECASE,
        )
        clean = re.sub(r"\S+@\S+\.\S+", "[EMAIL]", clean)
        clean = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]", clean)
        anonymised.append(clean)
    return anonymised


# ── Snapshot Builder ───────────────────────────────────────────────────


def build_snapshot(
    *,
    tenant_id: str = "",
    secure_score_current: float = 0.0,
    secure_score_max: float = 100.0,
    workload_scores: dict[str, float] | None = None,
    gap_count: int = 0,
    estimated_days_to_green: int = 0,
    top_gaps: list[str] | None = None,
    assessment_summary: str = "",
    metadata: dict[str, Any] | None = None,
) -> PostureSnapshot:
    """Build an anonymised posture snapshot.

    Args:
        tenant_id: Raw tenant identifier (will be hashed).
        secure_score_current: Current secure score value.
        secure_score_max: Maximum possible secure score.
        workload_scores: Per-workload coverage percentages.
        gap_count: Total number of identified gaps.
        estimated_days_to_green: Estimated days to achieve green status.
        top_gaps: Top gap descriptions (will be anonymised).
        assessment_summary: Brief text summary of the assessment.
        metadata: Additional key-value metadata.

    Returns:
        Frozen :class:`PostureSnapshot` ready for lakehouse write.
    """
    pct = round(
        (secure_score_current / secure_score_max * 100) if secure_score_max > 0 else 0.0,
        1,
    )

    return PostureSnapshot(
        tenant_id_hash=hash_tenant_id(tenant_id),
        secure_score_current=round(secure_score_current, 1),
        secure_score_max=round(secure_score_max, 1),
        secure_score_percentage=pct,
        workload_scores=workload_scores or {},
        gap_count=gap_count,
        estimated_days_to_green=estimated_days_to_green,
        top_gaps=anonymise_gaps(top_gaps or []),
        assessment_summary=assessment_summary[:500],
        metadata=metadata or {},
    )


def validate_snapshot(snapshot: PostureSnapshot) -> list[str]:
    """Validate a snapshot against the required schema.

    Returns:
        List of validation error messages. Empty if valid.
    """
    errors: list[str] = []
    d = snapshot.to_dict()

    for field_name in REQUIRED_SCHEMA_FIELDS:
        if field_name not in d:
            errors.append(f"Missing required field: {field_name}")

    if not snapshot.snapshot_id:
        errors.append("snapshot_id must not be empty")

    if not snapshot.tenant_id_hash:
        errors.append("tenant_id_hash must not be empty")

    if snapshot.secure_score_current < 0:
        errors.append("secure_score_current must be non-negative")

    if snapshot.secure_score_max <= 0:
        errors.append("secure_score_max must be positive")

    if snapshot.gap_count < 0:
        errors.append("gap_count must be non-negative")

    if snapshot.estimated_days_to_green < 0:
        errors.append("estimated_days_to_green must be non-negative")

    return errors


# ── Fabric Lakehouse Client ───────────────────────────────────────────


def _create_fabric_client() -> Any | None:
    """Create a Fabric lakehouse client.

    Returns None when the Fabric endpoint is not configured,
    enabling the in-memory fallback.
    """
    endpoint = settings.fabric_lakehouse_endpoint
    if not endpoint:
        logger.info(
            "tool.fabric_telemetry.client.skipped",
            reason="Fabric lakehouse endpoint not configured — using in-memory buffer",
        )
        return None

    try:
        # Placeholder for real Fabric SDK / REST client
        logger.info("tool.fabric_telemetry.client.created", endpoint=endpoint)
        return {"endpoint": endpoint}
    except Exception as exc:
        logger.warning(
            "tool.fabric_telemetry.client.error",
            error=str(exc),
        )
        return None


async def _write_to_lakehouse(
    client: dict[str, Any],
    snapshot: PostureSnapshot,
) -> bool:
    """Write a snapshot row to the Fabric lakehouse.

    Args:
        client: Fabric client dict (or SDK instance).
        snapshot: Posture snapshot to write.

    Returns:
        True if write succeeded.
    """
    try:
        # Placeholder — in production this would call the Fabric REST API
        # e.g. POST /lakehouse/tables/posture_snapshots/rows
        logger.info(
            "tool.fabric_telemetry.write_remote",
            snapshot_id=snapshot.snapshot_id,
            endpoint=client["endpoint"],
        )
        return True
    except Exception as exc:
        logger.warning(
            "tool.fabric_telemetry.write_failed",
            error=str(exc),
            snapshot_id=snapshot.snapshot_id,
        )
        return False


# ── In-Memory Snapshot Buffer ──────────────────────────────────────────

# Append-only buffer for local dev / testing
_snapshot_buffer: list[PostureSnapshot] = []


def get_snapshot_buffer() -> tuple[PostureSnapshot, ...]:
    """Return all buffered snapshots as an immutable tuple."""
    return tuple(_snapshot_buffer)


def clear_snapshot_buffer() -> None:
    """Clear the in-memory snapshot buffer (for testing)."""
    _snapshot_buffer.clear()


def query_snapshots(
    *,
    tenant_id_hash: str | None = None,
    limit: int = 100,
) -> list[PostureSnapshot]:
    """Query buffered snapshots with optional filter.

    Args:
        tenant_id_hash: Filter by hashed tenant ID.
        limit: Maximum results.

    Returns:
        List of matching snapshots (newest first).
    """
    results = list(_snapshot_buffer)

    if tenant_id_hash:
        results = [s for s in results if s.tenant_id_hash == tenant_id_hash]

    return list(reversed(results))[:limit]


# ── Public Tool Function ──────────────────────────────────────────────


@trace_tool_call("push_posture_snapshot")
async def push_posture_snapshot(
    *,
    tenant_id: str = "",
    secure_score_current: float = 0.0,
    secure_score_max: float = 100.0,
    workload_scores: dict[str, float] | None = None,
    gap_count: int = 0,
    estimated_days_to_green: int = 0,
    top_gaps: list[str] | None = None,
    assessment_summary: str = "",
) -> dict[str, Any]:
    """Push a security posture snapshot to the Fabric lakehouse.

    Called after each assessment to enable longitudinal dashboarding.
    The tenant ID is hashed and gaps are anonymised before storage.

    Args:
        tenant_id: Raw tenant identifier (will be hashed).
        secure_score_current: Current secure score value.
        secure_score_max: Maximum possible secure score.
        workload_scores: Per-workload coverage percentages.
        gap_count: Total number of identified gaps.
        estimated_days_to_green: Estimated days to green status.
        top_gaps: Top gap descriptions (will be anonymised).
        assessment_summary: Brief assessment summary.

    Returns:
        Dict confirming the write with snapshot_id, destination, and
        schema validation result.
    """
    # Build anonymised snapshot
    snapshot = build_snapshot(
        tenant_id=tenant_id,
        secure_score_current=secure_score_current,
        secure_score_max=secure_score_max,
        workload_scores=workload_scores,
        gap_count=gap_count,
        estimated_days_to_green=estimated_days_to_green,
        top_gaps=top_gaps,
        assessment_summary=assessment_summary,
    )

    # Validate
    validation_errors = validate_snapshot(snapshot)
    if validation_errors:
        logger.warning(
            "tool.fabric_telemetry.validation_failed",
            errors=validation_errors,
        )

    # Write to Fabric or buffer
    client = _create_fabric_client()
    destination: str
    write_success = True

    if client:
        write_success = await _write_to_lakehouse(client, snapshot)
        destination = "fabric_lakehouse"
    else:
        _snapshot_buffer.append(snapshot)
        destination = "in_memory_buffer"

    logger.info(
        "tool.fabric_telemetry.snapshot_written",
        snapshot_id=snapshot.snapshot_id,
        destination=destination,
        write_success=write_success,
    )

    return {
        "snapshot_id": snapshot.snapshot_id,
        "schema_version": snapshot.schema_version,
        "tenant_id_hash": snapshot.tenant_id_hash,
        "timestamp": snapshot.timestamp,
        "destination": destination,
        "write_success": write_success,
        "validation_errors": validation_errors,
        "secure_score_percentage": snapshot.secure_score_percentage,
        "gap_count": snapshot.gap_count,
        "estimated_days_to_green": snapshot.estimated_days_to_green,
    }


# ── Aggregation Helpers (for dashboarding) ─────────────────────────────


def compute_trend(
    snapshots: list[PostureSnapshot],
) -> list[dict[str, Any]]:
    """Compute a secure score trend from a list of snapshots.

    Args:
        snapshots: List of snapshots (should be for the same tenant).

    Returns:
        List of {timestamp, score, percentage} dicts in chronological order.
    """
    return [
        {
            "timestamp": s.timestamp,
            "score": s.secure_score_current,
            "percentage": s.secure_score_percentage,
            "gap_count": s.gap_count,
        }
        for s in sorted(snapshots, key=lambda s: s.timestamp)
    ]


def compute_common_gaps(
    snapshots: list[PostureSnapshot],
    top_n: int = 10,
) -> list[dict[str, Any]]:
    """Aggregate most common gaps across all snapshots.

    Args:
        snapshots: List of snapshots (may span multiple tenants).
        top_n: Number of top gaps to return.

    Returns:
        List of {gap, count} dicts sorted by frequency descending.
    """
    from collections import Counter

    counter: Counter[str] = Counter()
    for s in snapshots:
        for gap in s.top_gaps:
            counter[gap] += 1

    return [
        {"gap": gap, "count": count}
        for gap, count in counter.most_common(top_n)
    ]


def compute_avg_days_to_green(snapshots: list[PostureSnapshot]) -> float:
    """Compute average estimated days-to-green across snapshots.

    Args:
        snapshots: List of posture snapshots.

    Returns:
        Average days-to-green, or 0.0 if no snapshots.
    """
    if not snapshots:
        return 0.0
    total = sum(s.estimated_days_to_green for s in snapshots)
    return round(total / len(snapshots), 1)
