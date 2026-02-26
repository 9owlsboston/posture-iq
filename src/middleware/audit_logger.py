"""PostureIQ — Immutable audit logger.

Every agent action is logged as an immutable :class:`AuditEntry` with:
  - Timestamp (UTC, ISO-8601)
  - Session ID
  - User identity (from Entra ID token, PII-redacted)
  - Tool called
  - Input summary (PII-redacted, truncated)
  - Output summary (PII-redacted, truncated)
  - Reasoning chain (why the agent chose this tool)
  - Event type (tool_call, interaction, safety_event, session_start, session_end)
  - Duration (ms, for tool calls)

Storage:
  1. Structured JSON via structlog (stdout/file) for local dev
  2. App Insights ``customEvents`` table for production (queryable via KQL)

Retention:
  Configurable via ``AUDIT_RETENTION_DAYS`` (default 90).

RBAC:
  Audit log query requires the ``SecurityAdmin`` or ``AuditLog.Read`` role.
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
from src.middleware.pii_redaction import redact_pii

logger = structlog.get_logger(__name__)


# ── Configuration ──────────────────────────────────────────────────────

AUDIT_RETENTION_DAYS: int = 90
"""Default retention period (days) for audit entries in App Insights."""

MAX_INPUT_SUMMARY_LENGTH: int = 500
MAX_OUTPUT_SUMMARY_LENGTH: int = 500
MAX_REASONING_LENGTH: int = 300

# Roles allowed to query audit logs
AUDIT_READER_ROLES: frozenset[str] = frozenset({
    "SecurityAdmin",
    "AuditLog.Read",
    "GlobalAdmin",
})


# ── Immutable Audit Entry ──────────────────────────────────────────────


@dataclass(frozen=True)
class AuditEntry:
    """Immutable audit log entry.

    Fields cannot be modified after creation, guaranteeing the integrity
    of the audit trail. Each entry has a unique ``entry_id`` (UUID).

    Attributes:
        entry_id: Unique identifier for this audit entry (UUID v4).
        timestamp: UTC ISO-8601 timestamp.
        session_id: Session identifier correlating related entries.
        event_type: Category of event (``tool_call``, ``interaction``,
                    ``safety_event``, ``session_start``, ``session_end``).
        user_identity: PII-redacted user identity string.
        tool_name: Name of the tool invoked (if applicable).
        input_summary: PII-redacted, truncated summary of inputs.
        output_summary: PII-redacted, truncated summary of outputs.
        reasoning: Why the agent chose this action.
        duration_ms: Wall-clock duration in milliseconds.
        metadata: Extra key-value pairs (e.g. ``tools_called`` list).
        integrity_hash: SHA-256 hash of the core fields for tamper detection.
    """

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    session_id: str = ""
    event_type: str = ""
    user_identity: str = ""
    tool_name: str = ""
    input_summary: str = ""
    output_summary: str = ""
    reasoning: str = ""
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    integrity_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (for JSON / App Insights)."""
        return asdict(self)


def _compute_integrity_hash(entry: AuditEntry) -> str:
    """Compute a SHA-256 hash over core fields for tamper detection.

    The hash covers: timestamp, session_id, event_type, user_identity,
    tool_name, input_summary, output_summary, reasoning.
    """
    payload = "|".join([
        entry.timestamp,
        entry.session_id,
        entry.event_type,
        entry.user_identity,
        entry.tool_name,
        entry.input_summary,
        entry.output_summary,
        entry.reasoning,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _build_entry(
    *,
    session_id: str,
    event_type: str,
    user_identity: str = "dev-user",
    tool_name: str = "",
    input_summary: str = "",
    output_summary: str = "",
    reasoning: str = "",
    duration_ms: float = 0.0,
    metadata: dict[str, Any] | None = None,
) -> AuditEntry:
    """Construct a new immutable AuditEntry with PII redaction and integrity hash."""
    # Redact and truncate
    redacted_user = redact_pii(user_identity)
    redacted_input = redact_pii(input_summary[:MAX_INPUT_SUMMARY_LENGTH])
    redacted_output = redact_pii(output_summary[:MAX_OUTPUT_SUMMARY_LENGTH])
    safe_reasoning = reasoning[:MAX_REASONING_LENGTH]

    # Build entry without hash first
    entry = AuditEntry(
        session_id=session_id,
        event_type=event_type,
        user_identity=redacted_user,
        tool_name=tool_name,
        input_summary=redacted_input,
        output_summary=redacted_output,
        reasoning=safe_reasoning,
        duration_ms=round(duration_ms, 2),
        metadata=metadata or {},
    )

    # Compute integrity hash and create final entry
    integrity = _compute_integrity_hash(entry)
    # Since frozen=True, we use object.__setattr__ to finalize
    object.__setattr__(entry, "integrity_hash", integrity)
    return entry


def verify_integrity(entry: AuditEntry) -> bool:
    """Verify that an audit entry has not been tampered with.

    Recomputes the integrity hash from the core fields and compares
    it against the stored ``integrity_hash``.
    """
    expected = _compute_integrity_hash(entry)
    return entry.integrity_hash == expected


# ── App Insights Custom Event Emitter ──────────────────────────────────


def _emit_to_app_insights(entry: AuditEntry) -> None:
    """Emit an audit entry as a customEvent to App Insights via OpenTelemetry.

    Uses the OpenTelemetry Trace API to create zero-duration spans that
    appear as ``customEvents`` in the App Insights transaction search.
    """
    try:
        from opentelemetry import trace

        tracer = trace.get_tracer("postureiq.audit", "0.1.0")
        with tracer.start_as_current_span(
            name=f"audit.{entry.event_type}",
            attributes={
                "postureiq.audit.entry_id": entry.entry_id,
                "postureiq.audit.session_id": entry.session_id,
                "postureiq.audit.event_type": entry.event_type,
                "postureiq.audit.user_identity": entry.user_identity,
                "postureiq.audit.tool_name": entry.tool_name,
                "postureiq.audit.input_summary": entry.input_summary,
                "postureiq.audit.output_summary": entry.output_summary,
                "postureiq.audit.reasoning": entry.reasoning,
                "postureiq.audit.duration_ms": entry.duration_ms,
                "postureiq.audit.integrity_hash": entry.integrity_hash,
                "postureiq.audit.retention_days": AUDIT_RETENTION_DAYS,
            },
        ):
            pass  # zero-duration span → customEvent
    except Exception as exc:
        logger.warning(
            "audit.appinsights.emit_failed",
            error=str(exc),
            entry_id=entry.entry_id,
        )


# ── RBAC Enforcement ──────────────────────────────────────────────────


def check_audit_access(user_roles: list[str]) -> bool:
    """Check whether the user has permission to read audit logs.

    Requires one of: ``SecurityAdmin``, ``AuditLog.Read``, ``GlobalAdmin``.

    Args:
        user_roles: Roles assigned to the authenticated user.

    Returns:
        True if the user has at least one allowed role.
    """
    return bool(AUDIT_READER_ROLES & set(user_roles))


# ── AuditLogger Class ─────────────────────────────────────────────────


class AuditLogger:
    """Immutable audit trail for all PostureIQ agent actions.

    Every call produces a frozen :class:`AuditEntry` that is:
      1. Logged via structlog (JSON-structured, for stdout/file)
      2. Emitted to App Insights ``customEvents`` (for KQL queries)
      3. Stored in the in-memory ledger (for testing / local queries)

    The in-memory ledger is append-only — there is no delete or update API.
    """

    def __init__(self, session_id: str = "dev-session") -> None:
        self._session_id = session_id
        self._audit_log = structlog.get_logger("postureiq.audit")
        self._entries: list[AuditEntry] = []

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        """Return all audit entries as an immutable tuple."""
        return tuple(self._entries)

    def _record(self, entry: AuditEntry) -> AuditEntry:
        """Persist an entry: structlog + App Insights + in-memory ledger."""
        # 1. Structured log
        self._audit_log.info(
            f"audit.{entry.event_type}",
            **entry.to_dict(),
        )

        # 2. App Insights customEvent
        if settings.applicationinsights_connection_string:
            _emit_to_app_insights(entry)

        # 3. Append-only in-memory ledger
        self._entries.append(entry)

        return entry

    # ── Public Logging Methods ─────────────────────────────

    def log_tool_call(
        self,
        tool_name: str,
        input_params: dict[str, Any],
        output_summary: str,
        user_identity: str = "dev-user",
        reasoning: str = "",
        duration_ms: float = 0.0,
    ) -> AuditEntry:
        """Log a tool invocation to the audit trail.

        Returns:
            The frozen :class:`AuditEntry` that was recorded.
        """
        entry = _build_entry(
            session_id=self._session_id,
            event_type="tool_call",
            user_identity=user_identity,
            tool_name=tool_name,
            input_summary=json.dumps(input_params)[:MAX_INPUT_SUMMARY_LENGTH],
            output_summary=output_summary[:MAX_OUTPUT_SUMMARY_LENGTH],
            reasoning=reasoning,
            duration_ms=duration_ms,
        )
        return self._record(entry)

    def log_interaction(
        self,
        user_input: str,
        agent_response: str,
        user_identity: str = "dev-user",
        tools_called: list[str] | None = None,
    ) -> AuditEntry:
        """Log a user↔agent interaction to the audit trail.

        Returns:
            The frozen :class:`AuditEntry` that was recorded.
        """
        entry = _build_entry(
            session_id=self._session_id,
            event_type="interaction",
            user_identity=user_identity,
            input_summary=user_input[:MAX_INPUT_SUMMARY_LENGTH],
            output_summary=agent_response[:MAX_OUTPUT_SUMMARY_LENGTH],
            metadata={"tools_called": tools_called or []},
        )
        return self._record(entry)

    def log_safety_event(
        self,
        event_type: str,
        details: str,
        user_identity: str = "dev-user",
    ) -> AuditEntry:
        """Log a safety/RAI event (content blocked, injection detected, etc.).

        Returns:
            The frozen :class:`AuditEntry` that was recorded.
        """
        entry = _build_entry(
            session_id=self._session_id,
            event_type="safety_event",
            user_identity=user_identity,
            input_summary=details[:MAX_INPUT_SUMMARY_LENGTH],
            metadata={"safety_event_type": event_type},
        )
        return self._record(entry)

    def log_session_start(self, user_identity: str = "dev-user") -> AuditEntry:
        """Log session creation.

        Returns:
            The frozen :class:`AuditEntry` that was recorded.
        """
        entry = _build_entry(
            session_id=self._session_id,
            event_type="session_start",
            user_identity=user_identity,
        )
        return self._record(entry)

    def log_session_end(self, user_identity: str = "dev-user") -> AuditEntry:
        """Log session termination.

        Returns:
            The frozen :class:`AuditEntry` that was recorded.
        """
        entry = _build_entry(
            session_id=self._session_id,
            event_type="session_end",
            user_identity=user_identity,
        )
        return self._record(entry)

    # ── Query Methods ──────────────────────────────────────

    def query_entries(
        self,
        *,
        event_type: str | None = None,
        tool_name: str | None = None,
        user_identity: str | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries with optional filters.

        Args:
            event_type: Filter by event type.
            tool_name: Filter by tool name.
            user_identity: Filter by (redacted) user identity substring.
            limit: Maximum entries to return.

        Returns:
            List of matching :class:`AuditEntry` instances (newest first).
        """
        results = self._entries

        if event_type:
            results = [e for e in results if e.event_type == event_type]

        if tool_name:
            results = [e for e in results if e.tool_name == tool_name]

        if user_identity:
            results = [
                e for e in results
                if user_identity.lower() in e.user_identity.lower()
            ]

        # Newest first, limited
        return list(reversed(results))[:limit]

    def get_entry_by_id(self, entry_id: str) -> AuditEntry | None:
        """Retrieve a single audit entry by its ``entry_id``."""
        for e in self._entries:
            if e.entry_id == entry_id:
                return e
        return None
