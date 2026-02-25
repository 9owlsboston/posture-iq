"""PostureIQ — Immutable audit logger.

Logs every agent action with user identity, tool calls, inputs/outputs,
and reasoning chains. Stored in App Insights customEvents table (queryable via KQL).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import structlog

from src.middleware.pii_redaction import redact_pii

logger = structlog.get_logger(__name__)


class AuditLogger:
    """Immutable audit trail for all PostureIQ agent actions.

    Every interaction is logged with:
      - Timestamp (UTC)
      - Session ID
      - User identity (from Entra ID token)
      - Tool called (if applicable)
      - Input summary (PII-redacted)
      - Output summary (PII-redacted)
      - Reasoning chain context

    Logs are written to:
      1. Structured JSON (stdout/file) for local dev
      2. App Insights customEvents table for production (queryable via KQL)
    """

    def __init__(self, session_id: str = "dev-session") -> None:
        self._session_id = session_id
        self._audit_log = structlog.get_logger("postureiq.audit")

    def log_tool_call(
        self,
        tool_name: str,
        input_params: dict[str, Any],
        output_summary: str,
        user_identity: str = "dev-user",
        reasoning: str = "",
        duration_ms: float = 0.0,
    ) -> None:
        """Log a tool invocation to the audit trail."""
        self._audit_log.info(
            "audit.tool_call",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self._session_id,
            user_identity=redact_pii(user_identity),
            tool_name=tool_name,
            input_summary=redact_pii(json.dumps(input_params)[:500]),
            output_summary=redact_pii(output_summary[:500]),
            reasoning=reasoning[:300],
            duration_ms=round(duration_ms, 2),
        )

    def log_interaction(
        self,
        user_input: str,
        agent_response: str,
        user_identity: str = "dev-user",
        tools_called: list[str] | None = None,
    ) -> None:
        """Log a user↔agent interaction to the audit trail."""
        self._audit_log.info(
            "audit.interaction",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self._session_id,
            user_identity=redact_pii(user_identity),
            user_input_preview=redact_pii(user_input[:200]),
            agent_response_preview=redact_pii(agent_response[:200]),
            tools_called=tools_called or [],
        )

    def log_safety_event(
        self,
        event_type: str,
        details: str,
        user_identity: str = "dev-user",
    ) -> None:
        """Log a safety/RAI event (content blocked, injection detected, etc.)."""
        self._audit_log.warning(
            "audit.safety_event",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self._session_id,
            user_identity=redact_pii(user_identity),
            event_type=event_type,
            details=redact_pii(details[:500]),
        )

    def log_session_start(self, user_identity: str = "dev-user") -> None:
        """Log session creation."""
        self._audit_log.info(
            "audit.session_start",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self._session_id,
            user_identity=redact_pii(user_identity),
        )

    def log_session_end(self, user_identity: str = "dev-user") -> None:
        """Log session termination."""
        self._audit_log.info(
            "audit.session_end",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self._session_id,
            user_identity=redact_pii(user_identity),
        )
