"""Comprehensive tests for Task 3.3 — Audit Trail.

Covers:
  - AuditEntry immutability (frozen dataclass, no update/delete)
  - Required fields present (timestamp, session_id, user, tool, redacted I/O, reasoning)
  - PII redaction in audit entries
  - Integrity hash computation & tamper detection
  - AuditLogger operations (tool_call, interaction, safety_event, session lifecycle)
  - In-memory ledger (append-only, query, get_by_id)
  - RBAC enforcement on audit log access
  - App Insights emission (mocked)
  - Retention policy configuration
  - Audit query endpoint (/audit/logs) with RBAC
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from unittest.mock import patch

import pytest

from src.middleware.audit_logger import (
    AUDIT_READER_ROLES,
    AUDIT_RETENTION_DAYS,
    MAX_INPUT_SUMMARY_LENGTH,
    MAX_OUTPUT_SUMMARY_LENGTH,
    MAX_REASONING_LENGTH,
    AuditEntry,
    AuditLogger,
    _build_entry,
    _compute_integrity_hash,
    check_audit_access,
    verify_integrity,
)

# ========================================================================
# SECTION 1: AuditEntry Immutability
# ========================================================================


class TestAuditEntryImmutability:
    """The AuditEntry dataclass must be frozen (immutable)."""

    def test_cannot_modify_timestamp(self):
        entry = AuditEntry(session_id="s1", event_type="test")
        with pytest.raises(FrozenInstanceError):
            entry.timestamp = "2024-01-01T00:00:00"  # type: ignore[misc]

    def test_cannot_modify_session_id(self):
        entry = AuditEntry(session_id="s1", event_type="test")
        with pytest.raises(FrozenInstanceError):
            entry.session_id = "tampered"  # type: ignore[misc]

    def test_cannot_modify_event_type(self):
        entry = AuditEntry(session_id="s1", event_type="tool_call")
        with pytest.raises(FrozenInstanceError):
            entry.event_type = "tampered"  # type: ignore[misc]

    def test_cannot_modify_user_identity(self):
        entry = AuditEntry(session_id="s1", event_type="test", user_identity="user@x.com")
        with pytest.raises(FrozenInstanceError):
            entry.user_identity = "hacker"  # type: ignore[misc]

    def test_cannot_modify_tool_name(self):
        entry = AuditEntry(session_id="s1", event_type="test", tool_name="secure_score")
        with pytest.raises(FrozenInstanceError):
            entry.tool_name = "malicious_tool"  # type: ignore[misc]

    def test_cannot_modify_input_summary(self):
        entry = AuditEntry(session_id="s1", event_type="test")
        with pytest.raises(FrozenInstanceError):
            entry.input_summary = "modified"  # type: ignore[misc]

    def test_cannot_modify_output_summary(self):
        entry = AuditEntry(session_id="s1", event_type="test")
        with pytest.raises(FrozenInstanceError):
            entry.output_summary = "modified"  # type: ignore[misc]

    def test_cannot_modify_integrity_hash(self):
        entry = AuditEntry(session_id="s1", event_type="test", integrity_hash="abc")
        with pytest.raises(FrozenInstanceError):
            entry.integrity_hash = "forged"  # type: ignore[misc]

    def test_cannot_delete_field(self):
        entry = AuditEntry(session_id="s1", event_type="test")
        with pytest.raises(FrozenInstanceError):
            del entry.session_id  # type: ignore[misc]


# ========================================================================
# SECTION 2: AuditEntry Required Fields
# ========================================================================


class TestAuditEntryRequiredFields:
    """Every AuditEntry must contain all required fields."""

    def test_entry_has_entry_id(self):
        entry = AuditEntry(session_id="s1", event_type="test")
        assert entry.entry_id  # non-empty UUID
        assert len(entry.entry_id) == 36  # UUID format

    def test_entry_has_timestamp(self):
        entry = AuditEntry(session_id="s1", event_type="test")
        assert entry.timestamp
        assert "T" in entry.timestamp  # ISO-8601 format

    def test_entry_has_session_id(self):
        entry = AuditEntry(session_id="test-session", event_type="test")
        assert entry.session_id == "test-session"

    def test_entry_has_event_type(self):
        entry = AuditEntry(session_id="s1", event_type="tool_call")
        assert entry.event_type == "tool_call"

    def test_unique_entry_ids(self):
        e1 = AuditEntry(session_id="s1", event_type="test")
        e2 = AuditEntry(session_id="s1", event_type="test")
        assert e1.entry_id != e2.entry_id

    def test_to_dict_contains_all_fields(self):
        entry = AuditEntry(
            session_id="s1",
            event_type="tool_call",
            user_identity="user",
            tool_name="secure_score",
            input_summary="input",
            output_summary="output",
            reasoning="for testing",
        )
        d = entry.to_dict()
        assert "entry_id" in d
        assert "timestamp" in d
        assert "session_id" in d
        assert "event_type" in d
        assert "user_identity" in d
        assert "tool_name" in d
        assert "input_summary" in d
        assert "output_summary" in d
        assert "reasoning" in d
        assert "duration_ms" in d
        assert "metadata" in d
        assert "integrity_hash" in d


# ========================================================================
# SECTION 3: PII Redaction in Audit Entries
# ========================================================================


class TestAuditPIIRedaction:
    """PII in audit entries must be redacted via _build_entry."""

    def test_email_redacted_in_user_identity(self):
        entry = _build_entry(
            session_id="s1",
            event_type="test",
            user_identity="admin@contoso.com",
        )
        assert "admin@contoso.com" not in entry.user_identity
        assert "[USER_EMAIL]" in entry.user_identity

    def test_guid_redacted_in_input_summary(self):
        entry = _build_entry(
            session_id="s1",
            event_type="test",
            input_summary="Tenant 12345678-1234-1234-1234-123456789abc",
        )
        assert "12345678-1234-1234-1234-123456789abc" not in entry.input_summary
        assert "[TENANT_ID]" in entry.input_summary

    def test_ip_redacted_in_output_summary(self):
        entry = _build_entry(
            session_id="s1",
            event_type="test",
            output_summary="IP: 192.168.1.100 was compromised",
        )
        assert "192.168.1.100" not in entry.output_summary
        assert "[IP_ADDRESS]" in entry.output_summary

    def test_clean_text_passes_through(self):
        entry = _build_entry(
            session_id="s1",
            event_type="test",
            input_summary="Secure Score is 85",
        )
        assert entry.input_summary == "Secure Score is 85"


# ========================================================================
# SECTION 4: Integrity Hash
# ========================================================================


class TestIntegrityHash:
    """Integrity hash guarantees tamper detection."""

    def test_build_entry_sets_integrity_hash(self):
        entry = _build_entry(session_id="s1", event_type="test")
        assert entry.integrity_hash
        assert len(entry.integrity_hash) == 64  # SHA-256 hex

    def test_verify_integrity_passes(self):
        entry = _build_entry(
            session_id="s1",
            event_type="tool_call",
            tool_name="secure_score",
            input_summary="check score",
        )
        assert verify_integrity(entry) is True

    def test_verify_integrity_detects_tamper(self):
        entry = _build_entry(
            session_id="s1",
            event_type="tool_call",
            tool_name="secure_score",
        )
        # Simulate tamper by creating a new entry with different fields
        # but the same hash — this should fail integrity check
        tampered = AuditEntry(
            entry_id=entry.entry_id,
            timestamp=entry.timestamp,
            session_id="tampered-session",
            event_type=entry.event_type,
            user_identity=entry.user_identity,
            tool_name=entry.tool_name,
            input_summary=entry.input_summary,
            output_summary=entry.output_summary,
            reasoning=entry.reasoning,
            integrity_hash=entry.integrity_hash,
        )
        assert verify_integrity(tampered) is False

    def test_different_entries_get_different_hashes(self):
        e1 = _build_entry(session_id="s1", event_type="test", tool_name="a")
        e2 = _build_entry(session_id="s1", event_type="test", tool_name="b")
        assert e1.integrity_hash != e2.integrity_hash

    def test_compute_integrity_hash_deterministic(self):
        entry = AuditEntry(
            timestamp="2024-01-01T00:00:00",
            session_id="s1",
            event_type="test",
            user_identity="user",
            tool_name="tool",
            input_summary="input",
            output_summary="output",
            reasoning="reason",
        )
        h1 = _compute_integrity_hash(entry)
        h2 = _compute_integrity_hash(entry)
        assert h1 == h2


# ========================================================================
# SECTION 5: Truncation Limits
# ========================================================================


class TestTruncation:
    """Input/output summaries and reasoning must be truncated."""

    def test_input_truncated(self):
        long_input = "x" * (MAX_INPUT_SUMMARY_LENGTH + 500)
        entry = _build_entry(session_id="s1", event_type="test", input_summary=long_input)
        assert len(entry.input_summary) <= MAX_INPUT_SUMMARY_LENGTH

    def test_output_truncated(self):
        long_output = "y" * (MAX_OUTPUT_SUMMARY_LENGTH + 500)
        entry = _build_entry(session_id="s1", event_type="test", output_summary=long_output)
        assert len(entry.output_summary) <= MAX_OUTPUT_SUMMARY_LENGTH

    def test_reasoning_truncated(self):
        long_reason = "z" * (MAX_REASONING_LENGTH + 500)
        entry = _build_entry(session_id="s1", event_type="test", reasoning=long_reason)
        assert len(entry.reasoning) <= MAX_REASONING_LENGTH


# ========================================================================
# SECTION 6: AuditLogger — Tool Call Logging
# ========================================================================


class TestAuditLoggerToolCall:
    """Tests for AuditLogger.log_tool_call()."""

    def test_returns_audit_entry(self):
        al = AuditLogger(session_id="test-session")
        entry = al.log_tool_call(
            tool_name="query_secure_score",
            input_params={"tenant_id": "12345678-1234-1234-1234-123456789abc"},
            output_summary="Score: 85/100",
            user_identity="admin@contoso.com",
            reasoning="User asked about secure score",
            duration_ms=150.5,
        )
        assert isinstance(entry, AuditEntry)
        assert entry.event_type == "tool_call"
        assert entry.tool_name == "query_secure_score"
        assert entry.session_id == "test-session"
        assert entry.duration_ms == 150.5

    def test_pii_redacted_in_tool_call(self):
        al = AuditLogger(session_id="s1")
        entry = al.log_tool_call(
            tool_name="test_tool",
            input_params={"email": "user@contoso.com"},
            output_summary="Done for user@contoso.com",
            user_identity="admin@contoso.com",
        )
        assert "contoso.com" not in entry.user_identity
        assert "contoso.com" not in entry.output_summary

    def test_reasoning_captured(self):
        al = AuditLogger(session_id="s1")
        entry = al.log_tool_call(
            tool_name="defender_coverage",
            input_params={},
            output_summary="coverage data",
            reasoning="Agent determined coverage gaps exist",
        )
        assert "coverage gaps" in entry.reasoning

    def test_entry_appended_to_ledger(self):
        al = AuditLogger(session_id="s1")
        al.log_tool_call(tool_name="t1", input_params={}, output_summary="out1")
        al.log_tool_call(tool_name="t2", input_params={}, output_summary="out2")
        assert len(al.entries) == 2
        assert al.entries[0].tool_name == "t1"
        assert al.entries[1].tool_name == "t2"


# ========================================================================
# SECTION 7: AuditLogger — Interaction Logging
# ========================================================================


class TestAuditLoggerInteraction:
    """Tests for AuditLogger.log_interaction()."""

    def test_logs_interaction(self):
        al = AuditLogger(session_id="s1")
        entry = al.log_interaction(
            user_input="What is my Secure Score?",
            agent_response="Your score is 85/100",
            user_identity="user@contoso.com",
            tools_called=["query_secure_score"],
        )
        assert entry.event_type == "interaction"
        assert "Secure Score" in entry.input_summary
        assert "85/100" in entry.output_summary
        assert entry.metadata["tools_called"] == ["query_secure_score"]

    def test_empty_tools_list(self):
        al = AuditLogger(session_id="s1")
        entry = al.log_interaction(
            user_input="Hello",
            agent_response="Hi there",
        )
        assert entry.metadata["tools_called"] == []

    def test_pii_redacted_in_interaction(self):
        al = AuditLogger(session_id="s1")
        entry = al.log_interaction(
            user_input="Check tenant 12345678-1234-1234-1234-123456789abc",
            agent_response="Results for 192.168.1.1",
            user_identity="admin@contoso.com",
        )
        assert "12345678-1234-1234-1234-123456789abc" not in entry.input_summary
        assert "192.168.1.1" not in entry.output_summary


# ========================================================================
# SECTION 8: AuditLogger — Safety Event Logging
# ========================================================================


class TestAuditLoggerSafetyEvent:
    """Tests for AuditLogger.log_safety_event()."""

    def test_logs_safety_event(self):
        al = AuditLogger(session_id="s1")
        entry = al.log_safety_event(
            event_type="prompt_injection",
            details="Prompt injection pattern detected: ignore previous instructions",
            user_identity="attacker@evil.com",
        )
        assert entry.event_type == "safety_event"
        assert entry.metadata["safety_event_type"] == "prompt_injection"
        assert "ignore previous" in entry.input_summary

    def test_content_blocked_event(self):
        al = AuditLogger(session_id="s1")
        entry = al.log_safety_event(
            event_type="content_blocked",
            details="Hate category blocked: severity 6",
        )
        assert entry.metadata["safety_event_type"] == "content_blocked"


# ========================================================================
# SECTION 9: AuditLogger — Session Lifecycle
# ========================================================================


class TestAuditLoggerSessionLifecycle:
    """Tests for session start/end logging."""

    def test_session_start(self):
        al = AuditLogger(session_id="sess-001")
        entry = al.log_session_start(user_identity="user@contoso.com")
        assert entry.event_type == "session_start"
        assert entry.session_id == "sess-001"

    def test_session_end(self):
        al = AuditLogger(session_id="sess-001")
        entry = al.log_session_end(user_identity="user@contoso.com")
        assert entry.event_type == "session_end"

    def test_full_session_lifecycle(self):
        al = AuditLogger(session_id="lifecycle-test")
        al.log_session_start(user_identity="user")
        al.log_tool_call(
            tool_name="secure_score",
            input_params={},
            output_summary="score=85",
            reasoning="User requested score",
        )
        al.log_interaction(
            user_input="What's my score?",
            agent_response="Your score is 85",
            tools_called=["secure_score"],
        )
        al.log_session_end(user_identity="user")

        entries = al.entries
        assert len(entries) == 4
        assert entries[0].event_type == "session_start"
        assert entries[1].event_type == "tool_call"
        assert entries[2].event_type == "interaction"
        assert entries[3].event_type == "session_end"

    def test_session_id_property(self):
        al = AuditLogger(session_id="my-session")
        assert al.session_id == "my-session"


# ========================================================================
# SECTION 10: In-Memory Ledger — Append-Only
# ========================================================================


class TestAuditLedger:
    """The in-memory ledger must be append-only."""

    def test_entries_returns_tuple(self):
        al = AuditLogger(session_id="s1")
        al.log_session_start()
        assert isinstance(al.entries, tuple)

    def test_entries_tuple_is_copy(self):
        """Modifying the returned tuple doesn't affect the internal list."""
        al = AuditLogger(session_id="s1")
        al.log_session_start()
        entries_before = al.entries
        al.log_session_end()
        entries_after = al.entries
        assert len(entries_before) == 1
        assert len(entries_after) == 2

    def test_no_delete_api(self):
        al = AuditLogger(session_id="s1")
        assert not hasattr(al, "delete_entry")
        assert not hasattr(al, "clear_entries")
        assert not hasattr(al, "remove_entry")

    def test_no_update_api(self):
        al = AuditLogger(session_id="s1")
        assert not hasattr(al, "update_entry")
        assert not hasattr(al, "edit_entry")
        assert not hasattr(al, "modify_entry")

    def test_internal_list_not_directly_accessible(self):
        al = AuditLogger(session_id="s1")
        # _entries is private; public API is entries (tuple)
        al.log_session_start()
        assert isinstance(al.entries, tuple)


# ========================================================================
# SECTION 11: Query Methods
# ========================================================================


class TestAuditLoggerQuery:
    """Tests for query_entries() and get_entry_by_id()."""

    def _populated_logger(self) -> AuditLogger:
        al = AuditLogger(session_id="q1")
        al.log_session_start(user_identity="alice")
        al.log_tool_call(tool_name="secure_score", input_params={}, output_summary="85")
        al.log_tool_call(tool_name="defender_coverage", input_params={}, output_summary="90%")
        al.log_safety_event(event_type="injection", details="blocked")
        al.log_interaction(user_input="test", agent_response="result")
        al.log_session_end(user_identity="alice")
        return al

    def test_query_all(self):
        al = self._populated_logger()
        results = al.query_entries()
        assert len(results) == 6  # all entries

    def test_query_by_event_type(self):
        al = self._populated_logger()
        results = al.query_entries(event_type="tool_call")
        assert len(results) == 2
        assert all(e.event_type == "tool_call" for e in results)

    def test_query_by_tool_name(self):
        al = self._populated_logger()
        results = al.query_entries(tool_name="secure_score")
        assert len(results) == 1
        assert results[0].tool_name == "secure_score"

    def test_query_by_user_identity(self):
        al = self._populated_logger()
        results = al.query_entries(user_identity="alice")
        # session_start and session_end have user_identity="alice"
        assert len(results) >= 2

    def test_query_limit(self):
        al = self._populated_logger()
        results = al.query_entries(limit=2)
        assert len(results) == 2

    def test_query_returns_newest_first(self):
        al = self._populated_logger()
        results = al.query_entries()
        # Last entry logged is session_end — it should appear first
        assert results[0].event_type == "session_end"

    def test_get_entry_by_id_found(self):
        al = AuditLogger(session_id="s1")
        entry = al.log_session_start()
        found = al.get_entry_by_id(entry.entry_id)
        assert found is not None
        assert found.entry_id == entry.entry_id

    def test_get_entry_by_id_not_found(self):
        al = AuditLogger(session_id="s1")
        assert al.get_entry_by_id("nonexistent-id") is None

    def test_combined_filters(self):
        al = self._populated_logger()
        results = al.query_entries(event_type="tool_call", tool_name="defender_coverage")
        assert len(results) == 1
        assert results[0].tool_name == "defender_coverage"


# ========================================================================
# SECTION 12: RBAC Enforcement
# ========================================================================


class TestCheckAuditAccess:
    """Tests for check_audit_access() RBAC."""

    def test_security_admin_has_access(self):
        assert check_audit_access(["SecurityAdmin"]) is True

    def test_audit_log_read_has_access(self):
        assert check_audit_access(["AuditLog.Read"]) is True

    def test_global_admin_has_access(self):
        assert check_audit_access(["GlobalAdmin"]) is True

    def test_regular_user_denied(self):
        assert check_audit_access(["User"]) is False

    def test_empty_roles_denied(self):
        assert check_audit_access([]) is False

    def test_multiple_roles_one_matching(self):
        assert check_audit_access(["Reader", "SecurityAdmin", "Contributor"]) is True

    def test_no_matching_roles(self):
        assert check_audit_access(["Reader", "Contributor", "Writer"]) is False

    def test_audit_reader_roles_constant(self):
        assert "SecurityAdmin" in AUDIT_READER_ROLES
        assert "AuditLog.Read" in AUDIT_READER_ROLES
        assert "GlobalAdmin" in AUDIT_READER_ROLES
        assert len(AUDIT_READER_ROLES) == 3


# ========================================================================
# SECTION 13: Retention Policy
# ========================================================================


class TestRetentionPolicy:
    """Tests for retention policy configuration."""

    def test_default_retention_90_days(self):
        assert AUDIT_RETENTION_DAYS == 90

    def test_retention_is_positive(self):
        assert AUDIT_RETENTION_DAYS > 0


# ========================================================================
# SECTION 14: App Insights Emission
# ========================================================================


class TestAppInsightsEmission:
    """Tests for _emit_to_app_insights (mocked)."""

    @patch("src.middleware.audit_logger._emit_to_app_insights")
    @patch("src.middleware.audit_logger.settings")
    def test_emits_when_connection_string_set(self, mock_settings, mock_emit):
        mock_settings.applicationinsights_connection_string = "InstrumentationKey=test"
        al = AuditLogger(session_id="s1")
        al.log_session_start()
        mock_emit.assert_called_once()

    @patch("src.middleware.audit_logger._emit_to_app_insights")
    @patch("src.middleware.audit_logger.settings")
    def test_does_not_emit_without_connection_string(self, mock_settings, mock_emit):
        mock_settings.applicationinsights_connection_string = ""
        al = AuditLogger(session_id="s1")
        al.log_session_start()
        mock_emit.assert_not_called()

    @patch("src.middleware.audit_logger._emit_to_app_insights")
    @patch("src.middleware.audit_logger.settings")
    def test_emit_receives_correct_entry(self, mock_settings, mock_emit):
        mock_settings.applicationinsights_connection_string = "InstrumentationKey=test"
        al = AuditLogger(session_id="s1")
        entry = al.log_tool_call(
            tool_name="secure_score",
            input_params={},
            output_summary="score=85",
        )
        args = mock_emit.call_args[0]
        assert args[0].tool_name == "secure_score"
        assert args[0].entry_id == entry.entry_id


# ========================================================================
# SECTION 15: Audit Query Endpoint (/audit/logs)
# ========================================================================


class TestAuditQueryEndpoint:
    """Tests for the /audit/logs FastAPI endpoint."""

    @pytest.mark.asyncio
    async def test_audit_logs_requires_auth(self):
        from httpx import ASGITransport, AsyncClient

        from src.api.app import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/audit/logs")
        # No auth token → 401
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_audit_logs_requires_admin_role(self):
        """Regular user (no admin role) gets 403."""

        from httpx import ASGITransport, AsyncClient

        from src.api.app import app
        from src.middleware.auth import UserContext

        mock_user = UserContext(
            user_id="user-123",
            email="regular@contoso.com",
            name="Regular User",
            tenant_id="tenant-123",
            roles=["User"],  # No admin role
            scopes=["SecurityEvents.Read.All"],
        )

        async def mock_get_current_user():
            return mock_user

        auth_mod = __import__("src.middleware.auth", fromlist=["get_current_user"])
        app.dependency_overrides[auth_mod.get_current_user] = mock_get_current_user

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/audit/logs")
            assert resp.status_code == 403
            assert "Audit log access requires" in resp.json()["detail"]
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_audit_logs_allowed_for_security_admin(self):
        """SecurityAdmin role gets 200."""
        from httpx import ASGITransport, AsyncClient

        from src.api.app import app
        from src.middleware.auth import UserContext, get_current_user

        mock_user = UserContext(
            user_id="admin-123",
            email="admin@contoso.com",
            name="Admin User",
            tenant_id="tenant-123",
            roles=["SecurityAdmin"],
            scopes=[],
        )

        async def mock_get_current_user_fn():
            return mock_user

        app.dependency_overrides[get_current_user] = mock_get_current_user_fn

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/audit/logs")
            assert resp.status_code == 200
            body = resp.json()
            assert "entries" in body
            assert "count" in body
            assert body["queried_by"] == "admin@contoso.com"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_audit_logs_allowed_for_global_admin(self):
        """GlobalAdmin role gets 200."""
        from httpx import ASGITransport, AsyncClient

        from src.api.app import app
        from src.middleware.auth import UserContext, get_current_user

        mock_user = UserContext(
            user_id="gadmin",
            email="gadmin@contoso.com",
            name="Global Admin",
            tenant_id="t1",
            roles=["GlobalAdmin"],
            scopes=[],
        )

        async def mock_dep():
            return mock_user

        app.dependency_overrides[get_current_user] = mock_dep

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/audit/logs")
            assert resp.status_code == 200
        finally:
            app.dependency_overrides.clear()


# ========================================================================
# SECTION 16: Integration — Full Audit Pipeline
# ========================================================================


class TestAuditPipelineIntegration:
    """End-to-end integration tests for the audit trail."""

    def test_full_audit_trail(self):
        """Complete session with tool calls, interactions, and safety events."""
        al = AuditLogger(session_id="integration-test")

        # Session start
        e1 = al.log_session_start(user_identity="admin@contoso.com")
        assert e1.event_type == "session_start"
        assert verify_integrity(e1)

        # Tool call with reasoning
        e2 = al.log_tool_call(
            tool_name="query_secure_score",
            input_params={"tenant_id": "12345678-1234-1234-1234-123456789abc"},
            output_summary="Secure Score: 72/100, 5 gaps identified",
            user_identity="admin@contoso.com",
            reasoning="User asked: What is my secure score?",
            duration_ms=234.5,
        )
        assert e2.event_type == "tool_call"
        assert "query_secure_score" in e2.tool_name
        assert verify_integrity(e2)
        # PII should be redacted
        assert "12345678-1234-1234-1234-123456789abc" not in e2.input_summary

        # Safety event
        e3 = al.log_safety_event(
            event_type="prompt_injection",
            details="Pattern detected: ignore previous instructions",
            user_identity="attacker@evil.com",
        )
        assert e3.event_type == "safety_event"
        assert verify_integrity(e3)

        # Interaction
        e4 = al.log_interaction(
            user_input="What gaps should I fix first?",
            agent_response="Priority P0: Enable MFA for all admins",
            user_identity="admin@contoso.com",
            tools_called=["query_secure_score", "remediation_plan"],
        )
        assert e4.event_type == "interaction"
        assert verify_integrity(e4)

        # Session end
        e5 = al.log_session_end(user_identity="admin@contoso.com")
        assert e5.event_type == "session_end"

        # Verify complete trail
        assert len(al.entries) == 5
        for entry in al.entries:
            assert verify_integrity(entry)
            assert entry.session_id == "integration-test"
            assert entry.entry_id  # UUID present
            assert entry.timestamp  # timestamp present

    def test_all_entries_have_consistent_session_id(self):
        al = AuditLogger(session_id="consistent-session")
        al.log_session_start()
        al.log_tool_call(tool_name="t1", input_params={}, output_summary="o1")
        al.log_safety_event(event_type="test", details="d1")
        al.log_interaction(user_input="i1", agent_response="r1")
        al.log_session_end()

        for entry in al.entries:
            assert entry.session_id == "consistent-session"

    def test_query_after_multiple_operations(self):
        al = AuditLogger(session_id="query-test")
        al.log_session_start()
        al.log_tool_call(tool_name="secure_score", input_params={}, output_summary="85")
        al.log_tool_call(tool_name="defender", input_params={}, output_summary="90%")
        al.log_safety_event(event_type="blocked", details="harmful content")
        al.log_session_end()

        tool_calls = al.query_entries(event_type="tool_call")
        assert len(tool_calls) == 2

        safety = al.query_entries(event_type="safety_event")
        assert len(safety) == 1

        sessions = al.query_entries(event_type="session_start")
        assert len(sessions) == 1
