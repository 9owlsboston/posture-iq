"""Integration smoke tests — end-to-end application validation.

Verifies that the FastAPI application:
  - Starts without import errors
  - Health probes respond correctly
  - Auth enforcement is active on protected endpoints
  - OpenAPI schema exposes all endpoints
  - Agent tools can be invoked through the tool registry
  - Middleware pipeline (PII, Content Safety, RAI) is wired
  - Fabric telemetry pipeline works end-to-end (build → push → query)
  - Foundry IQ playbook lookup works end-to-end
  - Audit logger records tool invocations
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.app import app

# ── Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
async def client():
    """Async test client for the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ========================================================================
# SECTION 1: Application Startup
# ========================================================================


class TestApplicationStartup:
    """Verify the FastAPI app initialises without errors."""

    async def test_app_has_title(self):
        assert app.title == "PostureIQ"

    async def test_app_has_version(self):
        assert app.version == "0.1.0"

    async def test_app_has_routes(self):
        routes = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/health" in routes
        assert "/ready" in routes
        assert "/version" in routes


# ========================================================================
# SECTION 2: Health Probes (Live HTTP)
# ========================================================================


class TestHealthProbesE2E:
    """Hit health probe endpoints via the ASGI transport."""

    async def test_health_returns_200(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "timestamp" in body

    async def test_ready_returns_200(self, client: AsyncClient):
        """Readiness may report not_ready if deps unavailable, but must not crash."""
        resp = await client.get("/ready")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] in ("ready", "not_ready")
        assert "checks" in body
        assert set(body["checks"].keys()) == {
            "copilot_sdk",
            "azure_openai",
            "graph_api",
            "key_vault",
        }

    async def test_version_returns_200(self, client: AsyncClient):
        resp = await client.get("/version")
        assert resp.status_code == 200
        body = resp.json()
        assert body["version"] == "0.1.0"
        assert "git_sha" in body
        assert "build_time" in body
        assert "environment" in body


# ========================================================================
# SECTION 3: Auth Enforcement
# ========================================================================


class TestAuthEnforcementE2E:
    """Verify that protected endpoints reject unauthenticated requests."""

    async def test_assess_requires_auth(self, client: AsyncClient):
        resp = await client.post("/assess")
        assert resp.status_code == 401

    async def test_auth_me_requires_auth(self, client: AsyncClient):
        resp = await client.get("/auth/me")
        assert resp.status_code == 401

    async def test_audit_logs_requires_auth(self, client: AsyncClient):
        resp = await client.get("/audit/logs")
        assert resp.status_code == 401

    async def test_auth_login_redirects(self, client: AsyncClient):
        resp = await client.get("/auth/login", follow_redirects=False)
        assert resp.status_code == 307

    async def test_health_does_not_require_auth(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200

    async def test_ready_does_not_require_auth(self, client: AsyncClient):
        resp = await client.get("/ready")
        assert resp.status_code == 200


# ========================================================================
# SECTION 4: OpenAPI Schema
# ========================================================================


class TestOpenAPISchemaE2E:
    """Verify the OpenAPI schema includes all endpoints."""

    async def test_openapi_json_returns_200(self, client: AsyncClient):
        resp = await client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert schema["info"]["title"] == "PostureIQ"

    async def test_all_endpoints_in_schema(self, client: AsyncClient):
        resp = await client.get("/openapi.json")
        paths = list(resp.json()["paths"].keys())
        expected = [
            "/health",
            "/ready",
            "/version",
            "/auth/login",
            "/auth/callback",
            "/auth/me",
            "/assess",
            "/audit/logs",
        ]
        for ep in expected:
            assert ep in paths, f"Missing endpoint in OpenAPI schema: {ep}"

    async def test_docs_endpoint_returns_200(self, client: AsyncClient):
        resp = await client.get("/docs")
        assert resp.status_code == 200


# ========================================================================
# SECTION 5: Agent Tool Registry
# ========================================================================


class TestToolRegistryE2E:
    """Verify all tools are registered and callable."""

    def test_all_tools_registered(self):
        from src.agent.main import TOOLS

        tool_names = [t.name for t in TOOLS]
        expected = [
            "query_secure_score",
            "assess_defender_coverage",
            "check_purview_policies",
            "get_entra_config",
            "generate_remediation_plan",
            "create_adoption_scorecard",
            "get_project479_playbook",
        ]
        for name in expected:
            assert name in tool_names, f"Missing tool: {name}"

    def test_all_tools_have_handlers(self):
        from src.agent.main import TOOLS

        for tool in TOOLS:
            assert callable(tool.handler), f"Tool {tool.name} has no handler"

    def test_all_tools_have_descriptions(self):
        from src.agent.main import TOOLS

        for tool in TOOLS:
            assert tool.description, f"Tool {tool.name} has no description"
            assert len(tool.description) >= 20

    def test_all_tools_have_parameters(self):
        from src.agent.main import TOOLS

        for tool in TOOLS:
            assert tool.parameters, f"Tool {tool.name} has no parameters"
            assert tool.parameters.get("type") == "object"


# ========================================================================
# SECTION 6: Middleware Pipeline
# ========================================================================


class TestMiddlewarePipelineE2E:
    """Verify middleware components can be imported and invoked."""

    def test_pii_redaction_works(self):
        from src.middleware.pii_redaction import redact_pii

        text = "Tenant 12345678-1234-1234-1234-123456789abc has issues"
        result = redact_pii(text)
        assert "12345678-1234-1234-1234-123456789abc" not in result

    def test_content_safety_importable(self):
        from src.middleware.content_safety import check_content_safety

        assert callable(check_content_safety)

    def test_rai_disclaimer_applied(self):
        from src.middleware.rai import add_disclaimer

        output = {"score": 72}
        result = add_disclaimer(output)
        assert "disclaimer" in result
        assert "AI" in result["disclaimer"] or "review" in result["disclaimer"].lower()

    def test_rai_confidence_scoring(self):
        from src.middleware.rai import assign_confidence

        score = assign_confidence(data_source="mock", data_completeness_pct=80.0)
        assert score in ("high", "medium", "low")

    def test_input_validation(self):
        from src.middleware.input_validation import validate_user_input

        result = validate_user_input("Assess my tenant security posture")
        assert result.is_valid is True

    def test_input_validation_rejects_empty(self):
        from src.middleware.input_validation import validate_user_input

        result = validate_user_input("")
        assert result.is_valid is False


# ========================================================================
# SECTION 7: Foundry IQ Pipeline
# ========================================================================


class TestFoundryIQPipelineE2E:
    """End-to-end test of the Foundry IQ playbook pipeline."""

    async def test_gap_to_playbook_lookup(self):
        from src.tools.foundry_playbook import get_project479_playbook

        result = await get_project479_playbook(
            gaps=["MFA not enforced", "No DLP policies"],
        )
        assert result["playbook_version"]
        assert result["source"] == "built_in"
        assert len(result["matched_areas"]) >= 1
        assert result["context_summary"]

    async def test_all_playbooks_retrieval(self):
        from src.tools.foundry_playbook import get_project479_playbook

        result = await get_project479_playbook()
        assert len(result["playbooks"]) == 12

    async def test_playbook_has_remediation_steps(self):
        from src.tools.foundry_playbook import get_project479_playbook

        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"],
        )
        playbook = list(result["playbooks"].values())[0]
        assert "remediation_steps" in playbook
        assert len(playbook["remediation_steps"]) > 0

    async def test_playbook_has_offers(self):
        from src.tools.foundry_playbook import get_project479_playbook

        result = await get_project479_playbook(
            workload_areas=["defender_endpoint"],
            include_offers=True,
        )
        assert result["recommended_offers"]


# ========================================================================
# SECTION 8: Fabric Telemetry Pipeline
# ========================================================================


class TestFabricTelemetryPipelineE2E:
    """End-to-end test of the Fabric telemetry pipeline."""

    @pytest.fixture(autouse=True)
    def _clear(self):
        from src.tools.fabric_telemetry import clear_snapshot_buffer

        clear_snapshot_buffer()
        yield
        clear_snapshot_buffer()

    async def test_push_query_roundtrip(self):
        from src.tools.fabric_telemetry import (
            hash_tenant_id,
            push_posture_snapshot,
            query_snapshots,
        )

        result = await push_posture_snapshot(
            tenant_id="test-tenant-e2e",
            secure_score_current=75.0,
            secure_score_max=100.0,
            workload_scores={"defender_xdr": 80.0, "purview": 65.0},
            gap_count=5,
            estimated_days_to_green=30,
            top_gaps=["MFA not enforced", "No DLP policies"],
        )
        assert result["write_success"] is True
        assert result["destination"] == "in_memory_buffer"

        # Query back
        h = hash_tenant_id("test-tenant-e2e")
        snapshots = query_snapshots(tenant_id_hash=h)
        assert len(snapshots) == 1
        assert snapshots[0].secure_score_current == 75.0
        assert snapshots[0].gap_count == 5

    async def test_anonymisation_in_pipeline(self):
        from src.tools.fabric_telemetry import (
            get_snapshot_buffer,
            push_posture_snapshot,
        )

        await push_posture_snapshot(
            tenant_id="12345678-1234-1234-1234-123456789abc",
            top_gaps=["admin@contoso.com exposed"],
        )
        snap = get_snapshot_buffer()[0]
        # Tenant ID should be hashed
        assert snap.tenant_id_hash != "12345678-1234-1234-1234-123456789abc"
        assert len(snap.tenant_id_hash) == 64
        # Email should be redacted
        assert "admin@contoso.com" not in snap.top_gaps[0]

    async def test_trend_computation(self):
        from src.tools.fabric_telemetry import (
            compute_trend,
            get_snapshot_buffer,
            push_posture_snapshot,
        )

        for score in [60.0, 70.0, 80.0]:
            await push_posture_snapshot(
                tenant_id="trend-tenant",
                secure_score_current=score,
            )
        trend = compute_trend(list(get_snapshot_buffer()))
        assert len(trend) == 3
        scores = [t["score"] for t in trend]
        assert scores == [60.0, 70.0, 80.0]


# ========================================================================
# SECTION 9: Audit Logger
# ========================================================================


class TestAuditLoggerE2E:
    """Verify audit logging records actions."""

    def test_audit_entry_creation(self):
        from src.middleware.audit_logger import AuditEntry, AuditLogger

        logger = AuditLogger(session_id="e2e-test")
        entry = logger.log_tool_call(
            tool_name="query_secure_score",
            input_params={"tenant_id": "test"},
            output_summary="Score: 72%",
            user_identity="test-user",
        )
        assert isinstance(entry, AuditEntry)
        assert entry.tool_name == "query_secure_score"
        assert entry.session_id == "e2e-test"

    def test_audit_entry_has_integrity_hash(self):
        from src.middleware.audit_logger import AuditLogger

        logger = AuditLogger(session_id="e2e-test")
        entry = logger.log_tool_call(
            tool_name="test_tool",
            input_params={},
            output_summary="test",
            user_identity="user1",
        )
        assert entry.integrity_hash
        assert len(entry.integrity_hash) == 64  # SHA-256

    def test_audit_rbac_enforcement(self):
        from src.middleware.audit_logger import check_audit_access

        assert check_audit_access(["SecurityAdmin"]) is True
        assert check_audit_access(["User"]) is False


# ========================================================================
# SECTION 10: System Prompt
# ========================================================================


class TestSystemPromptE2E:
    """Verify system prompt is well-formed for agent use."""

    def test_prompt_contains_all_tool_names(self):
        from src.agent.main import TOOLS
        from src.agent.system_prompt import SYSTEM_PROMPT

        for tool in TOOLS:
            assert tool.name in SYSTEM_PROMPT, f"System prompt missing tool: {tool.name}"

    def test_prompt_has_guardrails(self):
        from src.agent.system_prompt import SYSTEM_PROMPT

        guardrail_keywords = ["ignore", "override", "injection"]
        assert any(kw in SYSTEM_PROMPT.lower() for kw in guardrail_keywords)

    def test_prompt_has_persona(self):
        from src.agent.system_prompt import SYSTEM_PROMPT

        assert "ME5" in SYSTEM_PROMPT or "security" in SYSTEM_PROMPT.lower()


# ========================================================================
# SECTION 11: Configuration
# ========================================================================


class TestConfigurationE2E:
    """Verify settings load correctly."""

    def test_settings_singleton(self):
        from src.agent.config import settings

        assert settings.environment in ("development", "production", "test", "staging")

    def test_settings_has_all_required_fields(self):
        from src.agent.config import settings

        assert hasattr(settings, "azure_openai_endpoint")
        assert hasattr(settings, "azure_content_safety_endpoint")
        assert hasattr(settings, "azure_tenant_id")
        assert hasattr(settings, "azure_client_id")
        assert hasattr(settings, "applicationinsights_connection_string")
        assert hasattr(settings, "azure_keyvault_url")
        assert hasattr(settings, "foundry_iq_endpoint")
        assert hasattr(settings, "fabric_lakehouse_endpoint")

    def test_graph_scope_list(self):
        from src.agent.config import settings

        scopes = settings.graph_scope_list
        assert isinstance(scopes, list)
        assert len(scopes) >= 1
