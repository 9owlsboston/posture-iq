"""Tests for Phase 2.4 — Health Probes (src/api/app.py).

Validates:
  - GET /health returns 200 (liveness)
  - GET /ready returns correct status based on dependency checks
  - GET /ready returns 503-equivalent "not_ready" when dependencies unavailable
  - GET /version returns expected fields (git SHA, build time, environment)
  - Individual dependency check helpers (Copilot SDK, OpenAI, Graph, Key Vault)
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.api.app import (
    _check_azure_openai,
    _check_copilot_sdk,
    _check_graph_api,
    _check_key_vault,
    app,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def client():
    """Async test client for the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ═══════════════════════════════════════════════════════════════════════════
# 1. GET /health — Liveness Probe
# ═══════════════════════════════════════════════════════════════════════════


class TestHealthEndpoint:
    """Liveness probe should always return 200 if the process is alive."""

    @pytest.mark.asyncio
    async def test_health_returns_200(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_health_status_is_healthy(self, client):
        resp = await client.get("/health")
        data = resp.json()
        assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_has_timestamp(self, client):
        resp = await client.get("/health")
        data = resp.json()
        assert "timestamp" in data
        assert "T" in data["timestamp"]  # ISO format

    @pytest.mark.asyncio
    async def test_health_response_schema(self, client):
        resp = await client.get("/health")
        data = resp.json()
        assert set(data.keys()) == {"status", "timestamp"}


# ═══════════════════════════════════════════════════════════════════════════
# 2. GET /version — Build Info
# ═══════════════════════════════════════════════════════════════════════════


class TestVersionEndpoint:
    """Version endpoint returns build metadata."""

    @pytest.mark.asyncio
    async def test_version_returns_200(self, client):
        resp = await client.get("/version")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_version_has_expected_fields(self, client):
        resp = await client.get("/version")
        data = resp.json()
        assert "version" in data
        assert "git_sha" in data
        assert "build_time" in data
        assert "environment" in data

    @pytest.mark.asyncio
    async def test_version_returns_app_version(self, client):
        resp = await client.get("/version")
        data = resp.json()
        assert data["version"] == "0.1.0"

    @pytest.mark.asyncio
    async def test_version_reads_git_sha_from_env(self, client):
        with patch.dict(os.environ, {"GIT_SHA": "abc123def"}):
            resp = await client.get("/version")
            data = resp.json()
            assert data["git_sha"] == "abc123def"

    @pytest.mark.asyncio
    async def test_version_reads_build_time_from_env(self, client):
        with patch.dict(os.environ, {"BUILD_TIME": "2026-02-25T10:00:00Z"}):
            resp = await client.get("/version")
            data = resp.json()
            assert data["build_time"] == "2026-02-25T10:00:00Z"

    @pytest.mark.asyncio
    async def test_version_defaults_when_env_unset(self, client):
        with patch.dict(os.environ, {}, clear=False):
            # Remove if present
            os.environ.pop("GIT_SHA", None)
            os.environ.pop("BUILD_TIME", None)
            resp = await client.get("/version")
            data = resp.json()
            assert data["git_sha"] == "unknown"
            assert data["build_time"] == "unknown"


# ═══════════════════════════════════════════════════════════════════════════
# 3. GET /ready — Readiness Probe
# ═══════════════════════════════════════════════════════════════════════════


class TestReadinessEndpoint:
    """Readiness probe checks all dependencies."""

    @pytest.mark.asyncio
    async def test_ready_returns_200(self, client):
        resp = await client.get("/ready")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_ready_has_expected_fields(self, client):
        resp = await client.get("/ready")
        data = resp.json()
        assert "status" in data
        assert "checks" in data
        assert "timestamp" in data

    @pytest.mark.asyncio
    async def test_ready_checks_include_all_dependencies(self, client):
        resp = await client.get("/ready")
        data = resp.json()
        checks = data["checks"]
        assert "copilot_sdk" in checks
        assert "azure_openai" in checks
        assert "graph_api" in checks
        assert "key_vault" in checks

    @pytest.mark.asyncio
    async def test_ready_status_ready_when_all_ok(self, client):
        """When all checks return ok/skipped, status should be 'ready'."""
        with (
            patch("src.api.app._check_copilot_sdk", return_value="ok"),
            patch("src.api.app._check_azure_openai", return_value="ok"),
            patch("src.api.app._check_graph_api", return_value="ok"),
            patch("src.api.app._check_key_vault", return_value="ok"),
        ):
            resp = await client.get("/ready")
            data = resp.json()
            assert data["status"] == "ready"

    @pytest.mark.asyncio
    async def test_ready_status_ready_when_skipped(self, client):
        """Skipped checks (unconfigured) should not block readiness."""
        with (
            patch("src.api.app._check_copilot_sdk", return_value="ok"),
            patch("src.api.app._check_azure_openai", return_value="skipped"),
            patch("src.api.app._check_graph_api", return_value="skipped"),
            patch("src.api.app._check_key_vault", return_value="skipped"),
        ):
            resp = await client.get("/ready")
            data = resp.json()
            assert data["status"] == "ready"

    @pytest.mark.asyncio
    async def test_ready_not_ready_when_dependency_fails(self, client):
        """Status should be 'not_ready' when any check fails."""
        with (
            patch("src.api.app._check_copilot_sdk", return_value="ok"),
            patch("src.api.app._check_azure_openai", return_value="unreachable"),
            patch("src.api.app._check_graph_api", return_value="ok"),
            patch("src.api.app._check_key_vault", return_value="ok"),
        ):
            resp = await client.get("/ready")
            data = resp.json()
            assert data["status"] == "not_ready"

    @pytest.mark.asyncio
    async def test_ready_not_ready_when_sdk_missing(self, client):
        with (
            patch("src.api.app._check_copilot_sdk", return_value="sdk_not_installed"),
            patch("src.api.app._check_azure_openai", return_value="skipped"),
            patch("src.api.app._check_graph_api", return_value="skipped"),
            patch("src.api.app._check_key_vault", return_value="skipped"),
        ):
            resp = await client.get("/ready")
            data = resp.json()
            assert data["status"] == "not_ready"

    @pytest.mark.asyncio
    async def test_ready_not_ready_multiple_failures(self, client):
        with (
            patch("src.api.app._check_copilot_sdk", return_value="ok"),
            patch("src.api.app._check_azure_openai", return_value="unreachable"),
            patch("src.api.app._check_graph_api", return_value="error: AuthError"),
            patch("src.api.app._check_key_vault", return_value="unreachable"),
        ):
            resp = await client.get("/ready")
            data = resp.json()
            assert data["status"] == "not_ready"
            checks = data["checks"]
            assert checks["azure_openai"] == "unreachable"
            assert "error" in checks["graph_api"]
            assert checks["key_vault"] == "unreachable"


# ═══════════════════════════════════════════════════════════════════════════
# 4. Individual Dependency Check Helpers
# ═══════════════════════════════════════════════════════════════════════════


class TestCheckCopilotSdk:
    """Tests for _check_copilot_sdk helper."""

    @pytest.mark.asyncio
    async def test_returns_ok_when_importable(self):
        result = await _check_copilot_sdk()
        # copilot SDK is installed in the dev env
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_returns_not_installed_when_missing(self):
        import builtins

        original_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "copilot":
                raise ImportError("No module named 'copilot'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            result = await _check_copilot_sdk()
        assert result == "sdk_not_installed"


class TestCheckAzureOpenAI:
    """Tests for _check_azure_openai helper."""

    @pytest.mark.asyncio
    async def test_returns_skipped_when_not_configured(self):
        with patch("src.api.app.settings") as mock_settings:
            mock_settings.azure_openai_endpoint = ""
            result = await _check_azure_openai()
        assert result == "skipped"

    @pytest.mark.asyncio
    async def test_returns_ok_on_200(self):
        mock_response = MagicMock()
        mock_response.status_code = 200

        with (
            patch("src.api.app.settings") as mock_settings,
            patch("httpx.AsyncClient.get", return_value=mock_response),
        ):
            mock_settings.azure_openai_endpoint = "https://test.openai.azure.com"
            result = await _check_azure_openai()
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_returns_ok_on_401(self):
        """401 means reachable but auth needed — still 'ok'."""
        mock_response = MagicMock()
        mock_response.status_code = 401

        with (
            patch("src.api.app.settings") as mock_settings,
            patch("httpx.AsyncClient.get", return_value=mock_response),
        ):
            mock_settings.azure_openai_endpoint = "https://test.openai.azure.com"
            result = await _check_azure_openai()
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_returns_unreachable_on_connect_error(self):
        with (
            patch("src.api.app.settings") as mock_settings,
            patch("httpx.AsyncClient.get", side_effect=httpx.ConnectError("refused")),
        ):
            mock_settings.azure_openai_endpoint = "https://test.openai.azure.com"
            result = await _check_azure_openai()
        assert result == "unreachable"

    @pytest.mark.asyncio
    async def test_returns_http_status_on_unexpected_code(self):
        mock_response = MagicMock()
        mock_response.status_code = 500

        with (
            patch("src.api.app.settings") as mock_settings,
            patch("httpx.AsyncClient.get", return_value=mock_response),
        ):
            mock_settings.azure_openai_endpoint = "https://test.openai.azure.com"
            result = await _check_azure_openai()
        assert result == "http_500"


class TestCheckGraphApi:
    """Tests for _check_graph_api helper."""

    @pytest.mark.asyncio
    async def test_returns_skipped_when_not_configured(self):
        with patch("src.api.app.settings") as mock_settings:
            mock_settings.azure_tenant_id = ""
            mock_settings.azure_client_id = ""
            result = await _check_graph_api()
        assert result == "skipped"

    @pytest.mark.asyncio
    async def test_returns_skipped_when_partial_config(self):
        with patch("src.api.app.settings") as mock_settings:
            mock_settings.azure_tenant_id = "some-tenant"
            mock_settings.azure_client_id = ""
            result = await _check_graph_api()
        assert result == "skipped"

    @pytest.mark.asyncio
    async def test_returns_ok_on_successful_token(self):
        mock_token = SimpleNamespace(token="eyJ...", expires_on=9999999999)
        mock_cred = MagicMock()
        mock_cred.get_token.return_value = mock_token

        with (
            patch("src.api.app.settings") as mock_settings,
            patch("azure.identity.ClientSecretCredential", return_value=mock_cred),
        ):
            mock_settings.azure_tenant_id = "test-tenant"
            mock_settings.azure_client_id = "test-client"
            mock_settings.azure_client_secret = "test-secret"
            result = await _check_graph_api()
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_returns_error_on_auth_failure(self):
        with (
            patch("src.api.app.settings") as mock_settings,
            patch(
                "azure.identity.ClientSecretCredential",
                side_effect=Exception("Invalid client secret"),
            ),
        ):
            mock_settings.azure_tenant_id = "test-tenant"
            mock_settings.azure_client_id = "test-client"
            mock_settings.azure_client_secret = "bad-secret"
            result = await _check_graph_api()
        assert "error" in result


class TestCheckKeyVault:
    """Tests for _check_key_vault helper."""

    @pytest.mark.asyncio
    async def test_returns_skipped_when_not_configured(self):
        with patch("src.api.app.settings") as mock_settings:
            mock_settings.azure_keyvault_url = ""
            result = await _check_key_vault()
        assert result == "skipped"

    @pytest.mark.asyncio
    async def test_returns_ok_on_401(self):
        """401 means reachable — expected without auth."""
        mock_response = MagicMock()
        mock_response.status_code = 401

        with (
            patch("src.api.app.settings") as mock_settings,
            patch("httpx.AsyncClient.get", return_value=mock_response),
        ):
            mock_settings.azure_keyvault_url = "https://test-kv.vault.azure.net"
            result = await _check_key_vault()
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_returns_unreachable_on_connect_error(self):
        with (
            patch("src.api.app.settings") as mock_settings,
            patch("httpx.AsyncClient.get", side_effect=httpx.ConnectError("refused")),
        ):
            mock_settings.azure_keyvault_url = "https://test-kv.vault.azure.net"
            result = await _check_key_vault()
        assert result == "unreachable"
