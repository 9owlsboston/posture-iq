"""Tests for Phase 2.5 — Deployment Target: Azure Container Apps.

Validates:
  - Dockerfile structure (multi-stage, GitHub CLI, health check, non-root user, uvicorn)
  - Container App Bicep configuration (health probes, scaling, managed identity, env vars)
  - Managed identity wiring across Bicep modules
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# Resolve project root relative to this test file
PROJECT_ROOT = Path(__file__).parent.parent.parent


# ═══════════════════════════════════════════════════════════════════════════
# 1. Dockerfile Validation
# ═══════════════════════════════════════════════════════════════════════════


class TestDockerfile:
    """Validate Dockerfile meets deployment requirements."""

    @pytest.fixture(autouse=True)
    def _load_dockerfile(self):
        self.dockerfile = (PROJECT_ROOT / "Dockerfile").read_text()

    def test_dockerfile_exists(self):
        assert (PROJECT_ROOT / "Dockerfile").exists()

    # ── Base image ────────────────────────────────────────

    def test_uses_python_slim_base(self):
        assert "python:3.11-slim" in self.dockerfile

    def test_multistage_build(self):
        """Should have at least 2 FROM statements (builder + runtime)."""
        from_count = len(re.findall(r"^FROM\s+", self.dockerfile, re.MULTILINE))
        assert from_count >= 2, f"Expected multi-stage build, found {from_count} FROM"

    def test_builder_stage_exists(self):
        assert "AS builder" in self.dockerfile

    def test_runtime_stage_exists(self):
        assert "AS runtime" in self.dockerfile

    # ── GitHub CLI ────────────────────────────────────────

    def test_installs_github_cli(self):
        """GitHub CLI is required for Copilot SDK runtime."""
        assert "gh" in self.dockerfile
        assert "github" in self.dockerfile.lower()

    # ── Application code ──────────────────────────────────

    def test_copies_app_code(self):
        assert "COPY src/" in self.dockerfile

    def test_copies_dependencies_from_builder(self):
        assert "COPY --from=builder" in self.dockerfile

    def test_installs_python_dependencies(self):
        assert "pip install" in self.dockerfile

    # ── Health check ──────────────────────────────────────

    def test_has_healthcheck(self):
        assert "HEALTHCHECK" in self.dockerfile

    def test_healthcheck_targets_health_endpoint(self):
        assert "/health" in self.dockerfile

    # ── Port & Entrypoint ─────────────────────────────────

    def test_exposes_port_8000(self):
        assert "EXPOSE 8000" in self.dockerfile

    def test_entrypoint_uses_uvicorn(self):
        assert "uvicorn" in self.dockerfile

    def test_entrypoint_targets_correct_app_module(self):
        assert "src.api.app:app" in self.dockerfile

    # ── Security ──────────────────────────────────────────

    def test_runs_as_non_root_user(self):
        assert "USER" in self.dockerfile
        # Should create and switch to a non-root user
        assert "useradd" in self.dockerfile

    def test_python_unbuffered(self):
        assert "PYTHONUNBUFFERED=1" in self.dockerfile

    # ── Version tracking ──────────────────────────────────

    def test_has_git_sha_build_arg(self):
        assert "ARG GIT_SHA" in self.dockerfile

    def test_has_build_time_build_arg(self):
        assert "ARG BUILD_TIME" in self.dockerfile

    def test_sets_git_sha_env(self):
        assert "ENV GIT_SHA" in self.dockerfile

    def test_sets_build_time_env(self):
        assert "ENV BUILD_TIME" in self.dockerfile


# ═══════════════════════════════════════════════════════════════════════════
# 2. Container App Bicep Validation
# ═══════════════════════════════════════════════════════════════════════════


class TestContainerAppBicep:
    """Validate Container App Bicep module meets deployment requirements."""

    @pytest.fixture(autouse=True)
    def _load_bicep(self):
        self.bicep = (PROJECT_ROOT / "infra" / "modules" / "container-app.bicep").read_text()

    # ── Health probes ─────────────────────────────────────

    def test_has_liveness_probe(self):
        assert "Liveness" in self.bicep

    def test_liveness_probe_path(self):
        assert "'/health'" in self.bicep

    def test_has_readiness_probe(self):
        assert "Readiness" in self.bicep

    def test_readiness_probe_path(self):
        assert "'/ready'" in self.bicep

    def test_probes_target_port_8000(self):
        # At least one probe should target port 8000
        assert "port: 8000" in self.bicep

    # ── Scaling ───────────────────────────────────────────

    def test_min_replicas_zero(self):
        assert "minReplicas: 0" in self.bicep

    def test_max_replicas_five(self):
        assert "maxReplicas: 5" in self.bicep

    def test_has_http_scale_rule(self):
        assert "http-rule" in self.bicep or "http" in self.bicep

    # ── Managed identity ──────────────────────────────────

    def test_uses_user_assigned_identity(self):
        assert "UserAssigned" in self.bicep

    def test_accepts_managed_identity_id_param(self):
        assert "param managedIdentityId" in self.bicep

    def test_accepts_managed_identity_client_id_param(self):
        assert "param managedIdentityClientId" in self.bicep

    def test_sets_azure_client_id_env(self):
        """Container should have AZURE_CLIENT_ID env var for DefaultAzureCredential."""
        assert "AZURE_CLIENT_ID" in self.bicep

    # ── Ingress ───────────────────────────────────────────

    def test_has_ingress_config(self):
        assert "ingress" in self.bicep

    def test_ingress_target_port(self):
        assert "targetPort: 8000" in self.bicep

    # ── Environment variables ─────────────────────────────

    def test_has_openai_endpoint_env(self):
        assert "AZURE_OPENAI_ENDPOINT" in self.bicep

    def test_has_content_safety_endpoint_env(self):
        assert "AZURE_CONTENT_SAFETY_ENDPOINT" in self.bicep

    def test_has_keyvault_url_env(self):
        assert "AZURE_KEYVAULT_URL" in self.bicep

    def test_has_app_insights_connection_string_env(self):
        assert "APPLICATIONINSIGHTS_CONNECTION_STRING" in self.bicep

    def test_has_environment_env(self):
        assert "ENVIRONMENT" in self.bicep

    # ── Container Apps Environment ────────────────────────

    def test_creates_container_apps_environment(self):
        assert "Microsoft.App/managedEnvironments" in self.bicep

    def test_creates_container_app(self):
        assert "Microsoft.App/containerApps" in self.bicep

    # ── Output ────────────────────────────────────────────

    def test_outputs_fqdn(self):
        assert "output fqdn" in self.bicep


# ═══════════════════════════════════════════════════════════════════════════
# 3. Managed Identity Wiring (main.bicep)
# ═══════════════════════════════════════════════════════════════════════════


class TestManagedIdentityWiring:
    """Verify managed identity is wired correctly across all Bicep modules."""

    @pytest.fixture(autouse=True)
    def _load_main(self):
        self.main_bicep = (PROJECT_ROOT / "infra" / "main.bicep").read_text()

    def test_main_creates_managed_identity(self):
        assert "Microsoft.ManagedIdentity/userAssignedIdentities" in self.main_bicep

    def test_main_passes_identity_to_container_app(self):
        assert "managedIdentityId" in self.main_bicep
        assert "managedIdentityClientId" in self.main_bicep

    def test_main_passes_principal_to_keyvault(self):
        assert "managedIdentityPrincipalId" in self.main_bicep

    def test_main_passes_principal_to_openai(self):
        # The main module should wire principalId to the openai module
        assert "managedIdentityPrincipalId" in self.main_bicep

    def test_main_outputs_managed_identity_client_id(self):
        assert "managedIdentityClientId" in self.main_bicep


# ═══════════════════════════════════════════════════════════════════════════
# 4. Dockerfile Syntax Validation
# ═══════════════════════════════════════════════════════════════════════════


class TestDockerfileSyntax:
    """Basic syntax checks for the Dockerfile."""

    @pytest.fixture(autouse=True)
    def _load_dockerfile(self):
        self.lines = (PROJECT_ROOT / "Dockerfile").read_text().strip().splitlines()

    def test_first_instruction_is_from(self):
        """First non-comment, non-blank line should be FROM."""
        for line in self.lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                assert stripped.startswith("FROM"), f"Expected FROM, got: {stripped}"
                break

    def test_no_add_instruction(self):
        """Prefer COPY over ADD for security (ADD can fetch URLs)."""
        for line in self.lines:
            stripped = line.strip()
            if stripped.startswith("ADD "):
                pytest.fail("Dockerfile uses ADD — prefer COPY for security")

    def test_workdir_is_set(self):
        assert any(line.strip().startswith("WORKDIR") for line in self.lines)

    def test_cmd_or_entrypoint_is_set(self):
        has_cmd = any(line.strip().startswith("CMD") for line in self.lines)
        has_entrypoint = any(line.strip().startswith("ENTRYPOINT") for line in self.lines)
        assert has_cmd or has_entrypoint, "Dockerfile must have CMD or ENTRYPOINT"
