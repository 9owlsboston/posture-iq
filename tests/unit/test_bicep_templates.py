"""Tests for Bicep infrastructure templates.

Validates that all Bicep templates compile, lint cleanly,
and parameter files match the expected schema.
"""

import json
import subprocess
import pytest
from pathlib import Path


INFRA_DIR = Path(__file__).parent.parent.parent / "infra"
MAIN_BICEP = INFRA_DIR / "main.bicep"
MODULES_DIR = INFRA_DIR / "modules"
PARAMS_DIR = INFRA_DIR / "parameters"

# All expected module files
EXPECTED_MODULES = [
    "app-insights.bicep",
    "container-app.bicep",
    "container-registry.bicep",
    "content-safety.bicep",
    "keyvault.bicep",
    "openai.bicep",
]

EXPECTED_PARAMS = [
    "dev.bicepparam",
    "prod.bicepparam",
]


def _bicep_available() -> bool:
    """Check if the Bicep CLI is available."""
    try:
        result = subprocess.run(
            ["az", "bicep", "version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


requires_bicep = pytest.mark.skipif(
    not _bicep_available(),
    reason="Azure CLI / Bicep CLI not available",
)


# ── File structure tests ─────────────────────────────────


class TestBicepFileStructure:
    """Verify all expected Bicep files exist."""

    def test_main_bicep_exists(self):
        assert MAIN_BICEP.exists(), f"Main template missing: {MAIN_BICEP}"

    @pytest.mark.parametrize("module_name", EXPECTED_MODULES)
    def test_module_exists(self, module_name: str):
        module_path = MODULES_DIR / module_name
        assert module_path.exists(), f"Module missing: {module_path}"

    @pytest.mark.parametrize("param_file", EXPECTED_PARAMS)
    def test_parameter_file_exists(self, param_file: str):
        param_path = PARAMS_DIR / param_file
        assert param_path.exists(), f"Parameter file missing: {param_path}"

    def test_modules_directory_has_no_unexpected_files(self):
        actual = {f.name for f in MODULES_DIR.glob("*.bicep")}
        expected = set(EXPECTED_MODULES)
        unexpected = actual - expected
        assert not unexpected, f"Unexpected module files: {unexpected}"


# ── Content validation tests ─────────────────────────────


class TestBicepContent:
    """Verify Bicep template content meets requirements."""

    def test_main_bicep_references_all_modules(self):
        content = MAIN_BICEP.read_text()
        for module in EXPECTED_MODULES:
            assert f"modules/{module}" in content, (
                f"main.bicep does not reference module: {module}"
            )

    def test_main_bicep_has_environment_param(self):
        content = MAIN_BICEP.read_text()
        assert "param environment string" in content

    def test_main_bicep_has_location_param(self):
        content = MAIN_BICEP.read_text()
        assert "param location string" in content

    def test_main_bicep_has_outputs(self):
        content = MAIN_BICEP.read_text()
        assert "output containerAppUrl" in content
        assert "output appInsightsName" in content
        assert "output keyVaultName" in content

    def test_main_bicep_has_managed_identity(self):
        content = MAIN_BICEP.read_text()
        assert "managedIdentity" in content
        assert "UserAssignedIdentities" in content or "userAssignedIdentities" in content

    def test_container_app_has_health_probes(self):
        content = (MODULES_DIR / "container-app.bicep").read_text()
        assert "'/health'" in content or "/health" in content
        assert "'/ready'" in content or "/ready" in content

    def test_container_app_has_scale_to_zero(self):
        content = (MODULES_DIR / "container-app.bicep").read_text()
        assert "minReplicas: 0" in content
        assert "maxReplicas: 5" in content

    def test_container_app_has_managed_identity(self):
        content = (MODULES_DIR / "container-app.bicep").read_text()
        assert "UserAssigned" in content

    def test_keyvault_has_rbac_auth(self):
        content = (MODULES_DIR / "keyvault.bicep").read_text()
        assert "enableRbacAuthorization: true" in content

    def test_keyvault_has_role_assignment(self):
        content = (MODULES_DIR / "keyvault.bicep").read_text()
        assert "roleAssignments" in content or "roleDefinitionId" in content

    def test_openai_has_gpt4o_deployment(self):
        content = (MODULES_DIR / "openai.bicep").read_text()
        assert "gpt-4o" in content

    def test_openai_has_role_assignment(self):
        content = (MODULES_DIR / "openai.bicep").read_text()
        assert "roleAssignments" in content or "roleDefinitionId" in content

    def test_content_safety_has_role_assignment(self):
        content = (MODULES_DIR / "content-safety.bicep").read_text()
        assert "roleAssignments" in content or "roleDefinitionId" in content

    @pytest.mark.parametrize("param_file", EXPECTED_PARAMS)
    def test_param_file_references_main(self, param_file: str):
        content = (PARAMS_DIR / param_file).read_text()
        assert "../main.bicep" in content

    def test_dev_params_has_dev_environment(self):
        content = (PARAMS_DIR / "dev.bicepparam").read_text()
        assert "'dev'" in content

    def test_prod_params_has_prod_environment(self):
        content = (PARAMS_DIR / "prod.bicepparam").read_text()
        assert "'prod'" in content


# ── Bicep compilation tests (require az CLI) ─────────────


@requires_bicep
class TestBicepCompilation:
    """Verify Bicep templates compile without errors."""

    def test_main_bicep_builds(self):
        result = subprocess.run(
            ["az", "bicep", "build", "--file", str(MAIN_BICEP), "--stdout"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, f"Bicep build failed:\n{result.stderr}"
        # Verify the output is valid JSON (ARM template)
        arm_template = json.loads(result.stdout)
        assert arm_template.get("$schema"), "ARM template missing $schema"
        assert "resources" in arm_template, "ARM template missing resources"

    @pytest.mark.parametrize("module_name", EXPECTED_MODULES)
    def test_module_builds(self, module_name: str):
        module_path = MODULES_DIR / module_name
        result = subprocess.run(
            ["az", "bicep", "build", "--file", str(module_path), "--stdout"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, (
            f"Module '{module_name}' build failed:\n{result.stderr}"
        )

    def test_dev_params_build(self):
        result = subprocess.run(
            [
                "az", "bicep", "build-params",
                "--file", str(PARAMS_DIR / "dev.bicepparam"),
                "--stdout",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, (
            f"Dev params build failed:\n{result.stderr}"
        )

    def test_prod_params_build(self):
        result = subprocess.run(
            [
                "az", "bicep", "build-params",
                "--file", str(PARAMS_DIR / "prod.bicepparam"),
                "--stdout",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, (
            f"Prod params build failed:\n{result.stderr}"
        )

    def test_main_bicep_lint(self):
        result = subprocess.run(
            ["az", "bicep", "lint", "--file", str(MAIN_BICEP)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, f"Bicep lint failed:\n{result.stderr}"
