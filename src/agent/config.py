"""PostureIQ — Configuration loader.

Loads settings from environment variables (sourced from .env or Azure Key Vault).
Uses pydantic-settings for validation and type coercion.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings, loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Azure OpenAI ──────────────────────────────────────
    azure_openai_endpoint: str = ""
    azure_openai_deployment: str = "gpt-4o"
    azure_openai_api_version: str = "2024-02-01"
    azure_openai_api_key: str = ""  # blank → use Managed Identity

    # ── Azure AI Content Safety ───────────────────────────
    azure_content_safety_endpoint: str = ""
    azure_content_safety_key: str = ""  # blank → use Managed Identity

    # ── Microsoft Graph API ───────────────────────────────
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    graph_scopes: str = (
        "SecurityEvents.Read.All,"
        "SecurityActions.Read.All,"
        "InformationProtection.Read.All,"
        "Policy.Read.All,"
        "Reports.Read.All"
    )

    # ── Azure Application Insights ────────────────────────
    applicationinsights_connection_string: str = ""

    # ── Azure Key Vault ───────────────────────────────────
    azure_keyvault_url: str = ""

    # ── Foundry IQ ────────────────────────────────────────
    foundry_iq_endpoint: str = ""

    # ── Microsoft Fabric ──────────────────────────────────
    fabric_lakehouse_endpoint: str = ""

    # ── App Settings ──────────────────────────────────────
    log_level: str = "INFO"
    environment: str = "development"
    port: int = 8000

    @property
    def graph_scope_list(self) -> list[str]:
        """Parse comma-separated Graph scopes into a list."""
        return [s.strip() for s in self.graph_scopes.split(",") if s.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def use_managed_identity(self) -> bool:
        """Use Managed Identity when no explicit API keys are set."""
        return not self.azure_openai_api_key


# Singleton — import this from anywhere
settings = Settings()
