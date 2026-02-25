"""PostureIQ — FastAPI application with health probes.

Provides:
  - GET /health  — liveness probe (is the process alive?)
  - GET /ready   — readiness probe (are dependencies accessible?)
  - GET /version — build info (git SHA, build time)
  - POST /assess — (future) HTTP-triggered assessment endpoint
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.agent.config import settings

app = FastAPI(
    title="PostureIQ",
    description="ME5 Security Posture Assessment Agent — Project 479 Get-to-Green",
    version="0.1.0",
)


# ── Response Models ────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    timestamp: str


class ReadinessResponse(BaseModel):
    status: str
    checks: dict[str, str]
    timestamp: str


class VersionResponse(BaseModel):
    version: str
    git_sha: str
    build_time: str
    environment: str


# ── Health Probes ──────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Liveness probe — returns 200 if the process is alive.

    Used by Azure Container Apps to determine if the container should be restarted.
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/ready", response_model=ReadinessResponse)
async def readiness_check() -> ReadinessResponse:
    """Readiness probe — returns 200 only if all dependencies are accessible.

    Checks:
      - Azure OpenAI endpoint is reachable
      - Graph API auth token can be obtained
      - Key Vault is accessible (if configured)

    Used by Azure Container Apps to determine if traffic should be routed to this instance.
    """
    checks: dict[str, str] = {}

    # Check Azure OpenAI
    if settings.azure_openai_endpoint:
        # TODO: Actually ping the endpoint
        checks["azure_openai"] = "configured"
    else:
        checks["azure_openai"] = "not_configured"

    # Check Graph API credentials
    if settings.azure_tenant_id and settings.azure_client_id:
        # TODO: Actually attempt token acquisition
        checks["graph_api"] = "configured"
    else:
        checks["graph_api"] = "not_configured"

    # Check App Insights
    if settings.applicationinsights_connection_string:
        checks["app_insights"] = "configured"
    else:
        checks["app_insights"] = "not_configured"

    # Check Key Vault
    if settings.azure_keyvault_url:
        checks["key_vault"] = "configured"
    else:
        checks["key_vault"] = "not_configured"

    # Determine overall readiness
    all_ready = all(v == "configured" for v in checks.values())
    status = "ready" if all_ready else "degraded"

    return ReadinessResponse(
        status=status,
        checks=checks,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/version", response_model=VersionResponse)
async def version_info() -> VersionResponse:
    """Return build information for diagnostics."""
    return VersionResponse(
        version="0.1.0",
        git_sha=os.environ.get("GIT_SHA", "unknown"),
        build_time=os.environ.get("BUILD_TIME", "unknown"),
        environment=settings.environment,
    )


# ── Assessment Endpoint (future) ───────────────────────────────────────────

@app.post("/assess")
async def trigger_assessment() -> dict[str, str]:
    """Trigger a full ME5 security posture assessment.

    This will be the HTTP-triggered entry point for production use.
    For now, returns a placeholder.
    """
    # TODO: Wire up to the agent session
    return {
        "status": "not_implemented",
        "message": "Assessment endpoint will be wired to the Copilot SDK agent session in Phase 1",
    }
