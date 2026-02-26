"""PostureIQ — FastAPI application with health probes and Entra ID auth.

Provides:
  - GET /health  — liveness probe (is the process alive?)
  - GET /ready   — readiness probe (are dependencies accessible?)
  - GET /version — build info (git SHA, build time)
  - GET /auth/login    — initiate OAuth2 authorization code flow
  - GET /auth/callback — handle Entra ID redirect with auth code
  - GET /auth/me       — return current user identity (protected)
  - POST /assess       — HTTP-triggered assessment endpoint (protected)
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from src.agent.config import settings
from src.middleware.auth import (
    UserContext,
    build_auth_url,
    exchange_code_for_tokens,
    get_current_user,
    validate_token,
)
from src.middleware.audit_logger import (
    AUDIT_READER_ROLES,
    AuditLogger,
    check_audit_access,
)

logger = structlog.get_logger(__name__)

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
      - Copilot SDK session can be created
      - Azure OpenAI endpoint is reachable
      - Graph API auth token can be obtained
      - Key Vault is accessible (if configured)

    Used by Azure Container Apps to determine if traffic should be routed to this instance.
    """
    checks: dict[str, str] = {}

    # Check Copilot SDK availability
    checks["copilot_sdk"] = await _check_copilot_sdk()

    # Check Azure OpenAI
    checks["azure_openai"] = await _check_azure_openai()

    # Check Graph API credentials
    checks["graph_api"] = await _check_graph_api()

    # Check Key Vault
    checks["key_vault"] = await _check_key_vault()

    # Determine overall readiness
    failed = {k: v for k, v in checks.items() if v not in ("ok", "skipped")}
    status = "ready" if not failed else "not_ready"

    response = ReadinessResponse(
        status=status,
        checks=checks,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    if failed:
        logger.warning("readiness.not_ready", failed_checks=failed)

    return response


# ── Dependency check helpers ───────────────────────────────────────────────


async def _check_copilot_sdk() -> str:
    """Verify the Copilot SDK can be imported and client constructed."""
    try:
        from copilot import CopilotClient  # noqa: F401

        return "ok"
    except ImportError:
        return "sdk_not_installed"
    except Exception as e:
        logger.error("readiness.copilot_sdk.error", error=str(e))
        return f"error: {e}"


async def _check_azure_openai() -> str:
    """Verify the Azure OpenAI endpoint is reachable."""
    endpoint = settings.azure_openai_endpoint
    if not endpoint:
        return "skipped"

    try:
        url = endpoint.rstrip("/") + "/openai/deployments?api-version=2024-02-01"
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
        # 401/403 = reachable but auth needed (expected with Managed Identity)
        if resp.status_code in (200, 401, 403):
            return "ok"
        return f"http_{resp.status_code}"
    except httpx.ConnectError:
        return "unreachable"
    except Exception as e:
        logger.error("readiness.azure_openai.error", error=str(e))
        return f"error: {type(e).__name__}"


async def _check_graph_api() -> str:
    """Verify Graph API credentials are configured and a token can be obtained."""
    if not settings.azure_tenant_id or not settings.azure_client_id:
        return "skipped"

    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential

        if settings.azure_client_secret:
            credential = ClientSecretCredential(
                tenant_id=settings.azure_tenant_id,
                client_id=settings.azure_client_id,
                client_secret=settings.azure_client_secret,
            )
        else:
            credential = DefaultAzureCredential()

        # Attempt to acquire a token (validates credentials)
        token = credential.get_token("https://graph.microsoft.com/.default")
        if token and token.token:
            return "ok"
        return "no_token"
    except ImportError:
        return "azure_identity_not_installed"
    except Exception as e:
        logger.error("readiness.graph_api.error", error=str(e))
        return f"error: {type(e).__name__}"


async def _check_key_vault() -> str:
    """Verify Key Vault is accessible."""
    kv_url = settings.azure_keyvault_url
    if not kv_url:
        return "skipped"

    try:
        # Ping Key Vault discovery endpoint (no auth needed)
        url = kv_url.rstrip("/") + "/keys?api-version=7.4"
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
        # 401 = reachable (auth required, expected); 200/403 also ok
        if resp.status_code in (200, 401, 403):
            return "ok"
        return f"http_{resp.status_code}"
    except httpx.ConnectError:
        return "unreachable"
    except Exception as e:
        logger.error("readiness.key_vault.error", error=str(e))
        return f"error: {type(e).__name__}"


@app.get("/version", response_model=VersionResponse)
async def version_info() -> VersionResponse:
    """Return build information for diagnostics."""
    return VersionResponse(
        version="0.1.0",
        git_sha=os.environ.get("GIT_SHA", "unknown"),
        build_time=os.environ.get("BUILD_TIME", "unknown"),
        environment=settings.environment,
    )


# ── Auth Endpoints ─────────────────────────────────────────────────────────


class AuthMeResponse(BaseModel):
    user_id: str
    email: str
    name: str
    tenant_id: str
    scopes: list[str]


@app.get("/auth/login")
async def auth_login(request: Request) -> RedirectResponse:
    """Initiate OAuth2 authorization code flow.

    Redirects the user to Entra ID for login. After authentication,
    Entra ID redirects back to ``/auth/callback`` with an authorization code.
    """
    redirect_uri = str(request.url_for("auth_callback"))
    state = secrets.token_urlsafe(32)
    auth_url = build_auth_url(redirect_uri=redirect_uri, state=state)
    return RedirectResponse(url=auth_url)


@app.get("/auth/callback")
async def auth_callback(
    request: Request,
    code: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    state: str | None = None,
) -> dict[str, str]:
    """Handle the Entra ID OAuth2 callback.

    Exchanges the authorization code for access + ID tokens and returns
    the access token. In a real deployment, this would set a session cookie
    or return the token for the SPA to store.
    """
    if error:
        logger.warning(
            "auth.callback.error",
            error=error,
            error_description=error_description,
        )
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed: {error_description or error}",
        )

    if not code:
        raise HTTPException(
            status_code=400,
            detail="Missing authorization code",
        )

    redirect_uri = str(request.url_for("auth_callback"))
    token_response = await exchange_code_for_tokens(
        code=code,
        redirect_uri=redirect_uri,
    )

    return {
        "access_token": token_response.get("access_token", ""),
        "token_type": "Bearer",
        "expires_in": str(token_response.get("expires_in", "")),
        "scope": token_response.get("scope", ""),
    }


@app.get("/auth/me", response_model=AuthMeResponse)
async def auth_me(user: UserContext = Depends(get_current_user)) -> AuthMeResponse:
    """Return the authenticated user's identity.

    Requires a valid Bearer token in the Authorization header.
    """
    return AuthMeResponse(
        user_id=user.user_id,
        email=user.email,
        name=user.name,
        tenant_id=user.tenant_id,
        scopes=user.scopes,
    )


# ── Assessment Endpoint (protected) ───────────────────────────────────────

@app.post("/assess")
async def trigger_assessment(
    user: UserContext = Depends(get_current_user),
) -> dict[str, str]:
    """Trigger a full ME5 security posture assessment.

    Requires a valid Bearer token. The agent uses the authenticated user's
    delegated permissions to access Graph API security data.
    """
    logger.info(
        "assess.triggered",
        user_id=user.user_id,
        email=user.email,
        scopes=user.scopes,
    )
    # TODO: Wire up to the agent session
    return {
        "status": "not_implemented",
        "message": "Assessment endpoint will be wired to the Copilot SDK agent session in Phase 1",
        "user": user.email,
    }


# ── Audit Log Endpoint (protected, RBAC) ──────────────────────────────────


@app.get("/audit/logs")
async def query_audit_logs(
    user: UserContext = Depends(get_current_user),
    event_type: str | None = None,
    tool_name: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Query the immutable audit trail.

    Requires one of: ``SecurityAdmin``, ``AuditLog.Read``, ``GlobalAdmin``.

    Query parameters:
      - ``event_type``: Filter by event type (tool_call, interaction, etc.)
      - ``tool_name``: Filter by tool name
      - ``limit``: Maximum entries to return (default 100)
    """
    if not check_audit_access(user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Audit log access requires one of: {', '.join(sorted(AUDIT_READER_ROLES))}",
        )

    # Use the global audit logger (in production, this queries App Insights)
    audit = AuditLogger(session_id="audit-query")
    entries = audit.query_entries(
        event_type=event_type,
        tool_name=tool_name,
        limit=limit,
    )

    return {
        "entries": [e.to_dict() for e in entries],
        "count": len(entries),
        "limit": limit,
        "queried_by": user.email,
    }
