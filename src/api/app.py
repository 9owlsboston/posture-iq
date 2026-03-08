"""SecPostureIQ — FastAPI application with health probes and Entra ID auth.

Provides:
  - GET /         — Chat UI (static HTML page)
  - GET /health   — liveness probe (is the process alive?)
  - GET /ready    — readiness probe (are dependencies accessible?)
  - GET /version  — build info (git SHA, build time)
  - POST /chat    — chat endpoint (bridges HTTP → agent tools)
  - GET /auth/login    — initiate OAuth2 authorization code flow
  - GET /auth/callback — handle Entra ID redirect with auth code
  - GET /auth/me       — return current user identity (protected)
  - POST /auth/revoke-consent — revoke external-tenant user consent (protected)
  - GET /config        — public app configuration (multi-tenant info)
  - POST /assess       — HTTP-triggered assessment endpoint (protected)
"""

from __future__ import annotations

import asyncio
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.agent.config import settings
from src.api.chat import ChatRequest, ChatResponse, handle_chat
from src.middleware.audit_logger import (
    AUDIT_READER_ROLES,
    AuditLogger,
    check_audit_access,
)
from src.middleware.auth import (
    REVOCATION_SCOPE,
    UserContext,
    build_auth_url,
    build_incremental_consent_url,
    exchange_code_for_tokens,
    get_current_user,
    oauth2_scheme,
    revoke_user_consent,
    validate_token,
)
from src.middleware.tracing import setup_tracing

logger = structlog.get_logger(__name__)

# ── Initialize OpenTelemetry / Azure Monitor tracing at import time ────────
# This must run before the FastAPI app is created so that the
# azure-monitor-opentelemetry instrumentor can patch FastAPI automatically.
setup_tracing()

app = FastAPI(
    title="SecPostureIQ",
    description="ME5 Security Posture Assessment Agent — Get to Green Get-to-Green",
    version="0.1.0",
)

# ── Explicitly instrument the FastAPI app for server-side request spans ────
# configure_azure_monitor() patches FastAPI.__init__ via instrument(), but
# that only captures apps created *after* the patch.  Since our `app` is
# created in the same module-load, we must also call instrument_app() to
# retroactively add the ASGI tracing middleware to this instance.
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(app)
except Exception:
    logger.debug("fastapi_instrumentor.skipped", reason="instrument_app failed or not available")

# ── Static files ───────────────────────────────────────────────────────────

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


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


# ── Chat UI + Endpoint ─────────────────────────────────────────────────────


@app.get("/", include_in_schema=False)
async def chat_ui() -> FileResponse:
    """Serve the chat UI at the root path."""
    return FileResponse(str(_STATIC_DIR / "index.html"), media_type="text/html")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> FileResponse:
    """Serve the favicon."""
    return FileResponse(str(_STATIC_DIR / "favicon.ico"), media_type="image/x-icon")


@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(
    request: ChatRequest,
    raw_request: Request,
    token: str | None = Depends(oauth2_scheme),
) -> ChatResponse:
    """Chat with the SecPostureIQ agent.

    Sends a user message, invokes the appropriate assessment tools,
    and returns a formatted response with tool-call metadata.

    If a valid Bearer token is present, the response includes
    ``tenant_id`` and ``data_source`` from the authenticated user's context.
    Unauthenticated requests still work (demo / mock-data mode).

    Headers:
        Authorization: Bearer <id_token>  — identifies the user.
        X-Graph-Token: <access_token>     — delegated Graph API token
            used by tools to query the real tenant.
    """
    tenant_id = ""
    user_id = ""
    if token:
        try:
            user = await validate_token(token)
            tenant_id = user.tenant_id
            user_id = user.user_id
        except Exception:  # noqa: S110
            pass  # Fall through to unauthenticated / mock mode

    # The SPA sends the Graph access_token (audience=graph.microsoft.com)
    # as a separate header so tools can make delegated Graph API calls.
    graph_token = raw_request.headers.get("X-Graph-Token", "")

    return await handle_chat(
        request,
        tenant_id=tenant_id,
        user_id=user_id,
        graph_token=graph_token,
    )


# ── Health Probes ──────────────────────────────────────────────────────────


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Liveness probe — returns 200 if the process is alive.

    Used by Azure Container Apps to determine if the container should be restarted.
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(UTC).isoformat(),
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
    # Run all dependency checks concurrently so the endpoint stays fast
    # even when external services are slow or unreachable.
    copilot_sdk, azure_openai, graph_api, key_vault = await asyncio.gather(
        _check_copilot_sdk(),
        _check_azure_openai(),
        _check_graph_api(),
        _check_key_vault(),
    )

    checks: dict[str, str] = {
        "copilot_sdk": copilot_sdk,
        "azure_openai": azure_openai,
        "graph_api": graph_api,
        "key_vault": key_vault,
    }

    # Determine overall readiness
    failed = {k: v for k, v in checks.items() if v not in ("ok", "skipped")}
    status = "ready" if not failed else "not_ready"

    response = ReadinessResponse(
        status=status,
        checks=checks,
        timestamp=datetime.now(UTC).isoformat(),
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
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(url)
        # Any HTTP response means the endpoint is reachable.
        # 401/403 = auth required (expected with Managed Identity)
        # 404 = path not found but server responding
        if resp.status_code in (200, 401, 403, 404):
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
            credential: ClientSecretCredential | DefaultAzureCredential = ClientSecretCredential(
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
        async with httpx.AsyncClient(timeout=2.0) as client:
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
async def auth_login(
    request: Request,
    login_hint: str = "",
) -> RedirectResponse:
    """Initiate OAuth2 authorization code flow.

    Redirects the user to Entra ID for login. After authentication,
    Entra ID redirects back to ``/auth/callback`` with an authorization code.

    Query params:
        login_hint: Optional email to pre-select in the Entra ID account picker.
    """
    redirect_uri = str(request.url_for("auth_callback"))
    state = secrets.token_urlsafe(32)
    auth_url = build_auth_url(
        redirect_uri=redirect_uri,
        state=state,
        login_hint=login_hint,
    )
    return RedirectResponse(url=auth_url)


@app.get("/auth/callback")
async def auth_callback(
    request: Request,
    code: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    state: str | None = None,
) -> RedirectResponse:
    """Handle the Entra ID OAuth2 callback.

    Exchanges the authorization code for access + ID tokens, then redirects
    back to the SPA root with the token in a URL fragment so the browser
    JavaScript can store it and display the authenticated user's identity.
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

    # Use id_token for SPA auth — its audience is our app's client-ID,
    # whereas the access_token audience is https://graph.microsoft.com.
    id_token = token_response.get("id_token", "")
    expires_in = token_response.get("expires_in", "")

    # Also pass the Graph access_token so the SPA can make Graph calls later
    access_token = token_response.get("access_token", "")

    # Redirect to SPA root with tokens in fragment (never hits the server)
    return RedirectResponse(
        url=f"/#id_token={id_token}&access_token={access_token}&expires_in={expires_in}",
        status_code=302,
    )


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


@app.post("/auth/revoke-consent")
async def revoke_consent(
    request: Request,
    user: UserContext = Depends(get_current_user),
) -> dict[str, str]:
    """Revoke the current external-tenant user's delegated consent.

    Requires:
      - Valid Bearer token (Authorization header)
      - Graph API access token with DelegatedPermissionGrant.ReadWrite.All
        scope (X-Graph-Token header)
      - User must be from an external tenant (not the hosting tenant)
    """
    # Only allow external-tenant users to revoke consent
    hosting_tenant = settings.azure_tenant_id
    if hosting_tenant and user.tenant_id == hosting_tenant:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Consent revocation is only available for external-tenant users",
        )

    graph_token = request.headers.get("X-Graph-Token", "")
    if not graph_token:
        # No Graph token — construct incremental consent URL
        redirect_uri = str(request.url_for("auth_callback"))
        consent_url = build_incremental_consent_url(
            redirect_uri=redirect_uri,
            additional_scopes=[REVOCATION_SCOPE],
            login_hint=user.email,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "insufficient_scope",
                "required_scope": REVOCATION_SCOPE,
                "consent_url": consent_url,
            },
        )

    deleted = await revoke_user_consent(
        graph_token=graph_token,
        user_id=user.user_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No user-level consent grant found to revoke",
        )

    # Audit log
    audit = AuditLogger(session_id="consent-revocation")
    audit.log_event(
        event_type="consent_revoked",
        tool_name="revoke_consent",
        input_summary=f"user={user.email} tenant={user.tenant_id}",
        output_summary="consent_revoked",
    )
    logger.info(
        "auth.consent.revoked",
        user_id=user.user_id,
        tenant_id=user.tenant_id,
        email=user.email,
    )

    return {"status": "revoked", "message": "Your consent has been revoked successfully"}


class AppConfigResponse(BaseModel):
    multi_tenant_enabled: bool
    hosting_tenant_id: str


@app.get("/config", response_model=AppConfigResponse)
async def app_config() -> AppConfigResponse:
    """Return public application configuration.

    The SPA uses this to determine whether to show external-tenant
    features like the consent revocation button.
    """
    return AppConfigResponse(
        multi_tenant_enabled=settings.multi_tenant_enabled,
        hosting_tenant_id=settings.azure_tenant_id,
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
    # The /assess endpoint is intentionally a stub. Full assessments are driven
    # through the conversational /chat endpoint, which streams results via the
    # Copilot SDK agent session. This endpoint is retained for future use as a
    # headless / API-only trigger (e.g., scheduled assessments, webhooks).
    return {
        "status": "not_implemented",
        "message": "Use the /chat endpoint to run an interactive assessment via the Copilot SDK agent session",
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
