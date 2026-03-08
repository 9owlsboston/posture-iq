"""SecPostureIQ — Authentication & Authorization middleware.

Provides Entra ID (Azure AD) OAuth2 authentication for the FastAPI application:
  - JWT bearer-token validation against Entra ID JWKS keys
  - OAuth2 authorization code flow (login → callback → token exchange)
  - User context extraction from validated tokens
  - FastAPI dependencies for protecting endpoints

The agent uses **delegated permissions**: it acts on behalf of the authenticated
user, ensuring they only see data they are authorized to access.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
import structlog
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer

from src.agent.config import settings

logger = structlog.get_logger(__name__)


# ── Constants ──────────────────────────────────────────────────────────────

ENTRA_AUTHORITY = "https://login.microsoftonline.com"
OPENID_CONFIG_PATH = "/.well-known/openid-configuration"
JWKS_CACHE_TTL_SECONDS = 3600  # Re-fetch signing keys every hour


# ── User Context ───────────────────────────────────────────────────────────


@dataclass
class UserContext:
    """Authenticated user identity extracted from an Entra ID JWT.

    Attributes:
        user_id: The ``oid`` (object-ID) claim — unique per user per tenant.
        email: ``preferred_username`` or ``email`` claim.
        name: ``name`` claim (display name).
        tenant_id: ``tid`` claim — the Entra ID tenant.
        roles: Application roles assigned to the user (``roles`` claim).
        scopes: Delegated scopes granted to the token (``scp`` claim).
        raw_claims: Full set of decoded JWT claims.
    """

    user_id: str
    email: str = ""
    name: str = ""
    tenant_id: str = ""
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    raw_claims: dict[str, Any] = field(default_factory=dict, repr=False)


# ── JWKS Key Cache ─────────────────────────────────────────────────────────


class JWKSKeyCache:
    """Fetches and caches Entra ID signing keys (JWKS).

    Keys are refreshed when they expire or when a token references a ``kid``
    not present in the current cache (key rotation).
    """

    def __init__(self) -> None:
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float = 0.0

    @property
    def is_expired(self) -> bool:
        return (time.time() - self._fetched_at) > JWKS_CACHE_TTL_SECONDS

    async def get_signing_key(self, kid: str, tenant_id: str) -> jwt.PyJWK:
        """Return the signing key for *kid*, refreshing cache if needed."""
        if self.is_expired or kid not in self._keys:
            await self._refresh(tenant_id)

        if kid not in self._keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token signing key not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return self._keys[kid]

    async def _refresh(self, tenant_id: str) -> None:
        """Fetch JWKS from the Entra ID OpenID Configuration endpoint."""
        openid_url = f"{ENTRA_AUTHORITY}/{tenant_id}{OPENID_CONFIG_PATH}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Step 1: discover the JWKS URI
                config_resp = await client.get(openid_url)
                config_resp.raise_for_status()
                jwks_uri = config_resp.json()["jwks_uri"]

                # Step 2: fetch the JWKS
                jwks_resp = await client.get(jwks_uri)
                jwks_resp.raise_for_status()

            jwks_data = jwks_resp.json()
            self._keys = {k["kid"]: jwt.PyJWK(k) for k in jwks_data.get("keys", []) if "kid" in k}
            self._fetched_at = time.time()
            logger.info(
                "auth.jwks.refreshed",
                key_count=len(self._keys),
                tenant_id=tenant_id,
            )
        except httpx.HTTPError as exc:
            logger.error("auth.jwks.fetch_failed", error=str(exc))
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to fetch Entra ID signing keys",
            ) from exc


# Module-level singleton
_jwks_cache = JWKSKeyCache()


# ── OAuth2 Scheme ──────────────────────────────────────────────────────────


def _get_oauth2_tenant_path() -> str:
    """Return 'organizations' (multi-tenant) or the configured tenant ID."""
    if settings.multi_tenant_enabled:
        return "organizations"
    return settings.azure_tenant_id


# The scheme object is just a FastAPI/OpenAPI schema hint — evaluated once at
# import time.  The actual URLs used at runtime come from _get_oauth2_tenant_path().
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{ENTRA_AUTHORITY}/organizations/oauth2/v2.0/authorize",
    tokenUrl=f"{ENTRA_AUTHORITY}/organizations/oauth2/v2.0/token",
    auto_error=False,  # We handle missing tokens ourselves for clearer messages
)


# ── Token Validation ───────────────────────────────────────────────────────


async def validate_token(token: str) -> UserContext:
    """Decode and validate an Entra ID JWT bearer token.

    Validation includes:
      - Signature verification against the Entra ID JWKS keys
      - Issuer check (must match the configured or token-claimed tenant)
      - Audience check (must match the configured client-ID)
      - Expiration check (iat, exp, nbf)
      - Tenant allowlist check (when multi-tenant + ALLOWED_TENANTS is set)

    Returns:
        A :class:`UserContext` with the authenticated user's identity.

    Raises:
        HTTPException(401): For invalid, expired, or untrusted tokens.
        HTTPException(403): For tokens from disallowed tenants.
    """
    client_id = settings.oauth_client_id

    # In multi-tenant mode, extract tenant from the token itself.
    # In single-tenant mode, use the configured tenant.
    if settings.multi_tenant_enabled:
        # Pre-decode (no signature check) to extract tid
        try:
            unverified_claims = jwt.decode(token, options={"verify_signature": False})
            tenant_id = unverified_claims.get("tid", "")
        except jwt.DecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        if not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing tid claim",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Tenant allowlist check
        allowed = settings.allowed_tenant_list
        if allowed and tenant_id not in allowed:
            logger.warning("auth.tenant.disallowed", tid=tenant_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Tenant {tenant_id} is not in the allowed tenants list",
            )
    else:
        tenant_id = settings.azure_tenant_id

    if not tenant_id or not client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Auth configuration incomplete: AZURE_TENANT_ID and ENTRA_APP_CLIENT_ID (or AZURE_CLIENT_ID) required"
            ),
        )

    # Decode header to get the key-ID (kid)
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.DecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token header missing kid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Retrieve signing key
    signing_key = await _jwks_cache.get_signing_key(kid, tenant_id)

    # Accepted issuers for v2.0 tokens
    valid_issuers = [
        f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        f"https://sts.windows.net/{tenant_id}/",
    ]

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=valid_issuers,
            options={
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.InvalidIssuerError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token issuer not trusted",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.InvalidAudienceError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token audience mismatch",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    # Extract user identity claims
    scopes_raw = claims.get("scp", "")
    scopes = scopes_raw.split() if isinstance(scopes_raw, str) else []

    return UserContext(
        user_id=claims.get("oid", claims.get("sub", "")),
        email=claims.get("preferred_username", claims.get("email", "")),
        name=claims.get("name", ""),
        tenant_id=claims.get("tid", ""),
        roles=claims.get("roles", []),
        scopes=scopes,
        raw_claims=claims,
    )


# ── FastAPI Dependencies ───────────────────────────────────────────────────


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
) -> UserContext:
    """FastAPI dependency — extracts and validates the bearer token.

    Usage::

        @app.post("/assess")
        async def assess(user: UserContext = Depends(get_current_user)):
            ...

    Raises:
        HTTPException(401): Missing or invalid bearer token.
    """
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await validate_token(token)


async def require_scope(required: str, user: UserContext = Depends(get_current_user)) -> UserContext:
    """Verify the authenticated user has a specific delegated scope.

    Usage::

        @app.get("/secure-score")
        async def secure_score(
            user: UserContext = Depends(require_security_read),
        ):
            ...

    Raises:
        HTTPException(403): When the required scope is not present.
    """
    if required not in user.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient scope: {required} required",
        )
    return user


def scope_checker(scope: str) -> Any:
    """Factory for scope-checking dependencies.

    Example::

        require_security_read = scope_checker("SecurityEvents.Read.All")

        @app.get("/secure-score")
        async def secure_score(user: UserContext = Depends(require_security_read)):
            ...
    """

    async def _check(user: UserContext = Depends(get_current_user)) -> UserContext:
        if scope not in user.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient scope: {scope} required",
            )
        return user

    return _check


# Pre-built scope checkers for common Graph API delegated scopes
require_security_events = scope_checker("SecurityEvents.Read.All")
require_security_actions = scope_checker("SecurityActions.Read.All")
require_policy_read = scope_checker("Policy.Read.All")
require_reports_read = scope_checker("Reports.Read.All")
require_info_protection = scope_checker("InformationProtectionPolicy.Read")


# ── OAuth2 Authorization Code Flow Helpers ─────────────────────────────────


def build_auth_url(
    redirect_uri: str,
    state: str = "",
    scopes: list[str] | None = None,
    login_hint: str = "",
    prompt: str = "select_account",
) -> str:
    """Build the Entra ID authorization URL for the OAuth2 code flow.

    Args:
        redirect_uri: Where Entra ID should redirect after login.
        state: Opaque value to prevent CSRF (should be validated on callback).
        scopes: OAuth2 scopes to request. Defaults to the configured Graph scopes.
        login_hint: Pre-fill the username field (e.g. alice@contoso.com).
        prompt: Entra ID prompt behaviour. Defaults to ``select_account`` so
            users with multiple identities always see the account picker.

    Returns:
        Fully-qualified authorization URL.
    """
    scope_list = scopes or settings.graph_scope_list
    # Always include openid + profile for ID token claims
    scope_str = " ".join({"openid", "profile", "email", *scope_list})

    params: dict[str, str] = {
        "client_id": settings.oauth_client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope_str,
        "response_mode": "query",
        "prompt": prompt,
    }
    if state:
        params["state"] = state
    if login_hint:
        params["login_hint"] = login_hint

    base = f"{ENTRA_AUTHORITY}/{_get_oauth2_tenant_path()}/oauth2/v2.0/authorize"
    return f"{base}?{urlencode(params)}"


async def exchange_code_for_tokens(
    code: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange an authorization code for access + ID tokens.

    Args:
        code: The authorization code from the callback.
        redirect_uri: Must match the redirect_uri used in the auth request.

    Returns:
        Token response dict containing ``access_token``, ``id_token``,
        ``refresh_token``, ``expires_in``, ``scope``.

    Raises:
        HTTPException(401): When the token exchange fails.
    """
    token_url = f"{ENTRA_AUTHORITY}/{_get_oauth2_tenant_path()}/oauth2/v2.0/token"
    data = {
        "client_id": settings.oauth_client_id,
        "client_secret": settings.entra_app_client_secret or settings.azure_client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(token_url, data=data)

        if resp.status_code != 200:
            error_body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            logger.warning(
                "auth.token_exchange.failed",
                status_code=resp.status_code,
                error=error_body.get("error", "unknown"),
                error_description=error_body.get("error_description", ""),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token exchange failed: {error_body.get('error_description', 'unknown error')}",
            )

        result: dict[str, Any] = resp.json()
        return result
    except httpx.HTTPError as exc:
        logger.error("auth.token_exchange.http_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to reach Entra ID token endpoint",
        ) from exc


def get_jwks_cache() -> JWKSKeyCache:
    """Return the module-level JWKS cache (for testability)."""
    return _jwks_cache


# ── Consent Revocation ─────────────────────────────────────────────────────

REVOCATION_SCOPE = "DelegatedPermissionGrant.ReadWrite.All"


async def revoke_user_consent(
    graph_token: str,
    user_id: str,
) -> bool:
    """Revoke the calling user's OAuth2 delegated permission grant for SecPostureIQ.

    Steps:
      1. Resolve SecPostureIQ's service principal object ID in the user's tenant.
      2. List oauth2PermissionGrants filtered by that service principal.
      3. Delete only grants where principalId matches the current user
         and consentType is 'Principal' (skip admin-consent grants).

    Args:
        graph_token: A Graph API access token with
            DelegatedPermissionGrant.ReadWrite.All scope.
        user_id: The authenticated user's oid (object ID).

    Returns:
        True if at least one grant was deleted, False if no matching grant found.

    Raises:
        HTTPException(403): If the Graph token lacks the required scope.
        HTTPException(502): If Graph API calls fail.
    """
    app_id = settings.oauth_client_id
    graph_base = "https://graph.microsoft.com/v1.0"
    headers = {"Authorization": f"Bearer {graph_token}"}

    async with httpx.AsyncClient(timeout=15.0) as client:
        # Step 1: Resolve the service principal object ID from the app ID
        sp_url = f"{graph_base}/servicePrincipals?$filter=appId eq '{app_id}'&$select=id"
        sp_resp = await client.get(sp_url, headers=headers)

        if sp_resp.status_code == 403:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Graph token lacks required scope for consent revocation",
            )
        if sp_resp.status_code != 200:
            logger.error(
                "auth.consent.sp_lookup_failed",
                status_code=sp_resp.status_code,
                body=sp_resp.text[:500],
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to resolve service principal in tenant",
            )

        sp_data = sp_resp.json()
        sp_values = sp_data.get("value", [])
        if not sp_values:
            return False  # Service principal not found — no consent exists

        sp_id = sp_values[0]["id"]

        # Step 2: List oauth2PermissionGrants for this service principal
        grants_url = f"{graph_base}/oauth2PermissionGrants?$filter=clientId eq '{sp_id}'"
        grants_resp = await client.get(grants_url, headers=headers)

        if grants_resp.status_code != 200:
            logger.error(
                "auth.consent.grants_list_failed",
                status_code=grants_resp.status_code,
                body=grants_resp.text[:500],
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to list consent grants",
            )

        grants = grants_resp.json().get("value", [])

        # Step 3: Delete only the user's own grants (consentType=Principal)
        deleted = False
        for grant in grants:
            if grant.get("consentType") == "Principal" and grant.get("principalId") == user_id:
                del_url = f"{graph_base}/oauth2PermissionGrants/{grant['id']}"
                del_resp = await client.delete(del_url, headers=headers)
                if del_resp.status_code == 204:
                    deleted = True
                    logger.info(
                        "auth.consent.grant_deleted",
                        grant_id=grant["id"],
                        user_id=user_id,
                    )
                else:
                    logger.warning(
                        "auth.consent.grant_delete_failed",
                        grant_id=grant["id"],
                        status_code=del_resp.status_code,
                    )

    return deleted


def build_incremental_consent_url(
    redirect_uri: str,
    additional_scopes: list[str],
    state: str = "",
    login_hint: str = "",
) -> str:
    """Build an auth URL that requests additional scopes via incremental consent.

    Args:
        redirect_uri: Where Entra ID should redirect after consent.
        additional_scopes: Extra scopes to request beyond the default Graph scopes.
        state: CSRF-prevention state value.
        login_hint: Pre-fill the username.

    Returns:
        Fully-qualified authorization URL requesting the combined scopes.
    """
    all_scopes = [*settings.graph_scope_list, *additional_scopes]
    return build_auth_url(
        redirect_uri=redirect_uri,
        scopes=all_scopes,
        state=state,
        login_hint=login_hint,
        prompt="consent",
    )
